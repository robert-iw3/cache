#![no_std]
#![feature(alloc_error_handler)]
#![cfg_attr(any(feature = "registry", feature = "threads", feature = "objects"), allow(unused))]

extern crate alloc;

use core::sync::atomic::{AtomicUsize, Ordering};
use core::ffi::c_void;
use wdk_sys::*;
use wdk_sys::ntddk::*;
use wdk_sys::ntifs::*;
use wdk_alloc::WdkAllocator;
use wdk_panic;

#[global_allocator]
static GLOBAL_ALLOCATOR: WdkAllocator = WdkAllocator;

const TAG_CONTEXT: u32 = u32::from_le_bytes(*b"monC");
const MAX_EVENTS: usize = 4096; // Increased size for lock-free safety

// --- Data Structures ---

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct MonitorEvent {
    pub event_type: u32,
    pub pid: HANDLE,
    pub parent_pid: HANDLE,
    pub timestamp: LARGE_INTEGER,
    pub path_len: u16,
    pub path: [WCHAR; 260],
    pub anomaly_score_fixed: u32,
    pub syscall_id: u32,
    pub event_id: u64,
    pub hash: [u8; 32],
    pub activity_id: GUID,
    pub cloud_context: [u8; 64],
    pub valid: u32, // Atomic flag: 0=Empty, 1=Writing, 2=Ready
}

#[repr(C)]
pub struct MonitorStreamContext {
    pub name_len: u16,
    pub name: [WCHAR; 260],
}

// --- Global State ---

// The Ring Buffer
static mut EVENT_QUEUE: [MonitorEvent; MAX_EVENTS] = [MonitorEvent {
    event_type: 0, pid: core::ptr::null_mut(), parent_pid: core::ptr::null_mut(),
    timestamp: LARGE_INTEGER { QuadPart: 0 }, path_len: 0, path: [0; 260],
    anomaly_score_fixed: 0, syscall_id: 0, event_id: 0, hash: [0; 32],
    activity_id: GUID { data1: 0, data2: 0, data3: 0, data4: [0; 8] },
    cloud_context: [0; 64], valid: 0
}; MAX_EVENTS];

// Lock-Free Indices
static QUEUE_HEAD: AtomicUsize = AtomicUsize::new(0); // Consumer
static QUEUE_TAIL: AtomicUsize = AtomicUsize::new(0); // Producer

// Pending IRP Management (Inverted Call)
static mut PENDING_IRP: *mut IRP = core::ptr::null_mut();
static mut IRP_LOCK: KSPIN_LOCK = 0;

static mut FILTER_HANDLE: PFLT_FILTER = core::ptr::null_mut();
#[cfg(feature = "objects")]
static mut OBJECT_CALLBACK_HANDLE: PVOID = core::ptr::null_mut();

// --- Lock-Free Logging Engine ---

unsafe fn log_event(event_type: u32, pid: HANDLE, p_pid: HANDLE, path: *const WCHAR, path_bytes: u16, score: u32) {
    // 1. Reserve Slot (Atomic Increment - No Lock)
    let tail_idx = QUEUE_TAIL.fetch_add(1, Ordering::Relaxed) % MAX_EVENTS;
    let event = &mut EVENT_QUEUE[tail_idx];

    // 2. Write Data
    // We optimistically write. If HEAD overwrites us, we handle that in consumer.
    event.valid = 1; // Mark writing
    event.event_type = event_type;
    event.pid = pid;
    event.parent_pid = p_pid;
    event.timestamp = KeQueryPerformanceCounter(core::ptr::null_mut());
    event.anomaly_score_fixed = score;

    if !path.is_null() && path_bytes > 0 {
        let len = (path_bytes / 2).min(260);
        event.path_len = len;
        RtlCopyMemory(event.path.as_mut_ptr() as _, path as _, (len * 2) as usize);
    } else { event.path_len = 0; }

    // 3. Commit
    core::sync::atomic::fence(Ordering::Release);
    event.valid = 2; // Mark ready

    // 4. Check for Pending IRP (Inverted Call)
    complete_pending_irp();
}

// --- Inverted Call Completion ---

unsafe fn complete_pending_irp() {
    let mut irql: KIRQL = 0;
    KeAcquireSpinLock(&mut IRP_LOCK, &mut irql);

    if !PENDING_IRP.is_null() {
        let irp = PENDING_IRP;

        // Check if we actually have data to send
        let head = QUEUE_HEAD.load(Ordering::Acquire);
        let tail_raw = QUEUE_TAIL.load(Ordering::Acquire);
        // Normalize tail to prevent wrap-around math issues in simple check
        let tail_idx = tail_raw % MAX_EVENTS;

        // Simple heuristic: If data exists, complete the IRP
        if EVENT_QUEUE[head].valid == 2 {
            PENDING_IRP = core::ptr::null_mut(); // Remove from queue

            // The actual data copy happens in `process_irp_read` usually,
            // but for simple Inverted Call, we just wake the user up to tell them "Check now".
            // Alternatively, we fill the buffer here. Let's fill it here.

            let stack = IoGetCurrentIrpStackLocation(irp);
            let out_buf = (*irp).AssociatedIrp.SystemBuffer;
            let out_len = (*stack).Parameters.DeviceIoControl.OutputBufferLength as usize;

            let bytes_written = fill_buffer(out_buf, out_len);

            (*irp).IoStatus.Information = bytes_written as ULONG_PTR;
            (*irp).IoStatus.Status = STATUS_SUCCESS;

            // Release lock before completing
            KeReleaseSpinLock(&mut IRP_LOCK, irql);

            IoCompleteRequest(irp, IO_NO_INCREMENT as i8);
            return;
        }
    }
    KeReleaseSpinLock(&mut IRP_LOCK, irql);
}

unsafe fn fill_buffer(out_buf: *mut c_void, out_len: usize) -> usize {
    let mut head = QUEUE_HEAD.load(Ordering::Relaxed);
    let tail_raw = QUEUE_TAIL.load(Ordering::Relaxed);
    let ev_size = core::mem::size_of::<MonitorEvent>();
    let max_events_to_read = out_len / ev_size;
    let mut events_read = 0;
    let mut buf_offset = 0;

    // We process up to tail, but check validity flag to ensure writer finished
    for _ in 0..max_events_to_read {
        let idx = head % MAX_EVENTS;
        let ev = &mut EVENT_QUEUE[idx];

        if ev.valid != 2 { break; } // Caught up to writer or wrap-around

        // Copy to user buffer
        let dest = (out_buf as usize + buf_offset) as *mut c_void;
        RtlCopyMemory(dest, ev as *const _ as _, ev_size);

        // Invalidate slot (optional, good for debugging)
        ev.valid = 0;

        head += 1;
        events_read += 1;
        buf_offset += ev_size;

        if head == tail_raw { break; }
    }

    QUEUE_HEAD.store(head, Ordering::Release);
    return events_read * ev_size;
}

// --- IOCTL Handler (Inverted Call Logic) ---

unsafe extern "system" fn ioctl_handler(_: PDEVICE_OBJECT, irp: *mut IRP) -> NTSTATUS {
    let stack = IoGetCurrentIrpStackLocation(irp);
    let code = (*stack).Parameters.DeviceIoControl.IoControlCode;

    if code == 0x80002004 { // GET_EVENTS
        let mut irql: KIRQL = 0;
        KeAcquireSpinLock(&mut IRP_LOCK, &mut irql);

        // If we already have a pending IRP, complete the old one with CANCELLED
        if !PENDING_IRP.is_null() {
            let old_irp = PENDING_IRP;
            (*old_irp).IoStatus.Status = STATUS_CANCELLED;
            (*old_irp).IoStatus.Information = 0;
            IoCompleteRequest(old_irp, IO_NO_INCREMENT as i8);
        }

        // Check if data is IMMEDIATELY available
        let head = QUEUE_HEAD.load(Ordering::Relaxed);
        let idx = head % MAX_EVENTS;

        if EVENT_QUEUE[idx].valid == 2 {
            // Data ready, complete immediately (Synchronous)
            KeReleaseSpinLock(&mut IRP_LOCK, irql);
            let out_buf = (*irp).AssociatedIrp.SystemBuffer;
            let out_len = (*stack).Parameters.DeviceIoControl.OutputBufferLength as usize;
            let bytes = fill_buffer(out_buf, out_len);
            (*irp).IoStatus.Information = bytes as ULONG_PTR;
            (*irp).IoStatus.Status = STATUS_SUCCESS;
            IoCompleteRequest(irp, IO_NO_INCREMENT as i8);
            return STATUS_SUCCESS;
        } else {
            // No data, Mark Pending (Asynchronous)
            IoMarkIrpPending(irp);
            PENDING_IRP = irp;
            KeReleaseSpinLock(&mut IRP_LOCK, irql);
            return STATUS_PENDING;
        }
    }

    (*irp).IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
    IoCompleteRequest(irp, IO_NO_INCREMENT as i8);
    STATUS_INVALID_DEVICE_REQUEST
}

// --- Callbacks (Unchanged Logic, Optimized Queuing) ---

unsafe extern "system" fn process_notify_callback(_: PEPROCESS, pid: HANDLE, info: *mut PS_CREATE_NOTIFY_INFO) {
    if !info.is_null() {
        let score = if ((*info).Flags & 0x1) != 0 { 600 } else { 0 };
        log_event(0, pid, (*info).ParentProcessId, (*(*info).ImageFileName).Buffer, (*(*info).ImageFileName).Length, score);
    }
}

unsafe extern "system" fn pre_operation_callback(data: *mut FLT_CALLBACK_DATA, obj: PFLT_RELATED_OBJECTS, _: *mut PVOID) -> FLT_PREOP_CALLBACK_STATUS {
    let op = (*(*data).Iopb).MajorFunction as u32;
    let mut ctx: *mut MonitorStreamContext = core::ptr::null_mut();

    if NT_SUCCESS(FltGetStreamContext((*obj).Instance, (*obj).FileObject, &mut ctx as *mut _ as *mut PFLT_CONTEXT)) {
        log_event(op, PsGetCurrentProcessId(), core::ptr::null_mut(), (*ctx).name.as_ptr(), (*ctx).name_len * 2, 0);
        FltReleaseContext(ctx as PFLT_CONTEXT);
    } else if op == IRP_MJ_CREATE {
        let mut name_info: *mut FLT_FILE_NAME_INFORMATION = core::ptr::null_mut();
        if NT_SUCCESS(FltGetFileNameInformation(data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &mut name_info)) {
            FltParseFileNameInformation(name_info);
            log_event(op, PsGetCurrentProcessId(), core::ptr::null_mut(), (*name_info).Name.Buffer, (*name_info).Name.Length, 0);
            if NT_SUCCESS(FltAllocateContext(FILTER_HANDLE, FLT_STREAM_CONTEXT, core::mem::size_of::<MonitorStreamContext>() as u64, NonPagedPoolNx, &mut ctx as *mut _ as *mut PFLT_CONTEXT)) {
                let len = ((*name_info).Name.Length / 2).min(260);
                (*ctx).name_len = len;
                RtlCopyMemory((*ctx).name.as_mut_ptr() as _, (*name_info).Name.Buffer as _, (len * 2) as usize);
                FltSetStreamContext((*obj).Instance, (*obj).FileObject, FLT_SET_CONTEXT_KEEP_IF_EXISTS, ctx as PFLT_CONTEXT, core::ptr::null_mut());
                FltReleaseContext(ctx as PFLT_CONTEXT);
            }
            FltReleaseFileNameInformation(name_info);
        }
    }
    FLT_PREOP_SUCCESS_NO_CALLBACK
}

#[cfg(feature = "objects")]
unsafe extern "system" fn object_callback(_: PVOID, pre_info: *mut OB_PRE_OPERATION_INFORMATION) -> OB_PREOP_CALLBACK_STATUS {
    if (*pre_info).ObjectType == *PsProcessType {
        let access = (*(*pre_info).Parameters).CreateHandleInformation.DesiredAccess;
        if (access & 0x0028) == 0x0028 {
             if PsGetCurrentProcessId() != PsGetProcessId((*pre_info).Object as PEPROCESS) {
                 log_event(8, PsGetCurrentProcessId(), core::ptr::null_mut(), core::ptr::null(), 0, 850);
            }
        }
    }
    OB_PREOP_SUCCESS
}

// --- Entry/Unload ---

#[export_name = "DriverEntry"]
pub unsafe extern "system" fn driver_entry(driver: PDRIVER_OBJECT, _: PCUNICODE_STRING) -> NTSTATUS {
    KeInitializeSpinLock(&mut IRP_LOCK);

    PsSetCreateProcessNotifyRoutineEx(Some(process_notify_callback), FALSE as u8);

    #[cfg(feature = "objects")]
    {
        let mut op = OB_OPERATION_REGISTRATION { ObjectType: PsProcessType, Operations: OB_OPERATION_HANDLE_CREATE, PreOperation: Some(object_callback), PostOperation: None };
        let mut cb = OB_CALLBACK_REGISTRATION { Version: OB_FLT_REGISTRATION_VERSION as u16, OperationRegistrationCount: 1, RegistrationContext: core::ptr::null_mut(), Altitude: RtlInitUnicodeString("320000"), OperationRegistration: &mut op };
        ObRegisterCallbacks(&cb, &mut OBJECT_CALLBACK_HANDLE);
    }

    let mut reg: FLT_REGISTRATION = core::mem::zeroed();
    reg.Size = core::mem::size_of::<FLT_REGISTRATION>() as USHORT;
    reg.Version = FLT_REGISTRATION_VERSION as USHORT;
    reg.OperationRegistration = OP_REG.as_ptr();
    reg.ContextRegistration = CONTEXT_REG.as_ptr();

    if NT_SUCCESS(FltRegisterFilter(driver, &reg, &mut FILTER_HANDLE)) { FltStartFiltering(FILTER_HANDLE); }

    let mut dev_name = RtlInitUnicodeString(r"\Device\EndpointMonitor\0");
    let mut device: PDEVICE_OBJECT = core::ptr::null_mut();
    if NT_SUCCESS(IoCreateDevice(driver, 0, &mut dev_name, FILE_DEVICE_UNKNOWN, 0, FALSE as u8, &mut device)) {
        (*driver).MajorFunction[IRP_MJ_DEVICE_CONTROL as usize] = Some(ioctl_handler);
        (*driver).DriverUnload = Some(driver_unload);
    }
    STATUS_SUCCESS
}

pub unsafe extern "system" fn driver_unload(driver: PDRIVER_OBJECT) {
    // Clean up Pending IRP
    let mut irql: KIRQL = 0;
    KeAcquireSpinLock(&mut IRP_LOCK, &mut irql);
    if !PENDING_IRP.is_null() {
        let irp = PENDING_IRP;
        PENDING_IRP = core::ptr::null_mut();
        (*irp).IoStatus.Status = STATUS_CANCELLED;
        IoCompleteRequest(irp, IO_NO_INCREMENT as i8);
    }
    KeReleaseSpinLock(&mut IRP_LOCK, irql);

    PsSetCreateProcessNotifyRoutineEx(Some(process_notify_callback), TRUE as u8);
    #[cfg(feature = "objects")]
    if !OBJECT_CALLBACK_HANDLE.is_null() { ObUnRegisterCallbacks(OBJECT_CALLBACK_HANDLE); }
    FltUnregisterFilter(FILTER_HANDLE);
    IoDeleteDevice((*driver).DeviceObject);
}

static OP_REG: [FLT_OPERATION_REGISTRATION; 4] = [
    FLT_OPERATION_REGISTRATION { MajorFunction: IRP_MJ_CREATE, Flags: 0, PreOperation: Some(pre_operation_callback), PostOperation: None, Reserved1: 0 },
    FLT_OPERATION_REGISTRATION { MajorFunction: IRP_MJ_READ, Flags: 0, PreOperation: Some(pre_operation_callback), PostOperation: None, Reserved1: 0 },
    FLT_OPERATION_REGISTRATION { MajorFunction: IRP_MJ_WRITE, Flags: 0, PreOperation: Some(pre_operation_callback), PostOperation: None, Reserved1: 0 },
    FLT_OPERATION_REGISTRATION { MajorFunction: IRP_MJ_OPERATION_END, Flags: 0, PreOperation: None, PostOperation: None, Reserved1: 0 },
];
static CONTEXT_REG: [FLT_CONTEXT_REGISTRATION; 2] = [
    FLT_CONTEXT_REGISTRATION { ContextType: FLT_STREAM_CONTEXT, Flags: 0, ContextCleanupCallback: None, Size: 600, PoolTag: TAG_CONTEXT },
    FLT_CONTEXT_REGISTRATION { ContextType: FLT_CONTEXT_END, ..unsafe { core::mem::zeroed() } }
];
fn RtlInitUnicodeString(s: &str) -> UNICODE_STRING {
    let mut us = UNICODE_STRING::default();
    us.Length = (s.len() * 2) as u16; us.MaximumLength = us.Length + 2;
    us.Buffer = s.as_ptr() as *mut u16; us
}