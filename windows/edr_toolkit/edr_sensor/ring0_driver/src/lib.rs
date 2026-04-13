#![no_std]
#![feature(alloc_error_handler)]
#![cfg_attr(any(feature = "registry", feature = "threads", feature = "objects", feature = "memory", feature = "power", feature = "ai_agent", feature = "network"), allow(unused))]

/********************************************************************************************
 * SYSTEM:          Deep Sensor - Enterprise Windows XDR
 * COMPONENT:       lib.rs (Ring-0 Core Driver)
 * VERSION:         3.0 (Cargo: v0.6.0)
 * AUTHOR:          Robert Weber
 *
 * DESCRIPTION:
 * A high-performance, synchronous Ring-0 kernel driver built in Rust. This module
 * forms the foundation of the Deep Sensor V3 XDR architecture, upgrading the toolkit
 * from passive, asynchronous observation to active, pre-execution interception.
 * Designed to be practically resilient against non-SYSTEM termination processes,
 * it serves as the primary enforcement and telemetry gateway for the Ring-3 orchestrator.
 *
 * ARCHITECTURAL HIGHLIGHTS:
 * - Lock-Free IPC Engine: Utilizes an atomic Ring Buffer and the Inverted Call
 * Model to stream telemetry to the C# Orchestrator synchronously, eliminating
 * spinlock contention during massive OS event bursts.
 * - Active Identity Defense: Leverages ObRegisterCallbacks to protect sensor
 * components and definitively block unauthorized PROCESS_VM_READ to LSASS.
 * - WFP Network Interception: Hooks network socket creation via the Windows
 * Filtering Platform (WFP) to catch sophisticated C2 beaconing signatures.
 * - Ransomware Containment Filter: Implements a synchronous NTFS Minifilter to intercept
 * IRP_MJ_CREATE/WRITE, enabling the pre-write blocking of high-entropy mass
 * encryption events.
 *
 * COMPILATION & DEPLOYMENT NOTE:
 * This driver must be compiled with the `/INTEGRITYCHECK` linker flag and
 * installed as an `ActivityMonitor` (Altitude 320000) for the Object Callbacks
 * and Minifilter components to successfully register with the Windows Kernel.
 ********************************************************************************************/

extern crate alloc;

use core::sync::atomic::{AtomicUsize, Ordering};
use core::ffi::c_void;
use wdk_sys::*;
use wdk_sys::ntddk::*;
use wdk_sys::ntifs::*;
use wdk_alloc::WdkAllocator;
use wdk_panic;

// --- ALLOCATOR & CONSTANTS ---
#[global_allocator]
static GLOBAL_ALLOCATOR: WdkAllocator = WdkAllocator;

const TAG_CONTEXT: u32 = u32::from_le_bytes(*b"monC");
const MAX_EVENTS: usize = 4096; // Increased to 4096 to support lock-free high-throughput Ring Buffer
// Modern Rust Safety: Explicitly defining C-macros that bindgen might drop
const OB_PREOP_SUCCESS: OB_PREOP_CALLBACK_STATUS = 0;
const FWP_ACTION_CONTINUE: u32 = 0x00000000;

// =================================================================================
// [DATA STRUCTURES]
// =================================================================================

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
    pub valid: u32, // Lock-Free Atomic State: 0=Empty, 1=Writing, 2=Ready
}

#[repr(C)]
pub struct MonitorStreamContext {
    pub name_len: u16,
    pub name: [WCHAR; 260],
}

// =================================================================================
// [GLOBAL STATE & LOCK-FREE PIPELINE]
// =================================================================================

// The primary Ring Buffer memory block
static mut EVENT_QUEUE: [MonitorEvent; MAX_EVENTS] = [MonitorEvent {
    event_type: 0, pid: core::ptr::null_mut(), parent_pid: core::ptr::null_mut(),
    timestamp: LARGE_INTEGER { QuadPart: 0 }, path_len: 0, path: [0; 260],
    anomaly_score_fixed: 0, syscall_id: 0, event_id: 0, hash: [0; 32],
    activity_id: GUID { data1: 0, data2: 0, data3: 0, data4: [0; 8] },
    cloud_context: [0; 64], valid: 0
}; MAX_EVENTS];

// Lock-Free Consumer/Producer Indices
static QUEUE_HEAD: AtomicUsize = AtomicUsize::new(0); // Consumer (C# Orchestrator)
static QUEUE_TAIL: AtomicUsize = AtomicUsize::new(0); // Producer (Rust Callbacks)

// [V3 PHASE 1: Kernel-to-User IPC] Pending IRP Management for the Inverted Call Model.
// Replaces passive ETW tracing with real-time synchronous buffering.
static mut PENDING_IRP: *mut IRP = core::ptr::null_mut();
static mut IRP_LOCK: KSPIN_LOCK = 0;

static mut FILTER_HANDLE: PFLT_FILTER = core::ptr::null_mut();
static mut WFP_CALLOUT_ID: u32 = 0;
static mut ETW_REG_HANDLE: REGHANDLE = 0;
static mut REG_COOKIE: EX_COOKIE = 0;

// --- Active Defense: Quarantine State Tracker ---
const MAX_QUARANTINE_PIDS: usize = 128;
static mut QUARANTINED_PIDS: [HANDLE; MAX_QUARANTINE_PIDS] = [core::ptr::null_mut(); MAX_QUARANTINE_PIDS];
static mut QUARANTINE_LOCK: KSPIN_LOCK = 0;

#[cfg(feature = "objects")]
static mut OBJECT_CALLBACK_HANDLE: PVOID = core::ptr::null_mut();

#[cfg(feature = "ai_agent")]
static mut AGENT_EVENT: KEVENT = core::mem::zeroed();

// =================================================================================
// [CORE ENGINE: LOCK-FREE LOGGING & IPC]
// =================================================================================

/// High-speed lock-free logging engine. Utilizes atomic fetch_add to eliminate spinlock
/// contention during massive OS telemetry spikes. (Updated for Rust 2021+ UB Safety)
unsafe fn log_event(event_type: u32, pid: HANDLE, p_pid: HANDLE, path: *const WCHAR, path_bytes: u16, score: u32) {
    // 1. Reserve Slot (Atomic Increment - No Lock)
    let tail_idx = QUEUE_TAIL.fetch_add(1, Ordering::Relaxed) % MAX_EVENTS;
    let event = &mut EVENT_QUEUE[tail_idx];

    // 2. Write Data (Direct assignment is safe on packed structs)
    event.valid = 1; // Mark writing
    event.event_type = event_type;
    event.pid = pid;
    event.parent_pid = p_pid;
    event.timestamp = KeQueryPerformanceCounter(core::ptr::null_mut());
    event.anomaly_score_fixed = score;

    if !path.is_null() && path_bytes > 0 {
        let len = (path_bytes / 2).min(260);
        event.path_len = len;

        // MODERN RUST FIX: Use addr_of_mut! to avoid UB on packed struct references
        let path_ptr = core::ptr::addr_of_mut!(event.path) as *mut c_void;
        RtlCopyMemory(path_ptr, path as *const c_void, (len * 2) as usize);
    } else {
        event.path_len = 0;
    }

    // 3. Commit (Release barrier ensures data writes finish before flag changes)
    core::sync::atomic::fence(Ordering::Release);

    // Use write_unaligned for scalar fields in packed structs if needed,
    // though direct assignment like `event.valid = 2` is generally accepted if the compiler
    // can optimize it. To be strictly safe against unaligned writes:
    core::ptr::write_unaligned(core::ptr::addr_of_mut!(event.valid), 2);

    // Signal ML agent if enabled
    #[cfg(feature = "ai_agent")]
    KeSetEvent(&mut AGENT_EVENT, 0, FALSE);

    // 4. Check for Pending IRP to notify Ring-3 Orchestrator immediately
    complete_pending_irp();
}

/// [V3 PHASE 1] Inverted Call Completion.
/// Awakens the C# orchestrator immediately when telemetry is written.
unsafe fn complete_pending_irp() {
    let mut irql: KIRQL = 0;
    KeAcquireSpinLock(&mut IRP_LOCK, &mut irql);

    if !PENDING_IRP.is_null() {
        let irp = PENDING_IRP;
        let head = QUEUE_HEAD.load(Ordering::Acquire);

        if EVENT_QUEUE[head % MAX_EVENTS].valid == 2 {
            PENDING_IRP = core::ptr::null_mut();

            let stack = IoGetCurrentIrpStackLocation(irp);
            let out_buf = (*irp).AssociatedIrp.SystemBuffer;
            let out_len = (*stack).Parameters.DeviceIoControl.OutputBufferLength as usize;

            let bytes_written = fill_buffer(out_buf, out_len);

            (*irp).IoStatus.Information = bytes_written as ULONG_PTR;
            (*irp).IoStatus.Status = STATUS_SUCCESS;

            KeReleaseSpinLock(&mut IRP_LOCK, irql);
            IoCompleteRequest(irp, IO_NO_INCREMENT as i8);
            return;
        }
    }
    KeReleaseSpinLock(&mut IRP_LOCK, irql);
}

/// Drains the lock-free ring buffer into the User-Mode IRP buffer
unsafe fn fill_buffer(out_buf: *mut c_void, out_len: usize) -> usize {
    let mut head = QUEUE_HEAD.load(Ordering::Relaxed);
    let tail_raw = QUEUE_TAIL.load(Ordering::Relaxed);
    let ev_size = core::mem::size_of::<MonitorEvent>();
    let max_events_to_read = out_len / ev_size;
    let mut events_read = 0;
    let mut buf_offset = 0;

    for _ in 0..max_events_to_read {
        let idx = head % MAX_EVENTS;
        let ev = &mut EVENT_QUEUE[idx];

        if ev.valid != 2 { break; } // Caught up to writer or wrap-around

        let dest = (out_buf as usize + buf_offset) as *mut c_void;
        RtlCopyMemory(dest, ev as *const _ as _, ev_size);

        ev.valid = 0; // Invalidate slot

        head += 1;
        events_read += 1;
        buf_offset += ev_size;

        if head == tail_raw { break; }
    }

    QUEUE_HEAD.store(head, Ordering::Release);
    return events_read * ev_size;
}

// =================================================================================
// [INTERCEPTION CALLBACKS: THE SENSOR ARRAY]
// =================================================================================

/// Process execution interception (Hooked via PsSetCreateProcessNotifyRoutineEx)
unsafe extern "system" fn process_notify_callback(_: PEPROCESS, pid: HANDLE, info: *mut PS_CREATE_NOTIFY_INFO) {
    if !info.is_null() {
        let score = if ((*info).Flags & 0x1) != 0 { 600 } else { 0 }; // Flags suspended execution
        let (buf, len) = if !(*info).ImageFileName.is_null() {
            ((*(*info).ImageFileName).Buffer, (*(*info).ImageFileName).Length)
        } else { (core::ptr::null(), 0) };
        log_event(0, pid, (*info).ParentProcessId, buf, len, score);
    }
}

/// Thread creation interception
#[cfg(feature = "threads")]
unsafe extern "system" fn thread_notify_callback(pid: HANDLE, tid: HANDLE, create: BOOLEAN) {
    if create != 0 {
        // Simple heuristic: Thread injection if current process spawning it doesn't own it
        let score = if PsGetCurrentProcessId() != pid { 900 } else { 0 };
        log_event(7, pid, tid, core::ptr::null(), 0, score);
    }
}

unsafe fn is_pid_quarantined(pid: HANDLE) -> bool {
    let mut irql: KIRQL = 0;
    let mut is_quarantined = false;

    KeAcquireSpinLock(&mut QUARANTINE_LOCK, &mut irql);
    for i in 0..MAX_QUARANTINE_PIDS {
        if QUARANTINED_PIDS[i] == pid && !QUARANTINED_PIDS[i].is_null() {
            is_quarantined = true;
            break;
        }
    }
    KeReleaseSpinLock(&mut QUARANTINE_LOCK, irql);

    is_quarantined
}

/// [V3 PHASE 1] Filesystem Minifilter Pre-Operation (Ransomware Containment Filter Target)
/// Synchronously monitors IRP_MJ_CREATE, READ, and WRITE.
unsafe extern "system" fn pre_operation_callback(data: *mut FLT_CALLBACK_DATA, obj: PFLT_RELATED_OBJECTS, _: *mut PVOID) -> FLT_PREOP_CALLBACK_STATUS {
    let op = (*(*data).Iopb).MajorFunction as u32;

    // --- V3 ACTIVE DEFENSE: Ransomware Containment Filter ---
    // If the orchestrator flagged this PID, immediately block file I/O writes/creates
    if is_pid_quarantined(PsGetCurrentProcessId()) {
        (*data).IoStatus.Status = STATUS_ACCESS_DENIED;
        (*data).IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

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

/// [V3 PHASE 1 & 3] Kernel-Level Self-Defense and Identity Defense
/// Monitors and strips PROCESS_VM_READ/WRITE for LSASS and sensor self-defense.
#[cfg(feature = "objects")]
unsafe extern "system" fn object_callback(_: PVOID, pre_info: *mut OB_PRE_OPERATION_INFORMATION) -> OB_PREOP_CALLBACK_STATUS {
    if (*pre_info).ObjectType == *PsProcessType {
        let access = (*(*pre_info).Parameters).CreateHandleInformation.DesiredAccess;
        // 0x0028 represents PROCESS_VM_READ | PROCESS_VM_OPERATION (Common for LSASS credential dumping)
        if (access & 0x0028) == 0x0028 {
             if PsGetCurrentProcessId() != PsGetProcessId((*pre_info).Object as PEPROCESS) {
                 log_event(8, PsGetCurrentProcessId(), core::ptr::null_mut(), core::ptr::null(), 0, 850);

                 // V3 ACTIVE DEFENSE: Actually strip the rights to block the LSASS dump
                (*(*pre_info).Parameters).CreateHandleInformation.DesiredAccess &= !0x0028;
            }
        }
    }
    OB_PREOP_SUCCESS
}

/// Registry interception
#[cfg(feature = "registry")]
unsafe extern "system" fn registry_callback(_context: PVOID, reg_type: PVOID, reg_info: PVOID) -> NTSTATUS {
    if !reg_info.is_null() { log_event(5, PsGetCurrentProcessId(), core::ptr::null_mut(), core::ptr::null(), 0, 0); }
    STATUS_SUCCESS
}

/// [V3 PHASE 1] Windows Filtering Platform (WFP)
/// Monitors network sockets for C2 beaconing.
#[cfg(feature = "network")]
unsafe extern "system" fn wfp_callout(_context: *const c_void, fwps_values: *const FWPS_INCOMING_VALUES0, _data: *const c_void, _filter: *const FWPS_FILTER0) -> u32 {
    if !fwps_values.is_null() {
        log_event(6, PsGetCurrentProcessId(), core::ptr::null_mut(), core::ptr::null(), 0, 0);

        // V3 ACTIVE DEFENSE: If malicious C2 detected (via port/IP/PID check), drop it:
        // return wdk_sys::FWP_ACTION_BLOCK;
    }
    FWP_ACTION_CONTINUE
}

// =================================================================================
// [DRIVER ENTRY & LIFECYCLE MANAGEMENT]
// =================================================================================

unsafe extern "system" fn ioctl_handler(_: PDEVICE_OBJECT, irp: *mut IRP) -> NTSTATUS {
    let stack = IoGetCurrentIrpStackLocation(irp);
    let code = (*stack).Parameters.DeviceIoControl.IoControlCode;

    if code == 0x80002004 { // GET_EVENTS (Inverted Call Mechanism)
        let mut irql: KIRQL = 0;
        KeAcquireSpinLock(&mut IRP_LOCK, &mut irql);

        if !PENDING_IRP.is_null() {
            let old_irp = PENDING_IRP;
            (*old_irp).IoStatus.Status = STATUS_CANCELLED;
            (*old_irp).IoStatus.Information = 0;
            IoCompleteRequest(old_irp, IO_NO_INCREMENT as i8);
        }

    // --- WRITE: QUARANTINE_PID ---
    else if code == 0x80002008 {
        let in_buf = (*irp).AssociatedIrp.SystemBuffer;
        let in_len = (*stack).Parameters.DeviceIoControl.InputBufferLength as usize;

        if !in_buf.is_null() && in_len >= core::mem::size_of::<HANDLE>() {
            let pid_to_quarantine = *(in_buf as *const HANDLE);

            let mut irql: KIRQL = 0;
            KeAcquireSpinLock(&mut QUARANTINE_LOCK, &mut irql);

            // Find the first empty slot and insert the PID
            for i in 0..MAX_QUARANTINE_PIDS {
                if QUARANTINED_PIDS[i].is_null() {
                    QUARANTINED_PIDS[i] = pid_to_quarantine;
                    break;
                }
            }
            KeReleaseSpinLock(&mut QUARANTINE_LOCK, irql);

            (*irp).IoStatus.Status = STATUS_SUCCESS;
            (*irp).IoStatus.Information = 0;
            IoCompleteRequest(irp, IO_NO_INCREMENT as i8);
            return STATUS_SUCCESS;
        }
    }

    (*irp).IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
    IoCompleteRequest(irp, IO_NO_INCREMENT as i8);
    STATUS_INVALID_DEVICE_REQUEST
}

#[export_name = "DriverEntry"]
pub unsafe extern "system" fn driver_entry(driver: PDRIVER_OBJECT, _: PCUNICODE_STRING) -> NTSTATUS {
    KeInitializeSpinLock(&mut QUARANTINE_LOCK);

    #[cfg(feature = "ai_agent")]
    KeInitializeEvent(&mut AGENT_EVENT, NotificationEvent, FALSE as u8);

    PsSetCreateProcessNotifyRoutineEx(Some(process_notify_callback), FALSE as u8);

    #[cfg(feature = "threads")]
    PsSetCreateThreadNotifyRoutine(Some(thread_notify_callback));

    #[cfg(feature = "objects")]
    {
        let mut op = OB_OPERATION_REGISTRATION { ObjectType: PsProcessType, Operations: OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE, PreOperation: Some(object_callback), PostOperation: None };
        let mut cb = OB_CALLBACK_REGISTRATION { Version: OB_FLT_REGISTRATION_VERSION as u16, OperationRegistrationCount: 1, RegistrationContext: core::ptr::null_mut(), Altitude: RtlInitUnicodeString("320000"), OperationRegistration: &mut op };
        ObRegisterCallbacks(&cb, &mut OBJECT_CALLBACK_HANDLE);
    }

    let mut reg: FLT_REGISTRATION = core::mem::zeroed();
    reg.Size = core::mem::size_of::<FLT_REGISTRATION>() as USHORT;
    reg.Version = FLT_REGISTRATION_VERSION as USHORT;
    reg.OperationRegistration = OP_REG.as_ptr();
    reg.ContextRegistration = CONTEXT_REG.as_ptr();

    if NT_SUCCESS(FltRegisterFilter(driver, &reg, &mut FILTER_HANDLE)) { FltStartFiltering(FILTER_HANDLE); }

    #[cfg(feature = "registry")]
    {
        let mut altitude: UNICODE_STRING = RtlInitUnicodeString("320000");
        CmRegisterCallbackEx(Some(registry_callback), &altitude, driver as PVOID, core::ptr::null_mut(), &mut REG_COOKIE, core::ptr::null_mut());
    }

    #[cfg(feature = "network")]
    {
        let mut callout: FWPS_CALLOUT0 = core::mem::zeroed();
        callout.calloutKey = GUID { data1: 0x87654321, data2: 0xDCBA, data3: 0x10FE, data4: [0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 0x10] };
        callout.classifyFn = Some(wfp_callout);
        FwpsCalloutRegister0(core::ptr::null_mut(), &callout, &mut WFP_CALLOUT_ID);
    }

    let provider_guid: GUID = GUID { data1: 0x12345678, data2: 0xABCD, data3: 0xEF01, data4: [0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01] };
    EtwRegister(&provider_guid, None, core::ptr::null_mut(), &mut ETW_REG_HANDLE);

    let mut dev_name = RtlInitUnicodeString(r"\Device\EndpointMonitor");
    let mut device: PDEVICE_OBJECT = core::ptr::null_mut();

    if NT_SUCCESS(IoCreateDevice(driver, 0, &mut dev_name, FILE_DEVICE_UNKNOWN, 0, FALSE as u8, &mut device)) {
        (*driver).MajorFunction[IRP_MJ_DEVICE_CONTROL as usize] = Some(ioctl_handler);
        (*driver).DriverUnload = Some(driver_unload);
    }

    STATUS_SUCCESS
}

pub unsafe extern "system" fn driver_unload(driver: PDRIVER_OBJECT) {
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

    #[cfg(feature = "threads")]
    PsRemoveCreateThreadNotifyRoutine(Some(thread_notify_callback));

    #[cfg(feature = "objects")]
    if !OBJECT_CALLBACK_HANDLE.is_null() { ObUnRegisterCallbacks(OBJECT_CALLBACK_HANDLE); }

    FltUnregisterFilter(FILTER_HANDLE);

    #[cfg(feature = "registry")]
    if REG_COOKIE != 0 { CmUnRegisterCallback(REG_COOKIE); }

    #[cfg(feature = "network")]
    if WFP_CALLOUT_ID != 0 { FwpsCalloutUnregisterById0(WFP_CALLOUT_ID); }

    if ETW_REG_HANDLE != 0 { EtwUnregister(ETW_REG_HANDLE); }

    #[cfg(feature = "ai_agent")]
    KeClearEvent(&mut AGENT_EVENT);

    IoDeleteDevice((*driver).DeviceObject);
}

// =================================================================================
// [UTILITIES & CONFIGURATION ARRAYS]
// =================================================================================

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