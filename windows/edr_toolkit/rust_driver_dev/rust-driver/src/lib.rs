#![no_std]
#![feature(alloc_error_handler)]
#![cfg_attr(any(feature = "registry", feature = "threads", feature = "objects", feature = "memory", feature = "power", feature = "ai_agent"), allow(unused))]

extern crate alloc;

use core::sync::atomic::{AtomicUsize, Ordering};
use wdk_sys::*;
use wdk_sys::ntddk::*;
use wdk_sys::ntifs::*;
use wdk_alloc::WdkAllocator;
use wdk_panic;
use fsfilter_rs::*;

#[global_allocator]
static GLOBAL_ALLOCATOR: WdkAllocator = WdkAllocator;

// Constants
const MAX_EVENTS: usize = 512;
const TAG_CONTEXT: u32 = u32::from_le_bytes(*b"monC");

// ML-Ready Event Struct
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct MonitorEvent {
    event_type: u32,
    pid: HANDLE,
    parent_pid: HANDLE,
    timestamp: LARGE_INTEGER,
    path_len: u16,
    path: [WCHAR; 260],
    anomaly_score_fixed: u32,  // ×1000
    syscall_id: u32,
    event_id: u64,
    hash: [u8; 32],
    activity_id: GUID,
    cloud_context: [u8; 64],
}

// Stream Context
#[repr(C)]
pub struct MonitorStreamContext {
    name_len: u16,
    name: [WCHAR; 260],
}

// Globals
static mut EVENT_QUEUE: [MonitorEvent; MAX_EVENTS] = [MonitorEvent {
    event_type: 0, pid: core::ptr::null_mut(), parent_pid: core::ptr::null_mut(), timestamp: LARGE_INTEGER { QuadPart: 0 },
    path_len: 0, path: [0; 260], anomaly_score_fixed: 0, syscall_id: 0, event_id: 0, hash: [0; 32],
    activity_id: GUID { data1: 0, data2: 0, data3: 0, data4: [0; 8] }, cloud_context: [0; 64],
}; MAX_EVENTS];
static QUEUE_HEAD: AtomicUsize = AtomicUsize::new(0);
static QUEUE_TAIL: AtomicUsize = AtomicUsize::new(0);
static mut QUEUE_LOCK: KSPIN_LOCK = 0;
static mut FILTER_HANDLE: PFLT_FILTER = core::ptr::null_mut();
static mut ETW_REG_HANDLE: REGHANDLE = 0;
static mut REG_COOKIE: EX_COOKIE = 0;
static mut OBJECT_CALLBACK_HANDLE: PVOID = core::ptr::null_mut();
static mut AGENT_EVENT: KEVENT = core::mem::zeroed();
static mut CURRENT_ACTIVITY_ID: GUID = GUID { data1: 0, data2: 0, data3: 0, data4: [0; 8] };

// Optimized Log Event (with better handling: Log failures via DbgPrint)
unsafe fn log_event(event_type: u32, pid: HANDLE, parent_pid: HANDLE, path: *const WCHAR, path_bytes: u16, score: u32) {
    let mut irql: KIRQL = 0;
    KeAcquireSpinLock(&mut QUEUE_LOCK, &mut irql);

    let tail = QUEUE_TAIL.load(Ordering::Relaxed);
    let head = QUEUE_HEAD.load(Ordering::Relaxed);

    if (tail + 1) % MAX_EVENTS != head {
        let ev = &mut EVENT_QUEUE[tail];
        ev.event_type = event_type;
        ev.pid = pid;
        ev.parent_pid = parent_pid;
        ev.timestamp = KeQueryPerformanceCounter(core::ptr::null_mut());
        ev.anomaly_score_fixed = score;

        if !path.is_null() && path_bytes > 0 {
            let len = (path_bytes / 2).min(260);
            ev.path_len = len;
            RtlCopyMemory(ev.path.as_mut_ptr() as _, path as _, (len * 2) as usize);
        } else {
            ev.path_len = 0;
        }

        QUEUE_TAIL.store((tail + 1) % MAX_EVENTS, Ordering::Release);
        #[cfg(feature = "ai_agent")]
        KeSetEvent(&mut AGENT_EVENT, 0, FALSE);
    } else {
        DbgPrint!("Queue full - event dropped\0".as_ptr());  // Better handling: Log overflow
    }

    KeReleaseSpinLock(&mut QUEUE_LOCK, irql);
}

// Process Callback
unsafe extern "system" fn process_notify_callback(_process: PEPROCESS, pid: HANDLE, info: *mut PS_CREATE_NOTIFY_INFO) {
    if !info.is_null() {
        let is_suspended = ((*info).Flags & 0x1) != 0;
        let score = if is_suspended { 600 } else { 0 };
        let (buf, len) = if !(*info).ImageFileName.is_null() {
            ((*(*info).ImageFileName).Buffer, (*(*info).ImageFileName).Length)
        } else { (core::ptr::null(), 0) };
        log_event(0, pid, (*info).ParentProcessId, buf, len, score);
    }
}

// Thread Callback
#[cfg(feature = "threads")]
unsafe extern "system" fn thread_notify_callback(pid: HANDLE, tid: HANDLE, create: BOOLEAN) {
    if create != 0 {
        let score = if PsGetCurrentProcessId() != pid { 900 } else { 0 };
        log_event(7, pid, tid, core::ptr::null(), 0, score);
    }
}

// Minifilter Pre-Op
unsafe extern "system" fn pre_operation_callback(data: *mut FLT_CALLBACK_DATA, obj: PFLT_RELATED_OBJECTS, _: *mut PVOID) -> FLT_PREOP_CALLBACK_STATUS {
    let op = (*(*data).Iopb).MajorFunction as u32;
    let mut ctx: *mut MonitorStreamContext = core::ptr::null_mut();

    let status = FltGetStreamContext((*obj).Instance, (*obj).FileObject, &mut ctx as *mut _ as *mut PFLT_CONTEXT);
    if NT_SUCCESS(status) {
        log_event(op, PsGetCurrentProcessId(), core::ptr::null_mut(), (*ctx).name.as_ptr(), (*ctx).name_len * 2, 0);
        FltReleaseContext(ctx as PFLT_CONTEXT);
    } else if op == IRP_MJ_CREATE {
        let mut name_info: FLT_FILE_NAME_INFORMATION = core::mem::zeroed();
        let name_status = FltGetFileNameInformation(data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &mut name_info);
        if NT_SUCCESS(name_status) {
            let parse_status = FltParseFileNameInformation(&mut name_info);
            if NT_SUCCESS(parse_status) {
                log_event(op, PsGetCurrentProcessId(), core::ptr::null_mut(), name_info.Name.Buffer, name_info.Name.Length, 0);

                let alloc_status = FltAllocateContext(FILTER_HANDLE, FLT_STREAM_CONTEXT, size_of::<MonitorStreamContext>() as u64, NonPagedPoolNx, &mut ctx as *mut _ as *mut PFLT_CONTEXT);
                if NT_SUCCESS(alloc_status) {
                    let len = (name_info.Name.Length / 2).min(260);
                    (*ctx).name_len = len;
                    RtlCopyMemory((*ctx).name.as_mut_ptr() as _, name_info.Name.Buffer as _, (len * 2) as usize);
                    let set_status = FltSetStreamContext((*obj).Instance, (*obj).FileObject, FLT_SET_CONTEXT_KEEP_IF_EXISTS, ctx as PFLT_CONTEXT, core::ptr::null_mut());
                    FltReleaseContext(ctx as PFLT_CONTEXT);  // Release regardless
                    if !NT_SUCCESS(set_status) {
                        DbgPrint!("Set context failed: 0x%X\0".as_ptr(), set_status);
                    }
                } else {
                    DbgPrint!("Alloc context failed: 0x%X\0".as_ptr(), alloc_status);
                }
            } else {
                DbgPrint!("Parse name failed: 0x%X\0".as_ptr(), parse_status);
            }
            FltReleaseFileNameInformation(&mut name_info);
        } else {
            DbgPrint!("Get name failed: 0x%X\0".as_ptr(), name_status);
        }
    }
    FLT_PREOP_SUCCESS_NO_CALLBACK
}

// Context Cleanup
unsafe extern "system" fn context_cleanup_callback(context: PFLT_CONTEXT, _type: FLT_CONTEXT_TYPE) {
    if _type == FLT_STREAM_CONTEXT {
        // No-op; future dynamic free here
    }
}

// Object Callback
#[cfg(feature = "objects")]
unsafe extern "system" fn object_callback(_: PVOID, pre_info: *mut OB_PRE_OPERATION_INFORMATION) -> OB_PREOP_CALLBACK_STATUS {
    if (*pre_info).ObjectType == *PsProcessType {
        let access = (*pre_info).Parameters.CreateHandleInformation.DesiredAccess;
        if (access & 0x0028) == 0x0028 {
            if PsGetCurrentProcessId() != PsGetProcessId((*pre_info).Object as PEPROCESS) {
                log_event(8, PsGetCurrentProcessId(), core::ptr::null_mut(), core::ptr::null(), 0, 850);
            }
        }
    }
    OB_PREOP_SUCCESS
}

// Registry Callback
#[cfg(feature = "registry")]
unsafe extern "system" fn registry_callback(
    _context: PVOID,
    reg_type: PVOID,
    reg_info: PVOID,
) -> NTSTATUS {
    let mut status = STATUS_SUCCESS;
    if let Some(info) = reg_info as *mut REG_NOTIFY_INFORMATION {
        let mut event = MonitorEvent {
            event_type: 5,
            pid: PsGetCurrentProcessId(),
            parent_pid: core::ptr::null_mut(),
            timestamp: KeQueryPerformanceCounter(core::ptr::null_mut()),
            path_len: 0,
            path: [0; 260],
            anomaly_score_fixed: 0,
            syscall_id: 0,
            event_id: 0,
            hash: [0; 32],
            activity_id: get_current_activity_id(),
            cloud_context: [0; 64],
        };
        // Extract path (with checks)
        // Stub: Assume extraction logic; add NT_SUCCESS
        log_event(5, event.pid, event.parent_pid, event.path.as_ptr(), event.path_len * 2, 0);
    } else {
        DbgPrint!("Invalid reg_info\0".as_ptr());
        status = STATUS_INVALID_PARAMETER;
    }
    status
}

// Network Callout
#[cfg(feature = "network")]
unsafe extern "system" fn wfp_callout(
    _context: *const c_void,
    fwps_incoming_values: *const FWPS_INCOMING_VALUES0,
    _related_data: *const c_void,
    _filter: *const FWPS_FILTER0,
) -> u32 {
    let mut event = MonitorEvent {
        event_type: 6,
        pid: PsGetCurrentProcessId(),
        parent_pid: core::ptr::null_mut(),
        timestamp: KeQueryPerformanceCounter(core::ptr::null_mut()),
        path_len: 0,
        path: [0; 260],
        anomaly_score_fixed: 0,
        syscall_id: 0,
        event_id: 0,
        hash: [0; 32],
        activity_id: get_current_activity_id(),
        cloud_context: [0; 64],
    };
    if !fwps_incoming_values.is_null() {
        // Extract (with null check)
        log_event(6, event.pid, event.parent_pid, event.path.as_ptr(), event.path_len * 2, 0);
    } else {
        DbgPrint!("Invalid fwps_values\0".as_ptr());
    }
    FWP_ACTION_CONTINUE
}

// ETW Tracing
unsafe fn trace_etw_event(event: &MonitorEvent) {
    if ETW_REG_HANDLE != 0 {
        let status = EventActivityIdControl(EVENT_ACTIVITY_CTRL_SET_ID, &event.activity_id);
        if !NT_SUCCESS(status) {
            DbgPrint!("Activity ID set failed: 0x%X\0".as_ptr(), status);
            return;
        }

        let mut desc: EVENT_DATA_DESCRIPTOR = core::mem::zeroed();
        EventDataDescCreate(&mut desc, event as *const _ as *const c_void, core::mem::size_of::<MonitorEvent>() as ULONG);
        let write_status = EventWrite(ETW_REG_HANDLE, core::ptr::null(), 1, &mut desc);
        if !NT_SUCCESS(write_status) {
            DbgPrint!("ETW write failed: 0x%X\0".as_ptr(), write_status);
        }
    }
}

// Get Activity ID
unsafe fn get_current_activity_id() -> GUID {
    let mut id = CURRENT_ACTIVITY_ID;
    if id.data1 == 0 {
        let status = RtlRandomEx(&mut id.data1 as *mut u32, 0);
        if !NT_SUCCESS(status) {
            DbgPrint!("Random gen failed: 0x%X\0".as_ptr(), status);
            return GUID { data1: 0, data2: 0, data3: 0, data4: [0; 8] };  // Fallback zero
        }
        CURRENT_ACTIVITY_ID = id;
    }
    id
}

// Driver Entry
#[export_name = "DriverEntry"]
pub unsafe extern "system" fn driver_entry(
    driver: PDRIVER_OBJECT,
    _registry: PCUNICODE_STRING,
) -> NTSTATUS {
    let mut status = STATUS_SUCCESS;

    KeInitializeSpinLock(&mut QUEUE_LOCK);
    #[cfg(feature = "ai_agent")]
    {
        KeInitializeEvent(&mut AGENT_EVENT, NotificationEvent, FALSE);
    }

    status = PsSetCreateProcessNotifyRoutineEx(Some(process_notify_callback), FALSE);
    if !NT_SUCCESS(status) {
        DbgPrint!("Process notify reg failed: 0x%X\0".as_ptr(), status);
        return status;
    }

    #[cfg(feature = "threads")]
    {
        status = PsSetCreateThreadNotifyRoutine(Some(thread_notify_callback));
        if !NT_SUCCESS(status) {
            DbgPrint!("Thread notify reg failed: 0x%X\0".as_ptr(), status);
            return status;
        }
    }

    #[cfg(feature = "objects")]
    {
        let mut op_reg = OB_OPERATION_REGISTRATION {
            ObjectType: PsProcessType,
            Operations: OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
            PreOperation: Some(object_callback),
            PostOperation: None,
        };
        let mut cb_reg = OB_CALLBACK_REGISTRATION {
            Version: OB_FLT_REGISTRATION_VERSION,
            OperationRegistrationCount: 1,
            Altitude: RtlInitUnicodeString(r"320000\0"),
            RegistrationContext: core::ptr::null_mut(),
            OperationRegistration: &mut op_reg,
        };
        status = ObRegisterCallbacks(&cb_reg, &mut OBJECT_CALLBACK_HANDLE);
        if !NT_SUCCESS(status) {
            DbgPrint!("Object callback reg failed: 0x%X\0".as_ptr(), status);
            return status;
        }
    }

    let mut reg: FLT_REGISTRATION = core::mem::zeroed();
    reg.Size = core::mem::size_of::<FLT_REGISTRATION>() as USHORT;
    reg.Version = FLT_REGISTRATION_VERSION;
    reg.OperationRegistration = &OP_REG as *const _;
    reg.FilterUnloadCallback = Some(unload_callback);
    reg.ContextRegistration = &CONTEXT_REG as *const _;
    status = FltRegisterFilter(driver, &reg, &mut FILTER_HANDLE);
    if !NT_SUCCESS(status) {
        DbgPrint!("Filter reg failed: 0x%X\0".as_ptr(), status);
        return status;
    }
    status = FltStartFiltering(FILTER_HANDLE);
    if !NT_SUCCESS(status) {
        DbgPrint!("Start filtering failed: 0x%X\0".as_ptr(), status);
        FltUnregisterFilter(FILTER_HANDLE);
        return status;
    }

    let provider_guid: GUID = GUID { data1: 0x12345678, data2: 0xABCD, data3: 0xEF01, data4: [0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01] };
    status = EtwRegister(&provider_guid, None, core::ptr::null_mut(), &mut ETW_REG_HANDLE);
    if !NT_SUCCESS(status) {
        DbgPrint!("ETW reg failed: 0x%X\0".as_ptr(), status);
    }

    #[cfg(feature = "registry")]
    {
        let mut altitude: UNICODE_STRING = RtlInitUnicodeString(r"320000\0");
        status = CmRegisterCallbackEx(Some(registry_callback), &altitude, driver as PVOID, core::ptr::null_mut(), &mut REG_COOKIE, core::ptr::null_mut());
        if !NT_SUCCESS(status) {
            DbgPrint!("Registry callback reg failed: 0x%X\0".as_ptr(), status);
        }
    }

    #[cfg(feature = "network")]
    {
        let mut callout: FWPS_CALLOUT0 = core::mem::zeroed();
        callout.calloutKey = GUID { data1: 0x87654321, data2: 0xDCBA, data3: 0x10FE, data4: [0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 0x10] };
        callout.flags = 0;
        callout.classifyFn = Some(wfp_callout);
        status = FwpsCalloutRegister0(core::ptr::null_mut(), &callout, &mut WFP_CALLOUT_ID);
        if !NT_SUCCESS(status) {
            DbgPrint!("WFP callout reg failed: 0x%X\0".as_ptr(), status);
        }
    }

    let mut dev_name = RtlInitUnicodeString(r"\Device\EndpointMonitor\0");
    let mut device: PDEVICE_OBJECT = core::ptr::null_mut();
    status = IoCreateDevice(driver, 0, &mut dev_name, FILE_DEVICE_UNKNOWN, 0, FALSE, &mut device);
    if NT_SUCCESS(status) {
        (*driver).MajorFunction[IRP_MJ_DEVICE_CONTROL as usize] = Some(ioctl_handler);
    } else {
        DbgPrint!("Device create failed: 0x%X\0".as_ptr(), status);
        return status;
    }

    DbgPrint!("Driver Loaded\0".as_ptr());
    status
}

// Unload
unsafe extern "system" fn unload_callback(_flags: FLT_REGISTRATION_FLAGS) -> NTSTATUS {
    let mut status = STATUS_SUCCESS;

    let dereg_status = PsSetCreateProcessNotifyRoutineEx(Some(process_notify_callback), TRUE);
    if !NT_SUCCESS(dereg_status) {
        DbgPrint!("Process dereg failed: 0x%X\0".as_ptr(), dereg_status);
        status = dereg_status;
    }

    #[cfg(feature = "threads")]
    {
        let thread_dereg = PsRemoveCreateThreadNotifyRoutine(Some(thread_notify_callback));
        if !NT_SUCCESS(thread_dereg) {
            DbgPrint!("Thread dereg failed: 0x%X\0".as_ptr(), thread_dereg);
            status = thread_dereg;
        }
    }

    #[cfg(feature = "objects")]
    if !OBJECT_CALLBACK_HANDLE.is_null() {
        let ob_dereg = ObUnRegisterCallbacks(OBJECT_CALLBACK_HANDLE);
        if !NT_SUCCESS(ob_dereg) {
            DbgPrint!("Object dereg failed: 0x%X\0".as_ptr(), ob_dereg);
            status = ob_dereg;
        }
    }

    let filt_dereg = FltUnregisterFilter(FILTER_HANDLE);
    if !NT_SUCCESS(filt_dereg) {
        DbgPrint!("Filter dereg failed: 0x%X\0".as_ptr(), filt_dereg);
        status = filt_dereg;
    }

    if ETW_REG_HANDLE != 0 {
        let etw_dereg = EtwUnregister(ETW_REG_HANDLE);
        if !NT_SUCCESS(etw_dereg) {
            DbgPrint!("ETW dereg failed: 0x%X\0".as_ptr(), etw_dereg);
            status = etw_dereg;
        }
    }

    #[cfg(feature = "registry")]
    {
        let reg_dereg = CmUnRegisterCallback(REG_COOKIE);
        if !NT_SUCCESS(reg_dereg) {
            DbgPrint!("Registry dereg failed: 0x%X\0".as_ptr(), reg_dereg);
            status = reg_dereg;
        }
    }

    #[cfg(feature = "network")]
    {
        let net_dereg = FwpsCalloutUnregisterById0(WFP_CALLOUT_ID);
        if !NT_SUCCESS(net_dereg) {
            DbgPrint!("WFP dereg failed: 0x%X\0".as_ptr(), net_dereg);
            status = net_dereg;
        }
    }

    #[cfg(feature = "ai_agent")]
    KeClearEvent(&mut AGENT_EVENT);

    status
}

// Operation Registration
static OP_REG: [FLT_OPERATION_REGISTRATION; 4] = [
    FLT_OPERATION_REGISTRATION { MajorFunction: IRP_MJ_CREATE, Flags: 0, PreOperation: Some(pre_operation_callback), PostOperation: None, Reserved1: 0 },
    FLT_OPERATION_REGISTRATION { MajorFunction: IRP_MJ_READ, Flags: 0, PreOperation: Some(pre_operation_callback), PostOperation: None, Reserved1: 0 },
    FLT_OPERATION_REGISTRATION { MajorFunction: IRP_MJ_WRITE, Flags: 0, PreOperation: Some(pre_operation_callback), PostOperation: None, Reserved1: 0 },
    FLT_OPERATION_REGISTRATION { MajorFunction: IRP_MJ_OPERATION_END, Flags: 0, PreOperation: None, PostOperation: None, Reserved1: 0 },
];

// Context Registration
static CONTEXT_REG: [FLT_CONTEXT_REGISTRATION; 2] = [
    FLT_CONTEXT_REGISTRATION {
        ContextType: FLT_STREAM_CONTEXT,
        Flags: 0,
        ContextCleanupCallback: Some(context_cleanup_callback),
        Size: core::mem::size_of::<MonitorStreamContext>() as usize,
        PoolTag: TAG_CONTEXT,
    },
    FLT_CONTEXT_REGISTRATION { ContextType: FLT_CONTEXT_END, Flags: 0, ContextCleanupCallback: None, Size: 0, PoolTag: 0 },
];