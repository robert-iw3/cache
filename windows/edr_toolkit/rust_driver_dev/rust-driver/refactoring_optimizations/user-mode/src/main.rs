use windows::Win32::Foundation::{HANDLE, NTSTATUS, INVALID_HANDLE_VALUE};
use windows::Win32::System::Ioctl::CTL_CODE;
use windows::Win32::Storage::FileSystem::{CreateFileW, FILE_ATTRIBUTE_NORMAL, GENERIC_READ, GENERIC_WRITE, OPEN_EXISTING, FILE_FLAG_OVERLAPPED};
use windows::Win32::System::WindowsProgramming::{IOCTL_METHOD_BUFFERED, FILE_ANY_ACCESS};
use std::mem::size_of;
use log::{info, warn, LevelFilter};

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct MonitorEvent {
    pub event_type: u32,
    pub pid: isize,
    pub parent_pid: isize,
    pub timestamp: i64,
    pub path_len: u16,
    pub path: [u16; 260],
    pub anomaly_score_fixed: u32,
    pub syscall_id: u32,
    pub event_id: u64,
    pub hash: [u8; 32],
    pub activity_id: [u8; 16],
    pub cloud_context: [u8; 64],
    pub valid: u32,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::builder().filter_level(LevelFilter::Info).init();

    unsafe {
        // Open handle
        let h = CreateFileW(windows::core::w!(r"\\.\EndpointMonitor\0"), GENERIC_READ.0 | GENERIC_WRITE.0, 0, None, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, HANDLE(0))?;
        if h == INVALID_HANDLE_VALUE { return Err("Failed to open driver handle".into()); }

        info!("Connected to Kernel Driver via Inverted Call (Push Model)...");

        loop {
            let mut events = [std::mem::zeroed::<MonitorEvent>(); 50];
            let mut ret: u32 = 0;
            let code = CTL_CODE(0x8000, 1, IOCTL_METHOD_BUFFERED, FILE_ANY_ACCESS);

            // This call will BLOCK until the driver provides data (or cancels)
            // No CPU usage while waiting!
            let status: NTSTATUS = windows::Win32::System::Ioctl::DeviceIoControl(
                h, code, None, 0,
                Some(events.as_mut_ptr() as _), (size_of::<MonitorEvent>() * 50) as u32,
                Some(&mut ret), None
            );

            if status.is_ok() {
                let count = ret as usize / size_of::<MonitorEvent>();
                if count > 0 {
                    info!("Received batch of {} events", count);
                    for i in 0..count {
                        let ev = events[i];
                        let score = ev.anomaly_score_fixed as f32 / 1000.0;
                        let path = String::from_utf16_lossy(&ev.path[..ev.path_len as usize]);

                        if score > 0.8 {
                            warn!("🚨 BLOCKED: Type {} | PID {:X} | Score {:.2} | {}", ev.event_type, ev.pid, score, path);
                        } else {
                            info!("Type {} | PID {:X} | {}", ev.event_type, ev.pid, path);
                        }
                    }
                }
            } else {
                // If it failed (e.g. driver unloaded), break loop
                warn!("Driver communication stopped (Status: {:?})", status);
                break;
            }
        }
    }
    Ok(())
}