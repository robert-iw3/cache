use windows::Win32::Foundation::{CloseHandle, HANDLE, NTSTATUS};
use windows::Win32::System::Ioctl::CTL_CODE;
use windows::Win32::Storage::FileSystem::{CreateFileW, FILE_ATTRIBUTE_NORMAL, GENERIC_READ, GENERIC_WRITE, OPEN_EXISTING};
use windows::Win32::System::WindowsProgramming::{IOCTL_METHOD_BUFFERED, FILE_ANY_ACCESS};

use std::mem::size_of;
use std::thread::sleep;
use std::time::Duration;
use log::{info, warn, error, LevelFilter};

// Mirror kernel's MonitorEvent (Adopted fixed-score)
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct MonitorEvent {
    event_type: u32,
    pid: isize,
    parent_pid: isize,
    timestamp: i64,
    path_len: u16,
    path: [u16; 260],
    anomaly_score_fixed: u32,  // Adopted
    syscall_id: u32,
    event_id: u64,
    hash: [u8; 32],
    activity_id: [u8; 16],  // GUID bytes
    cloud_context: [u8; 64],
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::builder().filter_level(LevelFilter::Info).init();

    info!("Pilot App starting: Polling kernel driver...");

    unsafe {
        let h_device = CreateFileW(
            r"\\.\EndpointMonitor\0".as_ptr(),
            GENERIC_READ.0 | GENERIC_WRITE.0,
            0,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE(0),
        )?;

        if h_device == windows::Win32::Foundation::INVALID_HANDLE_VALUE {
            error!("Failed to open device.");
            return Err("Device open failed".into());
        }

        info!("Device opened successfully.");

        loop {
            let mut events: [MonitorEvent; 10] = std::mem::zeroed();
            let mut returned: u32 = 0;

            let ioctl_code = CTL_CODE(0x8000, 1, IOCTL_METHOD_BUFFERED, FILE_ANY_ACCESS);

            let status: NTSTATUS = windows::Win32::System::Ioctl::DeviceIoControl(
                h_device,
                ioctl_code,
                None,
                0,
                Some(events.as_mut_ptr() as _),
                (size_of::<MonitorEvent>() * 10) as u32,
                Some(&mut returned),
                None,
            );

            if !windows::Win32::Foundation::NT_SUCCESS(status) {
                warn!("IOCTL failed: 0x{:X}", status.0);
                sleep(Duration::from_secs(1));
                continue;
            }

            let event_count = returned as usize / size_of::<MonitorEvent>();
            info!("Fetched {} events.", event_count);

            for i in 0..event_count {
                let ev = events[i];
                let score = ev.anomaly_score_fixed as f32 / 1000.0;  // Adopted conversion
                let path_str = String::from_utf16_lossy(&ev.path[0..ev.path_len as usize]);
                let activity_str = format!("{:02x}{:02x}{:02x}{:02x}", ev.activity_id[0], ev.activity_id[1], ev.activity_id[2], ev.activity_id[3]);  // Partial GUID display

                info!("Event {}: Type={}, PID=0x{:X}, Path='{}', Activity='{}'", i, ev.event_type, ev.pid, path_str, activity_str);

                if score > 0.8 {
                    warn!("Anomaly: Type={}, Score={:.2}", ev.event_type, score);
                }
            }

            sleep(Duration::from_millis(100));  // Adopted faster poll
        }

        CloseHandle(h_device);
    }

    Ok(())
}