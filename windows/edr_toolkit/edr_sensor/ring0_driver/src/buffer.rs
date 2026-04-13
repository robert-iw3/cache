#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;

    const MAX_EVENTS: usize = 4096;
    const MAX_QUARANTINE_PIDS: usize = 128;

    // --- Mock Data Structures ---
    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub struct MonitorEvent {
        pub valid: u32,
        pub event_type: u32,
        pub anomaly_score_fixed: u32,
        pub pid: usize, // Mocking HANDLE as usize for testing
    }

    // --- Mock Global State ---
    static mut TEST_QUEUE: [MonitorEvent; MAX_EVENTS] = unsafe { core::mem::zeroed() };
    static TEST_HEAD: AtomicUsize = AtomicUsize::new(0);
    static TEST_TAIL: AtomicUsize = AtomicUsize::new(0);

    // Mocking the new V3 Quarantine State Tracker
    static mut QUARANTINED_PIDS: [usize; MAX_QUARANTINE_PIDS] = [0; MAX_QUARANTINE_PIDS];
    lazy_static::lazy_static! {
        static ref QUARANTINE_LOCK: Mutex<()> = Mutex::new(());
    }

    // --- Mock Kernel Functions ---
    unsafe fn mock_log_event(event_type: u32, score: u32, pid: usize) {
        let tail_idx = TEST_TAIL.fetch_add(1, Ordering::Relaxed) % MAX_EVENTS;
        let event = &mut TEST_QUEUE[tail_idx];

        event.valid = 1; // Mark writing
        event.event_type = event_type;
        event.anomaly_score_fixed = score;
        event.pid = pid;

        // Release barrier ensures data is fully written before marking valid
        std::sync::atomic::fence(Ordering::Release);
        event.valid = 2; // Mark ready
    }

    unsafe fn mock_quarantine_pid(pid: usize) {
        let _guard = QUARANTINE_LOCK.lock().unwrap();
        for i in 0..MAX_QUARANTINE_PIDS {
            if QUARANTINED_PIDS[i] == 0 {
                QUARANTINED_PIDS[i] = pid;
                break;
            }
        }
    }

    unsafe fn mock_is_pid_quarantined(pid: usize) -> bool {
        let _guard = QUARANTINE_LOCK.lock().unwrap();
        for i in 0..MAX_QUARANTINE_PIDS {
            if QUARANTINED_PIDS[i] == pid && pid != 0 {
                return true;
            }
        }
        false
    }

    // =====================================================================
    // TEST 1: Lock-Free Concurrency (High-Volume OS Telemetry Spikes)
    // =====================================================================
    #[test]
    fn test_lock_free_concurrency() {
        // Reset state
        TEST_HEAD.store(0, Ordering::SeqCst);
        TEST_TAIL.store(0, Ordering::SeqCst);
        unsafe { TEST_QUEUE = core::mem::zeroed(); }

        let mut handles = vec![];
        // 4 Producers (OS Callbacks) generating 10,000 events total
        for _ in 0..4 {
            handles.push(thread::spawn(|| {
                for i in 0..2500 {
                    unsafe { mock_log_event(1, i, 100); }
                }
            }));
        }

        // 1 Consumer (C# Orchestrator via IOCTL)
        let consumer = thread::spawn(|| {
            let mut consumed = 0;
            while consumed < 10000 {
                let head = TEST_HEAD.load(Ordering::Relaxed);
                let tail = TEST_TAIL.load(Ordering::Relaxed);

                if head != tail {
                    let idx = head % MAX_EVENTS;
                    unsafe {
                        if TEST_QUEUE[idx].valid == 2 {
                            TEST_QUEUE[idx].valid = 0; // Invalidate slot
                            TEST_HEAD.fetch_add(1, Ordering::Release);
                            consumed += 1;
                        }
                    }
                }
            }
            assert_eq!(consumed, 10000);
        });

        for h in handles { h.join().unwrap(); }
        consumer.join().unwrap();
    }

    // =====================================================================
    // TEST 2: Ring Buffer Wrap-Around & Memory Alignment
    // =====================================================================
    #[test]
    fn test_ring_buffer_wrap_around() {
        // Force the HEAD and TAIL to start near the usize boundary to test modulo math
        let near_max = usize::MAX - 100;
        TEST_HEAD.store(near_max, Ordering::SeqCst);
        TEST_TAIL.store(near_max, Ordering::SeqCst);
        unsafe { TEST_QUEUE = core::mem::zeroed(); }

        unsafe {
            // Log 200 events, forcing it to wrap past usize::MAX
            for i in 0..200 {
                mock_log_event(2, i, 500);
            }
        }

        let mut consumed = 0;
        let mut current_head = TEST_HEAD.load(Ordering::Relaxed);
        let current_tail = TEST_TAIL.load(Ordering::Relaxed);

        while current_head != current_tail {
            let idx = current_head % MAX_EVENTS;
            unsafe {
                assert_eq!(TEST_QUEUE[idx].valid, 2, "Event slot was not marked valid during wrap-around");
                TEST_QUEUE[idx].valid = 0;
            }
            current_head = current_head.wrapping_add(1); // Safely wrap
            consumed += 1;
        }

        assert_eq!(consumed, 200, "Consumer missed events during usize wrap-around");
    }

    // =====================================================================
    // TEST 3: V3 Active Defense - Quarantine IPC Thread Safety
    // =====================================================================
    #[test]
    fn test_quarantine_array_concurrency() {
        unsafe { QUARANTINED_PIDS = [0; MAX_QUARANTINE_PIDS]; }

        let mut handles = vec![];

        // Thread 1: C# Orchestrator dropping PIDs down to Ring-0
        handles.push(thread::spawn(|| {
            for pid in 1000..1050 {
                unsafe { mock_quarantine_pid(pid); }
            }
        }));

        // Thread 2: Minifilter continuously checking PIDs during File I/O
        handles.push(thread::spawn(|| {
            for _ in 0..500 {
                // Should not deadlock or crash during read/write contention
                unsafe { mock_is_pid_quarantined(1025); }
            }
        }));

        for h in handles { h.join().unwrap(); }

        // Validate state was accurately recorded
        unsafe {
            assert!(mock_is_pid_quarantined(1000), "Failed to find first quarantined PID");
            assert!(mock_is_pid_quarantined(1049), "Failed to find last quarantined PID");
            assert!(!mock_is_pid_quarantined(9999), "False positive found in quarantine array");
        }
    }
}