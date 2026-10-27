use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::{Duration, Instant};

use munix_runtime::watchdog::{Clock, Limits, Snapshot, Trip, Watchdog};

struct FakeClock {
    now: Arc<Mutex<Instant>>,
    sleeps: AtomicU64,
    sleep_pause: Duration,
}

impl FakeClock {
    fn new(start: Instant) -> Arc<Self> {
        Arc::new(Self {
            now: Arc::new(Mutex::new(start)),
            sleeps: AtomicU64::new(0),
            sleep_pause: Duration::ZERO,
        })
    }

    fn with_pause(start: Instant, sleep_pause: Duration) -> Arc<Self> {
        Arc::new(Self {
            now: Arc::new(Mutex::new(start)),
            sleeps: AtomicU64::new(0),
            sleep_pause,
        })
    }
}

impl Clock for FakeClock {
    fn now(&self) -> Instant {
        *self.now.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn sleep(&self, d: Duration) {
        if !self.sleep_pause.is_zero() {
            std::thread::sleep(self.sleep_pause);
        }
        let mut now = self.now.lock().unwrap_or_else(|e| e.into_inner());
        *now += d;
        self.sleeps.fetch_add(1, Ordering::SeqCst);
    }
}

#[derive(Clone, Copy)]
struct SharedCounters {
    last_activity: Instant,
    model_calls: u64,
    model_tokens: u64,
    steps_completed: u64,
}

#[test]
fn liveness_trip() {
    let start = Instant::now();
    let clock = FakeClock::new(start);
    let counters = Arc::new(Mutex::new(SharedCounters {
        last_activity: start,
        model_calls: 0,
        model_tokens: 0,
        steps_completed: 0,
    }));

    let progress_counters = Arc::clone(&counters);
    let progress = Arc::new(move || {
        let c = progress_counters.lock().unwrap();
        Snapshot {
            last_activity: c.last_activity,
            model_calls: c.model_calls,
            model_tokens: c.model_tokens,
            steps_completed: c.steps_completed,
        }
    });

    let (tx, rx) = mpsc::channel();
    let watchdog = Watchdog::start(
        Limits::default(),
        Duration::from_secs(10),
        clock.clone(),
        progress,
        Box::new(move |trip| {
            let _ = tx.send(trip);
        }),
    );

    let trip = rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_eq!(trip, Trip::Liveness);
    // 60s liveness with 10s poll: trips on poll 7 (at 70s > 60s).
    assert_eq!(clock.sleeps.load(Ordering::SeqCst), 7);
    watchdog.stop();
}

#[test]
fn deadline_trip() {
    let start = Instant::now();
    let clock = FakeClock::new(start);
    let counters = Arc::new(Mutex::new(SharedCounters {
        last_activity: start,
        model_calls: 0,
        model_tokens: 0,
        steps_completed: 0,
    }));

    let progress_clock = Arc::clone(&clock);
    let progress_counters = Arc::clone(&counters);
    let progress = Arc::new(move || {
        let mut c = progress_counters.lock().unwrap();
        // Agent stays active so liveness never trips.
        c.last_activity = progress_clock.now();
        Snapshot {
            last_activity: c.last_activity,
            model_calls: c.model_calls,
            model_tokens: c.model_tokens,
            steps_completed: c.steps_completed,
        }
    });

    let (tx, rx) = mpsc::channel();
    let watchdog = Watchdog::start(
        Limits::default(),
        Duration::from_secs(100),
        clock.clone(),
        progress,
        Box::new(move |trip| {
            let _ = tx.send(trip);
        }),
    );

    let trip = rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_eq!(trip, Trip::Deadline);
    // 600s deadline with 100s poll: trips on poll 7 (at 700s > 600s).
    assert_eq!(clock.sleeps.load(Ordering::SeqCst), 7);
    watchdog.stop();
}

#[test]
fn spin_trip_avoided_when_steps_rise_then_trips_when_stalled() {
    let start = Instant::now();
    let clock = FakeClock::new(start);
    let limits = Limits {
        liveness: Duration::from_secs(60),
        deadline: Duration::from_secs(600),
        spin_calls: 10,
        spin_tokens: 1_000,
    };

    let counters = Arc::new(Mutex::new(SharedCounters {
        last_activity: start,
        model_calls: 0,
        model_tokens: 0,
        steps_completed: 0,
    }));

    let progress_clock = Arc::clone(&clock);
    let progress_counters = Arc::clone(&counters);
    let poll_num = Arc::new(AtomicU64::new(0));
    let progress_poll = Arc::clone(&poll_num);

    let progress = Arc::new(move || {
        let mut c = progress_counters.lock().unwrap();
        let n = progress_poll.fetch_add(1, Ordering::SeqCst);
        c.last_activity = progress_clock.now();
        if n == 0 {
            // Initial baseline read in Watchdog::start.
        } else if n <= 3 {
            // Polls 1..=3: each poll uses 8 calls and 800 tokens, and completes a step.
            // Cumulative calls reach 24 (> 10) and tokens reach 2,400 (> 1,000),
            // but baseline moves on every step so spin budget does not trip.
            c.model_calls += 8;
            c.model_tokens += 800;
            c.steps_completed += 1;
        } else {
            // Poll 4+: steps stop rising while calls/tokens keep growing from step 3's baseline (24 calls).
            // Poll 4 adds 6 calls (delta 6 <= 10), poll 5 adds 5 calls (delta 11 > 10 -> SpinBudget trip).
            c.model_calls += if n == 4 { 6 } else { 5 };
            c.model_tokens += 100;
        }
        Snapshot {
            last_activity: c.last_activity,
            model_calls: c.model_calls,
            model_tokens: c.model_tokens,
            steps_completed: c.steps_completed,
        }
    });

    let (tx, rx) = mpsc::channel();
    let watchdog = Watchdog::start(
        limits,
        Duration::from_secs(1),
        clock.clone(),
        progress,
        Box::new(move |trip| {
            let _ = tx.send(trip);
        }),
    );

    let trip = rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_eq!(trip, Trip::SpinBudget);
    // Polls 1..=3 advanced steps_completed (avoiding spin trip at cumulative 16 and 24 calls);
    // poll 4 had delta 6; poll 5 had delta 11 > 10 and tripped.
    assert_eq!(clock.sleeps.load(Ordering::SeqCst), 5);
    assert_eq!(counters.lock().unwrap().steps_completed, 3);
    assert_eq!(counters.lock().unwrap().model_calls, 35);
    watchdog.stop();
}

#[test]
fn stop_without_trip_never_calls_on_trip() {
    let start = Instant::now();
    let clock = FakeClock::with_pause(start, Duration::from_millis(1));
    let counters = Arc::new(Mutex::new(SharedCounters {
        last_activity: start,
        model_calls: 0,
        model_tokens: 0,
        steps_completed: 0,
    }));

    let poll_pair = Arc::new((Mutex::new(0u64), Condvar::new()));
    let progress_pair = Arc::clone(&poll_pair);
    let progress_clock = Arc::clone(&clock);
    let progress_counters = Arc::clone(&counters);

    let progress = Arc::new(move || {
        let mut c = progress_counters.lock().unwrap();
        c.last_activity = progress_clock.now();
        let snap = Snapshot {
            last_activity: c.last_activity,
            model_calls: c.model_calls,
            model_tokens: c.model_tokens,
            steps_completed: c.steps_completed,
        };
        let (lock, cvar) = &*progress_pair;
        let mut polls = lock.lock().unwrap();
        *polls += 1;
        cvar.notify_all();
        snap
    });

    let trip_count = Arc::new(AtomicUsize::new(0));
    let trip_count_clone = Arc::clone(&trip_count);

    let watchdog = Watchdog::start(
        Limits::default(),
        Duration::from_secs(1),
        clock,
        progress,
        Box::new(move |_trip| {
            trip_count_clone.fetch_add(1, Ordering::SeqCst);
        }),
    );

    // Wait for initial baseline read + at least 3 loop polls, all within limits.
    {
        let (lock, cvar) = &*poll_pair;
        let mut polls = lock.lock().unwrap();
        while *polls < 4 {
            polls = cvar.wait(polls).unwrap();
        }
    }

    watchdog.stop();
    assert_eq!(trip_count.load(Ordering::SeqCst), 0);
}

#[test]
fn on_trip_runs_exactly_once() {
    let start = Instant::now();
    let clock = FakeClock::new(start);
    let counters = Arc::new(Mutex::new(SharedCounters {
        last_activity: start,
        model_calls: 25,
        model_tokens: 0,
        steps_completed: 0,
    }));

    let progress_counters = Arc::clone(&counters);
    let call_num = Arc::new(AtomicU64::new(0));
    let progress_call = Arc::clone(&call_num);
    let progress = Arc::new(move || {
        let n = progress_call.fetch_add(1, Ordering::SeqCst);
        let c = progress_counters.lock().unwrap();
        Snapshot {
            last_activity: c.last_activity,
            // 0 at baseline, then 25 on first poll (> 20 default spin_calls).
            model_calls: if n == 0 { 0 } else { c.model_calls },
            model_tokens: c.model_tokens,
            steps_completed: c.steps_completed,
        }
    });

    let trip_count = Arc::new(AtomicUsize::new(0));
    let trip_count_clone = Arc::clone(&trip_count);
    let (tx, rx) = mpsc::channel();

    let watchdog = Watchdog::start(
        Limits::default(),
        Duration::from_secs(1),
        clock.clone(),
        progress,
        Box::new(move |trip| {
            trip_count_clone.fetch_add(1, Ordering::SeqCst);
            let _ = tx.send(trip);
        }),
    );

    let trip = rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_eq!(trip, Trip::SpinBudget);
    // Give the thread a moment to verify it exited and does not poll or trip again.
    std::thread::sleep(Duration::from_millis(5));
    watchdog.stop();
    assert_eq!(trip_count.load(Ordering::SeqCst), 1);
    assert_eq!(clock.sleeps.load(Ordering::SeqCst), 1);
}
