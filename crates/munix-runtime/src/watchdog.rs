//! The watchdog (invariant 10): a stalled or spinning agent is an attack, so a deterministic timer ends it.
//!
//! It polls a snapshot of progress (from the model gateway and the MCP channel) and trips once on the first limit
//! crossed. It can't make an agent useful; it bounds how long and how expensively it can be stalled.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// The limits. Code defaults; a plan may only tighten them (not wired yet).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// No tool call and no model call for this long.
    pub liveness: Duration,
    /// The whole task, from `start`.
    pub deadline: Duration,
    /// Model calls since the last completed step.
    pub spin_calls: u64,
    /// Model tokens (prompt plus completion) since the last completed step.
    pub spin_tokens: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            liveness: Duration::from_secs(60),
            deadline: Duration::from_secs(600),
            spin_calls: 20,
            spin_tokens: 120_000,
        }
    }
}

/// One reading of progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snapshot {
    /// The latest tool or model call.
    pub last_activity: Instant,
    /// Model calls and tokens so far (cumulative, from the gateway).
    pub model_calls: u64,
    pub model_tokens: u64,
    /// Plan steps completed so far (cumulative, from the Gate front: executed calls that delivered output).
    pub steps_completed: u64,
}

/// Which limit was crossed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trip {
    Liveness,
    Deadline,
    SpinBudget,
}

/// Time, injectable for tests.
pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
    fn sleep(&self, d: Duration);
}

/// The real clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn sleep(&self, d: Duration) {
        std::thread::sleep(d);
    }
}

/// Decides whether a snapshot crosses a limit. Pure. `baseline` is the snapshot taken when `steps_completed` last
/// changed (or at start): spin counts are `snapshot - baseline`. Checked in this order: deadline, liveness, spin
/// calls, spin tokens. `None` when within all limits.
pub fn check(
    limits: &Limits,
    start: Instant,
    now: Instant,
    baseline: &Snapshot,
    snapshot: &Snapshot,
) -> Option<Trip> {
    if now.saturating_duration_since(start) > limits.deadline {
        return Some(Trip::Deadline);
    }
    if now.saturating_duration_since(snapshot.last_activity) > limits.liveness {
        return Some(Trip::Liveness);
    }
    if snapshot.model_calls.saturating_sub(baseline.model_calls) > limits.spin_calls {
        return Some(Trip::SpinBudget);
    }
    if snapshot.model_tokens.saturating_sub(baseline.model_tokens) > limits.spin_tokens {
        return Some(Trip::SpinBudget);
    }
    None
}

/// A running watchdog. Dropping it (or calling `stop`) stops it without tripping.
pub struct Watchdog {
    stopped: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Watchdog {
    /// Starts a background thread that, every `poll` (use 1 s), reads `progress()`, moves the baseline whenever
    /// `steps_completed` rises, and calls [`check`]. On the first trip it calls `on_trip` once and exits. `start` is
    /// `clock.now()` when this is called.
    pub fn start(
        limits: Limits,
        poll: Duration,
        clock: Arc<dyn Clock>,
        progress: Arc<dyn Fn() -> Snapshot + Send + Sync>,
        on_trip: Box<dyn FnOnce(Trip) + Send>,
    ) -> Watchdog {
        let start = clock.now();
        let mut baseline = progress();
        let stopped = Arc::new(AtomicBool::new(false));
        let thread_stopped = Arc::clone(&stopped);
        let handle = thread::spawn(move || {
            while !thread_stopped.load(Ordering::Acquire) {
                clock.sleep(poll);
                if thread_stopped.load(Ordering::Acquire) {
                    break;
                }
                let snapshot = progress();
                if snapshot.steps_completed > baseline.steps_completed {
                    baseline = snapshot;
                }
                let now = clock.now();
                if let Some(trip) = check(&limits, start, now, &baseline, &snapshot) {
                    if !thread_stopped.load(Ordering::Acquire) {
                        on_trip(trip);
                    }
                    break;
                }
            }
        });
        Watchdog {
            stopped,
            handle: Some(handle),
        }
    }

    /// Stops the thread and waits for it, without tripping.
    pub fn stop(self) {
        drop(self);
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_snapshot(now: Instant) -> Snapshot {
        Snapshot {
            last_activity: now,
            model_calls: 0,
            model_tokens: 0,
            steps_completed: 0,
        }
    }

    #[test]
    fn check_within_all_limits_returns_none() {
        let start = Instant::now();
        let limits = Limits::default();
        let baseline = base_snapshot(start);
        let snapshot = Snapshot {
            last_activity: start + Duration::from_secs(30),
            model_calls: limits.spin_calls,
            model_tokens: limits.spin_tokens,
            steps_completed: 0,
        };
        let now = start + Duration::from_secs(30);
        assert_eq!(check(&limits, start, now, &baseline, &snapshot), None);
    }

    #[test]
    fn check_deadline_exact_boundary_and_trip() {
        let start = Instant::now();
        let limits = Limits::default();
        let baseline = base_snapshot(start);
        let at_deadline = start + limits.deadline;
        let snapshot = Snapshot {
            last_activity: at_deadline,
            ..baseline
        };
        assert_eq!(
            check(&limits, start, at_deadline, &baseline, &snapshot),
            None
        );

        let one_past = at_deadline + Duration::from_nanos(1);
        let snapshot_past = Snapshot {
            last_activity: one_past,
            ..baseline
        };
        assert_eq!(
            check(&limits, start, one_past, &baseline, &snapshot_past),
            Some(Trip::Deadline)
        );
    }

    #[test]
    fn check_liveness_exact_boundary_and_trip() {
        let start = Instant::now();
        let limits = Limits::default();
        let baseline = base_snapshot(start);
        let at_liveness = start + limits.liveness;
        assert_eq!(
            check(&limits, start, at_liveness, &baseline, &baseline),
            None
        );

        let one_past = at_liveness + Duration::from_nanos(1);
        assert_eq!(
            check(&limits, start, one_past, &baseline, &baseline),
            Some(Trip::Liveness)
        );
    }

    #[test]
    fn check_spin_calls_exact_boundary_and_trip() {
        let start = Instant::now();
        let limits = Limits::default();
        let baseline = base_snapshot(start);
        let at_limit = Snapshot {
            model_calls: limits.spin_calls,
            ..baseline
        };
        assert_eq!(check(&limits, start, start, &baseline, &at_limit), None);

        let one_past = Snapshot {
            model_calls: limits.spin_calls + 1,
            ..baseline
        };
        assert_eq!(
            check(&limits, start, start, &baseline, &one_past),
            Some(Trip::SpinBudget)
        );
    }

    #[test]
    fn check_spin_tokens_exact_boundary_and_trip() {
        let start = Instant::now();
        let limits = Limits::default();
        let baseline = base_snapshot(start);
        let at_limit = Snapshot {
            model_tokens: limits.spin_tokens,
            ..baseline
        };
        assert_eq!(check(&limits, start, start, &baseline, &at_limit), None);

        let one_past = Snapshot {
            model_tokens: limits.spin_tokens + 1,
            ..baseline
        };
        assert_eq!(
            check(&limits, start, start, &baseline, &one_past),
            Some(Trip::SpinBudget)
        );
    }

    #[test]
    fn check_spin_counted_from_baseline() {
        let start = Instant::now();
        let limits = Limits::default();
        let baseline = Snapshot {
            last_activity: start,
            model_calls: 50,
            model_tokens: 250_000,
            steps_completed: 2,
        };
        let within = Snapshot {
            last_activity: start,
            model_calls: 50 + limits.spin_calls,
            model_tokens: 250_000 + limits.spin_tokens,
            steps_completed: 2,
        };
        assert_eq!(check(&limits, start, start, &baseline, &within), None);

        let calls_past = Snapshot {
            model_calls: 50 + limits.spin_calls + 1,
            ..within
        };
        assert_eq!(
            check(&limits, start, start, &baseline, &calls_past),
            Some(Trip::SpinBudget)
        );

        let tokens_past = Snapshot {
            model_tokens: 250_000 + limits.spin_tokens + 1,
            ..within
        };
        assert_eq!(
            check(&limits, start, start, &baseline, &tokens_past),
            Some(Trip::SpinBudget)
        );
    }

    #[test]
    fn check_priority_order() {
        let start = Instant::now();
        let limits = Limits::default();
        let baseline = base_snapshot(start);

        // All four crossed: deadline wins over liveness and spin.
        let now_all = start + limits.deadline + Duration::from_secs(1);
        let snap_all = Snapshot {
            last_activity: start,
            model_calls: limits.spin_calls + 1,
            model_tokens: limits.spin_tokens + 1,
            steps_completed: 0,
        };
        assert_eq!(
            check(&limits, start, now_all, &baseline, &snap_all),
            Some(Trip::Deadline)
        );

        // Liveness + spin calls + spin tokens crossed (deadline not crossed): liveness wins.
        let now_liveness = start + limits.liveness + Duration::from_secs(1);
        assert_eq!(
            check(&limits, start, now_liveness, &baseline, &snap_all),
            Some(Trip::Liveness)
        );

        // Spin calls + spin tokens crossed (deadline and liveness not crossed): spin wins.
        let snap_spin_both = Snapshot {
            last_activity: now_liveness,
            ..snap_all
        };
        assert_eq!(
            check(&limits, start, now_liveness, &baseline, &snap_spin_both),
            Some(Trip::SpinBudget)
        );

        // Only spin tokens crossed: still trips SpinBudget.
        let snap_spin_tokens = Snapshot {
            last_activity: now_liveness,
            model_calls: limits.spin_calls,
            model_tokens: limits.spin_tokens + 1,
            steps_completed: 0,
        };
        assert_eq!(
            check(&limits, start, now_liveness, &baseline, &snap_spin_tokens),
            Some(Trip::SpinBudget)
        );
    }
}
