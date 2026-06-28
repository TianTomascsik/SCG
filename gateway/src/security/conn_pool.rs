//! Elastic connection thread pool — a base set of worker threads handles
//! connections. Safety pools may spawn overflow threads on demand when all
//! workers are busy; normal pools queue behind their bounded worker set.
//!
//! Relay tasks are long-lived (they run for the entire connection lifetime),
//! so a fixed pool would stall connections when concurrency exceeds pool
//! size.  The elastic design keeps the benefits of thread reuse under
//! normal load while preserving safety CPU capacity under normal-traffic bursts.
//!
//! Benefits:
//! - Eliminates thread creation/teardown overhead under normal load
//! - Keeps CPU caches warm (base workers stay on the same cores)
//! - Automatically scales safety handling up for high-concurrency bursts
//! - Bounds normal traffic CPU consumption under overload

use crate::management::config::TrafficClass;
use crate::networking::socket_manager::apply_safety_priority;
use log::{debug, warn};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;

type Job = Box<dyn FnOnce() + Send + 'static>;

/// Guaranteed minimum number of base worker threads reserved for a safety
/// pool, so safety relays always have dedicated capacity even on low-CPU hosts
/// where `default_size()` would otherwise be tiny.
const SAFETY_MIN_WORKERS: usize = 2;

/// Ceiling on concurrently-live overflow threads for a safety pool. Bounds the
/// blast radius of a connection storm: without it, every job submitted while
/// the base workers are busy spawns a fresh OS thread, so a flood can exhaust
/// thread/stack/scheduler resources. Over-cap jobs queue on the base workers
/// instead of spawning. Sized for bursty storms without unbounded growth.
const DEFAULT_MAX_OVERFLOW: usize = 64;

/// An elastic thread pool for connection handling.
///
/// Maintains a base set of long-lived worker threads.  When a safety job is
/// submitted and no base worker is idle, a temporary overflow thread is spawned
/// to handle the job immediately. Normal jobs queue behind the base workers
/// instead of spawning unbounded extra threads.
///
/// The pool is *class-aware*: a [`TrafficClass::Safety`] pool reserves a
/// minimum worker count and runs every worker (base and overflow) at elevated
/// scheduling priority. Normal pools do not spawn overflow threads, so a
/// normal-traffic connection storm cannot multiply runnable normal workers until
/// they compete with the reserved safety capacity.
pub struct ConnectionPool {
    sender: mpsc::Sender<Job>,
    idle_count: Arc<AtomicUsize>,
    /// Live overflow threads (spawned beyond the base workers). Bounded by
    /// `max_overflow`; decremented when each overflow thread exits.
    overflow_count: Arc<AtomicUsize>,
    /// Maximum concurrently-live overflow threads (0 = no overflow allowed).
    max_overflow: usize,
    name_prefix: String,
    class: TrafficClass,
    _workers: Vec<thread::JoinHandle<()>>,
}

impl ConnectionPool {
    /// Create a new `Normal`-class pool with `size` base worker threads.
    pub fn new(size: usize, name_prefix: &str) -> Self {
        Self::new_for_class(size, name_prefix, TrafficClass::Normal)
    }

    /// Create a new pool for the given traffic `class`.
    ///
    /// `Safety` pools reserve at least `SAFETY_MIN_WORKERS` base workers,
    /// elevate the scheduling priority of every worker thread, and may spawn up
    /// to `DEFAULT_MAX_OVERFLOW` overflow threads. Normal pools never overflow.
    pub fn new_for_class(size: usize, name_prefix: &str, class: TrafficClass) -> Self {
        let max_overflow = if class == TrafficClass::Safety {
            DEFAULT_MAX_OVERFLOW
        } else {
            0
        };
        Self::new_for_class_with_overflow(size, name_prefix, class, max_overflow)
    }

    /// Create a pool with an explicit overflow ceiling (used by tests to assert
    /// the bound; production callers go through [`Self::new_for_class`]).
    fn new_for_class_with_overflow(
        size: usize,
        name_prefix: &str,
        class: TrafficClass,
        max_overflow: usize,
    ) -> Self {
        let size = if class == TrafficClass::Safety {
            size.max(SAFETY_MIN_WORKERS)
        } else {
            size
        };
        let (sender, receiver) = mpsc::channel::<Job>();
        let receiver = Arc::new(std::sync::Mutex::new(receiver));
        let idle_count = Arc::new(AtomicUsize::new(0));
        let mut workers = Vec::with_capacity(size);

        for i in 0..size {
            let rx = receiver.clone();
            let idle = idle_count.clone();
            let name = format!("{}-pool-{}", name_prefix, i);
            let handle = thread::Builder::new()
                .name(name)
                .spawn(move || {
                    // Safety pools run their reserved workers at elevated
                    // priority from the start, before any per-connection call.
                    apply_safety_priority(class);
                    loop {
                        // Mark ourselves idle while waiting for work
                        idle.fetch_add(1, Ordering::Release);
                        let job = {
                            let lock = rx.lock().unwrap();
                            lock.recv()
                        };
                        idle.fetch_sub(1, Ordering::Release);

                        match job {
                            Ok(f) => f(),
                            Err(_) => break, // Channel closed — pool is shutting down
                        }
                    }
                })
                .expect("failed to spawn pool worker");
            workers.push(handle);
        }

        ConnectionPool {
            sender,
            idle_count,
            overflow_count: Arc::new(AtomicUsize::new(0)),
            max_overflow,
            name_prefix: name_prefix.to_owned(),
            class,
            _workers: workers,
        }
    }

    /// Submit a job to the pool.
    ///
    /// If at least one base worker is idle the job goes through the shared
    /// channel and will be picked up cheaply. If all base workers are busy,
    /// safety jobs spawn an overflow thread immediately; normal jobs remain
    /// queued on the bounded base worker set.
    ///
    /// Returns `false` only if the pool has been shut down.
    pub fn execute<F: FnOnce() + Send + 'static>(&self, f: F) -> bool {
        // Fast path: idle worker available → queue through channel
        if self.idle_count.load(Ordering::Acquire) > 0 {
            return self.queue_job(Box::new(f));
        }

        if self.class == TrafficClass::Normal {
            return self.queue_job(Box::new(f));
        }

        // Slow path: all base workers busy → bounded overflow.
        // Reserve a slot without exceeding the cap (lock-free CAS). Doing the
        // bump *before* spawning guarantees the live-thread count can never
        // exceed `max_overflow`, even under concurrent submitters.
        let mut cur = self.overflow_count.load(Ordering::Acquire);
        loop {
            if cur >= self.max_overflow {
                // Cap reached: queue on the base workers rather than spawning
                // unbounded threads. The job is not dropped — it runs when a
                // worker frees up — and safety capacity is preserved.
                warn!(
                    "{}: overflow cap {} reached; queueing job",
                    self.name_prefix, self.max_overflow
                );
                return self.queue_job(Box::new(f));
            }
            match self.overflow_count.compare_exchange_weak(
                cur,
                cur + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(actual) => cur = actual,
            }
        }

        let prefix = self.name_prefix.clone();
        let class = self.class;
        let counter = self.overflow_count.clone();
        // Hold the job in a shared slot the overflow thread takes from. If the
        // spawn fails the closure (and its clone of `pending`) is dropped having
        // never run, so the caller can recover the job here and queue it for a
        // base worker — never dropping it (the previous code sent an empty
        // closure, silently losing the job on spawn failure).
        let pending: Arc<Mutex<Option<Job>>> = Arc::new(Mutex::new(Some(Box::new(f))));
        let pending_thread = pending.clone();
        match thread::Builder::new()
            .name(format!("{}-overflow", prefix))
            .spawn(move || {
                // Release the reserved slot on *every* exit path, including an
                // unwinding relay closure, so the counter stays balanced.
                struct SlotGuard(Arc<AtomicUsize>);
                impl Drop for SlotGuard {
                    fn drop(&mut self) {
                        self.0.fetch_sub(1, Ordering::AcqRel);
                    }
                }
                let _slot = SlotGuard(counter);
                // Overflow threads inherit the pool's class priority too.
                apply_safety_priority(class);
                debug!("pool overflow thread started");
                let job = pending_thread.lock().ok().and_then(|mut g| g.take());
                if let Some(job) = job {
                    job();
                }
            }) {
            Ok(_) => true,
            Err(e) => {
                // Spawn failed: release the reservation and queue the recovered
                // job for the base workers rather than dropping it.
                self.overflow_count.fetch_sub(1, Ordering::AcqRel);
                warn!("connection pool: failed to spawn overflow thread: {}", e);
                let job = pending.lock().ok().and_then(|mut g| g.take());
                match job {
                    Some(job) => self.queue_job(job),
                    None => false,
                }
            }
        }
    }

    fn queue_job(&self, job: Job) -> bool {
        match self.sender.send(job) {
            Ok(()) => true,
            Err(_) => {
                warn!("connection pool: channel disconnected, dropping job");
                false
            }
        }
    }

    /// Returns the recommended base pool size: 2× the available CPUs.
    pub fn default_size() -> usize {
        let cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);
        cpus * 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::time::Duration;

    #[test]
    fn safety_pool_reserves_minimum_workers() {
        // A requested size below the floor is raised to SAFETY_MIN_WORKERS.
        let pool = ConnectionPool::new_for_class(1, "test-safety", TrafficClass::Safety);
        assert!(pool._workers.len() >= SAFETY_MIN_WORKERS);
    }

    #[test]
    fn normal_pool_uses_requested_size() {
        let pool = ConnectionPool::new_for_class(1, "test-normal", TrafficClass::Normal);
        assert_eq!(pool._workers.len(), 1);
        assert_eq!(pool.class, TrafficClass::Normal);
    }

    #[test]
    fn executes_submitted_job() {
        let pool = ConnectionPool::new(2, "test-exec");
        let flag = Arc::new(AtomicBool::new(false));
        let f = flag.clone();
        assert!(pool.execute(move || f.store(true, Ordering::SeqCst)));
        for _ in 0..200 {
            if flag.load(Ordering::SeqCst) {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert!(flag.load(Ordering::SeqCst));
    }

    #[test]
    fn normal_pool_queues_when_base_worker_is_busy() {
        let pool = ConnectionPool::new_for_class(1, "test-normal-queue", TrafficClass::Normal);
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        assert!(pool.execute(move || {
            started_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        }));
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        let ran = Arc::new(AtomicBool::new(false));
        let ran_worker = ran.clone();
        assert!(pool.execute(move || ran_worker.store(true, Ordering::SeqCst)));
        thread::sleep(Duration::from_millis(50));
        assert!(
            !ran.load(Ordering::SeqCst),
            "normal jobs should queue instead of spawning overflow workers"
        );

        release_tx.send(()).unwrap();
        for _ in 0..200 {
            if ran.load(Ordering::SeqCst) {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert!(ran.load(Ordering::SeqCst));
    }

    #[test]
    fn safety_pool_overflows_when_reserved_workers_are_busy() {
        let pool = ConnectionPool::new_for_class(2, "test-safety-overflow", TrafficClass::Safety);
        let worker_count = pool._workers.len();
        for _ in 0..200 {
            if pool.idle_count.load(Ordering::SeqCst) >= worker_count {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(pool.idle_count.load(Ordering::SeqCst), worker_count);

        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let mut release_txs = Vec::new();

        for _ in 0..worker_count {
            let started = started_tx.clone();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            release_txs.push(release_tx);
            assert!(pool.execute(move || {
                started.send(()).unwrap();
                release_rx.recv().unwrap();
            }));
        }
        drop(started_tx);
        for _ in 0..worker_count {
            started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        }

        let ran = Arc::new(AtomicBool::new(false));
        let ran_worker = ran.clone();
        assert!(pool.execute(move || ran_worker.store(true, Ordering::SeqCst)));
        for _ in 0..200 {
            if ran.load(Ordering::SeqCst) {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert!(
            ran.load(Ordering::SeqCst),
            "safety jobs should get overflow capacity when reserved workers are busy"
        );

        for tx in release_txs {
            let _ = tx.send(());
        }
    }

    #[test]
    fn safety_pool_caps_overflow_threads() {
        // max_overflow = 1: the first over-capacity safety job spawns an overflow
        // thread; the next is *queued* (not spawned, not dropped) and runs when a
        // base worker frees up. Live overflow threads never exceed the cap.
        let pool = ConnectionPool::new_for_class_with_overflow(
            2,
            "test-safety-cap",
            TrafficClass::Safety,
            1,
        );
        let worker_count = pool._workers.len();
        for _ in 0..200 {
            if pool.idle_count.load(Ordering::SeqCst) >= worker_count {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }

        // Saturate every base worker with a blocking job.
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let mut base_release = Vec::new();
        for _ in 0..worker_count {
            let started = started_tx.clone();
            let (rel_tx, rel_rx) = std::sync::mpsc::channel::<()>();
            base_release.push(rel_tx);
            assert!(pool.execute(move || {
                started.send(()).unwrap();
                rel_rx.recv().unwrap();
            }));
        }
        drop(started_tx);
        for _ in 0..worker_count {
            started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        }

        // First over-capacity job → one overflow thread (which blocks).
        let (ov_rel_tx, ov_rel_rx) = std::sync::mpsc::channel::<()>();
        let ov_started = Arc::new(AtomicBool::new(false));
        let ovs = ov_started.clone();
        assert!(pool.execute(move || {
            ovs.store(true, Ordering::SeqCst);
            ov_rel_rx.recv().unwrap();
        }));
        for _ in 0..200 {
            if ov_started.load(Ordering::SeqCst) {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert!(
            ov_started.load(Ordering::SeqCst),
            "first overflow job should start"
        );
        assert_eq!(pool.overflow_count.load(Ordering::SeqCst), 1);

        // Second over-capacity job → cap reached → queued, must not start yet.
        let queued_ran = Arc::new(AtomicBool::new(false));
        let qr = queued_ran.clone();
        assert!(pool.execute(move || qr.store(true, Ordering::SeqCst)));
        thread::sleep(Duration::from_millis(50));
        assert!(
            !queued_ran.load(Ordering::SeqCst),
            "over-cap job must queue, not spawn another overflow thread"
        );
        assert!(
            pool.overflow_count.load(Ordering::SeqCst) <= 1,
            "live overflow threads must never exceed the cap"
        );

        // Free a base worker → the queued job runs (proving it was not dropped).
        base_release.pop().unwrap().send(()).unwrap();
        for _ in 0..200 {
            if queued_ran.load(Ordering::SeqCst) {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert!(
            queued_ran.load(Ordering::SeqCst),
            "queued over-cap job must eventually run on a freed base worker"
        );

        // Release the remaining blocked jobs.
        let _ = ov_rel_tx.send(());
        for tx in base_release {
            let _ = tx.send(());
        }
    }
}
