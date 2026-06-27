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
use std::sync::Arc;
use std::thread;

type Job = Box<dyn FnOnce() + Send + 'static>;

/// Guaranteed minimum number of base worker threads reserved for a safety
/// pool, so safety relays always have dedicated capacity even on low-CPU hosts
/// where `default_size()` would otherwise be tiny.
const SAFETY_MIN_WORKERS: usize = 2;

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
    /// `Safety` pools reserve at least [`SAFETY_MIN_WORKERS`] base workers and
    /// elevate the scheduling priority of every worker thread.
    pub fn new_for_class(size: usize, name_prefix: &str, class: TrafficClass) -> Self {
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

        // Slow path: all base workers busy → spawn overflow thread
        let prefix = self.name_prefix.clone();
        let class = self.class;
        match thread::Builder::new()
            .name(format!("{}-overflow", prefix))
            .spawn(move || {
                // Overflow threads inherit the pool's class priority too.
                apply_safety_priority(class);
                debug!("pool overflow thread started");
                f();
            }) {
            Ok(_) => true,
            Err(e) => {
                warn!("connection pool: failed to spawn overflow thread: {}", e);
                // Last resort: queue it anyway — it will run when a worker is freed
                let _ = self.sender.send(Box::new(|| {}));
                false
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
}
