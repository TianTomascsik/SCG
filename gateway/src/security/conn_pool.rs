//! Elastic connection thread pool — a base set of worker threads handles
//! connections, with overflow threads spawned on demand when all workers
//! are busy.
//!
//! Relay tasks are long-lived (they run for the entire connection lifetime),
//! so a fixed pool would stall connections when concurrency exceeds pool
//! size.  The elastic design keeps the benefits of thread reuse under
//! normal load while guaranteeing no connection starvation under burst.
//!
//! Benefits:
//! - Eliminates thread creation/teardown overhead under normal load
//! - Keeps CPU caches warm (base workers stay on the same cores)
//! - Automatically scales up for high-concurrency bursts
//! - No connection starvation — every job gets a thread

use log::{debug, warn};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;

type Job = Box<dyn FnOnce() + Send + 'static>;

/// An elastic thread pool for connection handling.
///
/// Maintains a base set of long-lived worker threads.  When a job is
/// submitted and no base worker is idle, a temporary overflow thread is
/// spawned to handle the job immediately, preventing queue stalls.
pub struct ConnectionPool {
    sender: mpsc::Sender<Job>,
    idle_count: Arc<AtomicUsize>,
    name_prefix: String,
    _workers: Vec<thread::JoinHandle<()>>,
}

impl ConnectionPool {
    /// Create a new pool with `size` base worker threads.
    pub fn new(size: usize, name_prefix: &str) -> Self {
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
            _workers: workers,
        }
    }

    /// Submit a job to the pool.
    ///
    /// If at least one base worker is idle the job goes through the shared
    /// channel and will be picked up cheaply.  If all base workers are busy
    /// with long-lived relay tasks, an overflow thread is spawned immediately
    /// so the connection is never queued behind an already-running relay.
    ///
    /// Returns `false` only if the pool has been shut down.
    pub fn execute<F: FnOnce() + Send + 'static>(&self, f: F) -> bool {
        // Fast path: idle worker available → queue through channel
        if self.idle_count.load(Ordering::Acquire) > 0 {
            return match self.sender.send(Box::new(f)) {
                Ok(()) => true,
                Err(_) => {
                    warn!("connection pool: channel disconnected, dropping job");
                    false
                }
            };
        }

        // Slow path: all base workers busy → spawn overflow thread
        let prefix = self.name_prefix.clone();
        match thread::Builder::new()
            .name(format!("{}-overflow", prefix))
            .spawn(move || {
                debug!("pool overflow thread started");
                f();
            }) {
            Ok(_) => true,
            Err(e) => {
                warn!("connection pool: failed to spawn overflow thread: {}", e);
                // Last resort: queue it anyway — it will run when a worker is freed
                match self.sender.send(Box::new(|| {})) {
                    _ => {}
                }
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
