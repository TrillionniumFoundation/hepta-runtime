// Observe the exact, unchanged target lock; observers never replace its policy.
#![allow(dead_code)]
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Instant, Duration};
use std::io::{self, Write};
include!("audit_store_lock.rs.txt");

fn snap(out: &mut impl Write, lock: &AuditStoreLock, scenario: u64, op: u64, result: u64) {
    let queue = lock.queue.lock().unwrap_or_else(|e| e.into_inner());
    out.write_all(b"HAUDOR01").unwrap();
    for value in [scenario, op, result, queue.next_ticket, queue.active as u64,
        queue.readers as u64, queue.reader_poisoned as u64, lock.queue.is_poisoned() as u64,
        lock.inner.is_poisoned() as u64, queue.waiting.len() as u64] {
        out.write_all(&value.to_le_bytes()).unwrap();
    }
    for (ticket, access) in &queue.waiting {
        out.write_all(&ticket.to_le_bytes()).unwrap();
        out.write_all(&((*access == AuditStoreAccess::Shared) as u64).to_le_bytes()).unwrap();
    }
}
fn wait_queue(lock: &AuditStoreLock, count: usize) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while lock.queue.lock().unwrap().waiting.len() != count {
        assert!(Instant::now() < deadline, "original queue observation deadline");
        std::thread::yield_now();
    }
}
fn pending(rx: &mpsc::Receiver<()>) {
    assert!(matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
}
fn cohorts(out: &mut impl Write) {
    for (scenario, count) in [1usize, 2, 3, 32, 65, 257].into_iter().enumerate() {
        let lock = AuditStoreLock::default();
        snap(out, &lock, scenario as u64, 0, 0);
        let mut held = Vec::new();
        for _ in 0..count {
            let guard = lock.acquire_shared(Instant::now() + Duration::from_secs(5)).unwrap();
            held.push(Some(guard));
            snap(out, &lock, scenario as u64, 3, 0);
        }
        for index in (0..count).step_by(2).chain((1..count).step_by(2)) {
            assert_eq!(held[index].take().unwrap().finish(), Ok(()));
            snap(out, &lock, scenario as u64, 5, 0);
        }
        snap(out, &lock, scenario as u64, 8, 0);
    }
}
fn fifo(out: &mut impl Write) {
    let lock = Arc::new(AuditStoreLock::default());
    snap(out, &lock, 6, 0, 0);
    let first = lock.acquire(None).unwrap();
    snap(out, &lock, 6, 4, 0);
    let (ready1, seen1) = mpsc::channel();
    let (release1, done1) = mpsc::channel();
    let child1 = lock.clone();
    let reader1 = std::thread::spawn(move || {
        let guard = child1.acquire_shared(Instant::now() + Duration::from_secs(5)).unwrap();
        ready1.send(()).unwrap();
        done1.recv_timeout(Duration::from_secs(5)).unwrap();
        guard.finish().unwrap();
    });
    wait_queue(&lock, 1); pending(&seen1); snap(out, &lock, 6, 1, 1);
    let (ready2, seen2) = mpsc::channel();
    let (release2, done2) = mpsc::channel();
    let child2 = lock.clone();
    let writer2 = std::thread::spawn(move || {
        let guard = child2.acquire(None).unwrap();
        ready2.send(()).unwrap();
        done2.recv_timeout(Duration::from_secs(5)).unwrap();
        drop(guard);
    });
    wait_queue(&lock, 2); pending(&seen2); snap(out, &lock, 6, 1, 1);
    let (ready3, seen3) = mpsc::channel();
    let (release3, done3) = mpsc::channel();
    let child3 = lock.clone();
    let reader3 = std::thread::spawn(move || {
        let guard = child3.acquire_shared(Instant::now() + Duration::from_secs(5)).unwrap();
        ready3.send(()).unwrap();
        done3.recv_timeout(Duration::from_secs(5)).unwrap();
        guard.finish().unwrap();
    });
    wait_queue(&lock, 3); pending(&seen3); snap(out, &lock, 6, 1, 1);
    for rx in [&seen1, &seen2, &seen3] {
        pending(rx); snap(out, &lock, 6, 2, 1);
    }
    drop(first);
    seen1.recv_timeout(Duration::from_secs(5)).unwrap();
    wait_queue(&lock, 2);
    snap(out, &lock, 6, 3, 0);
    for rx in [&seen2, &seen3] {
        pending(rx); snap(out, &lock, 6, 2, 1);
    }
    release1.send(()).unwrap();
    seen2.recv_timeout(Duration::from_secs(5)).unwrap();
    wait_queue(&lock, 1);
    snap(out, &lock, 6, 4, 0);
    pending(&seen3); snap(out, &lock, 6, 2, 1);
    release2.send(()).unwrap();
    seen3.recv_timeout(Duration::from_secs(5)).unwrap();
    wait_queue(&lock, 0);
    snap(out, &lock, 6, 3, 0);
    release3.send(()).unwrap();
    reader1.join().unwrap(); writer2.join().unwrap(); reader3.join().unwrap();
    snap(out, &lock, 6, 5, 0);
    snap(out, &lock, 6, 8, 0);
}
fn main() {
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    cohorts(&mut out);
    fifo(&mut out);
    out.flush().unwrap();
}
