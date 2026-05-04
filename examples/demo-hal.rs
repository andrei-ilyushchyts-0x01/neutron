//! `cargo run --example demo-hal` — host-only fixture for the sprint-1 PR 2
//! ioctl decoder. Constructs `SyscallEvent` values that mimic the wire
//! payloads neutron would capture from a real Pixel running an Android HAL
//! workload (DMA_HEAP_IOCTL_ALLOC, BINDER_WRITE_READ-shape) and prints the
//! NDJSON the formatter would emit.
//!
//! Verifies decoder semantics without a device. The xtask `demo-hal`
//! subcommand runs this example and diffs the output against
//! `examples/expected/dma-heap.ndjson` so regressions are caught in CI.

use neutron::fdgraph::FdKind;
use neutron::format::{format_event_json_full, FdHint};
use neutron_common::SyscallEvent;

/// Build an ioctl exit event whose `data[]` carries a `cmd` (4 bytes LE) +
/// post-call `payload` bytes. `args[1] = cmd` mirrors what the BPF program
/// stamps so userspace and the policy predicate stay consistent.
fn ioctl_exit(pid: u32, cmd: u32, payload: &[u8], ret: i64, comm: &[u8]) -> SyscallEvent {
    let mut data = [0u8; 128];
    data[..4].copy_from_slice(&cmd.to_le_bytes());
    let take = payload.len().min(124);
    data[4..4 + take].copy_from_slice(&payload[..take]);
    let mut comm_bytes = [0u8; 16];
    let n = comm.len().min(16);
    comm_bytes[..n].copy_from_slice(&comm[..n]);
    SyscallEvent {
        syscall_nr: 29,
        is_enter: 0,
        ret,
        // ioctl(2) ABI: args[0]=fd, args[1]=cmd, args[2]=arg pointer.
        args: [12, cmd as u64, 0, 0, 0, 0],
        pid,
        tgid: pid,
        uid: 1000,
        timestamp_ns: 1_000_000,
        enter_timestamp_ns: 999_500,
        data,
        comm: comm_bytes,
        ..SyscallEvent::default()
    }
}

/// Build the 24-byte `dma_heap_allocation_data` payload.
fn dma_heap_payload(len: u64, fd: i32, fd_flags: u32, heap_flags: u64) -> Vec<u8> {
    let mut p = Vec::with_capacity(24);
    p.extend_from_slice(&len.to_le_bytes());
    p.extend_from_slice(&fd.to_le_bytes());
    p.extend_from_slice(&fd_flags.to_le_bytes());
    p.extend_from_slice(&heap_flags.to_le_bytes());
    p
}

fn main() {
    // 1. DMA_HEAP_IOCTL_ALLOC, post-call: fd 32, 4 KiB, O_RDWR|O_CLOEXEC.
    //    Models a HAL allocating a DMA buffer from /dev/dma_heap/system.
    let dh_payload = dma_heap_payload(4096, 32, 0x80002, 0);
    let dh_hint = FdHint {
        kind: FdKind::Device,
        path: "/dev/dma_heap/system".into(),
    };
    let ev = ioctl_exit(540, 0xC018_4800, &dh_payload, 0, b"hal-allocator");
    println!(
        "{}",
        format_event_json_full(&ev, false, None, Some(&dh_hint), Some(1))
    );

    // 2. BINDER_WRITE_READ-shape (cmd type='b', dir=RW). With a Binder fd
    //    hint we resolve to the binder family; without the hint we'd fall
    //    back to dma_buf — the third emission demonstrates the
    //    disambiguation path.
    let binder_cmd: u32 = (3u32 << 30) | (48u32 << 16) | (0x62u32 << 8) | 1;
    let binder_hint = FdHint {
        kind: FdKind::Binder,
        path: "/dev/binder".into(),
    };
    let ev = ioctl_exit(540, binder_cmd, &[0u8; 48], 0, b"binder:540_1");
    println!(
        "{}",
        format_event_json_full(&ev, false, None, Some(&binder_hint), Some(2))
    );

    // 3. Same cmd, no FdHint → dma_buf classification (collision tiebreak).
    let ev = ioctl_exit(540, binder_cmd, &[0u8; 48], 0, b"hal-allocator");
    println!(
        "{}",
        format_event_json_full(&ev, false, None, None, Some(3))
    );

    // 4. Truncated dma-heap payload — decoder must classify family but emit
    //    no nested object. Models a BPF capture that hit the ringbuf cap.
    let ev = ioctl_exit(540, 0xC018_4800, &[0u8; 12], 0, b"truncated-cap");
    println!(
        "{}",
        format_event_json_full(&ev, false, None, Some(&dh_hint), Some(4))
    );
}
