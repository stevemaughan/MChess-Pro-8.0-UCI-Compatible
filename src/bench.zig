//! Timing for the benchmarks that live in the test files. Not part of the engine.
//!
//! A benchmark is a test whose name starts with "bench: ". It returns at once unless the
//! build was given -Dbench=true, so an ordinary `zig build test` is not slowed by it:
//!
//!     zig build test -Doptimize=ReleaseFast -Dbench=true -Dtest-filter="bench: position"
//!
//! Each benchmark loads its unit's recorded calls once, then times the routine alone over
//! them, several passes, and reports the fastest pass. The fastest pass is the one least
//! disturbed by other work on the machine.

const std = @import("std");
const build_options = @import("build_options");

/// True when the build was given -Dbench=true.
pub const enabled: bool = build_options.bench;

/// Nanoseconds on the monotonic clock.
pub fn now() i96 {
    return std.Io.Clock.awake.now(std.testing.io).nanoseconds;
}

/// Keeps a value alive so the optimiser cannot delete the work that produced it.
pub fn keep(value: anytype) void {
    std.mem.doNotOptimizeAway(value);
}

/// The fastest of several timed passes.
pub const Best = struct {
    ns: i96 = std.math.maxInt(i96),

    /// Call with the clock reading taken just before the pass.
    pub fn pass(self: *Best, started: i96) void {
        const d = now() - started;
        if (d < self.ns) self.ns = d;
    }

    /// Prints "bench <name>: <ns per call> ns/call (<calls> calls, best of <passes>)".
    /// `overhead_ns` is the time of the same loop with the routine left out (state copies
    /// and the like), taken off before dividing; pass 0 if there is none.
    pub fn report(self: Best, name: []const u8, calls: usize, passes: usize, overhead_ns: i96) void {
        const net: i96 = @max(self.ns - overhead_ns, 0);
        const per: f64 = @as(f64, @floatFromInt(net)) / @as(f64, @floatFromInt(@max(calls, 1)));
        std.debug.print("bench {s}: {d:.1} ns/call ({d} calls, best of {d})\n", .{ name, per, calls, passes });
    }
};

test "bench: the timer itself" {
    if (!enabled) return;
    const passes = 5;
    const calls = 1_000_000;
    var best: Best = .{};
    var sum: u64 = 0;
    for (0..passes) |_| {
        const t0 = now();
        for (0..calls) |i| {
            sum +%= i *% 2654435761;
            keep(sum);
        }
        best.pass(t0);
    }
    best.report("timer self-check (one multiply and add)", calls, passes, 0);
}
