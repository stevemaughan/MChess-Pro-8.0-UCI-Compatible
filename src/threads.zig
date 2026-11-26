//! The engine's threads: the shell's worker (src/uci.zig) and the tablebase preload's helpers
//! (src/tb_store.zig). In the standard build they are `std.Thread`. In the Windows 7 build
//! (`-Dwin7=true`, src/win7_io.zig) they are started with kernel32's CreateThread, because
//! `std.Thread` reaches Windows through calls that build avoids.
//!
//! Platform adaptation only (AGENTS.md section 8.2): which thread runs a search, and in what
//! order the search does its work, is the same in both builds.

const std = @import("std");
const win7_io = @import("win7_io.zig");

/// A thread running `entry(arg)`.
pub const Thread = struct {
    impl: if (win7_io.enabled) win7_io.Thread else std.Thread,

    /// `arg` must outlive the thread.
    pub fn spawn(comptime T: type, comptime entry: fn (*T) void, arg: *T) !Thread {
        if (win7_io.enabled) return .{ .impl = try win7_io.Thread.spawn(T, entry, arg) };
        return .{ .impl = try std.Thread.spawn(.{}, entry, .{arg}) };
    }

    /// Waits for the thread to end.
    pub fn join(t: Thread) void {
        t.impl.join();
    }
};

/// Lets another thread that is ready run.
pub fn yield() void {
    if (win7_io.enabled) return win7_io.yield();
    std.Thread.yield() catch {};
}

const Counter = struct {
    n: std.atomic.Value(u32) = .init(0),

    fn add(c: *Counter) void {
        for (0..1000) |_| {
            _ = c.n.fetchAdd(1, .monotonic);
            yield();
        }
    }
};

test "threads: four threads each add a thousand, and join waits for them" {
    var c: Counter = .{};
    var ts: [4]Thread = undefined;
    for (&ts) |*t| t.* = try Thread.spawn(Counter, Counter.add, &c);
    for (ts) |t| t.join();
    try std.testing.expectEqual(@as(u32, 4000), c.n.load(.monotonic));
}
