//! Differential test of src/timecontrol.zig against the Python transcription of
//! Juggernaut's TTimeControl (tools/research/uci_time/juggernaut_tc.py), through the
//! vectors made by tools/research/uci_time/gen_timecontrol_vectors.py, whose docstring
//! defines the format:
//! - tests/golden/timecontrol/timecontrol.zst, the Pascal (replayed with `Fixes.original`);
//! - tests/golden/timecontrol/timecontrol_fixed.zst, the two faults corrected (owner
//!   decision 26; replayed with `Fixes.decision26`, the engine's default without the clock
//!   reserve, which is tested on its own at the end of this file). This replay also
//!   runs every call on a twin with the faults kept and counts the records whose results
//!   differ, which must be the count the generator printed.
//! On a mismatch it names the record and the first field that differs.
//!
//! The branching factor is compared within a few units in the last place: the
//! transcription's math.exp/math.log and Zig's @exp/@log may differ in the last bit
//! (the generator keeps the elapsed times away from the threshold where that could
//! change a decision). Everything else is compared exactly.

const std = @import("std");
const tc_mod = @import("timecontrol.zig");
const TimeControl = tc_mod.TimeControl;
const Limits = tc_mod.Limits;
const Kind = tc_mod.Kind;
const Fixes = tc_mod.Fixes;

fn readVectors(gpa: std.mem.Allocator, name: []const u8) ![]u8 {
    var path_buf: [256]u8 = undefined;
    const dir = @import("build_options").golden_dir;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/timecontrol/{s}", .{ dir, name });
    const compressed = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, gpa, .limited(64 << 20));
    defer gpa.free(compressed);
    var in: std.Io.Reader = .fixed(compressed);
    const window = try gpa.alloc(u8, std.compress.zstd.default_window_len + std.compress.zstd.block_size_max);
    defer gpa.free(window);
    var zd = std.compress.zstd.Decompress.init(&in, window, .{});
    return zd.reader.allocRemaining(gpa, .limited(64 << 20));
}

const Reader = struct {
    buf: []const u8,
    i: usize = 0,
    fn int(r: *Reader, comptime T: type) T {
        const n = @sizeOf(T);
        const v = std.mem.readInt(T, r.buf[r.i..][0..n], .little);
        r.i += n;
        return v;
    }
    fn float(r: *Reader) f64 {
        return @bitCast(r.int(u64));
    }
};

fn kindOf(code: u8) Kind {
    return switch (code) {
        0 => .clock,
        1 => .movetime,
        2 => .depth,
        3 => .nodes,
        4 => .mate,
        else => .infinite,
    };
}

fn ulpDistance(a: f64, b: f64) u64 {
    const ia: i64 = @bitCast(a);
    const ib: i64 = @bitCast(b);
    return @abs(ia - ib); // both non-negative here
}

fn fail(rec: u32, tag: u8, field: []const u8, comptime fmt: []const u8, args: anytype) error{TestUnexpectedResult} {
    std.debug.print("timecontrol: record {d} ('{c}'): first differing field: {s}: ", .{ rec, tag, field });
    std.debug.print(fmt ++ "\n", args);
    return error.TestUnexpectedResult;
}

const Stats = struct {
    /// 'S', 'P' and 'I' records
    by_tag: [3]u32 = .{ 0, 0, 0 },
    /// 'I' records where the clock rule ran
    clock_rule: u32 = 0,
    /// 'I' records that stop
    stops: u32 = 0,
    /// records where a twin with the other `Fixes` gives a different result ('S' with a
    /// clock: target, panic or max; 'P': the stop; 'I': the stop, or the scaling factor
    /// where the clock rule ran)
    differ: [3]u32 = .{ 0, 0, 0 },
};

/// Replays one vector file on a `TimeControl` with `fixes`, and every call also on a twin
/// with `twin_fixes`, counting the records where the twin's results differ.
fn replay(name: []const u8, fixes: Fixes, twin_fixes: Fixes) !Stats {
    const gpa = std.testing.allocator;
    const raw = try readVectors(gpa, name);
    defer gpa.free(raw);
    try std.testing.expectEqualSlices(u8, "MCTC", raw[0..4]);
    var r: Reader = .{ .buf = raw, .i = 4 };
    try std.testing.expectEqual(@as(u16, 1), r.int(u16));
    const pair = try gpa.alloc(TimeControl, 2);
    defer gpa.free(pair);
    const tcp = &pair[0];
    const twin = &pair[1];
    tcp.* = .{ .fixes = fixes };
    twin.* = .{ .fixes = twin_fixes };
    var n: u32 = 0;
    var st: Stats = .{};
    while (true) {
        const tag = r.int(u8);
        switch (tag) {
            'N' => {
                tcp.* = TimeControl.init();
                tcp.fixes = fixes;
                twin.* = TimeControl.init();
                twin.fixes = twin_fixes;
            },
            'L' => {
                var lim: Limits = .{};
                lim.kind = kindOf(r.int(u8));
                lim.wtime = r.int(u32);
                lim.btime = r.int(u32);
                lim.winc = r.int(u32);
                lim.binc = r.int(u32);
                lim.movestogo = r.int(u16);
                lim.movetime = r.int(u32);
                lim.depth = r.int(u16);
                lim.nodes = r.int(u64);
                lim.mate = r.int(u8);
                lim.move_overhead = r.int(u32);
                tcp.setLimits(lim);
                twin.setLimits(lim);
            },
            'S' => {
                const side: tc_mod.Side = if (r.int(u8) == 0) .white else .black;
                const has_exp = r.int(u8) != 0;
                const exp_move = r.int(u32);
                const exp_to = r.int(u8);
                const has_prev = r.int(u8) != 0;
                const prev_to = r.int(u8);
                const mc = r.int(u8);
                const exp: ?tc_mod.Expected = if (has_exp) .{ .move = exp_move, .to = exp_to } else null;
                tcp.start(side, exp, if (has_prev) prev_to else null, mc);
                twin.start(side, exp, if (has_prev) prev_to else null, mc);
                const target = r.int(i64);
                const panic = r.int(i64);
                const max = r.int(i64);
                if (tcp.limits.kind == .clock) {
                    if (tcp.target != target) return fail(n, tag, "target", "zig {d}, reference {d}", .{ tcp.target, target });
                    if (tcp.panic != panic) return fail(n, tag, "panic", "zig {d}, reference {d}", .{ tcp.panic, panic });
                    if (tcp.max != max) return fail(n, tag, "max", "zig {d}, reference {d}", .{ tcp.max, max });
                    if (twin.target != target or twin.panic != panic or twin.max != max) st.differ[0] += 1;
                }
                n += 1;
                st.by_tag[0] += 1;
            },
            'P' => {
                const elapsed = r.int(i64);
                const nodes = r.int(u64);
                const trouble = r.int(u8) != 0;
                const ponder = r.int(u8) != 0;
                const want = r.int(u8) != 0;
                const got = tcp.shouldStopInSearch(elapsed, nodes, trouble, ponder);
                if (got != want) return fail(n, tag, "stop", "zig {}, reference {} (elapsed {d}, nodes {d}, trouble {}, pondering {})", .{ got, want, elapsed, nodes, trouble, ponder });
                if (tcp.limits.kind == .nodes and tcp.nodeLimitReached(nodes) != want)
                    return fail(n, tag, "nodeLimitReached", "zig {}, reference {}", .{ !want, want });
                if (twin.shouldStopInSearch(elapsed, nodes, trouble, ponder) != want) st.differ[1] += 1;
                n += 1;
                st.by_tag[1] += 1;
            },
            'I' => {
                const it: tc_mod.Iteration = .{
                    .depth = r.int(u16),
                    .score = r.int(i32),
                    .best_move = r.int(u32),
                    .fail_high_low = r.int(u8),
                    .nodes = r.int(u64),
                    .elapsed_ms = r.int(i64),
                    .pondering = r.int(u8) != 0,
                    .mate_moves = blk: {
                        const has = r.int(u8) != 0;
                        const m = r.int(u32);
                        break :blk if (has) m else null;
                    },
                };
                const want = r.int(u8) != 0;
                const computed = r.int(u8) != 0;
                const factor = r.float();
                const branching = r.float();
                tcp.last_factor = 0;
                tcp.last_branching = 0;
                twin.last_factor = 0;
                const got = tcp.shouldStopAfterIteration(it);
                const twin_got = twin.shouldStopAfterIteration(it);
                if (computed) {
                    st.clock_rule += 1;
                    if (tcp.last_factor != factor) return fail(n, tag, "scaling factor", "zig {e}, reference {e} (depth {d})", .{ tcp.last_factor, factor, it.depth });
                    if (ulpDistance(tcp.last_branching, branching) > 4) return fail(n, tag, "branching factor", "zig {e}, reference {e} (depth {d}, nodes {d})", .{ tcp.last_branching, branching, it.depth, it.nodes });
                }
                if (got != want) return fail(n, tag, "stop", "zig {}, reference {} (depth {d}, elapsed {d})", .{ got, want, it.depth, it.elapsed_ms });
                if (twin_got != want or (computed and twin.last_factor != factor)) st.differ[2] += 1;
                if (got) st.stops += 1;
                n += 1;
                st.by_tag[2] += 1;
            },
            'Z' => {
                try std.testing.expectEqual(r.int(u32), n);
                break;
            },
            else => return fail(n, tag, "tag", "unknown", .{}),
        }
    }
    try std.testing.expectEqual(raw.len, r.i);
    return st;
}

test "time control: every vector of the Juggernaut transcription" {
    const st = try replay("timecontrol.zst", .original, .corrected);
    // the vectors must reach every part of the rules
    try std.testing.expect(st.by_tag[0] > 20_000 and st.by_tag[1] > 40_000 and st.by_tag[2] > 30_000);
    try std.testing.expect(st.clock_rule > 20_000 and st.stops > 5_000);
}

test "time control: every vector of the transcription with the faults corrected" {
    // The two faults of decision 26; the reserve (`Fixes.clock_reserve`) is tested below.
    const st = try replay("timecontrol_fixed.zst", .decision26, .original);
    try std.testing.expect(st.by_tag[0] > 15_000 and st.by_tag[1] > 30_000 and st.by_tag[2] > 30_000);
    try std.testing.expect(st.clock_rule > 20_000 and st.stops > 5_000);
    // The records where the Pascal's results differ on the same calls, as
    // gen_timecontrol_vectors.py --fixed counted them in the transcription: the
    // corrections show, and nowhere else.
    try std.testing.expectEqual([3]u32{ 2757, 2780, 10459 }, st.differ);
}

// ---- the table of docs/UCI_TIME.md section 2 (Move Overhead 30) ----------------------

fn budget(lim: Limits) [3]i64 {
    return budgetWith(.corrected, lim);
}

fn budgetWith(fixes: Fixes, lim: Limits) [3]i64 {
    var t: TimeControl = .{ .fixes = fixes };
    t.setLimits(lim);
    t.start(.white, null, null, 20);
    return .{ t.target, t.panic, t.max };
}

test "time control: 5 minutes, clocks equal" {
    try std.testing.expectEqual([3]i64{ 11970, 17955, 47880 }, budget(.{ .kind = .clock, .wtime = 300000, .btime = 300000 }));
}
test "time control: 3 minutes + 2 s, clocks equal" {
    try std.testing.expectEqual([3]i64{ 8770, 13155, 35080 }, budget(.{ .kind = .clock, .wtime = 180000, .btime = 180000, .winc = 2000, .binc = 2000 }));
}
test "time control: 1 minute, clocks equal" {
    try std.testing.expectEqual([3]i64{ 2370, 3555, 9480 }, budget(.{ .kind = .clock, .wtime = 60000, .btime = 60000 }));
}
test "time control: 10 s left, clocks equal" {
    try std.testing.expectEqual([3]i64{ 370, 555, 1480 }, budget(.{ .kind = .clock, .wtime = 10000, .btime = 10000 }));
}
test "time control: 1 s left, clocks equal" {
    try std.testing.expectEqual([3]i64{ 10, 15, 40 }, budget(.{ .kind = .clock, .wtime = 1000, .btime = 1000 }));
}
test "time control: 40 moves in 5 minutes, move 1" {
    try std.testing.expectEqual([3]i64{ 7470, 11205, 29880 }, budget(.{ .kind = .clock, .wtime = 300000, .btime = 300000, .movestogo = 40 }));
}
test "time control: 1 move to go, 20 s left" {
    const lim: Limits = .{ .kind = .clock, .wtime = 20000, .btime = 20000, .movestogo = 1 };
    // The Pascal (and decision 26's corrections) may use all but 60 ms of the clock; with
    // the reserve, at most four fifths of it.
    try std.testing.expectEqual([3]i64{ 19970, 19940, 19940 }, budgetWith(.decision26, lim));
    try std.testing.expectEqual([3]i64{ 19970, 16000, 16000 }, budget(lim));
}

test "time control: the opponent's clock rounds half to even" {
    // x = 9, o = 4: sqrt(9 / 4) = 1.5 exactly. Target 1 (Max(1, ...)) gives 1.5 -> 2; target 5
    // gives 7.5 -> 8; no overhead, 25 ms of clock per ms of target.
    var t: TimeControl = .{};
    t.setLimits(.{ .kind = .clock, .wtime = 9 * 25, .btime = 4 * 25, .move_overhead = 0 });
    t.start(.white, null, null, 20);
    try std.testing.expectEqual(@as(i64, 14), t.target); // 9 * 1.5 = 13.5 -> 14 (even)
    t.setLimits(.{ .kind = .clock, .wtime = 25 * 25, .btime = 25 * 25 * 4 / 9, .move_overhead = 0 });
    t.start(.white, null, null, 20);
    // 625 / 277 is not a square ratio; just the reference's value
    try std.testing.expectEqual(@as(i64, 38), t.target);
    t.setLimits(.{ .kind = .clock, .wtime = 2 * 25 * 9, .btime = 2 * 25 * 4, .move_overhead = 0 });
    t.start(.white, null, null, 20);
    try std.testing.expectEqual(@as(i64, 27), t.target); // 18 * 1.5 = 27 exactly
    t.setLimits(.{ .kind = .clock, .wtime = 25 * 9 * 5, .btime = 25 * 4 * 5, .move_overhead = 0 });
    t.start(.white, null, null, 20);
    try std.testing.expectEqual(@as(i64, 68), t.target); // 45 * 1.5 = 67.5 -> 68 (even)
    t.setLimits(.{ .kind = .clock, .wtime = 25 * 9 * 3, .btime = 25 * 4 * 3, .move_overhead = 0 });
    t.start(.white, null, null, 20);
    try std.testing.expectEqual(@as(i64, 40), t.target); // 27 * 1.5 = 40.5 -> 40 (even, not 41)
}

// ---- the two faults of the Pascal (owner decision 26) ---------------------------------

test "time control: fault 1, the target can reach 0 (corrected: at least 1)" {
    // 100 ms against 1000 ms, Move Overhead 30: Max(1, 100 div 25 - 30) = 1, then
    // Round(sqrt(0.1) * 1) = Round(0.316...) = 0.
    const lim: Limits = .{ .kind = .clock, .wtime = 100, .btime = 1000 };
    var pascal: TimeControl = .{ .fixes = .original };
    pascal.setLimits(lim);
    pascal.start(.white, null, null, 20);
    try std.testing.expectEqual([3]i64{ 0, 0, 0 }, [3]i64{ pascal.target, pascal.panic, pascal.max });
    var fixed: TimeControl = .{};
    try std.testing.expect(fixed.fixes.juggernaut_faults); // the default is corrected
    fixed.setLimits(lim);
    fixed.start(.white, null, null, 20);
    // panic = Min(100 - 60, 1 * 3 div 2) = 1; max = Max(1, Min(40, Min(4, 20))) = 4
    try std.testing.expectEqual([3]i64{ 1, 1, 4 }, [3]i64{ fixed.target, fixed.panic, fixed.max });
    // At the first node with no time spent, the Pascal stops (0 >= 0); corrected, it does not.
    try std.testing.expect(pascal.shouldStopInSearch(0, 1, false, false));
    try std.testing.expect(!fixed.shouldStopInSearch(0, 1, false, false));
}

/// Runs one clock search on `t` (5 minutes each, so target 11,970 ms): iterations
/// 1..`ponder_until` pondered with `ponder_move` and `ponder_score`, then iteration
/// `ponder_until + 1` after `ponderhit` with `move` and `score`, 5,000 ms elapsed and the
/// branching factor at its cap of 4. Returns the stop decision and the scaling factor.
fn ponderHit(t: *TimeControl, ponder_until: u16, ponder_move: tc_mod.Move, ponder_score: i32, move: tc_mod.Move, score: i32) struct { bool, f64 } {
    t.setLimits(.{ .kind = .clock, .wtime = 300000, .btime = 300000 });
    t.start(.white, null, null, 20);
    var d: u16 = 1;
    while (d <= ponder_until) : (d += 1) {
        const it: tc_mod.Iteration = .{ .depth = d, .score = ponder_score, .best_move = ponder_move, .fail_high_low = 0, .nodes = 1000, .elapsed_ms = 100 * @as(i64, d), .pondering = true };
        std.debug.assert(!t.shouldStopAfterIteration(it)); // nothing stops on time while pondering
    }
    const stop = t.shouldStopAfterIteration(.{ .depth = d, .score = score, .best_move = move, .fail_high_low = 0, .nodes = 1 << 40, .elapsed_ms = 5000 });
    return .{ stop, t.last_factor };
}

/// A first search on `t`, 12 iterations of `move` and `score`, not pondering, with no
/// time spent so that it never stops.
fn earlierSearch(t: *TimeControl, move: tc_mod.Move, score: i32) void {
    t.setLimits(.{ .kind = .clock, .wtime = 300000, .btime = 300000 });
    t.start(.white, null, null, 20);
    var d: u16 = 1;
    while (d <= 12) : (d += 1)
        std.debug.assert(!t.shouldStopAfterIteration(.{ .depth = d, .score = score, .best_move = move, .fail_high_low = 0, .nodes = 1000, .elapsed_ms = 0 }));
}

test "time control: fault 2, stale history after ponderhit (corrected: this search's own)" {
    const a: tc_mod.Move = 0x1234;
    const b: tc_mod.Move = 0x5678;
    const hi: f64 = 0x1.6db6db6db6db7p+0; // the clip's upper bound, 2.0 / 1.4 in Double
    var settled: f64 = 0.7; // the factor of a stable move and score: 1 * 0.7 * 0.8 in Double
    settled = settled * 0.8;
    // Case 1: the earlier search settled on A at 0; this one ponders 7 iterations on B at
    // 200 and plays A at 0 at iteration 8 after the hit. The Pascal reads the earlier
    // search's A / 0 at iterations 1-7: unchanged (no 1.3), stable move 0.7, stable score
    // 0.8 = 0.56, and stops (5000 * 4 >= 11970 * 2.1 * 0.56 = 14077). Corrected, it reads
    // B / 200: changed 1.3, unstable score 1.3 = 1.69, clipped to 2.0 / 1.4, and goes on.
    {
        var pascal: TimeControl = .{ .fixes = .original };
        earlierSearch(&pascal, a, 0);
        const p = ponderHit(&pascal, 7, b, 200, a, 0);
        try std.testing.expect(p[0]);
        try std.testing.expectEqual(settled, p[1]);
        var fixed: TimeControl = .{};
        earlierSearch(&fixed, a, 0);
        const f = ponderHit(&fixed, 7, b, 200, a, 0);
        try std.testing.expect(!f[0]);
        try std.testing.expectEqual(hi, f[1]);
    }
    // Case 2: the earlier search played A at 0; this one ponders 7 iterations on B at 200
    // and plays B at 200 at iteration 8. The Pascal sees a changed move and unstable score
    // (1.69, clipped) and goes on; corrected, B has been best for six iterations at 200:
    // 0.7 * 0.8, and it stops.
    {
        var pascal: TimeControl = .{ .fixes = .original };
        earlierSearch(&pascal, a, 0);
        const p = ponderHit(&pascal, 7, b, 200, b, 200);
        try std.testing.expect(!p[0]);
        try std.testing.expectEqual(hi, p[1]);
        var fixed: TimeControl = .{};
        earlierSearch(&fixed, a, 0);
        const f = ponderHit(&fixed, 7, b, 200, b, 200);
        try std.testing.expect(f[0]);
        try std.testing.expectEqual(settled, f[1]);
    }
    // Without pondering, the history is cleared at the start: a second search's iteration
    // 1 compares with nothing, and the earlier search's entries 2..7 are gone.
    {
        var fixed: TimeControl = .{};
        earlierSearch(&fixed, a, 0);
        fixed.start(.white, null, null, 20);
        for (fixed.best_move) |m| try std.testing.expectEqual(@as(?tc_mod.Move, null), m);
        for (fixed.best_score) |s| try std.testing.expectEqual(@as(i16, 0), s);
        var pascal: TimeControl = .{ .fixes = .original };
        earlierSearch(&pascal, a, 0);
        pascal.start(.white, null, null, 20);
        try std.testing.expectEqual(@as(?tc_mod.Move, a), pascal.best_move[12]);
    }
}

// ---- the third fault: the clock reserve (2026-11-22) -----------------------------------

const grid_clocks = [_]u32{ 100, 150, 151, 200, 500, 800, 1000, 2000, 3000, 5700, 10000, 20000, 60000, 180000, 600000 };
const grid_incs = [_]u32{ 0, 10, 2000 };
const grid_mtgs = [_]u16{ 0, 40, 10, 5, 2, 1 };

/// One cell of the grid, with the reserve off (decision 26's corrections) and on.
const Cell = struct { lim: Limits, before: [3]i64, after: [3]i64 };

fn gridCell(x: u32, inc: u32, mtg: u16) Cell {
    const lim: Limits = .{ .kind = .clock, .wtime = x, .btime = x, .winc = inc, .binc = inc, .movestogo = mtg };
    return .{ .lim = lim, .before = budgetWith(.decision26, lim), .after = budgetWith(.corrected, lim) };
}

/// The reserve's rule, checked on one pair: the target is never touched; `panic` and `max`
/// are unchanged where they are within the cap, and the cap where they exceed it.
fn checkReserve(lim: Limits, before: [3]i64, after: [3]i64) !bool {
    const x: i64 = lim.wtime;
    const cap = tc_mod.reserveCap(x, lim.move_overhead);
    try std.testing.expectEqual(before[0], after[0]);
    try std.testing.expectEqual(@min(before[1], cap), after[1]);
    try std.testing.expectEqual(@min(before[2], cap), after[2]);
    const binds = before[1] > cap or before[2] > cap;
    // `max` exceeds the cap only where `panic` does (it is above `panic` only up to x / 5).
    if (before[2] > cap) try std.testing.expect(before[1] > cap);
    // It binds only on a clock of more than five times the overhead.
    if (binds) try std.testing.expect(x > 5 * @as(i64, lim.move_overhead));
    return binds;
}

test "time control: the clock reserve over the grid (clock 100 ms to 10 min; increment 0, 10 ms, 2 s; movestogo none, 40, 10, 5, 2, 1)" {
    var changed: u32 = 0;
    var cells: u32 = 0;
    std.debug.print("time control: reserve: cells where it binds (target / panic / max, before -> after):\n", .{});
    for (grid_clocks) |x| for (grid_incs) |inc| for (grid_mtgs) |mtg| {
        const c = gridCell(x, inc, mtg);
        cells += 1;
        if (try checkReserve(c.lim, c.before, c.after)) {
            changed += 1;
            std.debug.print("time control: reserve:   clock {d} inc {d} movestogo {d}: {d} / {d} / {d} -> {d} / {d} / {d}\n", .{ x, inc, mtg, c.before[0], c.before[1], c.before[2], c.after[0], c.after[1], c.after[2] });
        } else {
            try std.testing.expectEqual(c.before, c.after);
        }
    };
    std.debug.print("time control: reserve: {d} of {d} cells change\n", .{ changed, cells });
    try std.testing.expectEqual(@as(u32, 15 * 3 * 6), cells);
    // 61: every cell with one move to go and a clock of 500 ms or more (33); with an
    // increment of 2 s, every cell with a clock of 500 ms to 3 s (25 more); and with 2 s and
    // two moves to go, 5.7, 10 and 20 s (3). Each had a panic of over four fifths of the
    // clock, most of them the whole clock but 60 ms.
    try std.testing.expectEqual(@as(u32, 61), changed);
    // The game lost on time: 5.7 s with one move to go may now use 4.56 s, not 5.64 s.
    const lost = gridCell(5700, 0, 1);
    try std.testing.expectEqual([3]i64{ 5670, 5640, 5640 }, lost.before);
    try std.testing.expectEqual([3]i64{ 5670, 4560, 4560 }, lost.after);
    // 800 ms with one move to go: 640, not 740.
    try std.testing.expectEqual([3]i64{ 770, 640, 640 }, gridCell(800, 0, 1).after);
    // An increment larger than the clock, sudden death: 1 s + 2 s may use 800 ms, not 940.
    try std.testing.expectEqual([3]i64{ 1610, 940, 940 }, gridCell(1000, 2000, 0).before);
    try std.testing.expectEqual([3]i64{ 1610, 800, 800 }, gridCell(1000, 2000, 0).after);
    // Untouched: 40 moves in 60 s, move 1; 5 minutes sudden death; 150 ms with one move to go
    // (the Pascal's x - 2 * ovh is the tighter limit there).
    try std.testing.expectEqual(gridCell(60000, 0, 40).before, gridCell(60000, 0, 40).after);
    try std.testing.expectEqual(gridCell(600000, 0, 0).before, gridCell(600000, 0, 0).after);
    try std.testing.expectEqual([3]i64{ 120, 90, 90 }, gridCell(150, 0, 1).after);
}

test "time control: the clock reserve on a million generated clocks changes only where panic or max exceeds the cap" {
    var prng: std.Random.DefaultPrng = .init(0x7E5E_2026_1122);
    const r = prng.random();
    var changed: u32 = 0;
    var n: u32 = 0;
    while (n < 1_000_000) : (n += 1) {
        const scale = r.uintLessThan(u5, 22);
        const x: u32 = r.uintLessThan(u32, (@as(u32, 1) << scale) + 1);
        const o: u32 = if (r.boolean()) x else r.uintLessThan(u32, (@as(u32, 1) << r.uintLessThan(u5, 22)) + 1);
        const inc: u32 = switch (r.uintLessThan(u8, 4)) {
            0 => 0,
            1 => r.uintLessThan(u32, 100),
            2 => r.uintLessThan(u32, 10000),
            else => r.uintLessThan(u32, 100000),
        };
        const oinc: u32 = if (r.boolean()) inc else r.uintLessThan(u32, 10000);
        const mtg: u16 = if (r.boolean()) 0 else r.uintLessThan(u16, 60);
        const ovh: u32 = switch (r.uintLessThan(u8, 4)) {
            0 => 30,
            1 => 0,
            2 => r.uintLessThan(u32, 100),
            else => r.uintLessThan(u32, 5001),
        };
        const white = r.boolean();
        const lim: Limits = .{ .kind = .clock, .wtime = if (white) x else o, .btime = if (white) o else x, .winc = if (white) inc else oinc, .binc = if (white) oinc else inc, .movestogo = mtg, .move_overhead = ovh };
        var a: TimeControl = .{ .fixes = .decision26 };
        var b: TimeControl = .{ .fixes = .corrected };
        a.setLimits(lim);
        b.setLimits(lim);
        const side: tc_mod.Side = if (white) .white else .black;
        a.start(side, null, null, 20);
        b.start(side, null, null, 20);
        const mover: Limits = .{ .wtime = x, .move_overhead = ovh };
        if (try checkReserve(mover, .{ a.target, a.panic, a.max }, .{ b.target, b.panic, b.max })) changed += 1;
        // Inside an iteration, the corrected limits never let a move run past the cap.
        const cap = tc_mod.reserveCap(x, ovh);
        if (cap >= 1) try std.testing.expect(b.shouldStopInSearch(cap, 1, r.boolean(), false));
    }
    std.debug.print("time control: reserve: {d} of {d} generated clocks change\n", .{ changed, n });
    try std.testing.expect(changed > 10_000 and changed < n / 2);
}
