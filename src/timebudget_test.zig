//! Differential test of src/timebudget.zig against calls recorded from the running
//! original (tests/golden/timebudget/timebudget.zst and levels.zst, made by
//! tools/port/gen_timebudget_vectors.py, whose docstring defines the format).
//!
//! Each record holds the time state the original had at a routine's entry (read from
//! DGROUP), the routine's other inputs, and the values the original left in DGROUP at
//! its return. The test runs the Zig function on the entry state and compares, field
//! by field, the values the original's harness compares for that routine
//! (tools/research/rootmodel/check_time.py). On a mismatch it names the record, the
//! routine, its arguments and the first field that differs.

const std = @import("std");
const tb = @import("timebudget.zig");
const TimeState = tb.TimeState;

const NI = 57; // inputs (the TimeState)
const NA = 7; // arguments
const NO = 15; // outputs

const Kind = enum(u8) { start = 1, budget = 2, renew = 3, newctl = 4, ponder = 5, faillow = 6, charge = 7 };

/// The outputs, in the file's order (gen_timebudget_vectors.OUTPUTS), and their sizes.
const Out = enum(u4) { mtg, single_move, clear_best, last_before_control, base, hard, soft, fail_high, time_left0, time_left1, next_control0, next_control1, stop, ext_iteration, ponder_elapsed };
const out_size = [NO]u8{ 2, 2, 1, 1, 4, 4, 4, 4, 4, 4, 2, 2, 1, 1, 4 };

/// The outputs compared for each routine (as check_time.py compares them).
fn compared(k: Kind) []const Out {
    const limits_and_clock = [_]Out{ .base, .hard, .soft, .fail_high, .time_left0, .time_left1, .next_control0, .next_control1 };
    return switch (k) {
        .start => &[_]Out{ .mtg, .last_before_control } ++ limits_and_clock,
        .budget => &[_]Out{ .mtg, .single_move, .clear_best, .last_before_control } ++ limits_and_clock,
        .renew, .newctl, .charge => &limits_and_clock,
        .ponder => &[_]Out{ .base, .hard, .soft, .fail_high, .time_left0, .time_left1, .stop, .ponder_elapsed },
        .faillow => &limits_and_clock ++ [_]Out{ .stop, .ext_iteration },
    };
}

/// One record's time state: the `TimeState` (its value fields) and the storage of its
/// pointer fields (`TimeState.Values`), bound by `state`.
const Rec = struct {
    st: TimeState = .{},
    v: TimeState.Values = .{},

    fn state(r: *Rec) *TimeState {
        r.st.bindValues(&r.v);
        return &r.st;
    }
};

fn stateFrom(v: *const [NI]i32) Rec {
    var i: usize = 0;
    const S = struct {
        fn next(vv: *const [NI]i32, ii: *usize) i32 {
            const x = vv[ii.*];
            ii.* += 1;
            return x;
        }
    };
    var r: Rec = .{};
    const st = &r.st;
    const o = &r.v;
    o.level = @intCast(S.next(v, &i));
    o.preset = @intCast(S.next(v, &i));
    for (&st.preset_seconds) |*p| p.* = S.next(v, &i);
    st.game_in = @intCast(S.next(v, &i));
    for (&o.tc) |*t| {
        t.m1 = @intCast(S.next(v, &i));
        t.m2 = @intCast(S.next(v, &i));
        t.m3 = @intCast(S.next(v, &i));
        t.t1 = @intCast(S.next(v, &i));
        t.t2 = @intCast(S.next(v, &i));
        t.t3 = @intCast(S.next(v, &i));
        t.last = @intCast(S.next(v, &i));
    }
    o.computer_side = @intCast(S.next(v, &i));
    o.opponent_side = @intCast(S.next(v, &i));
    o.clock_side = @intCast(S.next(v, &i));
    o.pondering = @intFromBool(S.next(v, &i) != 0);
    o.analysis = @intFromBool(S.next(v, &i) != 0);
    o.move_number = @intCast(S.next(v, &i));
    o.next_control[0] = @intCast(S.next(v, &i));
    o.next_control[1] = @intCast(S.next(v, &i));
    o.time_left[0] = S.next(v, &i);
    o.time_left[1] = S.next(v, &i);
    o.game_ply = @intCast(S.next(v, &i));
    o.book_exit_ply = @intCast(S.next(v, &i));
    st.speed = S.next(v, &i);
    st.base_shift = @intCast(S.next(v, &i));
    o.clear_best = @intCast(S.next(v, &i));
    o.single_move = @intCast(S.next(v, &i));
    o.last_before_control = @intCast(S.next(v, &i));
    o.mtg = @intCast(S.next(v, &i));
    o.base = S.next(v, &i);
    o.hard = S.next(v, &i);
    o.soft = S.next(v, &i);
    o.fail_high = S.next(v, &i);
    o.tick58[0] = @intCast(S.next(v, &i));
    o.tick58[1] = @intCast(S.next(v, &i));
    for (&st.display) |*d| {
        for (d) |*x| x.* = @intCast(S.next(v, &i));
    }
    std.debug.assert(i == NI);
    return r;
}

/// Run the Zig port on one record; returns the predicted outputs (those not written
/// keep the entry value, which is what the original's image holds for them too).
fn run(k: Kind, rec0: Rec, a: *const [NA]i32) [NO]i32 {
    var rec = rec0;
    const st = rec.state();
    const v = &rec.v;
    var stop: ?i32 = null;
    var ext: ?i32 = null;
    var pe: ?i32 = null;
    switch (k) {
        .start => tb.startOfMove(st),
        .budget => tb.mainBudget(st, .{ .best = @intCast(a[0]), .second = @intCast(a[1]), .byte = @intCast(a[2]), .flag = @intCast(a[3]) }),
        .renew => tb.addControlTime(st, st.computerSide()),
        .newctl => tb.checkNewControl(st, @intCast(a[0])),
        .ponder => {
            const s = tb.ponderCredit(st, .{
                .elapsed = a[0],
                .iteration = @intCast(a[1]),
                .ext_iteration = @intCast(a[2]),
                .fail_high_pending = a[3] != 0,
                .root_score = @intCast(a[4]),
                .reference_score = @intCast(a[5]),
            });
            stop = if (s) 1 else a[6];
            if (v.level < 3) pe = a[0];
        },
        .faillow => {
            const e = tb.failLowExtension(st, a[0], @intCast(a[1]));
            stop = if (e) 0 else a[3];
            ext = if (e) a[1] else a[2];
        },
        .charge => tb.chargeClock(st, a[0], a[1] != 0, a[2] != 0),
    }
    var o: [NO]i32 = undefined;
    o[@backingInt(Out.mtg)] = v.mtg;
    o[@backingInt(Out.single_move)] = v.single_move;
    o[@backingInt(Out.clear_best)] = v.clear_best;
    o[@backingInt(Out.last_before_control)] = v.last_before_control;
    o[@backingInt(Out.base)] = v.base;
    o[@backingInt(Out.hard)] = v.hard;
    o[@backingInt(Out.soft)] = v.soft;
    o[@backingInt(Out.fail_high)] = v.fail_high;
    o[@backingInt(Out.time_left0)] = v.time_left[0];
    o[@backingInt(Out.time_left1)] = v.time_left[1];
    o[@backingInt(Out.next_control0)] = v.next_control[0];
    o[@backingInt(Out.next_control1)] = v.next_control[1];
    o[@backingInt(Out.stop)] = stop orelse 0;
    o[@backingInt(Out.ext_iteration)] = ext orelse 0;
    o[@backingInt(Out.ponder_elapsed)] = pe orelse 0;
    return o;
}

fn readVectors(gpa: std.mem.Allocator, name: []const u8) ![]u8 {
    var path_buf: [256]u8 = undefined;
    const dir = @import("build_options").golden_dir;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/timebudget/{s}", .{ dir, name });
    const compressed = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, gpa, .limited(64 << 20));
    defer gpa.free(compressed);
    var in: std.Io.Reader = .fixed(compressed);
    const window = try gpa.alloc(u8, std.compress.zstd.default_window_len + std.compress.zstd.block_size_max);
    defer gpa.free(window);
    var zd = std.compress.zstd.Decompress.init(&in, window, .{});
    return zd.reader.allocRemaining(gpa, .limited(64 << 20));
}

test "time budget: every recorded call of the original" {
    try replayFile("timebudget.zst");
}

test "time budget: the recordings of the branches the first runs never took (2026-11-22)" {
    // tests/golden/timebudget/levels.zst: a level-2 record of three periods, "1 move in 1
    // minute" typed and in monitor mode, 2 s per move after 61 moves typed in monitor mode
    // (auto-play and normal play), the book on at level 2, Bonus 30 s, and the clock mode
    // "stop chess clocks" (tests/golden/README.md).
    try replayFile("levels.zst");
}

fn replayFile(name: []const u8) !void {
    const gpa = std.testing.allocator;
    const raw = try readVectors(gpa, name);
    defer gpa.free(raw);
    try std.testing.expectEqualSlices(u8, "MCTB", raw[0..4]);
    const hdr = [4]u16{
        std.mem.readInt(u16, raw[4..6], .little),  std.mem.readInt(u16, raw[6..8], .little),
        std.mem.readInt(u16, raw[8..10], .little), std.mem.readInt(u16, raw[10..12], .little),
    };
    try std.testing.expectEqual([4]u16{ 1, NI, NA, NO }, hdr);
    var i: usize = 12;
    var count: [8]u32 = @splat(0);
    var n: u32 = 0;
    var failures: u32 = 0;
    while (true) {
        const kb = raw[i];
        i += 1;
        if (kb == 0) {
            try std.testing.expectEqual(n, std.mem.readInt(u32, raw[i..][0..4], .little));
            break;
        }
        var vals: [NI + NA + NO]i32 = undefined;
        for (&vals) |*v| {
            v.* = std.mem.readInt(i32, raw[i..][0..4], .little);
            i += 4;
        }
        const k: Kind = @fromBackingInt(@intCast(kb));
        const rec = stateFrom(vals[0..NI]);
        const st = rec.v;
        const args = vals[NI..][0..NA];
        const real = vals[NI + NA ..][0..NO];
        const got = run(k, rec, args);
        var outs = compared(k);
        if (k == .ponder and st.level >= 3) outs = outs[0 .. outs.len - 1];
        for (outs) |f| {
            const fi = @backingInt(f);
            const mask: u32 = if (out_size[fi] == 4) 0xFFFF_FFFF else (@as(u32, 1) << @intCast(8 * out_size[fi])) - 1;
            if ((@as(u32, @bitCast(got[fi])) & mask) != (@as(u32, @bitCast(real[fi])) & mask)) {
                if (failures < 10) std.debug.print(
                    "timebudget record {d} ({s}, level {d}, preset {d}, move {d}, side {d}, args {any}): {s} port {d} original {d}\n",
                    .{ n, @tagName(k), st.level, st.preset, st.move_number, st.computer_side, args.*, @tagName(f), got[fi], real[fi] },
                );
                failures += 1;
                break;
            }
        }
        count[kb] += 1;
        n += 1;
    }
    std.debug.print(
        "timebudget {s}: {d} recorded calls replayed: start {d}, budget {d}, renew {d}, newctl {d}, ponder {d}, faillow {d}, charge {d}; {d} mismatches\n",
        .{ name, n, count[1], count[2], count[3], count[4], count[5], count[6], count[7], failures },
    );
    try std.testing.expectEqual(@as(u32, 0), failures);
}

test "set_time_budget: the period cap, the single-move control and the base shift" {
    // Branches that never ran in the recorded games, computed by hand from the model.
    // Level 2, "5 moves in 1 minute" with 2 minutes left: base = (2184-30)/5 = 430;
    // cap 3T/n = 3·1092/5 = 655 does not apply; with 10 minutes left base = 2154 > 655
    // and the cap applies.
    var r: Rec = .{ .v = .{ .level = tb.level_time_controls, .move_number = 1, .next_control = .{ 6, 6 }, .time_left = .{ 10920, 10920 } } };
    const st = r.state();
    r.v.tc = .{ .{ .m1 = 5, .t1 = 1, .t2 = 1, .last = 5 }, .{ .m1 = 5, .t1 = 1, .t2 = 1, .last = 5 } };
    tb.setTimeBudget(st);
    try std.testing.expectEqual(@as(i32, 655), r.v.base);
    // The same with both records "1 move in 1 minute, no second period": [1480] = 1
    // and the cap is not applied at step 4 (moves to go 5 < 6, so not at step 8 either).
    r.v.tc = .{ .{ .m1 = 1, .t1 = 1, .t2 = 0, .last = 5 }, .{ .m1 = 1, .t1 = 1, .t2 = 0, .last = 5 } };
    tb.setTimeBudget(st);
    try std.testing.expectEqual(@as(i16, 1), r.v.single_move);
    try std.testing.expectEqual(@as(i32, @divTrunc(10920 - 30, 5)), r.v.base);
    // Base shift 2 at 5 s per move: base 90 → ((90-3) >> 2) + 3 = 24.
    var q: Rec = .{ .st = .{ .base_shift = 2 }, .v = .{ .level = tb.level_per_move, .preset = 2, .next_control = .{ 61, 61 }, .time_left = .{ 5460, 5460 } } };
    tb.setTimeBudget(q.state());
    try std.testing.expectEqual(@as(i32, 24), q.v.base);
}
