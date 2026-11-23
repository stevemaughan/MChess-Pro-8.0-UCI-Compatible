//! DEV-019: the two piece-activity routines against each other's colour mirror
//! (src/activity.zig; docs/arch/53-evaluation-pieces-kings.md §4.3 and §6.3).
//!
//! The recorded calls are those of src/evalpieces_test.zig (tests/golden/evalpieces/),
//! whose replay proves both routines equal to the original; the generated ones are
//! recorded states changed at random as there (`mutate`, `scramble`; constant seeds).
//!
//! - Black's routine written as White's colour mirror with the five forms of the original
//!   (`activity.black_forms`) equals the original Black routine on every call: the five
//!   forms are every place where 1E30 is not the mirror of 16E4.
//! - Mirrored: each call's state is mirrored (ranks reversed, colours exchanged) and the
//!   other colour's routine run on it. The original differs from its mirror in the calls
//!   counted here; with DEV-019 corrected no call does.

const std = @import("std");
const pos = @import("position.zig");
const activity = @import("activity.zig");
const EvalState = @import("eval_state.zig").EvalState;
const ept = @import("evalpieces_test.zig");

const Position = pos.Position;

const fix019: pos.Fixes = blk: {
    var f = pos.Fixes.original;
    f.dev019_activity_mirror = true;
    break :blk f;
};

fn mirrorSquare(s: usize) usize {
    return (11 - s / 10) * 10 + s % 10;
}

fn swapCode(b: u8) u8 {
    return if (b >= 1 and b <= 6) b + 7 else if (b >= 8 and b <= 13) b - 7 else b;
}

/// The colour mirror of a call's state as the activity routines read it: ranks reversed,
/// colours exchanged; each side's piece list, pawn attacks, king-ray map (direction codes
/// mirrored, `activity.mirrorRayCode`), pawns per file, material, piece count, passed-pawn
/// mask and activity tables are the other side's. A captured entry (120 or more) stays
/// one.
fn mirrorState(p: *const Position, e: *const EvalState, mp: *Position, me: *EvalState) void {
    mp.* = p.*;
    me.* = e.*;
    for (0..120) |s| {
        const m = mirrorSquare(s);
        mp.board[m] = swapCode(p.board[s]);
        mp.square_slot[m] = p.square_slot[s];
        for (0..2) |c| {
            mp.pawn_attacks[1 - c][m] = p.pawn_attacks[c][s];
            mp.king_rays[1 - c][m] = activity.mirrorRayCode(p.king_rays[c][s]);
            for (0..3) |k| me.nrq_activity[1 - c][k][m] = e.nrq_activity[c][k][s];
            // The bishop tables hold squares 0..99 (the original's room).
            if (s < 100 and m < 100) me.bishop_activity[1 - c][m] = e.bishop_activity[c][s];
        }
    }
    for (0..2) |c| {
        for (0..16) |i| {
            const entry = p.piece_list[16 * c + i];
            mp.piece_list[16 * (1 - c) + i] = if (entry < 120) @intCast(mirrorSquare(entry)) else entry;
        }
        mp.pawns_per_file[1 - c] = p.pawns_per_file[c];
        mp.piece_material[1 - c] = p.piece_material[c];
        mp.piece_count[1 - c] = p.piece_count[c];
        me.passed_pawns[1 - c] = e.passed_pawns[c];
    }
}

const form_names = [_][]const u8{ "bishop_pawn_stop", "rook_pawn_table", "rook_behind_attacked", "queen_diag_queen_king", "queen_side_border" };

fn onlyForm(comptime i: usize) activity.Forms {
    var f: activity.Forms = .{};
    @field(f, form_names[i]) = true;
    return f;
}

const Tally = struct {
    calls: usize = 0,
    /// Original Black (forms written as the mirror) differs from the original.
    forms_unequal: usize = 0,
    /// Either colour differs from the other colour's routine on the mirror.
    differ_original: usize = 0,
    differ_fixed: usize = 0,
    /// The call's position where form i alone changes Black's result, on it or on its
    /// mirror.
    by_form: [form_names.len]usize = @splat(0),
    /// Calls whose result the switch changes: White, Black, mobility_term.
    changed: [3]usize = @splat(0),
    /// The first position for each form, for the report.
    example: [form_names.len]?Example = @splat(null),

    const Example = struct { fen: [100]u8 = undefined, len: usize = 0, white_on_mirror: i16, black: i16, black_fixed: i16, white: i16, white_fixed: i16 };
};

fn check(p: *const Position, e: *const EvalState, t: *Tally, mp: *Position, me: *EvalState) !void {
    t.calls += 1;
    mirrorState(p, e, mp, me);
    const black = activity.pieceActivityBlack(p, e);
    const white = activity.pieceActivityWhite(p, e);
    if (activity.pieceActivityForms(true, activity.black_forms, p, e) != black) t.forms_unequal += 1;
    if (activity.pieceActivityForms(true, activity.black_forms, mp, me) != activity.pieceActivityBlack(mp, me)) t.forms_unequal += 1;
    // The original against its mirror, both ways.
    const w_on_m = activity.pieceActivityWhite(mp, me);
    const b_on_m = activity.pieceActivityBlack(mp, me);
    if (black != w_on_m or white != b_on_m) t.differ_original += 1;
    const bf = activity.pieceActivityBlackFixes(fix019, p, e);
    const wf = activity.pieceActivityWhiteFixes(fix019, p, e);
    if (bf != activity.pieceActivityWhiteFixes(fix019, mp, me) or wf != activity.pieceActivityBlackFixes(fix019, mp, me)) t.differ_fixed += 1;
    if (wf != white) t.changed[0] += 1;
    if (bf != black) t.changed[1] += 1;
    if (activity.mobilityTermFixes(fix019, p, e) != activity.mobilityTerm(p, e)) t.changed[2] += 1;
    const none_p = activity.pieceActivityForms(true, .{}, p, e);
    const none_m = activity.pieceActivityForms(true, .{}, mp, me);
    inline for (0..form_names.len) |i| {
        const vp = activity.pieceActivityForms(true, onlyForm(i), p, e);
        const vm = activity.pieceActivityForms(true, onlyForm(i), mp, me);
        if (vp != none_p or vm != none_m) {
            t.by_form[i] += 1;
            if (t.example[i] == null and vp != none_p) {
                var x: Tally.Example = .{ .white_on_mirror = w_on_m, .black = black, .black_fixed = bf, .white = white, .white_fixed = wf };
                x.len = ept.fenOf(&x.fen, p).len;
                t.example[i] = x;
            }
        }
    }
}

fn report(what: []const u8, t: *const Tally) void {
    std.debug.print("activity mirrored, {s}: {d} calls; 1E30 written as 16E4's mirror with its five forms differs from 1E30 in {d}; differ from the mirror: original {d}, DEV-019 corrected {d}; the switch changes White {d}, Black {d}, mobility_term {d}\n", .{ what, t.calls, t.forms_unequal, t.differ_original, t.differ_fixed, t.changed[0], t.changed[1], t.changed[2] });
    for (form_names, t.by_form, t.example) |n, c, ex| {
        std.debug.print("  form {s}: changes Black's result in {d} calls", .{ n, c });
        if (ex) |x| std.debug.print("; first: {s}: Black original {d}, White on the mirror {d}, Black corrected {d} (White {d}, corrected {d})", .{ x.fen[0..x.len], x.black, x.white_on_mirror, x.black_fixed, x.white, x.white_fixed });
        std.debug.print("\n", .{});
    }
}

test "activity: 1E30 is 16E4's colour mirror but for five forms, and DEV-019 makes it the mirror: recorded calls" {
    const gpa = std.testing.allocator;
    var t: Tally = .{};
    const mp = try gpa.create(Position);
    defer gpa.destroy(mp);
    const me = try gpa.create(EvalState);
    defer gpa.destroy(me);
    for (ept.runs) |name| {
        var col: ept.Collector = .{ .stride = 1 };
        defer col.deinit(gpa);
        _ = try ept.replayInto(gpa, name, &col);
        for (col.calls.items) |call| {
            if (call.tag != 2 and call.tag != 3) continue;
            try check(&col.positions.items[call.p], &col.states.items[call.e], &t, mp, me);
        }
    }
    report("recorded", &t);
    try std.testing.expectEqual(@as(usize, 0), t.forms_unequal);
    try std.testing.expectEqual(@as(usize, 0), t.differ_fixed);
    try std.testing.expect(t.differ_original > 0);
}

test "activity: 1E30 is 16E4's colour mirror but for five forms, and DEV-019 makes it the mirror: generated calls" {
    const gpa = std.testing.allocator;
    var col: ept.Collector = .{ .stride = 50 };
    defer col.deinit(gpa);
    for (ept.runs) |name| _ = try ept.replayInto(gpa, name, &col);
    var t: Tally = .{};
    const mp = try gpa.create(Position);
    defer gpa.destroy(mp);
    const me = try gpa.create(EvalState);
    defer gpa.destroy(me);
    var prng: std.Random.DefaultPrng = .init(0xDE7_0019);
    const r = prng.random();
    const n: usize = if (@import("builtin").mode == .debug) 100_000 else 1_200_000;
    for (0..n) |i| {
        const call = col.calls.items[r.uintLessThan(usize, col.calls.items.len)];
        var p = col.positions.items[call.p];
        var e = col.states.items[call.e];
        if (i % 4 == 0) ept.scramble(r, &p);
        if (i % 8 != 1) ept.mutate(r, &p, &e);
        try check(&p, &e, &t, mp, me);
    }
    report("generated", &t);
    try std.testing.expectEqual(@as(usize, 0), t.forms_unequal);
    try std.testing.expectEqual(@as(usize, 0), t.differ_fixed);
    // Every form that can arise is seen, and corrected.
    inline for (0..4) |i| try std.testing.expect(t.by_form[i] > 0);
}

// ---- timing ------------------------------------------------------------------------------

const bench = @import("bench.zig");
const activity_ref = @import("activity_reference.zig");

const Routine = enum { white_ref, white, white_fixed, black_ref, black, black_fixed };

fn timeRoutine(comptime which: Routine, ps: []const Position, es: []const *const EvalState, best: *bench.Best) void {
    const t0 = bench.now();
    for (ps, es) |*p, e| {
        bench.keep(p);
        const r = switch (which) {
            .white_ref => activity_ref.pieceActivityWhite(p, e),
            .white => activity.pieceActivityWhite(p, e),
            .white_fixed => activity.pieceActivityWhiteFixes(fix019, p, e),
            .black_ref => activity_ref.pieceActivityBlack(p, e),
            .black => activity.pieceActivityBlack(p, e),
            .black_fixed => activity.pieceActivityBlackFixes(fix019, p, e),
        };
        bench.keep(r);
    }
    best.pass(t0);
}

test "bench: activity: the two routines, original and with DEV-019 corrected" {
    if (!bench.enabled) return;
    const gpa = std.testing.allocator;
    var col: ept.Collector = .{ .stride = 1, .per_file = 600 };
    defer col.deinit(gpa);
    for (ept.runs) |name| _ = try ept.replayInto(gpa, name, &col);
    const n = 4000;
    const passes = 100;
    inline for (.{ 2, 3 }) |tag| {
        const ps = try gpa.alloc(Position, n);
        defer gpa.free(ps);
        const es = try gpa.alloc(*const EvalState, n);
        defer gpa.free(es);
        var total: usize = 0;
        for (col.calls.items) |call| total += @intFromBool(call.tag == tag);
        var i: usize = 0;
        var k: usize = 0;
        for (col.calls.items) |call| if (call.tag == tag) {
            if (k * n / total == i and i < n) {
                ps[i] = col.positions.items[call.p];
                es[i] = &col.states.items[call.e];
                i += 1;
            }
            k += 1;
        };
        std.debug.assert(i == n);
        const set = if (tag == 2) [3]Routine{ .white_ref, .white, .white_fixed } else [3]Routine{ .black_ref, .black, .black_fixed };
        var best: [3]bench.Best = @splat(.{});
        for (0..passes) |pass| {
            inline for (0..3) |j| {
                // Rotate which goes first: the first of a set runs a little slower.
                const m = (j + pass) % 3;
                inline for (0..3) |q| if (q == m) timeRoutine(set[q], ps, es, &best[q]);
            }
        }
        inline for (0..3) |q| best[q].report(@tagName(set[q]), n, passes, 0);
    }
}
