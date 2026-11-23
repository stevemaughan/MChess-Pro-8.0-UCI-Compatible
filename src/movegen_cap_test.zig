//! DEV-063: the move generators at the list's capacity of 100 entries (src/movegen.zig,
//! `Out.room`, `Out.narrow`, `GenAll.uroom`, `GenAll.finish`).
//!
//! What the original writes past the 100th entry is compared with a reference that has
//! no cap: the same generator run once for each piece-list slot of the side, the other
//! slots of the side marked off the board (an entry of 120 or more, which every
//! generator skips), and the moves of that slot's square kept. The two knight slots and
//! the king slot stay on the board in every run, because the exchange evaluator reads
//! them (not in the cases with one knight in many slots, whose exchanges all return
//! before reading them); their own moves are taken from the run of their own slot.
//! gen_all_moves sorts its scored group, so the reference has those moves but not their
//! order of writing: the port's are checked to be the reference's, in sort order, and,
//! when cut, the highest-scored (`checkScored`); the search tests show the order of
//! equal scores (src/adapt_setup_manymoves_test.zig). Each run starts from
//! the same position and search variables, so the marks gen_all_moves decrements are as
//! at the start of the call, as they are for each move in one call (no two moves share a
//! mark). The concatenation in the generator's slot order (DG:1A60 for gen_all_moves,
//! 0..15 for the others) is what the original writes, from the start of the list on.
//! The test positions are chosen so that the per-slot runs see the same state: no hint
//! squares (DG:725C, A8D8, A846 zero) and no enemy queen or rook in slots 4..6, so that
//! no generator writes into a king ray map between slots.
//!
//! From that reference the original's result, where it is defined, is:
//! - gen_all_moves (1E9D:3938, end 48D8): the scored group sorted by sort_moves, then the
//!   unscored group in generation order, its score bytes those found in DG:B106, cut at
//!   100 entries in all; the count n1 + n2; `SearchVars.unscored` holds the first 100
//!   unscored moves with their score bytes untouched. A scored group of more than 100:
//!   the first 100 of it sorted (the original then wraps its copy count; the port
//!   returns 100, the original's AX).
//! - the four quiescence generators: the list as written, unsorted, and the count; past
//!   100 the original's list runs into the next ply's, and the node sorts all of it
//!   (0000:4BBC, 6142): the port's list is the first 100 of that sort, count 100.

const std = @import("std");
const pos = @import("position.zig");
const mg = @import("movegen.zig");
const see_mod = @import("see.zig");
const setup = @import("setup.zig");
const fen = @import("fen.zig");
const sortMoves = @import("sort.zig").sortMoves;
const dg = @import("original.zig").dgroup;

const Position = pos.Position;
const Move = pos.Move;
const Side = pos.Side;

/// DG:1A60: gen_all_moves' slot order.
const all_slot_order = dg(0x1A60, 16);

const Gen = enum { all, tactical, no_losers, quiescence, captures };

fn positionOf(text: []const u8) !Position {
    const d = try fen.parse(text);
    var p: Position = .{};
    var v: setup.SetupVars = .{};
    setup.buildFromDescription(&p, &v, &d);
    return p;
}

fn generate(gen: Gen, p: *Position, v: *mg.SearchVars, list: *mg.MoveList, side: Side, ply: usize) u16 {
    var s: see_mod.Scratch = .{};
    return switch (gen) {
        .all => mg.genAllMoves(mg.Fixes.corrected, p, &s, v, list, side, ply, .{}),
        .tactical => mg.genTacticalMoves(p, &s, v, 0, list, side, ply),
        .no_losers => mg.genTacticalMovesNoLosers(p, &s, v, list, side, ply),
        .quiescence => mg.genQuiescenceMoves(p, &s, v, list, side, ply),
        .captures => mg.genCaptures(p, &s, v, list, side, ply),
    };
}

/// The uncapped output of `gen`: the moves of the list group in the order written, and
/// for gen_all_moves the unscored group in the order written (score bytes as written,
/// i.e. not at all: 0 here).
const Reference = struct {
    list: [mg.max_written]Move = undefined,
    n: usize = 0,
    unscored: [mg.max_written]Move = undefined,
    nu: usize = 0,
};

/// knights: keep the knight slots 0 and 1 on the board in every run (the exchange
/// evaluator reads them); false for the cases whose exchange calls return before reading
/// them (a knight taking a rook or a queen: 2B9F:C345).
fn reference(gen: Gen, p0: *const Position, v0: *const mg.SearchVars, side: Side, ply: usize, knights: bool) !Reference {
    var r: Reference = .{};
    const base: usize = 16 * @as(usize, @backingInt(side));
    var order: [16]u8 = undefined;
    for (&order, 0..) |*o, i| o.* = if (gen == .all) all_slot_order[i] else @intCast(i);
    for (order) |slot| {
        const sq = p0.piece_list[base + slot];
        if (sq >= 120) continue;
        var p = p0.*;
        for (0..16) |k| {
            if (k == slot or k == 7 or (knights and (k == 0 or k == 1))) continue;
            p.piece_list[base + k] = 0xFF;
        }
        var v = v0.*;
        // The list group of one slot is at most 27 moves; the unscored group of one slot
        // too, so `v.unscored` (100) holds it.
        var list: mg.MoveList = undefined;
        const n = generate(gen, &p, &v, &list, side, ply);
        if (n == mg.king_capture) return error.KingCapture;
        if (gen == .all) {
            // gen_all_moves copies its unscored group after the sorted scored group; in
            // one slot's run nothing is cut, so the scored group is the list before the
            // unscored moves written. It comes back sorted, so the reference has the
            // scored moves but not their order of writing (see `checkScored`).
            const nu_slot = countUnscored(&v, v0, n);
            const ns_slot = n - nu_slot;
            for (list[0..ns_slot]) |m| if (m.from == sq) {
                r.list[r.n] = m;
                r.n += 1;
            };
            for (v.unscored[0..nu_slot]) |m| if (m.from == sq) {
                r.unscored[r.nu] = .{ .from = m.from, .to = m.to, .flag = m.flag, .score = 0 };
                r.nu += 1;
            };
        } else {
            for (list[0..n]) |m| if (m.from == sq) {
                r.list[r.n] = m;
                r.n += 1;
            };
        }
    }
    return r;
}

/// The number of unscored moves one call of gen_all_moves wrote: the entries of
/// `SearchVars.unscored` it changed. The test positions give every slot's run fewer
/// than 100 moves, and the score bytes there are made distinct from any from byte, so
/// an entry written is one whose from, to or flag differs from the start; an entry
/// rewritten with the same bytes would be missed, which the starting pattern rules out
/// (from 0, never a square).
fn countUnscored(v: *const mg.SearchVars, v0: *const mg.SearchVars, n: u16) usize {
    var k: usize = 0;
    while (k < @min(n, mg.list_len) and v.unscored[k].from != v0.unscored[k].from) k += 1;
    return k;
}

/// The search variables every test starts from: no marks unless given, no hints, the
/// quiet-check flag set (so that gen_quiescence_moves keeps its queen checks off the
/// last rank), and the unscored group's stale score bytes a pattern.
fn startVars() mg.SearchVars {
    var v: mg.SearchVars = .{};
    for (&v.unscored, 0..) |*m, i| m.* = .{ .from = 0, .to = 0, .flag = 0, .score = @truncate(0x37 *% i +% 5) };
    v.check_flag = 1;
    return v;
}

/// The quiescence generators: what the port must return, from the uncapped reference
/// (exact: these generators do not sort).
fn expectedQuiescence(r: *const Reference, out: *mg.MoveList) u16 {
    var all: [mg.max_written]Move = r.list;
    if (r.n <= mg.list_len) {
        @memcpy(out[0..r.n], all[0..r.n]);
        return @intCast(r.n);
    }
    sortMoves(all[0..r.n], @intCast(r.n));
    @memcpy(out, all[0..mg.list_len]);
    return mg.list_len;
}

fn sameMove(a: Move, b: Move) bool {
    return a.from == b.from and a.to == b.to and a.flag == b.flag and a.score == b.score;
}

/// gen_all_moves' sorted part: `got` (the first `k` entries of the list) is in the order
/// sort_moves leaves (scores non-increasing as signed bytes), each entry is a distinct
/// scored move of the reference, and when the group was cut no move left out scores
/// above the lowest kept. (The order of equal scores is sort_moves' over the order of
/// writing, which the per-slot reference does not have; the search tests show it.)
fn checkScored(r: *const Reference, got: []const Move) !void {
    var used: [mg.max_written]bool = @splat(false);
    for (got, 0..) |m, i| {
        if (i > 0) try std.testing.expect(@as(i8, @bitCast(got[i - 1].score)) >= @as(i8, @bitCast(m.score)));
        var found = false;
        for (r.list[0..r.n], 0..) |x, j| {
            if (!used[j] and sameMove(x, m)) {
                used[j] = true;
                found = true;
                break;
            }
        }
        if (!found) {
            std.debug.print("  sorted entry {d} {any} is not a scored move of the reference\n", .{ i, m });
            return error.ListDiffers;
        }
    }
    if (got.len == 0) return;
    const lowest: i8 = @bitCast(got[got.len - 1].score);
    for (r.list[0..r.n], 0..) |x, j| {
        if (!used[j]) try std.testing.expect(@as(i8, @bitCast(x.score)) <= lowest);
    }
}

const Case = struct {
    name: []const u8,
    fen: []const u8,
    gen: Gen,
    /// Marks set on every quiet move of the side (gen_all_moves scores a marked quiet
    /// move): the scored group then holds nearly every move.
    marks: bool = false,
    /// Every slot of the side but the king's (7) made to hold the square of slot 0, a
    /// knight that takes eight rooks and queens: each slot then writes that knight's
    /// moves again, 15 times in all. A state no position can give (one piece in many
    /// slots), made to pass the cap in the generators whose moves no position has been
    /// found to take past it (the quiescence generators).
    dup: bool = false,
    /// The uncapped count the case is built to reach (at least).
    min_written: usize,
};

/// A White knight on e4 attacked by nothing it cannot take: eight Black rooks and queens
/// on its eight squares (an exchange value of victim - 9 > 0 at once, 2B9F:C345, so every
/// generator keeps the capture). The Black king is shut in on a8, so that no knight move
/// checks it and no Black queen or rook stands on its rays. The mirror for Black.
const knight_white = "kb6/pp6/3q1q2/2q3r1/4N3/2r3q1/3q1q2/7K w - - 0 1";
const knight_black = "7k/3Q1Q2/2R3Q1/4n3/2Q3R1/3Q1Q2/PP6/KB6 b - - 0 1";
const pos218_white = "R6R/3Q4/1Q4Q1/4Q3/2Q4Q/Q4Q2/pp1Q4/kBNN1KB1 w - - 0 1";
const pos218_black = "Kbnn1kb1/PP1q4/q4q2/2q4q/4q3/1q4q1/3q4/r6r b - - 0 1";

/// The position of 218 legal moves for White and its mirror for Black, and the knight
/// state above for every generator, both colours.
const cases = [_]Case{
    .{ .name = "218 moves, gen_all_moves, White", .fen = pos218_white, .gen = .all, .min_written = 218 },
    .{ .name = "218 moves, gen_all_moves, Black", .fen = pos218_black, .gen = .all, .min_written = 218 },
    .{ .name = "218 moves, gen_all_moves, every quiet move marked (a scored group past 100), White", .fen = pos218_white, .gen = .all, .marks = true, .min_written = 218 },
    .{ .name = "218 moves, gen_all_moves, every quiet move marked (a scored group past 100), Black", .fen = pos218_black, .gen = .all, .marks = true, .min_written = 218 },
    .{ .name = "one knight in 15 slots, gen_all_moves, White", .fen = knight_white, .gen = .all, .dup = true, .min_written = 120 },
    .{ .name = "one knight in 15 slots, gen_all_moves, Black", .fen = knight_black, .gen = .all, .dup = true, .min_written = 120 },
    .{ .name = "one knight in 15 slots, gen_tactical_moves, White", .fen = knight_white, .gen = .tactical, .dup = true, .min_written = 120 },
    .{ .name = "one knight in 15 slots, gen_tactical_moves, Black", .fen = knight_black, .gen = .tactical, .dup = true, .min_written = 120 },
    .{ .name = "one knight in 15 slots, gen_tactical_moves_no_losers, White", .fen = knight_white, .gen = .no_losers, .dup = true, .min_written = 120 },
    .{ .name = "one knight in 15 slots, gen_tactical_moves_no_losers, Black", .fen = knight_black, .gen = .no_losers, .dup = true, .min_written = 120 },
    .{ .name = "one knight in 15 slots, gen_quiescence_moves, White", .fen = knight_white, .gen = .quiescence, .dup = true, .min_written = 120 },
    .{ .name = "one knight in 15 slots, gen_quiescence_moves, Black", .fen = knight_black, .gen = .quiescence, .dup = true, .min_written = 120 },
    .{ .name = "one knight in 15 slots, gen_captures, White", .fen = knight_white, .gen = .captures, .dup = true, .min_written = 120 },
    .{ .name = "one knight in 15 slots, gen_captures, Black", .fen = knight_black, .gen = .captures, .dup = true, .min_written = 120 },
};

fn markAll(p: *const Position, v: *mg.SearchVars, side: Side) void {
    const base: usize = 16 * @as(usize, @backingInt(side));
    for (p.piece_list[base..][0..16]) |from| {
        if (from >= 120) continue;
        for (21..99) |to| {
            if (p.board[to] == pos.border) continue;
            // Only the moves a piece can make lie inside the table (DG:781A).
            const df = @abs(@as(i32, @intCast(to % 10)) - @as(i32, from % 10));
            const dr = @abs(@as(i32, @intCast(to / 10)) - @as(i32, from / 10));
            const line = (df == 0 or dr == 0 or df == dr) and to != from;
            const knight = (df == 1 and dr == 2) or (df == 2 and dr == 1);
            if (!line and !knight) continue;
            v.marks[mg.markIndex(from, to)] = @truncate(1 + (@as(usize, from) * 7 + to * 13) % 120);
        }
    }
}

fn runCase(c: Case) !void {
    var p0 = try positionOf(c.fen);
    const d = try fen.parse(c.fen);
    const side = d.side_to_move;
    const base: usize = 16 * @as(usize, @backingInt(side));
    const ply: usize = 1;
    if (c.dup) {
        for (1..16) |k| if (k != 7) {
            p0.piece_list[base + k] = p0.piece_list[base];
        };
    }
    var v0 = startVars();
    if (c.marks) markAll(&p0, &v0, side);
    const r = try reference(c.gen, &p0, &v0, side, ply, !c.dup);
    const written = r.n + r.nu;
    try std.testing.expect(written >= c.min_written);

    var p = p0;
    var v = v0;
    // Guards on both sides of the list: nothing may be written past it.
    const Guarded = extern struct { before: [8]Move, list: mg.MoveList, after: [8]Move };
    const fill: Move = .{ .from = 0xEE, .to = 0xEE, .flag = 0xEE, .score = 0xEE };
    var g: Guarded = .{ .before = @splat(fill), .list = @splat(fill), .after = @splat(fill) };
    const n = generate(c.gen, &p, &v, &g.list, side, ply);
    const list = g.list;
    std.debug.print("movegen cap: {s}: {d} moves written uncapped ({d} to the list, {d} unscored), count {d}\n", .{ c.name, written, r.n, r.nu, n });
    if (c.gen == .all) {
        const ns = @min(r.n, mg.list_len);
        const n2 = if (r.n > mg.list_len) 0 else @min(r.nu, mg.list_len - r.n);
        try std.testing.expectEqual(@as(u16, @intCast(ns + n2)), n);
        try checkScored(&r, list[0..ns]);
        // The unscored group, in the order written, with the score bytes of DG:B106.
        for (0..n2) |i| {
            const m = r.unscored[i];
            const want: Move = .{ .from = m.from, .to = m.to, .flag = m.flag, .score = v0.unscored[i].score };
            if (!sameMove(want, list[ns + i])) {
                std.debug.print("  entry {d}: port {any}, expected {any}\n", .{ ns + i, list[ns + i], want });
                return error.ListDiffers;
            }
        }
        // DG:B106: the first 100 unscored moves written, their score bytes untouched;
        // the variables after it unchanged.
        for (0..mg.list_len) |i| {
            const got = v.unscored[i];
            try std.testing.expectEqual(v0.unscored[i].score, got.score);
            if (i < r.nu) {
                try std.testing.expectEqual(r.unscored[i].from, got.from);
                try std.testing.expectEqual(r.unscored[i].to, got.to);
            } else try std.testing.expect(sameMove(got, v0.unscored[i]));
        }
        try std.testing.expectEqual(v0.bishop_hint, v.bishop_hint);
        try std.testing.expectEqual(v0.rook_hint, v.rook_hint);
        try std.testing.expectEqual(v0.queen_hint, v.queen_hint);
        try std.testing.expectEqual(v0.check_flag, v.check_flag);
    } else {
        var want: mg.MoveList = undefined;
        const want_n = expectedQuiescence(&r, &want);
        try std.testing.expectEqual(want_n, n);
        for (0..want_n) |i| {
            if (!sameMove(want[i], list[i])) {
                std.debug.print("  entry {d}: port {any}, expected {any}\n", .{ i, list[i], want[i] });
                return error.ListDiffers;
            }
        }
    }
    for (g.before ++ g.after) |m| try std.testing.expect(sameMove(m, fill));
    // The position is given back unchanged.
    try std.testing.expect(std.mem.eql(u8, &p.board, &p0.board));
    try std.testing.expect(std.mem.eql(u8, &p.piece_list, &p0.piece_list));
}

test "DEV-063: every move generator at the list's cap of 100: no write past it, and the original's 100 moves where its result is defined" {
    var cut: u32 = 0;
    for (cases) |c| {
        try runCase(c);
        cut += 1;
    }
    try std.testing.expectEqual(@as(u32, cases.len), cut);
}

test "DEV-063: the check-evasion generator cannot reach the cap: its most moves for a piece set" {
    // gen_evasions (38C0:E260, helpers.genEvasions) writes only moves onto the line of
    // the check or the checker's square, and king moves; the bound in docs/DEVIATIONS.md
    // DEV-063 is 68. Its list stays [100]Move, bounds-checked in the safe builds.
    // A large case: a check along the eighth rank (Rh8 against Ka8), six pawns on the
    // seventh that promote onto the line (four entries each), one that also takes the
    // rook, and two queens that can interpose or take.
    var p = try positionOf("K6r/1PPPPPP1/8/8/8/8/Q6Q/4k3 w - - 0 1");
    // The check byte of a line check: the direction code of the king's ray map at the
    // checker (DG:8C06 + ply, as make_move leaves it).
    p.check_by_ply[1] = p.king_rays[0][98];
    const v: mg.SearchVars = .{};
    var list: mg.MoveList = undefined;
    const n = @import("helpers.zig").genEvasions(&p, &v, &list, .white, 1);
    std.debug.print("gen_evasions: {d} moves\n", .{n});
    try std.testing.expect(n != mg.king_capture);
    try std.testing.expect(n >= 30 and n <= 68);
}
