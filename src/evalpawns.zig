//! The two pawn-structure evaluators.
//!
//! Specification: docs/arch/52-evaluation-pawns.md section 4, whose executable form is
//! tools/research/evalpawns/model.py (`pawn_eval`, proved against the running original
//! on 252,038 calls). Tests: src/evalpawns_test.zig, which replays calls recorded from
//! the original (tests/golden/evalpawns/).
//!
//! The two routines are hand-written assembly and are not a White/Black pair. Both
//! score both colours from White's view; they differ in a few terms that apply to the
//! pawns of one colour only (section 4.4): with White to move (0EF8:89DC) a White pawn
//! attacked by a Black pawn costs 18, a White pawn with its own pawn in front and
//! exactly one own attacker of that square stops early, and the weak-pawn mask lists
//! White pawns; with Black to move (0EF8:8F82) the same apply to Black's pawns. Both
//! are one function here, with the side to move as a compile-time parameter.

const std = @import("std");
const pos = @import("position.zig");
const dg = @import("original.zig").dgroup;
const EvalVars = @import("evalvars.zig").EvalVars;

const Position = pos.Position;
const Side = pos.Side;

// ---------------------------------------------------------------------------
// Constant tables, read from the original's initialised data
// ---------------------------------------------------------------------------

/// DG:100A: file of a square (1..8 on the board).
const file_of: [120]u8 = dg(0x100A, 120);
/// DG:0850: square class 0..4 (0 on the a- and h-files and the border; 2 on b4, g4,
/// b5, g5; 3 on c4-f4; 4 on c5-f5; 1 elsewhere).
const class_of: [120]u8 = dg(0x0850, 120);

fn words(comptime addr: usize, comptime n: usize) [n]i16 {
    const raw = dg(addr, 2 * n);
    var t: [n]i16 = undefined;
    for (&t, 0..) |*v, i| v.* = @bitCast(std.mem.readInt(u16, raw[2 * i ..][0..2], .little));
    return t;
}

/// Bonuses by square class (section 3.1): DG:0102 White "supported", DG:010C its Black
/// mirror, DG:0116 White "two pawns behind", DG:0120 its mirror, DG:012A both colours.
const supported = [2][5]i16{ words(0x0102, 5), words(0x010C, 5) };
const backed_twice = [2][5]i16{ words(0x0116, 5), words(0x0120, 5) };
const backed_once: [5]i16 = words(0x012A, 5);
/// DG:15E8 (wing files) and DG:15EE (centre files): space bonus by the number of enemy
/// pawn attacks on two squares, added as unsigned bytes.
const space_wing: [6]u8 = dg(0x15E8, 6);
const space_centre: [6]u8 = dg(0x15EE, 6);

comptime {
    // DG:0042: the mask bit of pawn slot 8 + i, read as [si+3Ah]. The port uses 1 << i.
    for (dg(0x0042, 8), 0..) |b, i| std.debug.assert(b == 1 << i);
}

// ---------------------------------------------------------------------------
// The evaluators
// ---------------------------------------------------------------------------

/// Port of pawn_eval_wtm (0EF8:89DC-8F81) when `stm` is White and of pawn_eval_btm
/// (0EF8:8F82-9527) when it is Black.
///
/// Returns the score from White's view (the original's AX). Writes the weak-pawn mask
/// DG:8EB6 (cleared, then OR-ed in the loop) and the two passed-pawn masks DG:A6C2 and
/// DG:9D8C; nothing else.
///
/// The score is the original's CX register, so every term is added with wrap-around.
pub fn pawnEval(p: *const Position, v: *EvalVars, comptime stm: Side) i16 {
    return pawnEvalWith(p, v, stm, lanes_available);
}

/// `pawnEval` with the pawns' trees evaluated one pawn at a time (`lanes` false) or all
/// sixteen at once in vector lanes (`lanes` true, which needs `lanes_available`). The
/// two give the same results; the tests run both.
pub fn pawnEvalWith(p: *const Position, v: *EvalVars, comptime stm: Side, comptime lanes: bool) i16 {
    const late = v.late_endgame != 0;
    const r = if (lanes) byLane(p, late, stm) else bySlot(p, late, stm);
    v.weak_pawns = r.weak;
    v.passed_pawns = r.passed;
    // Doubled pawns, by file slot - 7, whether or not the slot holds a pawn (89EF).
    var cx: i16 = doubledPawns(p) +% r.score;
    if (@as(i8, @bitCast(p.pawn_count)) <= 8) {
        // 8E5E: no space terms; three quarters of the score.
        return cx -% (cx >> 2);
    }
    // 8E7A: space, by the enemy pawns' attacks on the squares of ranks 5-6 (Black's) and
    // 4-3 (White's). Table bytes are unsigned.
    const wa = &p.pawn_attacks[0];
    const ba = &p.pawn_attacks[1];
    const Pair = struct { a: u8, b: u8, centre: bool };
    const black_pairs = [_]Pair{ .{ .a = 64, .b = 74, .centre = true }, .{ .a = 65, .b = 75, .centre = true }, .{ .a = 63, .b = 73, .centre = true }, .{ .a = 62, .b = 72, .centre = false }, .{ .a = 66, .b = 76, .centre = false }, .{ .a = 67, .b = 77, .centre = false } };
    const white_pairs = [_]Pair{ .{ .a = 55, .b = 45, .centre = true }, .{ .a = 56, .b = 46, .centre = false }, .{ .a = 57, .b = 47, .centre = false }, .{ .a = 52, .b = 42, .centre = false }, .{ .a = 53, .b = 43, .centre = true }, .{ .a = 54, .b = 44, .centre = true } };
    inline for (black_pairs) |q| {
        const t = if (q.centre) &space_centre else &space_wing;
        cx +%= t[@as(usize, ba[q.a]) + ba[q.b]];
    }
    inline for (white_pairs) |q| {
        const t = if (q.centre) &space_centre else &space_wing;
        cx -%= t[@as(usize, wa[q.a]) + wa[q.b]];
    }
    // 8F30: pawns still on d2, e2 (White) and d7, e7 (Black).
    if (p.board[34] == pos.white_pawn) cx -%= space_centre[wa[44]];
    if (p.board[35] == pos.white_pawn) cx -%= space_centre[wa[45]];
    if (p.board[84] == pos.black_pawn) cx +%= space_centre[ba[74]];
    if (p.board[85] == pos.black_pawn) cx +%= space_centre[ba[75]];
    return cx;
}

/// The pawns' part of the evaluation: the sum of their terms (wrapping) and the masks.
const Pawns = struct { score: i16, weak: u8, passed: [2]u8 };

/// The slot loop (89EF), one pawn at a time: the original's tree, test by test.
fn bySlot(p: *const Position, late: bool, comptime stm: Side) Pawns {
    var e: Eval(stm) = .{ .p = p, .late = late };
    var passed_white: u8 = 0;
    var passed_black: u8 = 0;
    for (8..16) |slot| {
        const m: u8 = @as(u8, 1) << @intCast(slot - 8);
        // A captured pawn's entry is its square + 63h (120..197), past the board: the
        // original reads DG:9EF6 + entry there, ordinary program data that has never been
        // seen to hold a pawn code (the recorder checks every call). Such a slot is skipped.
        const wsq = p.piece_list[slot];
        if (wsq < 120 and p.board[wsq] == pos.white_pawn) {
            if (e.whitePawn(wsq, m)) passed_white |= m;
        }
        const bsq = p.piece_list[16 + slot];
        if (bsq < 120 and p.board[bsq] == pos.black_pawn) {
            if (e.blackPawn(bsq, m)) passed_black |= m;
        }
    }
    return .{ .score = e.cx, .weak = e.weak_mask, .passed = .{ passed_white, passed_black } };
}

/// The working state of one evaluation: the score register and the inputs.
fn Eval(comptime stm: Side) type {
    return struct {
        p: *const Position,
        late: bool,
        cx: i16 = 0,
        weak_mask: u8 = 0,

        const Self = @This();
        /// The terms that only the White-to-move routine (89DC) applies to White pawns,
        /// and only the Black-to-move routine (8F82) applies to Black pawns.
        const own_white = stm == .white;
        const own_black = stm == .black;

        fn add(e: *Self, d: i16) void {
            e.cx +%= d;
        }
        fn weak(e: *Self, m: u8) void {
            e.weak_mask |= m;
        }
        fn board(e: *const Self, sq: usize) u8 {
            return e.p.board[sq];
        }
        fn wa(e: *const Self, sq: usize) i8 {
            return @bitCast(e.p.pawn_attacks[0][sq]);
        }
        fn ba(e: *const Self, sq: usize) i8 {
            return @bitCast(e.p.pawn_attacks[1][sq]);
        }
        fn wpf(e: *const Self, f: usize) i8 {
            return @bitCast(e.p.pawns_per_file[0][f]);
        }
        fn bpf(e: *const Self, f: usize) i8 {
            return @bitCast(e.p.pawns_per_file[1][f]);
        }

        /// A White pawn on `sq` (89DC: 8A28-8C6A; 8F82: 8FCE-91A6). Returns whether it
        /// is passed.
        fn whitePawn(e: *Self, sq: usize, m: u8) bool {
            if (own_white and e.ba(sq) != 0) e.add(-18); // 8A2A
            // Passed (8A34).
            const passed = if (sq <= 58)
                e.bpf(file_of[sq]) == 0 and e.ba(sq + 10) == 0 and e.ba(sq + 20) == 0 and
                    e.ba(sq + 30) == 0 and e.ba(sq + 40) == 0
            else if (sq <= 68)
                e.ba(sq + 10) == 0 and e.board(sq + 10) != pos.black_pawn and e.board(sq + 20) != pos.black_pawn
            else
                e.board(sq + 10) != pos.black_pawn;
            const f = file_of[sq];
            const c = class_of[sq];
            const d: i8 = e.wa(sq) -% e.ba(sq); // 8A89
            if (d < 0) {
                if (own_white) e.weak(m); // 8A97
                e.whiteWeakPawn(sq, f, m);
            } else if (d > 1) { // 8AE6
                e.add(18);
                if (e.wa(sq + 10) != 0) e.add(supported[0][c]);
            } else if (d == 1) { // 8AA8
                e.add(12);
                if (e.board(sq - 9) == pos.white_pawn) {
                    if (e.board(sq - 1) == pos.white_pawn) {
                        e.add(supported[0][c]);
                    } else if (e.board(sq + 11) == pos.white_pawn or e.board(sq + 9) == pos.white_pawn) {
                        e.add(18);
                    }
                } else if (e.board(sq + 1) == pos.white_pawn) {
                    e.add(supported[0][c]);
                } else if (e.board(sq + 9) == pos.white_pawn or e.board(sq + 11) == pos.white_pawn) {
                    e.add(18);
                }
            } else {
                // d = 0 (8B0C), by the White attacks on the square in front.
                const w10 = e.wa(sq + 10);
                if (w10 > 1) {
                    e.add(backed_twice[0][c]);
                } else if (w10 == 1) { // 8B22
                    e.add(backed_once[c]);
                    if (own_white and e.board(sq + 10) == pos.white_pawn) { // 8B2C
                        e.weak(m);
                        return passed;
                    }
                    const b10 = e.ba(sq + 10);
                    if (b10 == 1) {
                        if (e.bpf(f) == 0) e.add(-24);
                    } else if (b10 > 1) { // 8B68
                        if (own_white) e.weak(m);
                        if (sq < 51) e.add(-12);
                        if (e.bpf(f) == 0) e.add(-30);
                    }
                } else if (e.board(sq + 10) != pos.white_pawn) { // 8B8A
                    e.whiteWeakPawn(sq, f, m);
                } else {
                    e.add(-12);
                    const x: i8 = e.wa(sq + 20) -% e.ba(sq + 20);
                    if (x > 0 or (x == 0 and e.board(sq + 20) != pos.black_pawn)) {
                        e.whiteWeakPawn(sq, f, m);
                    } else if (own_white) {
                        e.add(-24); // 8BA9
                        e.whiteBlocked(f, m);
                    } else {
                        e.add(-36); // 9113
                        e.whiteIsolated(f, m, false);
                    }
                }
            }
            return passed;
        }

        /// 8BAF (8F82: 9118): a White pawn not defended enough.
        fn whiteWeakPawn(e: *Self, sq: usize, f: usize, m: u8) void {
            if (sq >= 51 and (sq > 58 or e.wa(sq - 10) < 1)) e.add(-12);
            if (e.board(sq + 10) == pos.black_pawn) { // 8BC3
                e.whiteBlocked(f, m);
                return;
            }
            const b10 = e.ba(sq + 10);
            if (b10 >= 1) { // 8C02
                if (own_white) e.weak(m);
                e.add(-24);
                if (sq >= 51) {
                    if (e.bpf(f) == 0) e.add(-30); // 8B7A
                    return;
                }
                if (e.bpf(f) != 0) return; // 8C17
                e.add(-36);
                if (b10 >= 2) e.add(-12);
                return;
            }
            if (sq >= 41) { // 8BD1
                e.whiteIsolated(f, m, own_white);
                return;
            }
            // A pawn on its second rank.
            if (own_white and e.late) e.weak(m); // 8BD6
            if (e.wa(sq + 20) >= e.ba(sq + 20)) { // 8BE7
                e.whiteIsolated(f, m, own_white);
                return;
            }
            e.add(-18);
            if (e.bpf(f) == 0) {
                e.add(-30); // 8B84
                return;
            }
            if (e.wpf(f - 1) != 0 or e.wpf(f + 1) != 0) return; // 8B4C
            e.add(-42);
            if (own_white) e.weak(m);
        }

        /// 8C30 (8F82: 9180): blocked by a pawn.
        fn whiteBlocked(e: *Self, f: usize, m: u8) void {
            e.add(-12);
            if (own_white) e.weak(m);
            e.whiteIsolated(f, m, own_white);
        }

        /// 8C3D (8F82: 9183): isolated.
        fn whiteIsolated(e: *Self, f: usize, m: u8, mark: bool) void {
            if (e.wpf(f - 1) != 0 or e.wpf(f + 1) != 0) return;
            e.add(-42);
            if (mark) e.weak(m);
            if (e.bpf(f) != 0) return;
            e.add(-36);
            if (e.wpf(f) > 1) e.add(12);
        }

        /// A Black pawn on `sq` (89DC: 8C7A-8E52; 8F82: 91B6-93F8): the mirror of
        /// `whitePawn` with the variant terms on the other routine. Returns whether it
        /// is passed.
        fn blackPawn(e: *Self, sq: usize, m: u8) bool {
            if (own_black and e.wa(sq) != 0) e.add(18); // 91B8
            const passed = if (sq >= 61)
                e.wpf(file_of[sq]) == 0 and e.wa(sq - 10) == 0 and e.wa(sq - 20) == 0 and
                    e.wa(sq - 30) == 0 and e.wa(sq - 40) == 0
            else if (sq >= 51)
                e.wa(sq - 10) == 0 and e.board(sq - 10) != pos.white_pawn and e.board(sq - 20) != pos.white_pawn
            else
                e.board(sq - 10) != pos.white_pawn;
            const f = file_of[sq];
            const c = class_of[sq];
            const d: i8 = e.ba(sq) -% e.wa(sq); // 8CD1
            if (d < 0) {
                if (own_black) e.weak(m); // 9225
                e.blackWeakPawn(sq, f, m);
            } else if (d > 1) { // 8D24
                e.add(-18);
                if (e.ba(sq - 10) != 0) e.add(-supported[1][c]);
            } else if (d == 1) { // 8CE6
                e.add(-12);
                if (e.board(sq + 11) == pos.black_pawn) {
                    if (e.board(sq - 1) == pos.black_pawn) {
                        e.add(-supported[1][c]);
                    } else if (e.board(sq - 9) == pos.black_pawn or e.board(sq - 11) == pos.black_pawn) {
                        e.add(-18);
                    }
                } else if (e.board(sq + 1) == pos.black_pawn) {
                    e.add(-supported[1][c]);
                } else if (e.board(sq - 11) == pos.black_pawn or e.board(sq - 9) == pos.black_pawn) {
                    e.add(-18);
                }
            } else {
                // d = 0 (8D3C)
                const b10 = e.ba(sq - 10);
                if (b10 > 1) {
                    e.add(-backed_twice[1][c]);
                } else if (b10 == 1) { // 8D52
                    e.add(-backed_once[c]);
                    if (own_black and e.board(sq - 10) == pos.black_pawn) { // 92BA
                        e.weak(m);
                        return passed;
                    }
                    const w10 = e.wa(sq - 10);
                    if (w10 == 1) {
                        if (e.wpf(f) == 0) e.add(24);
                    } else if (w10 > 1) { // 92F6
                        if (own_black) e.weak(m);
                        if (sq > 68) e.add(12); // 8D76
                        if (e.wpf(f) == 0) e.add(30);
                    }
                } else if (e.board(sq - 10) != pos.black_pawn) { // 8DA0
                    e.blackWeakPawn(sq, f, m);
                } else {
                    e.add(12);
                    const x: i8 = e.ba(sq - 20) -% e.wa(sq - 20);
                    if (x > 0 or (x == 0 and e.board(sq - 20) != pos.white_pawn)) {
                        e.blackWeakPawn(sq, f, m);
                    } else if (own_white) {
                        e.add(36); // 8DBF
                        e.blackIsolated(f, m, false);
                    } else {
                        e.add(24); // 9337
                        e.blackBlocked(f, m);
                    }
                }
            }
            return passed;
        }

        /// 8DC4 (8F82: 933D)
        fn blackWeakPawn(e: *Self, sq: usize, f: usize, m: u8) void {
            if (sq <= 68 and (sq < 61 or e.ba(sq + 10) < 1)) e.add(12);
            if (e.board(sq - 10) == pos.white_pawn) { // 8DD8
                e.blackBlocked(f, m);
                return;
            }
            const w10 = e.wa(sq - 10);
            if (w10 >= 1) { // 8E08
                if (own_black) e.weak(m);
                e.add(24);
                if (sq <= 68) {
                    if (e.wpf(f) == 0) e.add(30); // 8D7E
                    return;
                }
                if (e.wpf(f) != 0) return; // 8E13
                e.add(36);
                if (w10 >= 2) e.add(12);
                return;
            }
            if (sq <= 78) { // 8DE6
                e.blackIsolated(f, m, own_black);
                return;
            }
            if (own_black and e.late) e.weak(m); // 9364
            if (e.ba(sq - 20) >= e.wa(sq - 20)) { // 8DEB
                e.blackIsolated(f, m, own_black);
                return;
            }
            e.add(18);
            if (e.wpf(f) == 0) {
                e.add(30); // 8E02
                return;
            }
            if (e.bpf(f - 1) != 0 or e.bpf(f + 1) != 0) return; // 8D8E
            e.add(42);
            if (own_black) e.weak(m);
        }

        /// 8E2C (8F82: 93BE)
        fn blackBlocked(e: *Self, f: usize, m: u8) void {
            e.add(12);
            if (own_black) e.weak(m);
            e.blackIsolated(f, m, own_black);
        }

        /// 8E2F (8F82: 93CB)
        fn blackIsolated(e: *Self, f: usize, m: u8, mark: bool) void {
            if (e.bpf(f - 1) != 0 or e.bpf(f + 1) != 0) return;
            e.add(42);
            if (mark) e.weak(m);
            if (e.wpf(f) != 0) return;
            e.add(36);
            if (e.bpf(f) > 1) e.add(-12);
        }
    };
}

/// 89EF: the doubled-pawn terms of the slot loop, which go by file index slot - 7 (1..8)
/// whether or not the slot holds a pawn: -42 for more than one White pawn on the file
/// and -100 more for more than two (signed byte compares); Black's mirrored.
fn doubledPawns(p: *const Position) i16 {
    const F = @Vector(8, i8);
    const W = @Vector(8, i16);
    const w: F = @bitCast(p.pawns_per_file[0][1..9].*);
    const b: F = @bitCast(p.pawns_per_file[1][1..9].*);
    const one: F = @splat(1);
    const two: F = @splat(2);
    const t: W = @as(W, @intFromBool(b > one)) * @as(W, @splat(42)) +
        @as(W, @intFromBool(b > two)) * @as(W, @splat(100)) -
        @as(W, @intFromBool(w > one)) * @as(W, @splat(42)) -
        @as(W, @intFromBool(w > two)) * @as(W, @splat(100));
    return @reduce(.Add, t);
}

// ---------------------------------------------------------------------------
// All sixteen pawns at once
// ---------------------------------------------------------------------------
//
// The same trees, one vector lane per slot: lanes 0..7 White's slots 8..15, lanes 8..15
// Black's. Each test of the tree is a lane compare, every branch is taken in every lane
// and each leaf's terms are added in the lanes that reach it. A Black pawn's tree is the
// White one with the roles of the colours swapped (its own attack and per-file tables,
// the enemy's, -10 for +10, the rank tests on the square seen from Black, 119 - sq, and
// the support neighbours sq+11, sq+1, sq-11/sq-9) and its terms negated; the variant
// terms of the two routines are on the lanes of the side to move. A lane reads the
// tables with a byte permute (AVX-512 VBMI), so the lanes need no branch. Every term is
// even and a pawn's terms lie between -144 and +144: the lanes hold half the terms in a
// signed byte. A lane reads `sq + d` modulo 128; it differs from the slot loop only where
// that loop would read outside the 120 squares (no position has a pawn there).

const builtin = @import("builtin");

/// Whether the target has the byte permutes (AVX-512 VBMI) `byLane` reads the tables
/// with. Without them `pawnEval` evaluates one pawn at a time.
pub const lanes_available = builtin.cpu.arch == .x86_64 and
    std.Target.x86.featureSetHas(builtin.cpu.features, .avx512vbmi) and
    std.Target.x86.featureSetHas(builtin.cpu.features, .avx512bw);

const Z = @Vector(64, u8);
const L = @Vector(16, u8);
const S = @Vector(16, i8);
const M = @Vector(16, bool);

/// A 128-byte table in two registers, for `gather`.
const Table = struct { lo: Z, hi: Z };

const widen: [64]i32 = blk: {
    var m: [64]i32 = undefined;
    for (0..64) |i| m[i] = if (i < 16) i else 0;
    break :blk m;
};
const first16: [16]i32 = .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
const down8: [64]i32 = blk: {
    var m: [64]i32 = undefined;
    for (0..64) |i| m[i] = if (i < 56) i + 8 else -1;
    break :blk m;
};

/// A 120-byte table, bytes 120..127 zero: the first 64 bytes, and bytes 56..119 moved
/// down 8.
inline fn table(t: *const [120]u8) Table {
    const x: Z = t[56..120].*;
    return .{ .lo = t[0..64].*, .hi = @shuffle(u8, x, @as(Z, @splat(0)), down8) };
}

fn constTable(comptime t: [120]u8) Table {
    var b: [128]u8 = @splat(0);
    b[0..120].* = t;
    return .{ .lo = b[0..64].*, .hi = b[64..128].* };
}

/// Byte `idx mod 128` of the table, in each lane (VPERMI2B).
inline fn gather(t: Table, idx: L) L {
    const r: Z = asm ("vpermi2b %[hi], %[lo], %[ret]"
        : [ret] "=v" (-> Z),
        : [lo] "v" (t.lo),
          [hi] "v" (t.hi),
          [idx] "0" (@shuffle(u8, idx, undefined, widen)),
    );
    return @shuffle(u8, r, undefined, first16);
}

/// Byte `idx mod 64` of a 64-byte table, in each lane (VPERMB).
inline fn gather64(t: Z, idx: L) L {
    const r: Z = asm ("vpermb %[t], %[idx], %[ret]"
        : [ret] "=v" (-> Z),
        : [t] "v" (t),
          [idx] "v" (@shuffle(u8, idx, undefined, widen)),
    );
    return @shuffle(u8, r, undefined, first16);
}

const file_table = constTable(file_of);
const class_table = constTable(class_of);

/// Half the class tables' values (DG:0850 classes), at 0 + class for White's lanes and
/// 8 + class for Black's: supported (DG:0102, 010C) at 0, two pawns behind (DG:0116,
/// 0120) at 16, one pawn behind (DG:012A) at 32.
const class_values: Z = blk: {
    var t: [64]u8 = @splat(0);
    for (0..5) |c| {
        t[c] = @intCast(@divExact(supported[0][c], 2));
        t[8 + c] = @intCast(@divExact(supported[1][c], 2));
        t[16 + c] = @intCast(@divExact(backed_twice[0][c], 2));
        t[24 + c] = @intCast(@divExact(backed_twice[1][c], 2));
        t[32 + c] = @intCast(@divExact(backed_once[c], 2));
        t[40 + c] = @intCast(@divExact(backed_once[c], 2));
    }
    break :blk t;
};

/// A lane constant: `w` in White's lanes, `b` in Black's.
fn perSide(comptime T: type, comptime w: T, comptime b: T) @Vector(16, T) {
    var v: [16]T = undefined;
    for (0..16) |i| v[i] = if (i < 8) w else b;
    return v;
}

/// The square `d` ahead of the pawn (a negative `d` behind it), as a lane offset.
fn ahead(comptime d: i8) L {
    return perSide(u8, @bitCast(d), @bitCast(-d));
}

/// The square `w` from a White pawn and `b` from a Black one.
fn offset(comptime w: i8, comptime b: i8) L {
    return perSide(u8, @bitCast(w), @bitCast(b));
}

inline fn sbytes(x: L) S {
    return @bitCast(x);
}

inline fn when(c: M, k: i8) S {
    return @select(i8, c, @as(S, @splat(k)), @as(S, @splat(0)));
}

inline fn whenV(c: M, k: L) S {
    return @select(i8, c, sbytes(k), @as(S, @splat(0)));
}

/// The own and the enemy pawns' attacks `d` ahead of each lane's pawn.
const Attacks = struct {
    own: S,
    enemy: S,

    inline fn at(w: Table, b: Table, sq: L, comptime d: i8) Attacks {
        const i = sq +% comptime ahead(d);
        const x = sbytes(gather(w, i));
        const y = sbytes(gather(b, i));
        const black_lane: M = comptime perSide(bool, false, true);
        return .{ .own = @select(i8, black_lane, y, x), .enemy = @select(i8, black_lane, x, y) };
    }
};

/// Every pawn of both sides at once; see the section comment.
fn byLane(p: *const Position, late: bool, comptime stm: Side) Pawns {
    const black_lane: M = comptime perSide(bool, false, true);
    const own: M = comptime perSide(bool, stm == .white, stm == .black);
    const own_code: L = comptime perSide(u8, pos.white_pawn, pos.black_pawn);
    const enemy_code: L = comptime perSide(u8, pos.black_pawn, pos.white_pawn);
    const zero: S = @splat(0);
    const one: S = @splat(1);

    const list: @Vector(32, u8) = p.piece_list;
    const sq: L = @shuffle(u8, list, undefined, @Vector(16, i32){ 8, 9, 10, 11, 12, 13, 14, 15, 24, 25, 26, 27, 28, 29, 30, 31 });
    const board = table(&p.board);
    const wa = table(&p.pawn_attacks[0]);
    const ba = table(&p.pawn_attacks[1]);
    const present = (sq < @as(L, @splat(120))) & (gather(board, sq) == own_code);

    // The square seen from the pawn's side, for the rank tests.
    const msq = @select(u8, black_lane, @as(L, @splat(119)) -% sq, sq);
    const below41 = msq < @as(L, @splat(41));
    const below51 = msq < @as(L, @splat(51));
    const upto58 = msq <= @as(L, @splat(58));
    const from59to68 = (msq >= @as(L, @splat(59))) & (msq <= @as(L, @splat(68)));
    const from69 = msq >= @as(L, @splat(69));

    const a0 = Attacks.at(wa, ba, sq, 0);
    const a10 = Attacks.at(wa, ba, sq, 10);
    const a20 = Attacks.at(wa, ba, sq, 20);
    const behind10 = Attacks.at(wa, ba, sq, -10);
    const a30 = Attacks.at(wa, ba, sq, 30);
    const a40 = Attacks.at(wa, ba, sq, 40);
    const b10 = gather(board, sq +% comptime ahead(10));
    const b20 = gather(board, sq +% comptime ahead(20));

    // Per file: pawns per file at 0 (White) and 16 (Black).
    var files: [64]u8 = @splat(0);
    files[0..10].* = p.pawns_per_file[0];
    files[16..26].* = p.pawns_per_file[1];
    const pf: Z = files;
    const f = gather(file_table, sq);
    const own_f = f +% comptime perSide(u8, 0, 16);
    const enemy_f = f +% comptime perSide(u8, 16, 0);
    const no_enemy_on_file = gather64(pf, enemy_f) == @as(L, @splat(0));
    const lonely = (gather64(pf, own_f -% @as(L, @splat(1))) | gather64(pf, own_f +% @as(L, @splat(1)))) == @as(L, @splat(0));
    const doubled = sbytes(gather64(pf, own_f)) > one;
    const c = gather(class_table, sq) +% comptime perSide(u8, 0, 8);
    const supported_half = gather64(class_values, c);
    const backed_twice_half = gather64(class_values, c +% @as(L, @splat(16)));
    const backed_once_half = gather64(class_values, c +% @as(L, @splat(32)));

    var h: S = zero;
    h +%= when(own & (a0.enemy != zero), -9); // 8A2A
    const d = a0.own -% a0.enemy; // 8A89
    const d0 = d == zero;
    const d1 = d == one;
    const d2 = d > one;
    // d > 1 (8AE6)
    h +%= when(d2, 9) +% whenV(d2 & (a10.own != zero), supported_half);
    // d = 1 (8AA8): supported beside, or by a pawn diagonally behind.
    const behind = gather(board, sq +% comptime offset(-9, 11)) == own_code;
    const left = gather(board, sq +% comptime offset(-1, -1)) == own_code;
    const right = gather(board, sq +% comptime offset(1, 1)) == own_code;
    const beside = (behind & left) | (!behind & right);
    const diagonal = (gather(board, sq +% comptime offset(9, -9)) == own_code) | (gather(board, sq +% comptime offset(11, -11)) == own_code);
    h +%= when(d1, 6) +% whenV(d1 & beside, supported_half) +% when(d1 & !beside & diagonal, 9);
    // d = 0 (8B0C), by the own attacks ahead: > 1; = 1 (8B22); < 1 (8B8A).
    h +%= whenV(d0 & (a10.own > one), backed_twice_half);
    const once = d0 & (a10.own == one);
    h +%= whenV(once, backed_once_half);
    const own_in_front = b10 == own_code;
    const once_on = once & !(own & own_in_front); // 8B2C: own stops
    h +%= when(once_on & (a10.enemy == one) & no_enemy_on_file, -12);
    const once_attacked = once_on & (a10.enemy > one); // 8B68
    h +%= when(once_attacked & below51, -6) +% when(once_attacked & no_enemy_on_file, -15);
    const none = d0 & (a10.own < one);
    const none_own_front = none & own_in_front;
    h +%= when(none_own_front, -6);
    const e = a20.own -% a20.enemy;
    const ahead_held = (e > zero) | ((e == zero) & (b20 != enemy_code));
    const stuck = none_own_front & !ahead_held; // 8BA9 / 9113: -36 more, and isolated
    h +%= when(stuck, -18);

    // The weak pawn (8BAF).
    const weak_pawn = (d < zero) | (none & !own_in_front) | (none_own_front & ahead_held);
    h +%= when(weak_pawn & !below51 & (!upto58 | (behind10.own < one)), -6);
    const enemy_in_front = b10 == enemy_code;
    const blocked = weak_pawn & enemy_in_front; // 8C30
    h +%= when(blocked, -6);
    const open = weak_pawn & !enemy_in_front;
    const hit = open & (a10.enemy >= one); // 8C02
    h +%= when(hit, -12) +% when(hit & !below51 & no_enemy_on_file, -15);
    const hit_low = hit & below51 & no_enemy_on_file; // 8C17
    h +%= when(hit_low, -18) +% when(hit_low & (a10.enemy > one), -6);
    const free = open & (a10.enemy < one);
    const second_rank = free & below41; // 8BD6
    const ge = a20.own >= a20.enemy; // 8BE7
    const covered = second_rank & ge;
    const exposed = second_rank & !ge;
    h +%= when(exposed, -9) +% when(exposed & no_enemy_on_file, -15);

    // Isolated (8C3D): reached from blocked, the weak pawn above its second rank, a
    // covered or exposed second-rank pawn (the latter only with an enemy pawn on its
    // file), and the stuck pawn.
    const isolated = (blocked | (free & !below41) | covered | (exposed & !no_enemy_on_file) | stuck) & lonely;
    const iso_open = isolated & no_enemy_on_file;
    h +%= when(isolated, -21) +% when(iso_open, -18) +% when(iso_open & doubled, 6);

    const late_mark: M = @splat(late);
    const weak = own & ((d < zero) | (once & (own_in_front | (a10.enemy > one))) | stuck | blocked | hit | isolated | (second_rank & late_mark));
    // Passed (8A34).
    const passed = (upto58 & no_enemy_on_file & ((a10.enemy | a20.enemy | a30.enemy | a40.enemy) == zero)) |
        (from59to68 & (a10.enemy == zero) & !enemy_in_front & (b20 != enemy_code)) |
        (from69 & !enemy_in_front);

    const half = @select(i8, black_lane, zero -% h, h);
    const sum: i16 = @reduce(.Add, @as(@Vector(16, i16), @select(i8, present, half, zero)));
    const weak_bits: u16 = @bitCast(weak & present);
    const passed_bits: u16 = @bitCast(passed & present);
    return .{
        .score = 2 * sum,
        .weak = if (stm == .white) @truncate(weak_bits) else @truncate(weak_bits >> 8),
        .passed = .{ @truncate(passed_bits), @truncate(passed_bits >> 8) },
    };
}
