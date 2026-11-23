//! Test-only reference: the pawn evaluators as they were before the speed pass of
//! 2026-11-18 (a direct transcription of the original's decision tree). The
//! differential test in src/evalpawns_test.zig compares src/evalpawns.zig with it.
//!
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
    var e: Eval(stm) = .{ .p = p, .v = v };
    v.weak_pawns = 0;
    var passed_white: u8 = 0;
    var passed_black: u8 = 0;
    for (8..16) |slot| {
        const m: u8 = @as(u8, 1) << @intCast(slot - 8);
        // Doubled pawns, by file slot - 7, whether or not the slot holds a pawn (89EF).
        const f0 = slot - 7;
        const wpf = e.wpf(f0);
        if (wpf > 1) e.add(-42);
        if (wpf > 2) e.add(-100);
        const bpf = e.bpf(f0);
        if (bpf > 1) e.add(42);
        if (bpf > 2) e.add(100);
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
    v.passed_pawns = .{ passed_white, passed_black };
    if (@as(i8, @bitCast(p.pawn_count)) <= 8) {
        // 8E5E: no space terms; three quarters of the score.
        return e.cx -% (e.cx >> 2);
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
        e.add(t[@as(usize, ba[q.a]) + ba[q.b]]);
    }
    inline for (white_pairs) |q| {
        const t = if (q.centre) &space_centre else &space_wing;
        e.add(-@as(i16, t[@as(usize, wa[q.a]) + wa[q.b]]));
    }
    // 8F30: pawns still on d2, e2 (White) and d7, e7 (Black).
    if (p.board[34] == pos.white_pawn) e.add(-@as(i16, space_centre[wa[44]]));
    if (p.board[35] == pos.white_pawn) e.add(-@as(i16, space_centre[wa[45]]));
    if (p.board[84] == pos.black_pawn) e.add(space_centre[ba[74]]);
    if (p.board[85] == pos.black_pawn) e.add(space_centre[ba[75]]);
    return e.cx;
}

/// The working state of one evaluation: the score register and the inputs.
fn Eval(comptime stm: Side) type {
    return struct {
        p: *const Position,
        v: *EvalVars,
        cx: i16 = 0,

        const Self = @This();
        /// The terms that only the White-to-move routine (89DC) applies to White pawns,
        /// and only the Black-to-move routine (8F82) applies to Black pawns.
        const own_white = stm == .white;
        const own_black = stm == .black;

        fn add(e: *Self, d: i16) void {
            e.cx +%= d;
        }
        fn weak(e: *Self, m: u8) void {
            e.v.weak_pawns |= m;
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
            if (own_white and e.v.late_endgame != 0) e.weak(m); // 8BD6
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
            if (own_black and e.v.late_endgame != 0) e.weak(m); // 9364
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
