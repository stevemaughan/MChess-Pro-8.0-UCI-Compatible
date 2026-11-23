//! The pin-aware exchange evaluators: exchange_pinaware_white (4793:41B6) and
//! exchange_pinaware_black (4793:4CEC), with their near pin helpers (4162 / 418C and
//! 4C98 / 4CC2).
//!
//! Specification: docs/arch/22-search-helpers.md §1 (and §7, "Not mirrors"); the threat
//! evaluators' view of them is docs/arch/54-evaluation-threats.md 7.4. Proved model:
//! tools/research/helpers/model.py `exchange_pinaware`. Tests: src/pinexchange_test.zig,
//! which replays every call recorded from the original (tests/golden/evalthreats/, tags
//! 1 and 2) and compares this port with the machine-lifted routines of
//! src/attackers.zig on generated calls.
//!
//! Each is the movegen exchange evaluator (src/see.zig, 2B9F:C32A / CAC2) with four
//! changes: pawns are taken one by one from the board, each tested for a pin, instead of
//! from the attack count; the side that captures first is pin-tested too; a pin sets that
//! side's pinned flag; and each side's flag takes the other side's king out of the
//! exchange.
//!
//! The two are colour mirrors except in two places (DEV-023): an own bishop behind an
//! own queen on a diagonal is pin-tested by 4CEC (50A2) and not by 41B6 (4574); an own
//! bishop in the "mixed" diagonal state is pin-tested by 41B6 (4718) and not by 4CEC
//! (525E). One body serves both, with the colour as a compile-time parameter and those
//! two places as named constants (`Codes`). `exchange` reproduces the original;
//! `exchangeFixes` with `Fixes.dev023_pinned_bishop` corrects it (owner decision 27):
//! the bishop is pin-tested in all four places, as every other piece counted in either
//! routine is.
//!
//! The work areas are the same DGROUP bytes as the movegen exchange evaluator's
//! (DG:9FEC, DG:A060, DG:70E5, DG:B4E6), so the routine takes `see.Scratch`: one store
//! for both, as in the original. The frame locals (the queen counters, the two pinned
//! flags, the pawn flag and the line counter) are all written before they are read
//! (41F9, 41FC, 447E-448A, 47FB), so no stack byte is an input. One work-area byte is:
//! a swap-off that runs all ten rounds reads h[10] (DG:B4F0), which no call writes, as
//! the movegen exchange evaluator does; it is `Scratch.net[10]`, so the caller's scratch
//! carries it.
//!
//! Everything is a signed or unsigned byte as in the original; counters and list entries
//! wrap at 8 bits.

const std = @import("std");
const pos = @import("position.zig");
const see = @import("see.zig");
const Position = pos.Position;
const Side = pos.Side;
const dg = @import("original.zig").dgroup;

/// The work areas: DG:9FEC (the list of the side that captures first), DG:A060 (the
/// other side's list), DG:70E5 (g[i]) and DG:B4E6 (h[i]). The same bytes as
/// `see.Scratch`, and the same type, so that when the units are joined the two
/// evaluators share them as the original does.
pub const Scratch = see.Scratch;

// ---------------------------------------------------------------------------
// Tables, from the original's initialised data
// ---------------------------------------------------------------------------

/// DG:1A71 + code, the code read as a signed byte (`cbw`): exchange value, empty 1, P 3,
/// N 9, B 9, R 15, Q 27, K 0. Indexed by `code +% 128`, so any byte reads what the
/// original reads.
const see_value = dg(0x1A71 - 128, 256);

/// DG:0490 + code and DG:047E + code, the code read as a signed byte (`cbw`): king ray
/// direction code to step and to slider bit. Codes 1..16 are the ray codes; any other
/// byte reads what the original reads. Indexed by `code +% 128`.
const dir_step_any: [256]i8 = @bitCast(dg(0x0490 - 128, 256));
const dir_bit_any = dg(0x047E - 128, 256);

/// DG:0470 + code, the code unsigned (`sub bh, bh`): the slider bits of a piece code.
const slider_bits = dg(0x0470, 256);

/// DG:0A68 + d, read for d = sq - (a knight's list entry), any entry 0..255: the
/// knight-step table and the bytes around it. Index d + 255, d = -255..119. A captured
/// knight's entry (its square + 63h, so 78h..C5h) never reaches a square 21..98: checked
/// below at compile time.
const knight_reach = dg(0x0A68 - 255, 375);

/// DG:0CFF + d: non-zero when d is a king step. Same range as `knight_reach`.
const king_reach = dg(0x0CFF - 255, 375);

comptime {
    @setEvalBranchQuota(100_000);
    for (21..99) |sq| for (0x78..0xC6) |e| {
        if (knight_reach[sq + 255 - e] != 0) @compileError("a captured knight's entry reaches a board square");
    };
}

inline fn reach(table: *const [375]u8, sq: usize, entry: u8) bool {
    return table[sq + 255 - entry] != 0;
}

inline fn s8(x: u8) i8 {
    return @bitCast(x);
}

inline fn add(sq: usize, d: i32) usize {
    return @intCast(@as(i32, @intCast(sq)) + d);
}

inline fn dirStep(code: u8) i8 {
    return dir_step_any[code +% 128];
}

inline fn dirBit(code: u8) u8 {
    return dir_bit_any[code +% 128];
}

/// The colour-dependent codes and tables of one routine. "Own" is the side that
/// captures first (White in 41B6), "opp" the other.
fn Codes(comptime us: Side, comptime fixes: pos.Fixes) type {
    const white = us == .white;
    const dev023 = fixes.dev023_pinned_bishop;
    return struct {
        const o_pawn: u8 = if (white) pos.white_pawn else pos.black_pawn;
        const o_bishop: u8 = if (white) pos.white_bishop else pos.black_bishop;
        const o_rook: u8 = if (white) pos.white_rook else pos.black_rook;
        const o_queen: u8 = if (white) pos.white_queen else pos.black_queen;
        const p_pawn: u8 = if (white) pos.black_pawn else pos.white_pawn;
        const p_bishop: u8 = if (white) pos.black_bishop else pos.white_bishop;
        const p_rook: u8 = if (white) pos.black_rook else pos.white_rook;
        const p_queen: u8 = if (white) pos.black_queen else pos.white_queen;
        const u: usize = @backingInt(us);
        const t: usize = 1 - u;
        /// The own pawns stand on sq-9, sq-11 (41B6 4218, 4264) or sq+9, sq+11 (4CEC);
        /// the opponent's on the other two (41B6 4356, 43A2).
        const own_pawn_from: [2]i8 = if (white) .{ -9, -11 } else .{ 9, 11 };
        const opp_pawn_from: [2]i8 = if (white) .{ 9, 11 } else .{ -9, -11 };
        /// Diagonals in scan order: the first two pass an opponent pawn next to sq, the
        /// last two the own pawn.
        const diag_first: [2]i8 = if (white) .{ 9, 11 } else .{ -9, -11 };
        const diag_last: [2]i8 = if (white) .{ -9, -11 } else .{ 9, 11 };
        /// DEV-023, first place: an own bishop behind an own queen on a diagonal is
        /// pin-tested by 4CEC (50A2, helper 4CC2) and counted untested by 41B6 (4574).
        /// Corrected, 41B6 tests it too, as 4CEC does: a pin sets the own pinned flag
        /// and ends the direction.
        const pin_test_bishop_behind_queen = !white or dev023;
        /// DEV-023, second place: an own bishop in the mixed diagonal state (own queen
        /// after an opponent queen) is pin-tested by 41B6 (4718, helper 4162) and counted
        /// untested by 4CEC (525E). Corrected, 4CEC tests it too, as 41B6 does.
        const pin_test_bishop_in_mixed = white or dev023;
    };
}

/// One call: the position read, the work areas written, and the frame locals.
fn Run(comptime us: Side, comptime fixes: pos.Fixes) type {
    const C = Codes(us, fixes);
    return struct {
        const Self = @This();

        p: *const Position,
        s: *Scratch,
        sq: usize,
        /// DX: the next entry of the own list (DG:9FEC + own).
        own: usize = 1,
        /// CX: the next entry of the opponent list (DG:A060 + opp).
        opp: usize = 0,
        /// 41B6 [bp-2], [bp-4] (4CEC the same): own queens on diagonals / lines (+10h
        /// each) and own bishops / rooks behind them (+1 each).
        own_qd: u8 = 0,
        own_qo: u8 = 0,
        /// [bp-0Ah], [bp-12h]: the same for the opponent.
        opp_qd: u8 = 0,
        opp_qo: u8 = 0,
        /// An own piece was found pinned: [bp-0Ch] in 41B6, [bp-6] in 4CEC (so [bp-0Ch]
        /// is always White's flag and [bp-6] Black's). Bars the opponent's king.
        own_pinned: bool = false,
        /// An opponent piece was found pinned: [bp-6] in 41B6, [bp-0Ch] in 4CEC. Bars
        /// the own king.
        opp_pinned: bool = false,
        /// [bp-0Eh]: the own pawn stands next to sq on this diagonal; an opponent bishop
        /// or queen then ends the direction.
        flag: bool = false,

        fn pushOwn(r: *Self, v: u8) void {
            r.s.attackers[r.own] = v;
            r.own += 1;
        }

        fn pushOpp(r: *Self, v: u8) void {
            r.s.defenders[r.opp] = v;
            r.opp += 1;
        }

        inline fn board(r: *const Self, sq: usize) u8 {
            return r.p.board[sq];
        }

        /// The first square after `sq` along step `d` that is not empty.
        inline fn nextPiece(r: *const Self, sq: usize, comptime d: i8) usize {
            var s = add(sq, d);
            while (r.board(s) == pos.empty) s = add(s, d);
            return s;
        }

        /// The pin helper's walk (4162 / 418C, 4C98 / 4CC2): from `sq` along the step
        /// of ray code `code` to the first piece. The ray codes 1..16 walk with a
        /// compile-time step; any other byte with the step the original reads for it.
        fn nextPieceByCode(r: *const Self, sq: usize, code: u8) usize {
            return switch (code) {
                inline 1...16 => |c| r.nextPiece(sq, comptime dirStep(c)),
                else => blk: {
                    const d = dirStep(code);
                    var s = add(sq, d);
                    while (r.board(s) == pos.empty) s = add(s, d);
                    break :blk s;
                },
            };
        }

        /// The piece on `s`, whose king ray code is `code` (non-zero), has a slider of
        /// that ray's kind behind it: the helper's `test` (4185, 41AF).
        inline fn pinnerBehind(r: *const Self, s: usize, code: u8) bool {
            const q = r.nextPieceByCode(s, code);
            return dirBit(code) & slider_bits[r.board(q)] != 0;
        }

        /// The pin test made before a scanned piece is counted (e.g. 41B6 44C6..44DA):
        /// pinned when the piece is on its king's ray map, the helper finds a slider of
        /// the ray's kind beyond it, and the ray's step is not ±d.
        inline fn pinned(r: *const Self, map: *const [120]u8, s: usize, comptime d: i8) bool {
            const code = map[s];
            if (code == 0) return false;
            if (!r.pinnerBehind(s, code)) return false;
            const step = dirStep(code);
            return !(step == d or -@as(i32, step) == d);
        }

        /// An own piece on `s` may take part; if pinned, the own flag is set and the
        /// caller ends the direction.
        inline fn ownOk(r: *Self, s: usize, comptime d: i8) bool {
            if (r.pinned(&r.p.king_rays[C.u], s, d)) {
                r.own_pinned = true;
                return false;
            }
            return true;
        }

        /// The same for an opponent piece, on the opponent king's map.
        inline fn oppOk(r: *Self, s: usize, comptime d: i8) bool {
            if (r.pinned(&r.p.king_rays[C.t], s, d)) {
                r.opp_pinned = true;
                return false;
            }
            return true;
        }

        /// Pawns next to sq (41B6 41FF..429F own, 433E..43DD opponent; 4CEC the
        /// mirror): only if the side's pawn-attack count at sq is non-zero. A pawn on its
        /// king's ray, the ray not the line of the capture (step ≠ -off), with a slider
        /// beyond it, is pinned: the side's flag is set and the pawn skipped.
        inline fn pawns(r: *Self, comptime own_side: bool) void {
            const side = if (own_side) C.u else C.t;
            if (r.p.pawn_attacks[side][r.sq] == 0) return;
            const map = &r.p.king_rays[side];
            const code_here = if (own_side) C.o_pawn else C.p_pawn;
            const froms = if (own_side) C.own_pawn_from else C.opp_pawn_from;
            inline for (froms) |off| blk: {
                const ps = add(r.sq, off);
                if (r.board(ps) != code_here) break :blk;
                const code = map[ps];
                if (code != 0 and dirStep(code) != -off and r.pinnerBehind(ps, code)) {
                    if (own_side) r.own_pinned = true else r.opp_pinned = true;
                    break :blk;
                }
                if (own_side) r.pushOwn(3) else r.pushOpp(3);
            }
        }

        /// Knights in slots 0 and 1 (41B6 42A2..433B own, 43E0..4479 opponent): a knight
        /// on its king's ray with a slider beyond it is pinned, whatever the ray (no test
        /// of the line of the capture).
        inline fn knights(r: *Self, comptime own_side: bool) void {
            const side = if (own_side) C.u else C.t;
            const map = &r.p.king_rays[side];
            inline for (0..2) |slot| blk: {
                const kn = r.p.piece_list[16 * side + slot];
                // DEV-058: a knight lifted with entry 0 reaches a1 in the original.
                if (fixes.dev058_lifted_knight_entry and kn == 0) break :blk;
                if (!reach(&knight_reach, r.sq, kn)) break :blk;
                // A reaching entry is a board square (a captured knight never reaches,
                // checked at compile time). An entry set to 0..20 or C6h..FFh by a
                // caller would index the map beyond its end here, a trap in safe builds;
                // no caller of these routines does that.
                const code = map[kn];
                if (code != 0 and r.pinnerBehind(kn, code)) {
                    if (own_side) r.own_pinned = true else r.opp_pinned = true;
                    break :blk;
                }
                if (own_side) r.pushOwn(9) else r.pushOpp(9);
            }
        }

        /// One diagonal (41B6 44A4..47BE; 4CEC 4FDA..52E4), from si.
        fn diag(r: *Self, start: usize, comptime d: i8) void {
            var si = start;
            while (r.board(si) == pos.empty) si = add(si, d);
            var state: enum { main, aq, dq, mixed } = .main;
            while (true) switch (state) {
                .main => { // 44A6
                    const a = r.board(si);
                    if (a == C.o_bishop) { // 44C6
                        if (!r.ownOk(si, d)) return;
                        r.pushOwn(9);
                        si = r.nextPiece(si, d); // 44EA
                        if (r.board(si) == C.o_queen) {
                            state = .aq;
                            continue;
                        }
                        return;
                    }
                    if (a == C.o_queen) {
                        state = .aq;
                        continue;
                    }
                    if (a == C.p_bishop) { // 4500
                        if (r.flag or !r.oppOk(si, d)) return;
                        r.pushOpp(9); // 4532
                        si = r.nextPiece(si, d);
                        const b = r.board(si);
                        if (b == C.o_bishop) { // 454E
                            if (!r.ownOk(si, d)) return;
                            r.pushOwn(9);
                            si = r.nextPiece(si, d); // 4570 -> 44A4
                            continue;
                        }
                        if (b == C.o_queen) {
                            state = .aq;
                            continue;
                        }
                        if (b == C.p_queen) {
                            state = .dq;
                            continue;
                        }
                        return;
                    }
                    if (a == C.p_queen) { // 4710 -> 46CE
                        state = .dq;
                        continue;
                    }
                    return; // border, pawn, knight, rook, king
                },
                .aq => { // 459E: an own queen
                    if (!r.ownOk(si, d)) return;
                    r.own_qd +%= 0x10;
                    state = blk: while (true) { // 45C0
                        si = r.nextPiece(si, d);
                        const a = r.board(si);
                        if (a == C.o_bishop) { // 41B6 4574 / 4CEC 50A2 (DEV-023)
                            if (C.pin_test_bishop_behind_queen and !r.ownOk(si, d)) return;
                            r.own_qd +%= 1;
                        } else if (a == C.o_queen) {
                            break :blk .aq; // the queen is pin-tested again
                        } else return;
                    };
                },
                .dq => { // 46CE: an opponent queen
                    if (r.flag or !r.oppOk(si, d)) return;
                    r.opp_qd +%= 0x10;
                    state = blk: while (true) { // 46F6
                        si = r.nextPiece(si, d);
                        const a = r.board(si);
                        if (a == C.o_bishop) { // 46A8
                            if (!r.ownOk(si, d)) return;
                            r.pushOwn(9);
                        } else if (a == C.o_queen) { // 4760
                            break :blk .mixed;
                        } else if (a == C.p_bishop) { // 4684
                            if (!r.oppOk(si, d)) return;
                            r.opp_qd +%= 1;
                        } else if (a == C.p_queen) {
                            break :blk .dq;
                        } else return;
                    };
                },
                .mixed => { // 4760: an own queen after an opponent queen
                    if (!r.ownOk(si, d)) return;
                    r.own_qd +%= 0x10;
                    state = blk: while (true) { // 4782
                        si = r.nextPiece(si, d);
                        const a = r.board(si);
                        if (a == C.o_bishop) { // 41B6 4718 / 4CEC 525E (DEV-023)
                            if (C.pin_test_bishop_in_mixed and !r.ownOk(si, d)) return;
                            r.own_qd +%= 1;
                        } else if (a == C.o_queen) {
                            break :blk .mixed;
                        } else if (a == C.p_bishop) { // 473C
                            if (!r.oppOk(si, d)) return;
                            r.opp_qd +%= 1;
                        } else if (a == C.p_queen) { // 47A0
                            if (!r.oppOk(si, d)) return;
                            r.opp_qd +%= 0x10;
                        } else return;
                    };
                },
            };
        }

        /// One rank or file (41B6 480B..4B3E; 4CEC 5327..5652): the diagonal machine
        /// with rooks for bishops, value 15, no pawn rule and no flag, and every piece
        /// pin-tested in both routines.
        fn line(r: *Self, comptime d: i8) void {
            var si = r.nextPiece(r.sq, d);
            var state: enum { main, ar, dr, aq, dq, mixed } = .main;
            while (true) switch (state) {
                .main => { // 480B
                    const a = r.board(si);
                    if (a == C.o_rook) {
                        state = .ar;
                    } else if (a == C.o_queen) {
                        state = .aq;
                    } else if (a == C.p_rook) {
                        state = .dr;
                    } else if (a == C.p_queen) {
                        state = .dq;
                    } else return;
                },
                .ar => { // 482C: an own rook
                    if (!r.ownOk(si, d)) return;
                    r.pushOwn(15);
                    si = r.nextPiece(si, d); // 4850
                    const a = r.board(si);
                    if (a == C.o_rook) {
                        state = .ar;
                    } else if (a == C.o_queen) {
                        state = .aq;
                    } else return;
                },
                .dr => { // 4866: an opponent rook
                    if (!r.oppOk(si, d)) return;
                    r.pushOpp(15); // 4892
                    si = r.nextPiece(si, d);
                    const a = r.board(si);
                    if (a == C.o_queen) {
                        state = .aq;
                    } else if (a == C.p_rook) {
                        state = .dr;
                    } else if (a == C.o_rook) { // 48B2
                        if (!r.ownOk(si, d)) return;
                        r.pushOwn(15);
                        si = r.nextPiece(si, d); // 48D4 -> 480B
                        state = .main;
                    } else if (a == C.p_queen) {
                        state = .dq;
                    } else return;
                },
                .aq => { // 4920: an own queen
                    if (!r.ownOk(si, d)) return;
                    r.own_qo +%= 0x10;
                    state = blk: while (true) { // 4942
                        si = r.nextPiece(si, d);
                        const a = r.board(si);
                        if (a == C.o_rook) { // 48D8
                            if (!r.ownOk(si, d)) return;
                            r.own_qo +%= 1;
                        } else if (a == C.o_queen) {
                            break :blk .aq;
                        } else return;
                    };
                },
                .dq => { // 4A50: an opponent queen
                    if (!r.oppOk(si, d)) return;
                    r.opp_qo +%= 0x10;
                    state = blk: while (true) { // 4A72
                        si = r.nextPiece(si, d);
                        const a = r.board(si);
                        if (a == C.o_rook) { // 4A2A
                            if (!r.ownOk(si, d)) return;
                            r.pushOwn(15);
                        } else if (a == C.o_queen) { // 4ADC
                            break :blk .mixed;
                        } else if (a == C.p_rook) { // 4A06
                            if (!r.oppOk(si, d)) return;
                            r.opp_qo +%= 1;
                        } else if (a == C.p_queen) {
                            break :blk .dq;
                        } else return;
                    };
                },
                .mixed => { // 4ADC: an own queen after an opponent queen
                    if (!r.ownOk(si, d)) return;
                    r.own_qo +%= 0x10;
                    state = blk: while (true) { // 4AFE
                        si = r.nextPiece(si, d);
                        const a = r.board(si);
                        if (a == C.o_rook) { // 4A94
                            if (!r.ownOk(si, d)) return;
                            r.own_qo +%= 1;
                        } else if (a == C.o_queen) {
                            break :blk .mixed;
                        } else if (a == C.p_rook) { // 4AB8
                            if (!r.oppOk(si, d)) return;
                            r.opp_qo +%= 1;
                        } else if (a == C.p_queen) { // 4B1C
                            if (!r.oppOk(si, d)) return;
                            r.opp_qo +%= 0x10;
                        } else return;
                    };
                },
            };
        }

        /// The queens counted on diagonals and lines, after all bishops and rooks (41B6
        /// 4B40..4BB7 own, 4BBA..4C31 opponent), as the movegen exchange evaluator emits
        /// them: "27, 9" once if a bishop stands behind a diagonal queen, "27, 15" and
        /// another 15 for each further rook behind line queens, then 27 for every queen
        /// left (a leftover bishop count adds one more).
        inline fn emitQueens(r: *Self, qd_in: u8, qo: u8, comptime own_side: bool) void {
            const push = if (own_side) &pushOwn else &pushOpp;
            var qd = qd_in;
            if (qd == 0 and qo == 0) return;
            if (qd & 0x0F != 0) {
                push(r, 27);
                push(r, 9);
                qd -%= 0x11;
            }
            var al = qo;
            if (al & 0x0F != 0) {
                push(r, 27);
                push(r, 15);
                al -%= 0x11;
                while (al & 0x0F != 0) {
                    push(r, 15);
                    al -%= 1;
                }
            }
            al +%= qd;
            while (s8(al) > 0) {
                push(r, 27);
                al -%= 0x10;
            }
        }
    };
}

/// Port of exchange_pinaware_white (4793:41B6-4C97, pin helpers 4162 and 418C) and
/// exchange_pinaware_black (4793:4CEC-57AB, pin helpers 4C98 and 4CC2): the exchange
/// value, in the units of DG:1A71 (pawn 3), of `side` capturing on `sq` first with a piece
/// of exchange value `v` (its low byte, signed), both sides' pieces tested for pins.
/// Returns the original's AX: a signed byte, sign-extended to 16 bits. Writes the work
/// areas in `s` as the original writes DG:9FEC, A060, 70E5 and B4E6 (on the early return
/// only g[0], DG:70E5). `sq` is a square of the 10x12 board whose diagonal and line
/// neighbours lie on it (any square 11..108; the callers pass 21..98).
pub fn exchange(p: *const Position, s: *Scratch, side: Side, sq: u8, v: u16) u16 {
    return exchangeFixes(pos.Fixes.original, p, s, side, sq, v);
}

/// `exchange` with this unit's class C fix as `fixes` says (`dev023_pinned_bishop`; no
/// other switch is read here). With `pos.Fixes.original` it is the original.
pub fn exchangeFixes(comptime fixes: pos.Fixes, p: *const Position, s: *Scratch, side: Side, sq: u8, v: u16) u16 {
    return switch (side) {
        inline else => |c| exchangeSide(c, fixes, p, s, sq, v),
    };
}

fn exchangeSide(comptime us: Side, comptime fixes: pos.Fixes, p: *const Position, s: *Scratch, sq_in: u8, v: u16) u16 {
    const C = Codes(us, fixes);
    const R = Run(us, fixes);
    const sq: usize = sq_in;
    const vb: u8 = @truncate(v);
    // 1. The victim's value (41C4..41CF); a capturer worth less than the victim wins the
    // difference at once (41D2..41E3).
    const victim = see_value[p.board[sq] +% 128];
    s.gain[0] = victim;
    if (s8(vb) < s8(victim)) return @bitCast(@as(i16, s8(victim)) - s8(vb));

    // 2. The capturer is the first own entry; the opponent list starts empty
    // (41E6..41FC).
    var r: R = .{ .p = p, .s = s, .sq = sq };
    s.attackers[0] = vb;
    s.defenders[0] = 0;
    // 3.-5. Own pawns and knights, then the opponent's.
    r.pawns(true);
    r.knights(true);
    r.pawns(false);
    r.knights(false);
    // 6. The four diagonals (4490..47F4). First two: an opponent pawn next to sq is
    // passed only when the first opponent entry is a pawn.
    inline for (C.diag_first) |d| blk: {
        var si = add(sq, d);
        if (p.board[si] == C.p_pawn) {
            if (s.defenders[0] != 3) break :blk;
            si = add(si, d);
        }
        r.flag = false;
        r.diag(si, d);
    }
    // Last two: the own pawn next to sq is passed and sets the flag.
    inline for (C.diag_last) |d| {
        r.flag = false;
        var si = add(sq, d);
        if (p.board[si] == C.o_pawn) {
            r.flag = true;
            si = add(si, d);
        }
        r.diag(si, d);
    }
    // The four lines, +10, -10, +1, -1 (DG:04A6 read from index 3 down, 47F8..488F), in
    // both routines.
    inline for ([4]i8{ 10, -10, 1, -1 }) |d| r.line(d);
    // 7. Own queens; the own king only if no opponent piece was found pinned; 0. The
    // opponent's queens; its king only if no own piece was found pinned; 0 (4B40..4C31).
    r.emitQueens(r.own_qd, r.own_qo, true);
    if (!r.opp_pinned and reach(&king_reach, sq, p.piece_list[16 * C.u + 7])) r.pushOwn(30);
    s.attackers[r.own] = 0;
    r.emitQueens(r.opp_qd, r.opp_qo, false);
    if (!r.own_pinned and reach(&king_reach, sq, p.piece_list[16 * C.t + 7])) r.pushOpp(30);
    s.defenders[r.opp] = 0;
    // 8. Swap-off (4C34..4C8B), identical to the movegen exchange evaluator's, signed
    // bytes.
    var di: usize = 0;
    while (di < 10) {
        if (s.defenders[di] == 0) {
            s.net[di] = s.gain[di];
            break;
        }
        const h = s.gain[di] -% s.attackers[di];
        s.net[di] = h;
        if (s.attackers[di + 1] == 0) break;
        s.gain[di + 1] = h +% s.defenders[di];
        di += 1;
    }
    // The first maximum of h[0..di] (strictly above -27), then the minimum of it and
    // g[0..at].
    var best: u8 = 0xE5;
    var at: usize = 0;
    for (0..di + 1) |i| {
        if (s8(s.net[i]) > s8(best)) {
            best = s.net[i];
            at = i;
        }
    }
    var j = at + 1;
    while (j > 0) {
        j -= 1;
        if (s8(s.gain[j]) < s8(best)) best = s.gain[j];
    }
    return @bitCast(@as(i16, s8(best)));
}
