//! Static exchange evaluation: see_capture_by_white (2B9F:C32A) and
//! see_capture_by_black (2B9F:CAC2).
//!
//! Specification: docs/arch/21-move-generation.md §1, whose executable form is
//! tools/research/movegen/model.py `see` (proved on about two million calls). Test:
//! src/see_test.zig, which replays calls recorded from the original
//! (tests/golden/movegen/).
//!
//! The two routines are mirrors, so one generic body serves both, with the colour as
//! a compile-time parameter. Everything is a signed or unsigned byte as in the
//! original; the counters and list entries wrap at 8 bits.
//!
//! The eight rays are unrolled, each with its step known at compile time, and a step
//! read from a king ray map is dispatched to the same compile-time walks: about a tenth
//! faster than looping over a table of steps (measured on recorded calls).

const std = @import("std");
const pos = @import("position.zig");
const Position = pos.Position;
const Side = pos.Side;
const dg = @import("original.zig").dgroup;

/// The routine's work areas in DGROUP. Nothing in this unit reads them after the call,
/// but the original leaves them for whoever looks, so the port keeps them: the lists
/// are 0-terminated and bytes beyond the terminator keep what they held.
pub const Scratch = struct {
    /// DG:9FEC: the capturing side's exchange values, the capturer first.
    attackers: [116]u8 = @splat(0),
    /// DG:A060: the defending side's exchange values.
    defenders: [32]u8 = @splat(0),
    /// DG:70E5: g[i], the material balance before each capture of the swap-off.
    gain: [11]u8 = @splat(0),
    /// DG:B4E6: h[i], the balance after it. Entry 10 is read (never written) only when
    /// the swap-off runs ten rounds; it stands for DG:B4F0.
    net: [11]u8 = @splat(0),
};

// ---------------------------------------------------------------------------
// Tables, from the original's initialised data
// ---------------------------------------------------------------------------

/// DG:1A71: exchange value by piece code: empty 1, P 3, N 9, B 9, R 15, Q 27, K 0
/// (both colours).
const see_value = dg(0x1A71, 14);

/// DG:0A68 + d, read for d = sq - (a knight's list entry), which the original does for
/// any entry 0..255: the knight-step table and, beyond its ±77 range, the bytes that
/// follow and precede it (the en-passant tables among them). A knight whose entry is
/// FFh (set so by a caller) is therefore counted on the target squares 40..47 and
/// 70..77, as in the original (docs/arch/21-move-generation.md, suspected bug 8).
/// Index d + 255, d = -255..119.
const knight_reach = dg(0x0A68 - 255, 375);

/// DG:0CFF + d: non-zero when d is a king step. Same range as `knight_reach`.
const king_reach = dg(0x0CFF - 255, 375);

/// DG:0490, DG:047E, DG:0470: direction code to step and to slider bit; piece code to
/// slider bits (the same tables make_move uses).
const dir_step: [17]i8 = @bitCast(dg(0x0490, 17));
const dir_bit = dg(0x047E, 17);
const slider_bits = dg(0x0470, 14);

inline fn reach(table: *const [375]u8, sq: u8, entry: u8) bool {
    return table[@as(usize, sq) + 255 - entry] != 0;
}

inline fn add(sq: usize, d: i32) usize {
    return @intCast(@as(i32, @intCast(sq)) + d);
}

inline fn s8(x: u8) i8 {
    return @bitCast(x);
}

/// The colour-dependent codes and tables of one routine. `us` captures first.
fn Codes(comptime us: Side) type {
    const white = us == .white;
    return struct {
        const a_pawn: u8 = if (white) pos.white_pawn else pos.black_pawn;
        const a_bishop: u8 = if (white) pos.white_bishop else pos.black_bishop;
        const a_rook: u8 = if (white) pos.white_rook else pos.black_rook;
        const a_queen: u8 = if (white) pos.white_queen else pos.black_queen;
        const d_pawn: u8 = if (white) pos.black_pawn else pos.white_pawn;
        const d_bishop: u8 = if (white) pos.black_bishop else pos.white_bishop;
        const d_rook: u8 = if (white) pos.black_rook else pos.white_rook;
        const d_queen: u8 = if (white) pos.black_queen else pos.white_queen;
        const u: usize = @backingInt(us);
        const t: usize = 1 - u;
        /// The defender's pawns stand on sq+9 and sq+11 (White captures) or sq-9 and
        /// sq-11.
        const def_pawn_dirs: [2]i8 = if (white) .{ 9, 11 } else .{ -9, -11 };
        /// Diagonals in scan order: the first two test the defender's pawn next to
        /// sq, the last two the capturer's own pawn.
        const diag_first: [2]i8 = if (white) .{ 9, 11 } else .{ -9, -11 };
        const diag_last: [2]i8 = if (white) .{ -9, -11 } else .{ 9, 11 };
    };
}

/// One call: the position read, the work areas written, and the scan state.
fn Run(comptime us: Side) type {
    const C = Codes(us);
    return struct {
        const Self = @This();

        p: *const Position,
        s: *Scratch,
        sq: usize,
        /// The defender's king ray map: the defender's pieces are tested for pins, the
        /// capturer's are not.
        pins: *const [120]u8,
        att: usize = 1,
        def: usize = 0,
        /// [bp-2], [bp-4]: the capturer's queens on diagonals / lines (+10h each) and the
        /// bishops / rooks behind them (+1 each).
        att_qd: u8 = 0,
        att_qo: u8 = 0,
        /// [bp-0Ah], [bp-12h]: the same for the defender.
        def_qd: u8 = 0,
        def_qo: u8 = 0,
        /// [bp-0Eh]: the capturer's own pawn stands next to sq on this diagonal.
        flag: bool = false,

        fn pushAtt(r: *Self, v: u8) void {
            r.s.attackers[r.att] = v;
            r.att += 1;
        }

        fn pushDef(r: *Self, v: u8) void {
            r.s.defenders[r.def] = v;
            r.def += 1;
        }

        fn board(r: *const Self, sq: usize) u8 {
            return r.p.board[sq];
        }

        /// The first square after `sq` along step `d` that is not empty.
        inline fn nextPiece(r: *const Self, sq: usize, comptime d: i8) usize {
            var s = add(sq, d);
            while (r.board(s) == pos.empty) s = add(s, d);
            return s;
        }

        /// `nextPiece` along the step of king ray code `code` (`dir_step[code]`).
        fn nextPieceByCode(r: *const Self, sq: usize, code: u8) usize {
            return switch (code) {
                inline 1...16 => |c| r.nextPiece(sq, comptime dir_step[c]),
                else => blk: {
                    // Not a ray code: the same walk with the step read at run time.
                    const d = dir_step[code];
                    var s = add(sq, d);
                    while (r.board(s) == pos.empty) s = add(s, d);
                    break :blk s;
                },
            };
        }

        /// The pin helper (2B9F:C300 / CA98): walk from s, away from the defender's
        /// king along the ray s lies on, to the first piece; pinned when that piece
        /// slides along this kind of line. Returns the ray's step and the verdict.
        fn pinHelper(r: *const Self, s: usize) struct { step: i8, pinned: bool } {
            const code = r.pins[s];
            const step = dir_step[code];
            const p = r.nextPieceByCode(s, code);
            return .{ .step = step, .pinned = dir_bit[code] & slider_bits[r.board(p)] != 0 };
        }

        /// A defender on s may take part: it is not on its king's rays, or no pinner is
        /// behind it, or it is pinned along the line of the capture (step = ±d).
        fn pinOk(r: *const Self, s: usize, comptime d: i8) bool {
            if (r.pins[s] == 0) return true;
            const h = r.pinHelper(s);
            if (!h.pinned) return true;
            return h.step == d or -@as(i32, h.step) == d;
        }

        /// One diagonal (C4EA..C704), from si.
        fn diag(r: *Self, start: usize, comptime d: i8) void {
            var si = start;
            while (r.board(si) == pos.empty) si = add(si, d);
            var state: enum { main, aq, dq, mixed } = .main;
            while (true) switch (state) {
                .main => {
                    const a = r.board(si);
                    if (a == C.a_bishop) { // C520
                        r.pushAtt(9);
                        si = r.nextPiece(si, d);
                        if (r.board(si) == C.a_queen) {
                            state = .aq;
                            continue;
                        }
                        return;
                    }
                    if (a == C.a_queen) {
                        state = .aq;
                        continue;
                    }
                    if (a == C.d_bishop) { // C53C
                        if (r.flag or !r.pinOk(si, d)) return;
                        r.pushDef(9); // C568
                        si = r.nextPiece(si, d);
                        const b = r.board(si);
                        if (b == C.a_bishop) { // C584
                            r.pushAtt(9);
                            si = r.nextPiece(si, d);
                            continue;
                        }
                        if (b == C.a_queen) {
                            state = .aq;
                            continue;
                        }
                        if (b == C.d_queen) {
                            state = .dq;
                            continue;
                        }
                        return;
                    }
                    if (a == C.d_queen) { // C696 -> C65C
                        state = .dq;
                        continue;
                    }
                    return; // border, pawn, knight, rook, king
                },
                .aq => { // C5B4
                    r.att_qd +%= 0x10;
                    while (true) {
                        si = r.nextPiece(si, d);
                        const a = r.board(si);
                        if (a == C.a_bishop) {
                            r.att_qd +%= 1;
                        } else if (a == C.a_queen) {
                            r.att_qd +%= 0x10;
                        } else return;
                    }
                },
                .dq => { // C65C
                    if (r.flag or !r.pinOk(si, d)) return;
                    r.def_qd +%= 0x10;
                    state = blk: while (true) { // C680
                        si = r.nextPiece(si, d);
                        const a = r.board(si);
                        if (a == C.a_bishop) {
                            r.pushAtt(9);
                        } else if (a == C.a_queen) {
                            break :blk .mixed;
                        } else if (a == C.d_bishop) {
                            if (!r.pinOk(si, d)) return;
                            r.def_qd +%= 1;
                        } else if (a == C.d_queen) {
                            break :blk .dq; // the flag and the pin are tested again
                        } else return;
                    };
                },
                .mixed => { // C6C4
                    r.att_qd +%= 0x10;
                    while (true) {
                        si = r.nextPiece(si, d);
                        const a = r.board(si);
                        if (a == C.a_bishop) {
                            r.att_qd +%= 1;
                        } else if (a == C.a_queen) {
                            r.att_qd +%= 0x10;
                        } else if (a == C.d_bishop) {
                            if (!r.pinOk(si, d)) return;
                            r.def_qd +%= 1;
                        } else if (a == C.d_queen) {
                            if (!r.pinOk(si, d)) return;
                            r.def_qd +%= 0x10;
                        } else return;
                    }
                },
            };
        }

        /// One rank or file (C741..C94A): the diagonal machine with rooks for bishops,
        /// value 15, no pawn rule and no flag.
        fn line(r: *Self, comptime d: i8) void {
            var si = r.nextPiece(r.sq, d);
            var state: enum { main, dr, aq, dq, mixed } = .main;
            while (true) switch (state) {
                .main => { // C74D
                    const a = r.board(si);
                    if (a == C.a_rook) { // C76E
                        while (true) {
                            r.pushAtt(15);
                            si = r.nextPiece(si, d);
                            const b = r.board(si);
                            if (b == C.a_rook) continue;
                            if (b == C.a_queen) break;
                            return;
                        }
                        state = .aq;
                    } else if (a == C.a_queen) {
                        state = .aq;
                    } else if (a == C.d_rook) {
                        state = .dr;
                    } else if (a == C.d_queen) { // C8DC
                        state = .dq;
                    } else return;
                },
                .dr => { // C788
                    if (!r.pinOk(si, d)) return;
                    r.pushDef(15); // C7B0
                    si = r.nextPiece(si, d);
                    const a = r.board(si);
                    if (a == C.a_queen) {
                        state = .aq;
                    } else if (a == C.d_rook) {
                        state = .dr;
                    } else if (a == C.a_rook) { // C7D0
                        r.pushAtt(15);
                        si = r.nextPiece(si, d);
                        state = .main;
                    } else if (a == C.d_queen) {
                        state = .dq;
                    } else return;
                },
                .aq => { // C800
                    r.att_qo +%= 0x10;
                    while (true) {
                        si = r.nextPiece(si, d);
                        const a = r.board(si);
                        if (a == C.a_rook) {
                            r.att_qo +%= 1;
                        } else if (a == C.a_queen) {
                            r.att_qo +%= 0x10;
                        } else return;
                    }
                },
                .dq => { // C8A8
                    if (!r.pinOk(si, d)) return;
                    r.def_qo +%= 0x10;
                    state = blk: while (true) { // C8C6
                        si = r.nextPiece(si, d);
                        const a = r.board(si);
                        if (a == C.a_rook) {
                            r.pushAtt(15);
                        } else if (a == C.a_queen) {
                            break :blk .mixed;
                        } else if (a == C.d_rook) {
                            if (!r.pinOk(si, d)) return;
                            r.def_qo +%= 1;
                        } else if (a == C.d_queen) {
                            break :blk .dq;
                        } else return;
                    };
                },
                .mixed => { // C90A
                    r.att_qo +%= 0x10;
                    while (true) {
                        si = r.nextPiece(si, d);
                        const a = r.board(si);
                        if (a == C.a_rook) {
                            r.att_qo +%= 1;
                        } else if (a == C.a_queen) {
                            r.att_qo +%= 0x10;
                        } else if (a == C.d_rook) {
                            if (!r.pinOk(si, d)) return;
                            r.def_qo +%= 1;
                        } else if (a == C.d_queen) {
                            if (!r.pinOk(si, d)) return;
                            r.def_qo +%= 0x10;
                        } else return;
                    }
                },
            };
        }

        /// The queens counted on diagonals and lines, emitted after all bishops and
        /// rooks (C94C..CA2F): "27, 9" once if a bishop stands behind a diagonal queen,
        /// "27, 15" and another 15 for each further rook behind line queens, then 27
        /// for every queen left (a leftover bishop count adds one more).
        fn emitQueens(r: *Self, qd_in: u8, qo: u8, comptime attacker: bool) void {
            const push = if (attacker) &pushAtt else &pushDef;
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

/// Port of see_capture_by_white (2B9F:C32A-CA94, pin helper C300) and
/// see_capture_by_black (2B9F:CAC2-D210, pin helper CA98): the exchange value, in the
/// units of DG:1A71 (pawn 3), of `side` capturing on `sq` with a piece of exchange
/// value `v` (the callers pass 9, 15 or 27). Returns the original's AX: a signed byte,
/// sign-extended to 16 bits.
pub fn see(p: *const Position, s: *Scratch, side: Side, sq: u8, v: u16) u16 {
    return seeFixes(pos.Fixes.original, p, s, side, sq, v);
}

/// `see` with the class C fixes of `fixes`: DEV-058 (`dev058_lifted_knight_entry`), a
/// knight whose list entry is 0 (lifted for the call by a generator or the threat
/// evaluators) takes no part; in the original entry 0 reaches a1 (DG:0A68 + 21).
pub fn seeFixes(comptime fixes: pos.Fixes, p: *const Position, s: *Scratch, side: Side, sq: u8, v: u16) u16 {
    return switch (side) {
        inline else => |c| seeSide(c, fixes.dev058_lifted_knight_entry, p, s, sq, v),
    };
}

fn seeSide(comptime us: Side, comptime dev058: bool, p: *const Position, s: *Scratch, sq: u8, v: u16) u16 {
    const C = Codes(us);
    const R = Run(us);
    const vb: u8 = @truncate(v);
    // 1. The victim's value; a capturer worth less than the victim wins the
    // difference at once (C345). The board code is indexed as a signed byte.
    const victim = see_value[@intCast(s8(p.board[sq]))];
    s.gain[0] = victim;
    if (s8(vb) < s8(victim)) return @bitCast(@as(i16, s8(victim)) - s8(vb));

    var r: R = .{ .p = p, .s = s, .sq = sq, .pins = &p.king_rays[C.t] };
    // 2. The capturer is the first attacker; the defender list starts empty.
    s.attackers[0] = vb;
    s.defenders[0] = 0;
    // 3. Attacking pawns: one entry, or two when the count is exactly 2.
    const n = p.pawn_attacks[C.u][sq];
    if (n != 0) {
        if (n == 2) r.pushAtt(3);
        r.pushAtt(3);
    }
    // 4. Attacking knights, slots 0 and 1, not tested for pins.
    for (0..2) |slot| {
        if (dev058 and p.piece_list[16 * C.u + slot] == 0) continue;
        if (reach(&knight_reach, sq, p.piece_list[16 * C.u + slot])) r.pushAtt(9);
    }
    // 5. Defending pawns, only if the defender's pawn-attack count is non-zero: not
    // counted when pinned off the line of the capture.
    if (p.pawn_attacks[C.t][sq] != 0) {
        inline for (C.def_pawn_dirs) |d| blk: {
            const ps = add(sq, d);
            if (p.board[ps] != C.d_pawn) break :blk;
            const code = r.pins[ps];
            if (code != 0) {
                const step = dir_step[code];
                if (step != -d) {
                    const q = r.nextPieceByCode(ps, code);
                    if (dir_bit[code] & slider_bits[p.board[q]] != 0) break :blk;
                }
            }
            r.pushDef(3);
        }
    }
    // 6. Defending knights, slots 0 and 1; a pinned knight never counts.
    for (0..2) |slot| {
        const kn = p.piece_list[16 * C.t + slot];
        if (dev058 and kn == 0) continue;
        if (!reach(&knight_reach, sq, kn)) continue;
        // A captured knight (entry above 62h) never reaches this far on a board
        // square; the map is indexed as the original does, and an entry off the board
        // traps here in safe builds.
        if (r.pins[kn] != 0) {
            const h = r.pinHelper(kn);
            if (h.pinned) continue;
        }
        r.pushDef(9);
    }
    // 7. The four diagonals.
    inline for (C.diag_first) |d| blk: {
        var si = add(sq, d);
        if (p.board[si] == C.d_pawn) {
            // Past the defender's pawn only if the first defender entry is a pawn.
            if (s.defenders[0] != 3) break :blk;
            si = add(si, d);
        }
        r.flag = false;
        r.diag(si, d);
    }
    inline for (C.diag_last) |d| {
        r.flag = false;
        var si = add(sq, d);
        if (p.board[si] == C.a_pawn) {
            // Past the capturer's own pawn; a defending bishop or queen is then ignored.
            r.flag = true;
            si = add(si, d);
        }
        r.diag(si, d);
    }
    // 8. The four lines, +10, -10, +1, -1 (table DG:04A6 read from index 3 down).
    inline for ([4]i8{ 10, -10, 1, -1 }) |d| r.line(d);
    // 9. Queens and king of the capturer, then a 0; the same for the defender.
    r.emitQueens(r.att_qd, r.att_qo, true);
    if (reach(&king_reach, sq, p.piece_list[16 * C.u + 7])) r.pushAtt(30);
    s.attackers[r.att] = 0;
    r.emitQueens(r.def_qd, r.def_qo, false);
    if (reach(&king_reach, sq, p.piece_list[16 * C.t + 7])) r.pushDef(30);
    s.defenders[r.def] = 0;
    // 10. Swap-off (CA34..CA8B), signed bytes.
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
