//! TEST ONLY: src/evalpieces.zig as it was before the speed pass of 2026-11-18, kept as the
//! reference that src/evalpieces_test.zig compares the faster routines with on states
//! beyond the recorded ones. Not part of the engine; do not change it.
//!
//! The evaluation of pieces and kings: eval_pieces_and_kings (0EF8:0006–2BD4).
//!
//! Specification: docs/arch/53-evaluation-pieces-kings.md §4.1, whose executable form is
//! tools/research/evalpieces/model.py (proved against the running original on
//! 1,279,712 calls, at 15 checkpoints inside the routine). Tests:
//! src/evalpieces_test.zig, which replays calls recorded from the original
//! (tests/golden/evalpieces/) and compares the running score at each checkpoint as well
//! as the result.
//!
//! The routine is five parts in address order: White king safety, Black king safety, a
//! game-stage switch with an endgame branch, the pieces (rooks, knights, bishops), then
//! the style weights and a material-imbalance term. It reads the search position, the
//! tables prepare_eval builds before each search (`EvalState`) and constant tables of
//! the program, which are read from the program file (`original.dgroup`) by their
//! DGROUP address, never retyped.
//!
//! The score is the original's SI: 16 bits, every addition wraps. Table bytes are
//! signed unless stated (`cbw`), as the instruction at each cited address reads them.
//!
//! Two undecided suspected bugs are reproduced (docs/DEVIATIONS.md):
//! - DEV-017: after an enemy bishop or queen is found on a castling diagonal (0313 for
//!   White, 0D99 for Black) the register holding the king's square is left at the
//!   square where the walk stopped, and the king-safety blocks below use that square as
//!   the king's. Here the square is the explicit variable `k` of `whiteKing` and
//!   `blackKing`, which the diagonal walks update as the original's DI.
//! - The activity routines' reads past the board (DEV-018) are in src/activity.zig.

const std = @import("std");
const pos = @import("position.zig");
const EvalState = @import("eval_state.zig").EvalState;
const original = @import("original.zig");

const Position = pos.Position;

/// DG:0000..165F of the program file: the constant tables below are read from it by
/// address.
const K = original.dgroup(0, 0x1660);

// Constant tables (docs/arch/53-evaluation-pieces-kings.md §3.3, §9).
const side_term_entry = 0x155A; // +10 / -10 by side, at entry
const side_term_pieces = 0x155C; // the same, before the pieces
const king_file_block_centre = 0x155E;
const shelter_white_diag = 0x1568; // K+9, K+11
const shelter_black_diag = 0x1576; // K-9, K-11
const shelter_white_orth = 0x1584; // K-1, K+1, K+10
const shelter_black_orth = 0x1592; // K-1, K+1, K-10
const shelter_sum_eg5 = 0x15A0;
const shelter_sum_eg3 = 0x15B0;
const shelter_sum_mid3 = 0x15BA;
const shelter_sum_mid5 = 0x15C4;
const shelter_sum_full5 = 0x15D4;
const bishop_defended = 0x15E4;
// Open-file penalties by pawn count, named by their entry 0 (the only non-zero one).
const open24 = 0x15F4;
const open30 = 0x15FA;
const open36 = 0x1600;
const open42 = 0x1606;
const open48 = 0x160C;
const open54 = 0x1612;
const open60 = 0x1618;
const open72 = 0x161E;
const open84 = 0x162A;
const open96 = 0x1630;
const g_pawn_moved = 0x1636;
const outpost_163C = 0x163C;
const outpost_1640 = 0x1640;
const outpost_1644 = 0x1644;
const bishop_attacked = 0x1648;
const outpost_164C = 0x164C;
const piece_on_f2 = 0x0454;
const piece_on_f7 = 0x0462;
const rook_semi_eg = 0x02FD;
const rook_open_eg = 0x0313;
const rook_semi_low = 0x0329;
const rook_open_low = 0x033F;
const rook_semi_high = 0x0355;
const rook_open_high = 0x036B;
const imbalance_by_pawns = 0x02EC;
const king_distance_eg = 0x040A; // words
const king_safety_eg_white = 0x0530;
const king_safety_eg_black = 0x0594;
const king_centre_eg_white = 0x05F8;
const king_centre_eg_black = 0x065C;
const minor_square_class = 0x0850; // unsigned
const file_of = 0x100A;

/// The addresses at which the test reads the running score: the model's CHECKPOINTS.
pub const checkpoint_addresses = [15]u16{ 0x0AB1, 0x152F, 0x1B5C, 0x1D0E, 0x1F8A, 0x2131, 0x2215, 0x22F9, 0x23DD, 0x2563, 0x2731, 0x28BF, 0x2A95, 0x2B00, 0x2BCF };

/// The running score at each checkpoint a call passed, null where it did not pass.
pub const Checkpoints = struct { score: [15]?i16 = @splat(null) };

/// Port of eval_pieces_and_kings (0EF8:0006–2BD4). `side` is the side to move (0 White,
/// 1 Black), `ply` the search ply. Returns the score from White's point of view.
pub fn evalPiecesAndKings(p: *const Position, e: *const EvalState, side: u16, ply: u16) i16 {
    var c: Ctx(void) = .{ .p = p, .e = e, .side = side, .ply = ply, .probe = {} };
    return c.run();
}

/// The same, recording the running score at the checkpoints (for the tests).
pub fn evalPiecesAndKingsTraced(p: *const Position, e: *const EvalState, side: u16, ply: u16, cp: *Checkpoints) i16 {
    var c: Ctx(*Checkpoints) = .{ .p = p, .e = e, .side = side, .ply = ply, .probe = cp };
    return c.run();
}

/// Signed byte of a constant table.
inline fn t(base: i32, idx: i32) i16 {
    return @as(i8, @bitCast(K[@intCast(base + idx)]));
}
/// Unsigned byte of a constant table.
inline fn tu(base: i32, idx: i32) u8 {
    return K[@intCast(base + idx)];
}
/// Signed word of a constant table.
inline fn tw(base: i32, idx: i32) i16 {
    return std.mem.readInt(i16, K[@intCast(base + idx)..][0..2], .little);
}

inline fn onBoard(entry: u8) bool {
    return entry < 0x63;
}

const Next = enum { pieces, style, return0 };

fn Ctx(comptime Probe: type) type {
    return struct {
        p: *const Position,
        e: *const EvalState,
        side: u16,
        ply: u16,
        probe: Probe,
        /// SI, the running score.
        si: i16 = 0,
        /// [bp-0Ah], [bp-8]: White's and Black's trapped-rook penalties (120 once the
        /// middlegame king block ran).
        la: i16 = 60,
        l8: i16 = 60,
        /// [bp-0Ch]: opposite-coloured-bishops flag (endgame branch only).
        lc: i16 = 0,
        /// [bp-2]: the king-safety subtotal.
        ks: i16 = 0,

        const Self = @This();

        inline fn mark(c: *Self, comptime i: usize) void {
            if (Probe != void) c.probe.score[i] = c.si;
        }
        inline fn add(c: *Self, v: i16) void {
            c.si +%= v;
        }
        inline fn sub(c: *Self, v: i16) void {
            c.si -%= v;
        }
        inline fn bd(c: *const Self, sq: i32) i16 {
            return c.p.board[@intCast(sq)];
        }
        inline fn wpf(c: *const Self, f: i32) i16 {
            return @as(i8, @bitCast(c.p.pawns_per_file[0][@intCast(f)]));
        }
        inline fn bpf(c: *const Self, f: i32) i16 {
            return @as(i8, @bitCast(c.p.pawns_per_file[1][@intCast(f)]));
        }
        inline fn wa(c: *const Self, sq: i32) i16 {
            return @as(i8, @bitCast(c.p.pawn_attacks[0][@intCast(sq)]));
        }
        inline fn ba(c: *const Self, sq: i32) i16 {
            return @as(i8, @bitCast(c.p.pawn_attacks[1][@intCast(sq)]));
        }
        /// White (`wl`) and Black (`bl`) piece-list entries.
        inline fn wl(c: *const Self, slot: usize) u8 {
            return c.p.piece_list[slot];
        }
        inline fn bl(c: *const Self, slot: usize) u8 {
            return c.p.piece_list[16 + slot];
        }
        /// DG:AE38, DG:AE3A: non-pawn material, signed.
        inline fn wnp(c: *const Self) i16 {
            return @bitCast(c.p.piece_material[0]);
        }
        inline fn bnp(c: *const Self) i16 {
            return @bitCast(c.p.piece_material[1]);
        }
        inline fn kfW(c: *const Self) i16 {
            return @as(i8, @bitCast(c.p.king_file[0]));
        }
        inline fn kfB(c: *const Self) i16 {
            return @as(i8, @bitCast(c.p.king_file[1]));
        }
        inline fn krW(c: *const Self) i16 {
            return @as(i8, @bitCast(c.p.king_rank[0]));
        }
        inline fn krB(c: *const Self) i16 {
            return @as(i8, @bitCast(c.p.king_rank[1]));
        }
        inline fn count(v: u8) i16 {
            return @as(i8, @bitCast(v));
        }
        inline fn kingTable(c: *const Self, s: usize, k: i32) i16 {
            return @bitCast(c.e.king_table[s][@intCast(k)]);
        }
        inline fn kingZone(c: *const Self, s: usize, k: i32) i16 {
            return @bitCast(c.e.king_zone[s][@intCast(k)]);
        }
        /// `cmp [bp+6],1; sbb ax,ax; and ..`: `white` when White is to move, else `black`.
        inline fn bySide(c: *const Self, white: i16, black: i16) i16 {
            return if (c.side == 0) white else black;
        }

        /// The castling-diagonal test (0256–0311 and its mirrors): `d = sb [base − ub
        /// entry]`; if non-zero, walk from `origin + d` in steps of `d` over empty
        /// squares. The walk leaves DI (`k`) at the square where it stopped, hit or not.
        fn diagHit(c: *const Self, k: *i32, base: i32, entry: u8, origin: i32, piece: u8) bool {
            const d: i32 = t(base, -@as(i32, entry));
            if (d == 0) return false;
            var s = origin + d;
            while (c.p.board[@intCast(s)] == 0) s += d;
            k.* = s;
            return c.p.board[@intCast(s)] == piece;
        }

        fn wShelter5(c: *const Self, k: i32) i16 {
            return t(shelter_white_orth, c.bd(k + 1)) + t(shelter_white_orth, c.bd(k + 10)) +
                t(shelter_white_orth, c.bd(k - 1)) + t(shelter_white_diag, c.bd(k + 9)) +
                t(shelter_white_diag, c.bd(k + 11));
        }
        fn wShelter3(c: *const Self, k: i32) i16 {
            return t(shelter_white_orth, c.bd(k + 10)) + t(shelter_white_diag, c.bd(k + 9)) +
                t(shelter_white_diag, c.bd(k + 11));
        }
        fn bShelter5(c: *const Self, k: i32) i16 {
            return t(shelter_black_orth, c.bd(k + 1)) + t(shelter_black_orth, c.bd(k - 10)) +
                t(shelter_black_orth, c.bd(k - 1)) + t(shelter_black_diag, c.bd(k - 11)) +
                t(shelter_black_diag, c.bd(k - 9));
        }
        fn bShelter3(c: *const Self, k: i32) i16 {
            return t(shelter_black_orth, c.bd(k - 10)) + t(shelter_black_diag, c.bd(k - 11)) +
                t(shelter_black_diag, c.bd(k - 9));
        }
        /// DG:9EBE + n, the first-rank shelter score built by prepare_eval.
        inline fn firstRank(c: *const Self, n: i16) i16 {
            return @as(i8, @bitCast(c.e.shelter_first_rank[@intCast(n)]));
        }

        // =====================================================================
        fn run(c: *Self) i16 {
            c.si = t(side_term_entry, c.side); // 001A
            c.whiteKing();
            c.mark(0);
            c.blackKing();
            c.mark(1);
            // 152F
            c.ks = c.si;
            c.si = 0;
            if (c.p.piece_material_sum < 6200) { // unsigned compare
                switch (c.endgame()) {
                    .return0 => return 0, // 155C
                    .style => return c.finish(),
                    .pieces => {}, // rejoins at 1B5C without the side-to-move term
                }
            } else {
                c.add(t(side_term_pieces, c.side)); // 1B52
            }
            c.mark(2);
            c.rooks();
            c.mark(4);
            c.knights();
            c.mark(8);
            c.bishops();
            return c.finish();
        }

        // =====================================================================
        // White king safety 0024–0AB0
        // =====================================================================
        fn whiteKing(c: *Self) void {
            var k: i32 = c.wl(7); // 0024: DI = the White king's square
            const nb = c.bnp();
            if (nb <= 3600) { // 002B
                if (nb < 3100) return c.wKingEndgame(k); // 0140
                return c.wReduced(k, t(king_safety_eg_white, k)); // 0041
            }
            if (c.wKingsideProspect(&k)) return c.wCentre(); // 0242
            // 0374
            if (c.p.ooo_lost_at[0] == 0 and c.wpf(2) != 0) {
                if (c.wQueensideProspect(&k)) return c.wCentre();
            }
            // 04A5: k is the king's square, or (DEV-017) where a diagonal walk stopped.
            if (nb <= 4250) return c.w08C6(k);
            c.w04B0(k);
        }

        /// 0242–0373. True when it goes on to the pieces at home (0835).
        fn wKingsideProspect(c: *Self, k: *i32) bool {
            if (c.p.oo_lost_at[0] != 0 or c.wpf(7) == 0) {
                c.sub(12); // 0371
                return false;
            }
            var hit = c.diagHit(k, 0x0B80, c.bl(3), 26, pos.black_bishop) or // 0256
                c.diagHit(k, 0x0B80, c.bl(6), 26, pos.black_queen); // 0286
            if (!hit and c.bd(36) == 0) { // 02B3: f2 empty
                hit = c.diagHit(k, 0x0B81, c.bl(2), 27, pos.black_bishop) or // 02BA
                    c.diagHit(k, 0x0B81, c.bl(6), 27, pos.black_queen); // 02E7
            }
            if (hit) {
                c.sub(48); // 0313: k is left where the walk stopped
                return false;
            }
            if (c.wpf(6) + c.bpf(6) == 0) { // 0318
                k.* = 25; // 036E
                c.sub(12);
                return false;
            }
            c.sub(t(open36, c.bpf(6)) + t(open36, c.wa(47)) + t(open36, c.wpf(6))); // 0328
            c.wEFile();
            return true;
        }

        /// 0349: the e-file term.
        fn wEFile(c: *Self) void {
            c.add(c.kingTable(0, 25) -% t(open48, c.bpf(5)) -% t(open48, c.wpf(5)));
        }

        /// 0388–04A2. True when it goes on to the pieces at home (0835).
        fn wQueensideProspect(c: *Self, k: *i32) bool {
            const hit = c.diagHit(k, 0x0B7E, c.bl(2), 24, pos.black_bishop) or // 0388
                c.diagHit(k, 0x0B7E, c.bl(6), 24, pos.black_queen) or // 03B8
                c.diagHit(k, 0x0B7D, c.bl(3), 23, pos.black_bishop) or // 03E5
                c.diagHit(k, 0x0B7D, c.bl(6), 23, pos.black_queen); // 0411
            if (hit) c.sub(36); // 043D
            const wd = c.wpf(4);
            const bdd = c.bpf(4);
            const wc = c.wpf(3);
            const bc = c.bpf(3);
            if (wd + bdd == 0 or wc + bc == 0) { // 0440
                k.* = 25; // 04A2
                return false;
            }
            c.sub(t(open48, bdd) + t(open36, c.wa(42)) + t(open48, wd) + t(open36, bc) + t(open36, wc)); // 0463
            c.wEFile();
            return true;
        }

        /// 04B0–0834: Black's non-pawn material above 4250.
        fn w04B0(c: *Self, k: i32) void {
            c.la = 120;
            c.add(c.kingTable(0, k)); // 04B7
            if (k < 31) c.add(c.firstRank(c.wShelter3(k))) else c.add(t(shelter_sum_full5, c.wShelter5(k)));
            const kf = c.kfW(); // the king's real file
            if (kf >= 6) { // 055B
                c.add(t(piece_on_f2, c.bd(k + 9)) - t(open96, c.bpf(7)) - t(open84, c.bpf(8)) -
                    t(open84, c.wpf(8)) - t(open54, c.bpf(6)) - t(open30, c.wpf(6)));
                if (c.bd(37) != pos.white_pawn) c.w05B8(); // g2
                c.w081A();
            } else if (kf <= 3) { // 0650
                c.add(t(piece_on_f2, c.bd(k + 11)) - t(open96, c.bpf(2)) - t(open84, c.bpf(1)) -
                    t(open84, c.wpf(1)) - t(open54, c.bpf(3)) - t(open30, c.wpf(3)));
                if (c.bd(32) != pos.white_pawn) c.w06AD(); // b2
                c.w07BD();
            } else { // 073C
                c.sub(t(open72, c.wpf(4)) + t(open60, c.bpf(4)) + t(open60, c.bpf(5)) + t(open72, c.wpf(5)));
                if (kf == 4) {
                    c.sub(t(open72, c.wpf(3)) + t(open60, c.bpf(3)));
                    if (c.bd(32) != pos.white_pawn) { // 0795
                        c.sub(t(open42, c.wpf(2)));
                        if (!onBoard(c.wl(3))) {
                            c.sub(12);
                            if (onBoard(c.bl(2))) c.sub(30);
                        }
                    }
                    c.w07BD();
                } else { // 07D6
                    c.sub(t(open72, c.wpf(6)) + t(open60, c.bpf(6)));
                    if (c.bd(37) != pos.white_pawn) {
                        c.sub(t(open42, c.wpf(7)));
                        if (!onBoard(c.wl(2))) {
                            c.sub(12);
                            if (onBoard(c.bl(3))) c.sub(30);
                        }
                    }
                    c.w081A();
                }
            }
            c.wCentre();
        }

        /// 05B8: the g2 pawn has moved (king on the kingside).
        fn w05B8(c: *Self) void {
            if (c.bd(47) != pos.white_pawn) { // g3
                c.sub(t(g_pawn_moved, c.wpf(7)));
                if (onBoard(c.bl(2))) c.sub(24);
            }
            if (c.bd(36) == pos.white_pawn) { // 05D6 f2
                if (onBoard(c.wl(2))) return;
                c.sub(12);
                if (onBoard(c.bl(3))) c.sub(24);
                if (c.ba(37) != 0) c.sub(24); // 05F4: BA[g2]
                return;
            }
            c.sub(12); // 0604
            if (c.bd(46) == pos.white_pawn) { // f3
                if (onBoard(c.wl(2))) return;
                c.sub(12);
                if (onBoard(c.bl(3))) c.sub(24);
                return;
            }
            if (onBoard(c.wl(2))) return; // 0628
            c.sub(24);
            if (onBoard(c.bl(3))) c.sub(36);
        }

        /// 06AD: the b2 pawn has moved (king on the queenside).
        fn w06AD(c: *Self) void {
            if (c.bd(42) != pos.white_pawn) { // b3
                c.sub(t(g_pawn_moved, c.wpf(2)));
                if (onBoard(c.bl(3))) c.sub(24);
            }
            if (c.bd(33) == pos.white_pawn) { // 06CB c2
                if (onBoard(c.wl(3))) return;
                c.sub(12);
                if (onBoard(c.bl(2))) c.sub(24);
                if (c.ba(32) != 0) c.sub(24); // 06E9: BA[b2]
                return;
            }
            c.sub(12); // 06FA
            if (c.bd(43) == pos.white_pawn) { // c3
                if (onBoard(c.wl(3))) return;
                c.sub(12);
                if (onBoard(c.bl(2))) c.sub(24);
                return;
            }
            if (onBoard(c.wl(3))) return; // 071E
            c.sub(24);
            if (onBoard(c.bl(2))) c.sub(36);
        }

        /// 07BD
        fn w07BD(c: *Self) void {
            if (c.wa(42) != 0) return; // WA[b3]
            if (onBoard(c.bl(3))) c.sub(24);
            if (!onBoard(c.wl(2))) c.sub(24);
        }

        /// 081A
        fn w081A(c: *Self) void {
            if (c.wa(47) != 0) return; // WA[g3]
            if (onBoard(c.bl(2))) c.sub(24);
            if (!onBoard(c.wl(3))) c.sub(24);
        }

        /// 0835–08C3: pieces at home behind the d- and e-pawns.
        fn wCentre(c: *Self) void {
            if (c.bd(34) != 0) { // d2
                if (c.bd(22) == pos.white_knight and (c.bd(43) != 0 or c.ba(43) != 0)) c.sub(24); // b1, c3
                if (c.bd(23) == pos.white_bishop and c.bd(32) != 0) c.sub(12); // c1, b2
                if (c.bd(34) == pos.white_pawn and c.bd(44) != 0) c.sub(24); // d2, d3
            }
            if (c.bd(35) == 0) return; // 0876 e2
            if (c.bd(27) == pos.white_knight and (c.bd(46) != 0 or c.ba(46) != 0)) c.sub(24); // g1, f3
            if (c.bd(26) == pos.white_bishop) { // f1
                c.sub(12);
                if (c.bd(37) != 0) c.sub(12);
            }
            if (c.bd(35) == pos.white_pawn and c.bd(45) != 0) c.sub(24); // e2, e3
        }

        /// 0046 (entered at 0041 with ax = T[0530](k)): the reduced variant.
        fn wReduced(c: *Self, k: i32, ax: i16) void {
            c.add(ax);
            if (k < 31) c.add(t(shelter_sum_mid3, c.wShelter3(k))) else c.add(t(shelter_sum_mid5, c.wShelter5(k)));
            const f: i32 = t(king_file_block_centre, c.kfW()); // 00DF
            c.sub(t(open30, c.wpf(f + 1)) + t(open24, c.bpf(f + 1)) + t(open24, c.bpf(f - 1)) +
                t(open30, c.wpf(f - 1)) + t(open24, c.bpf(f)) + t(open30, c.wpf(f)));
        }

        /// 0140–0241: Black's non-pawn material below 3100.
        fn wKingEndgame(c: *Self, k: i32) void {
            const nb = c.bnp();
            if (c.e.no_pawns_at_root != 0 or nb < 1100) return c.add(c.kingZone(0, k));
            if (nb < 2000) return c.add((t(king_centre_eg_white, k) +% c.kingZone(0, k)) >> 1);
            if (nb < 2650) {
                c.add(t(king_centre_eg_white, k));
            } else if (count(c.p.piece_count[1]) < 3) {
                c.add(t(king_safety_eg_white, k));
            } else {
                c.add((3 * t(king_centre_eg_white, k) + t(king_safety_eg_white, k)) >> 2);
            }
            if (k < 31) c.add(t(shelter_sum_eg3, c.wShelter3(k))) else c.add(t(shelter_sum_eg5, c.wShelter5(k)));
        }

        /// 08C6–0AB0: Black's non-pawn material 3601..4250.
        fn w08C6(c: *Self, k: i32) void {
            const n = count(c.p.piece_count[1]);
            if (n == 5) return c.wReduced(k, t(king_safety_eg_white, k)); // 08CD -> 0041
            if (n >= 4) return c.wReduced(k, (t(king_safety_eg_white, k) +% c.kingTable(0, k)) >> 1);
            c.add(c.kingTable(0, k)); // 08E8
            if (k < 31) c.add(t(shelter_sum_mid3, c.wShelter3(k))) else c.add(t(shelter_sum_mid5, c.wShelter5(k)));
            const kf = c.kfW();
            if (kf >= 6) { // 098C
                c.add(t(piece_on_f2, c.bd(k + 9)) - t(open54, c.wpf(7)) - t(open48, c.bpf(7)) -
                    t(open54, c.wpf(8)) - t(open48, c.bpf(8)) - t(open42, c.bpf(6)) - t(open24, c.wpf(6)));
            } else if (kf <= 3) { // 09F7
                c.add(t(piece_on_f2, c.bd(k + 11)) - t(open54, c.wpf(1)) - t(open48, c.bpf(1)) -
                    t(open54, c.wpf(2)) - t(open48, c.bpf(2)) - t(open42, c.bpf(3)) - t(open24, c.wpf(3)));
            } else { // 0A4E
                const f: i32 = t(king_file_block_centre, kf);
                c.sub(t(open54, c.wpf(f + 1)) + t(open48, c.bpf(f + 1)) + t(open48, c.bpf(f - 1)) +
                    t(open54, c.wpf(f - 1)) + t(open48, c.bpf(f)) + t(open54, c.wpf(f)));
            }
        }

        // =====================================================================
        // Black king safety 0AB1–152E (the mirror; scores added)
        // =====================================================================
        fn blackKing(c: *Self) void {
            var k: i32 = c.bl(7); // 0AB1
            const nw = c.wnp();
            if (nw <= 3600) {
                if (nw < 3100) return c.bKingEndgame(k); // 0BC6
                return c.bReduced(k, t(king_safety_eg_black, k)); // 0ACE
            }
            if (c.bKingsideProspect(&k)) return c.bCentre(); // 0CC8
            // 0DF8
            if (c.p.ooo_lost_at[1] == 0 and c.bpf(2) != 0) {
                if (c.bQueensideProspect(&k)) return c.bCentre();
            }
            // 0F29: k as for White (DEV-017)
            if (nw <= 4250) return c.b134A(k);
            c.b0F34(k);
        }

        fn bKingsideProspect(c: *Self, k: *i32) bool {
            if (c.p.oo_lost_at[1] != 0 or c.bpf(7) == 0) {
                c.add(12); // 0DF5
                return false;
            }
            var hit = c.diagHit(k, 0x0BC6, c.wl(3), 96, pos.white_bishop) or // 0CDC
                c.diagHit(k, 0x0BC6, c.wl(6), 96, pos.white_queen); // 0D0C
            if (!hit and c.bd(86) == 0) { // 0D39: f7 empty
                hit = c.diagHit(k, 0x0BC7, c.wl(2), 97, pos.white_bishop) or // 0D40
                    c.diagHit(k, 0x0BC7, c.wl(6), 97, pos.white_queen); // 0D6D
            }
            if (hit) {
                c.add(48); // 0D99
                return false;
            }
            if (c.wpf(6) + c.bpf(6) == 0) { // 0D9E
                k.* = 95; // 0DF2
                c.add(12);
                return false;
            }
            c.add(t(open36, c.bpf(6)) + t(open36, c.ba(77)) + t(open36, c.wpf(6))); // 0DAE
            c.bEFile();
            return true;
        }

        /// 0DCF: the e-file term.
        fn bEFile(c: *Self) void {
            c.add((t(open48, c.wpf(5)) + t(open48, c.bpf(5))) -% c.kingTable(1, 95));
        }

        fn bQueensideProspect(c: *Self, k: *i32) bool {
            const hit = c.diagHit(k, 0x0BC4, c.wl(2), 94, pos.white_bishop) or // 0E0C
                c.diagHit(k, 0x0BC4, c.wl(6), 94, pos.white_queen) or // 0E3C
                c.diagHit(k, 0x0BC3, c.wl(3), 93, pos.white_bishop) or // 0E69
                c.diagHit(k, 0x0BC3, c.wl(6), 93, pos.white_queen); // 0E95
            if (hit) c.add(36); // 0EC1
            const wd = c.wpf(4);
            const bdd = c.bpf(4);
            const wc = c.wpf(3);
            const bc = c.bpf(3);
            if (wd + bdd == 0 or wc + bc == 0) { // 0EC4
                k.* = 95; // 0F26
                return false;
            }
            c.add(t(open48, bdd) + t(open36, c.ba(72)) + t(open48, wd) + t(open36, bc) + t(open36, wc)); // 0EE7
            c.bEFile();
            return true;
        }

        /// 0F34: White's non-pawn material above 4250.
        fn b0F34(c: *Self, k: i32) void {
            c.l8 = 120;
            c.sub(c.kingTable(1, k)); // 0F3B
            if (k > 88) c.sub(c.firstRank(c.bShelter3(k))) else c.sub(t(shelter_sum_full5, c.bShelter5(k)));
            const kf = c.kfB();
            if (kf >= 6) { // 0FDF
                c.add(t(open96, c.wpf(7)) - t(piece_on_f7, c.bd(k - 11)) + t(open84, c.bpf(8)) +
                    t(open84, c.wpf(8)) + t(open54, c.wpf(6)) + t(open30, c.bpf(6)));
                if (c.bd(87) != pos.black_pawn) c.b103C(); // g7
                c.b129E();
            } else if (kf <= 3) { // 10D4
                c.add(t(open84, c.bpf(1)) - t(piece_on_f7, c.bd(k - 9)) + t(open96, c.wpf(2)) +
                    t(open84, c.wpf(1)) + t(open54, c.wpf(3)) + t(open30, c.bpf(3)));
                if (c.bd(82) != pos.black_pawn) c.b1131(); // b7
                c.b1241();
            } else { // 11C0
                c.add(t(open72, c.bpf(5)) + t(open72, c.bpf(4)) + t(open60, c.wpf(4)) + t(open60, c.wpf(5)));
                if (kf == 4) {
                    c.add(t(open60, c.wpf(3)) + t(open72, c.bpf(3)));
                    if (c.bd(82) != pos.black_pawn) { // 1219
                        c.add(t(open42, c.bpf(2)));
                        if (!onBoard(c.bl(3))) {
                            c.add(12);
                            if (onBoard(c.wl(2))) c.add(30);
                        }
                    }
                    c.b1241();
                } else { // 125A
                    c.add(t(open60, c.wpf(6)) + t(open72, c.bpf(6)));
                    if (c.bd(87) != pos.black_pawn) {
                        c.add(t(open42, c.bpf(7)));
                        if (!onBoard(c.bl(2))) {
                            c.add(12);
                            if (onBoard(c.wl(3))) c.add(30);
                        }
                    }
                    c.b129E();
                }
            }
            c.bCentre();
        }

        /// 103C: the g7 pawn has moved.
        fn b103C(c: *Self) void {
            if (c.bd(77) != pos.black_pawn) { // g6
                c.add(t(g_pawn_moved, c.bpf(7)));
                if (onBoard(c.wl(2))) c.add(24);
            }
            if (c.bd(86) == pos.black_pawn) { // 105A f7
                if (onBoard(c.bl(2))) return;
                c.add(12);
                if (onBoard(c.wl(3))) c.add(24);
                if (c.wa(87) != 0) c.add(24); // 1078: WA[g7]
                return;
            }
            c.add(12); // 1088
            if (c.bd(76) == pos.black_pawn) { // f6
                if (onBoard(c.bl(2))) return;
                c.add(12);
                if (onBoard(c.wl(3))) c.add(24);
                return;
            }
            if (onBoard(c.bl(2))) return; // 10AC
            c.add(24);
            if (onBoard(c.wl(3))) c.add(36);
        }

        /// 1131: the b7 pawn has moved.
        fn b1131(c: *Self) void {
            if (c.bd(72) != pos.black_pawn) { // b6
                c.add(t(g_pawn_moved, c.bpf(2)));
                if (onBoard(c.wl(3))) c.add(24);
            }
            if (c.bd(83) == pos.black_pawn) { // 114F c7
                if (onBoard(c.bl(3))) return;
                c.add(12);
                if (onBoard(c.wl(2))) c.add(24);
                if (c.wa(82) != 0) c.add(24); // 116D: WA[b7]
                return;
            }
            c.add(12); // 117E
            if (c.bd(73) == pos.black_pawn) { // c6
                if (onBoard(c.bl(3))) return;
                c.add(12);
                if (onBoard(c.wl(2))) c.add(24);
                return;
            }
            if (onBoard(c.bl(3))) return; // 11A2
            c.add(24);
            if (onBoard(c.wl(2))) c.add(36);
        }

        /// 1241
        fn b1241(c: *Self) void {
            if (c.ba(72) != 0) return; // BA[b6]
            if (onBoard(c.wl(3))) c.add(24);
            if (!onBoard(c.bl(2))) c.add(24);
        }

        /// 129E
        fn b129E(c: *Self) void {
            if (c.ba(77) != 0) return; // BA[g6]
            if (onBoard(c.wl(2))) c.add(24);
            if (!onBoard(c.bl(3))) c.add(24);
        }

        /// 12B9: pieces at home behind the d- and e-pawns.
        fn bCentre(c: *Self) void {
            if (c.bd(84) != 0) { // d7
                if (c.bd(92) == pos.black_knight and (c.bd(73) != 0 or c.wa(73) != 0)) c.add(24); // b8, c6
                if (c.bd(93) == pos.black_bishop and c.bd(82) != 0) c.add(12); // c8, b7
                if (c.bd(84) == pos.black_pawn and c.bd(74) != 0) c.add(24); // d7, d6
            }
            if (c.bd(85) == 0) return; // 12FA e7
            if (c.bd(97) == pos.black_knight and (c.bd(76) != 0 or c.wa(76) != 0)) c.add(24); // g8, f6
            if (c.bd(96) == pos.black_bishop) { // f8
                c.add(12);
                if (c.bd(87) != 0) c.add(12);
            }
            if (c.bd(85) == pos.black_pawn and c.bd(75) != 0) c.add(24); // e7, e6
        }

        /// 0AD3 (entered at 0ACE with ax = T[0594](k)).
        fn bReduced(c: *Self, k: i32, ax: i16) void {
            c.sub(ax);
            if (k > 88) c.sub(t(shelter_sum_mid3, c.bShelter3(k))) else c.sub(t(shelter_sum_mid5, c.bShelter5(k)));
            const f: i32 = t(king_file_block_centre, c.kfB()); // 0B6B
            c.add(t(open30, c.bpf(f - 1)) + t(open30, c.bpf(f + 1)) + t(open30, c.bpf(f)) +
                t(open24, c.wpf(f + 1)) + t(open24, c.wpf(f - 1)) + t(open24, c.wpf(f)));
        }

        /// 0BC6: White's non-pawn material below 3100.
        fn bKingEndgame(c: *Self, k: i32) void {
            const nw = c.wnp();
            if (c.e.no_pawns_at_root != 0 or nw < 1100) return c.sub(c.kingZone(1, k));
            if (nw < 2000) return c.sub((t(king_centre_eg_black, k) +% c.kingZone(1, k)) >> 1);
            if (nw < 2650) {
                c.sub(t(king_centre_eg_black, k));
            } else if (count(c.p.piece_count[0]) < 3) {
                c.sub(t(king_safety_eg_black, k));
            } else {
                c.sub((3 * t(king_centre_eg_black, k) + t(king_safety_eg_black, k)) >> 2);
            }
            if (k > 88) c.sub(t(shelter_sum_eg3, c.bShelter3(k))) else c.sub(t(shelter_sum_eg5, c.bShelter5(k)));
        }

        /// 134A: White's non-pawn material 3601..4250.
        fn b134A(c: *Self, k: i32) void {
            const n = count(c.p.piece_count[0]);
            if (n == 5) return c.bReduced(k, t(king_safety_eg_black, k));
            if (n >= 4) return c.bReduced(k, (t(king_safety_eg_black, k) +% c.kingTable(1, k)) >> 1);
            c.sub(c.kingTable(1, k)); // 136C
            if (k > 88) c.sub(t(shelter_sum_mid3, c.bShelter3(k))) else c.sub(t(shelter_sum_mid5, c.bShelter5(k)));
            const kf = c.kfB();
            if (kf >= 6) { // 1410
                c.add(t(open54, c.bpf(7)) - t(piece_on_f7, c.bd(k - 11)) + t(open54, c.bpf(8)) +
                    t(open48, c.wpf(7)) + t(open48, c.wpf(8)) + t(open42, c.wpf(6)) + t(open24, c.bpf(6)));
            } else if (kf <= 3) { // 1475
                c.add(t(open54, c.bpf(1)) - t(piece_on_f7, c.bd(k - 9)) + t(open54, c.bpf(2)) +
                    t(open48, c.wpf(1)) + t(open48, c.wpf(2)) + t(open42, c.wpf(3)) + t(open24, c.bpf(3)));
            } else { // 14CC
                const f: i32 = t(king_file_block_centre, kf);
                c.add(t(open54, c.bpf(f - 1)) + t(open54, c.bpf(f + 1)) + t(open54, c.bpf(f)) +
                    t(open48, c.wpf(f + 1)) + t(open48, c.wpf(f - 1)) + t(open48, c.wpf(f)));
            }
        }

        // =====================================================================
        // Endgame branch 153F–1B51 ([378E] < 6200)
        // =====================================================================
        fn endgame(c: *Self) Next {
            if (c.wnp() > 700 or c.bnp() > 700) { // 153F
                // 1ABA
                if (c.p.piece_balance == 0 and count(c.p.piece_count[0]) < 3) {
                    if (onBoard(c.wl(2)) != onBoard(c.bl(3))) c.lc += 1;
                }
                return c.eg1AE2();
            }
            if (c.p.pawn_count == 0) return .return0; // 1555
            // 1562: opposite-coloured bishops
            if (onBoard(c.wl(2))) {
                if (onBoard(c.bl(2))) c.lc += 1;
            } else if (onBoard(c.wl(3)) and onBoard(c.bl(3))) c.lc += 1;
            if (c.lc != 0) return c.eg1AE2();
            c.egBlackPawns(); // 1589
            c.egWhitePawns(); // 181C
            if (c.p.piece_material_sum != 0) return c.eg1AE2(); // 1AA8
            c.add(@as(i16, @bitCast(c.p.material_balance)) >> 2); // 1AAF
            return .style;
        }

        /// 1AE2: to the pieces, or the king-distance term.
        fn eg1AE2(c: *Self) Next {
            const np = count(c.p.pawn_count);
            if (np > 4) return .pieces;
            if (np > 1 and (c.e.passed_pawns[1] | c.e.passed_pawns[0]) != 0) return .pieces;
            const bal: i16 = @bitCast(c.p.piece_balance); // 1AF9
            if (bal >= -200 and bal <= 200) return .style;
            const n: i32 = @abs(c.kfW() - c.kfB()) + @abs(c.krW() - c.krB()); // 1B0C
            if (bal > 200) c.add(tw(king_distance_eg, 2 * n)) else c.sub(tw(king_distance_eg, 2 * n));
            return .style;
        }

        /// 1589–181B: subtracts [bp-6] (200 or 300) in some endings with Black pawns.
        fn egBlackPawns(c: *Self) void {
            const wkf = c.kfW();
            const bkf = c.kfB();
            const wkr = c.krW();
            const bkr = c.krB();
            const side: i16 = @bitCast(c.side);
            const bpawns = count(c.p.side_pawn_count[1]);
            if (wkr +% side < bkr or @as(i16, @bitCast(c.p.material_balance)) >= 400 or bpawns == 0) return;
            const l6: i16 = if (bpawns > 1 or c.p.piece_material[0] == 0) 300 else 200;
            const bp = &c.p.pawns_per_file[1];
            const wp = &c.p.pawns_per_file[0];
            var step: i32 = undefined;
            var near: i32 = undefined;
            var kin: u8 = undefined;
            const first_gap: i16 = if (side != 0) 1 else 2;
            if (wkf <= 4) { // 15D3
                if (bkf <= wkf or bkf >= 8) return;
                if (c.wpf(bkf - 1) != 0) return;
                if ((bp[5] | bp[6] | bp[7] | bp[8]) == 0) return;
                if ((wp[1] | wp[2] | wp[3] | wp[4]) != 0) return;
                step = -9;
                near = -1;
                kin = bp[8];
                if (side == 0 and !(wkf + 1 < bkf)) return; // 1680
            } else { // 16FE
                if (bkf >= wkf or bkf <= 1) return;
                if (c.wpf(bkf + 1) != 0) return;
                if ((bp[1] | bp[2] | bp[3] | bp[4]) == 0) return;
                if ((wp[5] | wp[6] | wp[7] | wp[8]) != 0) return;
                step = -11;
                near = 1;
                kin = bp[1];
                if (side == 0 and !(wkf - 1 > bkf)) return; // 17A8
            }
            var di: i32 = @as(i32, c.bl(7)) + step;
            if (c.bd(di) != 0 or c.wa(di) != 0) {
                if (near < 0) {
                    if (!(wkf + first_gap < bkf)) return;
                } else {
                    if (!(wkf - first_gap > bkf)) return;
                }
                if (c.bd(di + near) == pos.black_pawn) return;
                if (c.wa(di + near) != 0) return;
            }
            // 1652
            if (c.p.side_pawn_count[1] != kin or wkr - bkr >= 2) return c.sub(l6); // 1819
            while (c.bd(di) == 0) di += step;
            if (c.bd(di) == pos.border) c.sub(l6); // 1812
        }

        /// 181C–1AA7: adds [bp-6] in some endings with White pawns.
        fn egWhitePawns(c: *Self) void {
            const wkf = c.kfW();
            const bkf = c.kfB();
            const wkr = c.krW();
            const bkr = c.krB();
            const side: i16 = @bitCast(c.side);
            const wpawns = count(c.p.side_pawn_count[0]);
            if (bkr +% side -% 1 > wkr or @as(i16, @bitCast(c.p.material_balance)) <= -400 or wpawns == 0) return;
            const l6: i16 = if (wpawns > 1 or c.p.piece_material[1] == 0) 300 else 200;
            const bp = &c.p.pawns_per_file[1];
            const wp = &c.p.pawns_per_file[0];
            var step: i32 = undefined;
            var near: i32 = undefined;
            var kin: u8 = undefined;
            if (bkf <= 4) { // 1868
                if (wkf <= bkf or wkf >= 8) return;
                if (c.bpf(wkf - 1) != 0) return;
                if ((wp[5] | wp[6] | wp[7] | wp[8]) == 0) return;
                if ((bp[1] | bp[2] | bp[3] | bp[4]) != 0) return;
                step = 11;
                near = -1;
                kin = wp[8];
                if (side != 0 and !(bkf + 1 < wkf)) return; // 1910
            } else { // 198E
                if (bkf <= wkf or wkf <= 1) return;
                if (c.bpf(wkf + 1) != 0) return;
                if ((wp[1] | wp[2] | wp[3] | wp[4]) == 0) return;
                if ((bp[5] | bp[6] | bp[7] | bp[8]) != 0) return;
                step = 9;
                near = 1;
                kin = wp[1];
                if (side != 0 and !(bkf - 1 > wkf)) return; // 1A34
            }
            const first_gap: i16 = if (side == 0) 1 else 2;
            var di: i32 = @as(i32, c.wl(7)) + step;
            if (c.bd(di) != 0 or c.ba(di) != 0) {
                if (near < 0) {
                    if (!(bkf + first_gap < wkf)) return;
                } else {
                    if (!(bkf - first_gap > wkf)) return;
                }
                if (c.bd(di + near) == pos.white_pawn) return;
                if (c.ba(di + near) != 0) return;
            }
            // 18E2
            if (c.p.side_pawn_count[0] != kin or wkr - bkr >= 2) return c.add(l6); // 1AA5
            while (c.bd(di) == 0) di += step;
            if (c.bd(di) == pos.border) c.add(l6); // 1A9E
        }

        // =====================================================================
        // Rooks 1B5C–1F89
        // =====================================================================
        fn rooks(c: *Self) void {
            const ekf = c.kfB(); // the Black king's file
            if (c.bnp() < 3100) { // 1B5C: the 7th-rank form
                for ([_]usize{ 4, 5 }) |slot| {
                    const r = c.wl(slot);
                    if (!onBoard(r)) continue;
                    const di: i32 = r;
                    c.add(80); // 1B73
                    if (di >= 81 and (c.wa(di) != 0 or (di < 91 and c.p.king_rank[1] == 9))) c.add(50);
                    const f: i32 = t(file_of, di);
                    if (c.wpf(f) != 0) continue;
                    c.add(t(if (c.bpf(f) != 0) rook_semi_eg else rook_open_eg, ekf - f));
                }
            } else {
                const high = c.wnp() >= 3550; // 1C28
                const topen: i32 = if (high) rook_open_high else rook_open_low;
                const tsemi: i32 = if (high) rook_semi_high else rook_semi_low;
                const r4 = c.wl(4);
                if (onBoard(r4)) {
                    const f: i32 = t(file_of, r4);
                    if (c.wpf(f) == 0) {
                        c.add(t(if (c.bpf(f) != 0) tsemi else topen, ekf - f));
                    } else { // 1C78: trapped by its own king
                        const kf = c.kfW();
                        if (kf < f and c.p.oo_lost_at[0] != 0 and kf >= 5 and c.p.ooo_lost_at[0] != 0 and
                            c.p.king_rank[0] == 2 and r4 <= 0x26) c.sub(c.la);
                    }
                }
                const r5 = c.wl(5);
                if (onBoard(r5)) {
                    c.add(@as(i8, @bitCast(c.e.rook_square[0][r5]))); // 1CAF
                    const f: i32 = t(file_of, r5);
                    if (c.wpf(f) == 0) {
                        c.add(t(if (c.bpf(f) != 0) tsemi else topen, ekf - f));
                    } else { // 1CEE: no castling test
                        const kf = c.kfW();
                        if (kf < 5 and kf > f and c.p.king_rank[0] == 2 and r5 <= 0x21) c.sub(c.la);
                    }
                }
            }
            c.mark(3);
            // Black rooks 1D0E
            const wkf = c.kfW();
            if (c.wnp() < 3100) {
                for ([_]usize{ 4, 5 }) |slot| {
                    const r = c.bl(slot);
                    if (!onBoard(r)) continue;
                    const di: i32 = r;
                    c.sub(80);
                    if (di <= 0x26 and (c.ba(di) != 0 or (di > 0x1C and c.p.king_rank[0] == 2))) c.sub(50);
                    const f: i32 = t(file_of, di);
                    if (c.bpf(f) != 0) continue;
                    c.sub(t(if (c.wpf(f) != 0) rook_semi_eg else rook_open_eg, wkf - f));
                }
            } else {
                const high = c.bnp() >= 3550; // 1EA4
                const topen: i32 = if (high) rook_open_high else rook_open_low;
                const tsemi: i32 = if (high) rook_semi_high else rook_semi_low;
                const r4 = c.bl(4);
                if (onBoard(r4)) {
                    const f: i32 = t(file_of, r4);
                    if (c.bpf(f) == 0) {
                        c.sub(t(if (c.wpf(f) != 0) tsemi else topen, wkf - f));
                    } else {
                        const kf = c.kfB();
                        if (kf < f and c.p.oo_lost_at[1] != 0 and kf >= 5 and c.p.ooo_lost_at[1] != 0 and
                            c.p.king_rank[1] == 9 and r4 >= 0x56) c.add(c.l8);
                    }
                }
                const r5 = c.bl(5);
                if (onBoard(r5)) {
                    c.sub(@as(i8, @bitCast(c.e.rook_square[1][r5]))); // 1F2B
                    const f: i32 = t(file_of, r5);
                    if (c.bpf(f) == 0) {
                        c.sub(t(if (c.wpf(f) != 0) tsemi else topen, wkf - f));
                    } else {
                        const kf = c.kfB();
                        if (kf < 5 and kf > f and c.p.king_rank[1] == 9 and r5 >= 0x51) c.add(c.l8);
                    }
                }
            }
        }

        // =====================================================================
        // Knights 1F8A–23DC
        // =====================================================================
        fn knights(c: *Self) void {
            c.whiteKnight(c.wl(0));
            c.mark(5);
            c.whiteKnight(c.wl(1));
            c.mark(6);
            c.blackKnight(c.bl(0));
            c.mark(7);
            c.blackKnight(c.bl(1));
        }

        fn whiteKnight(c: *Self, entry: u8) void {
            if (!onBoard(entry)) return;
            const di: i32 = entry;
            c.add(4 *% count(c.p.side_pawn_count[0])); // 1F99
            if (c.ba(di) != 0) return c.sub(12); // 1FAC
            if (di < 0x33) return; // 2072
            if (tu(minor_square_class, di) != 0) { // 207A
                const w = c.wa(di);
                if (di >= 0x47) {
                    c.add(t(outpost_164C, w));
                } else if (c.ba(di + 10) != 0) {
                    c.add(t(outpost_1640, w));
                } else if (di >= 0x3D) {
                    c.add(t(outpost_1644, w));
                } else if (c.ba(di + 20) != 0) {
                    c.add(t(outpost_1640, w));
                } else c.add(t(outpost_163C, w));
                return;
            }
            // 20D2: a- or h-file
            if (c.wa(di) != 0) return c.add(12);
            if (di == 0x58) { // h7
                if (c.ba(76) == 0) return; // f6
                if (c.ba(67) == 0) { // g5
                    if (c.side == 0 or c.bd(86) != pos.black_pawn or c.bd(76) != 0) return;
                }
                c.sub(240); // 212D
            } else if (di == 0x51) { // a7
                if (c.ba(73) == 0) return; // c6
                if (c.ba(62) == 0) { // b5
                    if (c.side == 0 or c.bd(83) != pos.black_pawn or c.bd(73) != 0) return;
                }
                c.sub(240);
            }
        }

        fn blackKnight(c: *Self, entry: u8) void {
            if (!onBoard(entry)) return;
            const di: i32 = entry;
            c.sub(4 *% count(c.p.side_pawn_count[1])); // 2224
            if (c.wa(di) != 0) return c.add(12); // 2234
            if (di > 0x44) return; // 223A
            if (tu(minor_square_class, di) != 0) { // 2242
                const b = c.ba(di);
                if (di <= 0x30) {
                    c.sub(t(outpost_164C, b));
                } else if (c.wa(di - 10) != 0) {
                    c.sub(t(outpost_1640, b));
                } else if (di <= 0x3A) {
                    c.sub(t(outpost_1644, b));
                } else if (c.wa(di - 20) != 0) {
                    c.sub(t(outpost_1640, b));
                } else c.sub(t(outpost_163C, b));
                return;
            }
            if (c.ba(di) != 0) return c.sub(12); // 229A
            if (di == 0x26) { // h2
                if (c.wa(46) == 0) return; // f3
                if (c.wa(57) == 0) { // g4
                    if (c.side != 0 or c.bd(36) != pos.white_pawn or c.bd(46) != 0) return;
                }
                c.add(240); // 22F5
            } else if (di == 0x1F) { // a2
                if (c.wa(43) == 0) return; // c3
                if (c.wa(52) == 0) { // b4
                    if (c.side != 0 or c.bd(33) != pos.white_pawn or c.bd(43) != 0) return;
                }
                c.add(240);
            }
        }

        // =====================================================================
        // Bishops 23DD–2A94
        // =====================================================================

        /// 2402 / 25CF: a White bishop on rank 5 or higher defended by pawns.
        fn wBishopDefended(c: *Self, di: i32) bool {
            if (c.wa(di) == 0) return false;
            if (tu(minor_square_class, di) == 0) c.sub(24) else c.add(t(bishop_defended, c.wa(di)));
            return true;
        }
        fn bBishopDefended(c: *Self, di: i32) bool {
            if (c.ba(di) == 0) return false;
            if (tu(minor_square_class, di) == 0) c.add(24) else c.sub(t(bishop_defended, c.ba(di)));
            return true;
        }

        fn bishops(c: *Self) void {
            const white_to_move = c.side == 0;
            const wp = count(c.p.side_pawn_count[0]);
            const bp = count(c.p.side_pawn_count[1]);
            const wdark = count(c.p.pawns_on_dark[0]);
            const bdark = count(c.p.pawns_on_dark[1]);
            // ---- White bishop slot 2 (23DD): the light-squared bishop
            var slot3 = true;
            const q2 = c.wl(2);
            if (onBoard(q2)) {
                const di: i32 = q2;
                c.sub(t(bishop_attacked, c.ba(di))); // 23EC
                if (di >= 0x3D) {
                    if (!c.wBishopDefended(di)) {
                        if (di == 0x4D) { // 2428 g6
                            if (c.bd(66) == pos.black_pawn) { // f5
                                c.sub(30);
                                if (c.ba(66) != 0) c.sub(c.bySide(70, 100));
                            }
                        } else if (di == 0x52) { // 2454 b7
                            if (c.bd(73) == pos.black_pawn and !white_to_move) c.sub(100); // c6
                        } else if (di == 0x58) { // 2472 h7
                            c.wBishopTrapped(77, 87, 0x0D56);
                        } else if (di == 0x47) { // 250E a6
                            if (c.bd(62) == pos.black_pawn) { // b5
                                c.sub(c.bySide(50, 100));
                                if (c.ba(62) != 0) c.sub(100);
                            }
                        }
                    }
                } else { // 2530
                    if (c.bd(55) == pos.white_pawn and c.bd(65) != 0 and t(file_of, di) > 3) {
                        c.sub(42);
                        if (c.bd(44) == pos.white_pawn) { // d3
                            c.sub(30);
                            if (c.bd(54) == pos.black_pawn and c.ba(54) != 0) c.sub(36); // d4
                        }
                    }
                }
                c.mark(9);
                if (!onBoard(c.wl(3))) {
                    c.add(2 *% (2 *% (wdark -% wp) -% bdark +% bp));
                    slot3 = false;
                } else c.add(36); // 2592: the bishop pair
            } else { // 2598
                if (!onBoard(c.wl(3))) {
                    slot3 = false;
                } else c.add(2 *% (bdark -% 2 *% wdark));
            }
            if (slot3) { // 25B9: White bishop slot 3, the dark-squared bishop
                const di: i32 = c.wl(3);
                c.sub(t(bishop_attacked, c.ba(di)));
                if (di >= 0x3D) {
                    if (!c.wBishopDefended(di)) {
                        if (di == 0x48) { // 25F6 b6
                            if (c.bd(63) == pos.black_pawn) { // c5
                                c.sub(30);
                                if (c.ba(63) != 0) c.sub(c.bySide(70, 100));
                            }
                        } else if (di == 0x57) { // 2622 g7
                            if (c.bd(76) == pos.black_pawn and !white_to_move) c.sub(100); // f6
                        } else if (di == 0x51) { // 2640 a7
                            c.wBishopTrapped(72, 82, 0x0D51);
                        } else if (di == 0x4E) { // 26DC h6
                            if (c.bd(67) == pos.black_pawn) { // g5
                                c.sub(c.bySide(50, 100));
                                if (c.ba(67) != 0) c.sub(100);
                            }
                        }
                    }
                } else { // 26FE
                    if (c.bd(54) == pos.white_pawn and c.bd(64) != 0 and t(file_of, di) < 6) {
                        c.sub(42);
                        if (c.bd(45) == pos.white_pawn) { // e3
                            c.sub(30);
                            if (c.bd(55) == pos.black_pawn and c.ba(55) != 0) c.sub(36); // e4
                        }
                    }
                }
            }
            c.mark(10);
            // ---- Black bishop slot 2 (2731): the dark-squared bishop
            const r2 = c.bl(2);
            var di: i32 = undefined;
            if (onBoard(r2)) {
                di = r2;
                c.add(t(bishop_attacked, c.wa(di))); // 2740
                if (di <= 0x3A) {
                    if (!c.bBishopDefended(di)) {
                        if (di == 0x2F) { // 277C g3
                            if (c.bd(56) == pos.white_pawn) { // f4
                                c.add(30);
                                if (c.wa(56) != 0) c.add(c.bySide(100, 70));
                            }
                        } else if (di == 0x20) { // 27AA b2
                            if (c.bd(43) == pos.white_pawn and white_to_move) c.add(100); // c3
                        } else if (di == 0x26) { // 27C8 h2
                            c.bBishopTrapped(47, 37, 0x0D24);
                        } else if (di == 0x29) { // 2868 a3
                            if (c.bd(52) == pos.white_pawn) { // b4
                                c.add(c.bySide(100, 50));
                                if (c.wa(52) != 0) c.add(100);
                            }
                        }
                    }
                } else { // 288C
                    if (c.bd(65) == pos.black_pawn and c.bd(55) != 0 and t(file_of, di) > 3) {
                        c.add(42);
                        if (c.bd(74) == pos.black_pawn) { // d6
                            c.add(30);
                            if (c.bd(64) == pos.white_pawn and c.wa(64) != 0) c.add(36); // d5
                        }
                    }
                }
                c.mark(11); // 28BF
                const r3 = c.bl(3);
                if (!onBoard(r3)) return c.add(2 *% (2 *% bdark -% wdark));
                c.sub(36); // 28E0: the bishop pair
                di = r3;
            } else { // 28E6
                const r3 = c.bl(3);
                if (!onBoard(r3)) return;
                c.add(2 *% (2 *% (bp -% bdark) -% wp +% wdark));
                di = r3;
            }
            // 2915: Black bishop slot 3, the light-squared bishop
            c.add(t(bishop_attacked, c.wa(di)));
            if (di <= 0x3A) {
                if (c.bBishopDefended(di)) return;
                if (di == 0x2A) { // 2952 b3
                    if (c.bd(53) == pos.white_pawn) { // c4
                        c.add(30);
                        if (c.wa(53) != 0) c.add(c.bySide(100, 70));
                    }
                } else if (di == 0x25) { // 297E g2
                    if (c.bd(46) == pos.white_pawn and white_to_move) c.add(100); // f3
                } else if (di == 0x1F) { // 299C a2
                    c.bBishopTrapped(42, 32, 0x0D1F);
                } else if (di == 0x30) { // 2A3E h3
                    if (c.bd(57) == pos.white_pawn) { // g4
                        c.add(c.bySide(100, 50));
                        if (c.wa(57) != 0) c.add(100);
                    }
                }
            } else { // 2A62
                if (c.bd(64) == pos.black_pawn and c.bd(54) != 0 and t(file_of, di) < 6) {
                    c.add(42);
                    if (c.bd(75) == pos.black_pawn) { // e6
                        c.add(30);
                        if (c.bd(65) == pos.white_pawn and c.wa(65) != 0) c.add(36); // e5
                    }
                }
            }
        }

        /// 247A (h7, with g6 = `front`, g7 = `back`, table 0D56) and 2648 (a7, with b6,
        /// b7, 0D51): a White bishop in the corner, trapped by a Black pawn.
        fn wBishopTrapped(c: *Self, front: i32, back: i32, near_king: i32) void {
            if (c.bd(front) == pos.black_pawn) {
                if (c.side != 0) c.sub(50);
                c.sub(150);
                if (c.ba(front) != 0) return c.sub(200);
                if (c.wnp() < 3350) c.sub(80);
                if (tu(near_king, -@as(i32, c.bl(7))) != 0) c.sub(120); // 24A9
                return;
            }
            if (c.bd(back) != pos.black_pawn or c.bd(front) != 0) return; // 24C0
            if (c.side != 0) { // 24D4
                c.sub(50);
                if (c.ba(front) == 0 or c.wa(front) != 0) return;
                c.sub(150);
                if (c.wnp() < 3350) c.sub(100);
                return;
            }
            if (c.ba(front) == 0 or c.wa(front) != 0) return; // 24FA
            c.sub(50);
        }

        /// 27D0 (h2, with g3, g2, table 0D24) and 29A4 (a2, with b3, b2, 0D1F).
        fn bBishopTrapped(c: *Self, front: i32, back: i32, near_king: i32) void {
            if (c.bd(front) == pos.white_pawn) {
                if (c.side == 0) c.add(50);
                c.add(150);
                if (c.wa(front) != 0) return c.add(200);
                if (c.bnp() < 3350) c.add(80);
                if (tu(near_king, -@as(i32, c.wl(7))) != 0) c.add(120);
                return;
            }
            if (c.bd(back) != pos.white_pawn or c.bd(front) != 0) return;
            if (c.side == 0) {
                c.add(50);
                if (c.wa(front) == 0 or c.ba(front) != 0) return;
                c.add(150);
                if (c.bnp() < 3350) c.add(100);
                return;
            }
            if (c.wa(front) == 0 or c.ba(front) != 0) return;
            c.add(50);
        }

        // =====================================================================
        // 2A95–2BD4: style weights, material-imbalance term, return
        // =====================================================================
        fn finish(c: *Self) i16 {
            c.mark(12);
            var si = c.si;
            const e = c.e;
            if (e.style_normal == 0 and !(e.king_placement_weight == 100 and e.mobility_weight == 100)) {
                // 2ABE: (ks·[2912] + rest·[290A]) / 100 with the run-time long multiply
                // (low 32 bits) and divide (signed, toward zero).
                const sum = (@as(i32, c.ks) *% @as(i32, @bitCast(e.king_placement_weight))) +%
                    (@as(i32, si) *% @as(i32, @bitCast(e.mobility_weight)));
                si = @truncate(@divTrunc(sum, 100));
            } else si +%= c.ks; // 2AB8
            c.si = si;
            c.mark(13);
            // 2B00: material imbalance
            const p = c.p;
            const bal: i16 = @bitCast(p.material_balance);
            const wp = count(p.side_pawn_count[0]);
            const bp = count(p.side_pawn_count[1]);
            const flag = e.ply_flag[c.ply] == 0;
            const last: i16 = @bitCast(e.last_irreversible_ply);
            const now: i16 = @bitCast(p.game_ply);
            const stage: i16 = @intCast(p.piece_material_sum >> 7); // unsigned shift
            if (bal >= 150) {
                if (flag) si +%= last -% now;
                si +%= t(imbalance_by_pawns, wp) -% stage;
                if (c.bnp() > 700) {
                    if (c.lc != 0) si -%= 60;
                } else {
                    if (c.lc != 0) si -%= 100 else if (wp > 1) si +%= 20;
                    if (p.side_pawn_count[1] == 0 and si < 0) si = 0;
                }
            } else if (bal <= -150) {
                if (flag) si +%= now -% last;
                si +%= stage -% t(imbalance_by_pawns, bp);
                if (c.wnp() > 700) {
                    if (c.lc != 0) si +%= 60;
                } else {
                    if (c.lc != 0) si +%= 100 else if (bp > 1) si -%= 20;
                    if (p.side_pawn_count[0] == 0 and si > 0) si = 0;
                }
            }
            c.si = si;
            c.mark(14);
            return si;
        }
    };
}

test {
    _ = std;
}
