//! The move generators: gen_all_moves (1E9D:3938), gen_tactical_moves (1E9D:579A),
//! gen_tactical_moves_no_losers (1E9D:25A0), gen_quiescence_moves (0EF8:9528) and
//! gen_captures (1E9D:4954).
//!
//! Specification: docs/arch/21-move-generation.md §3-§8, whose executable form is
//! tools/research/movegen/model.py (proved against the running original on every call of
//! six runs). Test: src/movegen_test.zig, which replays calls recorded from the original
//! (tests/golden/movegen/gen_*.zst).
//!
//! Every generator writes 4-byte moves (from, to, flag, score) from the start of the
//! ply's list and returns the number written, or FFFFh when the side to move can take
//! the enemy king. Entries beyond the count keep what they held. The order of the moves
//! and every score byte are part of the result: the search sorts by the score byte and
//! tries the moves in that order.
//!
//! The generators dispatch on the code found on the board under each piece-list entry,
//! not on the side to move. A captured piece's entry is its square + 63h (120 or more):
//! the original then reads a byte beyond the board (DG:9F6E..9FBB), which the recorded
//! vectors show never holds a piece code, so the port skips such entries.

const std = @import("std");
const pos = @import("position.zig");
const Position = pos.Position;
const Side = pos.Side;
const Move = pos.Move;
const see_mod = @import("see.zig");
const sortMoves = @import("sort.zig").sortMoves;
const dg = @import("original.zig").dgroup;

/// Entries in one ply's move list (DG:3A34 + 400 * ply). The original's generators do not
/// test for overflow (DEV-063): past the 100th entry they write on into the next ply's
/// list, and gen_all_moves' unscored group past DG:B296. The port writes no list past
/// 100: see `Out.room`, `Out.narrow` and `GenAll.uroom`.
pub const list_len = 100;
pub const MoveList = [list_len]Move;

/// The most entries one piece writes in any generator: a queen's 27 moves (a pawn makes
/// at most 12, a king 10 with castling).
const per_piece = 27;

/// The most moves one generator call can write: a side's 16 piece-list slots, each one
/// piece. Real positions stay far below it (218 is the most a legal position has).
pub const max_written = 16 * per_piece;

/// Size of the move-mark table at DG:781A: the row of the 78th board square (h8) is
/// 4892, and h8's farthest target, g8, is 97 beyond it.
pub const marks_len = 4990;

/// The per-search variables the generators read or write, other than the position and
/// the exchange evaluator's work areas.
pub const SearchVars = struct {
    /// DG:781A: move marks, the byte at `mark_row[from] + to`: 3 for a killer, 2 for the
    /// best quiet move (written by the search node). gen_all_moves scores a quiet move
    /// by its mark and decrements it.
    marks: [marks_len]u8 = @splat(0),
    /// DG:B106: gen_all_moves' unscored moves. A move is written as from, to, flag 0;
    /// its score byte is not written and keeps what an earlier call left there, and is
    /// copied into the list with the move.
    unscored: [list_len]Move = @splat(.{ .from = 0, .to = 0, .flag = 0, .score = 0 }),
    /// DG:725C: hint square for gen_tactical_moves' bishop (0 for none).
    bishop_hint: u8 = 0,
    /// DG:A8D8: hint square for gen_tactical_moves' rook, and the gate of
    /// gen_tactical_moves_no_losers' rook x-ray.
    rook_hint: u16 = 0,
    /// DG:A846: hint square for gen_tactical_moves' queen (0 for none).
    queen_hint: u16 = 0,
    /// DG:73F2: signed; above 0 allows quiet queen checks off the last rank (9528) and
    /// rook checks on the 7th rank (4954).
    check_flag: u8 = 0,
};

/// The switchable bug fixes of this unit (AGENTS.md §9.2). `original` reproduces the
/// original exactly and is what the differential tests use.
pub const Fixes = struct {
    /// DEV-003: gen_all_moves adds a never-written frame byte (`StrayBytes`) to the order
    /// score of a pawn capture and a king capture. Corrected: the move's mark, which
    /// the code loads just before and discards.
    dev003_stray_capture_score: bool,

    pub const original: Fixes = .{ .dev003_stray_capture_score = false };
    pub const corrected: Fixes = .{ .dev003_stray_capture_score = true };
};

/// DEV-003: the four bytes of gen_all_moves' frame that it reads and never writes
/// ([bp-19h], [bp-1Fh], [bp-21h], [bp-23h]). Their value is whatever an earlier call
/// left on the stack, which the port cannot know; for the replay of the original they
/// are an input, taken from the recorded call. Unused when the fix is on.
pub const StrayBytes = struct {
    white_pawn_capture: u8 = 0,
    white_king_capture: u8 = 0,
    black_pawn_capture: u8 = 0,
    black_king_capture: u8 = 0,
};

/// The generators' return value when the side to move can take the enemy king.
pub const king_capture: u16 = 0xFFFF;

// ---------------------------------------------------------------------------
// Constant tables, from the original's initialised data
// ---------------------------------------------------------------------------

/// DG:1A71: exchange value by piece code: empty 1, P 3, N 9, B 9, R 15, Q 27, K 0.
const see_value = dg(0x1A71, 14);
/// DG:1A44: gen_all_moves' pawn-capture score by victim: P 2, N 7, B 7, R 13, Q 25, K 0.
const pawn_capture_value = dg(0x1A44, 14);
/// DG:1A52: gen_all_moves' king-capture score by victim: P 3, N 8, B 8, R 14, Q 26, K 0.
const king_capture_value = dg(0x1A52, 14);
/// DG:1A60: gen_all_moves' slot order: pawns of files d, c, e, f, b, g, a, h, then
/// bishops, knights, queen, rooks, king.
const slot_order = dg(0x1A60, 16);
/// DG:1A80: a word per square, the row of the mark table for a from-square
/// (78k - 22 for the k-th board square).
const mark_row: [120]i16 = blk: {
    const raw = dg(0x1A80, 240);
    var t: [120]i16 = undefined;
    for (&t, 0..) |*w, i| w.* = @bitCast(@as(u16, raw[2 * i]) | @as(u16, raw[2 * i + 1]) << 8);
    break :blk t;
};
/// DG:04A2: pawn steps 9, 11, 10, 20 (White adds them, Black subtracts).
const pawn_steps: [4]i8 = @bitCast(dg(0x04A2, 4));
/// DG:04A6: rook steps -1, +1, -10, +10 (read from index 3 down).
const rook_steps: [4]i8 = @bitCast(dg(0x04A6, 4));
/// DG:04AA: queen steps -9, -11, +1, -1, -10, +10, +9, +11 (read from index 7 down;
/// Black negates each).
const queen_steps: [8]i8 = @bitCast(dg(0x04AA, 8));
/// DG:1508: knight steps 8, 12, -8, -12, 19, 21, -19, -21 (read from index 7 down).
const knight_steps: [8]i8 = @bitCast(dg(0x1508, 8));
/// DG:1510: king and bishop steps 9, 11, -9, -11, 1, 10, -1, -10 (kings 7 down,
/// bishops 3 down).
const king_steps: [8]i8 = @bitCast(dg(0x1510, 8));
/// DG:28CC: 1 for the White codes 1..6.
const is_white_code = dg(0x28CC, 14);
/// DG:28E8: 1 for empty and the Black codes 8..13.
const is_empty_or_black = dg(0x28E8, 14);
/// DG:0A68 + d and DG:0CFF + d, d = -255..119 (index d + 255): non-zero when d is a
/// knight step, a king step. Read for d = to - (enemy king), which stays inside the
/// tables' own range for board squares.
const knight_reach = dg(0x0A68 - 255, 375);
const king_reach = dg(0x0CFF - 255, 375);
/// DG:0B66 + d, d = -255..119: the diagonal direction from a square d away
/// (gen_tactical_moves' bishop hint, d = to - hint for any hint byte).
const diagonal_reach = dg(0x0B66 - 255, 375);
/// DG:0E16: 1 on dark squares, indexed by any byte (the bishop hint).
const dark_square = dg(0x0E16, 256);
/// DG:0490, DG:047E, DG:0470: direction code to step and to slider bit; piece code to
/// slider bits.
const dir_step: [17]i8 = @bitCast(dg(0x0490, 17));
const dir_bit = dg(0x047E, 17);
const slider_bits = dg(0x0470, 14);

/// Index in `SearchVars.marks` of the mark of the move (from, to): DG:781A +
/// [1A80 + 2 * from] + to.
pub fn markIndex(from: usize, to: usize) usize {
    return @intCast(@as(i32, mark_row[from]) + @as(i32, @intCast(to)));
}

inline fn reach(table: *const [375]u8, to: usize, from: usize) u8 {
    return table[to + 255 - from];
}

inline fn add(sq: usize, d: i32) usize {
    return @intCast(@as(i32, @intCast(sq)) + d);
}

inline fn u8sq(sq: usize) u8 {
    return @intCast(sq);
}

const KingCapture = error{KingCapture};

/// The colour-dependent codes of a piece's own side.
fn Colour(comptime white: bool) type {
    return struct {
        const side: Side = if (white) .white else .black;
        const us: usize = if (white) 0 else 1;
        const them: usize = 1 - us;
        const pawn: u8 = if (white) pos.white_pawn else pos.black_pawn;
        const knight: u8 = if (white) pos.white_knight else pos.black_knight;
        const bishop: u8 = if (white) pos.white_bishop else pos.black_bishop;
        const rook: u8 = if (white) pos.white_rook else pos.black_rook;
        const queen: u8 = if (white) pos.white_queen else pos.black_queen;
        const king: u8 = if (white) pos.white_king else pos.black_king;
        const enemy_pawn: u8 = if (white) pos.black_pawn else pos.white_pawn;
        const enemy_king: u8 = if (white) pos.black_king else pos.white_king;

        /// A capture target: White takes codes above 7, Black codes below 7 (the
        /// caller has excluded empty squares).
        inline fn enemy(t: u8) bool {
            return if (white) t > 7 else t < 7;
        }
    };
}

/// The output list and the objects every generator works on.
const Out = struct {
    p: *Position,
    s: *see_mod.Scratch,
    v: *SearchVars,
    /// The king rule of gen_tactical_moves (byte 39AE; 0 for the other generators): the
    /// value of `EvalVars.black_king_by_passer`, its home, which static_eval writes.
    king_rule: u8 = 0,
    list: *MoveList,
    n: usize = 0,
    /// DEV-058 (`pos.Fixes.dev058_lifted_knight_entry`): the exchange evaluator skips a
    /// knight whose list entry is 0 (the lift of `seeEntry` in 579A, 25A0, 9528).
    dev058: bool = false,
    /// DEV-063: where `add` writes: the list, or `wide` once `room` has found that the
    /// next piece could take the count past 100. The original writes on past the list's
    /// 100th entry, into the next ply's list (DG:3A34 + 400 * (ply + 1)), where its sort
    /// reads them; here they go to `wide` and never reach past the list.
    out: [*]Move,
    wide: *[max_written]Move,
    widened: bool = false,
    /// The count above which the next piece could pass 100 (none once widened).
    limit: usize = list_len - per_piece,

    inline fn add(o: *Out, from: usize, to: usize, flag: u8, score: u8) void {
        // `room` keeps this true; checked in the safe builds, compiled out in ReleaseFast.
        if (std.debug.runtime_safety) std.debug.assert(o.n < @as(usize, if (o.widened) max_written else list_len));
        o.out[o.n] = .{ .from = u8sq(from), .to = u8sq(to), .flag = flag, .score = score };
        o.n += 1;
    }

    /// DEV-063, before each piece's moves (a piece writes at most `per_piece`): once the
    /// list could overflow, the moves so far move to `wide` and every later one goes
    /// there. One test a piece, none a move.
    inline fn room(o: *Out) void {
        if (o.n > o.limit) o.widen();
    }

    noinline fn widen(o: *Out) void {
        @branchHint(.cold);
        @memcpy(o.wide[0..o.n], o.list[0..o.n]);
        o.out = o.wide;
        o.widened = true;
        o.limit = std.math.maxInt(usize);
    }

    /// DEV-063, at the end of a call that widened: back into the list. Up to 100 moves
    /// as written. More than 100: the first 100 of all of them after sort_moves
    /// (0000:65BC) over all of them, which is what the original's sort leaves in its 100
    /// entries: gen_all_moves' own sort of its scored group (1E9D:48F1), or the node's
    /// sort of a quiescence list (0000:4BBC, 6142), which the node makes whenever the
    /// count is above 1 and which leaves a sorted list as it is; the count becomes 100.
    /// The original goes on with the moves past the 100th, read from the next ply's list
    /// after the child nodes have generated into it; the port drops them. True when the
    /// list was cut (and so is sorted).
    noinline fn narrow(o: *Out) bool {
        @branchHint(.cold);
        if (o.n <= list_len) {
            @memcpy(o.list[0..o.n], o.wide[0..o.n]);
            return false;
        }
        sortMoves(o.wide[0..o.n], @intCast(o.n));
        @memcpy(o.list, o.wide[0..list_len]);
        o.n = list_len;
        return true;
    }

    inline fn board(o: *const Out, sq: usize) u8 {
        return o.p.board[sq];
    }

    /// The exchange value (a signed byte, sign-extended) of the side `white` capturing
    /// on `to` with a piece worth `value`.
    inline fn see(o: *Out, comptime white: bool, to: usize, value: u16) i16 {
        const side: Side = if (white) .white else .black;
        if (o.dev058) return @bitCast(see_mod.seeFixes(dev058_only, o.p, o.s, side, u8sq(to), value));
        return @bitCast(see_mod.see(o.p, o.s, side, u8sq(to), value));
    }

    /// The same with the piece on `from` lifted off the board during the call.
    inline fn seeLifted(o: *Out, comptime white: bool, from: usize, to: usize, value: u16) i16 {
        const piece = o.p.board[from];
        o.p.board[from] = pos.empty;
        const r = o.see(white, to, value);
        o.p.board[from] = piece;
        return r;
    }

    /// The same with the knight's piece-list entry `entry` set to `during` for the call.
    inline fn seeEntry(o: *Out, comptime white: bool, entry: usize, during: u8, to: usize, value: u16) i16 {
        const kept = o.p.piece_list[entry];
        o.p.piece_list[entry] = during;
        const r = o.see(white, to, value);
        o.p.piece_list[entry] = kept;
        return r;
    }
};

/// The switch of DEV-058 alone, for `Out.see` (no other switch reads the evaluator).
const dev058_only: pos.Fixes = blk: {
    var f = pos.Fixes.original;
    f.dev058_lifted_knight_entry = true;
    break :blk f;
};

inline fn lowByte(x: i16) u8 {
    return @truncate(@as(u16, @bitCast(x)));
}

// ---------------------------------------------------------------------------
// Castling square tests: 1E9D:388C / 37E0 (and their copies 6A69 / 69F6 in 579A and
// 33A3 / 3330 in 25A0, the same logic)
// ---------------------------------------------------------------------------

/// Port of castle_square_attacked_by_black (1E9D:388C) for `white`, and of its mirror
/// castle_square_attacked_by_white (1E9D:37E0). Looking only away from the castling
/// side's back rank: the first piece along the file is an enemy rook or queen; the first
/// piece on either forward diagonal an enemy queen or bishop; an enemy knight on one of
/// four forward knight squares; an enemy pawn attacks the square; or the enemy king is
/// on one of the two forward diagonal neighbours. Nothing along the rank is looked at.
fn castleSquareAttacked(p: *const Position, comptime white: bool, s: usize) bool {
    const f: i32 = if (white) 1 else -1;
    const E = Colour(!white);
    var q = add(s, 10 * f);
    while (p.board[q] == pos.empty) q = add(q, 10 * f);
    if (p.board[q] == E.rook or p.board[q] == E.queen) return true;
    for ([2]i32{ 9, 11 }) |d| {
        q = add(s, d * f);
        while (p.board[q] == pos.empty) q = add(q, d * f);
        if (p.board[q] == E.queen or p.board[q] == E.bishop) return true;
    }
    for ([4]i32{ 19, 21, 8, 12 }) |d| {
        if (p.board[add(s, d * f)] == E.knight) return true;
    }
    if (p.pawn_attacks[E.us][s] != 0) return true;
    return p.board[add(s, 9 * f)] == E.king or p.board[add(s, 11 * f)] == E.king;
}

/// The castling moves of `white` that pass the original's tests: the right is held,
/// the squares between king and rook are empty, no enemy pawn attacks g1 / c1 (g8 /
/// c8), the rook stands in its corner and `castleSquareAttacked` clears f1 / d1 (f8 /
/// d8). The king's own square is not tested. Returns the target squares, O-O first;
/// 0 for a castling not allowed.
fn castling(p: *const Position, comptime white: bool) [2]usize {
    const C = Colour(white);
    const E = Colour(!white);
    const r: usize = if (white) 0 else 70; // back rank offset
    var out: [2]usize = .{ 0, 0 };
    if (p.oo_lost_at[C.us] == 0 and p.board[r + 26] == pos.empty and p.board[r + 27] == pos.empty and
        p.pawn_attacks[E.us][r + 27] == 0 and p.board[r + 28] == C.rook and
        !castleSquareAttacked(p, white, r + 26))
    {
        out[0] = r + 27;
    }
    if (p.ooo_lost_at[C.us] == 0 and p.board[r + 24] == pos.empty and p.board[r + 23] == pos.empty and
        p.board[r + 22] == pos.empty and p.pawn_attacks[E.us][r + 23] == 0 and p.board[r + 21] == C.rook and
        !castleSquareAttacked(p, white, r + 24))
    {
        out[1] = r + 23;
    }
    return out;
}

/// The king's square of the castling moves: written as the constant e1 / e8.
fn castleFrom(comptime white: bool) usize {
    return if (white) 0x19 else 0x5F;
}

// ---------------------------------------------------------------------------
// gen_all_moves, 1E9D:3938
// ---------------------------------------------------------------------------

/// `dev007` and `dev008` are the switches of `pos.Fixes` this generator reads
/// (`genAllMovesFixes`).
fn GenAll(comptime fixes: Fixes, comptime dev007: bool, comptime dev008: bool) type {
    return struct {
        const Self = @This();

        o: Out,
        /// Unscored moves written to `SearchVars.unscored` (DG:B106).
        q: usize = 0,
        /// The en-passant square of the ply ([9EC8 + ply]).
        ep: u8,
        stray: StrayBytes,
        /// DEV-063: where `addUnscored` writes: `SearchVars.unscored`, or `uwide` once
        /// `uroom` has found that the next piece could take the group past 100. The
        /// original writes every unscored move (1E9D:3938..48D7, DG:B106 on) and copies at
        /// most 100 of them; one past the 100th is never copied, and past the 200th it
        /// lies over the castling stamps and the variables after them (DG:B426 on). Here
        /// they go to `uwide`, and only the first 100 come back (`finish`).
        uout: [*]Move,
        uwide: *[max_written]Move,
        uwidened: bool = false,
        /// The total of both groups above which the next piece could take either past 100.
        limit: usize = list_len - per_piece,

        fn mark(g: *const Self, from: usize, to: usize) u8 {
            return g.o.v.marks[markIndex(from, to)];
        }

        /// An unscored move: from, to and flag 0; the score byte is not written.
        fn addUnscored(g: *Self, from: usize, to: usize) void {
            if (std.debug.runtime_safety) std.debug.assert(g.q < @as(usize, if (g.uwidened) max_written else list_len));
            const e = &g.uout[g.q];
            e.from = u8sq(from);
            e.to = u8sq(to);
            e.flag = pos.flag_normal;
            g.q += 1;
        }

        /// DEV-063, before each piece (see `Out.room`): one test of both groups together;
        /// both are widened when it fails. `uwide` starts as a copy of all 100 entries, so
        /// that the score bytes the original keeps come back unchanged.
        inline fn uroom(g: *Self) void {
            if (g.o.n + g.q > g.limit) g.uwiden();
        }

        noinline fn uwiden(g: *Self) void {
            @branchHint(.cold);
            if (!g.o.widened) g.o.widen();
            @memcpy(g.uwide[0..list_len], &g.o.v.unscored);
            g.uout = g.uwide;
            g.uwidened = true;
            g.limit = std.math.maxInt(usize);
        }

        /// A quiet move: with a non-zero mark, into the list with the mark as its score,
        /// and the mark is decremented; else into the unscored group.
        fn addMarkedOrUnscored(g: *Self, from: usize, to: usize) void {
            if (!g.addMarked(from, to)) g.addUnscored(from, to);
        }

        fn addMarked(g: *Self, from: usize, to: usize) bool {
            const m = &g.o.v.marks[markIndex(from, to)];
            if (m.* == 0) return false;
            g.o.add(from, to, pos.flag_normal, m.*);
            m.* -%= 1;
            return true;
        }

        /// The extra term of a pawn or king capture's score (DEV-003).
        fn captureExtra(g: *const Self, from: usize, to: usize, stray: u8) u8 {
            return if (fixes.dev003_stray_capture_score) g.mark(from, to) else stray;
        }

        fn run(g: *Self, side: Side) KingCapture!void {
            const base: usize = 16 * @as(usize, @backingInt(side));
            for (slot_order) |slot| {
                const entry = base + slot;
                const from: usize = g.o.p.piece_list[entry];
                if (from >= 120) continue; // a captured piece (see the file comment)
                g.uroom();
                switch (g.o.p.board[from]) {
                    pos.white_pawn => g.pawn(true, from),
                    pos.black_pawn => g.pawn(false, from),
                    pos.white_knight => try g.knight(true, from, entry),
                    pos.black_knight => try g.knight(false, from, entry),
                    pos.white_bishop => try g.bishop(true, from),
                    pos.black_bishop => try g.bishop(false, from),
                    pos.white_rook => try g.rook(true, from),
                    pos.black_rook => try g.rook(false, from),
                    pos.white_queen => try g.queen(true, from),
                    pos.black_queen => try g.queen(false, from),
                    pos.white_king => try g.king(true, from),
                    pos.black_king => try g.king(false, from),
                    else => {},
                }
            }
        }

        /// White pawn 39C6, Black pawn 40FC.
        fn pawn(g: *Self, comptime white: bool, from: usize) void {
            const f: i32 = if (white) 1 else -1;
            const C = Colour(white);
            const b = &g.o.p.board;
            for (pawn_steps[0..2]) |d| {
                const to = add(from, f * d);
                const t = b[to];
                const hit = if (white) t > 7 else is_white_code[t] != 0;
                if (hit) {
                    if (if (white) to >= 0x5B else to <= 0x1C) {
                        g.o.add(from, to, 5, 0x16);
                        g.o.add(from, to, 2, 9);
                        g.o.add(from, to, 4, 0);
                        g.o.add(from, to, 3, 0);
                    } else {
                        const stray = if (white) g.stray.white_pawn_capture else g.stray.black_pawn_capture;
                        g.o.add(from, to, pos.flag_normal, pawn_capture_value[t] +% g.captureExtra(from, to, stray));
                    }
                } else if (g.ep == to) {
                    g.o.add(from, to, pos.flag_en_passant, 4);
                }
            }
            for (pawn_steps[2..4]) |d| {
                const to = add(from, f * d);
                if (b[to] != pos.empty) return;
                if (if (white) to >= 0x5B else to <= 0x1C) {
                    g.o.add(from, to, 5, 0x12);
                    g.o.add(from, to, 2, 4);
                    g.o.add(from, to, 4, 0);
                    g.o.add(from, to, 3, 0);
                    return;
                }
                if (!g.addMarked(from, to)) {
                    // Score 1 when the push attacks a piece from a square an own pawn
                    // defends (White 3AC2). DEV-007: Black's code (1E9D:4200-4223) gates
                    // only the -9 target on the defence: its "not defended" exit at 4207
                    // jumps to the -11 test (4217), not past it (4234), so the -11
                    // target counts whether or not `to` is defended
                    // (docs/arch/21-move-generation.md, suspected bug 2). Corrected
                    // (`dev007_black_pawn_push`): White's mirror, the defence gating
                    // both targets. A push the correction no longer scores goes to the
                    // unscored group, as White's does.
                    const threat = if (white)
                        g.o.p.pawn_attacks[C.us][to] != 0 and (b[to + 9] >= 9 or b[to + 11] >= 9)
                    else if (dev007)
                        g.o.p.pawn_attacks[C.us][to] != 0 and (isWhitePiece(b[to - 9]) or isWhitePiece(b[to - 11]))
                    else
                        (g.o.p.pawn_attacks[C.us][to] != 0 and isWhitePiece(b[to - 9])) or isWhitePiece(b[to - 11]);
                    if (threat) g.o.add(from, to, pos.flag_normal, 1) else g.addUnscored(from, to);
                }
                // The double push only from a single push to the 3rd (6th) rank.
                if (if (white) to > 0x30 else to < 0x47) return;
            }
        }

        /// Knight 3AFE (White), 42DA (Black).
        fn knight(g: *Self, comptime white: bool, from: usize, entry: usize) KingCapture!void {
            const C = Colour(white);
            var k: usize = 8;
            while (k > 0) {
                k -= 1;
                const to = add(from, knight_steps[k]);
                const t = g.o.board(to);
                if (t == pos.empty) {
                    g.addMarkedOrUnscored(from, to);
                    continue;
                }
                if (!C.enemy(t)) continue;
                if (t == C.enemy_king) return error.KingCapture;
                // The knight's list entry is FFh during the exchange call.
                const v = g.o.seeEntry(white, entry, 0xFF, to, 9);
                if (v < 0) {
                    g.addUnscored(from, to);
                } else {
                    g.o.add(from, to, pos.flag_normal, g.mark(from, to) +% lowByte(v) +% 3);
                }
            }
        }

        /// The sliders' common body: empty squares by the mark rule (the queen tries an
        /// empty square on the enemy king's rays with the exchange evaluator instead),
        /// then a capture scored mark + SEE + bonus (+ king adjacency for the queen); a
        /// capture or queen check that loses goes to the unscored group.
        fn slider(g: *Self, comptime white: bool, from: usize, dirs: []const i8, comptime value: u16, comptime bonus: u8, comptime is_queen: bool) void {
            const C = Colour(white);
            const emap = &g.o.p.king_rays[C.them];
            const eking: usize = g.o.p.piece_list[16 * C.them + 7];
            for (dirs) |d| {
                var to = add(from, d);
                while (g.o.board(to) == pos.empty) : (to = add(to, d)) {
                    if (is_queen and emap[to] != 0) {
                        const v = g.o.seeLifted(white, from, to, value);
                        if (v < 0) {
                            g.addUnscored(from, to);
                        } else {
                            g.o.add(from, to, pos.flag_normal, g.mark(from, to) +% reach(&king_reach, to, eking) +% 2);
                        }
                    } else {
                        g.addMarkedOrUnscored(from, to);
                    }
                }
                if (!C.enemy(g.o.board(to))) continue;
                const v = g.o.seeLifted(white, from, to, value);
                if (v < 0) {
                    g.addUnscored(from, to);
                } else {
                    var sc = g.mark(from, to) +% lowByte(v) +% bonus;
                    if (is_queen) sc +%= reach(&king_reach, to, eking);
                    g.o.add(from, to, pos.flag_normal, sc);
                }
            }
        }

        /// Bishop 3BE6 (White), 43BC (Black): FFFFh when it stands on a diagonal ray
        /// of the enemy king.
        fn bishop(g: *Self, comptime white: bool, from: usize) KingCapture!void {
            const C = Colour(white);
            const code = g.o.p.king_rays[C.them][from];
            if (if (white) code >= 9 and code <= 0x0C else code >= 1 and code <= 4) return error.KingCapture;
            const dirs = [4]i8{ king_steps[3], king_steps[2], king_steps[1], king_steps[0] };
            g.slider(white, from, &dirs, 9, 3, false);
        }

        /// Rook 3CFE (White), 44D4 (Black): FFFFh on a rank or file ray of the enemy
        /// king (signed tests).
        fn rook(g: *Self, comptime white: bool, from: usize) KingCapture!void {
            const C = Colour(white);
            const code: i8 = @bitCast(g.o.p.king_rays[C.them][from]);
            if (code >= (if (white) 0x0D else 5)) return error.KingCapture;
            const dirs = [4]i8{ rook_steps[3], rook_steps[2], rook_steps[1], rook_steps[0] };
            g.slider(white, from, &dirs, 15, 2, false);
        }

        /// Queen 3E0E (White), 45E6 (Black): FFFFh on any ray of the enemy king.
        fn queen(g: *Self, comptime white: bool, from: usize) KingCapture!void {
            const C = Colour(white);
            if (g.o.p.king_rays[C.them][from] != 0) return error.KingCapture;
            var dirs: [8]i8 = undefined;
            for (&dirs, 0..) |*d, i| d.* = king_steps[7 - i];
            g.slider(white, from, &dirs, 27, 2, true);
        }

        /// King 3F8E (White), 4766 (Black), then castling.
        fn king(g: *Self, comptime white: bool, from: usize) KingCapture!void {
            const C = Colour(white);
            const E = Colour(!white);
            const enemy_pawns = &g.o.p.pawn_attacks[E.us];
            var k: usize = 8;
            while (k > 0) {
                k -= 1;
                const to = add(from, king_steps[k]);
                const t = g.o.board(to);
                if (t == pos.empty) {
                    if (enemy_pawns[to] != 0) continue;
                    g.addMarkedOrUnscored(from, to);
                    continue;
                }
                if (!C.enemy(t)) continue;
                if (t == C.enemy_king) return error.KingCapture;
                if (enemy_pawns[to] != 0) continue;
                const stray = if (white) g.stray.white_king_capture else g.stray.black_king_capture;
                g.o.add(from, to, pos.flag_normal, king_capture_value[t] +% g.captureExtra(from, to, stray));
            }
            // DEV-008 (1E9D:4088, 40ED White; 485F, 48C4 Black): castling is scored with
            // the mark of the king's step to from + 9, the register the loop above left
            // behind, plus 3, not with its own mark (suspected bug 3). For White that is
            // the mark of e1-d2, read after the loop may have decremented it; for Black,
            // e8 + 9 lies off the board and the byte read is the mark of f8-f1. Corrected
            // (`dev008_castling_mark`): the castling move's own mark, the byte the node
            // sets to 3 for a killer and 2 for a best move. In both forms the mark is
            // read, not decremented, as for the generator's captures.
            for (castling(g.o.p, white)) |to| {
                if (to == 0) continue;
                const m = if (dev008) g.mark(castleFrom(white), to) else g.mark(from, from + 9);
                g.o.add(castleFrom(white), to, pos.flag_castle, m +% 3);
            }
        }

        /// The end (48D8): sort the scored group, append the unscored group behind it
        /// (capped at 100 entries in all, 48F9..4913), return the total. A scored group
        /// of more than 100 (DEV-063): the original sorts it whole, then its cap goes
        /// negative and the copy count wraps (a copy of about 64 KB over its own data
        /// segment); the port keeps the first 100 of the sorted group, copies nothing and
        /// returns 100, the original's AX ((100 - n1) + n1).
        fn finish(g: *Self) u16 {
            const cut = g.o.widened and g.o.narrow();
            const n1 = g.o.n;
            if (!cut and n1 > 1) sortMoves(g.o.list[0..n1], @intCast(n1));
            if (g.uwidened) g.unarrow();
            const n2 = @min(g.q, list_len - n1);
            @memcpy(g.o.list[n1..][0..n2], g.o.v.unscored[0..n2]);
            return @intCast(n1 + n2);
        }

        /// DEV-063: the first 100 unscored entries back into `SearchVars.unscored`.
        noinline fn unarrow(g: *Self) void {
            @branchHint(.cold);
            @memcpy(&g.o.v.unscored, g.uwide[0..list_len]);
        }

        /// A piece can take the enemy king: the moves written so far stay written, as in
        /// the original, as far as the list and the unscored group hold them.
        fn kingCapture(g: *Self) u16 {
            if (g.o.widened) {
                @branchHint(.cold);
                const n = @min(g.o.n, list_len);
                @memcpy(g.o.list[0..n], g.o.wide[0..n]);
            }
            if (g.uwidened) g.unarrow();
            return king_capture;
        }
    };
}

/// Port of gen_all_moves (1E9D:3938-4932, castling helpers 388C and 37E0): every
/// pseudo-legal move of `side` (the side whose piece list is walked), used for
/// ply <= H. Quiet moves with a mark and captures that do not lose are scored and sorted
/// (by `sortMoves`, descending); the rest follow unsorted, in the order generated, with
/// whatever score byte `SearchVars.unscored` held. Returns the count, or FFFFh if a
/// piece can take the enemy king (the moves written until then stay written).
///
/// `stray` is DEV-003's input: ignored when `fixes.dev003_stray_capture_score` is on.
/// The class C fixes of `pos.Fixes` are all off here: `genAllMovesFixes` takes them.
pub fn genAllMoves(
    comptime fixes: Fixes,
    p: *Position,
    s: *see_mod.Scratch,
    v: *SearchVars,
    list: *MoveList,
    side: Side,
    ply: usize,
    stray: StrayBytes,
) u16 {
    return genAllMovesFixes(fixes, pos.Fixes.original, p, s, v, list, side, ply, stray);
}

/// `genAllMoves` with the class C fixes of `pfixes` that touch it:
/// `dev007_black_pawn_push` (DEV-007) and `dev008_castling_mark` (DEV-008). Each changes
/// a move's order score only, never which moves are generated. With
/// `pos.Fixes.original` this is `genAllMoves`.
pub fn genAllMovesFixes(
    comptime fixes: Fixes,
    comptime pfixes: pos.Fixes,
    p: *Position,
    s: *see_mod.Scratch,
    v: *SearchVars,
    list: *MoveList,
    side: Side,
    ply: usize,
    stray: StrayBytes,
) u16 {
    var wide: [max_written]Move = undefined;
    var uwide: [max_written]Move = undefined;
    var g: GenAll(fixes, pfixes.dev007_black_pawn_push, pfixes.dev008_castling_mark) = .{
        .o = .{ .p = p, .s = s, .v = v, .list = list, .out = list, .wide = &wide },
        .ep = p.ep_square_by_ply[ply],
        .stray = stray,
        .uout = &v.unscored,
        .uwide = &uwide,
    };
    g.run(side) catch return g.kingCapture();
    return g.finish();
}

// ---------------------------------------------------------------------------
// The quiescence generators: 579A, 25A0, 9528, 4954
// ---------------------------------------------------------------------------

/// The state of one quiescence generator call and the helpers the four share.
const Q = struct {
    o: Out,
    /// The en-passant square of the ply ([9EC8 + ply]).
    ep: u8,

    /// The enemy king's ray map, as seen by a piece of colour `white`.
    inline fn emap(q: *Q, comptime white: bool) *[120]u8 {
        return &q.o.p.king_rays[Colour(white).them];
    }

    /// The enemy's piece-list entry `slot`.
    inline fn enemyEntry(q: *const Q, comptime white: bool, slot: usize) usize {
        return q.o.p.piece_list[16 * Colour(white).them + slot];
    }

    inline fn enemyKing(q: *const Q, comptime white: bool) usize {
        return q.enemyEntry(white, 7);
    }

    /// The square is on the enemy's last rank (White >= 5Bh, Black <= 1Ch).
    inline fn lastRank(comptime white: bool, to: usize) bool {
        return if (white) to >= 0x5B else to <= 0x1C;
    }

    /// The square is on the enemy's last two ranks (White >= 51h, Black <= 26h).
    inline fn lastTwoRanks(comptime white: bool, to: usize) bool {
        return if (white) to >= 0x51 else to <= 0x26;
    }

    /// The square is on the mover's own first two ranks (White < 29h, Black > 4Eh).
    inline fn ownBack(comptime white: bool, to: usize) bool {
        return if (white) to < 0x29 else to > 0x4E;
    }

    inline fn s8(x: u8) i8 {
        return @bitCast(x);
    }

    /// The piece on s stands on a ray of the enemy king (map code non-zero): walk on
    /// from s along that ray to the first piece; true if its slider bits meet `bits`
    /// (the ray's own bit, DG:047E, when null).
    fn discovers(q: *Q, comptime white: bool, s: usize, bits: ?u8) bool {
        const code = q.emap(white)[s];
        const step = dir_step[code];
        var p = add(s, step);
        while (q.o.board(p) == pos.empty) p = add(p, step);
        return slider_bits[q.o.board(p)] & (bits orelse dir_bit[code]) != 0;
    }

    /// Write `value` into the enemy king's map on the empty squares beyond sq along
    /// the direction `code`.
    fn markRay(q: *Q, comptime white: bool, sq: usize, code: u8, value: u8) void {
        const step = dir_step[code];
        const m = q.emap(white);
        var b = add(sq, step);
        while (q.o.board(b) == pos.empty) : (b = add(b, step)) m[b] = value;
    }

    /// Every move of a slider that uncovers a check: quiet ones scored `quiet`,
    /// captures `capture` (no exchange test, no king test).
    fn allSliderMoves(q: *Q, comptime white: bool, from: usize, dirs: []const i8, quiet: u8, capture: u8) void {
        for (dirs) |d| {
            var to = add(from, d);
            while (q.o.board(to) == pos.empty) : (to = add(to, d)) q.o.add(from, to, pos.flag_normal, quiet);
            if (Colour(white).enemy(q.o.board(to))) q.o.add(from, to, pos.flag_normal, capture);
        }
    }

    /// A pawn push that may uncover a check (579A and 25A0): the square behind `to` is
    /// on an enemy ray not along the file, and the first piece met walking along that
    /// ray **from the pawn's square** slides that way.
    fn pushUncovers(q: *Q, comptime white: bool, from: usize, to: usize) bool {
        const f: i32 = if (white) 1 else -1;
        const code = q.emap(white)[add(to, -10 * f)];
        if (code == 0) return false;
        if (if (white) code == 0x0E or code == 0x10 else code == 6 or code == 8) return false;
        const step = dir_step[code];
        var p = add(from, step);
        while (q.o.board(p) == pos.empty) p = add(p, step);
        return dir_bit[code] & slider_bits[q.o.board(p)] != 0;
    }

    const Xray = struct { sq: usize = 0, code: u8 = 0 };

    /// The x-ray of 579A's bishop: the first of the enemy queen and rooks (slots 6, 5,
    /// 4) that stands on a diagonal of its own king gets the empty squares beyond it
    /// marked 9 (Black's bishops: 1). Returns what to unmark (code 0: nothing).
    fn bishopXray(q: *Q, comptime white: bool) Xray {
        const m = q.emap(white);
        for ([3]usize{ 6, 5, 4 }) |slot| {
            const s = q.enemyEntry(white, slot);
            // A captured piece (entry >= 120) is off the map: the vector tool checks
            // that the bytes the original reads there never pass these tests.
            if (s >= 120) continue;
            const v = s8(m[s]);
            if (if (white) v >= 9 else v != 0) {
                if (if (white) v < 0x0D else v < 5) {
                    const code = m[s];
                    q.markRay(white, s, code, if (white) 9 else 1);
                    return .{ .sq = s, .code = code };
                }
            }
        }
        return .{};
    }

    /// The x-ray of the rooks (579A, and 25A0 when the rook hint is set): the enemy
    /// queen on a rank or file of its own king gets the empty squares beyond it marked
    /// 0Dh (Black's rooks: 5).
    fn rookXray(q: *Q, comptime white: bool) Xray {
        const m = q.emap(white);
        const s = q.enemyEntry(white, 6);
        if (s >= 120) return .{}; // as in bishopXray
        if (onLine(white, m[s])) {
            const code = m[s];
            q.markRay(white, s, code, if (white) 0x0D else 5);
            return .{ .sq = s, .code = code };
        }
        return .{};
    }

    /// The x-ray marks are cleared to 0, not restored (suspected bug 4).
    fn unmark(q: *Q, comptime white: bool, x: Xray) void {
        if (x.code != 0) q.markRay(white, x.sq, x.code, 0);
    }

    /// The slot loop of every quiescence generator (579A 69B4, 25A0 2F66, 9528 9732,
    /// 4954 4B56): slots 0..15 of the side's list, dispatched on the code found on the
    /// board.
    fn run(q: *Q, comptime G: type, side: Side) KingCapture!void {
        const base: usize = 16 * @as(usize, @backingInt(side));
        for (0..16) |slot| {
            const from: usize = q.o.p.piece_list[base + slot];
            if (from >= 120) continue; // a captured piece (see the file comment)
            q.o.room();
            switch (q.o.p.board[from]) {
                pos.white_pawn => G.pawn(q, true, from),
                pos.black_pawn => G.pawn(q, false, from),
                pos.white_knight => try G.knight(q, true, from, slot),
                pos.black_knight => try G.knight(q, false, from, slot),
                pos.white_bishop => try G.bishop(q, true, from),
                pos.black_bishop => try G.bishop(q, false, from),
                pos.white_rook => try G.rook(q, true, from),
                pos.black_rook => try G.rook(q, false, from),
                pos.white_queen => try G.queen(q, true, from),
                pos.black_queen => try G.queen(q, false, from),
                pos.white_king => try G.king(q, true, from),
                pos.black_king => try G.king(q, false, from),
                else => {},
            }
        }
    }

    fn generate(comptime G: type, p: *Position, s: *see_mod.Scratch, v: *SearchVars, list: *MoveList, side: Side, ply: usize) u16 {
        return generateFull(G, false, p, s, v, 0, list, side, ply);
    }

    /// `generate` with DEV-058 (`dev058`) as the engine sets it.
    fn generateFixes(comptime G: type, comptime dev058: bool, p: *Position, s: *see_mod.Scratch, v: *SearchVars, list: *MoveList, side: Side, ply: usize) u16 {
        return generateFull(G, dev058, p, s, v, 0, list, side, ply);
    }

    /// `generateFixes` with the king rule of gen_tactical_moves (byte 39AE).
    fn generateFull(comptime G: type, comptime dev058: bool, p: *Position, s: *see_mod.Scratch, v: *SearchVars, king_rule: u8, list: *MoveList, side: Side, ply: usize) u16 {
        var wide: [max_written]Move = undefined;
        var q: Q = .{ .o = .{ .p = p, .s = s, .v = v, .king_rule = king_rule, .list = list, .dev058 = dev058, .out = list, .wide = &wide }, .ep = p.ep_square_by_ply[ply] };
        q.run(G, side) catch {
            if (q.o.widened) {
                // The moves written so far stay written, as far as the list holds them.
                @branchHint(.cold);
                const n = @min(q.o.n, list_len);
                @memcpy(list[0..n], wide[0..n]);
            }
            return king_capture;
        };
        // DEV-063: the original returns the full count and writes past the list.
        if (q.o.widened) _ = q.o.narrow();
        return @intCast(q.o.n);
    }
};

/// Bishop directions (DG:1510 from index 3 down), rook directions (DG:04A6 from index 3
/// down) and king / 579A queen directions (DG:1510 from index 7 down).
const diag_dirs = [4]i8{ king_steps[3], king_steps[2], king_steps[1], king_steps[0] };
const line_dirs = [4]i8{ rook_steps[3], rook_steps[2], rook_steps[1], rook_steps[0] };
const all_dirs = blk: {
    var d: [8]i8 = undefined;
    for (&d, 0..) |*x, i| x.* = king_steps[7 - i];
    break :blk d;
};

/// DG:04AA read from index 7 down, negated for Black (25A0, 9528, 4954 queens).
fn queenDirs(comptime white: bool) [8]i8 {
    var d: [8]i8 = undefined;
    for (&d, 0..) |*x, i| x.* = if (white) queen_steps[7 - i] else -queen_steps[7 - i];
    return d;
}

/// A code of the enemy king's map on one of its diagonals (White's pieces read Black's
/// map, 9..0Ch; Black's read White's, 1..4), signed.
fn onDiagonal(comptime white: bool, code: u8) bool {
    const c: i8 = @bitCast(code);
    return if (white) c >= 9 and c <= 0x0C else c >= 1 and c <= 4;
}

/// A code of the enemy king's map on a rank or file (>= 0Dh; >= 5), signed.
fn onLine(comptime white: bool, code: u8) bool {
    const c: i8 = @bitCast(code);
    return c >= (if (white) 0x0D else 5);
}

// ---- gen_tactical_moves, 1E9D:579A --------------------------------------------

const Tactical = struct {
    /// Knight 57C0 (White), 58B8 (Black).
    fn knight(q: *Q, comptime white: bool, from: usize, slot: usize) KingCapture!void {
        const C = Colour(white);
        if (q.emap(white)[from] != 0 and q.discovers(white, from, null)) {
            // UNVERIFIED for Black: only White knights uncovered a check in the recorded calls.
            // The knight uncovers a check: every move to an empty or enemy square,
            // scored code + 8.
            var k: usize = 8;
            while (k > 0) {
                k -= 1;
                const to = add(from, knight_steps[k]);
                const t = q.o.board(to);
                if (if (white) is_empty_or_black[t] != 0 else t < 7) q.o.add(from, to, pos.flag_normal, t + 8);
            }
            return;
        }
        const eking = q.enemyKing(white);
        const own_pawns = &q.o.p.pawn_attacks[C.us];
        var k: usize = 8;
        while (k > 0) {
            k -= 1;
            const to = add(from, knight_steps[k]);
            const t = q.o.board(to);
            if (t == pos.empty) {
                if (reach(&knight_reach, to, eking) != 0) {
                    q.o.add(from, to, pos.flag_normal, 2);
                    continue;
                }
                // Deep in the enemy's half: two squares in front of an own pawn's
                // attack, or a defended square on the last rank.
                if (if (white) to < 0x47 else to > 0x30) continue;
                const ahead = if (white) to + 20 else to - 20;
                if (Q.s8(own_pawns[ahead]) > 0 or (own_pawns[to] != 0 and Q.lastRank(white, to)))
                    q.o.add(from, to, pos.flag_normal, 2);
                continue;
            }
            if (!C.enemy(t)) continue;
            if (t == C.enemy_king) return error.KingCapture;
            // The knight's list entry is 0 during the exchange call; kept always.
            const v = q.o.seeEntry(white, 16 * C.us + slot, 0, to, 9);
            q.o.add(from, to, pos.flag_normal, lowByte(v));
        }
    }

    /// Bishop 59A0 (White), 5DE2 (Black).
    fn bishop(q: *Q, comptime white: bool, from: usize) KingCapture!void {
        const C = Colour(white);
        const m = q.emap(white);
        const code = m[from];
        if (code != 0) {
            if (if (white) Q.s8(code) <= 0x0C else Q.s8(code) < 5) return error.KingCapture;
            if (q.discovers(white, from, if (white) 8 else 2)) {
                q.allSliderMoves(white, from, &diag_dirs, 0x0A, 0x0C);
                return;
            }
        }
        const x = q.bishopXray(white);
        const h: usize = q.o.v.bishop_hint;
        const use_hint = h != 0 and dark_square[h] == dark_square[from];
        const own_pawns = &q.o.p.pawn_attacks[C.us];
        for (diag_dirs) |d| {
            var to = add(from, d);
            while (q.o.board(to) == pos.empty) : (to = add(to, d)) {
                if (onDiagonal(white, m[to]) or
                    (own_pawns[to] != 0 and Q.lastRank(white, to)) or
                    (use_hint and reach(&diagonal_reach, to, h) != 0))
                    q.o.add(from, to, pos.flag_normal, 1);
            }
            if (C.enemy(q.o.board(to))) q.o.add(from, to, pos.flag_normal, lowByte(q.o.seeLifted(white, from, to, 9)));
        }
        q.unmark(white, x);
    }

    /// Rook 5B62 (White), 5F9E (Black).
    fn rook(q: *Q, comptime white: bool, from: usize) KingCapture!void {
        const C = Colour(white);
        const m = q.emap(white);
        const code = m[from];
        if (code != 0) {
            if (onLine(white, code)) return error.KingCapture;
            if (q.discovers(white, from, if (white) 4 else 1)) {
                q.allSliderMoves(white, from, &line_dirs, 0x0A, 0x0C);
                return;
            }
        }
        const hint: usize = q.o.v.rook_hint;
        m[hint] = if (white) 0x0D else 5;
        const x = q.rookXray(white);
        const own_pawns = &q.o.p.pawn_attacks[C.us];
        for (line_dirs) |d| {
            var to = add(from, d);
            while (q.o.board(to) == pos.empty) : (to = add(to, d)) {
                if (Q.lastTwoRanks(white, to)) {
                    if (Q.s8(own_pawns[to]) > 0) {
                        q.o.add(from, to, pos.flag_normal, 4);
                        continue;
                    }
                    if (Q.lastRank(white, to)) {
                        if (onLine(white, m[to])) q.o.add(from, to, pos.flag_normal, 4);
                        continue;
                    }
                }
                if (onLine(white, m[to]) and q.o.seeLifted(white, from, to, 15) >= 0)
                    q.o.add(from, to, pos.flag_normal, 4);
            }
            if (C.enemy(q.o.board(to))) q.o.add(from, to, pos.flag_normal, lowByte(q.o.seeLifted(white, from, to, 15)));
        }
        q.unmark(white, x);
        // Cleared, not restored (suspected bug 4).
        m[hint] = 0;
    }

    /// Queen 5CEC (White), 6128 (Black).
    fn queen(q: *Q, comptime white: bool, from: usize) KingCapture!void {
        const C = Colour(white);
        const m = q.emap(white);
        if (m[from] != 0) return error.KingCapture;
        const hint: usize = q.o.v.queen_hint;
        if (hint != 0) m[hint] = if (white) 1 else 9;
        const eking = q.enemyKing(white);
        const own_pawns = &q.o.p.pawn_attacks[C.us];
        for (all_dirs) |d| {
            var to = add(from, d);
            while (q.o.board(to) == pos.empty) : (to = add(to, d)) {
                const sc = reach(&king_reach, to, eking) +% 2;
                if (Q.lastRank(white, to)) {
                    if (own_pawns[to] != 0 or m[to] != 0) q.o.add(from, to, pos.flag_normal, sc);
                } else if (m[to] != 0 and q.o.seeLifted(white, from, to, 27) >= 0) {
                    q.o.add(from, to, pos.flag_normal, sc);
                }
            }
            if (C.enemy(q.o.board(to))) {
                const v = q.o.seeLifted(white, from, to, 27);
                const sc = if (v >= 0) reach(&king_reach, to, eking) +% lowByte(v) else lowByte(v);
                q.o.add(from, to, pos.flag_normal, sc);
            }
        }
        // Cleared even when the hint is 0 (suspected bug 4: a code there is lost).
        m[hint] = 0;
    }

    /// King 621E (White), 64B0 (Black).
    fn king(q: *Q, comptime white: bool, from: usize) KingCapture!void {
        const C = Colour(white);
        const E = Colour(!white);
        const b = &q.o.p.board;
        const enemy_pawns = &q.o.p.pawn_attacks[E.us];
        var castle = true;
        if (q.emap(white)[from] != 0 and q.discovers(white, from, null)) {
            // The king uncovers a check: every move not onto an enemy pawn's attack.
            for (all_dirs) |d| {
                const to = add(from, d);
                const t = b[to];
                if (t == pos.empty) {
                    if (enemy_pawns[to] == 0) q.o.add(from, to, pos.flag_normal, 0x14);
                } else if (C.enemy(t)) {
                    if (t == C.enemy_king) return error.KingCapture;
                    // 1E9D:6284: a capture not onto an enemy pawn's attack.
                    if (enemy_pawns[to] == 0) q.o.add(from, to, pos.flag_normal, 0x1E);
                }
            }
        } else if (q.o.king_rule != 0) {
            // 644A: steps next to an own pawn; no castling on this path.
            castle = false;
            const near = if (white) [4]i8{ 1, -1, -9, -11 } else [4]i8{ 1, -1, 9, 11 };
            for (all_dirs) |d| {
                const to = add(from, d);
                const t = b[to];
                if (t == pos.empty) {
                    if (enemy_pawns[to] != 0) continue;
                    for (near) |o| {
                        if (b[add(to, o)] == C.pawn) {
                            q.o.add(from, to, pos.flag_normal, 1);
                            break;
                        }
                    }
                } else if (C.enemy(t)) {
                    if (t == C.enemy_king) return error.KingCapture;
                    if (enemy_pawns[to] == 0) q.o.add(from, to, pos.flag_normal, 3);
                }
            }
        } else if (@as(i16, @bitCast(q.o.p.piece_material[C.them])) <= 0x546) {
            // 62BA: few enemy pieces: steps next to an enemy pawn its own pawns do not
            // guard.
            const near = if (white) [6]i8{ 1, -1, 10, -10, -9, -11 } else [6]i8{ 1, -1, 10, -10, 9, 11 };
            for (all_dirs) |d| {
                const to = add(from, d);
                const t = b[to];
                if (t == pos.empty) {
                    if (enemy_pawns[to] != 0) continue;
                    for (near) |o| {
                        const n = add(to, o);
                        if (b[n] == C.enemy_pawn and enemy_pawns[n] == 0) {
                            q.o.add(from, to, pos.flag_normal, 1);
                            break;
                        }
                    }
                } else if (C.enemy(t)) {
                    if (t == C.enemy_king) return error.KingCapture;
                    if (enemy_pawns[to] == 0) q.o.add(from, to, pos.flag_normal, 3);
                }
            }
        } else {
            // 6356: captures only, scored by the victim's exchange value.
            for (all_dirs) |d| {
                const to = add(from, d);
                const t = b[to];
                if (t == pos.empty or !C.enemy(t)) continue;
                if (t == C.enemy_king) return error.KingCapture;
                if (enemy_pawns[to] == 0) q.o.add(from, to, pos.flag_normal, see_value[t]);
            }
        }
        if (castle) {
            for (castling(q.o.p, white)) |to| {
                if (to != 0) q.o.add(castleFrom(white), to, pos.flag_castle, 2);
            }
        }
    }

    /// Pawn 6714 (White), 6856 (Black).
    fn pawn(q: *Q, comptime white: bool, from: usize) void {
        const C = Colour(white);
        const f: i32 = if (white) 1 else -1;
        const b = &q.o.p.board;
        for (pawn_steps[0..2]) |d| {
            const to = add(from, f * d);
            const t = b[to];
            if (if (white) t > 7 else is_white_code[t] != 0) {
                if (Q.lastRank(white, to)) {
                    q.o.add(from, to, 5, 0x28);
                    q.o.add(from, to, 2, 0x23);
                } else {
                    q.o.add(from, to, pos.flag_normal, see_value[t]);
                }
            } else if (q.ep == to) {
                q.o.add(from, to, pos.flag_en_passant, 3);
            }
        }
        const eking = q.enemyKing(white);
        const own_pawns = &q.o.p.pawn_attacks[C.us];
        for (pawn_steps[2..4]) |d| {
            const to = add(from, f * d);
            if (b[to] != pos.empty) return;
            if (Q.lastTwoRanks(white, to)) {
                if (Q.lastRank(white, to)) {
                    q.o.add(from, to, 5, 0x1E);
                    q.o.add(from, to, 2, 0x19);
                } else {
                    q.o.add(from, to, pos.flag_normal, 2);
                }
                return;
            }
            var ok = false;
            if (if (white) to >= 0x47 else to <= 0x30) {
                const ahead = add(to, 10 * f);
                ok = b[ahead] == pos.empty or own_pawns[ahead] != 0 or reach(&king_reach, ahead, eking) != 0;
            }
            if (!ok) {
                ok = if (white)
                    b[to + 9] >= 9 or b[to + 11] >= 9
                else
                    isWhitePiece(b[to - 9]) or isWhitePiece(b[to - 11]);
            }
            if (!ok) ok = q.pushUncovers(white, from, to);
            if (ok) q.o.add(from, to, pos.flag_normal, 2);
            // The double push is tried whether or not the single push was kept.
            if (if (white) to > 0x30 else to < 0x47) return;
        }
    }
};

/// White codes 2..6 (the test `2 <= code < 7`, signed).
inline fn isWhitePiece(t: u8) bool {
    return t >= 2 and t < 7;
}

// ---- gen_tactical_moves_no_losers, 1E9D:25A0 ----------------------------------

/// `dev005` is `pos.Fixes.dev005_bishop_check_score`.
fn NoLosers(comptime dev005: bool) type {
    return struct {
        /// 25A0's rule for a capture that loses: kept on the mover's own first two ranks,
        /// or on the enemy's last two when `check` holds.
        fn keepLoser(comptime white: bool, to: usize, check: bool) bool {
            if (Q.ownBack(white, to)) return true;
            if (!Q.lastTwoRanks(white, to)) return false;
            return check;
        }

        /// Knight 25C6 (White), 26DE (Black).
        fn knight(q: *Q, comptime white: bool, from: usize, slot: usize) KingCapture!void {
            const C = Colour(white);
            if (q.emap(white)[from] != 0 and q.discovers(white, from, null)) {
                var k: usize = 8;
                while (k > 0) {
                    k -= 1;
                    const to = add(from, knight_steps[k]);
                    const t = q.o.board(to);
                    if (if (white) is_empty_or_black[t] != 0 else t < 7) q.o.add(from, to, pos.flag_normal, 0x0A);
                }
                return;
            }
            const eking = q.enemyKing(white);
            const entry = 16 * C.us + slot;
            var k: usize = 8;
            while (k > 0) {
                k -= 1;
                const to = add(from, knight_steps[k]);
                const t = q.o.board(to);
                const checks = reach(&knight_reach, to, eking) != 0;
                if (t == pos.empty) {
                    if (!checks) continue;
                    const v = q.o.seeEntry(white, entry, 0, to, 9);
                    if (v >= 0 or Q.lastTwoRanks(white, to)) q.o.add(from, to, pos.flag_normal, 2);
                    continue;
                }
                if (if (white) t <= 7 else t > 6) continue;
                if (t == C.enemy_king) return error.KingCapture;
                const v = q.o.seeEntry(white, entry, 0, to, 9);
                if (v >= 0 or keepLoser(white, to, checks)) q.o.add(from, to, pos.flag_normal, lowByte(v));
            }
        }

        /// Bishop 27E8 (White), 2B44 (Black).
        fn bishop(q: *Q, comptime white: bool, from: usize) KingCapture!void {
            const C = Colour(white);
            const m = q.emap(white);
            const code = m[from];
            if (code != 0) {
                if (if (white) Q.s8(code) < 0x0D else Q.s8(code) < 5) return error.KingCapture;
                if (q.discovers(white, from, if (white) 8 else 2)) {
                    q.allSliderMoves(white, from, &diag_dirs, 8, 0x0A);
                    return;
                }
            }
            // DEV-005 (suspected bug 5): a quiet bishop check scores 2 for White (1E9D:28AE)
            // and 1 for Black (1E9D:2C06); every other constant of the routine is the same
            // for both colours. Corrected (`dev005_bishop_check_score`): 2 for Black too.
            const quiet: u8 = if (white or dev005) 2 else 1;
            for (diag_dirs) |d| {
                var to = add(from, d);
                while (q.o.board(to) == pos.empty) : (to = add(to, d)) {
                    if (onDiagonal(white, m[to])) {
                        const v = q.o.seeLifted(white, from, to, 9);
                        if (v >= 0 or Q.lastTwoRanks(white, to)) q.o.add(from, to, pos.flag_normal, quiet);
                    }
                }
                if (C.enemy(q.o.board(to))) {
                    const v = q.o.seeLifted(white, from, to, 9);
                    if (v >= 0 or keepLoser(white, to, onDiagonal(white, m[to]))) q.o.add(from, to, pos.flag_normal, lowByte(v));
                }
            }
        }

        /// Rook 2926 (White), 2C7E (Black).
        fn rook(q: *Q, comptime white: bool, from: usize) KingCapture!void {
            const C = Colour(white);
            const m = q.emap(white);
            const code = m[from];
            if (code != 0) {
                if (onLine(white, code)) return error.KingCapture;
                if (q.discovers(white, from, if (white) 4 else 1)) {
                    q.allSliderMoves(white, from, &line_dirs, 0x0A, 0x0C);
                    return;
                }
            }
            const x: Q.Xray = if (q.o.v.rook_hint != 0) q.rookXray(white) else .{};
            const own_pawns = &q.o.p.pawn_attacks[C.us];
            for (line_dirs) |d| {
                var to = add(from, d);
                while (q.o.board(to) == pos.empty) : (to = add(to, d)) {
                    if (Q.lastRank(white, to)) {
                        if (Q.s8(own_pawns[to]) > 0 or onLine(white, m[to])) q.o.add(from, to, pos.flag_normal, 4);
                    } else if (onLine(white, m[to]) and q.o.seeLifted(white, from, to, 15) >= 0) {
                        q.o.add(from, to, pos.flag_normal, 4);
                    }
                }
                if (C.enemy(q.o.board(to))) q.o.add(from, to, pos.flag_normal, lowByte(q.o.seeLifted(white, from, to, 15)));
            }
            q.unmark(white, x);
        }

        /// Queen 2AA0 (White), 2DF8 (Black).
        fn queen(q: *Q, comptime white: bool, from: usize) KingCapture!void {
            const C = Colour(white);
            const m = q.emap(white);
            if (m[from] != 0) return error.KingCapture;
            for (queenDirs(white)) |d| {
                var to = add(from, d);
                while (q.o.board(to) == pos.empty) : (to = add(to, d)) {
                    if (m[to] == 0) continue;
                    if (Q.lastRank(white, to) or q.o.seeLifted(white, from, to, 27) >= 0)
                        q.o.add(from, to, pos.flag_normal, 0x0C);
                }
                if (C.enemy(q.o.board(to))) {
                    const v = q.o.seeLifted(white, from, to, 27);
                    if (v >= 0) q.o.add(from, to, pos.flag_normal, lowByte(v));
                }
            }
        }

        /// King 2E9C (White), 2F96 (Black): captures not attacked by an enemy pawn, then
        /// castling.
        fn king(q: *Q, comptime white: bool, from: usize) KingCapture!void {
            try kingCaptures(q, white, from, &all_dirs);
            for (castling(q.o.p, white)) |to| {
                if (to != 0) q.o.add(castleFrom(white), to, pos.flag_castle, 2);
            }
        }

        /// Pawn 3062 (White), 3198 (Black).
        fn pawn(q: *Q, comptime white: bool, from: usize) void {
            const C = Colour(white);
            const f: i32 = if (white) 1 else -1;
            const b = &q.o.p.board;
            for (pawn_steps[0..2]) |d| {
                const to = add(from, f * d);
                const t = b[to];
                // Suspected bug 6: White's test includes the Black king, Black's excludes
                // the White king.
                const hit = if (white) t > 7 else t != 0 and t < 6;
                const ep_test = if (white) !hit else t == 0;
                if (hit) {
                    if (Q.lastRank(white, to)) {
                        q.o.add(from, to, 5, 0x1E);
                        q.o.add(from, to, 2, 0x0F);
                    } else {
                        q.o.add(from, to, pos.flag_normal, see_value[t]);
                    }
                } else if (ep_test and q.ep == to) {
                    q.o.add(from, to, pos.flag_en_passant, 3);
                }
            }
            const own_pawns = &q.o.p.pawn_attacks[C.us];
            for (pawn_steps[2..4]) |d| {
                const to = add(from, f * d);
                if (b[to] != pos.empty) return;
                if (Q.lastTwoRanks(white, to)) {
                    if (Q.lastRank(white, to)) {
                        q.o.add(from, to, 5, 0x19);
                        q.o.add(from, to, 2, 0x0A);
                    } else {
                        q.o.add(from, to, pos.flag_normal, 2);
                    }
                    return;
                }
                if ((if (white) to >= 0x47 else to <= 0x30) and b[add(to, 10 * f)] == pos.empty) {
                    q.o.add(from, to, pos.flag_normal, 2);
                    return;
                }
                const a = b[add(to, 11 * f)];
                const c = b[add(to, 9 * f)];
                const hit_a = if (white) a >= 9 else a >= 2 and a <= 6;
                const hit_c = if (white) c >= 9 else c >= 2 and c <= 6;
                const guarded = Q.s8(own_pawns[to]) > 0;
                var ok = false;
                if (hit_a) {
                    ok = guarded or a == C.enemy_king or hit_c; // defended, check, or a fork
                } else if (hit_c) {
                    ok = guarded or c == C.enemy_king;
                }
                if (!ok) ok = q.pushUncovers(white, from, to);
                if (ok) {
                    // A kept single push ends the pawn: no double push after it.
                    q.o.add(from, to, pos.flag_normal, 2);
                    return;
                }
                if (if (white) to > 0x30 else to < 0x47) return;
            }
        }
    };
}

/// King captures of 25A0 (steps `dirs`), 9528 and 4954: not onto an enemy pawn's
/// attack, scored by the victim's exchange value.
fn kingCaptures(q: *Q, comptime white: bool, from: usize, dirs: []const i8) KingCapture!void {
    const C = Colour(white);
    const enemy_pawns = &q.o.p.pawn_attacks[Colour(!white).us];
    for (dirs) |d| {
        const to = add(from, d);
        const t = q.o.board(to);
        if (if (white) t <= 7 else (t == 0 or t > 6)) continue;
        if (t == C.enemy_king) return error.KingCapture;
        if (enemy_pawns[to] == 0) q.o.add(from, to, pos.flag_normal, see_value[t]);
    }
}

/// The fixed order of the king captures of 9528 and 4954 (9ADE / 9C8E), both colours.
const king_capture_order = [8]i8{ 1, 9, 10, 11, -11, -10, -9, -1 };

// ---- gen_quiescence_moves, 0EF8:9528 ------------------------------------------

/// `dev005` is `pos.Fixes.dev005_bishop_check_score`.
fn Quiescence(comptime dev005: bool) type {
    return struct {
        /// Knight 9558 (White), 95F0 (Black).
        fn knight(q: *Q, comptime white: bool, from: usize, slot: usize) KingCapture!void {
            const C = Colour(white);
            const eking = q.enemyKing(white);
            const entry = 16 * C.us + slot;
            var k: usize = 8;
            while (k > 0) {
                k -= 1;
                const to = add(from, knight_steps[k]);
                const t = q.o.board(to);
                if (t == pos.empty) {
                    if (reach(&knight_reach, to, eking) == 0) continue;
                    if (q.o.seeEntry(white, entry, 0, to, 9) >= 0) q.o.add(from, to, pos.flag_normal, 2);
                    continue;
                }
                if (!C.enemy(t)) continue;
                if (t == C.enemy_king) return error.KingCapture;
                const v = q.o.seeEntry(white, entry, 0, to, 9);
                if (v >= 0 or Q.ownBack(white, to)) q.o.add(from, to, pos.flag_normal, lowByte(v));
            }
        }

        /// Bishop 9688 (White), 98CA (Black).
        fn bishop(q: *Q, comptime white: bool, from: usize) KingCapture!void {
            const C = Colour(white);
            const m = q.emap(white);
            if (onDiagonal(white, m[from])) return error.KingCapture;
            // DEV-005 (suspected bug 5): a quiet bishop check scores 2 for White (0EF8:96D1)
            // and 1 for Black (0EF8:9913); every other quiet move of the routine, knight,
            // rook and queen of both colours, scores 2. Corrected
            // (`dev005_bishop_check_score`): 2 for Black too.
            const quiet: u8 = if (white or dev005) 2 else 1;
            for (diag_dirs) |d| {
                var to = add(from, d);
                while (q.o.board(to) == pos.empty) : (to = add(to, d)) {
                    if (onDiagonal(white, m[to]) and q.o.seeLifted(white, from, to, 9) >= 0)
                        q.o.add(from, to, pos.flag_normal, quiet);
                }
                if (C.enemy(q.o.board(to))) {
                    const v = q.o.seeLifted(white, from, to, 9);
                    if (v >= 0 or Q.ownBack(white, to)) q.o.add(from, to, pos.flag_normal, lowByte(v));
                }
            }
        }

        /// Rook 9768 (White), 997C (Black).
        fn rook(q: *Q, comptime white: bool, from: usize) KingCapture!void {
            const C = Colour(white);
            const m = q.emap(white);
            if (onLine(white, m[from])) return error.KingCapture;
            for (line_dirs) |d| {
                var to = add(from, d);
                while (q.o.board(to) == pos.empty) : (to = add(to, d)) {
                    if (onLine(white, m[to]) and q.o.seeLifted(white, from, to, 15) >= 0)
                        q.o.add(from, to, pos.flag_normal, 2);
                }
                const t = q.o.board(to);
                if (C.enemy(t)) {
                    const v = q.o.seeLifted(white, from, to, 15);
                    // A losing rook capture is kept unless the victim is a pawn.
                    if (v >= 0 or (if (white) t >= 9 else t >= 2)) q.o.add(from, to, pos.flag_normal, lowByte(v));
                }
            }
        }

        /// Queen 980E (White), 9A22 (Black).
        fn queen(q: *Q, comptime white: bool, from: usize) KingCapture!void {
            const C = Colour(white);
            const m = q.emap(white);
            if (m[from] != 0) return error.KingCapture;
            const eking = q.enemyKing(white);
            for (queenDirs(white)) |d| {
                var to = add(from, d);
                while (q.o.board(to) == pos.empty) : (to = add(to, d)) {
                    if (m[to] != 0 and (Q.lastRank(white, to) or Q.s8(q.o.v.check_flag) > 0 or reach(&king_reach, to, eking) != 0) and
                        q.o.seeLifted(white, from, to, 27) >= 0)
                        q.o.add(from, to, pos.flag_normal, 2);
                }
                if (C.enemy(q.o.board(to))) {
                    const v = q.o.seeLifted(white, from, to, 27);
                    if (v >= 0) q.o.add(from, to, pos.flag_normal, lowByte(v));
                }
            }
        }

        /// King 9ADE (White), 9C8E (Black): captures only, no castling.
        fn king(q: *Q, comptime white: bool, from: usize) KingCapture!void {
            try kingCaptures(q, white, from, &king_capture_order);
        }

        /// Pawn 9E06 (White), 9EFA (Black).
        fn pawn(q: *Q, comptime white: bool, from: usize) void {
            const f: i32 = if (white) 1 else -1;
            const b = &q.o.p.board;
            for (pawn_steps[0..2]) |d| {
                const to = add(from, f * d);
                const t = b[to];
                if (if (white) t > 7 else is_white_code[t] != 0) {
                    if (Q.lastRank(white, to)) {
                        q.o.add(from, to, 5, 0x28);
                        q.o.add(from, to, 2, 0x23);
                    } else {
                        q.o.add(from, to, pos.flag_normal, see_value[t]);
                    }
                } else if (q.ep == to) {
                    q.o.add(from, to, pos.flag_en_passant, 3);
                }
            }
            for (0..2) |k| {
                // The double push only from the 2nd (7th) rank.
                if (k == 1 and (if (white) from > 0x26 else from < 0x51)) return;
                const to = add(from, f * @as(i32, if (k == 0) 10 else 20));
                if (b[to] != pos.empty) return;
                if (Q.lastTwoRanks(white, to)) {
                    if (Q.lastRank(white, to)) {
                        q.o.add(from, to, 5, 0x1E);
                        q.o.add(from, to, 2, 0x19);
                        return;
                    }
                    q.o.add(from, to, pos.flag_normal, 0);
                    continue;
                }
                // A fork, or a check by the pawn itself.
                const ok = if (white) blk: {
                    const b9 = b[to + 9];
                    const b11 = b[to + 11];
                    break :blk if (b9 >= 9) b11 >= 9 or b9 == pos.black_king else b11 == pos.black_king;
                } else blk: {
                    const a = b[to - 9];
                    const c = b[to - 11];
                    break :blk if (a >= 2 and a <= 6) a == pos.white_king or (c >= 2 and c <= 6) else c == pos.white_king;
                };
                if (ok) q.o.add(from, to, pos.flag_normal, 0);
            }
        }
    };
}

// ---- gen_captures, 1E9D:4954 --------------------------------------------------

/// `dev004` is `pos.Fixes.dev004_promotion_capture_score`.
fn Captures(comptime dev004: bool) type {
    return struct {
        const Rule = enum { nonneg, positive, positive_or_back };

        /// Lift the piece, run the exchange evaluator, keep the move by `rule`.
        fn capture(q: *Q, comptime white: bool, from: usize, to: usize, value: u16, comptime rule: Rule) void {
            const v = q.o.seeLifted(white, from, to, value);
            const keep = switch (rule) {
                .nonneg => v >= 0,
                .positive => v > 0,
                .positive_or_back => v > 0 or Q.ownBack(white, to),
            };
            if (keep) q.o.add(from, to, pos.flag_normal, lowByte(v));
        }

        /// Knight 4984 (White), 49DA (Black): its list entry holds the target square
        /// during the exchange call.
        fn knight(q: *Q, comptime white: bool, from: usize, slot: usize) KingCapture!void {
            const C = Colour(white);
            const entry = 16 * C.us + slot;
            var k: usize = 8;
            while (k > 0) {
                k -= 1;
                const to = add(from, knight_steps[k]);
                const t = q.o.board(to);
                if (if (white) t <= 7 else (t == 0 or t >= 7)) continue;
                if (t == C.enemy_king) return error.KingCapture;
                const v = q.o.seeEntry(white, entry, u8sq(to), to, 9);
                if (v > 0 or Q.ownBack(white, to)) q.o.add(from, to, pos.flag_normal, lowByte(v));
            }
        }

        /// Bishop 4A38 (White), 4D36 (Black): captures only, +9, +11, -9, -11 (Black
        /// negated).
        fn bishop(q: *Q, comptime white: bool, from: usize) KingCapture!void {
            const C = Colour(white);
            if (onDiagonal(white, q.emap(white)[from])) return error.KingCapture;
            const f: i8 = if (white) 1 else -1;
            for ([4]i8{ 9, 11, -9, -11 }) |d0| {
                const d = d0 * f;
                var to = add(from, d);
                while (q.o.board(to) == pos.empty) to = add(to, d);
                if (C.enemy(q.o.board(to))) capture(q, white, from, to, 9, .positive_or_back);
            }
        }

        /// Rook 4B8C (White), 4E62 (Black).
        fn rook(q: *Q, comptime white: bool, from: usize) KingCapture!void {
            const C = Colour(white);
            const m = q.emap(white);
            if (onLine(white, m[from])) return error.KingCapture;
            for (line_dirs) |d| {
                var to = add(from, d);
                while (q.o.board(to) == pos.empty) : (to = add(to, d)) {
                    // A quiet rook check on the enemy's last two ranks: on the last rank, or
                    // on the next one when the flag DG:73F2 is positive.
                    if (Q.lastTwoRanks(white, to) and onLine(white, m[to]) and
                        (Q.s8(q.o.v.check_flag) > 0 or Q.lastRank(white, to)))
                        capture(q, white, from, to, 15, .nonneg);
                }
                if (C.enemy(q.o.board(to))) capture(q, white, from, to, 15, .nonneg);
            }
        }

        /// Queen 4C3E (White), 4F14 (Black).
        fn queen(q: *Q, comptime white: bool, from: usize) KingCapture!void {
            const C = Colour(white);
            const m = q.emap(white);
            if (m[from] != 0) return error.KingCapture;
            const dirs = queenDirs(white);
            // The three forward directions first: on the last rank an empty square on the
            // enemy king's rank is tried; any other empty last-rank square ends the
            // direction.
            dir: for (dirs[0..3]) |d| {
                var to = add(from, d);
                while (q.o.board(to) == pos.empty) : (to = add(to, d)) {
                    if (Q.lastRank(white, to)) {
                        const code = m[to];
                        if (if (white) code == 0x0D or code == 0x0F else code == 5 or code == 7) {
                            capture(q, white, from, to, 27, .nonneg);
                        } else continue :dir;
                    }
                }
                if (C.enemy(q.o.board(to))) capture(q, white, from, to, 27, .nonneg);
            }
            // The other five: captures that win.
            for (dirs[3..8]) |d| {
                var to = add(from, d);
                while (q.o.board(to) == pos.empty) to = add(to, d);
                if (C.enemy(q.o.board(to))) capture(q, white, from, to, 27, .positive);
            }
        }

        /// King 500E (White), 51BE (Black): as 9528.
        fn king(q: *Q, comptime white: bool, from: usize) KingCapture!void {
            try kingCaptures(q, white, from, &king_capture_order);
        }

        /// Pawn 5336 (White), 53F0 (Black).
        fn pawn(q: *Q, comptime white: bool, from: usize) void {
            const f: i32 = if (white) 1 else -1;
            const b = &q.o.p.board;
            for (pawn_steps[0..2]) |d| {
                const to = add(from, f * d);
                const t = b[to];
                if (if (white) t > 7 else is_white_code[t] != 0) {
                    if (Q.lastRank(white, to)) {
                        // DEV-004 (suspected bug 7): White's queen promotion by capture is
                        // scored with AL as the capture step left it (9 or 11, loaded at
                        // 1E9D:53AA; stored at 534B); Black's mirror stores 28h (540B), as
                        // do the queen promotion captures of 579A and 9528. Corrected
                        // (`dev004_promotion_capture_score`): 28h for White too.
                        q.o.add(from, to, 5, if (white and !dev004) @as(u8, @bitCast(d)) else 0x28);
                        q.o.add(from, to, 2, 0x23);
                    } else {
                        q.o.add(from, to, pos.flag_normal, see_value[t]);
                    }
                } else if (q.ep == to) {
                    q.o.add(from, to, pos.flag_en_passant, 3);
                }
            }
            const to = add(from, 10 * f);
            if (Q.lastRank(white, to) and b[to] == pos.empty) {
                q.o.add(from, to, 5, 0x1E);
                q.o.add(from, to, 2, 0x19);
            }
        }
    };
}

/// Port of gen_tactical_moves (1E9D:579A-69F5, castling helpers 6A69 and 69F6): the
/// first quiescence generator (H < ply <= H+2): captures (all kept, scored by the
/// exchange value), checks, discovered checks, moves to the hint squares
/// `SearchVars.bishop_hint`, `rook_hint` and `queen_hint`, threatening pawn pushes,
/// king moves by the rule `king_rule` (DG:39AE, `EvalVars.black_king_by_passer`, which
/// static_eval writes) and the enemy's material select, and
/// castling. Unsorted (the node sorts). Returns the count, or FFFFh if a piece can take
/// the enemy king.
///
/// The rook and queen write marks into the enemy king's ray map at the hint squares and
/// clear them to 0 afterwards, not restoring what was there (suspected bug 4, kept).
pub fn genTacticalMoves(p: *Position, s: *see_mod.Scratch, v: *SearchVars, king_rule: u8, list: *MoveList, side: Side, ply: usize) u16 {
    return Q.generateFull(Tactical, false, p, s, v, king_rule, list, side, ply);
}

/// `genTacticalMoves` under the class C fixes `pfixes`: DEV-058
/// (`dev058_lifted_knight_entry`), in its exchange calls.
pub fn genTacticalMovesFixes(comptime pfixes: pos.Fixes, p: *Position, s: *see_mod.Scratch, v: *SearchVars, king_rule: u8, list: *MoveList, side: Side, ply: usize) u16 {
    return Q.generateFull(Tactical, pfixes.dev058_lifted_knight_entry, p, s, v, king_rule, list, side, ply);
}

/// Port of gen_tactical_moves_no_losers (1E9D:25A0-332F, castling helpers 33A3 and
/// 3330): the second quiescence generator (H+2 < ply <= H+4): captures that do not
/// lose (or that land on the mover's own back ranks, or check on the enemy's), checks
/// that do not lose, threatening pawn pushes, king captures and castling. Unsorted.
pub fn genTacticalMovesNoLosers(p: *Position, s: *see_mod.Scratch, v: *SearchVars, list: *MoveList, side: Side, ply: usize) u16 {
    return genTacticalMovesNoLosersFixes(pos.Fixes.original, p, s, v, list, side, ply);
}

/// `genTacticalMovesNoLosers` with the class C fix of `pfixes` that touches it:
/// `dev005_bishop_check_score` (DEV-005).
pub fn genTacticalMovesNoLosersFixes(comptime pfixes: pos.Fixes, p: *Position, s: *see_mod.Scratch, v: *SearchVars, list: *MoveList, side: Side, ply: usize) u16 {
    return Q.generateFixes(NoLosers(pfixes.dev005_bishop_check_score), pfixes.dev058_lifted_knight_entry, p, s, v, list, side, ply);
}

/// Port of gen_quiescence_moves (0EF8:9528-A025): the third quiescence generator
/// (H+4 < ply <= H+6): captures that do not lose, checks that do not lose, forking or
/// checking pawn pushes, promotions. Unsorted.
pub fn genQuiescenceMoves(p: *Position, s: *see_mod.Scratch, v: *SearchVars, list: *MoveList, side: Side, ply: usize) u16 {
    return genQuiescenceMovesFixes(pos.Fixes.original, p, s, v, list, side, ply);
}

/// `genQuiescenceMoves` with the class C fix of `pfixes` that touches it:
/// `dev005_bishop_check_score` (DEV-005).
pub fn genQuiescenceMovesFixes(comptime pfixes: pos.Fixes, p: *Position, s: *see_mod.Scratch, v: *SearchVars, list: *MoveList, side: Side, ply: usize) u16 {
    return Q.generateFixes(Quiescence(pfixes.dev005_bishop_check_score), pfixes.dev058_lifted_knight_entry, p, s, v, list, side, ply);
}

/// Port of gen_captures (1E9D:4954-54CD): the last quiescence generator (ply > H+6):
/// winning captures, promotions, and checks on the last ranks. Unsorted.
pub fn genCaptures(p: *Position, s: *see_mod.Scratch, v: *SearchVars, list: *MoveList, side: Side, ply: usize) u16 {
    return genCapturesFixes(pos.Fixes.original, p, s, v, list, side, ply);
}

/// `genCaptures` with the class C fix of `pfixes` that touches it:
/// `dev004_promotion_capture_score` (DEV-004).
pub fn genCapturesFixes(comptime pfixes: pos.Fixes, p: *Position, s: *see_mod.Scratch, v: *SearchVars, list: *MoveList, side: Side, ply: usize) u16 {
    return Q.generate(Captures(pfixes.dev004_promotion_capture_score), p, s, v, list, side, ply);
}
