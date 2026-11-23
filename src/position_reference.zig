//! TEST ONLY. src/position.zig as it was before the speed pass of 2026-11-18, kept
//! unchanged as the reference the differential tests compare the faster routines
//! with. Imported only by the test files; not part of the engine.
//!
//! The search position and its incremental update: make_move, unmake_move and
//! update_hash_key.
//!
//! Specification: docs/arch/20-position-make-unmake.md, whose executable form is
//! tools/research/position/model.py (proved against the running original on about
//! 850,000 calls of each routine). Tests: src/position_test.zig, which replays calls
//! recorded from the original (tests/golden/position/).
//!
//! Squares are 10x12 mailbox indices: a1 = 21, h1 = 28, a8 = 91, h8 = 98; one rank is
//! 10. Piece codes: 0 empty, 7 border; White pawn 1, knight 2, bishop 3, rook 4,
//! queen 5, king 6; Black 8..13 in the same order (White code + 7).
//!
//! `DG:xxxx` is an address in the original's default data segment (DGROUP, 61E4).
//!
//! Integer widths follow the original: "byte" fields wrap at 8 bits and "word" fields
//! at 16 bits. The counters and sums below are updated with wrapping operators
//! because the original's are plain 8- and 16-bit adds; a value that would wrap means
//! the state was already inconsistent, but the original carries on, and so must we.
//! Indexing is ordinary (bounds-checked in safe builds): an index the original would
//! have taken outside an array is a class A defect, not behaviour to reproduce.

const std = @import("std");

// ---------------------------------------------------------------------------
// Pieces, sides, moves
// ---------------------------------------------------------------------------

pub const empty: u8 = 0;
pub const border: u8 = 7;
pub const white_pawn: u8 = 1;
pub const white_knight: u8 = 2;
pub const white_bishop: u8 = 3;
pub const white_rook: u8 = 4;
pub const white_queen: u8 = 5;
pub const white_king: u8 = 6;
pub const black_pawn: u8 = 8;
pub const black_knight: u8 = 9;
pub const black_bishop: u8 = 10;
pub const black_rook: u8 = 11;
pub const black_queen: u8 = 12;
pub const black_king: u8 = 13;

pub const Side = enum(u1) {
    white = 0,
    black = 1,

    pub fn other(s: Side) Side {
        return @fromBackingInt(@intCast(1 - @backingInt(s)));
    }
};

/// Move flags (the move's third byte), as make_move reads them (1E9D:0059..0084).
pub const flag_normal: u8 = 0;
pub const flag_en_passant: u8 = 1;
pub const flag_castle: u8 = 6;
// Any other flag is a promotion: the new piece as a White code (2 knight .. 5 queen).

/// A move as the original stores it: 4 bytes.
pub const Move = extern struct {
    from: u8,
    to: u8,
    flag: u8,
    /// Order score; not read by make_move, unmake_move or update_hash_key.
    score: u8 = 0,
};

/// The two bytes through which make_move reports a capture and unmake_move reads it
/// back. In the original they live in the search node's frame (`[bp-20h]` and
/// `[bp-2Ah]` in 0000:3AC6) and are passed by pointer.
pub const Undo = struct {
    /// Code of the captured piece, 0 for none. Written by every make_move.
    captured: u8 = 0,
    /// Piece-list slot of the captured piece. make_move writes it only for a capture
    /// or an en-passant move; unmake_move overwrites it with 80h after a capture and 0
    /// otherwise.
    captured_slot: u8 = 0,
};

// ---------------------------------------------------------------------------
// DEV-002: the per-ply arrays
// ---------------------------------------------------------------------------

/// Number of entries in each per-ply array (DEV-002, docs/DEVIATIONS.md).
///
/// The original has no bound: its arrays run into other variables at ply 46
/// (`ep_square_by_ply` into the search board), 36 (`reversible_by_ply` into
/// `check_by_ply`) and 40 (`quiet_move_by_ply` into the pondering flag DG:3676). The
/// node's ply ceiling is 35 (`[62]`, docs/arch/31-root-iteration-time.md) and the
/// deepest ply seen in any recorded run is 23. Whether quiescence and extensions stay
/// under the ceiling is not yet proved, so all four arrays get 64 entries: room above
/// every limit the original has, and at least as many entries as every region the
/// specification compares (46, 64, 36 and 40). Below ply 36 nothing changes; a ply of
/// 64 or more is a checked error (a panic) in safe builds.
pub const max_ply = 64;

// ---------------------------------------------------------------------------
// Class C fixes (AGENTS.md §9.2)
// ---------------------------------------------------------------------------

/// The switchable bug fixes that touch this subsystem. `original` reproduces the
/// original exactly and is what the differential tests use; `corrected` is what the
/// engine ships with.
pub const Fixes = struct {
    /// DEV-001: update_hash_key removes the pawn captured en passant from the keys on
    /// the square in front of the capturing pawn (from ± 10) instead of where it
    /// stands (to ∓ 10).
    dev001_ep_hash_square: bool,

    pub const original: Fixes = .{ .dev001_ep_hash_square = false };
    pub const corrected: Fixes = .{ .dev001_ep_hash_square = true };
};

// ---------------------------------------------------------------------------
// Constant tables (initialised data in the original; check.py compares each with
// the running program)
// ---------------------------------------------------------------------------

/// DG:100A: file of a square, `s mod 10` (0 and 9 on the border files); 0 from 110.
const file_of: [120]u8 = blk: {
    var t: [120]u8 = undefined;
    for (&t, 0..) |*v, s| v.* = if (s < 110) s % 10 else 0;
    break :blk t;
};

/// DG:1078: rank of a square, `s div 10` (rank 1 = 2 .. rank 8 = 9); 0 from 100.
const rank_of: [120]u8 = blk: {
    var t: [120]u8 = undefined;
    for (&t, 0..) |*v, s| v.* = if (s < 100) s / 10 else 0;
    break :blk t;
};

/// DG:0E16: 1 on dark squares (a1 is dark). 100 entries, as in the original.
const dark: [100]u8 = blk: {
    var t: [100]u8 = @splat(0);
    for (0..8) |r| for (0..8) |f| {
        t[21 + 10 * r + f] = if ((r + f) % 2 == 0) 1 else 0;
    };
    break :blk t;
};

/// DG:0490: direction code to step. Codes 1..8 are the White king's rays, 9..16 the
/// Black king's, in the order +9, +11, -9, -11, +1, +10, -1, -10.
const dir_step = [17]i8{ 0, 9, 11, -9, -11, 1, 10, -1, -10, 9, 11, -9, -11, 1, 10, -1, -10 };

/// DG:047E: direction code to slider bit.
const dir_bit = [17]u8{ 0, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 8, 8, 8, 8 };

/// DG:0470: piece code to slider bits (White B 4, R 8, Q 0Ch; Black B 1, R 2, Q 3).
const slider_bits = [14]u8{ 0, 0, 0, 4, 8, 12, 0, 0, 0, 0, 1, 2, 3, 0 };

/// DG:0990 + file and DG:09AE + file: the en-passant square behind a double step.
const ep_square_after = [2][10]u8{
    .{ 0, 41, 42, 43, 44, 45, 46, 47, 48, 0 },
    .{ 0, 71, 72, 73, 74, 75, 76, 77, 78, 0 },
};

/// DG:1216 (White castles: read from the Black king's map, codes 13..16) and DG:1204
/// (Black castles: the White king's map, codes 5..8): check value after castling,
/// indexed by the opponent king's ray code at the rook's new square.
const castle_check = [2][17]u8{
    .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 13, 14, 15, 16 },
    .{ 0, 0, 0, 0, 0, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0 },
};

/// DG:1498 (material) and DG:14D0 (the second balance's table, equal to it): piece
/// value by code.
const piece_value = [14]u16{ 0, 200, 650, 700, 1100, 2000, 0, 0, 200, 650, 700, 1100, 2000, 0 };
const piece_value_2 = piece_value;

/// DG:14B4 and DG:14EC: promotion gain by the promoted piece's code (value - 200).
const promotion_gain = [14]u16{ 0, 0, 450, 500, 900, 1800, 0, 0, 0, 450, 500, 900, 1800, 0 };
const promotion_gain_2 = promotion_gain;

/// DG:2A76, 2A7C, 2A82, 2A88: the castling keys, White O-O, White O-O-O, Black O-O,
/// Black O-O-O, as 48-bit little-endian values (bytes as in memory: 73 93 18 CE F9 CD,
/// and so on). Index `2 * side + wing`, wing 0 king side, 1 queen side.
const castle_keys = [4]u48{
    0xCDF9CE189373,
    0x3B84A6565EB1,
    0xE58291B75C2F,
    0x7AED68751E21,
};

/// DG:06C0: per square, the offset of its 78-byte block in the hash random table,
/// `78 * k - 6` for the k-th board square (a1 = 0 .. h8 = 63), as a 16-bit word (so
/// a1's is FFFAh); 0 off the board.
const hash_square_offset: [120]u16 = blk: {
    var t: [120]u16 = @splat(0);
    for (0..8) |r| for (0..8) |f| {
        t[21 + 10 * r + f] = @truncate(78 * (8 * r + f) -% 6);
    };
    break :blk t;
};

/// Number of words in the hash random table.
pub const random_table_words = 0x9E7;

/// The hash random table, built at start-up by 0000:74B9..750B into the segment
/// `[A512]`: srand(1) (4793:89C6), then for word k = 0..2534, `w = rand() | mask[k mod 8]`,
/// and if the next rand() is odd, `w += 8000h` (16-bit). rand() (4793:89D8) is the
/// Microsoft C generator: `seed = seed * 214013 + 2531011` (32-bit, wrapping),
/// result `(seed >> 16) & 7FFFh`. The masks are DG:12B6. Built here at compile time;
/// 5,070 bytes, words little-endian.
pub const random_table: [2 * random_table_words]u8 = blk: {
    @setEvalBranchQuota(200_000);
    const mask = [8]u16{ 0x92E1, 0x121F, 0x58BC, 0x3699, 0x7BB9, 0x939D, 0x692C, 0x987E };
    var t: [2 * random_table_words]u8 = undefined;
    var seed: u32 = 1;
    for (0..random_table_words) |k| {
        seed = seed *% 214013 +% 2531011;
        var w: u16 = @as(u16, @truncate((seed >> 16) & 0x7FFF)) | mask[k % 8];
        seed = seed *% 214013 +% 2531011;
        if ((seed >> 16) & 1 != 0) w +%= 0x8000;
        t[2 * k] = @truncate(w);
        t[2 * k + 1] = @truncate(w >> 8);
    }
    break :blk t;
};

/// The 48-bit key at byte offset `o` of the random table. The original forms the
/// offset as a 16-bit sum (`[06C0 + 2s] + 6c`), which wraps for a1 (FFFAh + 6c).
inline fn randomKey(o: u16) u48 {
    return std.mem.readInt(u48, random_table[o..][0..6], .little);
}

/// The key of the piece whose code times 6 is `c6` on square `sq`.
inline fn pieceKey(sq: usize, c6: u8) u48 {
    return randomKey(hash_square_offset[sq] +% c6);
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

inline fn sideIndex(comptime s: Side) usize {
    return @backingInt(s);
}

fn pawnCode(comptime s: Side) u8 {
    return if (s == .white) white_pawn else black_pawn;
}

fn kingCode(comptime s: Side) u8 {
    return if (s == .white) white_king else black_king;
}

/// Pawn attack steps of a side: White s+9, s+11; Black s-9, s-11.
fn attackSteps(comptime s: Side) [2]i8 {
    return if (s == .white) .{ 9, 11 } else .{ -9, -11 };
}

/// One rank forward for a side.
fn forward(comptime s: Side) i8 {
    return if (s == .white) 10 else -10;
}

/// Square plus a signed step. Out-of-range results trap in safe builds.
inline fn add(sq: usize, d: i32) usize {
    return @intCast(@as(i32, @intCast(sq)) + d);
}

/// The original's signed byte view of a slot number (slots are used as signed
/// offsets into the piece lists).
inline fn sbyte(x: u8) i32 {
    return @as(i8, @bitCast(x));
}

/// Is a square difference a knight step? The original reads a byte table at
/// DG:0A68 + d for d in -77..77, which is non-zero exactly for these.
inline fn isKnightStep(d: i32) bool {
    return switch (d) {
        -21, -19, -12, -8, 8, 12, 19, 21 => true,
        else => false,
    };
}

/// Add `v` to a balance with the sign of side `s` (White +, Black -), 16-bit wrap.
inline fn addSigned(x: *u16, comptime s: Side, v: u16) void {
    if (s == .white) x.* +%= v else x.* -%= v;
}

// ---------------------------------------------------------------------------
// The position
// ---------------------------------------------------------------------------

/// The search position: every variable make_move, unmake_move and update_hash_key
/// read or write (docs/arch/20-position-make-unmake.md, "The position state").
/// Fields that come in a White/Black pair are arrays indexed by `Side`.
pub const Position = struct {
    /// DG:9EF6: the search board, a 10x12 mailbox of piece codes.
    board: [120]u8 = @splat(0),
    /// DG:A03A (White, entries 0..15) and DG:A04A (Black, 16..31): the square of the
    /// piece in each slot. Slots 0-1 knights, 2-3 bishops, 4-5 rooks, 6 queen, 7 king,
    /// 8-15 pawns; a promoted pawn keeps its pawn slot. A captured piece's entry is
    /// its square plus 63h. The original indexes the two as one array,
    /// `side * 16 + slot`, with the slot as a signed byte.
    piece_list: [32]u8 = @splat(0),
    /// DG:A28C: the slot of the piece on each square, FFh when empty. Not exact: the
    /// square of a pawn captured en passant keeps its old entry (a quirk the search
    /// can see, kept).
    square_slot: [120]u8 = @splat(0),
    /// DG:A51C (White) and DG:37DA (Black): number of the side's pawns attacking each
    /// square.
    pawn_attacks: [2][120]u8 = @splat(@splat(0)),
    /// DG:A09E (White, codes 1..8) and DG:A164 (Black, codes 9..16): for each square on
    /// one of the 8 queen lines from the side's king, up to and including the first
    /// piece, the direction code; 0 elsewhere. A side's map is kept only while the
    /// opponent has a piece other than pawns and king.
    king_rays: [2][120]u8 = @splat(@splat(0)),
    /// DG:A8C8 (White) and DG:9EA8 (Black): pawns per file, index 1..8.
    pawns_per_file: [2][10]u8 = @splat(@splat(0)),
    /// DG:8DE4 (White) and DG:8DE6 (Black): material, pawns included (table DG:1498).
    material: [2]u16 = .{ 0, 0 },
    /// DG:AE38 (White) and DG:AE3A (Black): material without pawns.
    piece_material: [2]u16 = .{ 0, 0 },
    /// DG:378E: both sides' material without pawns.
    piece_material_sum: u16 = 0,
    /// DG:A420: both sides' material.
    total_material: u16 = 0,
    /// DG:A35E: White material minus Black.
    material_balance: u16 = 0,
    /// DG:A8D2: White material without pawns minus Black's.
    piece_balance: u16 = 0,
    /// DG:A4C6: a second balance, kept with tables DG:14D0 and DG:14EC (equal to the
    /// first pair).
    material_balance_2: u16 = 0,
    /// DG:7182: a piece-square sum kept by update_square_sums (0000:678A, not this
    /// unit). make_move subtracts 100 when White captures the piece in Black's slot 6
    /// and adds 100 when Black captures White's; unmake_move reverses it.
    piece_square_sum: u16 = 0,
    /// DG:154A: all men on the board, kings and pawns included.
    men: u8 = 0,
    /// DG:931A (White) and DG:931B (Black): pieces other than king and pawns.
    piece_count: [2]u8 = .{ 0, 0 },
    /// DG:90AA: both sides' pawns.
    pawn_count: u8 = 0,
    /// DG:AB1E (White) and DG:741A (Black): the side's pawns.
    side_pawn_count: [2]u8 = .{ 0, 0 },
    /// DG:B520 (White) and DG:A354 (Black): the side's pawns on dark squares.
    pawns_on_dark: [2]u8 = .{ 0, 0 },
    /// DG:A22E (White) and DG:A22F (Black): king's file, 1..8.
    king_file: [2]u8 = .{ 0, 0 },
    /// DG:70F0 (White) and DG:70F1 (Black): king's rank, 2..9. Not written by castling.
    king_rank: [2]u8 = .{ 0, 0 },
    /// DG:B426 (White) and DG:B428 (Black): game ply at which the side lost the right
    /// to castle king side; 0 while it is held.
    oo_lost_at: [2]u16 = .{ 0, 0 },
    /// DG:3A30 (White) and DG:3A32 (Black): the same for the queen side.
    ooo_lost_at: [2]u16 = .{ 0, 0 },
    /// DG:9FC8: +1 at the start of make_move, -1 at the end of unmake_move.
    game_ply: u16 = 0,
    /// DG:8CCC: the main hash key, 48 bits (three little-endian words in the original).
    hash_key: u48 = 0,
    /// DG:8CD2: the pawn hash key, 48 bits.
    pawn_hash_key: u48 = 0,
    /// DG:9EC8 + ply: the en-passant square made by the move at this ply, 0 if none.
    ep_square_by_ply: [max_ply]u8 = @splat(0),
    /// DG:8C06 + ply: 80h OR a non-zero check value if the move gives check, else 0.
    check_by_ply: [max_ply]u8 = @splat(0),
    /// DG:8BBE + 2 * ply: FFFFh after a move with flag 0 that is neither a capture nor
    /// a pawn move; 0 otherwise.
    reversible_by_ply: [max_ply]u16 = @splat(0),
    /// DG:3626 + 2 * ply: `from * 256 + to` after a non-capture with flag 0, else 0.
    quiet_move_by_ply: [max_ply]u16 = @splat(0),

    // ---- piece lists --------------------------------------------------------

    /// Square of a side's king (its slot 7).
    pub inline fn kingSquare(p: *const Position, comptime s: Side) u8 {
        return p.piece_list[16 * sideIndex(s) + 7];
    }

    /// The piece-list entry `side * 16 + slot`, the slot as a signed byte, as the
    /// original addresses it (A03A + side*16 + slot). Outside the two lists traps.
    inline fn listEntry(p: *Position, comptime s: Side, slot: u8) *u8 {
        return &p.piece_list[@intCast(16 * @as(i32, @backingInt(s)) + sbyte(slot))];
    }

    // ---- king ray maps -----------------------------------------------------

    /// Port of build_white_king_rays (1E9D:10E0) and build_black_king_rays
    /// (1E9D:1264). From king square k, along each queen line in the order +9, +11,
    /// -9, -11, +1, +10, -1, -10, write the direction code on every empty square and on
    /// the first piece (not the border). Clears nothing and leaves k itself alone.
    fn buildRays(p: *Position, comptime s: Side, k: u8) void {
        const steps = [8]i8{ 9, 11, -9, -11, 1, 10, -1, -10 };
        const m = &p.king_rays[sideIndex(s)];
        inline for (steps, 0..) |d, i| {
            const code: u8 = comptime 8 * @as(u8, @backingInt(s)) + @as(u8, i) + 1;
            var sq = add(k, d);
            while (p.board[sq] == empty) : (sq = add(sq, d)) m[sq] = code;
            if (p.board[sq] != border) m[sq] = code;
        }
    }

    /// Port of clear_white_king_rays (1E9D:13E8) and clear_black_king_rays
    /// (1E9D:147C): from k, in the order +9, +10, +11, -9, -10, -11, +1, -1, zero map
    /// entries while they are non-zero.
    fn clearRays(p: *Position, comptime s: Side, k: u8) void {
        const steps = [8]i8{ 9, 10, 11, -9, -10, -11, 1, -1 };
        const m = &p.king_rays[sideIndex(s)];
        inline for (steps) |d| {
            var sq = add(k, d);
            while (m[sq] != 0) : (sq = add(sq, d)) m[sq] = 0;
        }
    }

    /// If `sq` is on map `m`, continue its ray past `sq` over empty squares, then mark
    /// the first piece unless it is the border. The body of extend_rays_through
    /// (1E9D:1510) for one map; inline in make_move (02EE..0356) and unmake_move
    /// (0A7C..0B09).
    fn extendRay(p: *Position, m: *[120]u8, sq: usize) void {
        const code = m[sq];
        if (code == 0) return;
        const d = dir_step[code];
        var s = add(sq, d);
        while (p.board[s] == empty) : (s = add(s, d)) m[s] = code;
        if (p.board[s] != border) m[s] = code;
    }

    /// If `sq` is on map `m`, zero the entries beyond it along its ray while they are
    /// non-zero. The body of cut_rays_beyond (1E9D:15B1) for one map; inline in
    /// make_move (0368..03C1) and unmake_move (0B0B..0B58).
    fn cutRay(m: *[120]u8, sq: usize) void {
        const code = m[sq];
        if (code == 0) return;
        const d = dir_step[code];
        var s = add(sq, d);
        while (m[s] != 0) : (s = add(s, d)) m[s] = 0;
    }

    /// Port of extend_rays_through (1E9D:1510): the White king's map, then Black's.
    fn extendRaysThrough(p: *Position, sq: usize) void {
        p.extendRay(&p.king_rays[0], sq);
        p.extendRay(&p.king_rays[1], sq);
    }

    /// Port of cut_rays_beyond (1E9D:15B1): the White king's map, then Black's.
    fn cutRaysBeyond(p: *Position, sq: usize) void {
        cutRay(&p.king_rays[0], sq);
        cutRay(&p.king_rays[1], sq);
    }

    /// Walk from `sq` along direction `code` to the first non-empty square; is the
    /// piece there a slider along that direction? (make_move 06A1..06F8, 08D1..093A.)
    fn sliderBehind(p: *const Position, sq: usize, code: u8) bool {
        const d = dir_step[code];
        var s = add(sq, d);
        while (p.board[s] == empty) s = add(s, d);
        return slider_bits[p.board[s]] & dir_bit[code] != 0;
    }

    /// Port of the castling-key XORs 1E9D:160A (key 0, White O-O), 1637 (1, White
    /// O-O-O), 1664 (2, Black O-O), 1691 (3, Black O-O-O): XOR a key into the main
    /// hash key only.
    inline fn xorCastleKey(p: *Position, i: usize) void {
        p.hash_key ^= castle_keys[i];
    }

    /// Take away a side's castling right on a wing if it is still held: stamp it with
    /// the game ply and XOR its key (make_move 0124, 0168, 0264, 0290).
    inline fn loseRight(p: *Position, comptime s: Side, comptime wing: u1) void {
        const stamp = if (wing == 0) &p.oo_lost_at[sideIndex(s)] else &p.ooo_lost_at[sideIndex(s)];
        if (stamp.* == 0) {
            stamp.* = p.game_ply;
            p.xorCastleKey(2 * sideIndex(s) + wing);
        }
    }

    // ---- make_move ---------------------------------------------------------

    /// Port of make_move (1E9D:000C-095F). Makes `move` for `side` at search ply
    /// `ply`: the board, piece lists, slot map, pawn attacks, king ray maps, counts,
    /// material, castling stamps and castling-key XORs, and the per-ply records. The
    /// piece keys are not touched: the search calls update_hash_key first. Writes
    /// `undo.captured` always and `undo.captured_slot` for a capture or en passant.
    pub fn makeMove(p: *Position, move: Move, side: Side, ply: usize, undo: *Undo) void {
        switch (side) {
            inline else => |s| p.makeMoveSide(s, move, ply, undo),
        }
    }

    fn makeMoveSide(p: *Position, comptime us: Side, move: Move, ply: usize, undo: *Undo) void {
        const them = comptime us.other();
        const u = sideIndex(us);
        const t = sideIndex(them);
        const from: usize = move.from;
        const to: usize = move.to;
        const flag = move.flag;
        if (std.debug.runtime_safety and ply >= max_ply) @panic("make_move: ply beyond max_ply (DEV-002)");

        // 1. 0014
        p.game_ply +%= 1;
        // 2. 0018..003A
        var piece = p.board[from];
        var cap = p.board[to];
        p.board[to] = piece;
        p.board[from] = empty;
        // 3. 003F..0055
        p.ep_square_by_ply[ply] = 0;
        p.quiet_move_by_ply[ply] = 0;
        p.reversible_by_ply[ply] = 0xFFFF;
        var chk: u8 = 0;

        if (flag != flag_normal) {
            // 4. 006D: any flag makes the move irreversible.
            p.reversible_by_ply[ply] = 0;
            if (flag == flag_en_passant) {
                // 5. En passant (0600). cs: the captured pawn's square.
                const cs = add(to, -forward(us));
                cap = p.board[cs];
                const ta = attackSteps(them);
                const ua = attackSteps(us);
                p.pawn_attacks[t][add(cs, ta[0])] -%= 1;
                p.pawn_attacks[t][add(cs, ta[1])] -%= 1;
                p.pawns_on_dark[t] -%= dark[cs];
                p.pawn_attacks[u][add(from, ua[0])] -%= 1;
                p.pawn_attacks[u][add(from, ua[1])] -%= 1;
                p.pawn_attacks[u][add(to, ua[0])] +%= 1;
                p.pawn_attacks[u][add(to, ua[1])] +%= 1;
                if (p.pawn_attacks[u][p.kingSquare(them)] != 0) chk = @truncate(to);
                // 0683: the captured pawn's slot-map entry is left as it is.
                undo.captured_slot = p.square_slot[cs];
                p.board[cs] = empty;
                p.extendRaysThrough(cs);
                p.extendRaysThrough(from);
                p.cutRaysBeyond(to);
                // 06A1: discovered check through cs, on the opponent king's map.
                const code = p.king_rays[t][cs];
                if (code != 0 and p.sliderBehind(cs, code)) chk = code;
            } else if (flag == flag_castle) {
                // 6. Castling (0494).
                chk = p.castle(us, from, to);
            } else {
                // 7. Promotion (008E White, 06FC Black).
                p.pawn_count -%= 1;
                p.side_pawn_count[u] -%= 1;
                if (p.piece_count[u] == 0) p.buildRays(them, p.kingSquare(them));
                p.piece_count[u] +%= 1;
                p.pawns_per_file[u][file_of[from]] -%= 1;
                piece = if (us == .white) flag else flag +% 7;
                p.board[to] = piece;
                const ua = attackSteps(us);
                p.pawn_attacks[u][add(from, ua[0])] -%= 1;
                p.pawn_attacks[u][add(from, ua[1])] -%= 1;
                addSigned(&p.material_balance_2, us, promotion_gain_2[piece]);
                var g = promotion_gain[piece];
                p.material[u] +%= g;
                p.total_material +%= g;
                addSigned(&p.material_balance, us, g);
                g +%= 200;
                p.piece_material[u] +%= g;
                p.piece_material_sum +%= g;
                addSigned(&p.piece_balance, us, g);
                p.pawns_on_dark[u] -%= dark[from];
                if (piece == white_knight + 7 * @as(u8, u) and
                    isKnightStep(@as(i32, @intCast(to)) - p.kingSquare(them))) chk = @truncate(to);
                // 0788
                p.extendRaysThrough(from);
                if (cap == 0) p.cutRaysBeyond(to);
            }
        } else {
            // 8. Ordinary move: by the moving piece's code (010E, jump table cs:02D4).
            // The handler follows the piece's own colour, as the original's table does.
            switch (piece) {
                white_king => p.kingMoved(.white, from, to),
                black_king => p.kingMoved(.black, from, to),
                white_pawn => p.pawnMoved(.white, from, to, ply, &chk),
                black_pawn => p.pawnMoved(.black, from, to, ply, &chk),
                white_rook => p.rookMoved(.white, from),
                black_rook => p.rookMoved(.black, from),
                white_knight => {
                    if (isKnightStep(@as(i32, @intCast(to)) - p.kingSquare(.black))) chk = @truncate(to);
                },
                black_knight => {
                    if (isKnightStep(@as(i32, @intCast(to)) - p.kingSquare(.white))) chk = @truncate(to);
                },
                else => {},
            }
            // 02EE..03C1: the generic ray update.
            p.extendRaysThrough(from);
            if (cap == 0) p.cutRaysBeyond(to);
        }

        // 9. Capture or not (03C3).
        if (cap != 0) {
            // 03CE
            p.reversible_by_ply[ply] = 0;
            if (flag != flag_en_passant) undo.captured_slot = p.square_slot[to];
            const cslot = undo.captured_slot;
            // 03F4 White, 07D2 Black
            const s = p.square_slot[from];
            p.square_slot[to] = s;
            p.listEntry(us, s).* = @truncate(to);
            p.square_slot[from] = 0xFF;
            const entry = p.listEntry(them, cslot);
            entry.* +%= 0x63;
            if (sbyte(cslot) == 6) {
                // White capturing subtracts 100, Black capturing adds 100.
                if (us == .white) p.piece_square_sum -%= 100 else p.piece_square_sum +%= 100;
            }
            addSigned(&p.material_balance_2, us, piece_value_2[cap]);
            const v = piece_value[cap];
            p.material[t] -%= v;
            addSigned(&p.material_balance, us, v);
            p.total_material -%= v;
            p.men -%= 1;
            if (cap != pawnCode(them)) {
                p.piece_material[t] -%= v;
                p.piece_material_sum -%= v;
                addSigned(&p.piece_balance, us, v);
                p.piece_count[t] -%= 1;
                if (p.piece_count[t] == 0) p.clearRays(us, p.kingSquare(us));
            } else {
                p.pawn_count -%= 1;
                p.side_pawn_count[t] -%= 1;
                p.pawns_per_file[t][file_of[to]] -%= 1;
                if (flag == flag_normal) {
                    const ta = attackSteps(them);
                    p.pawn_attacks[t][add(to, ta[0])] -%= 1;
                    p.pawn_attacks[t][add(to, ta[1])] -%= 1;
                    p.pawns_on_dark[t] -%= dark[to];
                }
            }
            // 07AF / 0877: a pawn capturing changes file.
            if (piece == pawnCode(us)) {
                p.pawns_per_file[u][file_of[from]] -%= 1;
                p.pawns_per_file[u][file_of[to]] +%= 1;
            }
        } else {
            // 0894
            const s = p.square_slot[from];
            p.square_slot[to] = s;
            p.listEntry(us, s).* = @truncate(to);
            p.square_slot[from] = 0xFF;
            if (flag == flag_normal) p.quiet_move_by_ply[ply] = @truncate(from << 8 | to);
        }

        // 10. Check (08D1), unless a step above found one; on the opponent king's map.
        if (chk == 0) {
            const m = &p.king_rays[t];
            const code_to = m[to];
            if (code_to != 0 and slider_bits[piece] & dir_bit[code_to] != 0) {
                chk = code_to;
            } else {
                const code = m[from];
                if (code != 0 and code != code_to and p.sliderBehind(from, code)) chk = code;
            }
        }
        // 11. 093C..0953
        p.check_by_ply[ply] = if (chk != 0) chk | 0x80 else 0;
        undo.captured = cap;
    }

    /// make_move 0124 (White) / 0168 (Black): a king's ordinary move. Its ray map is
    /// moved only while the opponent has pieces.
    inline fn kingMoved(p: *Position, comptime s: Side, from: usize, to: usize) void {
        p.king_file[sideIndex(s)] = file_of[to];
        p.king_rank[sideIndex(s)] = rank_of[to];
        p.loseRight(s, 0);
        p.loseRight(s, 1);
        if (p.piece_count[1 - sideIndex(s)] != 0) {
            p.clearRays(s, @truncate(from));
            p.buildRays(s, @truncate(to));
        }
    }

    /// make_move 01AC (White) / 020E (Black): a pawn's ordinary move.
    inline fn pawnMoved(p: *Position, comptime s: Side, from: usize, to: usize, ply: usize, chk: *u8) void {
        const i = sideIndex(s);
        const o = 1 - i;
        // A double step next to an enemy pawn's attack makes an en-passant square. The
        // distance is taken as a byte.
        const dist: u8 = if (s == .white) @truncate(to -% from) else @truncate(from -% to);
        if (dist == 20 and p.pawn_attacks[o][add(to, -forward(s))] != 0)
            p.ep_square_by_ply[ply] = ep_square_after[i][file_of[to]];
        p.pawns_on_dark[i] +%= dark[to] -% dark[from];
        p.reversible_by_ply[ply] = 0;
        const a = attackSteps(s);
        p.pawn_attacks[i][add(from, a[0])] -%= 1;
        p.pawn_attacks[i][add(from, a[1])] -%= 1;
        p.pawn_attacks[i][add(to, a[0])] +%= 1;
        p.pawn_attacks[i][add(to, a[1])] +%= 1;
        if (p.pawn_attacks[i][p.kingSquare(s.other())] != 0) chk.* = @truncate(to);
    }

    /// make_move 0264 (White) / 0290 (Black): a rook leaving its corner takes away
    /// that wing's right. A rook captured on its corner does not take away the
    /// opponent's right here (kept).
    inline fn rookMoved(p: *Position, comptime s: Side, from: usize) void {
        const back: usize = if (s == .white) 0 else 70;
        if (from == 0x1C + back) p.loseRight(s, 0);
        if (from == 0x15 + back) p.loseRight(s, 1);
    }

    /// make_move, flag 6 (0494..05FC). The king is already on `to`. Moves the rook,
    /// stamps the castled wing's right unconditionally and XORs its key (whether the
    /// right was held is not tested), takes away the other wing's right if still
    /// held, sets the king's file (not its rank) and redoes the king's rays. The
    /// opponent king's map is not updated for the squares involved, and the generic
    /// ray update is skipped (both kept). Returns the check value.
    fn castle(p: *Position, comptime s: Side, from: usize, to: usize) u8 {
        const i = sideIndex(s);
        const o = 1 - i;
        const gp = p.game_ply;
        const king_side = to > from;
        const rook_from = if (king_side) to + 1 else to - 2;
        const rook_to = if (king_side) to - 1 else to + 1;
        p.board[rook_to] = p.board[rook_from];
        p.board[rook_from] = empty;
        const sl = p.square_slot[rook_from];
        p.square_slot[rook_to] = sl;
        p.listEntry(s, sl).* = @truncate(rook_to);
        if (king_side) {
            p.xorCastleKey(2 * i);
            p.oo_lost_at[i] = gp;
            if (p.ooo_lost_at[i] == 0) {
                p.ooo_lost_at[i] = gp;
                p.xorCastleKey(2 * i + 1);
            }
            p.king_file[i] = 7;
        } else {
            p.xorCastleKey(2 * i + 1);
            p.ooo_lost_at[i] = gp;
            if (p.oo_lost_at[i] == 0) {
                p.oo_lost_at[i] = gp;
                p.xorCastleKey(2 * i);
            }
            p.king_file[i] = 3;
        }
        if (p.piece_count[o] != 0) {
            p.clearRays(s, @truncate(from));
            p.buildRays(s, @truncate(to));
        }
        const chk = castle_check[i][p.king_rays[o][rook_to]];
        p.square_slot[rook_from] = 0xFF;
        return chk;
    }

    // ---- unmake_move -------------------------------------------------------

    /// Port of unmake_move (1E9D:0960-10C5). Takes back `move` for `side`, given the
    /// two bytes make_move left in `undo`. Does not restore the per-ply records, the
    /// hash keys (the search copies back the 12 key bytes it saved; castling-key
    /// XORs included) or the king's rank after castling. Writes
    /// `undo.captured_slot` = 80h after a capture and 0 otherwise; leaves
    /// `undo.captured` alone.
    pub fn unmakeMove(p: *Position, move: Move, side: Side, undo: *Undo) void {
        switch (side) {
            inline else => |s| p.unmakeMoveSide(s, move, undo),
        }
    }

    fn unmakeMoveSide(p: *Position, comptime us: Side, move: Move, undo: *Undo) void {
        const them = comptime us.other();
        const u = sideIndex(us);
        const t = sideIndex(them);
        const from: usize = move.from;
        const to: usize = move.to;
        const flag = move.flag;
        const cap = undo.captured;
        // The piece on `to` now: the promoted piece after a promotion.
        const piece = p.board[to];
        const ua = attackSteps(us);

        // 1. By flag, compared as a signed byte with 1 (0986 White, 0D24 Black): a flag
        // of 80h or more takes the ordinary path here, unlike in make_move.
        const fl: i8 = @bitCast(flag);
        if (fl < 1) {
            // Ordinary (0A18 / 0DB8).
            p.board[from] = piece;
            p.board[to] = cap;
            if (piece == pawnCode(us)) {
                // 0A94 / 0E34
                p.pawns_on_dark[u] -%= dark[to] -% dark[from];
                p.pawn_attacks[u][add(from, ua[0])] +%= 1;
                p.pawn_attacks[u][add(from, ua[1])] +%= 1;
                p.pawn_attacks[u][add(to, ua[0])] -%= 1;
                p.pawn_attacks[u][add(to, ua[1])] -%= 1;
            } else if (piece == kingCode(us) or piece == kingCode(us) - 2) {
                if (piece == kingCode(us)) {
                    // 0A36 / 0DD6
                    p.king_file[u] = file_of[from];
                    p.king_rank[u] = rank_of[from];
                    if (p.piece_count[t] != 0) {
                        p.clearRays(us, @truncate(to));
                        p.buildRays(us, @truncate(from));
                    }
                }
                // 0A53 / 0DF3: a right lost at this game ply is given back.
                if (p.oo_lost_at[u] == p.game_ply) p.oo_lost_at[u] = 0;
                if (p.ooo_lost_at[u] == p.game_ply) p.ooo_lost_at[u] = 0;
            }
            // 0A71 / 0E11
            if (cap == 0) p.extendRaysThrough(to);
            p.cutRaysBeyond(from);
        } else if (fl == 1) {
            // En passant (0C86 / 1026). The captured pawn is put back as the opponent's
            // pawn code.
            p.board[from] = piece;
            p.board[to] = empty;
            const cs = add(to, -forward(us));
            p.board[cs] = pawnCode(them);
            const ta = attackSteps(them);
            p.pawn_attacks[u][add(from, ua[0])] +%= 1;
            p.pawn_attacks[u][add(from, ua[1])] +%= 1;
            p.pawn_attacks[u][add(to, ua[0])] -%= 1;
            p.pawn_attacks[u][add(to, ua[1])] -%= 1;
            p.pawn_attacks[t][add(cs, ta[0])] +%= 1;
            p.pawn_attacks[t][add(cs, ta[1])] +%= 1;
            p.pawns_on_dark[t] +%= dark[cs];
            p.extendRaysThrough(to);
            p.cutRaysBeyond(from);
            p.cutRaysBeyond(cs);
        } else if (fl == 6) {
            // Castling (0BE8 / 0F88). The castled wing's stamp is cleared
            // unconditionally, the other only if it equals the game ply. The castling-key
            // XORs are not undone.
            p.board[from] = piece;
            p.board[to] = empty;
            p.king_file[u] = 5;
            const king_side = to > from;
            const rook_home = if (king_side) to + 1 else to - 2;
            const rook_now = if (king_side) to - 1 else to + 1;
            p.board[rook_home] = p.board[rook_now];
            p.board[rook_now] = empty;
            const sl = p.square_slot[rook_now];
            p.square_slot[rook_home] = sl;
            p.listEntry(us, sl).* = @truncate(rook_home);
            p.square_slot[rook_now] = 0xFF;
            if (king_side) {
                p.oo_lost_at[u] = 0;
                if (p.ooo_lost_at[u] == p.game_ply) p.ooo_lost_at[u] = 0;
            } else {
                p.ooo_lost_at[u] = 0;
                if (p.oo_lost_at[u] == p.game_ply) p.oo_lost_at[u] = 0;
            }
            if (p.piece_count[t] != 0) {
                p.clearRays(us, @truncate(to));
                p.buildRays(us, @truncate(from));
            }
        } else {
            // Promotion (09A0 / 0D40).
            p.pawn_count +%= 1;
            p.side_pawn_count[u] +%= 1;
            p.piece_count[u] -%= 1;
            if (p.piece_count[u] == 0) p.clearRays(them, p.kingSquare(them));
            p.pawns_per_file[u][file_of[from]] +%= 1;
            p.board[from] = pawnCode(us);
            p.pawn_attacks[u][add(from, ua[0])] +%= 1;
            p.pawn_attacks[u][add(from, ua[1])] +%= 1;
            p.pawns_on_dark[u] +%= dark[from];
            addSigned(&p.material_balance_2, them, promotion_gain_2[piece]);
            var g = promotion_gain[piece];
            p.material[u] -%= g;
            addSigned(&p.material_balance, them, g);
            p.total_material -%= g;
            g +%= 200;
            p.piece_material[u] -%= g;
            p.piece_material_sum -%= g;
            addSigned(&p.piece_balance, them, g);
            p.board[to] = cap;
            if (cap == 0) p.extendRaysThrough(to);
            p.cutRaysBeyond(from);
        }

        // 2. Piece list (0B5A / 0EFA).
        const s = p.square_slot[to];
        p.square_slot[from] = s;
        p.listEntry(us, s).* = @truncate(from);
        p.square_slot[to] = 0xFF;

        if (cap == 0) {
            // 3. 10B6
            undo.captured_slot = 0;
        } else {
            // 4. Captured material back (0B7E).
            addSigned(&p.material_balance_2, them, piece_value_2[cap]);
            const v = piece_value[cap];
            p.material[t] +%= v;
            addSigned(&p.material_balance, them, v);
            p.total_material +%= v;
            p.men +%= 1;
            if (cap != pawnCode(them)) {
                p.piece_material[t] +%= v;
                p.piece_material_sum +%= v;
                addSigned(&p.piece_balance, them, v);
                if (p.piece_count[t] == 0) p.buildRays(us, p.kingSquare(us));
                p.piece_count[t] +%= 1;
            } else {
                p.pawn_count +%= 1;
                p.side_pawn_count[t] +%= 1;
                p.pawns_per_file[t][file_of[to]] +%= 1;
                if (flag == flag_normal) {
                    const ta = attackSteps(them);
                    p.pawn_attacks[t][add(to, ta[0])] +%= 1;
                    p.pawn_attacks[t][add(to, ta[1])] +%= 1;
                    p.pawns_on_dark[t] +%= dark[to];
                }
            }
            if (piece == pawnCode(us)) {
                // 0CDA / 107A
                p.pawns_per_file[u][file_of[from]] +%= 1;
                p.pawns_per_file[u][file_of[to]] -%= 1;
            }
            // 5. Captured slot back (0CF5 / 1095).
            const cslot = undo.captured_slot;
            const entry = p.listEntry(them, cslot);
            entry.* -%= 0x63;
            if (sbyte(cslot) == 6) {
                if (us == .white) p.piece_square_sum +%= 100 else p.piece_square_sum -%= 100;
            }
            p.square_slot[entry.*] = cslot;
            undo.captured_slot = 0x80;
        }
        // 6. 10BC
        p.game_ply -%= 1;
    }

    // ---- hash keys ---------------------------------------------------------

    /// Port of update_hash_key (4793:3EA2-4023). Called by the search with the move
    /// just before make_move; reads the board before the move and XORs the move's
    /// piece keys into the main key and, for pawns, into the pawn key.
    ///
    /// The products `6 * code` and `6 * flag` are bytes in the original (8-bit wrap);
    /// the key offset is a 16-bit sum.
    ///
    /// DEV-001: for an en-passant capture the original removes the captured pawn on
    /// `from + 10` (White capturing) or `from - 10` (Black) instead of `to - 10` or
    /// `to + 10`, where it stands. `fixes.dev001_ep_hash_square` corrects it.
    pub fn updateHashKey(p: *Position, move: Move, comptime fixes: Fixes) void {
        const from: usize = move.from;
        const to: usize = move.to;
        var cl: u8 = p.board[from] *% 6; // the mover, times 6
        var dl: u8 = p.board[to] *% 6; // the captured piece, times 6
        const bh: u8 = move.flag *% 6;
        var sq = to; // where the captured piece is removed
        var main = p.hash_key;
        var pawn = p.pawn_hash_key;

        // 3EDE: remove the mover from `from`.
        if (cl == 6 or cl == 0x30) {
            const k = pieceKey(from, cl);
            main ^= k;
            pawn ^= k;
            // A promotion (6 < 6*flag < 24h, signed): place the promoted piece instead.
            const bs: i8 = @bitCast(bh);
            if (bs > 6 and bs < 0x24) cl = cl +% bh -% 6;
        } else {
            main ^= pieceKey(from, cl);
        }
        // 3F34: place it on `to`.
        if (cl == 6 or cl == 0x30) {
            const k = pieceKey(to, cl);
            main ^= k;
            pawn ^= k;
            if (bh == 6) {
                // En passant (3F70..3F81).
                if (cl == 6) {
                    sq = if (fixes.dev001_ep_hash_square) to - 10 else from + 10;
                    dl = 0x30;
                } else {
                    sq = if (fixes.dev001_ep_hash_square) to + 10 else from - 10;
                    dl = 6;
                }
            }
        } else {
            main ^= pieceKey(to, cl);
        }
        // 3F96: remove the captured piece.
        if (dl != 0) {
            const k = pieceKey(sq, dl);
            main ^= k;
            if (dl == 6 or dl == 0x30) pawn ^= k;
        } else if (bh == 0x24) {
            // 3FD2: castling, the rook (king code * 6 - 12 = rook code * 6).
            cl -%= 12;
            const rook_from = if (to > from) from + 3 else from - 4;
            const rook_to = if (to > from) to - 1 else to + 1;
            main ^= pieceKey(rook_from, cl) ^ pieceKey(rook_to, cl);
        }
        p.hash_key = main;
        p.pawn_hash_key = pawn;
    }

    /// update_hash_key with the fix chosen at run time.
    pub fn updateHashKeyWith(p: *Position, move: Move, fix_dev001: bool) void {
        if (fix_dev001) p.updateHashKey(move, .corrected) else p.updateHashKey(move, .original);
    }

    /// Port of hash_from_scratch (4793:4026): the keys of the board alone. Squares
    /// 21..98 in order, empty and border squares skipped, pawns in both keys; then the
    /// castling key of each right whose stamp is non-zero (4793:412E).
    // The same code as `position.zig`'s copy, which the replay of prepare_eval's recorded
    // calls (evaltables_test) proves against the original; position_test ("hash_from_scratch
    // equals the reference on random walks") compares the two.
    pub fn hashFromScratch(p: *const Position) struct { main: u48, pawn: u48 } {
        var main: u48 = 0;
        var pawn: u48 = 0;
        for (21..99) |sq| {
            const c = p.board[sq];
            if (c == empty or c == border) continue;
            const k = randomKey(hash_square_offset[sq] +% @as(u16, c) * 6);
            main ^= k;
            if (c == white_pawn or c == black_pawn) pawn ^= k;
        }
        const stamps = [4]u16{ p.oo_lost_at[0], p.ooo_lost_at[0], p.oo_lost_at[1], p.ooo_lost_at[1] };
        for (stamps, 0..) |st, i| {
            if (st != 0) main ^= castle_keys[i];
        }
        return .{ .main = main, .pawn = pawn };
    }
};
