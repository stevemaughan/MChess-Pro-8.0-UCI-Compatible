//! How a position gets into the engine: the search position built from a board.
//!
//! Port of build_position_from_setup (38C0:6788-6E3F), the check test it calls
//! (38C0:6E82 with 38C0:6EB0 and 38C0:70C4), and Setup mode's legality test
//! (38C0:6542 with 38C0:6E40). Specification: docs/arch/23-position-setup.md; the
//! proved model is tools/research/setup/model.py.
//!
//! The original rebuilds every field of the search position (src/position.zig) by
//! scanning a board, except the ones listed under "not written" in the
//! specification (men, pawns on dark squares, the second balance, the piece-square
//! sum, the reversible and quiet records, per-ply records beyond ply 34): those keep
//! whatever the Position held before, exactly as in the original, where the search
//! recomputes the first four at its start.
//!
//! **Slot order is behaviour.** Move generation walks the piece lists in slot order,
//! so the rule below that assigns pieces to slots decides move order. A position set
//! up here is not the same, slot for slot, as the same position reached by playing
//! moves from the start (new game puts the g1 knight in slot 0, this puts b1 there).

const std = @import("std");
const pos = @import("position.zig");
const original = @import("original.zig");
const fen = @import("fen.zig");
const Position = pos.Position;

// ---------------------------------------------------------------------------
// Constant tables, read from the original's initialised data
// ---------------------------------------------------------------------------

/// DG:100A: file of a square (0 and 9 on the border files).
const file_of = original.dgroup(0x100A, 110);
/// DG:1078: rank of a square (rank 1 = 2 .. rank 8 = 9).
const rank_of = original.dgroup(0x1078, 100);
/// DG:0E16: 1 on dark squares (a1 dark), 100 entries.
const dark = original.dgroup(0x0E16, 100);
/// DG:0CFF + d (d = -77..77): non-zero when two squares are a king step apart.
const king_step = original.dgroup(0x0CFF - 77, 155);

fn kingAdjacent(a: u8, b: u8) bool {
    return king_step[@intCast(@as(i32, a) - @as(i32, b) + 77)] != 0;
}

/// A piece-list entry with no piece after a build (38C0:6790).
pub const empty_slot: u8 = 0x78;

// ---------------------------------------------------------------------------
// The variables the build reads and writes besides the Position
// ---------------------------------------------------------------------------

/// The set-up board and the game-state variables 38C0:6788 reads or writes outside
/// the search position. Each field names its DGROUP address.
pub const SetupVars = struct {
    /// DG:8C42: the board Setup mode edits, 10x12 like the search board; index 120
    /// is DG:8CBA, which the build sets to 7 so that an empty piece-list entry (78h)
    /// reads as the border. The build cleans squares 21..98 in place and rewrites the
    /// border files. Its outer rows (0..19, 100..119) must hold 7 (new game writes
    /// them, 0000:9276); the check test scans into them.
    board: [121]u8 = @splat(7),
    /// DG:717C: the side to move the build reads (0 White, 1 Black).
    side: u8 = 0,
    /// DG:9FC6: the side to move as the Setup editor holds it. The check test reads
    /// this one, not DG:717C (equal on the Setup path, 38C0:6354).
    setup_side: u8 = 0,
    /// DG:90B8: the en-passant square copied into ep_square_by_ply[0]; Setup mode
    /// sets 0, the position loader (0EF8:6AA3) the square read from the file.
    ep_square: u8 = 0,

    // ---- outputs -------------------------------------------------------------
    /// DG:776C: the saved set-up board (squares 21..98 written), replayed when moves
    /// are taken back in a game that began from a set-up (38C0:16EF, 38C0:4D72).
    saved_setup: [120]u8 = @splat(0),
    /// DG:7520: the game (displayed) board, a copy of the search board.
    game_board: [120]u8 = @splat(0),
    /// DG:AE44, DG:9EEC, DG:B42A: copies of the side to move (bytes).
    side_ae44: u8 = 0,
    side_9eec: u8 = 0,
    setup_side_saved: u8 = 0,
    /// DG:A36A: the side to move, sign-extended to a word.
    side_word: u16 = 0,
    /// DG:8DDE: the side the program plays, 1 - side (the user is to move).
    computer_side: u8 = 0,
    /// DG:7328: 1 when the side to move is in check, else 0.
    in_check: u8 = 0,
    /// DG:70E4: 1: the book is not used (a set-up position).
    book_off: u8 = 0,
    /// DG:9FBC: book exit ply, FF9Ch (-100).
    book_exit_ply: u16 = 0,
    /// DG:A84A: move number, 1.
    move_number: u16 = 0,
    /// DG:7464: last irreversible ply, 1.
    last_irreversible_ply: u16 = 0,
    /// DG:A5E6, DG:A5E8: copies of the O-O stamps (White, Black).
    oo_copy: [2]u16 = .{ 0, 0 },
    /// DG:A6A4, DG:A6A6: copies of the O-O-O stamps.
    ooo_copy: [2]u16 = .{ 0, 0 },
    /// Bytes set to 0: DG:B42B (pv_length), DG:A4F3, DG:A4FA (stop_flag).
    zero_bytes: [3]u8 = .{ 0, 0, 0 },
    /// Words set to 0: DG:A8DA, 153C, 9D92, A6AE, 2A8E, A3FA, A414.
    zero_words: [7]u16 = @splat(0),
};

// ---------------------------------------------------------------------------
// Check tests on the set-up board (38C0:6EB0, 38C0:70C4)
// ---------------------------------------------------------------------------

inline fn at(b: *const [121]u8, sq: i32) u8 {
    return b[@intCast(sq)];
}

/// First non-empty code along a ray (the border, 7, stops it).
fn rayEnd(b: *const [121]u8, sq: u8, d: i32) u8 {
    var s: i32 = @as(i32, sq) + d;
    while (at(b, s) == 0) s += d;
    return at(b, s);
}

const knight_steps = [8]i32{ 8, 12, 19, 21, -8, -12, -19, -21 };

/// Port of 38C0:6EB0 (wk, bk): is the White king attacked on the set-up board?
/// 9 when the kings touch; the square of a checking Black pawn (wk+9, then wk+11)
/// or knight (steps in `knight_steps` order); else the direction code of the first
/// checking slider, rays in the order +1 (5), -1 (7), +10 (6), -10 (8) for a queen or
/// rook, then +9 (1), +11 (2), -9 (3), -11 (4) for a queen or bishop; else 0.
pub fn whiteKingAttacked(b: *const [121]u8, wk: u8, bk: u8) u16 {
    if (kingAdjacent(wk, bk)) return 9;
    const k: i32 = wk;
    for ([2]i32{ 9, 11 }) |d| if (at(b, k + d) == pos.black_pawn) return @intCast(k + d);
    for (knight_steps) |d| if (at(b, k + d) == pos.black_knight) return @intCast(k + d);
    const rays = [8]struct { d: i32, code: u16, other: u8 }{
        .{ .d = 1, .code = 5, .other = pos.black_rook },    .{ .d = -1, .code = 7, .other = pos.black_rook },
        .{ .d = 10, .code = 6, .other = pos.black_rook },   .{ .d = -10, .code = 8, .other = pos.black_rook },
        .{ .d = 9, .code = 1, .other = pos.black_bishop },  .{ .d = 11, .code = 2, .other = pos.black_bishop },
        .{ .d = -9, .code = 3, .other = pos.black_bishop }, .{ .d = -11, .code = 4, .other = pos.black_bishop },
    };
    for (rays) |r| {
        const c = rayEnd(b, wk, r.d);
        if (c == pos.black_queen or c == r.other) return r.code;
    }
    return 0;
}

/// Port of 38C0:70C4 (wk, bk): the mirror for the Black king. 10 when the kings
/// touch; a White pawn on bk-9, then bk-11; a White knight; sliders +1 (13), -1 (15),
/// +10 (14), -10 (16), +9 (9), +11 (10), -9 (11), -11 (12); else 0.
pub fn blackKingAttacked(b: *const [121]u8, wk: u8, bk: u8) u16 {
    if (kingAdjacent(bk, wk)) return 10;
    const k: i32 = bk;
    for ([2]i32{ -9, -11 }) |d| if (at(b, k + d) == pos.white_pawn) return @intCast(k + d);
    for (knight_steps) |d| if (at(b, k + d) == pos.white_knight) return @intCast(k + d);
    const rays = [8]struct { d: i32, code: u16, other: u8 }{
        .{ .d = 1, .code = 13, .other = pos.white_rook },    .{ .d = -1, .code = 15, .other = pos.white_rook },
        .{ .d = 10, .code = 14, .other = pos.white_rook },   .{ .d = -10, .code = 16, .other = pos.white_rook },
        .{ .d = 9, .code = 9, .other = pos.white_bishop },   .{ .d = 11, .code = 10, .other = pos.white_bishop },
        .{ .d = -9, .code = 11, .other = pos.white_bishop }, .{ .d = -11, .code = 12, .other = pos.white_bishop },
    };
    for (rays) |r| {
        const c = rayEnd(b, bk, r.d);
        if (c == pos.white_queen or c == r.other) return r.code;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Setup mode's legality test (38C0:6542, 38C0:6E40)
// ---------------------------------------------------------------------------

/// The result of `legality`, with the messages of ENGLISH.T80.
pub const Legality = enum(u16) {
    legal = 0,
    no_white_king = 1,
    too_many_white_kings = 2,
    no_black_king = 3,
    too_many_black_kings = 4,
    too_many_white_pawns = 5,
    too_many_white_pieces = 6,
    too_many_black_pawns = 7,
    too_many_black_pieces = 8,
    white_in_check = 9,
    black_in_check = 10,
};

/// Port of setup_legality (38C0:6542): the checks Setup mode applies, in order, to
/// the set-up board before it is saved. Kings and pieces are counted on squares
/// 21..98, pawns on 31..88 only. "Extra" men are the pawns plus every knight and rook
/// beyond two, queen beyond one, and bishop beyond one on each square colour; more
/// than eight is too many. Then the side not to move must not be in check
/// (38C0:6E40, with the last king of each colour found).
pub fn legality(b: *const [121]u8, setup_side: u8) Legality {
    var wk: u8 = 0;
    var bk: u8 = 0;
    var nwk: u32 = 0;
    var nbk: u32 = 0;
    for (0x15..0x63) |s| {
        if (b[s] == pos.white_king) {
            nwk += 1;
            wk = @intCast(s);
        }
    }
    if (nwk == 0) return .no_white_king;
    if (nwk > 1) return .too_many_white_kings;
    for (0x15..0x63) |s| {
        if (b[s] == pos.black_king) {
            nbk += 1;
            bk = @intCast(s);
        }
    }
    if (nbk == 0) return .no_black_king;
    if (nbk > 1) return .too_many_black_kings;
    inline for (.{ pos.Side.white, pos.Side.black }) |side| {
        const off: u8 = if (side == .white) 0 else 7;
        const too_many_pawns: Legality = if (side == .white) .too_many_white_pawns else .too_many_black_pawns;
        const too_many: Legality = if (side == .white) .too_many_white_pieces else .too_many_black_pieces;
        var extra: u32 = 0;
        for (0x1F..0x59) |s| extra += @intFromBool(b[s] == 1 + off);
        if (extra > 8) return too_many_pawns;
        var n = count(b, 2 + off, null);
        if (n > 2) {
            extra += n - 2;
            if (extra > 8) return too_many;
        }
        n = count(b, 4 + off, null);
        if (n > 2) {
            extra += n - 2;
            if (extra > 8) return too_many;
        }
        n = count(b, 5 + off, null);
        if (n > 1) {
            extra += n - 1;
            if (extra > 8) return too_many;
        }
        n = count(b, 3 + off, true);
        if (n > 1) {
            extra += n - 1;
            if (extra > 8) return too_many;
        }
        // Light-squared bishops: the sum is tested but not stored (66AE/6765); it is
        // the last count of the side, so nothing follows that could see the difference.
        n = count(b, 3 + off, false);
        if (n > 1 and extra + n - 1 > 8) return too_many;
    }
    if (setup_side != 0)
        return if (whiteKingAttacked(b, wk, bk) >= 1) .white_in_check else .legal;
    return if (blackKingAttacked(b, wk, bk) >= 1) .black_in_check else .legal;
}

fn count(b: *const [121]u8, code: u8, on_dark: ?bool) u32 {
    var n: u32 = 0;
    for (0x15..0x63) |s| {
        if (b[s] != code) continue;
        if (on_dark) |d| if ((dark[s] != 0) != d) continue;
        n += 1;
    }
    return n;
}

// ---------------------------------------------------------------------------
// build_position_from_setup (38C0:6788)
// ---------------------------------------------------------------------------

/// From king square k, along each queen line in the order +9, +11, -9, -11, +1, +10,
/// -1, -10, write the direction code on every empty square and on the first piece
/// unless it is the border (1E9D:10E0 for White, codes 1..8; 1E9D:1264 for Black,
/// codes 9..16). The same as Position's private buildRays, which this unit may not
/// call.
fn buildRays(p: *Position, side: usize, k: u8) void {
    const steps = [8]i32{ 9, 11, -9, -11, 1, 10, -1, -10 };
    for (steps, 0..) |d, i| {
        const code: u8 = @intCast(8 * side + i + 1);
        var s: i32 = @as(i32, k) + d;
        while (p.board[@intCast(s)] == pos.empty) : (s += d) p.king_rays[side][@intCast(s)] = code;
        if (p.board[@intCast(s)] != pos.border) p.king_rays[side][@intCast(s)] = code;
    }
}

/// Port of build_position_from_setup (38C0:6788). Builds the search position `p`
/// from the set-up board `v.board`, the side to move `v.side`, the check side
/// `v.setup_side` and the en-passant square `v.ep_square`, and writes the game-state
/// variables of `v`. Fields of `p` the original does not write keep their values.
/// The board's outer rows (0..20, 99..119 and the border files) must already hold 7,
/// as they always do in the original; only squares 21..98 are copied.
pub fn build(p: *Position, v: *SetupVars) void {
    // 6790..67A9: lists to 78h; slot map 0..98 to FFh.
    @memset(&p.piece_list, empty_slot);
    @memset(p.square_slot[0..0x63], 0xFF);
    // 67AB..67D8: the maps and pawn attacks (the original clears 198 bytes from each,
    // running into neighbouring variables that are not part of this unit).
    for (&p.king_rays) |*m| @memset(m, 0);
    for (&p.pawn_attacks) |*m| @memset(m, 0);
    // 67DA..67E8: plies 0..34 of ep_square_by_ply and check_by_ply.
    @memset(p.ep_square_by_ply[0..0x23], 0);
    @memset(p.check_by_ply[0..0x23], 0);
    // 67F8..6851: the side to move and game-state variables.
    const side = v.side;
    const side_word: u16 = @bitCast(@as(i16, @as(i8, @bitCast(side))));
    v.side_ae44 = side;
    v.side_9eec = side;
    v.side_word = side_word;
    v.setup_side_saved = side;
    p.game_ply = side_word;
    v.computer_side = 1 -% side;
    v.zero_bytes = .{ 0, 0, 0 };
    v.in_check = 0;
    v.book_off = 1;
    v.book_exit_ply = 0xFF9C;
    v.zero_words = @splat(0);
    v.last_irreversible_ply = 1;
    v.move_number = 1;
    for (&p.pawns_per_file) |*f| @memset(f[1..9], 0);
    p.material = .{ 0, 0 };
    p.piece_material = .{ 0, 0 };
    p.piece_count = .{ 0, 0 };
    p.side_pawn_count = .{ 0, 0 };
    v.board[0x78] = 7;
    // 6884..68BB: clean squares 21..98.
    for (0x15..0x63) |s| {
        if (file_of[s] == 0 or file_of[s] == 9) {
            v.board[s] = 7;
        } else {
            const c: i8 = @bitCast(v.board[s]);
            if (c < 0 or c == 7 or c > 13) v.board[s] = 0;
        }
    }
    assignSlots(p, &v.board);
    // 6C8D..6CBC: totals.
    p.total_material = p.material[1] +% p.material[0];
    p.material_balance = p.material[0] -% p.material[1];
    p.piece_material_sum = p.piece_material[1] +% p.piece_material[0];
    p.piece_balance = p.piece_material[0] -% p.piece_material[1];
    p.pawn_count = p.side_pawn_count[1] +% p.side_pawn_count[0];
    // 6CBF..6D0A: castling stamps from the board alone: held (0) when the king is on
    // its e-square and the rook on the corner, else lost (FFFFh).
    p.oo_lost_at = .{ 0xFFFF, 0xFFFF };
    p.ooo_lost_at = .{ 0xFFFF, 0xFFFF };
    if (v.board[0x19] == pos.white_king) {
        if (v.board[0x1C] == pos.white_rook) p.oo_lost_at[0] = 0;
        if (v.board[0x15] == pos.white_rook) p.ooo_lost_at[0] = 0;
    }
    if (v.board[0x5F] == pos.black_king) {
        if (v.board[0x62] == pos.black_rook) p.oo_lost_at[1] = 0;
        if (v.board[0x5B] == pos.black_rook) p.ooo_lost_at[1] = 0;
    }
    v.oo_copy = p.oo_lost_at;
    v.ooo_copy = p.ooo_lost_at;
    // 6D28..6D39: the border files of the set-up board (20, 29, 30, ..., 90, 99).
    var s: usize = 0x63;
    while (s >= 0x1D) : (s -= 10) {
        v.board[s] = 7;
        v.board[s - 9] = 7;
    }
    // 6D3B..6D55: squares 21..98 to the search board and to the saved copy.
    @memcpy(p.board[0x15..0x63], v.board[0x15..0x63]);
    @memcpy(v.saved_setup[0x15..0x63], v.board[0x15..0x63]);
    // 6D57..6D7E: each king's map only if the other side has non-pawn material.
    const wk = p.piece_list[7];
    const bk = p.piece_list[16 + 7];
    if (p.piece_material[1] != 0) buildRays(p, 0, wk);
    if (p.piece_material[0] != 0) buildRays(p, 1, bk);
    // 6D81..6DA4: king file and rank.
    p.king_rank = .{ rank_of[wk], rank_of[bk] };
    p.king_file = .{ file_of[wk], file_of[bk] };
    // 6DA7: hash_from_scratch (4793:4026).
    const keys = p.hashFromScratch();
    p.hash_key = keys.main;
    p.pawn_hash_key = keys.pawn;
    // 6DB9..6DC8 (6E82): check value of the side to move, on the set-up board.
    const chk: u16 = if (v.setup_side != 0) blackKingAttacked(&v.board, wk, bk) else whiteKingAttacked(&v.board, wk, bk);
    p.check_by_ply[0] = @truncate(chk);
    if (p.check_by_ply[0] != 0) v.in_check = 1;
    // 6DF7..6DFA: the en-passant square.
    p.ep_square_by_ply[0] = v.ep_square;
    // 6E28..6E35: the game board.
    v.game_board = p.board;
}

/// 6887..6C8B: the kings, then for White and then Black: pawns (ranks 2..7 only),
/// knights, bishops, rooks, queens, each scanned from a1 (21) upwards. Slots: knights
/// 0, 1 for the first two; bishops: White's first light-squared in 2 and first
/// dark-squared in 3, Black's first dark-squared in 2 and light-squared in 3; rooks: a
/// rook on the a-corner in 5 and on the h-corner in 4, then the others into 5 and 4
/// while free; queen 6; king 7; pawns from 8 in scan order; every further piece
/// (a promoted one) in the next slot after the pawns, in the order pawns, knights,
/// bishops, rooks, queens.
fn assignSlots(p: *Position, sb: *const [121]u8) void {
    const wk = firstOf(sb, pos.white_king);
    p.piece_list[7] = wk;
    p.square_slot[wk] = 7;
    const bk = firstOf(sb, pos.black_king);
    p.piece_list[16 + 7] = bk;
    p.square_slot[bk] = 7;
    inline for (.{ 0, 1 }) |side| {
        const off: u8 = 7 * side;
        const L = p.piece_list[16 * side ..][0..16];
        var di: u8 = 8;
        const Helpers = struct {
            fn piece(q: *Position, value: u16) void {
                q.piece_count[side] +%= 1;
                q.material[side] +%= value;
                q.piece_material[side] +%= value;
            }
        };
        // pawns
        for (0x1F..0x59) |s| {
            if (sb[s] != 1 + off) continue;
            p.material[side] +%= 200;
            if (side == 0) {
                p.pawn_attacks[0][s + 9] +%= 1;
                p.pawn_attacks[0][s + 11] +%= 1;
            } else {
                p.pawn_attacks[1][s - 9] +%= 1;
                p.pawn_attacks[1][s - 11] +%= 1;
            }
            p.pawns_per_file[side][file_of[s]] +%= 1;
            L[di] = @intCast(s);
            p.square_slot[s] = di;
            di += 1;
            p.side_pawn_count[side] +%= 1;
        }
        // knights
        var dx: u8 = 0;
        for (0x15..0x63) |s| {
            if (sb[s] != 2 + off) continue;
            Helpers.piece(p, 650);
            if (dx < 2) {
                L[dx] = @intCast(s);
                p.square_slot[s] = dx;
                dx += 1;
            } else {
                L[di] = @intCast(s);
                p.square_slot[s] = di;
                di += 1;
            }
        }
        // bishops
        for (0x15..0x63) |s| {
            if (sb[s] != 3 + off) continue;
            Helpers.piece(p, 700);
            const on_dark = dark[s] != 0;
            const k: u8 = if (side == 0) (if (on_dark) 3 else 2) else (if (on_dark) 2 else 3);
            if (L[k] > 0x62) {
                L[k] = @intCast(s);
                p.square_slot[s] = k;
            } else {
                L[di] = @intCast(s);
                p.square_slot[s] = di;
                di += 1;
            }
        }
        // rooks
        const a_sq: u8 = if (side == 0) 0x15 else 0x5B;
        const h_sq: u8 = if (side == 0) 0x1C else 0x62;
        if (sb[a_sq] == 4 + off) {
            Helpers.piece(p, 1100);
            L[5] = a_sq;
            p.square_slot[a_sq] = 5;
        }
        if (sb[h_sq] == 4 + off) {
            Helpers.piece(p, 1100);
            L[4] = h_sq;
            p.square_slot[h_sq] = 4;
        }
        var si: u8 = 5;
        const lo: usize = if (side == 0) 0x16 else 0x15;
        const hi: usize = if (side == 0) 0x62 else 0x61;
        const skip: usize = if (side == 0) 0x1C else 0x5B;
        for (lo..hi + 1) |s| {
            if (s == skip or sb[s] != 4 + off) continue;
            // An entry of 78h reads DG:8CBA, which holds 7, so it is never a rook.
            if (sb[L[si]] == 4 + off) {
                si -= 1;
                if (sb[L[si]] == 4 + off) si -= 1;
            }
            Helpers.piece(p, 1100);
            if (si > 3) {
                L[si] = @intCast(s);
                p.square_slot[s] = si;
                si -= 1;
            } else {
                L[di] = @intCast(s);
                p.square_slot[s] = di;
                di += 1;
            }
        }
        // queens
        var qn: u8 = 6;
        for (0x15..0x63) |s| {
            if (sb[s] != 5 + off) continue;
            Helpers.piece(p, 2000);
            if (qn < 7) {
                L[6] = @intCast(s);
                p.square_slot[s] = 6;
                qn += 1;
            } else {
                L[di] = @intCast(s);
                p.square_slot[s] = di;
                di += 1;
            }
        }
    }
}

/// The first square from 21 upwards holding `code`; 99 when there is none (the
/// original's loop ends there and uses the counter as the square).
fn firstOf(sb: *const [121]u8, code: u8) u8 {
    for (0x15..0x63) |s| if (sb[s] == code) return @intCast(s);
    return 0x63;
}

// ---------------------------------------------------------------------------
// New game (0000:919A): the start position, written as constants
// ---------------------------------------------------------------------------

/// Piece lists of a new game: knights g1, b1; bishops f1, c1; rooks h1, a1; queen;
/// king; pawns a..h (Black: g8, b8, f8, c8, h8, a8, d8, e8, pawns a7..h7).
pub const new_game_lists = [32]u8{
    0x1B, 0x16, 0x1A, 0x17, 0x1C, 0x15, 0x18, 0x19, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
    0x61, 0x5C, 0x60, 0x5D, 0x62, 0x5B, 0x5E, 0x5F, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
};

/// Port of the search-position part of new_game_position (0000:919A-94E3): the start
/// position written as constants, not scanned. Its slot order differs from a set-up
/// start position's in the knights: g1 (g8) in slot 0, b1 (b8) in slot 1. Fields it
/// does not write (men, pawns on dark squares, the second balance, the piece-square
/// sum, the reversible and quiet records, per-ply records beyond ply 35) keep their
/// values. It also writes 7 on the outer rows and border files of the set-up board,
/// which the original's check_by_ply[60..63] alias (DG:8C42..8C45); `v.board`
/// receives those writes here, `p.check_by_ply` does not.
pub fn newGame(p: *Position, v: *SetupVars) void {
    // 91A2..9250: clears.
    @memset(&p.board, 0);
    for (&p.king_rays) |*m| @memset(m, 0);
    for (&p.pawn_attacks) |*m| @memset(m, 0);
    @memset(p.square_slot[0..100], 0xFF);
    // 9252..9271: pawn attacks on ranks 3 and 6.
    @memset(p.pawn_attacks[0][0x29..0x31], 2);
    @memset(p.pawn_attacks[1][0x47..0x4F], 2);
    p.pawn_attacks[0][0x29] = 1;
    p.pawn_attacks[0][0x30] = 1;
    p.pawn_attacks[1][0x47] = 1;
    p.pawn_attacks[1][0x4E] = 1;
    // 9273..92FC: borders of both boards, pawns, pawns per file.
    for (0..120) |sq| {
        if (sq < 20 or sq >= 100 or sq % 10 == 0 or sq % 10 == 9) {
            p.board[sq] = pos.border;
            v.board[sq] = pos.border;
        }
    }
    p.pawns_per_file = .{ .{ 0, 1, 1, 1, 1, 1, 1, 1, 1, 0 }, .{ 0, 1, 1, 1, 1, 1, 1, 1, 1, 0 } };
    const back = [8]u8{ 4, 2, 3, 5, 6, 3, 2, 4 };
    for (0..8) |f| {
        p.board[0x1F + f] = pos.white_pawn;
        p.board[0x51 + f] = pos.black_pawn;
        p.board[0x15 + f] = back[f];
        p.board[0x5B + f] = back[f] + 7;
    }
    // 92FE..93C5: piece lists and slots.
    p.piece_list = new_game_lists;
    for (new_game_lists, 0..) |sq, i| p.square_slot[sq] = @intCast(i % 16);
    // 93C8..93D6: plies 0..35 of ep_square_by_ply and check_by_ply.
    @memset(p.ep_square_by_ply[0..0x24], 0);
    @memset(p.check_by_ply[0..0x24], 0);
    // 93DD..9415: material and counts of the start position.
    p.material = .{ 0x2134, 0x2134 };
    p.total_material = 0x4268;
    p.piece_material = .{ 0x1AF4, 0x1AF4 };
    p.piece_material_sum = 0x35E8;
    p.piece_count = .{ 7, 7 };
    p.king_rank = .{ 2, 9 };
    p.king_file = .{ 5, 5 };
    p.pawn_count = 0x10;
    p.side_pawn_count = .{ 8, 8 };
    p.oo_lost_at = .{ 0, 0 };
    p.ooo_lost_at = .{ 0, 0 };
    p.piece_balance = 0;
    p.material_balance = 0;
    // 949C..94AD: both kings' maps.
    buildRays(p, 0, 0x19);
    buildRays(p, 1, 0x5F);
    p.game_ply = 0;
    // 94CA: hash_from_scratch.
    const keys = p.hashFromScratch();
    p.hash_key = keys.main;
    p.pawn_hash_key = keys.pawn;
}

// ---------------------------------------------------------------------------
// For the UCI layer: a board, the side to move, castling rights, an en-passant square
// ---------------------------------------------------------------------------

/// Builds the search position from what a FEN supplies, the way the original loads
/// a position from text (0EF8:69CC, at 6A9A..6AF0; the file format is not
/// determined): the side to move into DG:717C (and DG:9FC6), the en-passant square into DG:90B8, build (38C0:6788), then every
/// right the file does not give is stamped lost (FFFFh). A right the file gives is
/// held only if the king and rook stand on their home squares (the build's rule).
/// The original does not recompute the hash key after those stamps, so the main key
/// can lack the castling keys of rights the file takes away; this is reproduced.
///
/// The FEN's halfmove clock and fullmove number are not used: the original sets the
/// move number and the last irreversible ply to 1 for every built position. `v.board`'s
/// outer rows must hold 7 (the default).
///
/// A test helper, not the engine's path: the engine sets up a FEN through Setup mode
/// (`adapt_setup.enterFen`). The tests use it to build positions. The build it calls is
/// proved against the original; the loader's stamps after it (6A9A..6AF0) are a reading,
/// and the engine's own copy of them is `adapt_setup.withdrawRights`.
pub fn buildFromDescription(p: *Position, v: *SetupVars, d: *const fen.Description) void {
    // The search board's outer rows and border files hold 7 in the original from
    // start-up on (new game, 0000:9276); the build copies only squares 21..98.
    for (0..120) |sq| {
        if (sq < 21 or sq > 98 or sq % 10 == 0 or sq % 10 == 9) p.board[sq] = pos.border;
    }
    @memcpy(v.board[0..120], &d.board);
    v.side = @backingInt(d.side_to_move);
    v.setup_side = v.side;
    v.ep_square = d.en_passant orelse 0;
    build(p, v);
    if (!d.castling.white_short) p.oo_lost_at[0] = 0xFFFF;
    if (!d.castling.white_long) p.ooo_lost_at[0] = 0xFFFF;
    if (!d.castling.black_short) p.oo_lost_at[1] = 0xFFFF;
    if (!d.castling.black_long) p.ooo_lost_at[1] = 0xFFFF;
    v.oo_copy = p.oo_lost_at;
    v.ooo_copy = p.ooo_lost_at;
}

test "the start position set up: knights b1/g1 in slots 0/1, the reverse of a new game" {
    var v: SetupVars = .{};
    const back = [8]u8{ 4, 2, 3, 5, 6, 3, 2, 4 };
    for (0..120) |s| v.board[s] = if (s < 21 or s > 98 or s % 10 == 0 or s % 10 == 9) 7 else 0;
    for (0..8) |f| {
        v.board[21 + f] = back[f];
        v.board[31 + f] = 1;
        v.board[81 + f] = 8;
        v.board[91 + f] = back[f] + 7;
    }
    var p: Position = .{};
    for (0..120) |s| p.board[s] = if (s < 21 or s > 98 or s % 10 == 0 or s % 10 == 9) 7 else 0;
    build(&p, &v);
    try std.testing.expectEqualSlices(u8, &.{ 0x16, 0x1B, 0x1A, 0x17, 0x1C, 0x15, 0x18, 0x19 }, p.piece_list[0..8]);
    try std.testing.expectEqualSlices(u8, &.{ 0x5C, 0x61, 0x60, 0x5D, 0x62, 0x5B, 0x5E, 0x5F }, p.piece_list[16..24]);
    try std.testing.expectEqual(@as(u16, 0), p.oo_lost_at[0]);
    try std.testing.expectEqual(Legality.legal, legality(&v.board, 0));
}

test "buildFromDescription: rights from the FEN and the board; the key is not rebuilt (suspected bug 2)" {
    const d0 = try fen.parse(fen.startpos);
    var p: Position = .{};
    var v: SetupVars = .{};
    buildFromDescription(&p, &v, &d0);
    try std.testing.expectEqual(@as(u8, 0x16), p.piece_list[0]); // b1, not g1 as after new game
    try std.testing.expectEqual([2]u16{ 0, 0 }, p.oo_lost_at);
    try std.testing.expectEqual(p.hashFromScratch().main, p.hash_key);

    const d1 = try fen.parse("r3k2r/8/8/8/8/8/8/R3K2R w Kq - 0 1");
    buildFromDescription(&p, &v, &d1);
    try std.testing.expectEqual([2]u16{ 0, 0xFFFF }, p.oo_lost_at);
    try std.testing.expectEqual([2]u16{ 0xFFFF, 0 }, p.ooo_lost_at);
    try std.testing.expect(p.hashFromScratch().main != p.hash_key);
}

test "newGame: knights g1 and g8 in slot 0" {
    var p: Position = .{};
    var v: SetupVars = .{};
    newGame(&p, &v);
    try std.testing.expectEqual(@as(u8, 0x1B), p.piece_list[0]);
    try std.testing.expectEqual(@as(u8, 0x61), p.piece_list[16]);
    try std.testing.expectEqual(@as(u8, 0), p.square_slot[0x1B]);
    try std.testing.expectEqual(p.hashFromScratch().main, p.hash_key);
}
