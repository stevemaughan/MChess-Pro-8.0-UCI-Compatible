//! Test-only reference: src/helpers.zig as it was proved against the original before the
//! speed pass of 2026-11-18, kept unchanged so that src/helpers_test.zig can compare the
//! faster routines with it on inputs the recordings do not cover. Imported by
//! src/helpers_test.zig only; nothing in the engine uses it.
//!
//! The original header follows.
//!
//! The search helpers: the "in check" tests (0000:1C76 / 1DE6), the hash-move tests
//! (0000:1F56 / 211E), the attacked-piece counters (1E9D:CE3E / CC4E), the check-evasion
//! generator (38C0:E260, with its attack tests 38C0:DFA0 / E100) and the attack tests
//! static_eval calls (2B9F:4A76 / 4AD4).
//!
//! Specification: docs/arch/22-search-helpers.md, whose executable form is
//! tools/research/helpers/model.py (proved against the running original on every call of
//! five games and on direct calls on made-up positions). Test: src/helpers_test.zig, which
//! replays calls recorded from the original (tests/golden/helpers/*.zst, made by
//! tools/port/gen_helpers_vectors.py).
//!
//! Each White/Black pair is one function with the colour as a compile-time parameter;
//! every pair here is an exact mirror (spec §7: the differences listed for E260 and
//! 1F56 / 211E are of form only and give the same result on codes 0..13). None of the
//! suspected bugs of the specification is decided (docs/DEVIATIONS.md has no entry for
//! these routines), so there is no `Fixes` parameter: everything reproduces the original,
//! including the pawn-blind "in check" test (OBSERVATIONS.md), the second bishop skipped
//! by the counters (suspected bug 3), the pawn capture of a checker scored without the
//! defence test (suspected bug 2) and the `board[SI]` test after a slider's walk (5).
//!
//! A captured piece's list entry is its square + 63h (120 or more). Where the original
//! reads a byte beyond a 120-byte table at such an entry, the port reads 0: the evasion
//! generator skips the entry (the original dispatches on the byte at DG:9EF6 + entry), and
//! the counters count no pawn attack on a captured minor piece (the original reads the
//! pawn-attack count at DG:A51C / 37DA + entry; suspected bug 4). The vector tool checks
//! at every recorded call that those bytes are 0 or no piece code. The direction tables
//! are read with the captured entry as the original reads them (they cover -255..119).

const std = @import("std");
const pos = @import("position.zig");
const Position = pos.Position;
const Side = pos.Side;
const Move = pos.Move;
const mg = @import("movegen.zig");
const sortMoves = @import("sort.zig").sortMoves;
const dg = @import("original.zig").dgroup;

// ---------------------------------------------------------------------------
// Constant tables, from the original's initialised data
// ---------------------------------------------------------------------------

/// DG:0A68 + d, DG:0CFF + d, DG:0B66 + d, DG:0C64 + d for d = -255..119 (index d + 255):
/// non-zero when d is a knight step; non-zero when d is a king step; for d = target -
/// piece, the diagonal step from the target back towards the piece, or 0; the same for
/// ranks and files.
const knight_reach = dg(0x0A68 - 255, 375);
const king_reach = dg(0x0CFF - 255, 375);
const diagonal_dir: [375]i8 = @bitCast(dg(0x0B66 - 255, 375));
const line_dir: [375]i8 = @bitCast(dg(0x0C64 - 255, 375));
/// DG:1A52: king-capture value by victim code: P 3, N 8, B 8, R 14, Q 26, K 0, empty 0.
const king_capture_value = dg(0x1A52, 14);
/// DG:04A2: pawn steps 9, 11, 10, 20 (White adds them, Black subtracts), followed by the
/// rook steps at DG:04A6 (read only by a pawn on its first rank, which no game has).
const pawn_steps: [8]i8 = @bitCast(dg(0x04A2, 8));
/// DG:1508: knight steps (read from index 7 down).
const knight_steps: [8]i8 = @bitCast(dg(0x1508, 8));
/// DG:1510: king steps 9, 11, -9, -11, 1, 10, -1, -10 (read from index 7 down).
const king_steps: [8]i8 = @bitCast(dg(0x1510, 8));
/// DG:04B2 + code: the number of slider directions - 1 (B 3, R 3, Q 7).
const slider_dir_count: [14]i8 = @bitCast(dg(0x04B2, 14));
/// DG:04C0 + 8 * code + k: slider steps (B -11, 9, 11, -9; R -10, -1, 10, 1; Q both).
const slider_steps: [8 * 14]i8 = @bitCast(dg(0x04C0, 8 * 14));
/// DG:28CC: 1 for the White codes 1..6.
const is_white_code = dg(0x28CC, 14);
/// DG:28E8: 1 for empty and the Black codes 8..13.
const is_empty_or_black = dg(0x28E8, 14);
/// DG:28F6: a word per side, +10 / -10: from a pawn that has just made a double step, the
/// square passed over.
const ep_behind: [2]i16 = blk: {
    const raw = dg(0x28F6, 4);
    break :blk .{ @bitCast(@as(u16, raw[0]) | @as(u16, raw[1]) << 8), @bitCast(@as(u16, raw[2]) | @as(u16, raw[3]) << 8) };
};

/// The order in which 1C76 / 1DE6 and 4A76 / 4AD4 look for a knight on the board.
const knight_scan = [8]i8{ 8, 12, 19, 21, -8, -12, -19, -21 };
/// The four rank/file and the four diagonal directions, in the order every attack test
/// here walks them.
const line_scan = [4]i8{ 1, -1, 10, -10 };
const diagonal_scan = [4]i8{ 9, 11, -9, -11 };

inline fn reach(table: anytype, d: i32) @TypeOf(table[0]) {
    return table[@intCast(d + 255)];
}

inline fn sq32(x: anytype) i32 {
    return @intCast(x);
}

inline fn at(arr: anytype, s: i32) @TypeOf(arr[0]) {
    return arr[@intCast(s)];
}

/// The colour-dependent codes of a side.
fn Colour(comptime side: Side) type {
    return struct {
        const white = side == .white;
        const us: usize = @backingInt(side);
        const them: usize = 1 - us;
        const pawn: u8 = if (white) pos.white_pawn else pos.black_pawn;
        const knight: u8 = if (white) pos.white_knight else pos.black_knight;
        const bishop: u8 = if (white) pos.white_bishop else pos.black_bishop;
        const rook: u8 = if (white) pos.white_rook else pos.black_rook;
        const queen: u8 = if (white) pos.white_queen else pos.black_queen;
        const king: u8 = if (white) pos.white_king else pos.black_king;
        /// The side's piece-list entries start here (DG:A03A / A04A).
        const list: usize = 16 * us;
    };
}

/// The first non-empty square from `s` along `d` (not looking at `s` itself).
inline fn firstPiece(p: *const Position, s: i32, d: i32) u8 {
    var q = s + d;
    while (at(&p.board, q) == pos.empty) q += d;
    return at(&p.board, q);
}

/// Whether the first piece from `sq` along one of `line_scan` is a rook or queen of
/// `side`, or along one of `diagonal_scan` a bishop or queen of `side`, in the original's
/// order (all lines, then all diagonals; the first find returns).
inline fn slidersAttack(p: *const Position, comptime side: Side, sq: i32) bool {
    const C = Colour(side);
    for (line_scan) |d| {
        const c = firstPiece(p, sq, d);
        if (c == C.rook or c == C.queen) return true;
    }
    for (diagonal_scan) |d| {
        const c = firstPiece(p, sq, d);
        if (c == C.queen or c == C.bishop) return true;
    }
    return false;
}

/// Whether a knight of `side` stands on one of the eight knight squares around `sq`,
/// looked for on the board (so a promoted third knight counts).
inline fn knightOnBoard(p: *const Position, comptime side: Side, sq: i32) bool {
    inline for (knight_scan) |d| {
        if (at(&p.board, sq + d) == Colour(side).knight) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// 0000:1C76 / 0000:1DE6: the "in check" test
// ---------------------------------------------------------------------------

/// Port of white_attacks_square_no_pawns (0000:1C76-1DE3, `side` = .white) and of its
/// exact mirror black_attacks_square_no_pawns (0000:1DE6-1F53, .black): whether the king
/// of `side` is next to `sq`, a knight of `side` stands a knight's step away (found on
/// the board), or a rook/queen of `side` on a rank or file or a bishop/queen on a
/// diagonal reaches `sq`. **Pawns are not tested** (the original's quirk, kept:
/// docs/OBSERVATIONS.md). The search calls it with the side to move's own king square
/// and the opponent as `side`. Returns the original's AX, 1 or 0.
pub fn attacksSquareNoPawns(p: *const Position, comptime side: Side, sq: usize) u16 {
    const C = Colour(side);
    const s = sq32(sq);
    const king = sq32(p.piece_list[C.list + 7]);
    if (reach(&king_reach, king - s) != 0) return 1; // index king - sq (1C85)
    if (knightOnBoard(p, side, s)) return 1;
    return @intFromBool(slidersAttack(p, side, s));
}

// ---------------------------------------------------------------------------
// 0000:1F56 / 0000:211E: is the hash move plausible?
// ---------------------------------------------------------------------------

/// Port of hash_move_plausible_white (0000:1F56-211B, `side` = .white) and its mirror
/// hash_move_plausible_black (0000:211E-22BD, .black): a cheap legality test of the hash
/// move for the side to move. Returns 1; or writes 0 to `move.from` and returns 0.
///
/// The piece on `from` must be the side's; a pawn may push one or two squares or capture
/// an enemy piece diagonally (no en passant, nothing onto the last rank); a knight, king
/// or slider must reach `to` (sliders over empty squares) and not land on an own piece; a
/// king not on a square an enemy pawn attacks. If the own king is attacked by an enemy
/// pawn, only a king move or the capture of that pawn is accepted (tested on the board
/// byte at the slider's walk end, the original's suspected bug 5, harmless). Pins and
/// other checks are not tested. 1F56's up-front test for a target holding the Black king
/// and 211E's per-handler test for targets >= 6 differ only in form (spec §7).
pub fn hashMovePlausible(p: *const Position, comptime side: Side, move: *Move) u16 {
    if (plausible(p, side, move.from, move.to)) return 1;
    move.from = 0;
    return 0;
}

fn plausible(p: *const Position, comptime side: Side, from_byte: u8, to_byte: u8) bool {
    const white = side == .white;
    const C = Colour(side);
    const b = &p.board;
    // The squares are signed bytes in the original.
    const to: i32 = @as(i8, @bitCast(to_byte));
    const from: i32 = @as(i8, @bitCast(from_byte));
    if (white and at(b, to) == pos.black_king) return false; // 1F6C
    const code = at(b, from);
    if (code < C.pawn or code > C.king) return false; // 20BA / 225A
    const t = at(b, to);
    const bad_target = if (white) (t >= 1 and t <= 7) else t >= 6;
    const d = from - to;
    var walk_end = from; // SI at 20D8 / 227A
    switch (code - C.pawn) {
        0 => { // pawn 1F80 / 2144
            const diff: i32 = if (white) to - from else from - to;
            if (white and to > 0x58) return false;
            if (!white and to < 0x1F) return false;
            if (diff == 20) {
                if (white and (to > 0x3A or at(b, to - 10) != pos.empty)) return false;
                if (!white and (to < 0x3D or at(b, to + 10) != pos.empty)) return false;
                if (t != pos.empty) return false;
            } else if (diff == 9 or diff == 11) {
                const ok = if (white) t > 7 else (t >= 1 and t <= 5);
                if (!ok) return false;
            } else if (diff == 10) {
                if (t != pos.empty) return false;
            } else return false;
        },
        1 => if (bad_target or reach(&knight_reach, d) == 0) return false,
        2, 3, 4 => {
            if (bad_target) return false;
            var step: i32 = switch (code - C.pawn) {
                2 => reach(&diagonal_dir, d),
                else => reach(&line_dir, d),
            };
            if (step == 0 and code == C.queen) step = reach(&diagonal_dir, d);
            if (step == 0) return false;
            var s = from;
            while (true) {
                s += step;
                if (s == to) break;
                if (at(b, s) != pos.empty) return false;
            }
            walk_end = to;
        },
        else => { // king 2090 / 2238
            if (bad_target or reach(&king_reach, d) == 0) return false;
            if (at(&p.pawn_attacks[C.them], to) != 0) return false;
        },
    }
    // 20D8 / 227A: with the own king attacked by an enemy pawn, only a king move or the
    // capture of that pawn.
    const king = sq32(p.piece_list[C.list + 7]);
    const n: i8 = @bitCast(at(&p.pawn_attacks[C.them], king));
    if (n == 0 or at(b, walk_end) == C.king) return true;
    if (n > 1) return false;
    const f: i32 = if (white) 1 else -1;
    const enemy_pawn: u8 = if (white) pos.black_pawn else pos.white_pawn;
    if (at(b, king + 9 * f) == enemy_pawn) return to == king + 9 * f;
    return to == king + 11 * f;
}

// ---------------------------------------------------------------------------
// 1E9D:CE3E / 1E9D:CC4E: the attacked-piece counters
// ---------------------------------------------------------------------------

/// Port of count_attacked_pieces_white_to_move (1E9D:CE3E-D02C, `side` = .white) and its
/// exact mirror count_attacked_pieces_black_to_move (1E9D:CC4E-CE3C, .black): the number
/// of the opponent's pieces attacked by a cheaper piece of `side`. The opponent's queen
/// counts if attacked by a pawn, knight, bishop or rook; each rook (slot 5, then 4) by a
/// pawn, knight or bishop; each knight and bishop by a pawn. Pawns by the pawn-attack
/// counts, knights through the list slots 0-1. The bishop test (suspected bug 3, kept):
/// only the first bishop slot that has a diagonal towards the target is tried; the
/// rook test tries both slots. Either walk accepts any bishop (rook) of `side` as the first
/// piece met. The result indexes the node's stand-pat bonus table (DG:03EA).
pub fn countAttacked(p: *const Position, comptime side: Side) u16 {
    const A = Colour(side); // attacker
    const vic = Colour(if (side == .white) .black else .white).list;
    const att = A.list;
    const counts = &p.pawn_attacks[A.us];
    const l = &p.piece_list;
    var n: u16 = 0;
    // 1. the queen (CE42..CF15)
    const q = l[vic + 6];
    if (q <= 0x62) {
        const t = sq32(q);
        var hit = counts[q] != 0 or knightHits(p, att, t) or bishopsHit(p, side, t);
        if (!hit) {
            for ([2]usize{ att + 4, att + 5 }) |s| {
                const st: i32 = reach(&line_dir, t - sq32(l[s]));
                if (st != 0 and firstPiece(p, t, st) == A.rook) {
                    hit = true;
                    break;
                }
            }
        }
        n += @intFromBool(hit);
    }
    // 2. the rooks, slot 5 then slot 4 (CF18..CFF3)
    for ([2]usize{ vic + 5, vic + 4 }) |s| {
        const r = l[s];
        if (r > 0x62) continue;
        const t = sq32(r);
        n += @intFromBool(counts[r] != 0 or knightHits(p, att, t) or bishopsHit(p, side, t));
    }
    // 3. the knights and bishops, by pawns only (CFF4..D025). No on-board test: a captured
    // piece's entry (>= 120) reads beyond the table in the original, 0 here.
    for (l[vic..][0..4]) |e| {
        if (e < 120 and counts[e] != 0) n += 1;
    }
    return n;
}

inline fn knightHits(p: *const Position, att: usize, t: i32) bool {
    return reach(&knight_reach, t - sq32(p.piece_list[att])) != 0 or
        reach(&knight_reach, t - sq32(p.piece_list[att + 1])) != 0;
}

/// CE84..CEBD: the first bishop slot with a diagonal towards `t` decides alone.
inline fn bishopsHit(p: *const Position, comptime side: Side, t: i32) bool {
    const A = Colour(side);
    for ([2]usize{ A.list + 2, A.list + 3 }) |s| {
        const st: i32 = reach(&diagonal_dir, t - sq32(p.piece_list[s]));
        if (st != 0) return firstPiece(p, t, st) == A.bishop;
    }
    return false;
}

// ---------------------------------------------------------------------------
// 38C0:DFA0 / 38C0:E100 and 2B9F:4A76 / 2B9F:4AD4: attack tests
// ---------------------------------------------------------------------------

/// Port of white_attacks_square_slots (38C0:DFA0, `side` = .white) and its exact mirror
/// black_attacks_square_slots (38C0:E100, .black): as `attacksSquareNoPawns`, except that
/// the knights are found through the list slots 0-1 and the king table is indexed
/// sq - king. Pawns are not tested.
fn attacksSquareSlots(p: *const Position, comptime side: Side, sq: i32) bool {
    const C = Colour(side);
    const l = &p.piece_list;
    if (reach(&king_reach, sq - sq32(l[C.list + 7])) != 0) return true;
    if (reach(&knight_reach, sq - sq32(l[C.list])) != 0) return true;
    if (reach(&knight_reach, sq - sq32(l[C.list + 1])) != 0) return true;
    return slidersAttack(p, side, sq);
}

/// Port of white_attacks_square (2B9F:4A76-4AD0, `side` = .white) and its exact mirror
/// black_attacks_square (2B9F:4AD4-4B2E, .black), called by static_eval: whether any
/// piece of `side`, pawns included, attacks `sq`: its pawn-attack count there, then
/// `attacksSquareSlots`, then a knight on the board. Returns the original's AX, 1 or 0.
pub fn attacksSquare(p: *const Position, comptime side: Side, sq: usize) u16 {
    if (p.pawn_attacks[@backingInt(side)][sq] != 0) return 1;
    const s = sq32(sq);
    if (attacksSquareSlots(p, side, s)) return 1;
    return @intFromBool(knightOnBoard(p, side, s));
}

// ---------------------------------------------------------------------------
// 38C0:E260: the check-evasion generator
// ---------------------------------------------------------------------------

/// The generator's return value when a piece of the side to move can take the enemy king.
pub const king_capture: u16 = mg.king_capture;

const KingCapture = error{KingCapture};

const Evasions = struct {
    p: *Position,
    v: *const mg.SearchVars,
    list: *mg.MoveList,
    n: usize = 0,
    /// DG:8C06 + ply AND 7Fh: below 21 the direction code of a line check, else the
    /// checker's square.
    chk: u8,

    inline fn put(e: *Evasions, from: i32, to: i32, flag: u8, score: u8) void {
        e.list[e.n] = .{ .from = @intCast(from), .to = @intCast(to), .flag = flag, .score = score };
        e.n += 1;
    }

    inline fn board(e: *const Evasions, s: i32) u8 {
        return at(&e.p.board, s);
    }

    inline fn mark(e: *const Evasions, from: i32, to: i32) u8 {
        return e.v.marks[mg.markIndex(@intCast(from), @intCast(to))];
    }

    inline fn kcap(e: *const Evasions, to: i32) u8 {
        return king_capture_value[e.board(to)];
    }

    /// On the line of the check: the own king's ray map (the piece's colour) holds the
    /// check's direction code there.
    inline fn onLine(e: *const Evasions, comptime white: bool, to: i32) bool {
        return at(&e.p.king_rays[if (white) 0 else 1], to) == e.chk;
    }

    /// E305..E33B, E39D..E423: queen 19h, knight 0Ch, rook 1, bishop 1.
    fn promotions(e: *Evasions, from: i32, to: i32) void {
        e.put(from, to, 5, 0x19);
        e.put(from, to, 2, 0x0C);
        e.put(from, to, 4, 1);
        e.put(from, to, 3, 1);
    }

    inline fn lastRank(comptime white: bool, to: i32) bool {
        return if (white) to >= 0x5B else to <= 0x1C;
    }

    /// The knight's test at E46C / E70A (both branches): it attacks the enemy king.
    fn knightGivesCheck(e: *const Evasions, comptime white: bool, from: i32) KingCapture!void {
        const ek = sq32(e.p.piece_list[if (white) 16 + 7 else 7]);
        if (reach(&knight_reach, from - ek) != 0) return error.KingCapture;
    }

    /// The slider's test (E4D0.. / E76E..): it stands on the enemy king's ray map on a
    /// ray it moves along.
    fn sliderGivesCheck(e: *const Evasions, comptime white: bool, code: u8, from: i32) KingCapture!void {
        const r: i8 = @bitCast(at(&e.p.king_rays[if (white) 1 else 0], from));
        const hit = switch (code - (if (white) @as(u8, 0) else 7)) {
            3 => if (white) (r >= 9 and r <= 12) else (r >= 1 and r <= 4),
            4 => if (white) r >= 13 else r >= 5,
            else => r != 0,
        };
        if (hit) return error.KingCapture;
    }

    // -- branch A: a check along a line (E288..E8E0) --------------------------

    fn pawnLine(e: *Evasions, comptime white: bool, from: i32) void {
        var cx: usize = 0;
        while (true) : (cx += 1) {
            const st: i32 = pawn_steps[cx];
            const to = if (white) from + st else from - st;
            if (cx < 2) {
                const t = e.board(to);
                const enemy = if (white) t > 7 else is_white_code[t] != 0;
                if (enemy and e.onLine(white, to)) {
                    if (lastRank(white, to)) e.promotions(from, to) else e.put(from, to, 0, e.mark(from, to) +% e.kcap(to));
                }
                continue;
            }
            if (e.board(to) != pos.empty) return; // E372 / E6DC
            if (e.onLine(white, to)) { // E392 / E6FC
                if (lastRank(white, to)) e.promotions(from, to) else e.put(from, to, 0, e.mark(from, to) +% 2);
                return;
            }
            if (if (white) to > 0x30 else to < 0x47) return;
        }
    }

    fn knightLine(e: *Evasions, comptime white: bool, from: i32) KingCapture!void {
        try e.knightGivesCheck(white, from);
        var k: usize = 8;
        while (k > 0) {
            k -= 1;
            const to = from + knight_steps[k];
            if (e.onLine(white, to)) e.put(from, to, 0, e.mark(from, to) +% e.kcap(to));
        }
    }

    fn sliderLine(e: *Evasions, comptime white: bool, code: u8, from: i32) KingCapture!void {
        try e.sliderGivesCheck(white, code, from);
        var cx: i32 = slider_dir_count[code];
        while (cx >= 0) : (cx -= 1) {
            const st: i32 = slider_steps[8 * @as(usize, code) + @as(usize, @intCast(cx))];
            var to = from + st;
            while (e.board(to) == pos.empty) : (to += st) {
                if (e.onLine(white, to)) e.put(from, to, 0, e.mark(from, to));
            }
            if (e.onLine(white, to)) e.put(from, to, 0, e.mark(from, to) +% e.kcap(to));
        }
    }

    /// E5B0 / E84E (branch A, score mark + capture value) and EB0E / EC92 (branch B,
    /// score the capture value). The king is lifted off the board while its targets are
    /// tested, and put back as 6 / 0Dh.
    fn king(e: *Evasions, comptime white: bool, from: i32, comptime with_mark: bool) KingCapture!void {
        const C = Colour(if (white) .white else .black);
        const E = if (white) Side.black else Side.white;
        const b = &e.p.board;
        b[@intCast(from)] = pos.empty;
        defer b[@intCast(from)] = C.king;
        var k: usize = 8;
        while (k > 0) {
            k -= 1;
            const to = from + king_steps[k];
            const t = at(b, to);
            if (white) {
                if (is_empty_or_black[t] == 0) continue;
                if (t == pos.black_king) return error.KingCapture;
            } else {
                if (t >= 7) continue;
                if (t == pos.white_king) return error.KingCapture;
            }
            if (at(&e.p.pawn_attacks[@backingInt(E)], to) != 0) continue;
            if (attacksSquareSlots(e.p, E, to)) continue;
            var sc = e.kcap(to);
            if (with_mark) sc +%= e.mark(from, to);
            e.put(from, to, 0, sc);
        }
    }

    fn lineCheck(e: *Evasions, comptime side: Side) KingCapture!void {
        for (e.p.piece_list[16 * @as(usize, @backingInt(side)) ..][0..16]) |entry| {
            if (entry >= 120) continue; // a captured piece (see the file comment)
            const from = sq32(entry);
            const code = e.board(from);
            switch (code) {
                pos.white_pawn => e.pawnLine(true, from),
                pos.black_pawn => e.pawnLine(false, from),
                pos.white_knight => try e.knightLine(true, from),
                pos.black_knight => try e.knightLine(false, from),
                pos.white_king => try e.king(true, from, true),
                pos.black_king => try e.king(false, from, true),
                3...5 => try e.sliderLine(true, code, from),
                10...12 => try e.sliderLine(false, code, from),
                else => {},
            }
        }
    }

    // -- branch B: a check by a knight or pawn (E8E4..ECFD) -------------------

    fn squareCheck(e: *Evasions, comptime side: Side, ply: usize) KingCapture!void {
        const chk = sq32(e.chk);
        // E8E4..E915: a checker defended by an enemy pawn is worth nothing to take.
        const capsc: u8 = if (at(&e.p.pawn_attacks[1 - @as(usize, @backingInt(side))], chk) != 0) 0 else e.kcap(chk);
        // E918..E93D: the en-passant square, if the checker is the pawn that made it.
        const ep: i32 = @as(i8, @bitCast(e.p.ep_square_by_ply[ply]));
        const ep_ok = ep != 0 and ep_behind[@backingInt(side)] + chk == ep;
        for (e.p.piece_list[16 * @as(usize, @backingInt(side)) ..][0..16]) |entry| {
            if (entry >= 120) continue;
            const from = sq32(entry);
            const code = e.board(from);
            switch (code) {
                pos.white_pawn, pos.black_pawn => {
                    const white = code == pos.white_pawn;
                    const f: i32 = if (white) -1 else 1;
                    const dc = from - chk;
                    if (dc == 9 * f or dc == 11 * f) {
                        // EA1E: scored by the capture value, without the defence test
                        // (suspected bug 2, kept).
                        if ((white and lastRank(true, chk)) or (!white and lastRank(false, chk)))
                            e.promotions(from, chk)
                        else
                            e.put(from, chk, 0, e.kcap(chk));
                    } else if (ep_ok and (from - ep == 9 * f or from - ep == 11 * f)) {
                        e.put(from, ep, pos.flag_en_passant, 2); // E9C2
                    }
                },
                pos.white_knight, pos.black_knight => {
                    if (code == pos.white_knight) try e.knightGivesCheck(true, from) else try e.knightGivesCheck(false, from);
                    var k: usize = 8;
                    while (k > 0) {
                        k -= 1;
                        if (from + knight_steps[k] == chk) e.put(from, chk, 0, capsc);
                    }
                },
                pos.white_king => try e.king(true, from, false),
                pos.black_king => try e.king(false, from, false),
                3...5, 10...12 => {
                    if (code < 7) try e.sliderGivesCheck(true, code, from) else try e.sliderGivesCheck(false, code, from);
                    var cx: i32 = slider_dir_count[code];
                    while (cx >= 0) : (cx -= 1) {
                        const st: i32 = slider_steps[8 * @as(usize, code) + @as(usize, @intCast(cx))];
                        var to = from + st;
                        while (e.board(to) == pos.empty) to += st;
                        if (to == chk) e.put(from, to, 0, capsc);
                    }
                },
                else => {},
            }
        }
    }
};

/// Port of gen_evasions (38C0:E260-ED33, with its attack tests 38C0:DFA0 and E100): the
/// moves of `side`, which is in check, written to `list` (DG:3A34 + 400 * ply); returns
/// their number, sorted by score (`sortMoves`) when more than one, or FFFFh when a piece of
/// `side` can take the enemy king (the moves written until then stay, unsorted).
///
/// `p.check_by_ply[ply]` AND 7Fh selects the kind: below 21 a check along a line (the
/// direction code of the own king's ray map from the king to the checker): every move of
/// a pawn, knight or slider to a square of that line (interpositions and the capture of
/// the checker) and every king move; else the checker's square (a knight or pawn): its
/// capture, en passant of a pawn checker, and the king moves. Pins and double check are
/// not tested (the child node finds the king capturable). The pieces are taken in list
/// order 0..15 and dispatched by the code on the board under the entry. The king is
/// lifted off the board during its moves and put back; `p` is unchanged on return.
pub fn genEvasions(p: *Position, v: *const mg.SearchVars, list: *mg.MoveList, side: Side, ply: usize) u16 {
    var e: Evasions = .{ .p = p, .v = v, .list = list, .chk = p.check_by_ply[ply] & 0x7F };
    const r = if (e.chk < 0x15) switch (side) {
        .white => e.lineCheck(.white),
        .black => e.lineCheck(.black),
    } else switch (side) {
        .white => e.squareCheck(.white, ply),
        .black => e.squareCheck(.black, ply),
    };
    r catch return king_capture;
    const n: i16 = @intCast(e.n);
    sortMoves(list, n);
    return @intCast(e.n);
}
