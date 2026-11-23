//! The opening book: the book key, the lookup in PRBOOK\M80KEY.000-.00F and
//! PRBOOK\PRBOOK.M80, the move check, the list of book moves in the order the
//! original shows them, and the choice of the move to play with the original's
//! random generator.
//!
//! Specification: docs/arch/40-opening-book.md, whose executable form is
//! tools/research/book/book.py (proved against the running original on 1,898 calls of
//! book_probe, 4793:621E). Test: src/book_test.zig, which replays calls recorded from
//! the original (tests/golden/book/, made by tools/port/gen_book_vectors.py).
//!
//! The reader works on the book files' contents, supplied by the caller as byte slices
//! (`Files`); opening the files is the layer above's business. Nothing here allocates.
//!
//! Squares are 10x12 mailbox indices (a1 = 21, h8 = 98). A **book square** is 0..63,
//! a1 = 0, b1 = 1 ... h8 = 63. Book moves are stored **from the side to move's view**:
//! for Black every square is mirrored rank for rank (`mirror`), and the key is that of
//! the colour-reversed mirror image, so a position and its mirror share one entry.
//!
//! Out of scope (spec, "Scope"): user books (`4793:6525`-`6A47`) and book learning
//! (`4793:6EF6`). As shipped there are no user books and no learned-book files, and the
//! rewrite does not learn (AGENTS.md §8.2), so the original's probe with those parts
//! present but empty is what is ported. The display index across plies
//! (`DG:8FDA`, `DG:2A8E`, `4793:57AC`) and the opening name on the status line are
//! user interface and are not ported; the name number is returned.

const std = @import("std");
const pos = @import("position.zig");
const original = @import("original.zig");

const Side = pos.Side;

// ---------------------------------------------------------------------------
// Constant tables, read from the original's initialised data (src/original.zig)
// ---------------------------------------------------------------------------

/// DG:2AD4: the number of slots in the draw by grade 0..7 (signed bytes
/// 0, 1, 1, 2, 3, 6, 9, 3).
const grade_weight: [8]i8 = @bitCast(original.dgroup(0x2AD4, 8));

/// DG:2A76, 2A7C, 2A82, 2A88: 6-byte keys XORed when a castling right is not
/// available; the book uses them in the order own O-O, own O-O-O, opponent's O-O,
/// opponent's O-O-O (the search's castling keys, White O-O, O-O-O, Black O-O, O-O-O).
const castle_keys: [4]u48 = blk: {
    const b = original.dgroup(0x2A76, 24);
    var k: [4]u48 = undefined;
    for (&k, 0..) |*v, i| v.* = std.mem.readInt(u48, b[6 * i ..][0..6], .little);
    break :blk k;
};

/// DG:2A90 + 6 * file: the en-passant key of files 0..9 (0 and 9 are zero).
const ep_keys: [10]u48 = blk: {
    const b = original.dgroup(0x2A90, 60);
    var k: [10]u48 = undefined;
    for (&k, 0..) |*v, i| v.* = std.mem.readInt(u48, b[6 * i ..][0..6], .little);
    break :blk k;
};

/// DG:06C0: per square, the 16-bit offset of the square's 78-byte block in the hash
/// random table (`78k - 6` for the k-th board square; FFFAh for a1).
const square_offset: [120]u16 = blk: {
    const b = original.dgroup(0x06C0, 240);
    var t: [120]u16 = undefined;
    for (&t, 0..) |*v, i| v.* = std.mem.readInt(u16, b[2 * i ..][0..2], .little);
    break :blk t;
};

/// The step tables the move check reads at `table + (from - to)`, for differences
/// -77..77 (every pair of board squares): DG:0B66 diagonal step, DG:0C64 orthogonal
/// step (signed bytes, 0 when not on such a line), DG:0A68 knight move, DG:0CFF king
/// move (non-zero when it is one). Index `d + 77`.
const diag_step: [155]i8 = @bitCast(original.dgroup(0x0B66 - 77, 155));
const orth_step: [155]i8 = @bitCast(original.dgroup(0x0C64 - 77, 155));
const knight_move: [155]u8 = original.dgroup(0x0A68 - 77, 155);
const king_move: [155]u8 = original.dgroup(0x0CFF - 77, 155);

/// DG:100A: the file of a square (`s mod 10`, 0 from 110). The en-passant byte
/// DG:9EC9 is 0 or a square of rank 3 or 6, so only those entries are ever read.
fn fileOf(s: u8) u8 {
    return if (s < 110) s % 10 else 0;
}

/// 4793:57F0: the same file on the mirrored rank, `(11 - s/10) * 10 + s mod 10`
/// (tables DG:1078 rank, DG:100A file).
pub fn mirror(s: u8) u8 {
    return (11 - s / 10) * 10 + s % 10;
}

/// A book square (0..63) as a mailbox square.
pub fn mailbox(x: u6) u8 {
    return @as(u8, x >> 3) * 10 + @as(u8, x & 7) + 21;
}

// ---------------------------------------------------------------------------
// The random source
// ---------------------------------------------------------------------------

/// The Microsoft C run-time generator, `rand()` (4793:89D8) and `srand()` (4793:89C6),
/// with its 32-bit state (DG:2DC8) as a value the caller owns. The original seeds it
/// from the BIOS tick count at start-up (`0000:0109`) and at each new game
/// (`4793:3288`); here the seed is an explicit input, so a test can set the seed the
/// original had and the UCI layer can seed it from an option.
pub const Rand = struct {
    /// DG:2DC8: the generator's state.
    seed: u32,

    /// `srand(x)`: the state becomes x (high word 0).
    pub fn srand(x: u16) Rand {
        return .{ .seed = x };
    }

    /// `rand()`: seed = seed * 343FDh + 269EC3h (32-bit), result (seed >> 16) & 7FFFh.
    pub fn next(r: *Rand) u15 {
        r.seed = r.seed *% 0x343FD +% 0x269EC3;
        return @truncate(r.seed >> 16);
    }
};

// ---------------------------------------------------------------------------
// The position as the book sees it
// ---------------------------------------------------------------------------

/// What book_probe reads of the position.
pub const BookPosition = struct {
    /// DG:9EF6: the search board.
    board: *const [120]u8,
    /// The probe's side argument: the side to move on that board.
    side: Side,
    /// DG:B426 (White O-O), DG:3A30 (White O-O-O), DG:B428 (Black O-O), DG:3A32
    /// (Black O-O-O): the game ply at which the right was lost, 0 while it is held.
    castle_lost: [4]u16,
    /// DG:9EC9: the en-passant square of the last game move (set only when an enemy
    /// pawn stands beside the pawn that made the double step), 0 for none.
    ep_square: u8,

    /// The book's view of a search position: `Position.ep_square_by_ply[1]` is DG:9EC9.
    pub fn fromPosition(p: *const pos.Position, side: Side) BookPosition {
        return .{
            .board = &p.board,
            .side = side,
            .castle_lost = .{ p.oo_lost_at[0], p.ooo_lost_at[0], p.oo_lost_at[1], p.ooo_lost_at[1] },
            .ep_square = p.ep_square_by_ply[1],
        };
    }
};

// ---------------------------------------------------------------------------
// The book key (4793:5816)
// ---------------------------------------------------------------------------

/// The book key DG:935A..935F as a little-endian 48-bit value (key byte 0 is the low
/// byte).
pub const Key = u48;

/// The 48-bit entry of the hash random table at byte offset `o`.
inline fn randomKey(o: u16) u48 {
    return std.mem.readInt(u48, pos.random_table[o..][0..6], .little);
}

/// Port of book_key (4793:5816). The XOR of the random-table entries
/// `[06C0 + 2s] + 6c` (16-bit sum) of every piece on squares 21..98, seen from the
/// side to move: for Black, colours swapped (c - 7 or c + 7) and the square mirrored.
/// Then the four castling keys, each XORed when that right is **not** available (lost,
/// or the rook not on its corner; the king's square is not looked at), the side to
/// move's own first; then the en-passant key of the file of DG:9EC9.
pub fn bookKey(bp: BookPosition) Key {
    const b = bp.board;
    var k: u48 = 0;
    const black = bp.side == .black;
    for (21..99) |s| {
        const c = b[s];
        if (c == pos.empty or c == pos.border) continue;
        const sq: u8 = if (black) mirror(@intCast(s)) else @intCast(s);
        const code: u8 = if (!black) c else if (c > 7) c - 7 else c + 7;
        k ^= randomKey(square_offset[sq] +% @as(u16, code) * 6);
    }
    const white_oo = bp.castle_lost[0] != 0 or b[28] != pos.white_rook;
    const white_ooo = bp.castle_lost[1] != 0 or b[21] != pos.white_rook;
    const black_oo = bp.castle_lost[2] != 0 or b[98] != pos.black_rook;
    const black_ooo = bp.castle_lost[3] != 0 or b[91] != pos.black_rook;
    const unavailable: [4]bool = if (black)
        .{ black_oo, black_ooo, white_oo, white_ooo }
    else
        .{ white_oo, white_ooo, black_oo, black_ooo };
    for (unavailable, castle_keys) |u, ck| {
        if (u) k ^= ck;
    }
    const f = fileOf(bp.ep_square);
    if (f != 0) k ^= ep_keys[f];
    return k;
}

/// The index file a key selects: bits 7-4 of key byte 5 (`M80KEY.%03x`).
pub fn indexFile(key: Key) u4 {
    return @truncate(key >> 44);
}

/// The group within the index file: bits 3-0 of key byte 5.
pub fn indexGroup(key: Key) u4 {
    return @truncate(key >> 40);
}

// ---------------------------------------------------------------------------
// The files and the lookup (4793:62D1-6395, 5DF4, 5DA2)
// ---------------------------------------------------------------------------

/// The contents of the book files, supplied by the caller.
pub const Files = struct {
    /// PRBOOK\M80KEY.000 .. M80KEY.00F.
    index: [16][]const u8,
    /// PRBOOK\PRBOOK.M80.
    moves: []const u8,
};

/// What an index entry gives for a position found in the book.
pub const Entry = struct {
    /// DG:7449: the name number (line of NAMES.T80; 0 leaves the name unchanged).
    name: u8,
    /// The word index of the position's list in PRBOOK.M80: the group's base plus the
    /// entry's offset (DG:744A), as the original's 32-bit sum.
    word_index: u32,
};

/// Key bytes 0..4 as one number ordered as the index is sorted: unsigned, byte 0 most
/// significant.
fn sortKey(key: Key) u40 {
    return @byteSwap(@as(u40, @truncate(key)));
}

/// Port of the index lookup (4793:62D1-6395) with the binary search 4793:5DF4 and the
/// comparison 4793:5DA2. The file is chosen by `indexFile`, the group record at
/// 10h + 10 * group gives the base (dword), the offset in the file of the group's first
/// 8-byte entry (dword) and the count (word); lo = 1, hi = count, mid = (lo + hi) >> 1,
/// entry mid - 1 compared on bytes 0..4. Returns null when the key is not in the book.
/// A record or entry beyond the end of the supplied file counts as not found (the
/// shipped files have none; the original would read whatever its short read left).
pub fn lookup(files: *const Files, key: Key) ?Entry {
    const d = files.index[indexFile(key)];
    const rec = 0x10 + 10 * @as(usize, indexGroup(key));
    if (rec + 10 > d.len) return null;
    const base = std.mem.readInt(u32, d[rec..][0..4], .little);
    const offset = std.mem.readInt(u32, d[rec + 4 ..][0..4], .little);
    const count = std.mem.readInt(u16, d[rec + 8 ..][0..2], .little);
    const want = sortKey(key);
    // The original's lo and hi are 16-bit words; with every count below 8000h (checked
    // over the shipped files by book_test.zig) lo + hi cannot wrap, so 32-bit sums
    // give the same mids.
    var lo: u32 = 1;
    var hi: u32 = count;
    while (lo <= hi) {
        const mid = (lo + hi) >> 1;
        const at = @as(usize, offset) + (mid - 1) * 8;
        if (at + 8 > d.len) return null;
        const e = d[at..][0..8];
        const have = std.mem.readInt(u40, e[0..5], .big);
        if (have == want) {
            return .{ .name = e[5], .word_index = base +% std.mem.readInt(u16, e[6..8], .little) };
        }
        if (have < want) lo = mid + 1 else hi = mid - 1;
    }
    return null;
}

// ---------------------------------------------------------------------------
// The move list (4793:63A7-64DE)
// ---------------------------------------------------------------------------

/// The size of the probe's word buffer and grade array (`[bp-1F4h]`, 200 bytes;
/// `[bp-0A8h]`, 100 bytes).
pub const max_words = 100;

/// A position's list as the probe holds it: the words read from PRBOOK.M80 and the
/// grade of each slot.
pub const RawList = struct {
    /// The buffer: 128 bytes (64 words) read from the list's start into a cleared
    /// 200-byte buffer, so words 64..99 are 0.
    words: [max_words]u16 = @splat(0),
    /// The grade (bits 12-14) of each move word; 0 for a promotion prefix's slot.
    grades: [max_words]u8 = @splat(0),
    /// The number of words that belong to the list (`[bp-1Ah]`).
    count: u8 = 0,
};

/// A book move: bits 0-5 from, 6-11 to (book squares, from the side to move's view),
/// bits 12-14 the promotion piece (White code 2..4) from a prefix word, 0 for none.
pub const BookMove = u16;

inline fn moveFrom(w: u16) u6 {
    return @truncate(w);
}
inline fn moveTo(w: u16) u6 {
    return @truncate(w >> 6);
}

/// Reads and decodes a found position's list (4793:63E1-640B and the decode loop
/// 6417-64DE). Words are 16-bit little-endian: bits 0-5 from, 6-11 to, 12-14 grade,
/// 15 last word. A word whose from equals its to is not a move: 2, 3 or 4 with no
/// prefix pending is a promotion prefix for the next word (its slot keeps grade 0);
/// any other value ends the list before it. Bytes past the end of the supplied file
/// read as 0 (the original's short read into its cleared buffer).
pub fn readList(files: *const Files, entry: Entry) RawList {
    var l: RawList = .{};
    const start = @as(u64, @as(u32, entry.word_index *% 2));
    for (0..64) |i| {
        const at = start + 2 * i;
        if (at + 2 > files.moves.len) break;
        l.words[i] = std.mem.readInt(u16, files.moves[@intCast(at)..][0..2], .little);
    }
    var prefix: u16 = 0;
    var i: usize = 0;
    while (true) {
        const w = l.words[i];
        if (prefix == 0 and moveFrom(w) == moveTo(w)) {
            const v = moveFrom(w);
            if (v < 2 or v > 4) break; // 6443: count = i
            prefix = v;
        } else {
            l.grades[i] = @truncate((w >> 12) & 7);
            prefix = 0;
        }
        i += 1;
        if (w & 0x8000 != 0 or i >= max_words) break; // 64D2: the last word
    }
    l.count = @intCast(i);
    return l;
}

// ---------------------------------------------------------------------------
// The move check (4793:59FE)
// ---------------------------------------------------------------------------

/// Walk from `from` by the step the table gives for `from - to` until `to` (true) or
/// an occupied square (false). The queen tries the orthogonal table first.
fn slide(b: *const [120]u8, from: u8, to: u8, comptime orth: bool, comptime diag: bool) bool {
    const d = @as(i32, from) - @as(i32, to) + 77;
    var step: i32 = 0;
    if (orth) step = orth_step[@intCast(d)];
    if (diag and step == 0) step = diag_step[@intCast(d)];
    if (step == 0) return false;
    var s: i32 = from;
    while (true) {
        s += step;
        if (s == to) return true;
        if (b[@intCast(s)] != pos.empty) return false;
    }
}

inline fn knightMove(from: u8, to: u8) bool {
    return knight_move[@intCast(@as(i32, from) - @as(i32, to) + 77)] != 0;
}
inline fn kingMove(from: u8, to: u8) bool {
    return king_move[@intCast(@as(i32, from) - @as(i32, to) + 77)] != 0;
}

/// Port of book_move_ok (4793:59FE): does the book move fit the board? A pseudo-legal
/// test only; **it does not test whether the king is left in check** (spec, suspected
/// bug 3: a pseudo-legal move that leaves the king in check would be played; no
/// position reachable by book moves has one). `ep_file` is the file (1..8) of
/// DG:9EC9, or 0.
// UNVERIFIED: runs in the engine with the book on, and every call that passes is compared
// with the original; the branches that return false are not: no move listed in the 216,405
// positions the shipped book reaches fails the test (spec §4.3, §8). Ported from the reading.
pub fn moveOk(b: *const [120]u8, move: BookMove, side: Side, ep_file: u8) bool {
    var from = mailbox(moveFrom(move));
    var to = mailbox(moveTo(move));
    if (side == .white) {
        if (b[to] == pos.black_king) return false;
        const p = b[from];
        if (p < 1 or p > 6) return false;
        const t = b[to];
        switch (p) {
            pos.white_pawn => {
                if (from < 31) return false;
                const d = @as(i32, to) - @as(i32, from);
                if (d == 20) return from <= 38 and b[from + 10] == pos.empty and t == pos.empty;
                if (d == 10) return t == pos.empty;
                if (d == 9 or d == 11) {
                    if (t == pos.empty and @as(i32, ep_file) - @as(i32, to) == -70) return true;
                    return t > 7;
                }
                return false;
            },
            pos.white_knight => return !(t >= 1 and t <= 7) and knightMove(from, to),
            else => {},
        }
        if (t >= 1 and t <= 7) return false;
        return switch (p) {
            pos.white_bishop => slide(b, from, to, false, true),
            pos.white_rook => slide(b, from, to, true, false),
            pos.white_queen => slide(b, from, to, true, true),
            else => blk: { // the king
                if (b[to + 9] == pos.black_pawn or b[to + 11] == pos.black_pawn) break :blk false;
                const d = @as(i32, to) - @as(i32, from);
                if ((d == 2 or d == -2) and from == 25) break :blk true;
                break :blk kingMove(from, to);
            },
        };
    }
    from = mirror(from);
    to = mirror(to);
    const p = b[from];
    if (p < 8 or p > 13) return false;
    const t = b[to];
    if (p == pos.black_pawn) {
        if (from > 88) return false;
        const d = @as(i32, from) - @as(i32, to);
        if (d == 20) return from >= 81 and b[from - 10] == pos.empty and t == pos.empty;
        if (d == 10) return t == pos.empty;
        if (d == 9 or d == 11) {
            if (t >= 6) return false;
            if (t != pos.empty) return true;
            return @as(i32, ep_file) - @as(i32, to) == -40;
        }
        return false;
    }
    if (t >= 6) return false;
    return switch (p) {
        pos.black_knight => knightMove(from, to),
        pos.black_bishop => slide(b, from, to, false, true),
        pos.black_rook => slide(b, from, to, true, false),
        pos.black_queen => slide(b, from, to, true, true),
        else => blk: { // the king
            if (b[to - 9] == pos.white_pawn or b[to - 11] == pos.white_pawn) break :blk false;
            const d = @as(i32, to) - @as(i32, from);
            if ((d == 2 or d == -2) and from == 95) break :blk true;
            break :blk kingMove(from, to);
        },
    };
}

// ---------------------------------------------------------------------------
// The move on the real board, and the display list (4793:5F4E, 6110, 609A, 8870)
// ---------------------------------------------------------------------------

/// The real squares of a book move (mirrored back for Black) and the move flag the
/// original gives it, as book_display_add (4793:5F4E) and the hand-over (6C73-6D7D)
/// compute them: 6 for a king move of two files; for a pawn reaching the last rank,
/// the promotion piece of the move, or 5 (queen) if none; 1 for a pawn's diagonal move
/// to an empty square (en passant); else 0.
pub fn realMove(b: *const [120]u8, move: BookMove, side: Side) pos.Move {
    var from = mailbox(moveFrom(move));
    var to = mailbox(moveTo(move));
    if (side == .black) {
        from = mirror(from);
        to = mirror(to);
    }
    const promo: u8 = @truncate((move >> 12) & 7);
    const p = b[from];
    const d = @as(i32, to) - @as(i32, from);
    var flag: u8 = 0;
    if (p == pos.white_king or p == pos.black_king) {
        if (d == 2 or d == -2) flag = 6;
    } else if (p == pos.white_pawn) {
        if (to >= 91) {
            flag = if (promo != 0) promo else 5;
        } else if ((d == 9 or d == 11) and b[to] == pos.empty) flag = 1;
    } else if (p == pos.black_pawn) {
        if (to <= 28) {
            flag = if (promo != 0) promo else 5;
        } else if ((d == -9 or d == -11) and b[to] == pos.empty) flag = 1;
    }
    return .{ .from = from, .to = to, .flag = flag };
}

/// An entry of the display list (the far array `[7816]`), 4 bytes as the original
/// writes them (4793:5F4E).
pub const DisplayEntry = extern struct {
    /// From, a real mailbox square.
    from: u8,
    /// To, a real mailbox square.
    to: u8,
    /// (piece on from) << 4, OR the move flag of `realMove`.
    piece_flag: u8,
    /// grade << 4, OR 80h if the target square is occupied or the move is en passant
    /// (the low nibble is 0 for the main book; a user book's number otherwise).
    grade_flags: u8,

    pub fn grade(e: DisplayEntry) u3 {
        return @truncate(e.grade_flags >> 4);
    }
    /// The promotion piece (White code 2..5), or 0 if the move is not a promotion.
    pub fn promotion(e: DisplayEntry) u8 {
        const p = e.piece_flag >> 4;
        if (p != pos.white_pawn and p != pos.black_pawn) return 0;
        const f = e.piece_flag & 0x0F;
        return if (f >= 2 and f <= 5) f else 0;
    }
};

/// Port of book_display_add (4793:5F4E) for one move of the main book.
pub fn displayEntry(b: *const [120]u8, move: BookMove, grade: u8, side: Side) DisplayEntry {
    const m = realMove(b, move, side);
    const capture = m.flag == 1 or b[m.to] != pos.empty;
    return .{
        .from = m.from,
        .to = m.to,
        .piece_flag = (b[m.from] << 4) | m.flag,
        .grade_flags = ((grade << 4) & 0x7F) | @as(u8, if (capture) 0x80 else 0),
    };
}

/// Port of the comparator book_display_cmp (4793:609A): by the low nibble of byte 3
/// (the book: 0 for the main book), then by byte 3 & 7Fh, higher first.
fn displayCmp(a: DisplayEntry, b: DisplayEntry) i32 {
    const ka = a.grade_flags & 0x7F;
    const kb = b.grade_flags & 0x7F;
    const la = ka & 0x0F;
    const lb = kb & 0x0F;
    if (lb > la) return -1;
    if (lb < la) return 1;
    if (kb < ka) return -1;
    if (kb > ka) return 1;
    return 0;
}

/// Port of the Microsoft C run-time `qsort` (4793:8870) as book_display_sort
/// (4793:6110) uses it, on an array of indices into `ents`. Moves of equal grade are
/// left in the order this algorithm leaves them, which is not their file order, so it
/// is reproduced step for step: a pre-check of adjacent pairs, then partitions with
/// the first element as the pivot, the larger part kept on an explicit stack and the
/// smaller part taken first.
fn msQsort(items: []u8, ents: []const DisplayEntry) void {
    const n = items.len;
    if (n <= 1) return;
    const C = struct {
        fn cmp(e: []const DisplayEntry, a: u8, b: u8) i32 {
            return displayCmp(e[a], e[b]);
        }
    };
    // 8883: already in order?
    var sorted = true;
    for (1..n) |k| {
        if (C.cmp(ents, items[k], items[k - 1]) < 0) {
            sorted = false;
            break;
        }
    }
    if (sorted) return;
    const Range = struct { lo: usize, hi: usize };
    // The smaller part is always on top, so the depth stays below log2(n) + 2.
    var stack: [16]Range = undefined;
    var sp: usize = 1;
    stack[0] = .{ .lo = 0, .hi = n - 1 };
    while (sp > 0) {
        const lo = stack[sp - 1].lo;
        const hi = stack[sp - 1].hi;
        if (lo >= hi) {
            sp -= 1;
            continue;
        }
        var b2 = hi;
        var b4 = lo;
        var i = lo;
        var j = hi + 1;
        while (true) {
            // 8902: up
            while (true) {
                i += 1;
                if (i == hi) break;
                const c = C.cmp(ents, items[i], items[lo]);
                if (c > 0) break;
                if (c < 0) b4 = i;
            }
            // 8925: down
            while (true) {
                j -= 1;
                const c = C.cmp(ents, items[lo], items[j]);
                if (c > 0) break;
                if (c == 0) {
                    if (j == lo) break;
                    continue;
                }
                b2 = j;
            }
            if (j <= i) break;
            std.mem.swap(u8, &items[i], &items[j]);
            b2 = j;
            b4 = i;
        }
        std.mem.swap(u8, &items[lo], &items[j]);
        // 897C
        if (hi - b2 >= b4 - lo) {
            stack[sp - 1] = .{ .lo = b2, .hi = hi };
            stack[sp] = .{ .lo = lo, .hi = b4 };
        } else {
            stack[sp - 1] = .{ .lo = lo, .hi = b4 };
            stack[sp] = .{ .lo = b2, .hi = hi };
        }
        sp += 1;
        std.debug.assert(sp < stack.len);
    }
}

/// The book moves of a position in the order the original lists them.
pub const DisplayList = struct {
    entries: [max_words]DisplayEntry = undefined,
    /// The book move (side to move's view) of each entry.
    moves: [max_words]BookMove = undefined,
    len: u8 = 0,

    pub fn slice(l: *const DisplayList) []const DisplayEntry {
        return l.entries[0..l.len];
    }
};

/// The display list of a found position: every move of the list that passes the move
/// check, as book_display_add writes it (decode loop 6417-64DE), sorted by grade,
/// highest first, with the original's `qsort` (4793:6110). The original also stops
/// adding entries once its far array holds 800 across all the game's plies (`64A4`);
/// that array is the screen's and is not kept here (no recorded game came near it).
pub fn displayList(bp: BookPosition, list: *const RawList) DisplayList {
    var tmp: DisplayList = .{};
    const ep_file = fileOf(bp.ep_square);
    var prefix: u16 = 0;
    for (list.words[0..list.count]) |w| {
        if (prefix == 0 and moveFrom(w) == moveTo(w)) {
            prefix = moveFrom(w); // 2..4: readList ended the list at any other value
            continue;
        }
        const mv: BookMove = (prefix << 12) | (w & 0x0FFF);
        prefix = 0;
        if (!moveOk(bp.board, mv, bp.side, ep_file)) continue;
        const g: u8 = @truncate((w >> 12) & 7);
        tmp.entries[tmp.len] = displayEntry(bp.board, mv, g, bp.side);
        tmp.moves[tmp.len] = mv;
        tmp.len += 1;
    }
    var order: [max_words]u8 = undefined;
    for (order[0..tmp.len], 0..) |*o, k| o.* = @intCast(k);
    msQsort(order[0..tmp.len], tmp.entries[0..tmp.len]);
    var out: DisplayList = .{ .len = tmp.len };
    for (order[0..tmp.len], 0..) |k, i| {
        out.entries[i] = tmp.entries[k];
        out.moves[i] = tmp.moves[k];
    }
    return out;
}

// ---------------------------------------------------------------------------
// The choice (4793:6A6B-6C5D)
// ---------------------------------------------------------------------------

/// The book settings book_probe reads.
pub const Settings = struct {
    /// DG:A6A0 bit 2 (4): the variety book.
    variety: bool = false,
    /// DG:A6A0 bit 5 (20h): the tournament book (the default).
    tournament: bool = true,
    /// DG:A5EE: the M-Chess book switched off (menu, or key K). The key is still
    /// computed, nothing is found.
    mchess_book_off: bool = false,

    pub const standard: Settings = .{ .tournament = false };
    pub const tournament_book: Settings = .{};
    pub const variety_book: Settings = .{ .variety = true, .tournament = false };

    /// From the original's flag word DG:A6A0 and DG:A5EE.
    pub fn fromFlags(a6a0: u16, a5ee: u16) Settings {
        return .{ .variety = a6a0 & 4 != 0, .tournament = a6a0 & 0x20 != 0, .mchess_book_off = a5ee != 0 };
    }
};

/// The size of the slot array (`[bp-6A4h]`, `[bp-384h]`): the walk stops when the
/// total weight passes it (4793:6B57).
pub const max_slots = 400;

/// The draw a position offers: the slot array of the choice walk.
pub const Draw = struct {
    slot_move: [max_slots]BookMove = undefined,
    slot_grade: [max_slots]u8 = undefined,
    /// Slots written.
    slots: u16 = 0,
    /// The total weight, which is the divisor of the draw: the slots written (DEV-026,
    /// corrected: the original's total can exceed them after the overflow below).
    total: i16 = 0,
    /// The move of the last grade-7 move, if any: played without a draw.
    forced: ?BookMove = null,
    /// A move of (effective) grade 4 or more was found.
    has_good: bool = false,
    /// The next move would have taken the total past 400 and the walk stopped (suspected
    /// bug 1).
    overflow: bool = false,
};

/// Port of the choice walk (4793:6A6B-6B9F). Walks the list again with the prefix
/// rule; grade 0 is skipped, grade 1 is skipped unless the variety bit is set (then it
/// is 3); in variety 3 becomes 4 and 5, 6 become 4, 5; the weight is DG:2AD4[grade]; a
/// grade-7 move is the forced move; grade 4 or more sets "has a good move". Each move
/// that passes the move check gets `weight` slots.
pub fn buildDraw(bp: BookPosition, list: *const RawList, settings: Settings) Draw {
    return buildDrawFixes(pos.Fixes.original, bp, list, settings);
}

/// `buildDraw` under `fixes` (DEV-026, `dev026_promotion_prefix`).
pub fn buildDrawFixes(comptime fixes: pos.Fixes, bp: BookPosition, list: *const RawList, settings: Settings) Draw {
    var d: Draw = .{};
    const ep_file = fileOf(bp.ep_square);
    var prefix: u16 = 0;
    for (list.words[0..list.count], list.grades[0..list.count]) |w, grade| {
        if (prefix == 0 and moveFrom(w) == moveTo(w)) {
            const v = moveFrom(w);
            if (v < 2 or v > 4) break;
            prefix = v;
            continue;
        }
        var g = grade;
        // 6AC9, 6AD8: the original skips a move of grade 0, or of grade 1 outside the
        // variety book, without clearing a pending promotion prefix ([bp-12h]), so the
        // prefix attaches to the next move (DEV-026, spec suspected bug 2). Every other
        // path clears it with the move it belongs to (6AEF), and the decode loop clears
        // it after every move. Corrected (`dev026_promotion_prefix`), the skip clears it.
        // UNVERIFIED: never exercised against the original; in the shipped book every
        // prefix is followed by its move, the list's last, so it cannot occur.
        if (g == 0 or (g == 1 and !settings.variety)) {
            if (fixes.dev026_promotion_prefix) prefix = 0;
            continue;
        }
        if (g == 1) g = 3;
        const mv: BookMove = (prefix << 12) | (w & 0x0FFF);
        prefix = 0;
        if (!moveOk(bp.board, mv, bp.side, ep_file)) continue;
        if (settings.variety) {
            if (g == 3) g = 4 else if (g == 5 or g == 6) g -= 1;
        }
        const weight = grade_weight[g];
        if (weight == 0) continue;
        // UNVERIFIED: grade 7 (the forced move) never occurs in the shipped book, so this
        // branch and the forced play below were never exercised against the original;
        // ported as the model and the specification read the code.
        if (g == 7) d.forced = mv;
        if (g >= 4) d.has_good = true;
        if (d.total + weight > max_slots) {
            // 6B54-6B5E (DEV-026, spec suspected bug 1): the original adds the weight
            // and, past 400, stops without writing this move's slots, so the total, the
            // divisor of the draw, counts slots never written, and a draw that falls on
            // one reads the stack (an uninitialised read). The guard is there to keep
            // the walk inside the 400 slots; corrected under the owner's rule on
            // uninitialised reads, the walk stops before the move that would pass 400
            // and the total is the slots written. UNVERIFIED: unreachable with the
            // shipped book (its largest total is 31).
            d.overflow = true;
            break;
        }
        d.total += weight;
        const n: u16 = @intCast(weight);
        @memset(d.slot_move[d.slots..][0..n], mv);
        @memset(d.slot_grade[d.slots..][0..n], g);
        d.slots += n;
    }
    return d;
}

/// Port of the draw (4793:6BEF-6C5D). A forced move is played with no `rand()` call.
/// Else, in the tournament book when a move of grade 4 or more exists, k = rand() %
/// total is drawn again until slot k has grade 4 or more (6C3E); else one draw
/// (6C52). Returns the move of slot k, or null when the total is 0.
///
/// In the original, after the overflow above, k can fall on a slot the walk never wrote
/// and the stack is read there (DEV-026, suspected bug 1). `buildDraw` keeps the total to
/// the slots written, so k always falls on a written slot; the test `k < d.slots` stays
/// as a guard. Unreachable with the shipped book.
pub fn choose(d: *const Draw, settings: Settings, rand: *Rand) ?BookMove {
    if (d.total == 0) return null;
    if (d.forced) |f| return f;
    const total: i32 = d.total;
    if (d.has_good and settings.tournament) {
        while (true) {
            const k: usize = @intCast(@rem(@as(i32, rand.next()), total));
            if (k < d.slots and d.slot_grade[k] >= 4) return d.slot_move[k];
        }
    }
    const k: usize = @intCast(@rem(@as(i32, rand.next()), total));
    return if (k < d.slots) d.slot_move[k] else null;
}

// ---------------------------------------------------------------------------
// book_probe (4793:621E)
// ---------------------------------------------------------------------------

/// The probe's mode argument (spec §4.1).
pub const Mode = enum(u8) {
    /// Before thinking on the opponent's time: is the predicted reply's position in
    /// the book? No list, no choice.
    query = 0,
    /// The program's own move: choose and hand over a book move.
    play = 1,
    /// After a game move: build the list for the side now to move.
    after_move = 2,
    /// Start-up, new game, set-up and take-back: build the list.
    refresh = 3,
};

/// The variables book_probe keeps between calls.
pub const Session = struct {
    /// DG:9FBC: the game ply at which the book was left, 0 while in it (signed).
    book_exit_ply: i16 = 0,
    /// DG:70E4: set when a position is set up or loaded; the probe then returns at
    /// once. (The "ignore book" key K sets `Settings.mchess_book_off` instead.)
    book_disabled: bool = false,
    /// DG:2522 + 2 * side: game ply + 1 of the side's last move drawn from the book.
    book_move_ply: [2]u16 = .{ 0, 0 },
};

/// What a probe gives.
pub const Result = struct {
    /// The probe returned at once (4793:6238-625E): nothing else was done.
    early: bool = false,
    /// DG:935A..935F (not computed on an early return).
    key: Key = 0,
    /// The position was found in the book (`[bp-1Ch]`).
    found: bool = false,
    /// DG:7449: the entry's name number, 0 when not found.
    name: u8 = 0,
    /// The book moves in the order the original lists them (empty for mode 0 and
    /// when not found).
    display: DisplayList = .{},
    /// Mode 1: the move handed over (DG:38A0 from, 38A1 to, 38A2 flag), or null.
    chosen: ?pos.Move = null,

    /// The return value (AX): in mode 1 whether a move was handed over, else whether
    /// the position was found; 0 on an early return.
    pub fn returnValue(r: *const Result, mode: Mode) u16 {
        if (r.early) return 0;
        return @intFromBool(if (mode == .play) r.chosen != null else r.found);
    }
};

/// Port of the gate of book_probe (4793:6238-625E): the probe returns 0 at once when
/// the game ply is above 200, when the book was left more than 10 plies ago (so a
/// transposition back into it within ten plies is found), or after a set-up.
pub fn gate(session: *const Session, ply: u16) bool {
    if (ply > 200) return false;
    const exit = session.book_exit_ply;
    if (exit != 0 and @as(i32, ply) - 10 > exit) return false;
    return !session.book_disabled;
}

/// Port of book_probe (4793:621E) with no user books and no book learning: the gate,
/// the key, the lookup (skipped when the M-Chess book is off), the list of book moves
/// (modes 1-3), the choice and the hand-over (mode 1, drawing from `rand`), and the
/// book-exit ply. `ply` is the game ply DG:9FC8.
pub fn probe(
    session: *Session,
    files: *const Files,
    bp: BookPosition,
    ply: u16,
    mode: Mode,
    settings: Settings,
    rand: *Rand,
) Result {
    return probeFixes(pos.Fixes.original, session, files, bp, ply, mode, settings, rand);
}

/// `probe` under `fixes` (DEV-026, `dev026_promotion_prefix`, in `buildDrawFixes`).
pub fn probeFixes(
    comptime fixes: pos.Fixes,
    session: *Session,
    files: *const Files,
    bp: BookPosition,
    ply: u16,
    mode: Mode,
    settings: Settings,
    rand: *Rand,
) Result {
    var r: Result = .{};
    if (!gate(session, ply)) {
        r.early = true;
        return r;
    }
    r.key = bookKey(bp);
    var list: RawList = .{};
    if (!settings.mchess_book_off) {
        if (lookup(files, r.key)) |e| {
            r.found = true;
            r.name = e.name;
            if (mode != .query) list = readList(files, e);
        }
    }
    if (r.found and mode != .query) {
        session.book_exit_ply = 0; // 6A6D
        r.display = displayList(bp, &list);
        const d = buildDrawFixes(fixes, bp, &list, settings);
        if (mode == .play and d.total != 0) {
            session.book_move_ply[@backingInt(bp.side)] = ply + 1; // 6BD2
            if (choose(&d, settings, rand)) |mv| r.chosen = realMove(bp.board, mv, bp.side);
        }
    }
    if (mode == .play and r.chosen == null and session.book_exit_ply == 0) session.book_exit_ply = @bitCast(ply); // 6D80
    if (mode == .refresh and !r.found and session.book_exit_ply == 0) session.book_exit_ply = @bitCast(ply); // 6D99
    return r;
}

test "rand() after srand(1) is the Microsoft C sequence" {
    var r = Rand.srand(1);
    const want = [_]u15{ 41, 18467, 6334, 26500, 19169 };
    for (want) |w| try std.testing.expectEqual(w, r.next());
}

test "mirror and mailbox" {
    try std.testing.expectEqual(@as(u8, 91), mirror(21));
    try std.testing.expectEqual(@as(u8, 25), mirror(95));
    try std.testing.expectEqual(@as(u8, 21), mailbox(0));
    try std.testing.expectEqual(@as(u8, 98), mailbox(63));
}

test "the constant tables are the model's" {
    // tools/research/book/book.py WEIGHTS, CASTLE_KEYS, EP_KEYS, HASH_SQ_OFFSET, which
    // check.py compares with the running original on the first call of every run.
    try std.testing.expectEqualSlices(i8, &.{ 0, 1, 1, 2, 3, 6, 9, 3 }, &grade_weight);
    try std.testing.expectEqual(@as(u48, 0xCDF9CE189373), castle_keys[0]);
    try std.testing.expectEqual(@as(u48, 0x7AED68751E21), castle_keys[3]);
    try std.testing.expectEqual(@as(u48, 0), ep_keys[0]);
    try std.testing.expectEqual(@as(u48, 0x879559B45D96), ep_keys[1]);
    try std.testing.expectEqual(@as(u48, 0xA67E9B4485CE), ep_keys[8]);
    try std.testing.expectEqual(@as(u48, 0), ep_keys[9]);
    for (0..8) |r| for (0..8) |f| {
        try std.testing.expectEqual(@as(u16, @truncate(78 * (8 * r + f) -% 6)), square_offset[21 + 10 * r + f]);
    };
    // The step tables: a diagonal step by from - to, as the model's DIAG_STEP.
    for (1..8) |k| {
        const i: i32 = @intCast(k);
        try std.testing.expectEqual(@as(i8, 9), diag_step[@intCast(-9 * i + 77)]);
        try std.testing.expectEqual(@as(i8, -11), diag_step[@intCast(11 * i + 77)]);
        try std.testing.expectEqual(@as(i8, 10), orth_step[@intCast(-10 * i + 77)]);
        try std.testing.expectEqual(@as(i8, -1), orth_step[@intCast(i + 77)]);
    }
    var knights: usize = 0;
    var kings: usize = 0;
    for (knight_move, king_move) |n, k| {
        knights += @intFromBool(n != 0);
        kings += @intFromBool(k != 0);
    }
    try std.testing.expectEqual(@as(usize, 8), knights);
    try std.testing.expectEqual(@as(usize, 8), kings);
}
