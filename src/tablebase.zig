//! The tablebase probe: tb_probe (2B9F:BB76).
//!
//! Specification: docs/arch/22-search-helpers.md section 6, whose executable form is
//! `tb_probe` in tools/research/helpers/model.py (proved by direct calls of the original
//! on made-up positions, tools/research/helpers/probe.py). Tests: src/tablebase_test.zig,
//! which replays calls recorded from the original (tests/golden/tablebase/, made by
//! tools/port/gen_tablebase_vectors.py) with the real tablebase files.
//!
//! Given a position, the probe names the tablebase file for its material (`KQK.TBW` and
//! so on), computes the position's index in it, reads the one byte there and turns it
//! into a score. The files hold one signed byte per position: 0 a draw, b > 0 a win in
//! b, b < 0 a loss; a byte outside -126..126 means "no result".
//!
//! **Files are supplied by the caller** (`Files`): this unit opens nothing and embeds
//! nothing. The original tries up to two places (step 10 of the specification): the
//! `TB` folder in the program's directory (`Location.program_tb`) and a second
//! directory string (`Location.second_dir`), each by the file name the probe builds.
//!
//! `DG:xxxx` is an address in the original's default data segment (DGROUP).
//!
//! Work areas: the original builds its lists in DG:77F4, 7808, 8CD8 (8 bytes each),
//! the counts in DG:8BB8, 8BBA, 9EBC, the order flag in DG:B521, the file name in
//! DG:B50E and the squares in DG:8FCA, and sprintf leaves the C run-time's string FILE
//! at DG:3476. No other code in the decoded listings reads any of them (only the score,
//! DG:7466), so they are not kept as state here; `locate` returns the values the test
//! compares with them.

const std = @import("std");
const pos = @import("position.zig");
const original = @import("original.zig");

// ---------------------------------------------------------------------------
// Class C fixes (AGENTS.md §9.2)
// ---------------------------------------------------------------------------

/// The switchable bug fixes of this unit. `original` reproduces the original exactly and
/// is what the differential test uses; `corrected` is what the engine ships with.
pub const Fixes = struct {
    /// DEV-025: when the file's read returns no byte (the index is at or past the end of
    /// the file, or negative, which DOS takes as a huge unsigned offset), the original
    /// uses the byte already in its stack slot `[bp-7]`: whatever the stack held, or the
    /// byte an earlier variant read in the same call. Corrected: such a read gives no
    /// result and the probe goes on to the next variant, exactly as for a byte outside
    /// -126..126. PROVISIONAL: the owner has not yet seen this correction.
    dev025_failed_read_no_result: bool,

    pub const original: Fixes = .{ .dev025_failed_read_no_result = false };
    pub const corrected: Fixes = .{ .dev025_failed_read_no_result = true };
};

// ---------------------------------------------------------------------------
// The files
// ---------------------------------------------------------------------------

/// Where the original looks for a file (C050..C14D).
pub const Location = enum {
    /// `sprintf("%Fs\TB\%s", 5A7B:7584, name)`: the `TB` folder of the program's
    /// directory (5A7B:7584 holds the directory, e.g. `C:\CHESS\MCHESS\M80`).
    program_tb,
    /// `sprintf("%Fs%s%s", 5A7B:5038, sep, name)`: the directory string at 5A7B:5038
    /// (empty at run time, so the root of the current drive), with a `\` between unless
    /// the string ends with one.
    second_dir,
};

/// The tablebase files, supplied by the layer above. `lookup` returns a file's whole
/// contents, or null if it does not exist (the original's open fails).
pub const Files = struct {
    ctx: ?*const anyopaque = null,
    lookupFn: *const fn (ctx: ?*const anyopaque, loc: Location, name: []const u8) ?[]const u8,

    pub fn lookup(f: Files, loc: Location, name: []const u8) ?[]const u8 {
        return f.lookupFn(f.ctx, loc, name);
    }
};

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// The variables the probe reads or writes beyond `Position`.
pub const State = struct {
    /// DG:239A: number of material signatures (a signed word; 6 at run time). The
    /// signature test at ply != 0 is skipped when it is negative (BBD8).
    signature_count: i16 = 0,
    /// DG:A422: the material signatures, at least `signature_count` words (at run time
    /// 4000h, 1F00h, 1100h, 40h, 1Fh, 11h: K+P, K+Q, K+R against a bare king, either way).
    signatures: []const u16 = &.{},
    /// DG:239C: the tablebase mode bits: bit 0 enables the probe away from the root, bit
    /// 1 the second directory, bits 2 (away from the root) and 3 (at the root) the
    /// program's `TB` folder. 0Ah in the repeatable state.
    mode: u8 = 0,
    /// DG:8DDE: the side the program plays (a byte compared, sign-extended, with `side`).
    program_side: u8 = 0,
    /// DG:AFC4: the bound a score is compared with before it is accepted (step 10).
    score_bound: i16 = 0,
    /// DG:7466: the probe's score, written only when a usable byte is read.
    score: i16 = 0,
};

// ---------------------------------------------------------------------------
// Constant tables, read from the original's initialised data
// ---------------------------------------------------------------------------

/// DG:1078 (rank of a square) and DG:100A (file), each read from 128 bytes before to
/// 128 bytes after the table's start, so that any square the probe can form (a signed
/// byte; a pawn moved 30 back by the en-passant rule can go below 0) reads the byte the
/// original reads.
const rank_window = original.dgroup(0x1078 - 128, 256);
const file_window = original.dgroup(0x100A - 128, 256);

/// DG:1C30 + type: the letter of a piece type (1 P .. 5 Q).
const letters = original.dgroup(0x1C30, 6);
/// DG:2372 ".TBW" and DG:2378 ".TBB" (4 letters each, then a NUL).
const suffix_w = original.dgroup(0x2372, 4);
const suffix_b = original.dgroup(0x2378, 4);
/// DG:237E: square 0..27 (a1..d4) to its number 0..9 in the a1-d1-d4 triangle (0 off
/// the triangle), for the last man of a pawnless ending after the symmetry reductions.
/// The table is 28 bytes: DG:239A (the signature count) and DG:239C (the mode) follow
/// it. After the reductions the entry is always in the triangle (file a-d, rank at most
/// the file) when the last man is a piece on a real square, which holds whenever the
/// pawn count DG:90AA agrees with the board. Any other index would read those variables
/// in the original; here it is a class A defect and traps in safe builds.
const triangle = original.dgroup(0x237E, 28);

comptime {
    std.debug.assert(std.mem.eql(u8, &suffix_w, ".TBW"));
    std.debug.assert(std.mem.eql(u8, &suffix_b, ".TBB"));
    std.debug.assert(letters[1] == 'P' and letters[5] == 'Q');
}

// ---------------------------------------------------------------------------
// The probe
// ---------------------------------------------------------------------------

/// Men per side the original's lists hold (DG:77F4, 7808, 8CD8 give each side 4 bytes).
pub const max_men_per_side = 4;
/// Men in all: the multiplier array on the stack holds 8.
pub const max_men = 2 * max_men_per_side;

/// What the probe computes before it reads a file: the values the original leaves in
/// its work areas, and the file index.
pub const Located = struct {
    /// DG:B521: the side named first in the file name is Black.
    first_black: bool,
    /// DG:8BB8 (White) and DG:8BBA (Black): men per side, kings included.
    counts: [2]u8,
    /// DG:9EBC: men in all.
    men: u8,
    /// DG:B50E: the file name, the first side's letters, the other's, then .TBW or
    /// .TBB (`men + 4` bytes; the original adds a NUL).
    name_buf: [max_men + 4]u8,
    /// DG:8FCA: per man, in name order, the square as 0..63 (a1..h8) after every
    /// transformation (colour reversal, mirroring, and the last man's reduction).
    entries: [max_men]u16,
    /// The 32-bit file index (BFB8..C000), wrapping; a "negative" index is a huge
    /// unsigned offset, as DOS takes it.
    index: u32,

    pub fn name(l: *const Located) []const u8 {
        return l.name_buf[0 .. @as(usize, l.men) + 4];
    }
};

/// A board byte as the probe counts it: 8 * side + type for a man other than a king
/// (codes 1..5 White, 8..12 Black), 0 for every other byte.
const man_class: [256]u8 = blk: {
    var t: [256]u8 = @splat(0);
    for (1..6) |ty| {
        t[ty] = ty;
        t[ty + 7] = 8 | ty;
    }
    break :blk t;
};

inline fn sx8(b: u8) i16 {
    return @as(i8, @bitCast(b));
}

inline fn sx16(w: u16) i32 {
    return @as(i16, @bitCast(w));
}

inline fn asWord(x: i16) u16 {
    return @bitCast(x);
}

/// The material signature test (BB81..BC08), made only when `ply` != 0. True if the
/// call goes on.
fn signatureFound(p: *const pos.Position, st: *const State, side: u1) bool {
    // Pawn counts are bytes, sign-extended; "own" is White for side 0.
    const wp = asWord(sx8(p.side_pawn_count[0]));
    const bp = asWord(sx8(p.side_pawn_count[1]));
    const own = if (side == 0) wp else bp;
    const opp = if (side == 0) bp else wp;
    var dx: u16 = ((own & 0xFF) << 8) | opp;
    dx <<= 4;
    dx |= (p.piece_material[side] +% 10) & 0x3FC0;
    dx <<= 2;
    dx |= asWord(@as(i16, @bitCast(p.piece_material[1 - @as(u2, side)] +% 10)) >> 6);
    const n = st.signature_count;
    if (n < 0) return true; // the search loop does not run and its index (0) is not n
    for (st.signatures[0..@intCast(n)]) |s| {
        if (s == dx) return true;
    }
    return false;
}

/// Steps 2 to 8 of the specification (BB76..C000): the signature test (ply != 0), the
/// men, the order of the sides, the file name, the squares and their reductions, and
/// the index. Null when the signature test fails (the original then returns 0 and
/// writes nothing) or when the position has more men than the original's arrays hold
/// (more than 4 on a side or 8 in all; only possible at ply 0, where there is no
/// signature test: the original then writes past its arrays, which cannot be
/// reproduced; this port gives no result).
pub fn locate(p: *const pos.Position, st: *const State, side: u1, ply: u16) ?Located {
    if (ply != 0 and !signatureFound(p, st, side)) return null;

    // BC0A..BCF9: each side's men: the king (list slot 7), then Q, R, B, N, P in square
    // order a1..h8. A pawn whose en-passant square (DG:9ECA, ply 2) lies behind it is
    // moved 30 back (White) or on (Black), byte arithmetic.
    //
    // The original scans squares 21..98 once per piece type and side (ten scans). One
    // scan that sorts each man into its side and type, square order kept within a type,
    // gives the same lists. More than three men besides the king on either side is the
    // case the original's arrays cannot hold; it gives no result whichever scan finds it.
    var by_type: [2][6][max_men_per_side - 1]u8 = undefined;
    var n_type: [2][6]u8 = @splat(@splat(0));
    var n_side: [2]u8 = .{ 0, 0 };
    for (21..99) |square| {
        const k = man_class[p.board[square]];
        if (k == 0) continue;
        const s = k >> 3;
        const t = k & 7;
        if (n_side[s] == max_men_per_side - 1) return null;
        n_side[s] += 1;
        by_type[s][t][n_type[s][t]] = @intCast(square);
        n_type[s][t] += 1;
    }
    var sq: [2][max_men_per_side]u8 = undefined;
    var ty: [2][max_men_per_side]u8 = undefined;
    var counts: [2]u8 = undefined;
    const ep = p.ep_square_by_ply[2];
    inline for (0..2) |s| {
        sq[s][0] = p.piece_list[16 * s + 7];
        var n: usize = 1;
        var t: u8 = 5;
        while (t >= 1) : (t -= 1) {
            for (by_type[s][t][0..n_type[s][t]]) |square| {
                var v: u8 = square;
                if (t == 1 and ep != 0) {
                    const d = sx8(ep) - @as(i16, v);
                    if (s == 0 and d == -10) v -%= 30;
                    if (s == 1 and d == 10) v +%= 30;
                }
                sq[s][n] = v;
                ty[s][n] = t;
                n += 1;
            }
        }
        counts[s] = @intCast(n);
    }
    const men: usize = counts[0] + counts[1];

    // BCF9..BDAE: Black first if it has more men, or as many and, type by type from
    // index 1, the first difference is a higher Black type.
    var first_black = counts[1] > counts[0];
    if (counts[1] == counts[0]) {
        for (1..counts[1]) |k| {
            if (ty[1][k] != ty[0][k]) {
                first_black = ty[1][k] > ty[0][k];
                break;
            }
        }
    }
    const f: usize = @intFromBool(first_black);

    // BD16..BDC1: the name; BDC2..BE3B: the squares, the first side's then the other's.
    var l: Located = .{
        .first_black = first_black,
        .counts = counts,
        .men = @intCast(men),
        .name_buf = undefined,
        .entries = undefined,
        .index = 0,
    };
    var k: usize = 0;
    for ([2]usize{ f, 1 - f }) |s| {
        for (0..counts[s]) |i| {
            l.name_buf[k] = if (i == 0) 'K' else letters[ty[s][i]];
            // BE50: square to 8*rank + file - 11h (0..63 for a1..h8), as a word.
            const v: i16 = sx8(sq[s][i]);
            const idx: usize = @intCast(@as(i16, 128) + v);
            const r: i16 = sx8(rank_window[idx]);
            const fl: i16 = sx8(file_window[idx]);
            l.entries[k] = asWord((r << 3) +% fl -% 0x11);
            k += 1;
        }
    }
    @memcpy(l.name_buf[men..][0..4], if ((side != 0) == first_black) &suffix_w else &suffix_b);
    const e = l.entries[0..men];

    // BE6E: colour reversal: Black named first, every rank flipped.
    if (first_black) for (e) |*x| {
        x.* ^= 0x38;
    };

    // BE91..BFB6: multipliers, and the symmetry reduction of the last man (pawnless) or
    // of the last pawn in the name.
    var mult: [max_men]u8 = @splat(0x40);
    if (p.pawn_count != 0) {
        var bx: usize = men - 1;
        while (bx >= 1 and l.name_buf[bx] != 'P') bx -= 1;
        if (e[bx] & 7 >= 4) for (e) |*x| {
            x.* ^= 7; // files e-h mirrored to d-a
        };
        mult[bx] = 0x20;
        const w = e[bx];
        e[bx] = w -% asWord(@as(i16, @bitCast(w & 0xFFF9)) >> 1);
    } else {
        const di = men - 1;
        if (@as(i16, @bitCast(e[di] & 0xFFF8)) >= 0x20) for (e) |*x| {
            x.* ^= 0x38; // ranks 5-8 flipped to 4-1
        };
        if (e[di] & 7 >= 4) for (e) |*x| {
            x.* ^= 7; // files e-h mirrored to d-a
        };
        const v = e[di];
        if ((@as(i16, @bitCast(v)) >> 3) > (v & 7)) for (e) |*x| {
            // transpose: above the a1-h8 diagonal, reflect in it
            x.* = ((x.* & 7) << 3) +% asWord(@as(i16, @bitCast(x.*)) >> 3);
        };
        mult[di] = 0x0A;
        e[di] = asWord(sx8(triangle[e[di]]));
    }

    // BFB8..C000: acc = (...((e[n-1]) * m[n-2] + e[n-2]) * m[n-3] ...) + e[0], 32-bit.
    var acc: u32 = 0;
    var i: usize = men - 1;
    while (i >= 1) : (i -= 1) {
        acc = (acc +% @as(u32, @bitCast(sx16(e[i])))) *% @as(u32, mult[i - 1]);
    }
    l.index = acc +% @as(u32, @bitCast(sx16(e[0])));
    return l;
}

/// Port of tb_probe (2B9F:BB76), far C `(side, ply)`. The search node calls it with
/// side 1 at a White node and 0 at a Black node. Returns AX != 0: the file gave a
/// usable score, left in `st.score` (DG:7466).
///
/// `stale_byte` is the byte in the original's stack slot `[bp-7]` at entry. The original
/// reads each file's byte into that slot and uses whatever is there when the read
/// returns nothing (DEV-025); with the fix off it is an input, taken from the recorded
/// calls in the test. With `fixes.dev025_failed_read_no_result` it is never read.
pub fn probe(
    comptime fixes: Fixes,
    p: *const pos.Position,
    st: *State,
    files: Files,
    side: u1,
    ply: u16,
    stale_byte: u8,
) bool {
    const l = locate(p, st, side, ply) orelse return false;

    // C003..C021: the variants to try.
    var flags: u8 = (if (ply == 0) @as(u8, 0x0A) else 0x06) & st.mode;
    if (ply != 0 and st.mode & 1 == 0) flags &= 4;

    var ret = false;
    var slot = stale_byte; // [bp-7]
    while (flags != 0) {
        // C050..C14D
        const loc: Location = if (flags & 0x0C != 0) .program_tb else .second_dir;
        if (loc == .program_tb) flags &= 2 else flags = 0;
        const data = files.lookup(loc, l.name()) orelse continue;
        if (l.index < data.len) {
            slot = data[l.index];
        } else if (fixes.dev025_failed_read_no_result) {
            continue;
        }
        const b: i16 = sx8(slot);
        if (b < -0x7E or b > 0x7E) continue;
        ret = true;
        const pl: i16 = @bitCast(ply);
        const t: i16 = if (b == 0) 0 else if (b > 0) 2 *% (b +% 0x2691) -% pl else 2 *% (b -% 0x2691) +% pl;
        st.score = t;
        if (asWord(sx8(st.program_side)) == side) {
            if (t > 0 and !(st.score_bound < t)) ret = false;
        } else {
            if (t < 0 and !(-%t > st.score_bound)) ret = false;
        }
    }
    return ret;
}
