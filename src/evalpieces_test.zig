//! Differential tests of src/evalpieces.zig and src/activity.zig against calls recorded
//! from the running original (tests/golden/evalpieces/*.zst, made by
//! tools/port/gen_evalpieces_vectors.py, whose docstring defines the format).
//!
//! Every call's input image is rebuilt from the recorded regions, loaded into a
//! `Position` and an `EvalState` by DGROUP address, and the routine is run. AX must be
//! equal, and for eval_pieces_and_kings the running score at each of the 15 checkpoints
//! the original passed (the model's CHECKPOINTS) must be equal too, so that a wrong
//! section is named by the first checkpoint after it.

const std = @import("std");
const pos = @import("position.zig");
const activity = @import("activity.zig");
const evalpieces = @import("evalpieces.zig");
const EvalState = @import("eval_state.zig").EvalState;
const dg = @import("original.zig").dgroup;

pub const Image = [0x10000]u8;

// ---- loading the state from a DGROUP image -----------------------------------------

fn byteAt(img: *const Image, a: usize) u8 {
    return img[a];
}
fn wordAt(img: *const Image, a: usize) u16 {
    return std.mem.readInt(u16, img[a..][0..2], .little);
}
fn dwordAt(img: *const Image, a: usize) u32 {
    return std.mem.readInt(u32, img[a..][0..4], .little);
}

pub fn loadPosition(img: *const Image) pos.Position {
    var p: pos.Position = .{};
    p.board = img[0x9EF6..][0..120].*;
    p.piece_list = img[0xA03A..][0..32].*;
    p.square_slot = img[0xA28C..][0..120].*;
    p.pawn_attacks = .{ img[0xA51C..][0..120].*, img[0x37DA..][0..120].* };
    p.king_rays = .{ img[0xA09E..][0..120].*, img[0xA164..][0..120].* };
    p.pawns_per_file = .{ img[0xA8C8..][0..10].*, img[0x9EA8..][0..10].* };
    p.piece_material = .{ wordAt(img, 0xAE38), wordAt(img, 0xAE3A) };
    p.piece_material_sum = wordAt(img, 0x378E);
    p.material_balance = wordAt(img, 0xA35E);
    p.piece_balance = wordAt(img, 0xA8D2);
    p.piece_count = .{ byteAt(img, 0x931A), byteAt(img, 0x931B) };
    p.pawn_count = byteAt(img, 0x90AA);
    p.side_pawn_count = .{ byteAt(img, 0xAB1E), byteAt(img, 0x741A) };
    p.pawns_on_dark = .{ byteAt(img, 0xB520), byteAt(img, 0xA354) };
    p.king_file = .{ byteAt(img, 0xA22E), byteAt(img, 0xA22F) };
    p.king_rank = .{ byteAt(img, 0x70F0), byteAt(img, 0x70F1) };
    p.oo_lost_at = .{ wordAt(img, 0xB426), wordAt(img, 0xB428) };
    p.ooo_lost_at = .{ wordAt(img, 0x3A30), wordAt(img, 0x3A32) };
    p.game_ply = wordAt(img, 0x9FC8);
    return p;
}

fn loadWords(img: *const Image, a: usize, comptime n: usize) [100]u16 {
    var t: [100]u16 = @splat(0);
    for (0..n) |i| t[i] = wordAt(img, a + 2 * i);
    return t;
}

pub fn loadState(img: *const Image) EvalState {
    var e: EvalState = .{};
    e.past_board = img[0x9F6E..][0..78].*;
    e.shelter_first_rank = img[0x9EBE..][0..10].*;
    e.passed_pawns = .{ byteAt(img, 0xA6C2), byteAt(img, 0x9D8C) };
    e.no_pawns_at_root = byteAt(img, 0xA6A3);
    e.ply_flag = img[0x9D94..][0..64].*;
    e.last_irreversible_ply = wordAt(img, 0x7464);
    e.style_normal = wordAt(img, 0x1548);
    e.mobility_weight = dwordAt(img, 0x290A);
    e.king_placement_weight = dwordAt(img, 0x2912);
    // The tables at the original's length (Stage B step 6): 100 entries each; the recorded
    // regions end with Black's.
    e.king_table = .{ loadWords(img, 0x7260, 100), loadWords(img, 0x732A, 99) };
    e.king_zone = .{ loadWords(img, 0xAEFA, 100), loadWords(img, 0xB03E, 99) };
    e.rook_square[0] = img[0xA6C8..][0..100].*;
    e.rook_square[1] = img[0xA72E..][0..100].*;
    const tables = [2][4]usize{ .{ 0xA84E, 0xA2F0, 0xABA0, 0xAB20 }, .{ 0xA9B4, 0xA390, 0xAFC6, 0xADBE } };
    for (tables, 0..) |side, s| {
        for (side, 0..) |a, k| {
            if (k == 1) e.bishop_activity[s] = img[a..][0..100].* else e.nrq_activity[s][if (k == 0) 0 else k - 1] = img[a..][0..120].*;
        }
    }
    return e;
}

/// The position as a FEN board, for failure reports.
pub fn fenOf(buf: []u8, p: *const pos.Position) []const u8 {
    const glyph = ".PNBRQK?pnbrqk";
    var n: usize = 0;
    var r: usize = 9;
    while (r >= 2) : (r -= 1) {
        var gap: u8 = 0;
        for (1..9) |f| {
            const v = p.board[r * 10 + f];
            if (v == 0) {
                gap += 1;
                continue;
            }
            if (gap > 0) {
                buf[n] = '0' + gap;
                n += 1;
                gap = 0;
            }
            buf[n] = if (v < glyph.len) glyph[v] else '?';
            n += 1;
        }
        if (gap > 0) {
            buf[n] = '0' + gap;
            n += 1;
        }
        if (r > 2) {
            buf[n] = '/';
            n += 1;
        }
    }
    return buf[0..n];
}

// ---- the vector file ----------------------------------------------------------------

const Cursor = struct {
    d: []const u8,
    i: usize = 0,

    fn byte(c: *Cursor) u8 {
        const v = c.d[c.i];
        c.i += 1;
        return v;
    }
    fn int(c: *Cursor, comptime T: type) T {
        const n = @sizeOf(T);
        const v = std.mem.readInt(T, c.d[c.i..][0..n], .little);
        c.i += n;
        return v;
    }
    fn take(c: *Cursor, n: usize) []const u8 {
        const v = c.d[c.i..][0..n];
        c.i += n;
        return v;
    }
    fn varint(c: *Cursor) usize {
        var n: usize = 0;
        var shift: std.math.Log2Int(usize) = 0;
        while (true) {
            const b = c.byte();
            n |= @as(usize, b & 0x7F) << shift;
            if (b & 0x80 == 0) return n;
            shift += 7;
        }
    }
    fn apply(c: *Cursor, state: []u8) void {
        const n = c.varint();
        var prev: isize = -1;
        for (0..n) |_| {
            const off: usize = @intCast(prev + 1 + @as(isize, @intCast(c.varint())));
            state[off] ^= c.byte();
            prev = @intCast(off);
        }
    }
};

fn readVectors(gpa: std.mem.Allocator, name: []const u8) ![]u8 {
    var path_buf: [256]u8 = undefined;
    const dir = @import("build_options").golden_dir;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/evalpieces/{s}", .{ dir, name });
    const compressed = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, gpa, .limited(64 << 20));
    defer gpa.free(compressed);
    var in: std.Io.Reader = .fixed(compressed);
    const window = try gpa.alloc(u8, std.compress.zstd.default_window_len + std.compress.zstd.block_size_max);
    defer gpa.free(window);
    var zd = std.compress.zstd.Decompress.init(&in, window, .{});
    return zd.reader.allocRemaining(gpa, .limited(512 << 20));
}

/// The constant data the routines read, as the recorder found it in the running
/// original, must equal what the port reads from the program file.
fn checkConstant(addr: u16, bytes: []const u8) !void {
    const window = dg(0, 0x1700);
    if (!std.mem.eql(u8, bytes, window[addr..][0..bytes.len])) {
        std.debug.print("constant region DG:{X:0>4} differs from the program file\n", .{addr});
        return error.ConstantRegionDiffers;
    }
}

pub const Counts = struct {
    epk: usize = 0,
    white: usize = 0,
    black: usize = 0,
    mobility: usize = 0,
    /// DEV-017: calls whose result the correction changes, and of those the ones checked
    /// against the original's own e1 / e8 path (`twin017`).
    dev017_changed: usize = 0,
    dev017_twins: usize = 0,
    /// The first such call of the file: its board, the original's and the corrected value.
    dev017_example: [100]u8 = undefined,
    dev017_example_len: usize = 0,
    dev017_example_values: [2]i16 = .{ 0, 0 },
    dev017_example_side: u16 = 0,
    /// DEV-018: activity calls with a captured slot, run again with piece codes past the
    /// board.
    dev018_checked: usize = 0,
};

const fixed_017: pos.Fixes = blk: {
    var f = pos.Fixes.original;
    f.dev017_king_square = true;
    break :blk f;
};

/// DEV-017's evidence on a recorded call that the correction changes. The original itself
/// evaluates the king on e1 (e8) after a kingside hit when the queenside test then runs
/// and ends at 04A2 (0F26), `di = 25` (95): it runs when the long castling right is held
/// and the side has a b-pawn, and ends there when no c-pawn is on the board. For each side
/// whose kingside test ran, two states are made from the recorded one, alike in every
/// field but one: no c-pawns and a b-pawn for the side in both; the long castling right
/// lost in `lost` (the queenside test does not run: the stale path) and held in `held`
/// (the original's own path to e1). The king tables are made distinct square by square,
/// so that no two squares score alike by chance. Then the corrected value of `lost` must
/// equal the value of `held`, less the queenside test's own -36 (043D; +36 for Black,
/// 0EC1) if its diagonals hit. `held` is valued corrected too, so that a stale path of
/// the other side, alike in both, is corrected in both; the side's own path in `held`
/// is the original's. Returns the number of sides checked where the correction changed
/// `lost`.
fn twin017(p: *const pos.Position, e: *const EvalState, side: u16, ply: u16) !usize {
    var e2 = e.*;
    for (&e2.king_table, 0..) |*row, c| {
        for (row, 0..) |*v, k| v.* +%= @intCast(7 * k + 1000 * c);
    }
    var checked: usize = 0;
    for ([2]usize{ 0, 1 }) |s| {
        if (p.oo_lost_at[s] != 0 or p.pawns_per_file[s][7] == 0) continue;
        var lost = p.*;
        lost.pawns_per_file[0][3] = 0;
        lost.pawns_per_file[1][3] = 0;
        if (lost.pawns_per_file[s][2] == 0) lost.pawns_per_file[s][2] = 1;
        lost.ooo_lost_at[s] = 1;
        var held = lost;
        held.ooo_lost_at[s] = 0;
        const fixed = evalpieces.evalPiecesAndKingsFixes(fixed_017, &lost, &e2, side, ply);
        const twin = evalpieces.evalPiecesAndKingsFixes(fixed_017, &held, &e2, side, ply);
        const queenside_hit: i16 = if (s == 0) -36 else 36;
        if (twin != fixed and twin != fixed +% queenside_hit) {
            std.debug.print("DEV-017 twin (side {d}): corrected {d}, the original's own e1/e8 path {d}\n", .{ s, fixed, twin });
            return error.TwinDiffers;
        }
        if (fixed != evalpieces.evalPiecesAndKings(&lost, &e2, side, ply)) checked += 1;
    }
    return checked;
}

const max_regions = 64;

/// Recorded calls kept in memory: every `stride`-th call of each kind, and at most
/// `per_file` of each kind from one vector file.
pub const Collector = struct {
    stride: usize,
    per_file: usize = std.math.maxInt(usize),
    seen: [5]usize = @splat(0),
    kept: [5]usize = @splat(0),
    positions: std.ArrayList(pos.Position) = .empty,
    states: std.ArrayList(EvalState) = .empty,
    calls: std.ArrayList(Call) = .empty,

    const Call = struct { tag: u8, side: u16, ply: u16, p: u32, e: u32 };

    fn push(col: *Collector, gpa: std.mem.Allocator, tag: u8, side: u16, ply: u16, p: *const pos.Position, e: *const EvalState) !void {
        col.seen[tag] += 1;
        if (col.seen[tag] % col.stride != 0 or col.kept[tag] >= col.per_file) return;
        col.kept[tag] += 1;
        const n = col.states.items.len;
        if (n == 0 or !std.mem.eql(u8, std.mem.asBytes(&col.states.items[n - 1]), std.mem.asBytes(e))) try col.states.append(gpa, e.*);
        try col.positions.append(gpa, p.*);
        try col.calls.append(gpa, .{ .tag = tag, .side = side, .ply = ply, .p = @intCast(col.positions.items.len - 1), .e = @intCast(col.states.items.len - 1) });
    }
    pub fn deinit(col: *Collector, gpa: std.mem.Allocator) void {
        col.positions.deinit(gpa);
        col.states.deinit(gpa);
        col.calls.deinit(gpa);
    }
};

fn replay(gpa: std.mem.Allocator, name: []const u8) !Counts {
    return replayInto(gpa, name, null);
}

pub fn replayInto(gpa: std.mem.Allocator, name: []const u8, col: ?*Collector) !Counts {
    if (col) |k| k.kept = @splat(0);
    const data = try readVectors(gpa, name);
    defer gpa.free(data);
    var c: Cursor = .{ .d = data };
    try std.testing.expectEqualSlices(u8, "MCEP", c.take(4));
    try std.testing.expectEqual(@as(u16, 1), c.int(u16));
    const size = c.int(u16);
    const nr = c.int(u16);
    var addr: [max_regions]u16 = undefined;
    var len: [max_regions]u16 = undefined;
    for (0..nr) |i| {
        addr[i] = c.int(u16);
        len[i] = c.int(u16);
    }
    for (0..c.int(u16)) |_| {
        const a = c.int(u16);
        const n = c.int(u16);
        try checkConstant(a, c.take(n));
    }
    const state = try gpa.alloc(u8, size);
    defer gpa.free(state);
    @memcpy(state, c.take(size));
    const img = try gpa.create(Image);
    defer gpa.destroy(img);
    @memset(img, 0xA5); // bytes outside the regions are never read
    var counts: Counts = .{};
    var index: usize = 0;
    var fen: [100]u8 = undefined;
    while (true) : (index += 1) {
        const tag = c.byte();
        if (tag == 0) {
            try std.testing.expectEqual(counts.epk, c.int(u32));
            try std.testing.expectEqual(counts.white, c.int(u32));
            try std.testing.expectEqual(counts.black, c.int(u32));
            try std.testing.expectEqual(counts.mobility, c.int(u32));
            return counts;
        }
        if (tag == 5) {
            if (!std.mem.eql(u8, c.take(size), state)) return error.FullImageDiffers;
            continue;
        }
        c.apply(state);
        var o: usize = 0;
        for (0..nr) |i| {
            @memcpy(img[addr[i]..][0..len[i]], state[o..][0..len[i]]);
            o += len[i];
        }
        const p = loadPosition(img);
        const e = loadState(img);
        switch (tag) {
            1 => {
                const side = c.byte();
                const ply = c.byte();
                const ax: i16 = @bitCast(c.int(u16));
                const mask = c.int(u16);
                var want: evalpieces.Checkpoints = .{};
                for (0..evalpieces.checkpoint_addresses.len) |i| {
                    if (mask >> @intCast(i) & 1 != 0) want.score[i] = @bitCast(c.int(u16));
                }
                var got: evalpieces.Checkpoints = .{};
                if (col) |k| try k.push(gpa, 1, side, ply, &p, &e);
                const got_ax = evalpieces.evalPiecesAndKingsTraced(&p, &e, side, ply, &got);
                try std.testing.expectEqual(got_ax, evalpieces.evalPiecesAndKings(&p, &e, side, ply));
                var bad: ?usize = null;
                for (want.score, got.score, 0..) |w, g, i| {
                    if (!std.meta.eql(w, g)) {
                        bad = i;
                        break;
                    }
                }
                if (bad != null or got_ax != ax) {
                    std.debug.print("\n{s}: record {d} differs: eval_pieces_and_kings(side {d}, ply {d}) on {s}: AX want {d}, got {d}\n", .{ name, index, side, ply, fenOf(&fen, &p), ax, got_ax });
                    if (bad) |i| std.debug.print("  first differing checkpoint: {X:0>4}: want {?d}, got {?d}\n", .{ evalpieces.checkpoint_addresses[i], want.score[i], got.score[i] });
                    return error.MismatchWithOriginal;
                }
                const fixed = evalpieces.evalPiecesAndKingsFixes(fixed_017, &p, &e, side, ply);
                if (fixed != ax) {
                    if (counts.dev017_changed == 0) {
                        const f = fenOf(&fen, &p);
                        @memcpy(counts.dev017_example[0..f.len], f);
                        counts.dev017_example_len = f.len;
                        counts.dev017_example_values = .{ ax, fixed };
                        counts.dev017_example_side = side;
                    }
                    counts.dev017_changed += 1;
                    counts.dev017_twins += try twin017(&p, &e, side, ply);
                }
                counts.epk += 1;
            },
            2, 3, 4 => {
                const ax: i16 = @bitCast(c.int(u16));
                if (col) |k| try k.push(gpa, tag, 0, 0, &p, &e);
                const got_ax = switch (tag) {
                    2 => activity.pieceActivityWhite(&p, &e),
                    3 => activity.pieceActivityBlack(&p, &e),
                    else => activity.mobilityTerm(&p, &e),
                };
                if (got_ax != ax) {
                    const names = [_][]const u8{ "piece_activity_white", "piece_activity_black", "mobility_term" };
                    std.debug.print("\n{s}: record {d} differs: {s}() on {s}: AX want {d}, got {d}\n", .{ name, index, names[tag - 2], fenOf(&fen, &p), ax, got_ax });
                    return error.MismatchWithOriginal;
                }
                if (tag != 4) {
                    // DEV-018: a piece code of the side (a knight, a rook) in the byte past
                    // the board at every captured slot 0..6; the slots are skipped, so the
                    // result is the recorded one where the original would evaluate a
                    // phantom piece.
                    const base: usize = if (tag == 2) 0 else 16;
                    var e2 = e;
                    var any = false;
                    for (p.piece_list[base..][0..7], 0..) |entry, slot| {
                        if (entry < 120 or entry >= 198) continue;
                        const code: u8 = if (slot % 2 == 0) pos.white_knight else pos.white_rook;
                        e2.past_board[entry - 120] = if (tag == 2) code else code + 7;
                        any = true;
                    }
                    if (any) {
                        const again = if (tag == 2) activity.pieceActivityWhite(&p, &e2) else activity.pieceActivityBlack(&p, &e2);
                        try std.testing.expectEqual(ax, again);
                        counts.dev018_checked += 1;
                    }
                }
                switch (tag) {
                    2 => counts.white += 1,
                    3 => counts.black += 1,
                    else => counts.mobility += 1,
                }
            },
            else => return error.BadRecordTag,
        }
    }
}

pub const runs = [_][]const u8{
    "A.zst",
    "B.zst",
    "C.zst",
    "D.zst",
    "E.zst",
    "G.zst",
    "MG1.zst",
    "MG2.zst",
    "MG3.zst",
    "STALE.zst",
    "QS.zst",
    "CUST.zst",
    "EG1.zst",
    "EG2.zst",
    "EG4.zst",
    "EG5.zst",
    "EG6.zst",
    "EG7.zst",
    "EG9.zst",
    "EG10.zst",
    "EG11.zst",
    "EG12.zst",
    "R7.zst",
    "R2.zst",
};

test "eval_pieces_and_kings, piece activity and mobility_term: replay every recorded call of the original" {
    const gpa = std.testing.allocator;
    var total: Counts = .{};
    for (runs) |name| {
        const n = try replay(gpa, name);
        std.debug.print("evalpieces vectors {s}: eval_pieces_and_kings {d}, piece_activity_white {d}, piece_activity_black {d}, mobility_term {d} calls replayed, all equal\n", .{ name, n.epk, n.white, n.black, n.mobility });
        if (n.dev017_changed != 0) std.debug.print("  DEV-017 in {s}: {d} calls changed by the correction; the first: {s}, side {d}: original {d}, corrected {d}\n", .{ name, n.dev017_changed, n.dev017_example[0..n.dev017_example_len], n.dev017_example_side, n.dev017_example_values[0], n.dev017_example_values[1] });
        total.epk += n.epk;
        total.white += n.white;
        total.black += n.black;
        total.mobility += n.mobility;
        total.dev017_changed += n.dev017_changed;
        total.dev017_twins += n.dev017_twins;
        total.dev018_checked += n.dev018_checked;
    }
    std.debug.print("DEV-018: {d} activity calls with a captured piece give the recorded result with piece codes past the board\n", .{total.dev018_checked});
    try std.testing.expect(total.dev018_checked > 0);
    std.debug.print("evalpieces vectors total: eval_pieces_and_kings {d}, piece_activity_white {d}, piece_activity_black {d}, mobility_term {d}\n", .{ total.epk, total.white, total.black, total.mobility });
    std.debug.print("DEV-017: the correction changes {d} of {d} recorded eval_pieces_and_kings calls; on {d} twin pairs made from them the corrected value equals the original's own path to e1 / e8\n", .{ total.dev017_changed, total.epk, total.dev017_twins });
    try std.testing.expect(total.dev017_twins > 0);
}

// ---- the routines against their reference copies, beyond the recorded calls -------
//
// src/activity_reference.zig and src/evalpieces_reference.zig are the routines as they
// were before the speed pass. The states here are recorded ones changed at random
// (pieces added, moved and removed, piece-list entries pointed at other pieces or
// marked captured, pawn-attack counts, king rays, pawn files, material, style weights
// and table entries), some with the whole board refilled at random; every routine must
// return what its reference returns.

const activity_ref = @import("activity_reference.zig");
const evalpieces_ref = @import("evalpieces_reference.zig");

const piece_codes = [_]u8{ 1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13 };

fn playable(r: std.Random) u8 {
    return 10 * r.intRangeAtMost(u8, 2, 9) + r.intRangeAtMost(u8, 1, 8);
}

fn randomCode(r: std.Random) u8 {
    return if (r.uintLessThan(u8, 3) == 0) 0 else piece_codes[r.uintLessThan(usize, piece_codes.len)];
}

/// A piece-list entry: a square, or a captured piece's entry (square + 63h).
fn randomEntry(r: std.Random) u8 {
    const sq = playable(r);
    return if (r.uintLessThan(u8, 5) == 0) sq + 0x63 else sq;
}

fn smallCount(r: std.Random) u8 {
    return switch (r.uintLessThan(u8, 16)) {
        0 => 0xFF,
        1 => 0x80,
        2...5 => r.intRangeAtMost(u8, 1, 2),
        else => 0,
    };
}

/// Material values at and around the thresholds the routines test.
const material_marks = [_]u16{ 0, 330, 700, 701, 1099, 1100, 1999, 2000, 2649, 2650, 3099, 3100, 3349, 3350, 3500, 3549, 3550, 3600, 3601, 4250, 4251, 5000, 6199, 6200, 8000, 0xFFF0 };

fn randomMaterial(r: std.Random) u16 {
    const m = material_marks[r.uintLessThan(usize, material_marks.len)];
    return m +% r.intRangeAtMost(u16, 0, 2) -% 1;
}

/// Puts a piece on a square, with the slot entry the routines read for a pawn.
fn put(r: std.Random, p: *pos.Position, sq: u8, code: u8) void {
    p.board[sq] = code;
    if (code == pos.white_pawn or code == pos.black_pawn) p.square_slot[sq] = r.intRangeAtMost(u8, 8, 15);
}

pub fn mutate(r: std.Random, p: *pos.Position, e: *EvalState) void {
    const n = r.intRangeAtMost(u8, 1, 24);
    for (0..n) |_| switch (r.uintLessThan(u8, 14)) {
        0, 1, 2, 3 => {
            const sq = playable(r);
            // The kings stay on their listed squares.
            if (sq != p.piece_list[7] and sq != p.piece_list[23]) put(r, p, sq, randomCode(r));
        },
        4, 5 => {
            const slot = r.uintLessThan(usize, 32);
            if (slot % 16 != 7) p.piece_list[slot] = randomEntry(r);
        },
        6 => p.pawn_attacks[r.uintLessThan(usize, 2)][playable(r)] = smallCount(r),
        7 => p.king_rays[r.uintLessThan(usize, 2)][playable(r)] = r.uintAtMost(u8, 16),
        8 => p.pawns_per_file[r.uintLessThan(usize, 2)][r.intRangeAtMost(usize, 1, 8)] = r.uintAtMost(u8, 3),
        9 => {
            const s = r.uintLessThan(usize, 2);
            p.piece_material[s] = randomMaterial(r);
            p.piece_count[s] = r.uintAtMost(u8, 7);
            p.side_pawn_count[s] = r.uintAtMost(u8, 8);
            p.pawns_on_dark[s] = r.uintAtMost(u8, 8);
        },
        10 => {
            e.passed_pawns[r.uintLessThan(usize, 2)] ^= @as(u8, 1) << r.int(u3);
            e.no_pawns_at_root = r.uintLessThan(u8, 2);
        },
        11 => {
            p.piece_material_sum = randomMaterial(r);
            p.material_balance = r.intRangeAtMost(u16, 0, 1200) -% 600;
            p.piece_balance = r.intRangeAtMost(u16, 0, 1200) -% 600;
            p.pawn_count = r.uintAtMost(u8, 16);
            p.oo_lost_at[r.uintLessThan(usize, 2)] = r.uintAtMost(u16, 3);
            p.ooo_lost_at[r.uintLessThan(usize, 2)] = r.uintAtMost(u16, 3);
        },
        12 => {
            // The same draws, in the same order, as when the tables were one array.
            const side = r.uintLessThan(usize, 2);
            const k = r.uintLessThan(usize, 4);
            const sq = playable(r);
            const v = r.int(u8);
            if (k == 1) e.bishop_activity[side][sq] = v else e.nrq_activity[side][if (k == 0) 0 else k - 1][sq] = v;
        },
        else => {
            e.style_normal = r.uintLessThan(u16, 2);
            e.mobility_weight = r.intRangeAtMost(u32, 0, 200);
            e.king_placement_weight = r.intRangeAtMost(u32, 0, 200);
        },
    };
}

/// Fills the board at random around the two kings, and points the piece lists at pieces
/// of their slots' types where there are any, else marks them captured.
pub fn scramble(r: std.Random, p: *pos.Position) void {
    const density = r.intRangeAtMost(u8, 5, 95);
    for (2..10) |rank| for (1..9) |file| {
        const sq: u8 = @intCast(rank * 10 + file);
        put(r, p, sq, if (r.uintLessThan(u8, 100) < density) piece_codes[r.uintLessThan(usize, piece_codes.len)] else 0);
    };
    p.board[p.piece_list[7]] = pos.white_king;
    p.board[p.piece_list[23]] = pos.black_king;
    const types = [_]u8{ 2, 2, 3, 3, 4, 4, 5 };
    for (0..2) |s| for (types, 0..) |t, slot| {
        const code = t + 7 * @as(u8, @intCast(s));
        var found: ?u8 = null;
        const start = r.uintLessThan(usize, 100);
        for (0..100) |i| {
            const sq: u8 = @intCast((start + i) % 100);
            if (sq >= 21 and p.board[sq] == code) {
                found = sq;
                break;
            }
        }
        p.piece_list[16 * s + slot] = found orelse playable(r) + 0x63;
    };
    for (0..2) |s| for (1..9) |f| {
        p.pawns_per_file[s][f] = r.uintAtMost(u8, 2);
    };
}

fn expectSameAsReference(p: *const pos.Position, e: *const EvalState, r: std.Random) !void {
    const side = r.uintLessThan(u16, 2);
    const ply = r.uintLessThan(u16, 64);
    const got = [4]i16{
        evalpieces.evalPiecesAndKings(p, e, side, ply), activity.pieceActivityWhite(p, e),
        activity.pieceActivityBlack(p, e),              activity.mobilityTerm(p, e),
    };
    const want = [4]i16{
        evalpieces_ref.evalPiecesAndKings(p, e, side, ply), activity_ref.pieceActivityWhite(p, e),
        activity_ref.pieceActivityBlack(p, e),              activity_ref.mobilityTerm(p, e),
    };
    for (got, want, 0..) |g, w, i| if (g != w) {
        var fen: [100]u8 = undefined;
        const routine = [_][]const u8{ "eval_pieces_and_kings", "piece_activity_white", "piece_activity_black", "mobility_term" };
        std.debug.print("\n{s}(side {d}, ply {d}) on {s}: reference {d}, now {d}\n", .{ routine[i], side, ply, fenOf(&fen, p), w, g });
        return error.DiffersFromReference;
    };
}

test "eval_pieces_and_kings, piece activity and mobility_term equal their reference copies on 1,200,000 changed states" {
    const gpa = std.testing.allocator;
    var col: Collector = .{ .stride = 50 };
    defer col.deinit(gpa);
    for (runs) |name| _ = try replayInto(gpa, name, &col);
    var prng: std.Random.DefaultPrng = .init(0x5EED_AC71);
    const r = prng.random();
    for (0..1_200_000) |i| {
        const call = col.calls.items[r.uintLessThan(usize, col.calls.items.len)];
        var p = col.positions.items[call.p];
        var e = col.states.items[call.e];
        if (i % 4 == 0) scramble(r, &p);
        if (i % 8 != 1) mutate(r, &p, &e);
        try expectSameAsReference(&p, &e, r);
    }
}

const bench = @import("bench.zig");

/// One kind of call, its positions copied out side by side (about 5 MB for 4000 calls:
/// in the cache, as a search's position is, yet too many calls for the branch
/// predictor to learn the sequence over the passes).
const BenchCalls = struct {
    positions: []pos.Position,
    states: []*const EvalState,
    sides: []u16,
    plies: []u16,
};

fn timeCalls(comptime tag: u8, comptime ref: bool, b: *const BenchCalls, best: *bench.Best) void {
    const t0 = bench.now();
    for (b.positions, b.states, b.sides, b.plies) |*p, e, side, ply| {
        bench.keep(p);
        const r = if (ref) switch (tag) {
            1 => evalpieces_ref.evalPiecesAndKings(p, e, side, ply),
            2 => activity_ref.pieceActivityWhite(p, e),
            3 => activity_ref.pieceActivityBlack(p, e),
            else => activity_ref.mobilityTerm(p, e),
        } else switch (tag) {
            1 => evalpieces.evalPiecesAndKings(p, e, side, ply),
            2 => activity.pieceActivityWhite(p, e),
            3 => activity.pieceActivityBlack(p, e),
            else => activity.mobilityTerm(p, e),
        };
        bench.keep(r);
    }
    best.pass(t0);
}

test "bench: evalpieces: eval_pieces_and_kings, piece activity, mobility_term" {
    if (!bench.enabled) return;
    const gpa = std.testing.allocator;
    // Runs of consecutive calls, in the order the search made them, from every file;
    // 4000 of each kind spread over them are timed.
    var col: Collector = .{ .stride = 1, .per_file = 600 };
    defer col.deinit(gpa);
    for (runs) |name| _ = try replayInto(gpa, name, &col);
    const names = [_][]const u8{ "", "eval_pieces_and_kings", "piece_activity_white", "piece_activity_black", "mobility_term" };
    const passes = 100;
    const n = 4000;
    inline for (.{ 1, 2, 3, 4 }) |tag| {
        var total: usize = 0;
        for (col.calls.items) |call| total += @intFromBool(call.tag == tag);
        const b: BenchCalls = .{
            .positions = try gpa.alloc(pos.Position, n),
            .states = try gpa.alloc(*const EvalState, n),
            .sides = try gpa.alloc(u16, n),
            .plies = try gpa.alloc(u16, n),
        };
        defer {
            gpa.free(b.positions);
            gpa.free(b.states);
            gpa.free(b.sides);
            gpa.free(b.plies);
        }
        var i: usize = 0;
        var k: usize = 0;
        for (col.calls.items) |call| if (call.tag == tag) {
            if (k * n / total == i and i < n) {
                b.positions[i] = col.positions.items[call.p];
                b.states[i] = &col.states.items[call.e];
                b.sides[i] = call.side;
                b.plies[i] = call.ply;
                i += 1;
            }
            k += 1;
        };
        std.debug.assert(i == n);
        var over: bench.Best = .{};
        var best: bench.Best = .{};
        var best_ref: bench.Best = .{};
        for (0..passes) |pass| {
            const t0 = bench.now();
            for (b.positions, b.states) |*p, e| {
                bench.keep(p);
                bench.keep(e);
            }
            over.pass(t0);
            // Alternate which goes first: the first of a pair runs a little slower.
            if (pass % 2 == 0) {
                timeCalls(tag, false, &b, &best);
                timeCalls(tag, true, &b, &best_ref);
            } else {
                timeCalls(tag, true, &b, &best_ref);
                timeCalls(tag, false, &b, &best);
            }
        }
        best_ref.report(names[tag] ++ " (before, src/*_reference.zig)", n, passes, over.ns);
        best.report(names[tag], n, passes, over.ns);
    }
}

test "evalpieces DEV-059: how many recorded calls the opposite-bishops flag changes" {
    const gpa = std.testing.allocator;
    const only059: pos.Fixes = .{ .dev001_ep_hash_square = false, .dev059_opposite_bishops_flag = true };
    var calls: usize = 0;
    var changed: usize = 0;
    for (runs) |name| {
        var col: Collector = .{ .stride = 1 };
        defer col.deinit(gpa);
        _ = try replayInto(gpa, name, &col);
        for (col.calls.items) |call| {
            if (call.tag != 1) continue;
            calls += 1;
            const p = &col.positions.items[call.p];
            const e = &col.states.items[call.e];
            if (evalpieces.evalPiecesAndKingsFixes(only059, p, e, call.side, call.ply) != evalpieces.evalPiecesAndKings(p, e, call.side, call.ply)) changed += 1;
        }
    }
    std.debug.print("evalpieces DEV-059: {d} recorded calls of 0EF8:0006, {d} changed\n", .{ calls, changed });
    try std.testing.expectEqual(@as(usize, 0), changed);
}
