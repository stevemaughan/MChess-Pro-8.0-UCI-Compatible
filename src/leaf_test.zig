//! Differential test of src/leaf.zig against calls of the original recorded in games
//! (tests/golden/leaf/*.zst, made by tools/port/gen_leaf_vectors.py, whose docstring
//! defines the format).

const std = @import("std");
const position = @import("position.zig");
const leaf = @import("leaf.zig");
const EvalState = @import("eval_state.zig").EvalState;
const EvalVars = @import("evalvars.zig").EvalVars;

const nply = 36;

const Region = struct { name: []const u8, dg: u16, len: usize };
/// The image's regions, in the recorder's order (REGIONS in gen_leaf_vectors.py).
const regions = [_]Region{
    .{ .name = "board", .dg = 0x9EF6, .len = 120 },
    .{ .name = "past board", .dg = 0x9F6E, .len = 78 },
    .{ .name = "piece lists", .dg = 0xA03A, .len = 32 },
    .{ .name = "White pawn attacks", .dg = 0xA51C, .len = 120 },
    .{ .name = "Black pawn attacks", .dg = 0x37DA, .len = 120 },
    .{ .name = "leaf map", .dg = 0x8FE4, .len = 120 },
    .{ .name = "wk orth table", .dg = 0x933E, .len = 14 },
    .{ .name = "wk diag table", .dg = 0xA234, .len = 14 },
    .{ .name = "bk orth table", .dg = 0x3A22, .len = 14 },
    .{ .name = "bk diag table", .dg = 0x77DA, .len = 14 },
    .{ .name = "pawn count", .dg = 0x90AA, .len = 1 },
    .{ .name = "A5F5", .dg = 0xA5F5, .len = 1 },
    .{ .name = "game ply", .dg = 0x9FC8, .len = 2 },
    .{ .name = "last irreversible game ply", .dg = 0x7464, .len = 2 },
    .{ .name = "root game ply", .dg = 0xA000, .len = 2 },
    .{ .name = "hash key", .dg = 0x8CCC, .len = 6 },
    .{ .name = "key history", .dg = 0x9DBE, .len = 6 * nply },
    .{ .name = "irreversible ply", .dg = 0x9D94, .len = nply },
    .{ .name = "ep squares", .dg = 0x9EC8, .len = nply },
    .{ .name = "check values", .dg = 0x8C06, .len = nply },
    .{ .name = "reversible", .dg = 0x8BBE, .len = 2 * nply },
    .{ .name = "quiet moves", .dg = 0x3626, .len = 2 * nply },
};
const image_size = blk: {
    var n: usize = 0;
    for (regions) |r| n += r.len;
    break :blk n;
};

const State = struct {
    p: position.Position = .{},
    v: leaf.LeafVars = .{},
    /// The per-ply last irreversible plies and the game ply of the last irreversible game
    /// move, whose home is `EvalState` (Stage B step 5).
    e: EvalState = .{},
    /// The passer flags DG:A5F5 the endgame king term overwrites, whose home is `EvalVars`.
    ev: EvalVars = .{},
};

/// Copy between the image and the state; `to_image` selects the direction.
fn transfer(comptime to_image: bool, st: *State, img: []u8) void {
    var o: usize = 0;
    const T = struct {
        fn bytes(im: []u8, off: *usize, part: []u8) void {
            if (to_image) @memcpy(im[off.*..][0..part.len], part) else @memcpy(part, im[off.*..][0..part.len]);
            off.* += part.len;
        }
        fn int(comptime I: type, im: []u8, off: *usize, x: *I) void {
            const n = @divExact(@bitSizeOf(I), 8);
            if (to_image) std.mem.writeInt(I, im[off.*..][0..n], x.*, .little) else x.* = std.mem.readInt(I, im[off.*..][0..n], .little);
            off.* += n;
        }
    };
    const p = &st.p;
    const v = &st.v;
    T.bytes(img, &o, &p.board);
    T.bytes(img, &o, &v.past_board);
    T.bytes(img, &o, &p.piece_list);
    T.bytes(img, &o, &p.pawn_attacks[0]);
    T.bytes(img, &o, &p.pawn_attacks[1]);
    T.bytes(img, &o, &v.leaf_map);
    T.bytes(img, &o, &v.wk_orth);
    T.bytes(img, &o, &v.wk_diag);
    T.bytes(img, &o, &v.bk_orth);
    T.bytes(img, &o, &v.bk_diag);
    T.int(u8, img, &o, &p.pawn_count);
    T.int(u8, img, &o, &st.ev.passer_flags);
    T.int(u16, img, &o, &p.game_ply);
    T.int(u16, img, &o, &st.e.last_irreversible_ply);
    T.int(u16, img, &o, &v.root_game_ply);
    T.int(u48, img, &o, &p.hash_key);
    for (0..nply) |i| T.int(u48, img, &o, &v.key_history[i]);
    T.bytes(img, &o, st.e.ply_flag[0..nply]);
    T.bytes(img, &o, p.ep_square_by_ply[0..nply]);
    T.bytes(img, &o, p.check_by_ply[0..nply]);
    for (0..nply) |i| T.int(u16, img, &o, &p.reversible_by_ply[i]);
    for (0..nply) |i| T.int(u16, img, &o, &p.quiet_move_by_ply[i]);
    std.debug.assert(o == image_size);
}

fn describe(buf: []u8, off: usize) []const u8 {
    var o: usize = 0;
    for (regions) |r| {
        if (off < o + r.len) return std.fmt.bufPrint(buf, "{s}[{d}] (DG:{X:0>4})", .{ r.name, off - o, r.dg + off - o }) catch r.name;
        o += r.len;
    }
    return "past the image";
}

fn readVectors(gpa: std.mem.Allocator, name: []const u8) ![]u8 {
    var path_buf: [256]u8 = undefined;
    const dir = @import("build_options").golden_dir;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/leaf/{s}", .{ dir, name });
    const compressed = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, gpa, .limited(64 << 20));
    defer gpa.free(compressed);
    var in: std.Io.Reader = .fixed(compressed);
    const window = try gpa.alloc(u8, std.compress.zstd.default_window_len + std.compress.zstd.block_size_max);
    defer gpa.free(window);
    var zd = std.compress.zstd.Decompress.init(&in, window, .{});
    return zd.reader.allocRemaining(gpa, .limited(512 << 20));
}

const names = [9][]const u8{
    "",                                     "is_repetition (0000:1B88)",            "make_null_move (1E9D:16BE)",
    "endgame king, White node (1E9D:3416)", "endgame king, Black node (1E9D:35FB)", "leaf attack map, White (2B9F:40A8)",
    "leaf attack map, Black (2B9F:42DA)",   "king ring map, White (2B9F:450E)",     "king ring map, Black (2B9F:454C)",
};

fn replay(gpa: std.mem.Allocator, file: []const u8, counts: *[9]usize) !void {
    const raw = try readVectors(gpa, file);
    defer gpa.free(raw);
    try std.testing.expectEqualSlices(u8, "MCLV", raw[0..4]);
    try std.testing.expectEqual(@as(u16, image_size), std.mem.readInt(u16, raw[6..8], .little));
    var pos: usize = 8;
    var index: usize = 0;
    var got: [image_size]u8 = undefined;
    var keys: [1024]u48 = undefined;
    while (true) : (index += 1) {
        const tag = raw[pos];
        pos += 1;
        if (tag == 0) break;
        const arg = std.mem.readInt(u16, raw[pos..][0..2], .little);
        pos += 2;
        const before = raw[pos..][0..image_size];
        pos += image_size;
        const ax = std.mem.readInt(u16, raw[pos..][0..2], .little);
        pos += 2;
        const after = raw[pos..][0..image_size];
        pos += image_size;
        var nkeys: usize = 0;
        if (tag == 1) {
            nkeys = std.mem.readInt(u16, raw[pos..][0..2], .little);
            pos += 2;
            for (0..nkeys) |i| keys[i] = std.mem.readInt(u48, raw[pos + 6 * i ..][0..6], .little);
            pos += 6 * nkeys;
        }
        var st: State = .{};
        var img: [image_size]u8 = before.*;
        transfer(false, &st, &img);
        var res: ?u16 = null;
        switch (tag) {
            1 => res = @intFromBool(leaf.isRepetition(&st.p, &st.v, &st.e, keys[0..nkeys], @bitCast(arg))),
            2 => leaf.makeNull(&st.p, arg),
            3 => res = @bitCast(leaf.endgameKing(&st.p, &st.v, &st.ev, .white)),
            4 => res = @bitCast(leaf.endgameKing(&st.p, &st.v, &st.ev, .black)),
            5 => leaf.leafAttackMap(&st.p, &st.v, .white),
            6 => leaf.leafAttackMap(&st.p, &st.v, .black),
            7 => res = @bitCast(leaf.kingRingMap(&st.p, &st.v, .white)),
            8 => res = @bitCast(leaf.kingRingMap(&st.p, &st.v, .black)),
            else => return error.BadTag,
        }
        transfer(true, &st, &got);
        if (tag == 5 or tag == 6) {
            // DEV-037: with a piece code of the side in the byte past the board at every
            // captured entry, the map must still be the recorded one (the entry skipped,
            // where the original would mark squares past the map).
            var q: State = .{};
            var img2: [image_size]u8 = before.*;
            transfer(false, &q, &img2);
            const list = q.p.piece_list[if (tag == 5) 0 else 16..][0..16];
            var any = false;
            for (list) |e| {
                if (e < 120 or e >= 198) continue;
                q.v.past_board[e - 120] = if (tag == 5) position.white_knight else position.black_knight;
                any = true;
            }
            if (any) {
                if (tag == 5) leaf.leafAttackMap(&q.p, &q.v, .white) else leaf.leafAttackMap(&q.p, &q.v, .black);
                try std.testing.expectEqualSlices(u8, &st.v.leaf_map, &q.v.leaf_map);
                counts[0] += 1;
            }
        }
        if (res) |r| if (r != ax) {
            std.debug.print("{s} call {d} ({s}), argument {d}: AX {X:0>4}, original {X:0>4}\n", .{ file, index, names[tag], arg, r, ax });
            return error.ResultDiffers;
        };
        if (!std.mem.eql(u8, &got, after)) {
            const off = std.mem.indexOfDiff(u8, &got, after).?;
            var buf: [96]u8 = undefined;
            std.debug.print("{s} call {d} ({s}), argument {d}: first difference at {s}: port {X:0>2}, original {X:0>2}\n", .{ file, index, names[tag], arg, describe(&buf, off), got[off], after[off] });
            return error.StateDiffers;
        }
        counts[tag] += 1;
    }
}

const runs = [_][]const u8{ "M.zst", "S.zst" };

test "leaf routines: replay every recorded call of the original" {
    const gpa = std.testing.allocator;
    var counts: [9]usize = @splat(0);
    for (runs) |f| try replay(gpa, f, &counts);
    std.debug.print("leaf vectors ({d} files), calls replayed, all equal to the original:\n", .{runs.len});
    for (1..9) |t| std.debug.print("  {s}: {d}\n", .{ names[t], counts[t] });
    std.debug.print("DEV-037: {d} leaf attack map calls with a captured entry give the recorded map with a piece code past the board\n", .{counts[0]});
    try std.testing.expect(counts[0] > 0);
}

// ---------------------------------------------------------------- leafTermA (2B9F:4BFE / 5534)

const see = @import("see.zig");
const bench = @import("bench.zig");
const setup = @import("setup.zig");
const fen = @import("fen.zig");

/// The image of the hanging-piece vectors, in the recorder's order (H_REGIONS in
/// gen_leaf_vectors.py).
const h_regions = [_]Region{
    .{ .name = "board", .dg = 0x9EF6, .len = 120 },
    .{ .name = "piece lists", .dg = 0xA03A, .len = 32 },
    .{ .name = "White pawn attacks", .dg = 0xA51C, .len = 120 },
    .{ .name = "White pawn attacks, past", .dg = 0xA594, .len = 78 },
    .{ .name = "Black pawn attacks", .dg = 0x37DA, .len = 120 },
    .{ .name = "Black pawn attacks, past", .dg = 0x3852, .len = 78 },
    .{ .name = "White king rays", .dg = 0xA09E, .len = 120 },
    .{ .name = "Black king rays", .dg = 0xA164, .len = 120 },
    .{ .name = "leaf map", .dg = 0x8FE4, .len = 120 },
    .{ .name = "leaf map, past", .dg = 0x905C, .len = 78 },
    .{ .name = "White passed mask", .dg = 0xA6C2, .len = 1 },
    .{ .name = "Black passed mask", .dg = 0x9D8C, .len = 1 },
    .{ .name = "attacker list", .dg = 0x9FEC, .len = 116 },
    .{ .name = "defender list", .dg = 0xA060, .len = 32 },
    .{ .name = "swap list", .dg = 0xA4CA, .len = 22 },
};
const h_size = blk: {
    var n: usize = 0;
    for (h_regions) |r| n += r.len;
    break :blk n;
};

const HState = struct {
    p: position.Position = .{},
    v: leaf.LeafVars = .{},
    s: see.Scratch = .{},
    passed: [2]u8 = .{ 0, 0 },
};

fn hTransfer(comptime to_image: bool, st: *HState, img: []u8) void {
    var o: usize = 0;
    const parts = [_][]u8{
        &st.p.board,                           &st.p.piece_list,
        &st.p.pawn_attacks[0],                 &st.v.pawn_attacks_past[0],
        &st.p.pawn_attacks[1],                 &st.v.pawn_attacks_past[1],
        &st.p.king_rays[0],                    &st.p.king_rays[1],
        &st.v.leaf_map,                        &st.v.map_past,
        st.passed[0..1],                       st.passed[1..2],
        &st.s.attackers,                       &st.s.defenders,
        std.mem.sliceAsBytes(&st.v.swap_gain),
    };
    inline for (parts) |part| {
        if (to_image) @memcpy(img[o..][0..part.len], part) else @memcpy(part, img[o..][0..part.len]);
        o += part.len;
    }
    std.debug.assert(o == h_size);
}

fn hDescribe(buf: []u8, off: usize) []const u8 {
    var o: usize = 0;
    for (h_regions) |r| {
        if (off < o + r.len) return std.fmt.bufPrint(buf, "{s}[{d}] (DG:{X:0>4})", .{ r.name, off - o, r.dg + off - o }) catch r.name;
        o += r.len;
    }
    return "past the image";
}

const HCall = struct { tag: u8, before: *const [h_size]u8, ax: u16, after: *const [h_size]u8 };

fn hCalls(gpa: std.mem.Allocator, raw: []const u8) !std.ArrayList(HCall) {
    try std.testing.expectEqualSlices(u8, "MCLH", raw[0..4]);
    try std.testing.expectEqual(@as(u16, h_size), std.mem.readInt(u16, raw[6..8], .little));
    var list: std.ArrayList(HCall) = .empty;
    var pos: usize = 8;
    while (raw[pos] != 0) {
        const tag = raw[pos];
        const before = raw[pos + 1 ..][0..h_size];
        const ax = std.mem.readInt(u16, raw[pos + 1 + h_size ..][0..2], .little);
        const after = raw[pos + 3 + h_size ..][0..h_size];
        pos += 3 + 2 * h_size;
        try list.append(gpa, .{ .tag = tag, .before = before, .ax = ax, .after = after });
    }
    return list;
}

fn hRun(st: *HState, tag: u8) u16 {
    return @bitCast(switch (tag) {
        9 => leaf.hangingPieces(&st.p, &st.v, &st.s, .white, st.passed),
        else => leaf.hangingPieces(&st.p, &st.v, &st.s, .black, st.passed),
    });
}

const h_runs = [_][]const u8{ "H1.zst", "H2.zst", "H3.zst", "H4.zst", "H5.zst", "H6.zst" };
const h_names = [2][]const u8{ "leafTermA, White node (2B9F:4BFE)", "leafTermA, Black node (2B9F:5534)" };

test "leaf routines: leafTermA replays every recorded call of the original" {
    const gpa = std.testing.allocator;
    var counts: [2]usize = .{ 0, 0 };
    var gains: usize = 0;
    var dev040_changed: usize = 0;
    var dev039_checked: usize = 0;
    for (h_runs) |file| {
        const raw = try readVectors(gpa, file);
        defer gpa.free(raw);
        var calls = try hCalls(gpa, raw);
        defer calls.deinit(gpa);
        for (calls.items, 0..) |c, index| {
            var st: HState = .{};
            var img: [h_size]u8 = c.before.*;
            hTransfer(false, &st, &img);
            const ax = hRun(&st, c.tag);
            var got: [h_size]u8 = undefined;
            hTransfer(true, &st, &got);
            if (ax != c.ax) {
                std.debug.print("{s} call {d} ({s}): AX {X:0>4}, original {X:0>4}\n", .{ file, index, h_names[c.tag - 9], ax, c.ax });
                return error.ResultDiffers;
            }
            if (!std.mem.eql(u8, &got, c.after)) {
                const off = std.mem.indexOfDiff(u8, &got, c.after).?;
                var buf: [96]u8 = undefined;
                std.debug.print("{s} call {d} ({s}): first difference at {s}: port {X:0>2}, original {X:0>2}\n", .{ file, index, h_names[c.tag - 9], hDescribe(&buf, off), got[off], c.after[off] });
                return error.StateDiffers;
            }
            counts[c.tag - 9] += 1;
            if (c.ax != 0) gains += 1;
            // DEV-040: the corrected routine on the same input.
            var fx: HState = .{};
            img = c.before.*;
            hTransfer(false, &fx, &img);
            const fixed_ax: u16 = @bitCast(switch (c.tag) {
                9 => leaf.hangingPiecesFixes(fixed_040, &fx.p, &fx.v, &fx.s, .white, fx.passed),
                else => leaf.hangingPiecesFixes(fixed_040, &fx.p, &fx.v, &fx.s, .black, fx.passed),
            });
            if (fixed_ax != c.ax) dev040_changed += 1;
            // DEV-039: non-zero bytes past the map and the pawn counts at every captured
            // victim entry; the entries are skipped, so the result is the recorded one.
            var ph: HState = .{};
            img = c.before.*;
            hTransfer(false, &ph, &img);
            const capturer: usize = if (c.tag == 9) 0 else 1;
            var any = false;
            for (ph.p.piece_list[16 * (1 - capturer) ..][0..16]) |e| {
                if (e < 120 or e >= 198) continue;
                ph.v.map_past[e - 120] = 1;
                ph.v.pawn_attacks_past[capturer][e - 120] = 1;
                any = true;
            }
            if (any) {
                try std.testing.expectEqual(c.ax, hRun(&ph, c.tag));
                dev039_checked += 1;
            }
        }
    }
    std.debug.print("leafTermA vectors ({d} files), calls replayed, all equal to the original: {s} {d}, {s} {d} ({d} with a gain)\n", .{ h_runs.len, h_names[0], counts[0], h_names[1], counts[1], gains });
    std.debug.print("DEV-040: the correction changes {d} of {d} recorded calls. DEV-039: {d} calls with a captured victim entry give the recorded result with non-zero bytes past the map and the pawn counts\n", .{ dev040_changed, counts[0] + counts[1], dev039_checked });
    try std.testing.expect(dev039_checked > 0);
}

const fixed_040: position.Fixes = blk: {
    var f = position.Fixes.original;
    f.dev040_hanging_ray_start = true;
    break :blk f;
};

/// leafTermA on a position from a FEN, as the node calls it: the leaf attack map of the
/// side to move first, then the original routine and the corrected one on copies.
fn hangingBoth(fen_text: []const u8, comptime side: position.Side) ![2]i16 {
    var p: position.Position = .{};
    var sv: setup.SetupVars = .{};
    const d = try fen.parse(fen_text);
    setup.buildFromDescription(&p, &sv, &d);
    var v: leaf.LeafVars = .{};
    leaf.leafAttackMap(&p, &v, side);
    var v2 = v;
    var s: see.Scratch = .{};
    var s2: see.Scratch = .{};
    return .{
        leaf.hangingPieces(&p, &v, &s, side, .{ 0, 0 }),
        leaf.hangingPiecesFixes(fixed_040, &p, &v2, &s2, side, .{ 0, 0 }),
    };
}

test "DEV-040: a diagonal skipped for a pinned pawn puts the ray start back" {
    // White to move; Black's knight on d5 is attacked by White's bishop on f7 (via e6).
    // Black's pawn on c6 is pinned to its king on c8 by the rook on c1, so it is no
    // defender, and the +9 diagonal (c6) is skipped (5030 -> 507D). The original then
    // scans the +11 diagonal from c6 + 11 = d7 (d7, e8) instead of from e6, misses the
    // bishop, and its best is the pawn on c6, which the rook wins (8 x 25); corrected, it
    // wins the knight: 28 x 25.
    try std.testing.expectEqual([2]i16{ 200, 700 }, try hangingBoth("2k5/5B2/2p5/3n4/8/8/8/2R3K1 w - - 0 1", .white));
    // The twin without the pawn: the original itself scans e6 and finds the bishop.
    try std.testing.expectEqual([2]i16{ 700, 700 }, try hangingBoth("2k5/5B2/8/3n4/8/8/8/2R3K1 w - - 0 1", .white));
    // Black to move, the mirror (59D6 -> 5A23): White's knight on d4, White's pawn on e3
    // pinned on the e-file, Black's bishop on b2 attacking d4 through c3.
    try std.testing.expectEqual([2]i16{ 200, 700 }, try hangingBoth("4r1k1/8/8/8/3N4/4P3/1b6/4K3 b - - 0 1", .black));
    try std.testing.expectEqual([2]i16{ 700, 700 }, try hangingBoth("4r1k1/8/8/8/3N4/8/1b6/4K3 b - - 0 1", .black));
}

test "bench: leaf: leafTermA (2B9F:4BFE / 5534) on recorded calls" {
    if (!bench.enabled) return;
    const gpa = std.testing.allocator;
    var states: std.ArrayList(HState) = .empty;
    defer states.deinit(gpa);
    var tags: std.ArrayList(u8) = .empty;
    defer tags.deinit(gpa);
    for (h_runs) |file| {
        const raw = try readVectors(gpa, file);
        defer gpa.free(raw);
        var calls = try hCalls(gpa, raw);
        defer calls.deinit(gpa);
        for (calls.items) |c| {
            var st: HState = .{};
            var img: [h_size]u8 = c.before.*;
            hTransfer(false, &st, &img);
            try states.append(gpa, st);
            try tags.append(gpa, c.tag);
        }
    }
    const passes = 21;
    var best: bench.Best = .{};
    var copy_best: bench.Best = .{};
    var work: HState = .{};
    for (0..passes) |_| {
        var t0 = bench.now();
        for (states.items) |*st| {
            work.v.leaf_map = st.v.leaf_map;
            bench.keep(&work);
        }
        copy_best.pass(t0);
        t0 = bench.now();
        for (states.items, tags.items) |*st, tag| {
            // The routine writes only the map byte of the king and the work areas, so a
            // fresh copy of the map is all that must be restored.
            work.v.leaf_map = st.v.leaf_map;
            const r = if (tag == 9)
                @call(.never_inline, leaf.hangingPieces, .{ &st.p, &work.v, &work.s, .white, st.passed })
            else
                @call(.never_inline, leaf.hangingPieces, .{ &st.p, &work.v, &work.s, .black, st.passed });
            bench.keep(r);
        }
        best.pass(t0);
    }
    best.report("leaf leafTermA", states.items.len, passes, copy_best.ns);
}
