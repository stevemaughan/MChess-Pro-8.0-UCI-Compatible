//! Stage A, step 4 (docs/arch/60-engine-assembly.md section 5): the exchange-evaluator
//! and sort vectors (tests/golden/movegen/{A,C,D}.zst), the generator vectors
//! (movegen/gen_*.zst) and the helper vectors (helpers/*.zst) replayed through the
//! DGROUP image, each call through src/adapt_movegen.zig. The formats are the vector
//! tools' (tools/port/gen_see_vectors.py, gen_movegen_gen_vectors.py,
//! gen_helpers_vectors.py); the regions are their IMAGE_REGIONS, as the units' own
//! tests (see_test.zig, movegen_test.zig, helpers_test.zig) list them.
//!
//! The state lives only in the image, which starts as the executable's data with the
//! recording's first image placed at its addresses; between calls the recorded changes
//! are applied to the image; after each call the image, read at the recording's
//! addresses, must equal the original's. A wrong or missing field in a map fails at the
//! first call that reads or writes it.

const std = @import("std");
const pos = @import("position.zig");
const mg = @import("movegen.zig");
const dgroup = @import("dgroup.zig");
const adapt = @import("adapt_movegen.zig");
const vec = @import("adapt_vectors.zig");
const R = vec.Regions.Region;

const max_ply_lists = 35;

const see_regions = [_]R{
    .{ .name = "board", .dg = 0x9EF6, .len = 120 },
    .{ .name = "piece lists", .dg = 0xA03A, .len = 32 },
    .{ .name = "White pawn attacks", .dg = 0xA51C, .len = 120 },
    .{ .name = "Black pawn attacks", .dg = 0x37DA, .len = 120 },
    .{ .name = "White king rays", .dg = 0xA09E, .len = 120 },
    .{ .name = "Black king rays", .dg = 0xA164, .len = 120 },
    .{ .name = "attacker list", .dg = 0x9FEC, .len = 116 },
    .{ .name = "defender list", .dg = 0xA060, .len = 32 },
    .{ .name = "gains g", .dg = 0x70E5, .len = 11 },
    .{ .name = "net values h", .dg = 0xB4E6, .len = 10 },
};

const gen_regions = [_]R{
    .{ .name = "board", .dg = 0x9EF6, .len = 120 },
    .{ .name = "piece lists", .dg = 0xA03A, .len = 32 },
    .{ .name = "White pawn attacks", .dg = 0xA51C, .len = 120 },
    .{ .name = "Black pawn attacks", .dg = 0x37DA, .len = 120 },
    .{ .name = "White king rays", .dg = 0xA09E, .len = 120 },
    .{ .name = "Black king rays", .dg = 0xA164, .len = 120 },
    .{ .name = "SEE attackers", .dg = 0x9FEC, .len = 116 },
    .{ .name = "SEE defenders", .dg = 0xA060, .len = 32 },
    .{ .name = "SEE gains", .dg = 0x70E5, .len = 11 },
    .{ .name = "SEE net", .dg = 0xB4E6, .len = 10 },
    .{ .name = "ep squares", .dg = 0x9EC8, .len = 46 },
    .{ .name = "O-O stamps", .dg = 0xB426, .len = 4 },
    .{ .name = "O-O-O stamps", .dg = 0x3A30, .len = 4 },
    .{ .name = "piece material", .dg = 0xAE38, .len = 4 },
    .{ .name = "bishop hint", .dg = 0x725C, .len = 1 },
    .{ .name = "rook hint", .dg = 0xA8D8, .len = 2 },
    .{ .name = "queen hint", .dg = 0xA846, .len = 2 },
    .{ .name = "check flag", .dg = 0x73F2, .len = 1 },
    .{ .name = "king rule", .dg = 0x39AE, .len = 1 },
    .{ .name = "marks", .dg = 0x781A, .len = mg.marks_len },
    .{ .name = "unscored list", .dg = 0xB106, .len = 400 },
    .{ .name = "move lists", .dg = 0x3A34, .len = 400 * max_ply_lists },
};

const helper_regions = [_]R{
    .{ .name = "board", .dg = 0x9EF6, .len = 120 },
    .{ .name = "piece lists", .dg = 0xA03A, .len = 32 },
    .{ .name = "White pawn attacks", .dg = 0xA51C, .len = 120 },
    .{ .name = "Black pawn attacks", .dg = 0x37DA, .len = 120 },
    .{ .name = "White king rays", .dg = 0xA09E, .len = 120 },
    .{ .name = "Black king rays", .dg = 0xA164, .len = 120 },
    .{ .name = "ep squares", .dg = 0x9EC8, .len = max_ply_lists },
    .{ .name = "check values", .dg = 0x8C06, .len = max_ply_lists },
    .{ .name = "marks", .dg = 0x781A, .len = mg.marks_len },
    .{ .name = "move lists", .dg = 0x3A34, .len = 400 * max_ply_lists },
};

/// Every byte of `regions` is covered by one of the adapters' maps (or is a move list).
fn expectCovered(regions: []const R) !void {
    for (regions) |r| {
        if (r.dg == adapt.move_lists) continue;
        for (0..r.len) |k| {
            const a = r.dg + k;
            if (!adapt.PositionMap.covers(a) and !adapt.ScratchMap.covers(a) and !adapt.SearchVarsMap.covers(a) and !@import("adapt_position.zig").EvalVarsMap.covers(a)) {
                std.debug.print("{s}+{d} (DG:{X:0>4}) is recorded but in no map\n", .{ r.name, k, a });
                return error.MapMissesRecordedByte;
            }
        }
    }
}

const Replay = struct {
    regions: vec.Regions,
    truth: []u8,
    got: []u8,
    img: *dgroup.Image,

    fn init(gpa: std.mem.Allocator, list: []const R, first: []const u8) !Replay {
        try expectCovered(list);
        var r: Replay = .{ .regions = try vec.Regions.init(gpa, list), .truth = undefined, .got = undefined, .img = undefined };
        r.truth = try gpa.dupe(u8, first[0..r.regions.len()]);
        r.got = try gpa.alloc(u8, r.regions.len());
        r.img = try gpa.create(dgroup.Image);
        dgroup.init(r.img);
        r.regions.scatter(r.truth, r.img);
        return r;
    }
    fn deinit(r: *Replay, gpa: std.mem.Allocator) void {
        r.regions.deinit(gpa);
        gpa.free(r.truth);
        gpa.free(r.got);
        gpa.destroy(r.img);
    }
    /// A keyframe: the whole record image, replacing the state.
    fn keyframe(r: *Replay, rec: []const u8) void {
        @memcpy(r.truth, rec);
        r.regions.scatter(r.truth, r.img);
    }
    fn check(r: *Replay, comptime fmt: []const u8, args: anytype) !void {
        r.regions.gather(r.img, r.got);
        try vec.expectRecord(&r.regions, r.truth, r.got, fmt, args);
    }
};

// ---------------------------------------------------------------------------
// The exchange evaluator and the sort (MCSV)
// ---------------------------------------------------------------------------

const SeeCounts = struct { white: usize = 0, black: usize = 0, sorts: usize = 0 };

fn replaySee(gpa: std.mem.Allocator, name: []const u8) !SeeCounts {
    const data = try vec.readVectors(gpa, "movegen", name);
    defer gpa.free(data);
    var c: vec.Cursor = .{ .d = data };
    try std.testing.expectEqualSlices(u8, "MCSV", c.take(4));
    try std.testing.expectEqual(@as(u16, 1), c.int(u16));
    const size = c.int(u16);
    _ = c.take(333 + 333 + 14); // the constant tables (see_test.zig checks them)
    var r = try Replay.init(gpa, &see_regions, c.take(size));
    defer r.deinit(gpa);
    try std.testing.expectEqual(@as(usize, size), r.regions.len());
    var counts: SeeCounts = .{};
    var index: usize = 0;
    while (true) : (index += 1) {
        const tag = c.byte();
        switch (tag) {
            0 => {
                try std.testing.expectEqual(counts.white, c.int(u32));
                try std.testing.expectEqual(counts.black, c.int(u32));
                try std.testing.expectEqual(counts.sorts, c.int(u32));
                return counts;
            },
            1, 2 => {
                _ = c.apply(r.truth, &r.regions, r.img);
                const sq = c.byte();
                const v = c.int(u16);
                const ax = c.int(u16);
                const side: pos.Side = if (tag == 1) .white else .black;
                const got_ax = adapt.see(r.img, side, sq, v);
                _ = c.apply(r.truth, null, null);
                if (got_ax != ax) {
                    std.debug.print("\n{s}: call {d}: see(sq {d}, v {d}): AX want {X:0>4}, got {X:0>4}\n", .{ name, index, sq, v, ax, got_ax });
                    return error.MismatchWithOriginal;
                }
                try r.check("{s}: call {d}: see(sq {d}, v {d})", .{ name, index, sq, v });
                if (tag == 1) counts.white += 1 else counts.black += 1;
            },
            3 => {
                // A sort of a recorded list: put it in the list of ply 1 of the image.
                const n: i16 = @bitCast(c.int(u16));
                counts.sorts += 1;
                if (n <= 0) {
                    adapt.sortList(r.img, 1, n);
                    continue;
                }
                const count: usize = @intCast(n);
                const before = c.take(4 * count);
                const perm = c.take(count);
                const at = adapt.listAddr(1);
                const saved = r.img[at..][0..adapt.list_bytes].*;
                @memcpy(r.img[at..][0 .. 4 * count], before);
                adapt.sortList(r.img, 1, n);
                for (0..count) |i| {
                    const want = before[4 * @as(usize, perm[i]) ..][0..4];
                    if (!std.mem.eql(u8, want, r.img[at + 4 * i ..][0..4])) {
                        std.debug.print("\n{s}: call {d}: sort_moves(n {d}): entry {d} differs\n", .{ name, index, n, i });
                        return error.MismatchWithOriginal;
                    }
                }
                r.img[at..][0..adapt.list_bytes].* = saved;
            },
            else => return error.BadRecordTag,
        }
    }
}

test "stage A: exchange evaluator and sort vectors replayed through the DGROUP image" {
    const gpa = std.testing.allocator;
    var t: SeeCounts = .{};
    for ([_][]const u8{ "A.zst", "C.zst", "D.zst" }) |name| {
        const n = try replaySee(gpa, name);
        t.white += n.white;
        t.black += n.black;
        t.sorts += n.sorts;
    }
    std.debug.print("stage A see/sort: see White {d}, Black {d}, sort_moves {d} calls through the image, all equal\n", .{ t.white, t.black, t.sorts });
}

// ---------------------------------------------------------------------------
// The generators (MCGV)
// ---------------------------------------------------------------------------

fn skipConstRanges(c: *vec.Cursor) void {
    const n = c.int(u16);
    for (0..n) |_| {
        _ = c.int(u16);
        const len = c.int(u16);
        _ = c.take(len);
    }
}

fn replayGen(gpa: std.mem.Allocator, name: []const u8, counts: *[6]usize) !void {
    return replayGenWith(adapt.SearchVarsMap, gpa, name, counts);
}

/// `replayGen` with the generators' search variables moved through `SVMap`.
fn replayGenWith(comptime SVMap: type, gpa: std.mem.Allocator, name: []const u8, counts: *[6]usize) !void {
    const data = try vec.readVectors(gpa, "movegen", name);
    defer gpa.free(data);
    var c: vec.Cursor = .{ .d = data };
    try std.testing.expectEqualSlices(u8, "MCGV", c.take(4));
    try std.testing.expectEqual(@as(u16, 1), c.int(u16));
    const size = c.int(u16);
    skipConstRanges(&c); // movegen_test.zig checks them against the executable
    var r = try Replay.init(gpa, &gen_regions, c.take(size));
    defer r.deinit(gpa);
    try std.testing.expectEqual(@as(usize, size), r.regions.len());
    const buf = try gpa.create(adapt.GenStateBuf);
    defer gpa.destroy(buf);
    var index: usize = 0;
    var seen: [6]usize = @splat(0);
    while (true) {
        const tag = c.byte();
        switch (tag) {
            0 => {
                for (1..6) |t| try std.testing.expectEqual(seen[t], c.int(u32));
                for (1..6) |t| counts[t] += seen[t];
                return;
            },
            9 => {
                r.keyframe(c.take(size));
                continue;
            },
            1...5 => {},
            else => return error.BadRecordTag,
        }
        const side: pos.Side = if (c.byte() == 0) .white else .black;
        const ply: usize = c.byte();
        var stray: mg.StrayBytes = .{};
        if (tag == 1) {
            const b = c.take(4);
            stray = .{ .white_pawn_capture = b[0], .white_king_capture = b[1], .black_pawn_capture = b[2], .black_king_capture = b[3] };
        }
        _ = c.apply(r.truth, &r.regions, r.img);
        const ax = c.int(u16);
        const got_ax = adapt.generateWith(SVMap, buf, r.img, .original, pos.Fixes.original, @fromBackingInt(@intCast(tag)), side, ply, stray);
        _ = c.apply(r.truth, null, null);
        if (got_ax != ax) {
            std.debug.print("\n{s}: call {d}: generator {d} (ply {d}): AX want {X:0>4}, got {X:0>4}\n", .{ name, index, tag, ply, ax, got_ax });
            return error.MismatchWithOriginal;
        }
        try r.check("{s}: call {d}: generator {d} (side {t}, ply {d})", .{ name, index, tag, side, ply });
        seen[tag] += 1;
        index += 1;
    }
}

const gen_files = [_][]const u8{ "gen_A.zst", "gen_C.zst", "gen_D.zst", "gen_E.zst", "gen_G.zst", "gen_A5.zst" };

test "stage A: move generator vectors replayed through the DGROUP image" {
    const gpa = std.testing.allocator;
    var counts: [6]usize = @splat(0);
    for (gen_files) |name| try replayGen(gpa, name, &counts);
    std.debug.print("stage A generators: 3938 {d}, 579A {d}, 25A0 {d}, 9528 {d}, 4954 {d} calls through the image, all equal\n", .{ counts[1], counts[2], counts[3], counts[4], counts[5] });
}

/// `SearchVarsMap` with field `field` mapped one byte off.
fn SearchVarsMapShifted(comptime field: []const u8) type {
    const entries = blk: {
        var a = dgroup.maps.movegen.SearchVars;
        for (&a) |*e| {
            if (std.mem.eql(u8, e.field, field)) e.addr += 1;
        }
        const final = a;
        break :blk final;
    };
    return dgroup.Map(mg.SearchVars, &entries);
}

test "stage A: the generator replays fail with a field of SearchVars (the marks, a hint, the unscored list) mapped one byte off" {
    const gpa = std.testing.allocator;
    inline for (@typeInfo(mg.SearchVars).@"struct".field_names) |field| {
        var failed: usize = 0;
        for (gen_files) |name| {
            var counts: [6]usize = @splat(0);
            replayGenWith(SearchVarsMapShifted(field), gpa, name, &counts) catch {
                failed += 1;
            };
        }
        std.debug.print("generators, SearchVars.{s} one byte off: {d} of {d} files fail\n", .{ field, failed, gen_files.len });
        try std.testing.expect(failed > 0);
    }
}

// ---------------------------------------------------------------------------
// The helpers (MCHV)
// ---------------------------------------------------------------------------

fn replayHelpers(gpa: std.mem.Allocator, name: []const u8, counts: *[10]usize) !void {
    const data = try vec.readVectors(gpa, "helpers", name);
    defer gpa.free(data);
    var c: vec.Cursor = .{ .d = data };
    try std.testing.expectEqualSlices(u8, "MCHV", c.take(4));
    try std.testing.expectEqual(@as(u16, 1), c.int(u16));
    const size = c.int(u16);
    skipConstRanges(&c); // helpers_test.zig checks them against the executable
    var r = try Replay.init(gpa, &helper_regions, c.take(size));
    defer r.deinit(gpa);
    try std.testing.expectEqual(@as(usize, size), r.regions.len());
    const buf = try gpa.create(adapt.GenStateBuf);
    defer gpa.destroy(buf);
    var index: usize = 0;
    var seen: [10]usize = @splat(0);
    while (true) {
        const tag = c.byte();
        var sq: u16 = 0;
        var move: pos.Move = .{ .from = 0, .to = 0, .flag = 0 };
        var side: pos.Side = .white;
        var ply: usize = 0;
        switch (tag) {
            0 => {
                for (1..10) |t| try std.testing.expectEqual(seen[t], c.int(u32));
                for (1..10) |t| counts[t] += seen[t];
                return;
            },
            0xFE => {
                r.keyframe(c.take(size));
                continue;
            },
            1, 2, 8, 9 => sq = c.int(u16),
            3, 4 => {
                move.from = c.byte();
                move.to = c.byte();
            },
            5, 6 => {},
            7 => {
                side = if (c.byte() == 0) .white else .black;
                ply = c.byte();
            },
            else => return error.BadRecordTag,
        }
        _ = c.apply(r.truth, &r.regions, r.img);
        const ax = c.int(u16);
        const got_ax: u16 = switch (tag) {
            1 => adapt.attacksSquareNoPawns(r.img, .white, sq),
            2 => adapt.attacksSquareNoPawns(r.img, .black, sq),
            3 => adapt.hashMovePlausible(r.img, .white, &move),
            4 => adapt.hashMovePlausible(r.img, .black, &move),
            5 => adapt.countAttacked(r.img, .white),
            6 => adapt.countAttacked(r.img, .black),
            7 => adapt.genEvasions(buf, r.img, side, ply),
            8 => adapt.attacksSquare(r.img, .white, sq),
            9 => adapt.attacksSquare(r.img, .black, sq),
            else => unreachable,
        };
        _ = c.apply(r.truth, null, null);
        if (tag == 3 or tag == 4) {
            const from_after = c.byte();
            if (move.from != from_after) {
                std.debug.print("\n{s}: call {d}: hash_move_plausible: from byte want {d}, got {d}\n", .{ name, index, from_after, move.from });
                return error.MismatchWithOriginal;
            }
        }
        if (got_ax != ax) {
            std.debug.print("\n{s}: call {d}: helper {d}: AX want {X:0>4}, got {X:0>4}\n", .{ name, index, tag, ax, got_ax });
            return error.MismatchWithOriginal;
        }
        try r.check("{s}: call {d}: helper {d}", .{ name, index, tag });
        seen[tag] += 1;
        index += 1;
    }
}

test "stage A: helper vectors replayed through the DGROUP image" {
    const gpa = std.testing.allocator;
    var counts: [10]usize = @splat(0);
    for ([_][]const u8{ "A.zst", "E.zst", "probe.zst" }) |name| try replayHelpers(gpa, name, &counts);
    var total: usize = 0;
    for (counts) |n| total += n;
    std.debug.print("stage A helpers: {d} calls through the image ({any}), all equal\n", .{ total, counts[1..] });
}

test "stage A: the maps of SearchVars and Scratch agree with the units' tests' transfer code" {
    // movegen_test.zig's transfer: hints, flag, marks, unscored list (the rule DG:39AE is
    // `EvalVars.black_king_by_passer` since Stage B step 6); see_test.zig's:
    // the four work areas. Each region must start a map entry of the field the test moves.
    const Want = struct { dg: u16, field: []const u8 };
    const sv = [_]Want{
        .{ .dg = 0x781A, .field = "marks" },       .{ .dg = 0xB106, .field = "unscored" },
        .{ .dg = 0x725C, .field = "bishop_hint" }, .{ .dg = 0xA8D8, .field = "rook_hint" },
        .{ .dg = 0xA846, .field = "queen_hint" },  .{ .dg = 0x73F2, .field = "check_flag" },
    };
    const sc = [_]Want{
        .{ .dg = 0x9FEC, .field = "attackers" }, .{ .dg = 0xA060, .field = "defenders" },
        .{ .dg = 0x70E5, .field = "gain" },      .{ .dg = 0xB4E6, .field = "net" },
    };
    for (sv) |w| {
        var ok = false;
        inline for (adapt.SearchVarsMap.map) |e| ok = ok or (e.addr == w.dg and std.mem.eql(u8, e.field, w.field));
        if (!ok) return error.MapDisagreesWithTransfer;
    }
    for (sc) |w| {
        var ok = false;
        inline for (adapt.ScratchMap.map) |e| ok = ok or (e.addr == w.dg and std.mem.eql(u8, e.field, w.field));
        if (!ok) return error.MapDisagreesWithTransfer;
    }
    try std.testing.expectEqual(sv.len, adapt.SearchVarsMap.map.len);
    try std.testing.expectEqual(sc.len, adapt.ScratchMap.map.len);
}
