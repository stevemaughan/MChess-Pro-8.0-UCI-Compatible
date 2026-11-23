//! Stage A, steps 5 and 6 (docs/arch/60-engine-assembly.md section 5): prepare_eval
//! (tests/golden/evaltables/*.zst), the piece evaluation (evalpieces/*.zst) and the pawn
//! evaluation, pawn hash, update_square_sums and static_eval (evalpawns/*.zst), replayed
//! through the DGROUP image with src/adapt_eval.zig and src/adapt_staticeval.zig. Formats:
//! tools/port/gen_evaltables_vectors.py, gen_evalpieces_vectors.py,
//! gen_evalpawns_vectors.py.
//!
//! static_eval runs with its callees bound to the real routines; each real callee's
//! result is checked against the one the original returned at that call.

const std = @import("std");
const pos = @import("position.zig");
const et = @import("evaltables.zig");
const se = @import("staticeval.zig");
const PawnHash = @import("pawnhash.zig").PawnHash;
const dgroup = @import("dgroup.zig");
const adapt = @import("adapt_eval.zig");
const adapt_position = @import("adapt_position.zig");
const ase = @import("adapt_staticeval.zig");
const vec = @import("adapt_vectors.zig");
const R = vec.Regions.Region;

fn covered(a: usize, comptime maps: anytype) bool {
    inline for (maps) |M| if (M.covers(a)) return true;
    return false;
}

// ---------------------------------------------------------------------------
// prepare_eval (MCET, evaltables)
// ---------------------------------------------------------------------------

fn replayTables(gpa: std.mem.Allocator, name: []const u8) !usize {
    const data = try vec.readVectors(gpa, "evaltables", name);
    defer gpa.free(data);
    var c: vec.Cursor = .{ .d = data };
    try std.testing.expectEqualSlices(u8, "MCET", c.take(4));
    try std.testing.expectEqual(@as(u16, 1), c.int(u16));
    const nr = c.int(u16);
    const list = try gpa.alloc(R, nr);
    defer gpa.free(list);
    for (list) |*r| {
        r.* = .{ .name = "", .dg = c.int(u16), .len = c.int(u16) };
        // every recorded byte is in the Position, Tables or Inputs map
        for (0..r.len) |k| if (!covered(r.dg + k, .{ adapt.PositionMap, adapt.TablesMap, adapt.InputsMap })) {
            std.debug.print("DG:{X:0>4} is recorded by the prepare_eval vectors but in no map\n", .{r.dg + k});
            return error.MapMissesRecordedByte;
        };
    }
    const nb = c.int(u16);
    for (0..nb) |_| _ = c.int(u16);
    try std.testing.expectEqual(@as(usize, et.sections.len + 1), nb);
    var regions = try vec.Regions.init(gpa, list);
    defer regions.deinit(gpa);
    const truth = try gpa.alloc(u8, regions.len());
    defer gpa.free(truth);
    @memset(truth, 0);
    const got = try gpa.alloc(u8, regions.len());
    defer gpa.free(got);
    const img = try gpa.create(dgroup.Image);
    defer gpa.destroy(img);
    dgroup.init(img);
    regions.scatter(truth, img);
    const buf = try gpa.create(adapt.Buf);
    defer gpa.destroy(buf);
    buf.* = .{};
    var calls: usize = 0;
    while (true) {
        const tag = c.byte();
        if (tag == 0) {
            try std.testing.expectEqual(calls, c.int(u32));
            return calls;
        }
        if (tag != 1) return error.BadRecordTag;
        const scen = c.int(u16);
        const ncall = c.int(u16);
        _ = c.int(u16); // SP at entry
        _ = c.apply(truth, &regions, img);
        adapt.prepareEval(buf, img);
        for (et.sections) |_| {
            if (c.byte() != 0) _ = c.apply(truth, null, null);
        }
        regions.gather(img, got);
        if (!std.mem.eql(u8, truth, got)) {
            const off = std.mem.indexOfDiff(u8, truth, got).?;
            var b1: [96]u8 = undefined;
            var b2: [96]u8 = undefined;
            const a = regions.addr[off];
            const where = if (adapt.TablesMap.covers(a)) adapt.TablesMap.describe(&b1, a) else adapt.PositionMap.describe(&b1, a);
            _ = &b2;
            std.debug.print("\n{s}: call {d} (scenario {d}, call {d}): {s}: want {X:0>2}, got {X:0>2}\n", .{ name, calls, scen, ncall, where, truth[off], got[off] });
            return error.MismatchWithOriginal;
        }
        calls += 1;
    }
}

test "stage A: prepare_eval vectors replayed through the DGROUP image" {
    const gpa = std.testing.allocator;
    var n: usize = 0;
    for ([_][]const u8{ "all.zst", "custom.zst" }) |name| n += try replayTables(gpa, name);
    std.debug.print("stage A prepare_eval: {d} calls through the image, all equal\n", .{n});
}

// ---------------------------------------------------------------------------
// eval_pieces_and_kings, piece activity, mobility_term (MCEP, evalpieces)
// ---------------------------------------------------------------------------

const PieceCounts = struct { epk: usize = 0, white: usize = 0, black: usize = 0, mobility: usize = 0 };

fn replayPieces(gpa: std.mem.Allocator, name: []const u8) !PieceCounts {
    const data = try vec.readVectors(gpa, "evalpieces", name);
    defer gpa.free(data);
    var c: vec.Cursor = .{ .d = data };
    try std.testing.expectEqualSlices(u8, "MCEP", c.take(4));
    try std.testing.expectEqual(@as(u16, 1), c.int(u16));
    const size = c.int(u16);
    const nr = c.int(u16);
    const list = try gpa.alloc(R, nr);
    defer gpa.free(list);
    for (list) |*r| r.* = .{ .name = "", .dg = c.int(u16), .len = c.int(u16) };
    for (0..c.int(u16)) |_| {
        _ = c.int(u16);
        _ = c.take(c.int(u16)); // evalpieces_test.zig checks them against the executable
    }
    var regions = try vec.Regions.init(gpa, list);
    defer regions.deinit(gpa);
    try std.testing.expectEqual(@as(usize, size), regions.len());
    const state = try gpa.alloc(u8, size);
    defer gpa.free(state);
    @memcpy(state, c.take(size));
    const img = try gpa.create(dgroup.Image);
    defer gpa.destroy(img);
    dgroup.init(img);
    regions.scatter(state, img);
    const buf = try gpa.create(adapt.Buf);
    defer gpa.destroy(buf);
    buf.* = .{};
    var n: PieceCounts = .{};
    var index: usize = 0;
    while (true) : (index += 1) {
        const tag = c.byte();
        if (tag == 0) {
            try std.testing.expectEqual(n.epk, c.int(u32));
            try std.testing.expectEqual(n.white, c.int(u32));
            try std.testing.expectEqual(n.black, c.int(u32));
            try std.testing.expectEqual(n.mobility, c.int(u32));
            return n;
        }
        if (tag == 5) {
            _ = c.take(size);
            continue;
        }
        _ = c.apply(state, &regions, img);
        var want: i16 = undefined;
        var got: i16 = undefined;
        switch (tag) {
            1 => {
                const side = c.byte();
                const ply = c.byte();
                want = @bitCast(c.int(u16));
                const mask = c.int(u16);
                for (0..16) |i| if (mask >> @intCast(i) & 1 != 0) {
                    _ = c.int(u16);
                };
                got = adapt.evalPiecesAndKings(buf, img, side, ply);
                n.epk += 1;
            },
            2 => {
                want = @bitCast(c.int(u16));
                got = adapt.pieceActivityWhite(buf, img);
                n.white += 1;
            },
            3 => {
                want = @bitCast(c.int(u16));
                got = adapt.pieceActivityBlack(buf, img);
                n.black += 1;
            },
            4 => {
                want = @bitCast(c.int(u16));
                got = adapt.mobilityTerm(buf, img);
                n.mobility += 1;
            },
            else => return error.BadRecordTag,
        }
        if (want != got) {
            std.debug.print("\n{s}: record {d}: tag {d}: AX want {d}, got {d}\n", .{ name, index, tag, want, got });
            return error.MismatchWithOriginal;
        }
    }
}

test "stage A: piece evaluation vectors replayed through the DGROUP image" {
    const gpa = std.testing.allocator;
    var t: PieceCounts = .{};
    const runs = [_][]const u8{ "A.zst", "B.zst", "C.zst", "D.zst", "E.zst", "G.zst", "MG1.zst", "MG2.zst", "MG3.zst", "STALE.zst", "QS.zst", "CUST.zst", "EG1.zst", "EG2.zst", "EG4.zst", "EG5.zst", "EG6.zst", "EG7.zst", "EG9.zst", "EG10.zst", "EG11.zst", "EG12.zst", "R7.zst", "R2.zst" };
    for (runs) |name| {
        const n = try replayPieces(gpa, name);
        t.epk += n.epk;
        t.white += n.white;
        t.black += n.black;
        t.mobility += n.mobility;
    }
    std.debug.print("stage A pieces: eval_pieces_and_kings {d}, piece_activity_white {d}, _black {d}, mobility_term {d} calls through the image, all equal\n", .{ t.epk, t.white, t.black, t.mobility });
}

// ---------------------------------------------------------------------------
// The pawn evaluation, the pawn hash, update_square_sums, static_eval (evalpawns)
// ---------------------------------------------------------------------------

/// gen_evalpawns_vectors.py IMAGE, as src/evalpawns_test.zig lists it, without the two
/// pawn-hash regions (segment 5A7B, 2560 bytes each), which follow them in the record.
const pawn_regions = [_]R{
    .{ .name = "board", .dg = 0x9EF6, .len = 120 },                  .{ .name = "piece lists", .dg = 0xA03A, .len = 32 },
    .{ .name = "White pawn attacks", .dg = 0xA51C, .len = 120 },     .{ .name = "Black pawn attacks", .dg = 0x37DA, .len = 120 },
    .{ .name = "White pawns per file", .dg = 0xA8C8, .len = 10 },    .{ .name = "Black pawns per file", .dg = 0x9EA8, .len = 10 },
    .{ .name = "pawn_count", .dg = 0x90AA, .len = 1 },               .{ .name = "White pawns", .dg = 0xAB1E, .len = 1 },
    .{ .name = "Black pawns", .dg = 0x741A, .len = 1 },              .{ .name = "late_endgame", .dg = 0xA72C, .len = 1 },
    .{ .name = "weak_pawns", .dg = 0x8EB6, .len = 1 },               .{ .name = "White passed_pawns", .dg = 0xA6C2, .len = 1 },
    .{ .name = "Black passed_pawns", .dg = 0x9D8C, .len = 1 },       .{ .name = "pawn_hash_key", .dg = 0x8CD2, .len = 6 },
    .{ .name = "piece_material_sum", .dg = 0x378E, .len = 2 },       .{ .name = "style_normal", .dg = 0x1548, .len = 2 },
    .{ .name = "pawn_structure_weight", .dg = 0x2916, .len = 4 },    .{ .name = "centrality_weight", .dg = 0x290E, .len = 4 },
    .{ .name = "piece_square_sum", .dg = 0x7182, .len = 2 },         .{ .name = "White pawn_square_sum", .dg = 0x90B6, .len = 2 },
    .{ .name = "Black pawn_square_sum", .dg = 0x369A, .len = 2 },    .{ .name = "material_balance_2", .dg = 0xA4C6, .len = 2 },
    .{ .name = "Black queen_gone_at_root", .dg = 0x9354, .len = 1 }, .{ .name = "White queen_gone_at_root", .dg = 0x7100, .len = 1 },
    .{ .name = "material", .dg = 0x8DE4, .len = 4 },                 .{ .name = "piece_material", .dg = 0xAE38, .len = 4 },
    .{ .name = "piece_balance", .dg = 0xA8D2, .len = 2 },            .{ .name = "total_material", .dg = 0xA420, .len = 2 },
    .{ .name = "king_file", .dg = 0xA22E, .len = 2 },                .{ .name = "king_rank", .dg = 0x70F0, .len = 2 },
    .{ .name = "black_king_by_passer", .dg = 0x39AE, .len = 1 },     .{ .name = "passer_flags", .dg = 0xA5F5, .len = 1 },
    .{ .name = "draw_flag", .dg = 0xA8DE, .len = 1 },                .{ .name = "promotion_square", .dg = 0x8CCA, .len = 1 },
    .{ .name = "promotion_flags", .dg = 0x9EBA, .len = 1 },          .{ .name = "piece_count", .dg = 0x931A, .len = 2 },
    .{ .name = "material_balance", .dg = 0xA35E, .len = 2 },         .{ .name = "endgame", .dg = 0xA6C3, .len = 1 },
    .{ .name = "square_slot", .dg = 0xA28C, .len = 120 },            .{ .name = "passed_pawns_weight", .dg = 0x291A, .len = 4 },
    .{ .name = "passer_rank_tables", .dg = 0x0144, .len = 80 },      .{ .name = "passer table 746C", .dg = 0x746C, .len = 178 },
    .{ .name = "passer table 718C", .dg = 0x718C, .len = 178 },      .{ .name = "passer table 90BA", .dg = 0x90BA, .len = 178 },
    .{ .name = "passer table AE46", .dg = 0xAE46, .len = 178 },      .{ .name = "passer table A792", .dg = 0xA792, .len = 178 },
    .{ .name = "passer table 369E", .dg = 0x369E, .len = 178 },      .{ .name = "square values White P", .dg = 0xA8EC, .len = 200 },
    .{ .name = "square values White N", .dg = 0x75CA, .len = 200 },  .{ .name = "square values White B", .dg = 0xAC2A, .len = 200 },
    .{ .name = "square values White R", .dg = 0x9182, .len = 200 },  .{ .name = "square values White Q", .dg = 0x8DEA, .len = 200 },
    .{ .name = "square values Black P", .dg = 0xAA2C, .len = 200 },  .{ .name = "square values Black N", .dg = 0x76A2, .len = 200 },
    .{ .name = "square values Black B", .dg = 0xACF4, .len = 200 },  .{ .name = "square values Black R", .dg = 0x924A, .len = 200 },
    .{ .name = "square values Black Q", .dg = 0x8EB8, .len = 200 },
};
const hash_bytes = 2 * 2560;

/// The record image of the evalpawns vectors: the DGROUP regions, then the pawn hash.
const PawnRecord = struct {
    regions: vec.Regions,
    rec: []u8,
    got: []u8,
    img: *dgroup.Image,
    h: *PawnHash,

    fn hash(pr: *PawnRecord) []u8 {
        return std.mem.sliceAsBytes(&pr.h.tables);
    }
    /// A change list applied to the record, and to the image and the pawn hash when
    /// `to_state`.
    fn apply(pr: *PawnRecord, c: *vec.Cursor, to_state: bool) void {
        const n = c.varint();
        var prev: isize = -1;
        const dg_len = pr.regions.len();
        for (0..n) |_| {
            const off: usize = @intCast(prev + 1 + @as(isize, @intCast(c.varint())));
            pr.rec[off] ^= c.byte();
            if (to_state) {
                if (off < dg_len) pr.img[pr.regions.addr[off]] = pr.rec[off] else pr.hash()[off - dg_len] = pr.rec[off];
            }
            prev = @intCast(off);
        }
    }
    fn gather(pr: *PawnRecord) void {
        const dg_len = pr.regions.len();
        pr.regions.gather(pr.img, pr.got[0..dg_len]);
        @memcpy(pr.got[dg_len..], pr.hash());
    }
};

const CalleeRecord = struct { site: u16, a0: u16, a1: u16, ax: u16 };

/// The test mode of the binding: each real callee is the next recorded call, to the same
/// routine with the same arguments, and must return what the original returned.
const Checker = struct {
    recs: [64]CalleeRecord = undefined,
    n: usize = 0,
    next: usize = 0,
    checked: usize = 0,
    equal: [6]usize = @splat(0),
    differ: [6]usize = @splat(0),
    failed: ?[]const u8 = null,
    msg: [200]u8 = undefined,

    fn push(k: *Checker, r: CalleeRecord) void {
        if (k.n < k.recs.len) {
            k.recs[k.n] = r;
            k.n += 1;
        }
    }
    fn after(ctx: *anyopaque, callee: ase.Callee, a0: u16, a1: ?u16, real: u16) u16 {
        const k: *Checker = @ptrCast(@alignCast(ctx));
        if (k.failed != null) return real;
        if (k.next >= k.n) {
            k.failed = std.fmt.bufPrint(&k.msg, "the port called {t}({d}); the original made no further call", .{ callee, a0 }) catch "an extra call";
            return real;
        }
        const r = k.recs[k.next];
        k.next += 1;
        if (std.mem.indexOfScalar(u16, ase.sitesOf(callee), r.site) == null or r.a0 != a0 or (a1 != null and r.a1 != a1.?)) {
            k.failed = std.fmt.bufPrint(&k.msg, "the port called {t}({d}, {d}); the original called at 2B9F:{X:0>4} ({d}, {d})", .{ callee, a0, a1 orelse 0, r.site, r.a0, r.a1 }) catch "a different call";
            return real;
        }
        k.checked += 1;
        if (real != r.ax) {
            // The recording does not hold all the state the callee reads (the king-ray
            // maps, the exchange work areas, the bytes beyond the board): counted, and
            // the recorded result substituted so that the replay stays on the original's
            // path.
            k.differ[@backingInt(callee)] += 1;
            return r.ax;
        }
        k.equal[@backingInt(callee)] += 1;
        return real;
    }
    fn check(k: *Checker) ase.Check {
        return .{ .ctx = k, .after = after };
    }
};

const PawnCounts = struct { by_tag: [10]usize = @splat(0), callees: usize = 0, equal: [6]usize = @splat(0), differ: [6]usize = @splat(0) };

fn replayPawns(gpa: std.mem.Allocator, name: []const u8, counts: *PawnCounts) !void {
    const data = try vec.readVectors(gpa, "evalpawns", name);
    defer gpa.free(data);
    var c: vec.Cursor = .{ .d = data };
    try std.testing.expectEqualSlices(u8, "MCEP", c.take(4));
    try std.testing.expectEqual(@as(u16, 4), c.int(u16));
    const size = c.int(u16);
    _ = c.take(c.int(u16)); // the constant ranges (evalpawns_test.zig checks them)
    var pr: PawnRecord = .{ .regions = try vec.Regions.init(gpa, &pawn_regions), .rec = undefined, .got = undefined, .img = undefined, .h = undefined };
    defer pr.regions.deinit(gpa);
    try std.testing.expectEqual(@as(usize, size), pr.regions.len() + hash_bytes);
    for (pawn_regions) |r| for (0..r.len) |k| if (!covered(r.dg + k, .{ adapt.PositionMap, adapt.EvalVarsMap })) {
        std.debug.print("DG:{X:0>4} is recorded by the pawn vectors but in no map\n", .{r.dg + k});
        return error.MapMissesRecordedByte;
    };
    pr.rec = try gpa.dupe(u8, c.take(size));
    defer gpa.free(pr.rec);
    pr.got = try gpa.alloc(u8, size);
    defer gpa.free(pr.got);
    pr.img = try gpa.create(dgroup.Image);
    defer gpa.destroy(pr.img);
    dgroup.init(pr.img);
    pr.h = try gpa.create(PawnHash);
    defer gpa.destroy(pr.h);
    pr.h.* = .{};
    pr.regions.scatter(pr.rec[0..pr.regions.len()], pr.img);
    @memcpy(pr.hash(), pr.rec[pr.regions.len()..]);
    const buf = try gpa.create(adapt.Buf);
    defer gpa.destroy(buf);
    buf.* = .{};

    var seen: [10]usize = @splat(0);
    var previous: Checker = .{};
    var previous_stray: se.StrayBytes = .{};
    var index: usize = 0;
    while (true) : (index += 1) {
        const tag = c.byte();
        switch (tag) {
            0 => {
                for (1..10) |t| try std.testing.expectEqual(@as(u32, @intCast(seen[t])), c.int(u32));
                for (1..10) |t| counts.by_tag[t] += seen[t];
                return;
            },
            10 => {
                _ = c.take(size);
                continue;
            },
            1...9 => {},
            else => return error.BadRecordTag,
        }
        pr.apply(&c, true);
        var want_ax: ?u16 = null;
        var got_ax: ?u16 = null;
        switch (tag) {
            1, 2 => {
                want_ax = c.int(u16);
                got_ax = @bitCast(adapt.pawnEval(buf, pr.img, if (tag == 1) .white else .black));
            },
            3, 4 => {
                want_ax = c.int(u16);
                _ = c.byte(); // hit
                got_ax = @bitCast(adapt.pawnHashProbe(buf, pr.img, pr.h, if (tag == 3) .white else .black));
            },
            5, 6 => {
                want_ax = c.int(u16);
                got_ax = adapt.pawnHashStore(buf, pr.img, pr.h, if (tag == 5) .white else .black);
            },
            7 => pr.h.clear(),
            8 => {
                const m = c.take(4);
                adapt_position.updateSquareSums(pr.img, .{ .from = m[0], .to = m[1], .flag = m[2], .score = m[3] });
            },
            9 => {
                const side = c.int(u16);
                const arg2 = c.int(u16);
                const path = c.byte();
                const ax = c.int(u16);
                var reached = false;
                var cp: []const u8 = &.{};
                var k: Checker = .{};
                if (path == 1) {
                    reached = c.byte() != 0;
                    if (reached) cp = c.take(2 + 2 * 6 + 5 + 2);
                    const nrec = c.byte();
                    for (0..nrec) |_| {
                        k.push(.{ .site = c.int(u16), .a0 = c.int(u16), .a1 = c.int(u16), .ax = c.int(u16) });
                        skipDelta(&c);
                    }
                    if (c.byte() != 0) {
                        _ = c.take(2 + 2 * 10 + 7);
                        skipDelta(&c);
                    }
                }
                const own = k.n;
                for (previous.recs[0..previous.n]) |r| k.push(r);
                const stray: se.StrayBytes = if (reached) .{ .bp29 = cp[19], .bp2B = cp[20] } else .{};
                const r = ase.staticEval(buf, pr.img, pr.h, side, arg2, se.Fixes.original, .{ stray, previous_stray }, k.check());
                previous_stray = stray;
                if (k.failed) |msg| {
                    std.debug.print("\n{s}: call {d}: static_eval(side {d}, arg2 {d}): {s}\n", .{ name, index, side, arg2, msg });
                    return error.MismatchWithOriginal;
                }
                counts.callees += k.checked;
                for (0..6) |j| {
                    counts.equal[j] += k.equal[j];
                    counts.differ[j] += k.differ[j];
                }
                previous = .{};
                for (k.recs[0..own]) |x| previous.push(x);
                want_ax = ax;
                got_ax = @bitCast(r);
            },
            else => unreachable,
        }
        pr.apply(&c, false);
        pr.gather();
        if (want_ax != got_ax or !std.mem.eql(u8, pr.rec, pr.got)) {
            std.debug.print("\n{s}: call {d} (tag {d}) differs: AX want {?X}, got {?X}\n", .{ name, index, tag, want_ax, got_ax });
            if (std.mem.indexOfDiff(u8, pr.rec, pr.got)) |off| {
                var b: [96]u8 = undefined;
                const what = if (off < pr.regions.len()) pr.regions.describe(&b, off) else "pawn hash";
                _ = &pawn_regions;
                std.debug.print("  first differing byte: {s} (record offset {d}): want {X:0>2}, got {X:0>2}\n", .{ what, off, pr.rec[off], pr.got[off] });
            }
            return error.MismatchWithOriginal;
        }
        seen[tag] += 1;
    }
}

fn skipDelta(c: *vec.Cursor) void {
    const n = c.varint();
    for (0..n) |_| {
        _ = c.varint();
        _ = c.byte();
    }
}

test "stage A: pawn evaluation, pawn hash, square sums and static_eval with its real callees, through the DGROUP image" {
    const gpa = std.testing.allocator;
    var t: PawnCounts = .{};
    for ([_][]const u8{ "A.zst", "B.zst", "C.zst", "D.zst", "E.zst", "F.zst" }) |name| try replayPawns(gpa, name, &t);
    for (0..6) |j| std.debug.print("  real callee {t}: {d} results equal to the original's, {d} differ\n", .{ @as(ase.Callee, @fromBackingInt(@intCast(j))), t.equal[j], t.differ[j] });
    // The exchange evaluators and the attack tests read only what the recording holds:
    // every result must be the original's. The lifted attacker routines also read the
    // king-ray maps and the bytes beyond the board, which these vectors do not record
    // (they are proved on full images in adapt_threats_test.zig): a few may differ.
    for ([_]ase.Callee{ .see_white, .see_black, .att_4a76, .att_4ad4 }) |k| try std.testing.expectEqual(@as(usize, 0), t.differ[@backingInt(k)]);
    for ([_]ase.Callee{ .att_41b6, .att_4cec }) |k| try std.testing.expect(t.differ[@backingInt(k)] * 100 <= t.equal[@backingInt(k)]);
    std.debug.print("stage A pawns: pawn_eval {d}+{d}, probe {d}+{d}, store {d}+{d}, clear {d}, update_square_sums {d}, static_eval {d} (its real callees checked against the original's on {d} calls), all equal\n", .{ t.by_tag[1], t.by_tag[2], t.by_tag[3], t.by_tag[4], t.by_tag[5], t.by_tag[6], t.by_tag[7], t.by_tag[8], t.by_tag[9], t.callees });
}
