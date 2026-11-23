//! Tests of the node domain (src/engine_state.zig, Stage B step 1):
//!
//! - the 18 recorded subtrees of src/adapt_node_test.zig through the domain, with every
//!   event, AX, count, every DGROUP byte below C000 and every hash slot at the return
//!   compared with the original's, and no alias write;
//! - one holder per byte, and the homes the steps gave the node's variables;
//! - static_eval with 4793:41B6 / 4CEC bound to the hand-written `pinexchange` under
//!   `Fixes.original`, as the domain binds them, against every recorded call;
//! - the deliberate faults of `engine_state.Break`, each caught.
//!
//! The whole searches through the domain are the golden tests of src/engine_root*_test.zig
//! and the engine tests, which run through `engine_root.EngineRoot`.

const std = @import("std");
const est = @import("engine_state.zig");
const ant = @import("adapt_node_test.zig");
const an = @import("adapt_node.zig");
const sn = @import("searchnode.zig");
const pos = @import("position.zig");
const vec = @import("adapt_vectors.zig");

const DomainCtx = est.NodeEnvWith(pos.Fixes.original, .none, true);

const Summary = struct { failed: usize = 0, nodes: u64 = 0, alias_writes: u64 = 0 };

/// Runs the subtrees `names` through `C` on a domain; reports
/// each failure and returns the totals.
fn runSubtrees(comptime C: type, comptime label: []const u8, names: []const []const u8, quiet: bool) !Summary {
    const gpa = std.heap.page_allocator;
    var tables: ?ant.Tables = null;
    defer if (tables) |*t| t.deinit(gpa);
    const dom = try est.Members.create(gpa);
    defer dom.destroy(gpa);
    var sum: Summary = .{};
    for (names) |name| {
        const d = try vec.readVectors(gpa, "subtree", name);
        defer gpa.free(d);
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const r = try ant.parse(arena_state.allocator(), d);
        const bytes = std.mem.readInt(u32, r.dg_in[0x5A..][0..4], .little);
        const slots = bytes / 10;
        if (tables == null or tables.?.mem[0].len != slots) {
            if (tables) |*t| t.deinit(gpa);
            tables = try ant.Tables.init(gpa, slots);
        }
        const o = ant.runOneCtx(C, label, gpa, name, &r, &tables.?, quiet, dom) catch |e| {
            if (!quiet) std.debug.print("{s} ({s}): FAILED, {s}\n", .{ name, label, @errorName(e) });
            sum.failed += 1;
            continue;
        };
        sum.nodes += o.nodes;
        sum.alias_writes += o.alias_writes;
    }
    return sum;
}

test "stage B: the node domain on the recorded subtrees (every DGROUP byte and hash slot at the return, no alias write)" {
    const s = try runSubtrees(DomainCtx, "domain", &ant.files, false);
    std.debug.print("subtrees (domain): {d} files, {d} nodes, {d} failed, {d} alias writes\n", .{ ant.files.len, s.nodes, s.failed, s.alias_writes });
    try std.testing.expectEqual(@as(usize, 0), s.failed);
    try std.testing.expectEqual(@as(u64, 0), s.alias_writes);
}

// ---- one holder per byte ---------------------------------------------------------------

test "stage B: one holder per byte, and the homes of steps 2 to 6" {
    const gpa = std.testing.allocator;
    var l = try est.Layout.build(gpa, false);
    defer l.deinit(gpa);
    try std.testing.expect(est.checkOneHolder(&l));
    var held: usize = 0;
    var two: usize = 0;
    for (0..0x10000) |a| {
        var n: usize = 0;
        for (0..est.n_members) |m| {
            if (l.offOf(m)[a] >= 0) {
                n += 1;
                // A holder covers the byte, at the same offset.
                try std.testing.expectEqual(l.offOf(m)[a], l.covOf(m)[a]);
            }
        }
        if (n > 0) held += 1;
        if (n > 1) two += 1;
    }
    try std.testing.expectEqual(@as(usize, 0), two);
    std.debug.print("one holder: {d} bytes held, none by two members\n", .{held});
    const M = est.Member;
    const homes = [_]struct { a: u16, m: M }{
        // step 2: Position
        .{ .a = 0x8CCC, .m = .p },  .{ .a = 0x8CD2, .m = .p },  .{ .a = 0x9EF6, .m = .p },  .{ .a = 0xA03A, .m = .p },  .{ .a = 0x8C06, .m = .p },
        // step 3: SearchVars
        .{ .a = 0x781A, .m = .sv }, .{ .a = 0x8B97, .m = .sv }, .{ .a = 0x725C, .m = .sv }, .{ .a = 0x73F2, .m = .sv }, .{ .a = 0xA846, .m = .sv },
        .{ .a = 0xA8D8, .m = .sv },
        // step 4: EvalVars, EvalState
        .{ .a = 0x369A, .m = .ev }, .{ .a = 0x8CCA, .m = .ev }, .{ .a = 0x8EB6, .m = .ev }, .{ .a = 0x90B6, .m = .ev },
        .{ .a = 0x9EBA, .m = .ev }, .{ .a = 0xA8DE, .m = .ev }, .{ .a = 0xA6A3, .m = .ev },
        // step 5: LeafVars, ThreatVars, EvalState (the last irreversible plies, alone since the
        // repetition test reads them there)
        .{ .a = 0x9D94, .m = .ev }, .{ .a = 0x9DBD, .m = .ev },
        .{ .a = 0x7464, .m = .ev }, .{ .a = 0xA5F5, .m = .ev }, .{ .a = 0x8FE4, .m = .lv }, .{ .a = 0x9DBE, .m = .lv }, .{ .a = 0x9E95, .m = .lv },
        .{ .a = 0xA272, .m = .tv }, .{ .a = 0x9356, .m = .tv }, .{ .a = 0xA5EC, .m = .tv }, .{ .a = 0xA3F4, .m = .tv },
        // step 6: EvalVars (EvalState is EvalVars): the style flag, the masks, the king rule
        .{ .a = 0x1548, .m = .ev },
        .{ .a = 0x9D8C, .m = .ev }, .{ .a = 0xA6C2, .m = .ev }, .{ .a = 0x39AE, .m = .ev },
        // the bytes past the board: ThreatVars alone
        .{ .a = 0x9F6E, .m = .tv }, .{ .a = 0x9FBB, .m = .tv },
    };
    for (homes) |x| {
        for (0..est.n_members) |m| {
            const want = m == @backingInt(x.m);
            try std.testing.expectEqual(want, l.offOf(m)[x.a] >= 0);
        }
        try std.testing.expect(l.covOf(0)[x.a] < 0); // State no longer declares it
    }
    // Past the marks' room (DG:8B98) no struct of the domain declares a byte up to the
    // next variable the original has there (rootprep's word DG:8BAA).
    for (0x8B98..0x8BAA) |a| for (0..est.n_members) |m| try std.testing.expect(l.covOf(m)[a] < 0);
    // The square-value, king, king-zone and rook tables are at the original's length since
    // step 6 (Black's pawn table no longer runs into State.pv_end at DG:AB08); an over-long
    // table does not hold the variable it runs into: ThreatVars.black_rays_after (136 bytes
    // at DG:A1DC) and LeafVars.wk_diag at DG:A234.
    try std.testing.expect(l.covOf(2)[0xAB08] < 0);
    const tv_m: usize = @backingInt(est.Member.tv);
    try std.testing.expect(l.offOf(tv_m)[0xA234] < 0 and l.covOf(tv_m)[0xA234] >= 0);
}

test "stage B: a byte with two holders fails the check" {
    const gpa = std.testing.allocator;
    var l = try est.Layout.build(gpa, false);
    defer l.deinit(gpa);
    // Give LeafVars a holder's offset at DG:A5F5, which only EvalVars holds.
    const lv: usize = @backingInt(est.Member.lv);
    l.off[lv * 0x10000 + 0xA5F5] = 0;
    try std.testing.expect(!est.checkOneHolder(&l));
}

// ---- static_eval's exchange callees on pinexchange -----------------------------------

// The pawn vectors (tests/golden/evalpawns/*.zst, tools/port/gen_evalpawns_vectors.py) as
// src/adapt_eval_test.zig replays them; here only static_eval runs, as the domain binds it
// (`StaticEvalCallees`, on one Position, EvalVars and Scratch), with each callee's result
// checked against the one the original returned at that call. The other calls' effects
// are taken from the recording.

const dgroup = @import("dgroup.zig");
const se = @import("staticeval.zig");
const ase = @import("adapt_staticeval.zig");
const PawnHash = @import("pawnhash.zig").PawnHash;
const adapt_position = @import("adapt_position.zig");
const adapt_movegen = @import("adapt_movegen.zig");
const R = vec.Regions.Region;

/// gen_evalpawns_vectors.py IMAGE (as src/adapt_eval_test.zig `pawn_regions`).
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

const CalleeRecord = struct { site: u16, a0: u16, a1: u16, ax: u16 };

/// The domain's static_eval callees, each checked against the next recorded call.
const Checked = struct {
    inner: *DomainCtx.StaticEvalCallees,
    recs: [64]CalleeRecord = undefined,
    n: usize = 0,
    next: usize = 0,
    equal: [6]usize = @splat(0),
    differ: [6]usize = @splat(0),
    failed: ?[]const u8 = null,
    msg: [200]u8 = undefined,

    fn push(k: *Checked, r: CalleeRecord) void {
        if (k.n < k.recs.len) {
            k.recs[k.n] = r;
            k.n += 1;
        }
    }
    fn self(ctx: *anyopaque) *Checked {
        return @ptrCast(@alignCast(ctx));
    }
    fn after(k: *Checked, callee: ase.Callee, a0: u16, a1: ?u16, real: u16) u16 {
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
        if (real != r.ax) {
            // As in adapt_eval_test.zig: the vectors do not record everything the exchange
            // routines read (the king-ray maps, the work areas, the bytes past the board):
            // counted, and the recorded result used so that the replay keeps the original's path.
            k.differ[@backingInt(callee)] += 1;
            return r.ax;
        }
        k.equal[@backingInt(callee)] += 1;
        return real;
    }
    fn seeWhite(ctx: *anyopaque, sq: u16, v: u16) u16 {
        const k = self(ctx);
        return k.after(.see_white, sq, v, DomainCtx.StaticEvalCallees.seeWhite(k.inner, sq, v));
    }
    fn seeBlack(ctx: *anyopaque, sq: u16, v: u16) u16 {
        const k = self(ctx);
        return k.after(.see_black, sq, v, DomainCtx.StaticEvalCallees.seeBlack(k.inner, sq, v));
    }
    fn att4CEC(ctx: *anyopaque, sq: u16, v: u16) u16 {
        const k = self(ctx);
        return k.after(.att_4cec, sq, v, DomainCtx.StaticEvalCallees.att4CEC(k.inner, sq, v));
    }
    fn att41B6(ctx: *anyopaque, sq: u16, v: u16) u16 {
        const k = self(ctx);
        return k.after(.att_41b6, sq, v, DomainCtx.StaticEvalCallees.att41B6(k.inner, sq, v));
    }
    fn att4A76(ctx: *anyopaque, sq: u16) u16 {
        const k = self(ctx);
        return k.after(.att_4a76, sq, null, DomainCtx.StaticEvalCallees.att4A76(k.inner, sq));
    }
    fn att4AD4(ctx: *anyopaque, sq: u16) u16 {
        const k = self(ctx);
        return k.after(.att_4ad4, sq, null, DomainCtx.StaticEvalCallees.att4AD4(k.inner, sq));
    }
    fn callees(k: *Checked) se.Callees {
        return .{ .see_white = seeWhite, .see_black = seeBlack, .r4793_4CEC = att4CEC, .r4793_41B6 = att41B6, .r2B9F_4A76 = att4A76, .r2B9F_4AD4 = att4AD4, .ctx = k };
    }
};

fn skipDelta(c: *vec.Cursor) void {
    const n = c.varint();
    for (0..n) |_| {
        _ = c.varint();
        _ = c.byte();
    }
}

const PinCounts = struct { calls: usize = 0, callees: usize = 0, equal: [6]usize = @splat(0), differ: [6]usize = @splat(0) };

fn replayStaticEval(gpa: std.mem.Allocator, name: []const u8, counts: *PinCounts) !void {
    const data = try vec.readVectors(gpa, "evalpawns", name);
    defer gpa.free(data);
    var c: vec.Cursor = .{ .d = data };
    try std.testing.expectEqualSlices(u8, "MCEP", c.take(4));
    try std.testing.expectEqual(@as(u16, 4), c.int(u16));
    const size = c.int(u16);
    _ = c.take(c.int(u16));
    var regions = try vec.Regions.init(gpa, &pawn_regions);
    defer regions.deinit(gpa);
    const dg_len = regions.len();
    try std.testing.expectEqual(@as(usize, size), dg_len + hash_bytes);
    const rec = try gpa.dupe(u8, c.take(size));
    defer gpa.free(rec);
    const got = try gpa.alloc(u8, dg_len);
    defer gpa.free(got);
    const img = try gpa.create(dgroup.Image);
    defer gpa.destroy(img);
    dgroup.init(img);
    const ph = try gpa.create(PawnHash);
    defer gpa.destroy(ph);
    ph.* = .{};
    const hash = std.mem.sliceAsBytes(&ph.tables);
    // The record into the image and the pawn hash.
    const Sync = struct {
        fn toState(r: []const u8, rg: *vec.Regions, im: *dgroup.Image, hs: []u8) void {
            rg.scatter(r[0..rg.len()], im);
            @memcpy(hs, r[rg.len()..]);
        }
        /// A change list applied to the record, and to the image and the pawn hash when
        /// `to_state`.
        fn apply(cur: *vec.Cursor, r: []u8, rg: *vec.Regions, im: *dgroup.Image, hs: []u8, to_state: bool) void {
            const n = cur.varint();
            var prev: isize = -1;
            for (0..n) |_| {
                const off: usize = @intCast(prev + 1 + @as(isize, @intCast(cur.varint())));
                r[off] ^= cur.byte();
                if (to_state) {
                    if (off < rg.len()) im[rg.addr[off]] = r[off] else hs[off - rg.len()] = r[off];
                }
                prev = @intCast(off);
            }
        }
    };
    Sync.toState(rec, &regions, img, hash);
    const dom = try est.Members.create(gpa);
    defer dom.destroy(gpa);

    var previous: Checked = .{ .inner = undefined };
    var previous_stray: se.StrayBytes = .{};
    while (true) {
        const tag = c.byte();
        switch (tag) {
            0 => {
                for (1..10) |_| _ = c.int(u32);
                return;
            },
            10 => {
                _ = c.take(size);
                continue;
            },
            1...9 => {},
            else => return error.BadRecordTag,
        }
        Sync.apply(&c, rec, &regions, img, hash, true);
        var want_ax: ?u16 = null;
        var got_ax: ?u16 = null;
        switch (tag) {
            1, 2, 5, 6 => _ = c.int(u16),
            3, 4 => {
                _ = c.int(u16);
                _ = c.byte(); // hit
            },
            7 => {},
            8 => _ = c.take(4),
            9 => {
                const side = c.int(u16);
                const arg2 = c.int(u16);
                const path = c.byte();
                const ax = c.int(u16);
                var reached = false;
                var cp: []const u8 = &.{};
                var inner: DomainCtx.StaticEvalCallees = .{ .p = &dom.p, .s = &dom.s };
                var k: Checked = .{ .inner = &inner };
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
                // static_eval as the domain calls it: one Position, EvalVars and Scratch,
                // the callees on them, DEV-015's stray bytes as recorded (Fixes.original).
                var pb: adapt_position.PositionMap.Snapshot = undefined;
                var vb: adapt_position.EvalVarsMap.Snapshot = undefined;
                var sb: adapt_movegen.ScratchMap.Snapshot = undefined;
                adapt_position.PositionMap.loadSnap(&dom.p, img, &pb);
                adapt_position.EvalVarsMap.loadSnap(&dom.ev, img, &vb);
                adapt_movegen.ScratchMap.loadSnap(&dom.s, img, &sb);
                const iface = k.callees();
                const r = se.staticEval(&dom.p, &dom.ev, ph, &iface, side, arg2, se.Fixes.original, .{ stray, previous_stray });
                _ = adapt_movegen.ScratchMap.storeChanged(&dom.s, img, &sb);
                _ = adapt_position.EvalVarsMap.storeChanged(&dom.ev, img, &vb);
                _ = adapt_position.PositionMap.storeChanged(&dom.p, img, &pb);
                previous_stray = stray;
                if (k.failed) |msg| {
                    std.debug.print("\n{s}: static_eval(side {d}, arg2 {d}): {s}\n", .{ name, side, arg2, msg });
                    return error.MismatchWithOriginal;
                }
                counts.calls += 1;
                counts.callees += k.next;
                for (0..6) |j| {
                    counts.equal[j] += k.equal[j];
                    counts.differ[j] += k.differ[j];
                }
                previous = .{ .inner = undefined };
                for (k.recs[0..own]) |x| previous.push(x);
                want_ax = ax;
                got_ax = @bitCast(r);
            },
            else => unreachable,
        }
        Sync.apply(&c, rec, &regions, img, hash, tag != 9);
        if (tag == 9) {
            regions.gather(img, got);
            if (want_ax != got_ax or !std.mem.eql(u8, rec[0..dg_len], got) or !std.mem.eql(u8, rec[dg_len..], hash)) {
                std.debug.print("\n{s}: static_eval differs: AX want {?X}, got {?X}\n", .{ name, want_ax, got_ax });
                if (std.mem.indexOfDiff(u8, rec[0..dg_len], got)) |off| {
                    var b: [96]u8 = undefined;
                    std.debug.print("  first differing byte: {s}: want {X:0>2}, got {X:0>2}\n", .{ regions.describe(&b, off), rec[off], got[off] });
                }
                return error.MismatchWithOriginal;
            }
        }
    }
}

test "stage B: static_eval with 4793:41B6 / 4CEC as pinexchange under Fixes.original, as the domain binds it: every recorded call" {
    const gpa = std.testing.allocator;
    var t: PinCounts = .{};
    for ([_][]const u8{ "A.zst", "B.zst", "C.zst", "D.zst", "E.zst", "F.zst" }) |name| try replayStaticEval(gpa, name, &t);
    for (0..6) |j| std.debug.print("  domain static_eval callee {t}: {d} results equal to the original's, {d} differ\n", .{ @as(ase.Callee, @fromBackingInt(@intCast(j))), t.equal[j], t.differ[j] });
    std.debug.print("domain static_eval: {d} calls, {d} callee results checked\n", .{ t.calls, t.callees });
    try std.testing.expect(t.calls > 0);
    // As for Stage A's lifted routines (adapt_eval_test.zig): the exchange evaluators and
    // the attack tests read only what the recording holds and must all agree; 41B6 / 4CEC
    // also read what these vectors do not record (proved on full images in
    // pinexchange_test.zig), so a few may differ.
    for ([_]ase.Callee{ .see_white, .see_black, .att_4a76, .att_4ad4 }) |k| try std.testing.expectEqual(@as(usize, 0), t.differ[@backingInt(k)]);
    for ([_]ase.Callee{ .att_41b6, .att_4cec }) |k| try std.testing.expect(t.differ[@backingInt(k)] * 100 <= t.equal[@backingInt(k)]);
}

// ---- deliberate faults ------------------------------------------------------------------

const break_files_all = [_][]const u8{ "start-d3-s1-subtree-207.zst", "check-evasion-d4-s1-subtree-1572.zst", "rook-ending-d4-s2-subtree-21305.zst" };
/// The subtrees the Stage A faults are tried on (skipped in Debug, stageABreak).
const break_files: []const []const u8 = &break_files_all;

// ---- the bytes past the board that the threat evaluators can read ------------------------

test "stage B: past the board, boardAt reads each byte from its holder, a redirect, or a copy threats refreshes" {
    const gpa = std.testing.allocator;
    var l = try est.Layout.build(gpa, false);
    defer l.deinit(gpa);
    const st: usize = @backingInt(est.Member.st);
    const p: usize = @backingInt(est.Member.p);
    const s: usize = @backingInt(est.Member.s);
    const lv: usize = @backingInt(est.Member.lv);
    const tv: usize = @backingInt(est.Member.tv);
    // DG:9F6E to 9FEB, `ThreatVars.board_after`: held there, but the game ply (9FC8), which
    // `boardAt` takes from `Position`.
    for (0x9F6E..0x9FEC) |a| {
        if (a == 0x9FC8 or a == 0x9FC9) {
            try std.testing.expect(l.offOf(p)[a] >= 0);
            continue;
        }
        try std.testing.expect(l.offOf(tv)[a] >= 0);
    }
    // DG:9FEC to A07F, `Scratch.attackers` and `defenders`: held there, but the piece lists
    // (A03A to A059), which `boardAt` takes from `Position`, and the two words `threats`
    // refreshes from their holders.
    const sc = @import("see.zig").Scratch;
    for (0x9FEC..0xA080) |a| {
        if (a >= 0xA03A and a < 0xA05A) {
            try std.testing.expect(l.offOf(p)[a] >= 0);
        } else if (a == 0xA000 or a == 0xA001) {
            try std.testing.expectEqual(@as(i32, @intCast(@offsetOf(@import("leaf.zig").LeafVars, "root_game_ply") + a - 0xA000)), l.offOf(lv)[a]);
            try std.testing.expectEqual(@as(i32, @intCast(@offsetOf(sc, "attackers") + est.root_ply_in_attackers + a - 0xA000)), l.covOf(s)[a]);
        } else if (a == 0xA05A or a == 0xA05B) {
            try std.testing.expectEqual(@as(i32, @intCast(@offsetOf(sn.State, "root_material_balance") + a - 0xA05A)), l.offOf(st)[a]);
            try std.testing.expectEqual(@as(i32, @intCast(@offsetOf(sc, "attackers") + est.root_balance_in_attackers + a - 0xA05A)), l.covOf(s)[a]);
        } else {
            try std.testing.expect(l.offOf(s)[a] >= 0);
        }
    }
    std.debug.print("past the board: DG:9F6E to A07F, every byte read from its holder, a redirect or a refreshed copy\n", .{});
}

/// After `enter` on a recorded subtree's image, the root's game ply and material balance are
/// changed in their holders, as main changes them inside the domain since Stage B step 7,
/// and the threat evaluator is called: whether `Scratch`'s copies then equal the holders.
fn rootAliasesFresh(comptime C: type) !bool {
    const gpa = std.heap.page_allocator;
    const d = try vec.readVectors(gpa, "subtree", ant.files[0]);
    defer gpa.free(d);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const r = try ant.parse(arena_state.allocator(), d);
    var tables = try ant.Tables.init(gpa, std.mem.readInt(u32, r.dg_in[0x5A..][0..4], .little) / 10);
    defer tables.deinit(gpa);
    for (&tables.t) |*t| t.clear();
    const dom = try est.Members.create(gpa);
    defer dom.destroy(gpa);
    const img = try gpa.create(@import("dgroup.zig").Image);
    defer gpa.destroy(img);
    @memcpy(img, r.dg_in);
    const st = try gpa.create(sn.State);
    defer gpa.destroy(st);
    st.* = .{};
    const ph = try gpa.create(@import("pawnhash.zig").PawnHash);
    defer gpa.destroy(ph);
    ph.* = .{};
    var keys: [512]u48 = @splat(0);
    var events: std.ArrayList(an.Event) = .empty;
    defer events.deinit(gpa);
    var c: C = .{ .codec = .{ .img = img }, .st = st, .pawn_hash = ph, .tables = &tables.t, .game_keys = &keys, .events = &events, .gpa = gpa, .dom = dom, .alias_panic = false };
    @import("state_image.zig").enter(&c);
    dom.lv.root_game_ply +%= 0x0101;
    st.root_material_balance +%= 0x0101;
    var counter: u8 = 0;
    _ = c.threats(r.side, r.ply, 0, &counter);
    const ply: [2]u8 = @bitCast(dom.lv.root_game_ply);
    const bal: [2]u8 = @bitCast(st.root_material_balance);
    return std.mem.eql(u8, &ply, dom.s.attackers[est.root_ply_in_attackers..][0..2]) and
        std.mem.eql(u8, &bal, dom.s.attackers[est.root_balance_in_attackers..][0..2]) and c.alias_writes == 0;
}

test "stage B: threats reads the root's game ply (DG:A000) and material balance (DG:A05A) as main left them inside the domain" {
    try std.testing.expect(try rootAliasesFresh(DomainCtx));
    // Without the refresh `Scratch` keeps what `enter` loaded: the fault this guards against.
    try std.testing.expect(!try rootAliasesFresh(est.NodeEnvWith(pos.Fixes.original, .stale_root_aliases, true)));
    std.debug.print("root aliases: Scratch's copies of DG:A000 and DG:A05A equal their holders after threats; stale with the refresh left out\n", .{});
}

test "stage B: a write through an over-long declaration is caught by the alias-write detector (and not by the search)" {
    const s = try runSubtrees(est.NodeEnvWith(pos.Fixes.original, .alias_write, true), "alias write", &break_files_all, true);
    std.debug.print("break alias_write: {d} of {d} subtrees differ, {d} alias writes found\n", .{ s.failed, break_files_all.len, s.alias_writes });
    try std.testing.expect(s.alias_writes > 0);
}

test "stage B: the domain's position loaded with the main key one byte off is caught by the subtrees" {
    const s = try runSubtrees(est.NodeEnvWith(pos.Fixes.original, .position_off_by_one, true), "position off by one", &break_files_all, true);
    std.debug.print("break position_off_by_one: {d} of {d} subtrees differ\n", .{ s.failed, break_files_all.len });
    try std.testing.expect(s.failed > 0);
}

test "stage B: the domain's SearchVars loaded with the move marks one byte off is caught by the subtrees" {
    const s = try runSubtrees(est.NodeEnvWith(pos.Fixes.original, .search_vars_off_by_one, true), "search vars off by one", &break_files_all, true);
    std.debug.print("break search_vars_off_by_one: {d} of {d} subtrees differ\n", .{ s.failed, break_files_all.len });
    try std.testing.expect(s.failed > 0);
}

test "stage B: the domain's EvalVars loaded with the pawn square sums one byte off is caught by the subtrees" {
    const s = try runSubtrees(est.NodeEnvWith(pos.Fixes.original, .eval_vars_off_by_one, true), "eval vars off by one", &break_files_all, true);
    std.debug.print("break eval_vars_off_by_one: {d} of {d} subtrees differ\n", .{ s.failed, break_files_all.len });
    try std.testing.expect(s.failed > 0);
}

test "stage A: the node's EvalVars synchronised with the pawn square sums one byte off is caught by the subtrees" {
    try std.testing.expect(try stageABreak(an.CtxMaps(.hand, pos.Fixes.original, adapt_position.PositionMap, adapt_movegen.SearchVarsMap, est.EvalVarsMapOffByOne, an.LeafVarsMap, an.ThreatVarsMap), "eval vars") > 0);
}

test "stage B: the domain's ThreatVars loaded with the first ply limit one byte off is caught by the subtrees" {
    const s = try runSubtrees(est.NodeEnvWith(pos.Fixes.original, .threat_vars_off_by_one, true), "threat vars off by one", &break_files_all, true);
    std.debug.print("break threat_vars_off_by_one: {d} of {d} subtrees differ\n", .{ s.failed, break_files_all.len });
    try std.testing.expect(s.failed > 0);
}

test "stage A: the node's ThreatVars synchronised with the first ply limit one byte off is caught by the subtrees" {
    try std.testing.expect(try stageABreak(an.CtxMaps(.hand, pos.Fixes.original, adapt_position.PositionMap, adapt_movegen.SearchVarsMap, adapt_position.EvalVarsMap, an.LeafVarsMap, est.ThreatVarsMapOffByOne), "threat vars") > 0);
}

test "stage A: the node's position synchronised with the main key one byte off is caught by the subtrees" {
    try std.testing.expect(try stageABreak(an.CtxPos(.hand, pos.Fixes.original, est.PositionMapOffByOne), "position") > 0);
}

test "stage A: the node's SearchVars synchronised with the move marks one byte off is caught by the subtrees" {
    try std.testing.expect(try stageABreak(an.CtxMaps(.hand, pos.Fixes.original, adapt_position.PositionMap, est.SearchVarsMapOffByOne, adapt_position.EvalVarsMap, an.LeafVarsMap, an.ThreatVarsMap), "search vars") > 0);
}

/// The break subtrees through the Stage A `Ctx` `C`; the number that differ.
fn stageABreak(comptime C: type, comptime what: []const u8) !usize {
    // In Debug the Stage A binding copies every struct around each callee: one subtree took
    // over 40 minutes. The faults are shown in ReleaseFast and ReleaseSafe.
    if (@import("builtin").mode == .debug) return error.SkipZigTest;
    const gpa = std.heap.page_allocator;
    var failed: usize = 0;
    for (break_files) |name| {
        const d = try vec.readVectors(gpa, "subtree", name);
        defer gpa.free(d);
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const r = try ant.parse(arena_state.allocator(), d);
        const slots = std.mem.readInt(u32, r.dg_in[0x5A..][0..4], .little) / 10;
        var tables = try ant.Tables.init(gpa, slots);
        defer tables.deinit(gpa);
        _ = ant.runOneCtx(C, "stage A, " ++ what ++ " off by one", gpa, name, &r, &tables, true, null) catch {
            failed += 1;
            continue;
        };
    }
    std.debug.print("break Stage A " ++ what ++ " off by one: {d} of {d} subtrees differ\n", .{ failed, break_files.len });
    return failed;
}

// ---- DG:3766 + H: the read past the 40-byte table -----------------------------------

test "qs_max_ply: B(3766 + H) for every H from 0 to 127 is the byte the original reads, on prepare_eval's table" {
    const gpa = std.testing.allocator;
    const ert_test = @import("engine_root_test.zig");
    // DGROUP just after prepare_eval (start-d3 search 1), with the killers and the
    // non-pawn material made distinct so that every byte past the table is checked.
    const img = try gpa.create(dgroup.Image);
    defer gpa.destroy(img);
    const snap = try ert_test.readGolden(gpa, "whole/start-d3-s1-prepared.bin");
    defer gpa.free(snap);
    @memcpy(img, snap);
    for (0..0x4A) |i| img[0x3790 + i] = @truncate(0x80 + i);
    img[0x378E] = 0x5A;
    img[0x378F] = 0x01;
    for (0..12) |i| img[0x37DA + i] = @truncate(i + 1);
    const st = try gpa.create(sn.State);
    defer gpa.destroy(st);
    st.* = .{};
    var p: pos.Position = .{};
    adapt_position.PositionMap.load(&p, img);
    an.imageToState(img, st);
    st.p = &p;
    var nonzero: usize = 0;
    for (0..40) |h| nonzero += @intFromBool(img[0x3766 + h] != 0);
    try std.testing.expect(nonzero > 0); // prepare_eval has written the table
    for (0..128) |h| try std.testing.expectEqual(img[0x3766 + h], sn.qsMaxPly(st, @intCast(h)));
}

test "qs_max_ply: K and P against K, go depth 30 (H passes 31) runs to the end, shipped engine and the original's logic" {
    const engine_mod = @import("engine.zig");
    const fen = @import("fen.zig");
    const uci_engine = @import("uci_engine.zig");
    const gpa = std.testing.allocator;
    const Sink = struct {
        fn lineFn(_: ?*anyopaque, _: []const u8) void {}
    };
    inline for (.{ pos.Fixes.corrected, pos.Fixes.original }) |fixes| {
        const E = engine_mod.EngineOf(fixes);
        var e = try E.init(gpa);
        defer e.deinit();
        e.reporting = false;
        const eng = e.engine();
        var sig: uci_engine.Signals = .{};
        const d = try fen.parse("8/8/8/4K3/Pk6/8/8/8 b - - 0 67");
        try std.testing.expect(eng.setPosition(&d, .setup, &.{}) == null);
        const r = eng.search(&.{ .depth = 30 }, &sig, .{ .ctx = null, .lineFn = Sink.lineFn });
        try std.testing.expect(r.best != null);
        std.debug.print("K+P v K, depth 30 ({s}): {d} nodes\n", .{ if (fixes.dev001_ep_hash_square) "shipped" else "original", e.root.nodes });
    }
}
