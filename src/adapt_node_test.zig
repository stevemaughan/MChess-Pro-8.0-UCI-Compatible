//! Stage A, steps 9 and 10: the subtree test (docs/arch/60-engine-assembly.md 6.1). Each
//! file of tests/golden/subtree/ is one node of a recorded search, taken by
//! `tools/oracle/oracle.py --subtree K` (format: `SUBTREE_FORMAT` there): DGROUP, the far
//! data segment 5A7B (pawn hash, game record) and every non-zero main hash slot at the
//! node's entry; and at its return AX, the parent's legal word, the node and make counts,
//! every make (ply, from, to, flag), node entry (side, ply, alpha, beta) and node return
//! (side, ply, AX) in order, DGROUP and the hash slots.
//!
//! Recorded with `--hash-tail zero --dev003 move`: the oracle writes, for DEV-003, the
//! mark of the move itself, as docs/DEVIATIONS.md states the fix and `movegen.Fixes.corrected`
//! implements it. The oracle's default writes the mark the code loads, which at the two
//! pawn-capture sites (1E9D:3A40, 417E) is indexed by a row [bp-0Ch] that gen_all_moves
//! has not yet written in that call (pawns come first in its slot order, DG:1A60): a stale
//! stack word. Subtrees recorded with the default differ from the engine wherever such a
//! read hits a non-zero mark (4 of 5 tried in check-evasion-d4; see the report of the
//! task join-node). DEV-001 is off (`pos.Fixes.original`), as for every golden file.
//!
//! The test runs the real node tree (src/adapt_node.zig, every callee the ported routine)
//! from the entry state and compares: each event in order (the first difference is
//! named, with the events before it), AX, the legal word, the counts, every byte of
//! DGROUP below the stacks (named through the units' field maps), and every hash slot.
//! It runs with the lifted threat evaluators and with the hand-written ones.

const std = @import("std");
const sn = @import("searchnode.zig");
const pos = @import("position.zig");
const dgroup = @import("dgroup.zig");
const an = @import("adapt_node.zig");
const vec = @import("adapt_vectors.zig");
const PawnHash = @import("pawnhash.zig").PawnHash;
const bench = @import("bench.zig");

const Image = dgroup.Image;

/// The recorded subtrees (tests/golden/subtree/), and what each is.
pub const files = [_][]const u8{
    "start-d3-s1-subtree-1.zst", // start position, depth 3, iteration 0: the first ply-2 node (Black, entered from root_search), 1 node
    "start-d3-s1-subtree-114.zst", // the same search, later iteration: a White node at ply 3 below 2EC8, 47 nodes
    "start-d3-s1-subtree-207.zst", // the same search: a White node at ply 3, 387 nodes
    "check-evasion-d4-s1-subtree-300.zst", // Black in check at the root, depth 4: a Black node at ply 11 in check, 4 nodes
    "check-evasion-d4-s1-subtree-450.zst", // the same search: a White node at ply 8 in check, 10 nodes
    "check-evasion-d4-s1-subtree-1050.zst", // the same search: a Black node at ply 5 in check, 5 nodes
    "check-evasion-d4-s1-subtree-1572.zst", // the same search: a Black node at ply 3, 941 nodes
    "check-evasion-d4-s1-subtree-1800.zst", // the same search: a Black node at ply 7 (extended), 34 nodes
    "check-evasion-d4-s1-subtree-3796.zst", // the same search: a White node at ply 4, 700 nodes
    "check-evasion-d4-s2-subtree-52388.zst", // the next search (White; the game record holds the moves played): a White node at ply 3, 2,986 nodes
    "check-evasion-d4-s2-subtree-91604.zst", // the same search, 91,604 nodes in: a White node at ply 5, 2,994 nodes
    "sicilian-najdorf-d4-s2-subtree-20201.zst", // Sicilian Najdorf middlegame, depth 4, second search (Black): a Black node at ply 3, 3,443 nodes
    "rook-ending-d4-s2-subtree-6311.zst", // rook ending (Setup), depth 4, second search (Black): a Black node at ply 3, 5,979 nodes
    "rook-ending-d4-s2-subtree-21305.zst", // the same search: a White node at ply 4 in check, 972 nodes
    "open-game-d5-s2-subtree-38801.zst", // 1 e4 e5 2 Nf3 Nc6 3 Bb5, depth 5, Black to move: a White node at ply 4, 2,399 nodes
    "open-game-d5-s2-subtree-46022.zst", // the same search: a Black node at ply 3, 2,683 nodes
    "pawn-ending-d5-s2-subtree-1260.zst", // pawn ending (Setup), depth 5, second search (White): a White node at ply 3, 232 nodes
    "pawn-ending-d5-s3-subtree-790.zst", // the same game, third search (Black): a Black node at ply 3, 325 nodes
} ++ extra_files;

const extra_files = [_][]const u8{};

/// DGROUP bytes not compared, and why.
const Excluded = struct { lo: u16, hi: u16, why: []const u8 };
const excluded = [_]Excluded{
    // The original's stack (CD72..D5A0 in every recording) and the lifted routines'
    // scaffold stack below FFF0 (src/adapt_staticeval.zig, adapt_threats.zig).
    .{ .lo = 0xC000, .hi = 0xFFFF, .why = "stacks" },
    // The XMS move structures the original's probe and store fill for the driver
    // (0000:6A91; docs/arch/30-search-node.md, mirror table): read and write, White to
    // move AC18 / 9E98, Black to move A6B2 / 8C32. The engine indexes its tables directly.
    .{ .lo = 0xAC18, .hi = 0xAC27, .why = "XMS read structure, White to move" },
    .{ .lo = 0x9E98, .hi = 0x9EA7, .why = "XMS write structure, White to move" },
    .{ .lo = 0xA6B2, .hi = 0xA6C1, .why = "XMS read structure, Black to move" },
    .{ .lo = 0x8C32, .hi = 0x8C41, .why = "XMS write structure, Black to move" },
};

pub const Rec = struct {
    side: sn.Side,
    ply: i16,
    alpha: i16,
    beta: i16,
    legal_before: i16,
    k: u32,
    makes_before: u32,
    dg_in: []const u8,
    far_in: []const u8,
    slots_in: []const u8,
    nslots_in: u32,
    ax: i16,
    legal_after: i16,
    nodes: u32,
    makes: u32,
    events: []const an.Event,
    dg_out: []const u8,
    slots_out: []const u8,
    nslots_out: u32,
};

pub fn parse(arena: std.mem.Allocator, d: []const u8) !Rec {
    var c: vec.Cursor = .{ .d = d };
    if (!std.mem.eql(u8, c.take(8), "MCSUBT1\x00")) return error.BadMagic;
    var r: Rec = undefined;
    r.side = @truncate(c.byte());
    r.ply = c.int(i16);
    r.alpha = c.int(i16);
    r.beta = c.int(i16);
    r.legal_before = c.int(i16);
    r.k = c.int(u32);
    r.makes_before = c.int(u32);
    r.dg_in = c.take(0x10000);
    r.far_in = c.take(0x10000);
    r.nslots_in = c.int(u32);
    r.slots_in = c.take(15 * @as(usize, r.nslots_in));
    r.ax = c.int(i16);
    r.legal_after = c.int(i16);
    r.nodes = c.int(u32);
    r.makes = c.int(u32);
    const nev = c.int(u32);
    const evs = try arena.alloc(an.Event, nev);
    for (evs) |*e| {
        const b = c.take(8);
        e.* = switch (b[0]) {
            'm' => .{ .make = .{ .ply = b[1], .from = b[2], .to = b[3], .flag = b[4] } },
            'n' => .{ .node = .{
                .side = @truncate(b[1]),
                .ply = std.mem.readInt(i16, b[2..4], .little),
                .alpha = std.mem.readInt(i16, b[4..6], .little),
                .beta = std.mem.readInt(i16, b[6..8], .little),
            } },
            'x' => .{ .ret = .{
                .side = @truncate(b[1]),
                .ply = std.mem.readInt(i16, b[2..4], .little),
                .ax = std.mem.readInt(i16, b[4..6], .little),
            } },
            else => return error.BadEvent,
        };
    }
    r.events = evs;
    r.dg_out = c.take(0x10000);
    r.nslots_out = c.int(u32);
    r.slots_out = c.take(15 * @as(usize, r.nslots_out));
    if (c.i != d.len) return error.TrailingBytes;
    return r;
}

fn eventEql(a: an.Event, b: an.Event) bool {
    return switch (a) {
        .make => |x| switch (b) {
            .make => |y| x.ply == y.ply and x.from == y.from and x.to == y.to and x.flag == y.flag,
            else => false,
        },
        .node => |x| switch (b) {
            .node => |y| x.side == y.side and x.ply == y.ply and x.alpha == y.alpha and x.beta == y.beta,
            else => false,
        },
        .ret => |x| switch (b) {
            .ret => |y| x.side == y.side and x.ply == y.ply and x.ax == y.ax,
            else => false,
        },
    };
}

fn printEvent(tag: []const u8, i: usize, e: an.Event) void {
    switch (e) {
        .make => |x| std.debug.print("  {s} {d}: make ply {d} {d}-{d} flag {d}\n", .{ tag, i, x.ply, x.from, x.to, x.flag }),
        .node => |x| std.debug.print("  {s} {d}: node {s} ply {d} alpha {d} beta {d}\n", .{ tag, i, if (x.side == 0) "w" else "b", x.ply, x.alpha, x.beta }),
        .ret => |x| std.debug.print("  {s} {d}: return {s} ply {d} AX {d}\n", .{ tag, i, if (x.side == 0) "w" else "b", x.ply, x.ax }),
    }
}

/// The variable at a DGROUP address, through the node's map and the units' maps.
fn describe(buf: []u8, a: usize) []const u8 {
    inline for (sn.dg_fields) |f| {
        if (a >= f.addr and a < @as(usize, f.addr) + f.len)
            return std.fmt.bufPrint(buf, "searchnode.State.{s} + {d} (DG:{X:0>4})", .{ f.name, a - f.addr, a }) catch f.name;
    }
    inline for (.{ an.LeafVarsMap, an.ThreatVarsMap, @import("adapt_position.zig").PositionMap, @import("adapt_position.zig").EvalVarsMap, @import("adapt_movegen.zig").ScratchMap, @import("adapt_eval.zig").EvalStateMap, @import("adapt_eval.zig").TablesMap }) |M| {
        if (M.covers(a)) return M.describe(buf, a);
    }
    return std.fmt.bufPrint(buf, "DG:{X:0>4} (no field)", .{a}) catch "?";
}

fn isExcluded(a: usize) ?[]const u8 {
    for (excluded) |e| if (a >= e.lo and a <= e.hi) return e.why;
    return null;
}

pub const Tables = struct {
    mem: [2][][10]u8,
    t: [2]sn.HashTable,

    pub fn init(gpa: std.mem.Allocator, slots: usize) !Tables {
        var x: Tables = undefined;
        for (0..2) |i| {
            x.mem[i] = try gpa.alloc([10]u8, slots);
            x.t[i] = .{ .slots = x.mem[i] };
        }
        return x;
    }
    pub fn deinit(x: *Tables, gpa: std.mem.Allocator) void {
        for (x.mem) |m| gpa.free(m);
    }
    fn fill(x: *Tables, slots: []const u8, n: u32) void {
        for (&x.t) |*t| t.clear();
        var i: usize = 0;
        while (i < n) : (i += 1) {
            const s = slots[15 * i ..][0..15];
            const idx = std.mem.readInt(u32, s[1..5], .little);
            x.t[s[0]].put(idx, s[5..15].*);
        }
    }
};

pub const Outcome = struct { nodes: u64, makes: u64, ns: i96, dev030: usize, calls: std.EnumArray(an.Method, u64), alias_writes: u64 = 0 };

/// Run one recorded subtree with the threat evaluators `threats`; fails at the first
/// difference.
pub fn runOne(comptime threats: an.Threats, gpa: std.mem.Allocator, name: []const u8, r: *const Rec, tables: *Tables, quiet: bool) !Outcome {
    return runOneCtx(an.Ctx(threats, pos.Fixes.original), @tagName(threats), gpa, name, r, tables, quiet, null);
}

/// `runOne` with the node's interface `C`: adapt_node's (Stage A) or engine_state's (Stage
/// B), the latter on the domain `dom`. With engine_state's, its alias-write detector counts
/// instead of panicking, and the count is returned.
pub fn runOneCtx(comptime C: type, comptime label: []const u8, gpa: std.mem.Allocator, name: []const u8, r: *const Rec, tables: *Tables, quiet: bool, dom: ?*@import("engine_state.zig").Members) !Outcome {
    const img = try gpa.create(Image);
    defer gpa.destroy(img);
    @memcpy(img, r.dg_in);
    const st = try gpa.create(sn.State);
    defer gpa.destroy(st);
    st.* = .{};
    const work = try gpa.create(an.Work);
    defer gpa.destroy(work);
    work.* = .{};
    const ph = try gpa.create(PawnHash);
    defer gpa.destroy(ph);
    ph.* = .{};
    @memcpy(std.mem.asBytes(&ph.tables[0]), r.far_in[0x174E..][0..2560]);
    @memcpy(std.mem.asBytes(&ph.tables[1]), r.far_in[0x6A7C..][0..2560]);
    var keys: [512]u48 = undefined;
    for (&keys, 0..) |*k, g| {
        const a = 0x3A34 + 6 * g;
        k.* = if (a + 6 <= 0x10000) std.mem.readInt(u48, r.far_in[a..][0..6], .little) else 0;
    }
    tables.fill(r.slots_in, r.nslots_in);
    var events: std.ArrayList(an.Event) = .empty;
    defer events.deinit(gpa);
    try events.ensureTotalCapacity(gpa, r.events.len + 16);

    // The domain's `Ctx` (Stage B) takes the image through the tests' codec
    // (src/state_image.zig), and has no Stage A work area.
    var c: C = if (@hasField(C, "dom")) .{ .codec = .{ .img = img }, .st = st, .pawn_hash = ph, .tables = &tables.t, .game_keys = &keys, .events = &events, .gpa = gpa, .dom = dom.?, .alias_panic = false } else .{ .img = img, .st = st, .work = work, .pawn_hash = ph, .tables = &tables.t, .game_keys = &keys, .events = &events, .gpa = gpa };
    var legal: i16 = r.legal_before;
    const t0 = bench.now();
    const ax = c.run(r.side, &legal, r.beta, r.alpha, r.ply);
    const ns = bench.now() - t0;

    // The events, in order.
    const n = @min(events.items.len, r.events.len);
    for (0..n) |i| {
        if (!eventEql(events.items[i], r.events[i])) {
            std.debug.print("{s} ({s}): event {d} differs\n", .{ name, label, i });
            const from = if (i > 6) i - 6 else 0;
            for (from..i) |j| printEvent("same", j, r.events[j]);
            printEvent("want", i, r.events[i]);
            printEvent("got ", i, events.items[i]);
            // The list of the subtree's own ply in the engine now (the original's at the
            // return is in the recorded DGROUP).
            const lp: usize = @intCast(r.ply);
            std.debug.print("  engine's list of ply {d}:", .{lp});
            for (st.move_list[lp][0..8]) |m| std.debug.print(" {d}-{d}/{d}/{d}", .{ m.from, m.to, m.flag, m.score });
            std.debug.print("\n  original's at the return:", .{});
            for (0..8) |j| {
                const a = 0x3A34 + 400 * lp + 4 * j;
                std.debug.print(" {d}-{d}/{d}/{d}", .{ r.dg_out[a], r.dg_out[a + 1], r.dg_out[a + 2], r.dg_out[a + 3] });
            }
            std.debug.print("\n", .{});
            return error.EventDiffers;
        }
    }
    if (events.items.len != r.events.len) {
        std.debug.print("{s} ({s}): {d} events, the original made {d}\n", .{ name, label, events.items.len, r.events.len });
        if (n < r.events.len) printEvent("want", n, r.events[n]) else printEvent("got ", n, events.items[n]);
        return error.EventCount;
    }
    if (ax != r.ax or legal != r.legal_after or c.nodes != r.nodes or c.makes != r.makes or c.polls != 0) {
        std.debug.print("{s} ({s}): AX {d} (want {d}), legal {d} (want {d}), nodes {d} (want {d}), makes {d} (want {d}), polls {d}\n", .{ name, label, ax, r.ax, legal, r.legal_after, c.nodes, r.nodes, c.makes, r.makes, c.polls });
        return error.ResultDiffers;
    }

    // DGROUP at the return. DEV-030: where no move was stored the original leaves the
    // never-written to-square byte in the hash entry buffer (DG:7805); the engine has 0.
    var dev030: usize = 0;
    var bad: usize = 0;
    for (0..0x10000) |a| {
        if (img[a] == r.dg_out[a]) continue;
        if (isExcluded(a) != null) continue;
        if (a == 0x7805 and r.dg_out[0x7804] == 0 and img[a] == 0) {
            dev030 += 1;
            continue;
        }
        if (bad < 12) {
            var buf: [128]u8 = undefined;
            std.debug.print("{s} ({s}): {s}: want {X:0>2}, got {X:0>2}\n", .{ name, label, describe(&buf, a), r.dg_out[a], img[a] });
        }
        bad += 1;
    }
    if (bad != 0) return error.ImageDiffers;

    // The hash slots at the return (DEV-030 again: byte 7 of an entry whose byte 6 is 0).
    var want = tables.*;
    _ = &want;
    var i: usize = 0;
    var seen: usize = 0;
    while (i < r.nslots_out) : (i += 1) {
        const s = r.slots_out[15 * i ..][0..15];
        const idx = std.mem.readInt(u32, s[1..5], .little);
        const got = tables.t[s[0]].slots[idx];
        const exp = s[5..15];
        for (0..10) |b| {
            if (got[b] == exp[b]) continue;
            if (b == 7 and exp[6] == 0 and got[7] == 0) {
                dev030 += 1;
                continue;
            }
            std.debug.print("{s} ({s}): hash table {d} slot {d} byte {d}: want {X:0>2}, got {X:0>2}\n", .{ name, label, s[0], idx, b, exp[b], got[b] });
            return error.HashDiffers;
        }
        seen += 1;
    }
    // No slot may be non-zero in the engine's tables that the original left zero.
    var nonzero: usize = 0;
    for (tables.t) |t| {
        for (t.slots) |sl| {
            if (!std.mem.allEqual(u8, &sl, 0)) nonzero += 1;
        }
    }
    if (nonzero != r.nslots_out) {
        std.debug.print("{s} ({s}): {d} non-zero hash slots, the original {d}\n", .{ name, label, nonzero, r.nslots_out });
        return error.HashDiffers;
    }
    if (!quiet) std.debug.print("{s} ({s}): {d} nodes, {d} makes, AX {d}, {d} probes, {d} stores, {d} threat calls: equal ({d} DEV-030 bytes)\n", .{ name, label, c.nodes, c.makes, ax, c.calls.get(.probe), c.calls.get(.store), c.calls.get(.threats), dev030 });
    return .{ .nodes = c.nodes, .makes = c.makes, .ns = ns, .dev030 = dev030, .calls = c.calls, .alias_writes = if (@hasField(C, "dom")) c.alias_writes else 0 };
}

fn runAll(comptime threats: an.Threats) !void {
    const gpa = std.heap.page_allocator;
    var tables: ?Tables = null;
    defer if (tables) |*t| t.deinit(gpa);
    var total_nodes: u64 = 0;
    var failed: usize = 0;
    var calls: std.EnumArray(an.Method, u64) = .initFill(0);
    for (files) |name| {
        const d = try vec.readVectors(gpa, "subtree", name);
        defer gpa.free(d);
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const r = try parse(arena_state.allocator(), d);
        // The tables' size: DG:005A, bytes per table (docs/arch/35-hash-sizing.md).
        const bytes = std.mem.readInt(u32, r.dg_in[0x5A..][0..4], .little);
        const slots = bytes / 10;
        if (tables == null or tables.?.mem[0].len != slots) {
            if (tables) |*t| t.deinit(gpa);
            tables = try Tables.init(gpa, slots);
        }
        // Every file is run, so that one report names every subtree that differs.
        const o = runOne(threats, gpa, name, &r, &tables.?, false) catch |e| {
            std.debug.print("{s} ({s}): FAILED, {s}\n", .{ name, @tagName(threats), @errorName(e) });
            failed += 1;
            continue;
        };
        total_nodes += o.nodes;
        for (std.enums.values(an.Method)) |m| calls.getPtr(m).* += o.calls.get(m);
    }
    if (failed != 0) return error.SubtreeDiffers;
    std.debug.print("subtrees ({s}): {d} files, {d} nodes, all equal. Calls:", .{ @tagName(threats), files.len, total_nodes });
    for (std.enums.values(an.Method)) |m| std.debug.print(" {s} {d}", .{ @tagName(m), calls.get(m) });
    std.debug.print("\n", .{});
}

test "stage A: the real search node on recorded subtrees, lifted threat evaluators" {
    try runAll(.lifted);
}

test "stage A: the real search node on recorded subtrees, hand-written threat evaluators" {
    try runAll(.hand);
}

test "bench: node: the real node tree in Stage A (nodes per second)" {
    if (!bench.enabled) return;
    const gpa = std.heap.page_allocator;
    inline for (.{ an.Threats.lifted, an.Threats.hand }) |th| {
        var tables: ?Tables = null;
        defer if (tables) |*t| t.deinit(gpa);
        var nodes: u64 = 0;
        var best_ns: i96 = 0;
        for (files) |name| {
            const d = try vec.readVectors(gpa, "subtree", name);
            defer gpa.free(d);
            var arena_state = std.heap.ArenaAllocator.init(gpa);
            defer arena_state.deinit();
            const r = try parse(arena_state.allocator(), d);
            const slots = std.mem.readInt(u32, r.dg_in[0x5A..][0..4], .little) / 10;
            if (tables == null or tables.?.mem[0].len != slots) {
                if (tables) |*t| t.deinit(gpa);
                tables = try Tables.init(gpa, slots);
            }
            var best: i96 = std.math.maxInt(i96);
            for (0..5) |_| {
                const o = try runOne(th, gpa, name, &r, &tables.?, true);
                best = @min(best, o.ns);
            }
            nodes += r.nodes;
            best_ns += best;
        }
        const nps = @as(f64, @floatFromInt(nodes)) / (@as(f64, @floatFromInt(best_ns)) / 1e9);
        std.debug.print("bench: node ({s}): {d} nodes in {d:.1} ms, {d:.0} nodes/s (best of 5 per subtree)\n", .{ @tagName(th), nodes, @as(f64, @floatFromInt(best_ns)) / 1e6, nps });
    }
}
