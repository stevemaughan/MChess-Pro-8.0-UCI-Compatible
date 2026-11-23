//! No heap allocation in a search (AGENTS.md section 12, "No heap allocation in the
//! search path"; docs/ROBUSTNESS.md, 2026-11-22). The engine is given an allocator that
//! counts (`std.testing.FailingAllocator`, which fails nothing here), and its probe points
//! "before the search" and "after the search" (src/engine.zig `search`, around
//! `EngineRoot.search`) read the counts: between them nothing may be allocated, resized or
//! freed. The searches are of about a million nodes and more, one after another on the
//! same engine, each bigger than the one before, so that a list kept between searches
//! would have to grow again.
//!
//! Until 2026-11-22 the root appended every node entry and make below a root move to a
//! list on the heap and read it when the root move returned (engine_root `node_events`):
//! this test would have counted dozens of allocations in the first search (the list
//! doubling to the largest root move's subtree, tens of MB), more in each bigger one, and
//! one more for the loop's view (`iterate` took `rs.RootState` from the allocator).

const std = @import("std");
const builtin = @import("builtin");
const fen = @import("fen.zig");
const pos = @import("position.zig");
const uci_engine = @import("uci_engine.zig");
const engine_mod = @import("engine.zig");

/// The shipped engine (every class C fix on), whose node counts through UCI are known
/// (startpos depth 8: 942,290; the Najdorf position depth 7: 1,807,660).
const E = engine_mod.EngineOf(pos.Fixes.corrected);

const Counts = struct { allocations: usize, deallocations: usize, resizes: usize, allocated: usize, freed: usize };

const Watch = struct {
    fa: *std.testing.FailingAllocator,
    before: ?Counts = null,
    after: ?Counts = null,

    fn now(w: *const Watch) Counts {
        return .{
            .allocations = w.fa.allocations,
            .deallocations = w.fa.deallocations,
            .resizes = w.fa.resize_index,
            .allocated = w.fa.allocated_bytes,
            .freed = w.fa.freed_bytes,
        };
    }

    fn call(ctx: *anyopaque, label: []const u8) void {
        const w: *Watch = @ptrCast(@alignCast(ctx));
        if (std.mem.eql(u8, label, "before the search")) w.before = w.now();
        if (std.mem.eql(u8, label, "after the search")) w.after = w.now();
    }
};

/// Counts the lines and keeps none (reporting stays on: the reporter's work is in the
/// search too).
const Lines = struct {
    n: usize = 0,
    fn lineFn(ctx: ?*anyopaque, _: []const u8) void {
        const l: *Lines = @ptrCast(@alignCast(ctx.?));
        l.n += 1;
    }
};

const Case = struct {
    name: []const u8,
    fen: ?[]const u8 = null,
    moves: []const []const u8 = &.{},
    limits: uci_engine.Limits,
    /// The node entries the search must count (null: not checked, a stop decides).
    nodes: ?u64 = null,
};

test "engine: a search allocates nothing: no allocation, resize or free between the search's start and its end, over searches of 1 to 3 million nodes" {
    const najdorf = "rnbqkb1r/1p2pppp/p2p1n2/8/3NP3/2N5/PPP2PPP/R1BQKB1R w KQkq - 0 6";
    const long_cases = [_]Case{
        .{ .name = "startpos go depth 8", .limits = .{ .depth = 8 }, .nodes = 942_290 },
        .{ .name = "Najdorf go depth 7", .fen = najdorf, .limits = .{ .depth = 7 }, .nodes = 1_807_660 },
        .{ .name = "startpos moves e2e4 go nodes 3000000", .moves = &.{"e2e4"}, .limits = .{ .nodes = 3_000_000 } },
    };
    // Debug runs about fifty times slower: one search of 105,221 nodes there.
    const short_cases = [_]Case{
        .{ .name = "startpos go depth 6", .limits = .{ .depth = 6 } },
    };
    const cases: []const Case = if (builtin.mode == .debug) &short_cases else &long_cases;

    var fa: std.testing.FailingAllocator = .init(std.testing.allocator, .{});
    const gpa = fa.allocator();
    const e = try std.testing.allocator.create(E);
    defer std.testing.allocator.destroy(e);
    e.* = try E.init(gpa);
    defer e.deinit();
    var watch: Watch = .{ .fa = &fa };
    e.probe = .{ .ctx = &watch, .call = Watch.call };
    const eng = e.engine();
    for (cases) |c| {
        const start = try fen.parse(c.fen orelse fen.startpos);
        var moves: [4]fen.UciMove = undefined;
        for (c.moves, 0..) |m, i| moves[i] = try fen.parseMove(m);
        if (eng.setPosition(&start, if (c.fen == null) .new_game else .setup, moves[0..c.moves.len])) |why| {
            std.debug.print("{s}: rejected: {s}\n", .{ c.name, why });
            return error.Rejected;
        }
        watch.before = null;
        watch.after = null;
        var lines: Lines = .{};
        var sig: uci_engine.Signals = .{};
        const r = eng.search(&c.limits, &sig, .{ .ctx = &lines, .lineFn = Lines.lineFn });
        _ = r.best orelse return error.NoMove;
        const b = watch.before orelse return error.NoProbe;
        const a = watch.after orelse return error.NoProbe;
        std.debug.print("engine alloc: {s}: {d} nodes, {d} info lines; in the search {d} allocations ({d} bytes), {d} resizes, {d} frees ({d} bytes)\n", .{
            c.name,                            e.root.nodes,              lines.n,
            a.allocations - b.allocations,     a.allocated - b.allocated, a.resizes - b.resizes,
            a.deallocations - b.deallocations, a.freed - b.freed,
        });
        if (c.nodes) |n| try std.testing.expectEqual(n, e.root.nodes);
        try std.testing.expect(e.root.nodes > 40_000);
        try std.testing.expectEqual(b, a);
    }
}
