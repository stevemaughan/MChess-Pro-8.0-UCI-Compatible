//! Games longer than the original's (owner decision 26, DEV-F19) through the `Engine`
//! interface (src/engine.zig): the root's turn routines slide the game record from game
//! ply 300 (`EngineRoot.slideIfDue`, src/gameslide.zig).
//!
//! - Two engines play each other from an ending with bishops of opposite colours (a FEN
//!   through Setup mode) at depth 2, as a GUI drives them (`position fen ... moves ...`
//!   growing by one ply for the engine to move): every position after each engine's first
//!   is a continuation of the game it holds, never a rebuild, across several slides, to
//!   1,000 plies. The same two engines with the slide switched off play the same first
//!   401 plies: every search before the original's end is the same with and without the
//!   slides, though from ply 300 on one game is slid and the other not, across the
//!   repetitions and the fifty-move count that ending is full of.
//! - The same game rebuilt from scratch at several plies by a third engine (the rebuild
//!   plays every move in auto-play, sliding as it goes): accepted and searched; up to the
//!   original's end the same search with the slides on and off; at every ply tried, the
//!   same move and nodes as the continued game.
//! - `position startpos moves ...` of 500, 1,000 and 4,000 plies (knights out and back):
//!   accepted, rebuilt and searched, with the cost of the rebuild.

const std = @import("std");
const builtin = @import("builtin");
const fen = @import("fen.zig");
const pos = @import("position.zig");
const uci_engine = @import("uci_engine.zig");
const engine_mod = @import("engine.zig");
const gs = @import("gameslide.zig");

fn nowMs() u64 {
    const ns: i96 = std.Io.Clock.awake.now(std.testing.io).nanoseconds;
    return @intCast(@divTrunc(ns, std.time.ns_per_ms));
}

const E = engine_mod.Engine;

const Null = struct {
    fn lineFn(ctx: ?*anyopaque, line: []const u8) void {
        _ = ctx;
        _ = line;
    }
    const out: uci_engine.Output = .{ .ctx = null, .lineFn = lineFn };
};

const ending = "8/5k2/4bp2/8/3P4/2B5/5K2/8 w - - 0 1";

/// A word of DGROUP at its home (`EngineRoot.Home`): the engine's commands leave the image as it
/// was (Stage B step 8, stage 6).
fn word(root: anytype, a: u16) u16 {
    return @import("dgroup.zig").memWord(root.home(), a);
}

const Game = struct {
    moves: []fen.UciMove,
    nodes: []u64,
    n: usize = 0,
    continued: u32 = 0,
    rebuilt: u32 = 0,
    dropped: u64 = 0,
    highest_ply: u16 = 0,

    fn deinit(g: *Game, gpa: std.mem.Allocator) void {
        gpa.free(g.moves);
        gpa.free(g.nodes);
    }
};

/// Two engines play `plies` plies from `ending` at depth 2, each told the whole game so far.
fn playPair(gpa: std.mem.Allocator, plies: usize, slides: bool) !Game {
    var g: Game = .{ .moves = try gpa.alloc(fen.UciMove, plies), .nodes = try gpa.alloc(u64, plies) };
    errdefer g.deinit(gpa);
    var engines: [2]E = .{ try E.init(gpa), undefined };
    defer engines[0].deinit();
    engines[1] = try E.init(gpa);
    defer engines[1].deinit();
    for (&engines) |*e| {
        e.reporting = false;
        e.root.slide_when_due = slides;
    }
    const start = try fen.parse(ending);
    var sig: uci_engine.Signals = .{};
    while (g.n < plies) {
        const e = &engines[g.n % 2];
        const eng = e.engine();
        if (eng.setPosition(&start, .setup, g.moves[0..g.n])) |why| {
            std.debug.print("engine long game: ply {d}: position rejected: {s}\n", .{ g.n, why });
            return error.Rejected;
        }
        const r = eng.search(&.{ .depth = 2 }, &sig, Null.out);
        const best = r.best orelse {
            std.debug.print("engine long game: ply {d}: no move\n", .{g.n});
            return error.NoMove;
        };
        g.moves[g.n] = best;
        g.nodes[g.n] = e.root.nodes;
        g.n += 1;
        g.highest_ply = @max(g.highest_ply, word(e.root, gs.game_ply_addr));
    }
    for (&engines) |*e| {
        g.continued += e.continued;
        g.rebuilt += e.rebuilt;
        g.dropped += e.root.dropped_plies;
    }
    return g;
}

fn longTests(gpa: std.mem.Allocator) !bool {
    if (builtin.mode != .debug) return true;
    return std.testing.environ.containsUnempty(gpa, "MCHESS_LONG_TESTS");
}

test "engine long game: two engines continue a game move by move to 1,000 plies across slides; the first 401 plies are those of the game without slides; rebuilds at several plies" {
    const gpa = std.testing.allocator;
    if (!try longTests(gpa)) return;
    const plies = 1000;
    const t0 = nowMs();
    var g = try playPair(gpa, plies, true);
    defer g.deinit(gpa);
    const ms_on = nowMs() - t0;
    var total: u64 = 0;
    for (g.nodes) |x| total += x;
    std.debug.print("engine long game: {d} plies at depth 2 ({d} nodes, {d} ms), {d} positions continued, {d} rebuilt, {d} plies dropped by slides, the highest game ply held {d}\n", .{ g.n, total, ms_on, g.continued, g.rebuilt, g.dropped, g.highest_ply });
    // Each engine rebuilt once (its first position) and continued every other.
    try std.testing.expectEqual(@as(u32, 2), g.rebuilt);
    try std.testing.expectEqual(@as(u32, plies - 2), g.continued);
    try std.testing.expect(g.dropped >= plies - 400);
    try std.testing.expect(g.highest_ply < 402);

    var off = try playPair(gpa, 401, false);
    defer off.deinit(gpa);
    try std.testing.expectEqual(@as(u64, 0), off.dropped);
    for (0..401) |i| {
        if (!g.moves[i].eql(off.moves[i]) or g.nodes[i] != off.nodes[i]) {
            var a: [5]u8 = undefined;
            var b: [5]u8 = undefined;
            std.debug.print("engine long game: ply {d}: {s} {d} nodes with slides, {s} {d} without\n", .{ i, fen.formatMove(g.moves[i], &a), g.nodes[i], fen.formatMove(off.moves[i], &b), off.nodes[i] });
            return error.SlidesChangedTheGame;
        }
    }
    std.debug.print("engine long game: plies 0..400 equal with and without slides\n", .{});

    // Rebuilt from scratch by a third engine (auto-play replay, sliding as it goes).
    var e = try E.init(gpa);
    defer e.deinit();
    e.reporting = false;
    const eng = e.engine();
    const start = try fen.parse(ending);
    var sig: uci_engine.Signals = .{};
    for ([_]usize{ 350, 401, 500, 999 }) |k| {
        var nodes: [2]u64 = undefined;
        var best: [2]fen.UciMove = undefined;
        var dropped: u64 = 0;
        for ([_]bool{ true, false }, 0..) |slides, j| {
            if (!slides and k > 401) break;
            e.root.slide_when_due = slides;
            if (eng.setPosition(&start, .setup, g.moves[0..k])) |why| {
                std.debug.print("engine long game: rebuild at ply {d}: rejected: {s}\n", .{ k, why });
                return error.Rejected;
            }
            const r = eng.search(&.{ .depth = 2 }, &sig, Null.out);
            best[j] = r.best orelse return error.NoMove;
            nodes[j] = e.root.nodes;
            if (slides) dropped = e.root.dropped_plies;
        }
        var a: [5]u8 = undefined;
        var c: [5]u8 = undefined;
        std.debug.print("engine long game: rebuilt at ply {d}: {s}, {d} nodes, {d} plies dropped (the continued game: {s}, {d} nodes)\n", .{ k, fen.formatMove(best[0], &a), nodes[0], dropped, fen.formatMove(g.moves[k], &c), g.nodes[k] });
        // The rebuild (auto-play) searches as the continued game (normal play) did here.
        try std.testing.expect(best[0].eql(g.moves[k]));
        try std.testing.expectEqual(g.nodes[k], nodes[0]);
        if (k <= 401) {
            try std.testing.expect(best[0].eql(best[1]));
            try std.testing.expectEqual(nodes[1], nodes[0]);
        }
    }
}

test "engine long game: position startpos moves ... of 500, 1,000 and 4,000 plies accepted, rebuilt and searched" {
    const gpa = std.testing.allocator;
    if (!try longTests(gpa)) return;
    var e = try E.init(gpa);
    defer e.deinit();
    e.reporting = false;
    const eng = e.engine();
    const start = try fen.parse(fen.startpos);
    const shuffle = [4]fen.UciMove{
        try fen.parseMove("g1f3"), try fen.parseMove("g8f6"),
        try fen.parseMove("f3g1"), try fen.parseMove("f6g8"),
    };
    var moves: [4000]fen.UciMove = undefined;
    for (&moves, 0..) |*m, i| m.* = shuffle[i % 4];
    var sig: uci_engine.Signals = .{};
    for ([_]usize{ 500, 1000, 4000 }) |k| {
        const t = nowMs();
        if (eng.setPosition(&start, .new_game, moves[0..k])) |why| {
            std.debug.print("engine long game: startpos + {d} plies: rejected: {s}\n", .{ k, why });
            return error.Rejected;
        }
        const ms_rebuild = nowMs() - t;
        const r = eng.search(&.{ .depth = 2 }, &sig, Null.out);
        const best = r.best orelse return error.NoMove;
        var mb: [5]u8 = undefined;
        std.debug.print("engine long game: startpos + {d} plies: rebuilt in {d} ms ({d} plies dropped, game ply {d}), bestmove {s}, {d} nodes\n", .{ k, ms_rebuild, e.root.dropped_plies, word(e.root, gs.game_ply_addr), fen.formatMove(best, &mb), e.root.nodes });
        try std.testing.expectEqual(@as(u64, k), e.root.dropped_plies + word(e.root, gs.game_ply_addr) - 1);
    }
}
