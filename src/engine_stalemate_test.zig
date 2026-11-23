//! DEV-045 (class B): a stalemate in which the side to move has pseudo-legal moves and
//! every one of them leaves its king attacked. The original's pre-scoring finds no legal
//! root move and plays the stale best-move variable [A36C] without a search (0000:0FEA;
//! traced with `7k/7p/7P/8/8/8/P7/K5R1 b`: it concluded with the move 00 00 and the score
//! -20000). The engine's guard after the search (src/engine.zig, the lines after
//! `s.search(.own)` returns, added with DEV-051) reports "no move" for 00 00 and refuses any
//! other stale move that fails the legality test, so `go` answers `bestmove 0000`.
//!
//! Each position is tested with its colour mirror, under the shipped engine (every class C
//! fix on) and under the original's (every fix off): from a fresh engine, where [A36C]
//! holds 00 00, and in a continued game, where [A36C] holds the program's previous move,
//! which is no longer legal: the program's only legal move, then the opponent's move that
//! stalemates it.

const std = @import("std");
const fen = @import("fen.zig");
const pos = @import("position.zig");
const uci_engine = @import("uci_engine.zig");
const engine_mod = @import("engine.zig");

const Capture = struct {
    buf: [1 << 16]u8 = undefined,
    len: usize = 0,
    fn lineFn(ctx: ?*anyopaque, line: []const u8) void {
        const c: *Capture = @ptrCast(@alignCast(ctx.?));
        if (c.len + line.len + 1 > c.buf.len) c.len = 0;
        @memcpy(c.buf[c.len..][0..line.len], line);
        c.len += line.len;
        c.buf[c.len] = '\n';
        c.len += 1;
    }
    fn text(c: *const Capture) []const u8 {
        return c.buf[0..c.len];
    }
    fn out(c: *Capture) uci_engine.Output {
        return .{ .ctx = c, .lineFn = lineFn };
    }
};

/// Stalemates with pseudo-legal moves, each followed by its colour mirror.
const stalemates = [_][]const u8{
    // The traced position: Kh8 has g8 and g7, both attacked (Rg1, h6 pawn); h7 is blocked.
    "7k/7p/7P/8/8/8/P7/K5R1 b - - 0 1",
    "k5r1/p7/8/8/8/7p/7P/7K w - - 0 1",
    // A queen's stalemate outside the tablebases (five men): Ka8 has a7, b7 and b8, all
    // attacked by Qb6; the h3 pawn is blocked.
    "k7/8/1QK5/8/8/7p/7P/8 b - - 0 1",
    "8/7p/7P/8/8/1qk5/8/K7 w - - 0 1",
};

/// Games that end in the first two stalemates: the program's only legal move (its king
/// steps into the corner), then the opponent's rook move that stalemates it. The game is
/// continued (the second position adds the opponent's one move), so [A36C] still holds the
/// program's previous move, whose from square is now empty.
const games = [_]struct { start: []const u8, program: []const u8, opponent: []const u8 }{
    .{ .start = "6k1/7p/7P/8/8/8/P7/K4R2 b - - 0 1", .program = "g8h8", .opponent = "f1g1" },
    .{ .start = "k4r2/p7/8/8/8/7p/7P/6K1 w - - 0 1", .program = "g1h1", .opponent = "f8g8" },
};

fn search(e: anytype, cap: *Capture, f: []const u8, moves: []const []const u8, depth: u32) !?fen.UciMove {
    const d = try fen.parse(f);
    var ms: [4]fen.UciMove = undefined;
    for (moves, 0..) |m, i| ms[i] = try fen.parseMove(m);
    const eng = e.engine();
    if (eng.setPosition(&d, .setup, ms[0..moves.len])) |why| {
        std.debug.print("rejected {s}: {s}\n", .{ f, why });
        return error.Rejected;
    }
    var sig: uci_engine.Signals = .{};
    return eng.search(&.{ .depth = depth }, &sig, cap.out()).best;
}

fn checkEngine(comptime E: type, label: []const u8) !void {
    const gpa = std.testing.allocator;
    for (stalemates) |f| {
        const e = try gpa.create(E);
        defer gpa.destroy(e);
        e.* = try E.init(gpa);
        defer e.deinit();
        var cap: Capture = .{};
        const best = try search(e, &cap, f, &.{}, 4);
        std.debug.print("DEV-045 ({s}): {s}: bestmove {s}\n", .{ label, f, if (best == null) "0000" else "a move" });
        try std.testing.expect(best == null);
        try std.testing.expect(std.mem.indexOf(u8, cap.text(), "info string no move") != null);
    }
    for (games) |g| {
        const e = try gpa.create(E);
        defer gpa.destroy(e);
        e.* = try E.init(gpa);
        defer e.deinit();
        var c0: Capture = .{};
        const m0 = (try search(e, &c0, g.start, &.{}, 4)) orelse return error.NoMove;
        var mb: [5]u8 = undefined;
        try std.testing.expectEqualStrings(g.program, fen.formatMove(m0, &mb));
        var cap: Capture = .{};
        const best = try search(e, &cap, g.start, &.{ g.program, g.opponent }, 4);
        std.debug.print("DEV-045 ({s}, continued game): {s} moves {s} {s}: bestmove {s}\n", .{ label, g.start, g.program, g.opponent, if (best == null) "0000" else "a move" });
        try std.testing.expect(best == null);
        // The stale move came back and failed the legality test.
        try std.testing.expect(std.mem.indexOf(u8, cap.text(), "info string no move") != null);
        try std.testing.expect(std.mem.indexOf(u8, cap.text(), g.program) != null);
    }
}

test "DEV-045: a stalemate whose only moves walk into check answers bestmove 0000 (shipped engine)" {
    try checkEngine(engine_mod.Engine, "every fix on");
}

test "DEV-045: a stalemate whose only moves walk into check answers bestmove 0000 (Original Bugs)" {
    try checkEngine(engine_mod.EngineOf(pos.Fixes.original), "every fix off");
}
