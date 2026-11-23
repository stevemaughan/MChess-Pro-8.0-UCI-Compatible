//! The rewrite's own legality test (src/legality.zig) and the promotion spelling of a move
//! entered, through the engine (owner decision 41; docs/code review astra.md, findings 1
//! and 6):
//!
//! - DEV-066: with the side to move in check and more than 100 pseudo-legal moves,
//!   gen_all_moves' cap of 100 (DEV-063) dropped the king's moves, and the legality test,
//!   which generated with gen_all_moves at every ply, refused every legal reply: the
//!   bestmove guard answered "no move", the PV was cut after its first move, and position
//!   input refused the replies. The test now generates with the generator the original
//!   uses there (gen_evasions in check). The searches are unchanged: their node counts are
//!   those before the correction.
//! - Outside check the cap still decides what is accepted (the original's own move entry
//!   refuses a legal move past it, which the owner keeps): the 100 moves accepted at a root
//!   of 218 are the same as before.
//! - The list-identity test: at every root generation of the golden searches the legality
//!   test's list is the root's own (`EngineRoot.root_lists`, which every test build runs at every
//!   root of every search; here counted over the golden positions with the fixes off and
//!   on).
//! - DEV-F22: a promotion needs its letter and any other move takes none, on the
//!   continuation path as on the rebuild.

const std = @import("std");
const builtin = @import("builtin");
const fen = @import("fen.zig");
const pos = @import("position.zig");
const uci_engine = @import("uci_engine.zig");
const engine_mod = @import("engine.zig");
const adapt_setup = @import("adapt_setup.zig");
const build_options = @import("build_options");

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
    /// The moves of the last `info depth` line with a pv.
    fn lastPv(c: *const Capture) []const u8 {
        var it = std.mem.splitBackwardsScalar(u8, c.text(), '\n');
        while (it.next()) |l| {
            if (!std.mem.startsWith(u8, l, "info depth")) continue;
            const i = std.mem.indexOf(u8, l, " pv ") orelse continue;
            return l[i + 4 ..];
        }
        return "";
    }
};

const Engine = engine_mod.Engine;
const OriginalEngine = engine_mod.EngineOf(pos.Fixes.original);

fn newEngine(comptime E: type, gpa: std.mem.Allocator) !*E {
    const e = try gpa.create(E);
    errdefer gpa.destroy(e);
    e.* = try E.init(gpa);
    var o: uci_engine.Options = .{};
    o.use_tablebases = false;
    e.engine().applyOptions(&o);
    return e;
}

fn freeEngine(gpa: std.mem.Allocator, e: anytype) void {
    e.deinit();
    gpa.destroy(e);
}

fn parseMoves(buf: []fen.UciMove, moves: []const []const u8) ![]fen.UciMove {
    for (moves, 0..) |m, i| buf[i] = try fen.parseMove(m);
    return buf[0..moves.len];
}

/// `position fen f moves ...`: null if accepted, else the reason.
fn setPos(e: anytype, f: []const u8, moves: []const []const u8) !?[]const u8 {
    const d = try fen.parse(f);
    var buf: [16]fen.UciMove = undefined;
    return e.engine().setPosition(&d, .setup, try parseMoves(&buf, moves));
}

const Searched = struct { best: ?fen.UciMove, nodes: u64 };

fn goDepth(e: anytype, cap: *Capture, depth: u32) Searched {
    var sig: uci_engine.Signals = .{};
    const r = e.engine().search(&.{ .depth = depth }, &sig, cap.out());
    return .{ .best = r.best, .nodes = e.root.nodes };
}

fn moveText(m: ?fen.UciMove, buf: *[5]u8) []const u8 {
    return if (m) |x| fen.formatMove(x, buf) else "0000";
}

fn isIn(t: []const u8, list: []const []const u8) bool {
    for (list) |x| if (std.mem.eql(u8, x, t)) return true;
    return false;
}

const A1 = "R7/4Q3/6Q1/2Q5/8/5Q2/p2n4/k4K2 w - - 0 1";
const A1_legal = [_][]const u8{ "f1e1", "f1e2", "f1f2", "f1g1", "f1g2" };
const A2 = "K4k2/P2N4/5q2/8/2q5/6q1/4q3/r7 b - - 0 1";
const A2_legal = [_][]const u8{ "f8e7", "f8e8", "f8f7", "f8g7", "f8g8" };
const A4 = "R7/4Q3/6Q1/2Q5/8/5Q2/1k6/r4K2 w - - 0 1";
const F = "R7/4Q3/6Q1/2Q5/8/5Q2/p7/kn3K2 b - - 0 1";
const MANY = "R6R/3Q4/1Q4Q1/4Q3/2Q4Q/Q4Q2/pp1Q4/kBNN1KB1 w - - 0 1";

test "legality: DEV-066: in check with 107 pseudo-legal moves, a legal bestmove, the line beyond its first move, and the search's node counts unchanged (A1, A2)" {
    const gpa = std.testing.allocator;
    const cases = [_]struct { f: []const u8, legal: []const []const u8, nodes: [2]u64 }{
        .{ .f = A1, .legal = &A1_legal, .nodes = .{ 583, 9_049 } },
        .{ .f = A2, .legal = &A2_legal, .nodes = .{ 874, 8_682 } },
    };
    for (cases) |c| {
        for ([_]u32{ 1, 3 }, 0..) |depth, k| {
            const e = try newEngine(Engine, gpa);
            defer freeEngine(gpa, e);
            try std.testing.expect((try setPos(e, c.f, &.{})) == null);
            var cap: Capture = .{};
            const r = goDepth(e, &cap, depth);
            var mb: [5]u8 = undefined;
            const t = moveText(r.best, &mb);
            std.debug.print("legality: {s} go depth {d}: bestmove {s}, {d} nodes, pv {s}\n", .{ c.f, depth, t, r.nodes, cap.lastPv() });
            try std.testing.expect(isIn(t, c.legal));
            try std.testing.expect(std.mem.indexOf(u8, cap.text(), "no move") == null);
            try std.testing.expect(std.mem.indexOf(u8, cap.text(), "illegal move") == null);
            try std.testing.expectEqual(c.nodes[k], r.nodes);
            if (depth == 3 and c.f.ptr == A1.ptr) {
                // The line goes on past the king's move (before: cut to `f1e2`).
                try std.testing.expect(std.mem.indexOfScalar(u8, cap.lastPv(), ' ') != null);
            }
        }
    }
}

test "legality: DEV-066: the original's engine (every fix off) also answers A1 and A2 with a legal move" {
    const gpa = std.testing.allocator;
    for ([_][]const u8{ A1, A2 }, [_][]const []const u8{ &A1_legal, &A2_legal }) |f, legal| {
        const e = try newEngine(OriginalEngine, gpa);
        defer freeEngine(gpa, e);
        try std.testing.expect((try setPos(e, f, &.{})) == null);
        var cap: Capture = .{};
        const r = goDepth(e, &cap, 1);
        var mb: [5]u8 = undefined;
        try std.testing.expect(isIn(moveText(r.best, &mb), legal));
    }
}

test "legality: DEV-066: every legal reply to check is accepted as input (A1, A2, the king's moves in A4, and b1d2 f1g2 after F)" {
    const gpa = std.testing.allocator;
    const e = try newEngine(Engine, gpa);
    defer freeEngine(gpa, e);
    for (A1_legal) |m| try std.testing.expect((try setPos(e, A1, &.{m})) == null);
    for (A2_legal) |m| try std.testing.expect((try setPos(e, A2, &.{m})) == null);
    // A4: a rook's check along the first rank; before the correction the three king moves
    // were refused (a8a1 and the interpositions were in the first 100).
    for ([_][]const u8{ "f1e2", "f1f2", "f1g2", "a8a1", "c5c1", "e7e1", "f3d1", "g6b1" }) |m| {
        if (try setPos(e, A4, &.{m})) |why| {
            std.debug.print("legality: A4 moves {s} refused: {s}\n", .{ m, why });
            return error.Refused;
        }
    }
    // Two moves: the program plays both in auto-play; White's reply to the knight's check.
    const fresh = try newEngine(Engine, gpa);
    defer freeEngine(gpa, fresh);
    if (try setPos(fresh, F, &.{ "b1d2", "f1g2" })) |why| {
        std.debug.print("legality: F moves b1d2 f1g2 refused: {s}\n", .{why});
        return error.Refused;
    }
    // An illegal reply is still refused, with the reason.
    const why = (try setPos(e, A1, &.{"a8a7"})) orelse return error.Accepted;
    std.debug.print("legality: A1 moves a8a7: {s}\n", .{why});
}

test "legality: DEV-066: F at depth 3: the line goes on past b1d2 (the reply to check is no longer cut)" {
    if (builtin.mode == .debug) return; // 5.5 million nodes
    const gpa = std.testing.allocator;
    const e = try newEngine(Engine, gpa);
    defer freeEngine(gpa, e);
    try std.testing.expect((try setPos(e, F, &.{})) == null);
    var cap: Capture = .{};
    const r = goDepth(e, &cap, 3);
    var mb: [5]u8 = undefined;
    std.debug.print("legality: {s} go depth 3: bestmove {s}, {d} nodes, pv {s}\n", .{ F, moveText(r.best, &mb), r.nodes, cap.lastPv() });
    try std.testing.expectEqualStrings("b1d2", moveText(r.best, &mb));
    try std.testing.expectEqual(@as(u64, 5_466_194), r.nodes);
    try std.testing.expect(std.mem.startsWith(u8, cap.lastPv(), "b1d2 "));
}

test "legality: a root move the search hands back that is not legal is not sent in a pv either (the guard plays the legal one)" {
    // Found by the stress harness's new sessions (2026-11-22): White's lone king with one
    // legal move, b8b7, against seven queens, a rook and a knight (Black more than 100
    // pseudo-legal moves). The search gives b8c7 (the knight is defended), the guard plays
    // b8b7 (AGENTS.md 9.3 item 3). The root's choice is the search's, not changed here; the
    // pv of every line used to keep that first move.
    const gpa = std.testing.allocator;
    const e = try newEngine(Engine, gpa);
    defer freeEngine(gpa, e);
    try std.testing.expect((try setPos(e, "1K4k1/2nqq3/8/7q/8/2q1q3/2q5/r5q1 w - - 0 1", &.{})) == null);
    var cap: Capture = .{};
    const r = goDepth(e, &cap, 1);
    var mb: [5]u8 = undefined;
    std.debug.print("legality: lone king: bestmove {s}\n{s}", .{ moveText(r.best, &mb), cap.text() });
    try std.testing.expectEqualStrings("b8b7", moveText(r.best, &mb));
    try std.testing.expect(std.mem.indexOf(u8, cap.text(), " pv b8c7") == null);
}

/// The 100 moves accepted at MANY before the correction (python-chess's 218 legal moves
/// each sent as `position fen MANY moves m` to the build before it): outside check the
/// cap of gen_all_moves still decides.
const many_accepted = "a3a2 a3b2 b1a2 b6a5 b6a6 b6a7 b6b2 b6b3 b6b4 b6b5 b6b7 b6b8 b6c5 b6c6 b6c7 b6d4 b6d6 b6d8 b6e3 b6e6 b6f2 b6f6 c1a2 c4a2 c4a4 c4a6 c4b3 c4b4 c4b5 c4c2 c4c3 c4c5 c4c6 c4c7 c4c8 c4d3 c4d4 c4d5 c4e2 c4e4 c4e6 c4f4 c4f7 c4g4 c4g8 d1b2 d2b2 e5a5 e5b2 e5b5 e5b8 e5c3 e5c5 e5c7 e5d4 e5d5 e5d6 e5e1 e5e2 e5e3 e5e4 e5e6 e5e7 e5e8 e5f4 e5f5 e5f6 e5g3 e5g5 e5g7 e5h2 e5h5 f3b3 f3c3 f3d3 f3e3 f3f2 f3f4 f3f5 f3f6 f3f7 f3f8 f3g3 h4d4 h4d8 h4e1 h4e4 h4e7 h4f2 h4f4 h4f6 h4g3 h4g4 h4g5 h4h1 h4h2 h4h3 h4h5 h4h6 h4h7";

test "legality: outside check the 100 moves accepted at a root of 218 are those accepted before the correction" {
    const gpa = std.testing.allocator;
    const e = try newEngine(Engine, gpa);
    defer freeEngine(gpa, e);
    try std.testing.expect((try setPos(e, MANY, &.{})) == null);
    // Every from-to pair, on the state at main 0526 (`findLegal`'s), in square order.
    var got: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&got);
    var n: usize = 0;
    for (0..8) |ff| for (0..8) |fr| for (0..8) |tf| for (0..8) |tr| {
        const from: u8 = @intCast(21 + 10 * fr + ff);
        const to: u8 = @intCast(21 + 10 * tr + tf);
        if (from == to) continue;
        const m: fen.UciMove = .{ .from = from, .to = to };
        switch (e.findLegal(m, .white)) {
            .ok => {
                var mb: [5]u8 = undefined;
                try w.print("{s}{s}", .{ if (n == 0) "" else " ", fen.formatMove(m, &mb) });
                n += 1;
            },
            .no => {},
        }
    };
    try std.testing.expectEqual(@as(usize, 100), n);
    try std.testing.expectEqualStrings(many_accepted, w.buffered());
}

// ---- the list-identity test over the golden positions -------------------------------

const Search = struct { fen: []const u8, depth: u32, nodes: u64 };

/// The whole-search golden files whose searches are played from their positions here (the
/// files of other settings, book, hash sizes, tablebase sets, are left to their own tests;
/// deep-long.jsonl only with MCHESS_LONG_TESTS).
const golden_files = [_][]const u8{ "smoke", "corpus1", "corpus2", "normal1", "normal2", "castling", "longgame", "deep", "manymoves", "unverified", "unverified2" };

fn loadSearches(arena: std.mem.Allocator, files: []const []const u8) ![]Search {
    var list: std.ArrayList(Search) = .empty;
    for (files) |name| {
        const path = try std.fmt.allocPrint(arena, "{s}/{s}.jsonl", .{ build_options.golden_dir, name });
        const text = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, arena, .limited(1 << 26));
        var depth: u32 = 0;
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            const v = try std.json.parseFromSliceLeaky(std.json.Value, arena, line, .{});
            const o = v.object;
            if (o.get("search") == null) {
                if (o.get("depth")) |d| depth = @intCast(d.integer);
                continue;
            }
            // A record with no position of its own (the board or the side is null) is left out.
            const board = o.get("board") orelse continue;
            const side = o.get("side") orelse continue;
            if (board != .string or side != .string) continue;
            const f = try std.fmt.allocPrint(arena, "{s} {s}", .{ board.string, side.string });
            const nodes: u64 = if (o.get("nodes")) |x| @intCast(x.integer) else 0;
            try list.append(arena, .{ .fen = f, .depth = depth, .nodes = nodes });
        }
    }
    return list.items;
}

/// `max_nodes`: a search the golden file gives more nodes is not run (null: every one).
fn listIdentity(comptime E: type, searches: []const Search, max_nodes: ?u64, label: []const u8) !void {
    const gpa = std.heap.page_allocator;
    const e = try newEngine(E, gpa);
    defer freeEngine(gpa, e);
    var run: u32 = 0;
    for (searches) |s| {
        if (max_nodes) |mx| if (s.nodes > mx) continue;
        var d = try fen.parse(s.fen);
        d.castling = adapt_setup.rightsFromBoard(&d.board);
        if (e.engine().setPosition(&d, .setup, &.{}) != null) continue;
        var cap: Capture = .{};
        _ = goDepth(e, &cap, @max(s.depth, 1));
        if (e.root.failure) |f| {
            std.debug.print("legality: {s}: {s}: {s}\n", .{ label, s.fen, f });
            return error.Failure;
        }
        run += 1;
    }
    const c = e.root.root_lists;
    std.debug.print("legality: list identity ({s}): {d} golden positions searched, {d} root lists compared ({d} in check), {d} differ\n", .{ label, run, c.checked, c.in_check, c.mismatches });
    try std.testing.expectEqual(@as(u32, 0), c.mismatches);
    try std.testing.expect(c.checked >= run);
    try std.testing.expect(c.in_check > 0);
}

test "legality: list identity: at every root of the golden positions the legality test's list is the root's own, with the fixes off and on" {
    var arena_state: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    // As the other long tests: by default the searches up to 500,000 nodes (Debug: 15,000);
    // with MCHESS_LONG_TESTS every one, and deep-long.jsonl's.
    const long = try std.testing.environ.containsUnempty(arena, "MCHESS_LONG_TESTS");
    const max_nodes: ?u64 = if (long) null else if (builtin.mode == .debug) 15_000 else 500_000;
    const searches = try loadSearches(arena, if (long) &(golden_files ++ [_][]const u8{"deep-long"}) else &golden_files);
    try listIdentity(OriginalEngine, searches, max_nodes, "every fix off");
    try listIdentity(Engine, searches, max_nodes, "every fix on");
}

// ---- DEV-F22: the promotion spelling --------------------------------------------------

const P = "7k/6pp/8/8/8/8/p5PP/5K2 w - - 0 1";
const PR = "7k/6pp/8/8/8/8/r5PP/5K2 w - - 0 1";
const PW = "7k/P5pp/8/8/8/8/6PP/7K b - - 0 1";

/// A fresh engine that has searched `f` and played its move (at depth 1): the held game
/// waits for the opponent's move. Returns the move.
fn heldGame(e: anytype, f: []const u8, buf: *[5]u8) ![]const u8 {
    try std.testing.expect((try setPos(e, f, &.{})) == null);
    var cap: Capture = .{};
    const r = goDepth(e, &cap, 1);
    return moveText(r.best, buf);
}

test "legality: DEV-F22: a promotion without its letter is refused when the game is continued, as when it is rebuilt" {
    const gpa = std.testing.allocator;
    const e = try newEngine(Engine, gpa);
    defer freeEngine(gpa, e);
    var mb: [5]u8 = undefined;
    const w = try heldGame(e, P, &mb);
    try std.testing.expectEqualStrings("f1e2", w);
    const continued = e.continued;
    const why = (try setPos(e, P, &.{ w, "a2a1" })) orelse return error.Accepted;
    std.debug.print("legality: continued moves f1e2 a2a1: {s}\n", .{why});
    try std.testing.expect(std.mem.indexOf(u8, why, "a promotion needs n, b, r or q") != null);
    try std.testing.expectEqual(continued, e.continued);
    var cap: Capture = .{};
    try std.testing.expect(goDepth(e, &cap, 1).best == null);
    // The same after ucinewgame.
    e.engine().newGame();
    const why2 = (try setPos(e, P, &.{ "f1e2", "a2a1" })) orelse return error.Accepted;
    try std.testing.expectEqualStrings(why, why2);
    // Spelt with its letter: accepted and searched.
    try std.testing.expect((try setPos(e, P, &.{ "f1e2", "a2a1q" })) == null);
    var cap2: Capture = .{};
    var mb2: [5]u8 = undefined;
    try std.testing.expectEqualStrings("e2f2", moveText(goDepth(e, &cap2, 1).best, &mb2));
}

test "legality: DEV-F22: a correctly spelt promotion is continued, not rebuilt, and is the piece its letter names" {
    const gpa = std.testing.allocator;
    for ([_]struct { f: []const u8, m: []const u8, sq: u8, piece: u8 }{
        .{ .f = P, .m = "a2a1q", .sq = 21, .piece = pos.black_queen },
        .{ .f = P, .m = "a2a1n", .sq = 21, .piece = pos.black_knight },
        .{ .f = PW, .m = "a7a8n", .sq = 91, .piece = pos.white_knight },
        .{ .f = PW, .m = "a7a8r", .sq = 91, .piece = pos.white_rook },
    }) |c| {
        const e = try newEngine(Engine, gpa);
        defer freeEngine(gpa, e);
        var mb: [5]u8 = undefined;
        const w = try heldGame(e, c.f, &mb);
        var wb: [5]u8 = undefined;
        @memcpy(wb[0..w.len], w);
        const first = wb[0..w.len];
        const continued = e.continued;
        const rebuilt = e.rebuilt;
        try std.testing.expect((try setPos(e, c.f, &.{ first, c.m })) == null);
        try std.testing.expectEqual(continued + 1, e.continued);
        try std.testing.expectEqual(rebuilt, e.rebuilt);
        try std.testing.expectEqual(c.piece, e.root.node.dom.p.board[c.sq]);
        var cap: Capture = .{};
        const a = goDepth(e, &cap, 3);
        // The same position rebuilt gives the same move.
        const r = try newEngine(Engine, gpa);
        defer freeEngine(gpa, r);
        try std.testing.expect((try setPos(r, c.f, &.{ first, c.m })) == null);
        try std.testing.expectEqual(c.piece, r.root.node.dom.p.board[c.sq]);
        var cap2: Capture = .{};
        const b = goDepth(r, &cap2, 3);
        var x: [5]u8 = undefined;
        var y: [5]u8 = undefined;
        std.debug.print("legality: {s} moves {s} {s}: continued {s} ({d} nodes), rebuilt {s} ({d} nodes)\n", .{ c.f, first, c.m, moveText(a.best, &x), a.nodes, moveText(b.best, &y), b.nodes });
        try std.testing.expectEqualStrings(moveText(a.best, &x), moveText(b.best, &y));
    }
}

test "legality: DEV-F22: a piece letter on a move that is not a promotion is refused when the game is continued, and White's promotion without a letter too" {
    const gpa = std.testing.allocator;
    {
        const e = try newEngine(Engine, gpa);
        defer freeEngine(gpa, e);
        var mb: [5]u8 = undefined;
        const w = try heldGame(e, PR, &mb);
        var wb: [5]u8 = undefined;
        @memcpy(wb[0..w.len], w);
        const continued = e.continued;
        const why = (try setPos(e, PR, &.{ wb[0..w.len], "a2a1q" })) orelse return error.Accepted;
        std.debug.print("legality: rook: continued moves {s} a2a1q: {s}\n", .{ wb[0..w.len], why });
        try std.testing.expect(std.mem.indexOf(u8, why, "a piece letter on a move that is not a promotion") != null);
        try std.testing.expectEqual(continued, e.continued);
        // Without the letter it is an ordinary rook move.
        try std.testing.expect((try setPos(e, PR, &.{ wb[0..w.len], "a2a1" })) == null);
    }
    {
        const e = try newEngine(Engine, gpa);
        defer freeEngine(gpa, e);
        var mb: [5]u8 = undefined;
        const b = try heldGame(e, PW, &mb);
        var bb: [5]u8 = undefined;
        @memcpy(bb[0..b.len], b);
        const why = (try setPos(e, PW, &.{ bb[0..b.len], "a7a8" })) orelse return error.Accepted;
        std.debug.print("legality: white pawn: continued moves {s} a7a8: {s}\n", .{ bb[0..b.len], why });
        try std.testing.expect(std.mem.indexOf(u8, why, "a promotion needs n, b, r or q") != null);
    }
}
