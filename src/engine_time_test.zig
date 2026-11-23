//! UCI time management joined to the engine (docs/UCI_TIME.md; src/engine.zig,
//! src/uci_report.zig, src/engine_root.zig), with the tests' scripted clock: the elapsed
//! time is a function of the node count (`Engine.scripted_us_per_node`), so a timed search
//! is reproducible (AGENTS.md section 8.3).
//!
//! - A timed search the time control ends after iteration k is the Fixed depth search of
//!   depth k: the same move, node entries, makes, line hash and image after the move.
//! - A search stopped inside an iteration plays the best move so far, a legal move, and
//!   its last `info` line's first PV move is the `bestmove`; it stops at the first
//!   1024-node test at or after `panic`.
//! - The same scripted clock twice gives the same output, line for line.
//! - `go nodes N` stops at the node entry N (plus the nodes the unwinding enters): the same
//!   N twice gives the same move and count.
//! - What the time control is handed: one legal move; the expected move and the previous
//!   target square (a recapture); root re-searches; root trouble.
//! - `go mate N`, `go ponder` and `movetime`.

const std = @import("std");
const si = @import("state_image.zig");
const fen = @import("fen.zig");
const pos = @import("position.zig");
const uci_engine = @import("uci_engine.zig");
const engine_mod = @import("engine.zig");
const timecontrol = @import("timecontrol.zig");

const E = engine_mod.Engine;

const Capture = struct {
    buf: [1 << 17]u8 = undefined,
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
    /// The first PV move of the last line with a pv.
    fn lastPvMove(c: *const Capture) ?[]const u8 {
        var it = std.mem.splitBackwardsScalar(u8, c.text(), '\n');
        while (it.next()) |l| {
            if (!std.mem.startsWith(u8, l, "info")) continue;
            const i = std.mem.indexOf(u8, l, " pv ") orelse continue;
            var w = std.mem.tokenizeScalar(u8, l[i + 4 ..], ' ');
            return w.next();
        }
        return null;
    }
};

fn newEngine(gpa: std.mem.Allocator) !*E {
    const e = try gpa.create(E);
    errdefer gpa.destroy(e);
    e.* = try E.init(gpa);
    e.scripted_us_per_node = 20; // 50,000 nodes a second, about the engine's speed
    return e;
}

fn freeEngine(gpa: std.mem.Allocator, e: *E) void {
    e.deinit();
    gpa.destroy(e);
}

const Pos = struct {
    fen: ?[]const u8 = null,
    moves: []const []const u8 = &.{},
};

fn setPos(e: *E, p: Pos, extra: []const fen.UciMove) !void {
    const d = try fen.parse(p.fen orelse fen.startpos);
    var ms: [64]fen.UciMove = undefined;
    for (p.moves, 0..) |m, i| ms[i] = try fen.parseMove(m);
    @memcpy(ms[p.moves.len..][0..extra.len], extra);
    if (e.engine().setPosition(&d, if (p.fen == null) .new_game else .setup, ms[0 .. p.moves.len + extra.len])) |why| {
        std.debug.print("rejected: {s}\n", .{why});
        return error.Rejected;
    }
}

const Run = struct {
    best: ?fen.UciMove,
    nodes: u64,
    makes: u64,
    line: [64]u8,
    log: E.Report.TimeLog,
};

fn go(e: *E, p: Pos, limits: uci_engine.Limits, cap: *Capture, sig: *uci_engine.Signals) !Run {
    try setPos(e, p, &.{});
    const r = e.engine().search(&limits, sig, cap.out());
    return .{ .best = r.best, .nodes = e.root.nodes, .makes = e.root.makes, .line = e.root.lineHex(), .log = e.time_log };
}

fn legalAfter(e: *E, p: Pos, m: fen.UciMove) bool {
    setPos(e, p, &.{m}) catch return false;
    return true;
}

fn mtext(m: ?fen.UciMove, b: *[5]u8) []const u8 {
    return if (m) |x| fen.formatMove(x, b) else "none";
}

const positions = [_]Pos{
    .{},
    .{ .moves = &.{ "e2e4", "e7e5", "g1f3", "b8c6", "f1b5", "a7a6" } },
    .{ .fen = "r1bq1rk1/ppp2ppp/2n5/3np3/1b6/2NP1NP1/PP2PPBP/R1BQ1RK1 w - - 0 1" },
    .{ .moves = &.{ "d2d4", "g8f6", "c2c4", "e7e6", "b1c3", "f8b4" } },
};

test "time: a timed search the time control ends after iteration k is go depth k (move, nodes, makes, line hash, image)" {
    const gpa = std.testing.allocator;
    const e = try newEngine(gpa);
    defer freeEngine(gpa, e);
    const img_a = try gpa.create([0x10000]u8);
    defer gpa.destroy(img_a);
    var equal: u32 = 0;
    var after: u32 = 0;
    for (positions) |p| {
        for ([_]u64{ 4000, 15000, 60000 }) |clock| {
            var cap: Capture = .{};
            var sig: uci_engine.Signals = .{};
            const t = try go(e, p, .{ .wtime = clock, .btime = clock }, &cap, &sig);

            si.toImage(e.root); // the members stored (Stage B step 8, stage 6)
            @memcpy(img_a, e.root.test_img[0..0x10000]);
            var b1: [5]u8 = undefined;
            std.debug.print("time: clock {d}: target {d} panic {d}: bestmove {s}, {d} nodes, stopped {s} {d}\n", .{ clock, e.tc.target, e.tc.panic, mtext(t.best, &b1), t.nodes, if (t.log.stopped_in_search) "inside iteration" else "after iteration", t.log.stopped_after orelse -1 });
            try std.testing.expect(t.best != null);
            try std.testing.expect(legalAfter(e, p, t.best.?));

            // The last line's first PV move is the bestmove.
            var b2: [5]u8 = undefined;
            try std.testing.expectEqualStrings(mtext(t.best, &b2), cap.lastPvMove() orelse "");
            const k = t.log.stopped_after orelse continue;
            if (t.log.stopped_in_search) continue;
            after += 1;
            var cap2: Capture = .{};
            var sig2: uci_engine.Signals = .{};
            const d = try go(e, p, .{ .depth = @intCast(k) }, &cap2, &sig2);

            const same = t.best.?.eql(d.best.?) and t.nodes == d.nodes and t.makes == d.makes and std.mem.eql(u8, &t.line, &d.line);
            // The image after the move: equal but for DG:1E02, the depth asked for.
            si.toImage(e.root);
            var diff: u32 = 0;
            for (img_a, e.root.test_img[0..0x10000], 0..) |x, y, i| {
                if (x != y and i != 0x1E02 and i != 0x1E03) {
                    if (diff < 8) std.debug.print("time:   DG:{X:0>4}: timed {X:0>2}, go depth {X:0>2}\n", .{ i, x, y });
                    diff += 1;
                }
            }
            std.debug.print("time:   go depth {d}: {s}, {d} nodes, {d} makes; equal {}, image bytes differing {d}\n", .{ k, mtext(d.best, &b1), d.nodes, d.makes, same, diff });

            try std.testing.expect(same);
            try std.testing.expectEqual(@as(u32, 0), diff);
            equal += 1;
        }
    }
    std.debug.print("time: {d} searches ended after an iteration, each equal to go depth k\n", .{equal});
    try std.testing.expect(after >= 3);
}

test "time: a search stopped inside an iteration stops at the first 1024-node test past panic and plays a legal best move" {
    const gpa = std.testing.allocator;
    const e = try newEngine(gpa);
    defer freeEngine(gpa, e);
    var inside: u32 = 0;
    for (positions) |p| {
        for ([_]u64{ 300, 1000, 2500, 15000 }) |clock| {
            var cap: Capture = .{};
            var sig: uci_engine.Signals = .{};
            const t = try go(e, p, .{ .wtime = clock, .btime = clock, .winc = 10, .binc = 10 }, &cap, &sig);
            var b1: [5]u8 = undefined;
            std.debug.print("time: clock {d}+10: panic {d}: bestmove {s}, {d} nodes, stopped {s} at {d} ms\n", .{ clock, e.tc.panic, mtext(t.best, &b1), t.nodes, if (t.log.stopped_in_search) "inside" else "after", t.log.stop_elapsed });
            try std.testing.expect(t.best != null);
            try std.testing.expect(legalAfter(e, p, t.best.?));
            var b2: [5]u8 = undefined;
            try std.testing.expectEqualStrings(mtext(t.best, &b2), cap.lastPvMove() orelse "");
            if (!t.log.stopped_in_search) continue;
            inside += 1;
            // At a test (every 1024 node entries, 20.48 ms here) at or past panic, or past
            // max while the root was in trouble at that test; and never later than the
            // first test past max.
            const limit = if (e.tc.root_trouble) e.tc.max else e.tc.panic;
            try std.testing.expect(t.log.stop_elapsed >= limit);
            try std.testing.expect(t.log.stop_elapsed < @max(e.tc.max, 0) + 21);
            if (!t.log.trouble_seen) try std.testing.expect(t.log.stop_elapsed < @max(e.tc.panic, 0) + 21);
        }
    }
    try std.testing.expect(inside >= 3);
}

test "time: the same scripted clock twice gives the same search, line for line" {
    const gpa = std.testing.allocator;
    const e = try newEngine(gpa);
    defer freeEngine(gpa, e);
    for ([_]u64{ 1000, 20000 }) |clock| {
        var c1: Capture = .{};
        var c2: Capture = .{};
        var s1: uci_engine.Signals = .{};
        var s2: uci_engine.Signals = .{};
        const p = positions[1];
        const a = try go(e, p, .{ .wtime = clock, .btime = clock, .winc = 100, .binc = 100 }, &c1, &s1);
        // Another search between them moves the engine's own 1024 phase.
        var c3: Capture = .{};
        var s3: uci_engine.Signals = .{};
        _ = try go(e, positions[2], .{ .depth = 3 }, &c3, &s3);
        const b = try go(e, p, .{ .wtime = clock, .btime = clock, .winc = 100, .binc = 100 }, &c2, &s2);
        try std.testing.expect(a.best.?.eql(b.best.?));
        try std.testing.expectEqual(a.nodes, b.nodes);
        try std.testing.expectEqual(a.makes, b.makes);
        try std.testing.expectEqualSlices(u8, &a.line, &b.line);
        try std.testing.expectEqualStrings(c1.text(), c2.text());
        std.debug.print("time: clock {d} twice: {d} nodes, {d} output bytes, identical\n", .{ clock, a.nodes, c1.len });
    }
}

test "time: go nodes N stops at node entry N, the same N giving the same move and count" {
    const gpa = std.testing.allocator;
    const e = try newEngine(gpa);
    defer freeEngine(gpa, e);
    for ([_]u64{ 1, 1000, 5000, 20000, 77777 }) |n| {
        var c1: Capture = .{};
        var c2: Capture = .{};
        var s1: uci_engine.Signals = .{};
        var s2: uci_engine.Signals = .{};
        const p = positions[2];
        const a = try go(e, p, .{ .nodes = n }, &c1, &s1);
        const b = try go(e, p, .{ .nodes = n }, &c2, &s2);
        var b1: [5]u8 = undefined;
        std.debug.print("time: go nodes {d}: bestmove {s}, {d} nodes ({d} past N), cause {s}\n", .{ n, mtext(a.best, &b1), a.nodes, a.nodes -| n, @tagName(e.root.stop_cause) });
        try std.testing.expect(a.best.?.eql(b.best.?));
        try std.testing.expectEqual(a.nodes, b.nodes);
        try std.testing.expectEqualSlices(u8, &a.line, &b.line);
        try std.testing.expect(legalAfter(e, p, a.best.?));
        try std.testing.expect(a.nodes >= n);
        // The unwinding enters at most the nodes below the open moves' first replies.
        try std.testing.expect(a.nodes < n + 200);
    }
}

test "time: what the time control is handed (one legal move, expected move and recapture square, re-searches, root trouble)" {
    const gpa = std.testing.allocator;
    const e = try newEngine(gpa);
    defer freeEngine(gpa, e);
    var b1: [5]u8 = undefined;
    {
        // One legal move: Kxb2.
        var cap: Capture = .{};
        var sig: uci_engine.Signals = .{};
        const t = try go(e, .{ .fen = "k7/ppp5/8/8/8/8/1q6/K6R w - - 0 1" }, .{ .wtime = 60000, .btime = 60000 }, &cap, &sig);
        std.debug.print("time: one legal move: bestmove {s}, move count {d}, iterations {d}\n", .{ mtext(t.best, &b1), e.tc.move_count, t.log.n });
        try std.testing.expectEqual(@as(u8, 1), e.tc.move_count);
    }
    {
        // The expected move: the third move of the last PV when the opponent played its
        // second; the previous target square is the opponent's move's. In an exchange the
        // expected move recaptures on that square (the 0.5 factor).
        var recaptures: u32 = 0;
        const cands = [_]Pos{
            .{ .moves = &.{ "e2e4", "e7e5", "g1f3", "b8c6", "d2d4" } },
            .{ .moves = &.{ "d2d4", "d7d5", "c2c4", "e7e6", "b1c3", "g8f6", "c1g5", "b8d7", "c4d5" } },
            // Rxd1+ Rxd1 Rxd1+: the answer recaptures on the reply's square.
            .{ .fen = "3r2k1/3r1ppp/8/8/8/8/5PPP/R2Q2K1 w - - 0 1", .moves = &.{"h2h3"} },
        };
        for (cands) |p| {
            const mv = p.moves;
            var cap: Capture = .{};
            var sig: uci_engine.Signals = .{};
            const t = try go(e, p, .{ .depth = 5 }, &cap, &sig);
            const pr = e.predicted orelse continue;
            const reply: fen.UciMove = .{ .from = @truncate(pr[0] & 0x7F), .to = @truncate((pr[0] >> 8) & 0x7F) };
            const answer_key = E.Report.moveKey(@truncate(pr[1]), @truncate(pr[1] >> 8));
            var ms: [16]fen.UciMove = undefined;
            for (mv, 0..) |m, i| ms[i] = try fen.parseMove(m);
            ms[mv.len] = t.best.?;
            ms[mv.len + 1] = reply;
            var b4: [5]u8 = undefined;
            var b5: [5]u8 = undefined;
            std.debug.print("time: candidate: bestmove {s}, reply {s}\n", .{ mtext(t.best, &b4), mtext(reply, &b5) });
            if (e.engine().setPosition(&(try fen.parse(p.fen orelse fen.startpos)), if (p.fen == null) .new_game else .setup, ms[0 .. mv.len + 2])) |why| {
                std.debug.print("time: rejected: {s}\n", .{why});
                return error.Rejected;
            }
            if (!e.by_continuation) {
                // The held game was not continued (the engine rebuilt the position): no
                // expected move, as for any rebuild.
                std.debug.print("time: not continued (rebuilt; root failure: {s})\n", .{e.root.failure orelse "none"});
                continue;
            }
            var cap2: Capture = .{};
            var sig2: uci_engine.Signals = .{};
            const r2 = e.engine().search(&.{ .wtime = 60000, .btime = 60000 }, &sig2, cap2.out());
            const x = e.last_expected orelse return error.NoExpected;
            var b2: [5]u8 = undefined;
            var b3: [5]u8 = undefined;
            std.debug.print("time: expected: bestmove {s}, reply {s}: expected move {x} to {d}, previous to {d}; played {s}\n", .{ mtext(t.best, &b1), mtext(reply, &b2), x.move, x.to, e.last_previous_to.?, mtext(r2.best, &b3) });
            try std.testing.expectEqual(answer_key, x.move);
            try std.testing.expectEqual(reply.to, e.last_previous_to.?);
            if (x.to == reply.to) recaptures += 1;
        }
        try std.testing.expect(recaptures > 0);
        // A different reply: no expected move.
        const p = cands[0];
        var cap3: Capture = .{};
        var sig3: uci_engine.Signals = .{};
        const r3 = try go(e, p, .{ .depth = 5 }, &cap3, &sig3);
        var ms: [8]fen.UciMove = undefined;
        for (p.moves, 0..) |m, i| ms[i] = try fen.parseMove(m);
        ms[5] = r3.best.?;
        ms[6] = try fen.parseMove("a2a3");
        try std.testing.expect(e.engine().setPosition(&(try fen.parse(fen.startpos)), .new_game, ms[0..7]) == null);
        _ = e.engine().search(&.{ .depth = 2 }, &sig3, cap3.out());
        try std.testing.expect(e.last_expected == null);
        try std.testing.expectEqual(@as(?u8, 41), e.last_previous_to); // a3
    }
    {
        // Root re-searches and root trouble, over a few searches.
        var fhl: u32 = 0;
        var trouble: u32 = 0;
        for (positions ++ [_]Pos{
            .{ .fen = "r1b1k2r/ppppqppp/2n2n2/2b1p3/2B1P3/2NP1N2/PPP2PPP/R1BQK2R w KQkq - 0 1" },
            .{ .fen = "2r3k1/pp3ppp/2n5/3q4/3P4/2PB1N2/P4PPP/2RQ2K1 b - - 0 1" },
        }) |p| {
            var cap: Capture = .{};
            var sig: uci_engine.Signals = .{};
            const t = try go(e, p, .{ .wtime = 30000, .btime = 30000, .depth = 6 }, &cap, &sig);
            for (t.log.iterations[0..t.log.n]) |it| {
                if (it.fail_high_low > 0) {
                    fhl += 1;
                    std.debug.print("time: re-searches: depth {d}: {d} (score {d})\n", .{ it.depth, it.fail_high_low, it.score });
                }
            }
            if (t.log.trouble_seen) trouble += 1;
        }
        std.debug.print("time: iterations with root re-searches {d}; searches with root trouble {d}\n", .{ fhl, trouble });
        try std.testing.expect(fhl > 0);
        try std.testing.expect(trouble > 0);
    }
}

test "time: the engine's time control counts a pawn as 200 (score unit 2: StableScore's 25 and RootTrouble's 50 are centipawns)" {
    const gpa = std.testing.allocator;
    const e = try newEngine(gpa);
    defer freeEngine(gpa, e);
    try std.testing.expectEqual(@as(i32, 2), e.tc.score_unit);
    // The transcription's own unit stays 1 (its recorded vectors replay with it).
    try std.testing.expectEqual(@as(i32, 1), (timecontrol.TimeControl{}).score_unit);
}

test "time: a rook and a queen promotion are different best moves to the clock; a timed search to depth 2 is still go depth 2" {
    const gpa = std.testing.allocator;
    const e = try newEngine(gpa);
    defer freeEngine(gpa, e);
    const o: uci_engine.Options = .{ .use_tablebases = false };
    e.engine().applyOptions(&o);
    const p: Pos = .{ .fen = "8/4kPq1/8/8/K7/8/8/8 w - - 0 1" };
    var cap: Capture = .{};
    var sig: uci_engine.Signals = .{};
    const t = try go(e, p, .{ .wtime = 60000, .btime = 60000, .depth = 2 }, &cap, &sig);
    var cap2: Capture = .{};
    var sig2: uci_engine.Signals = .{};
    const d = try go(e, p, .{ .depth = 2 }, &cap2, &sig2);
    var b1: [5]u8 = undefined;
    var b2: [5]u8 = undefined;
    std.debug.print("time: promotions: timed {s} {d} nodes, iterations {d}: keys {x} {x}; go depth 2 {s} {d} nodes\n", .{ mtext(t.best, &b1), t.nodes, t.log.n, t.log.iterations[0].best_move, t.log.iterations[1].best_move, mtext(d.best, &b2), d.nodes });
    try std.testing.expectEqual(@as(usize, 2), t.log.n);
    // Depth 1 f7f8r, depth 2 f7f8q: the same squares, two moves.
    try std.testing.expect(t.log.iterations[0].best_move != t.log.iterations[1].best_move);
    try std.testing.expectEqual(t.log.iterations[0].best_move & 0xFFFF, t.log.iterations[1].best_move & 0xFFFF);
    try std.testing.expectEqualStrings("f7f8q", mtext(d.best, &b2));
    try std.testing.expectEqual(@as(u64, 1748), d.nodes);
    try std.testing.expect(t.best.?.eql(d.best.?));
    try std.testing.expectEqual(d.nodes, t.nodes);
    try std.testing.expectEqual(d.makes, t.makes);
    try std.testing.expectEqualSlices(u8, &d.line, &t.line);
}

test "time: a predicted answer that promotes gives no expected move (the PV word holds no piece)" {
    const gpa = std.testing.allocator;
    const e = try newEngine(gpa);
    defer freeEngine(gpa, e);
    const o: uci_engine.Options = .{ .use_tablebases = false };
    e.engine().applyOptions(&o);
    // Pawn races, so that the program pushes its pawn at once and promotes at its next move
    // (with a lone pawn the program is as happy to move its king).
    const cands = [_][]const u8{
        "8/8/1P6/8/8/6p1/8/K6k w - - 0 1",
        "k7/8/8/8/8/1p6/6P1/7K b - - 0 1",
        "8/8/1P6/8/8/8/6k1/K7 w - - 0 1",
    };
    var seen: u32 = 0;
    for (cands) |f| {
        const p: Pos = .{ .fen = f };
        var cap: Capture = .{};
        var sig: uci_engine.Signals = .{};
        const t = try go(e, p, .{ .depth = 5 }, &cap, &sig);
        const pr = e.predicted orelse continue;
        const reply: fen.UciMove = .{ .from = @truncate(pr[0] & 0x7F), .to = @truncate((pr[0] >> 8) & 0x7F) };
        const ms = [_]fen.UciMove{ t.best.?, reply };
        try setPos(e, p, &ms);
        if (!e.by_continuation) continue;
        const a_from: u8 = @truncate(pr[1] & 0x7F);
        const a_to: u8 = @truncate((pr[1] >> 8) & 0x7F);
        const pc = e.root.node.dom.p.board[a_from];
        const promotes = (pc == 1 or pc == 8) and (a_to >= 91 or a_to <= 28);
        var cap2: Capture = .{};
        var sig2: uci_engine.Signals = .{};
        _ = e.engine().search(&.{ .wtime = 60000, .btime = 60000, .depth = 3 }, &sig2, cap2.out());
        var b1: [5]u8 = undefined;
        var b2: [5]u8 = undefined;
        std.debug.print("time: predicted promotion: {s}: bestmove {s}, reply {s}, answer from {d} to {d}, promotes {}; expected {any}\n", .{ f, mtext(t.best, &b1), mtext(reply, &b2), a_from, a_to, promotes, e.last_expected });
        if (!promotes) continue;
        seen += 1;
        try std.testing.expect(e.last_expected == null);
    }
    try std.testing.expect(seen > 0);
}

test "time: with one move to go a timed search keeps the clock reserve (a fifth of the clock); without it, it runs past four fifths" {
    const gpa = std.testing.allocator;
    const e = try newEngine(gpa);
    defer freeEngine(gpa, e);
    var past_without: u32 = 0;
    for (positions) |p| {
        for ([_]u32{ 800, 2000 }) |clock| {
            const cap = timecontrol.reserveCap(clock, timecontrol.default_move_overhead);
            for ([_]timecontrol.Fixes{ .corrected, .decision26 }) |fx| {
                e.tc.fixes = fx;
                defer e.tc.fixes = .corrected;
                var cap_out: Capture = .{};
                var sig: uci_engine.Signals = .{};
                const t = try go(e, p, .{ .wtime = clock, .btime = clock, .movestogo = 1 }, &cap_out, &sig);
                // The time used: where the search stopped inside an iteration, else the end
                // of its last iteration (the scripted clock: 20 us a node entry).
                const used: i64 = if (t.log.stopped_in_search) t.log.stop_elapsed else if (t.log.n > 0) t.log.iterations[t.log.n - 1].elapsed_ms else 0;
                var b1: [5]u8 = undefined;
                std.debug.print("time: clock {d}, movestogo 1, reserve {}: panic {d} (cap {d}): bestmove {s}, used {d} ms, stopped {s}\n", .{ clock, fx.clock_reserve, e.tc.panic, cap, mtext(t.best, &b1), used, if (t.log.stopped_in_search) "inside" else "after" });
                try std.testing.expect(t.best != null);
                try std.testing.expect(legalAfter(e, p, t.best.?));
                if (fx.clock_reserve) {
                    try std.testing.expectEqual(cap, e.tc.panic);
                    // At most the first 1024-node test past the cap (20.48 ms here).
                    try std.testing.expect(used < cap + 21);
                } else {
                    try std.testing.expectEqual(@as(i64, clock) - 60, e.tc.panic);
                    if (used > cap + 21) past_without += 1;
                }
            }
        }
    }
    try std.testing.expect(past_without > 0);
}

test "time: go mate, go ponder and movetime" {
    const gpa = std.testing.allocator;
    const e = try newEngine(gpa);
    defer freeEngine(gpa, e);
    var b1: [5]u8 = undefined;
    {
        var cap: Capture = .{};
        var sig: uci_engine.Signals = .{};
        // A back-rank mate in one (not a tablebase position: it is searched).
        const t = try go(e, .{ .fen = "6k1/5ppp/8/8/8/8/5PPP/3R2K1 w - - 0 1" }, .{ .mate = 2 }, &cap, &sig);
        try std.testing.expect(t.log.n > 0);
        const last = t.log.iterations[t.log.n - 1];
        std.debug.print("time: go mate 2: {s}, {d} iterations, stopped after {d}, mate in {?d}\n", .{ mtext(t.best, &b1), t.log.n, t.log.stopped_after orelse -1, last.mate_moves });
        try std.testing.expect(t.log.stopped_after != null);
        try std.testing.expect(last.mate_moves.? <= 2);
    }
    {
        // Pondering: no time rule stops it (a depth limit does); after ponderhit the clock
        // rules apply, with the time pondered counted as spent.
        var cap: Capture = .{};
        var sig: uci_engine.Signals = .{};
        const t = try go(e, positions[1], .{ .ponder = true, .wtime = 1000, .btime = 1000, .depth = 5 }, &cap, &sig);
        std.debug.print("time: go ponder (no ponderhit): {d} nodes, stopped in search {}, after {d}\n", .{ t.nodes, t.log.stopped_in_search, t.log.stopped_after orelse -1 });
        try std.testing.expect(!t.log.stopped_in_search);
        try std.testing.expectEqual(@as(?i16, 5), t.log.stopped_after);
        var cap2: Capture = .{};
        var sig2: uci_engine.Signals = .{};
        sig2.ponderhit.store(true, .release);
        const h = try go(e, positions[1], .{ .ponder = true, .wtime = 1000, .btime = 1000, .depth = 5 }, &cap2, &sig2);
        std.debug.print("time: go ponder after ponderhit: {d} nodes, stopped in search {}\n", .{ h.nodes, h.log.stopped_in_search });
        try std.testing.expect(h.nodes < t.nodes);
    }
    {
        var cap: Capture = .{};
        var sig: uci_engine.Signals = .{};
        const t = try go(e, positions[2], .{ .movetime = 500 }, &cap, &sig);
        std.debug.print("time: movetime 500: {s}, {d} nodes, stopped in search {} at {d}, after {d}\n", .{ mtext(t.best, &b1), t.nodes, t.log.stopped_in_search, t.log.stop_elapsed, t.log.stopped_after orelse -1 });
        // 500 - 30 = 470 ms, the first test past it: 470 / 0.02 = 23,500 nodes, the next
        // multiple of 1024 is 24,576 (491 ms), plus the unwinding.
        if (t.log.stopped_in_search) try std.testing.expect(t.log.stop_elapsed >= 470 and t.log.stop_elapsed < 491 + 1);
        try std.testing.expect(t.nodes * 20 / 1000 < 520);
    }
}
