//! The joined engine as a UCI game drives it (src/engine.zig, docs/UCI.md "The operator
//! script"):
//!
//! - games of tests/golden/normal1.jsonl replayed command by command as a GUI sends them
//!   (`position startpos|fen ... moves ...` growing by two plies, `go depth N`), each
//!   search equal to the golden one on the move, node entries, makes and line hash, and
//!   every search after the first reached by continuing the held game (normal play's
//!   opponent move), not by a rebuild; with reporting off and on;
//! - stops at different node counts give one legal move;
//! - mate scores as `score mate N` on the final `info` line (KRK from the tablebases).

const std = @import("std");
const builtin = @import("builtin");
const fen = @import("fen.zig");
const pos = @import("position.zig");
const uci_engine = @import("uci_engine.zig");
const engine_mod = @import("engine.zig");
const ert_test = @import("engine_root_test.zig");

/// The golden files record DEV-001 uncorrected.
const E = engine_mod.EngineOf(pos.Fixes.original);

const Capture = struct {
    buf: [1 << 16]u8 = undefined,
    len: usize = 0,
    lines: usize = 0,
    fn lineFn(ctx: ?*anyopaque, line: []const u8) void {
        const c: *Capture = @ptrCast(@alignCast(ctx.?));
        c.lines += 1;
        if (c.len + line.len + 1 > c.buf.len) c.len = 0; // keep the latest lines
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
    /// The last line that starts with `info depth` and carries a score.
    fn lastScoreLine(c: *const Capture) ?[]const u8 {
        var it = std.mem.splitBackwardsScalar(u8, c.text(), '\n');
        while (it.next()) |l| if (std.mem.startsWith(u8, l, "info depth") and std.mem.indexOf(u8, l, " score ") != null) return l;
        return null;
    }
};

fn moveText(m: fen.UciMove, buf: *[5]u8) []const u8 {
    return fen.formatMove(m, buf);
}

const GameResult = struct { ran: u32 = 0, equal: u32 = 0, nodes: u64 = 0, not_run: u32 = 0 };

/// Replays one game of normal1.jsonl through `e` as a GUI would; returns the counts.
fn replayGame(gpa: std.mem.Allocator, e: *E, scenario: []const u8, reporting: bool, max_nodes: ?u64) !GameResult {
    const jl = try ert_test.readGolden(gpa, "normal1.jsonl");
    defer gpa.free(jl);
    var lines = std.mem.splitScalar(u8, jl, '\n');
    var header: ?std.json.Parsed(std.json.Value) = null;
    defer if (header) |h| h.deinit();
    var res: GameResult = .{};
    var game: [200]fen.UciMove = undefined;
    var game_len: usize = 0;
    var start: fen.Description = undefined;
    var route: uci_engine.Route = .new_game;
    var depth: u32 = 0;
    e.reporting = reporting;
    const eng = e.engine();
    eng.newGame();
    const continued0 = e.continued;
    while (lines.next()) |text| {
        if (text.len == 0) continue;
        const parsed = try std.json.parseFromSlice(std.json.Value, gpa, text, .{});
        defer parsed.deinit();
        const o = parsed.value.object;
        if (!std.mem.eql(u8, o.get("scenario").?.string, scenario)) continue;
        if (o.get("search") == null) {
            header = try std.json.parseFromSlice(std.json.Value, gpa, text, .{});
            const h = header.?.value.object;
            depth = @intCast(h.get("depth").?.integer);
            switch (h.get("fen").?) {
                .string => |f| {
                    // The oracle enters the FEN through Setup mode, which gives the rights
                    // the board allows; the header's FEN stops before the castling field
                    // (which UCI would read as no rights, owner decision 16).
                    start = try fen.parse(f);
                    start.castling = @import("adapt_setup.zig").rightsFromBoard(&start.board);
                    route = .setup;
                },
                else => {
                    start = try fen.parse(fen.startpos);
                    route = .new_game;
                },
            }
            for (h.get("game").?.array.items, 0..) |m, i| game[i] = try fen.parseMove(m.string);
            game_len = h.get("game").?.array.items.len;
            continue;
        }
        const k: usize = @intCast(o.get("search").?.integer);
        const want = ert_test.expectedOf(parsed.value);
        if (max_nodes) |mx| if (want.nodes > mx) {
            res.not_run += 1;
            break;
        };
        // Search k follows the opponent's k-th move: game[0 .. 2k-1].
        const n = 2 * k - 1;
        if (n > game_len) return error.GoldenTooShort;
        if (eng.setPosition(&start, route, game[0..n])) |why| {
            std.debug.print("uci game {s}: search {d}: position rejected: {s}\n", .{ scenario, k, why });
            return error.Rejected;
        }
        var cap: Capture = .{};
        var sig: uci_engine.Signals = .{};
        const r = eng.search(&.{ .depth = depth }, &sig, cap.out());
        var mb: [5]u8 = undefined;
        const played = if (r.best) |b| moveText(b, &mb) else "none";
        const line = e.root.lineHex();
        const ok = std.mem.eql(u8, played, want.played) and e.root.nodes == want.nodes and e.root.makes == want.makes and std.mem.eql(u8, &line, want.line);
        res.ran += 1;
        res.nodes += e.root.nodes;
        if (ok) res.equal += 1 else std.debug.print("uci game {s} search {d}: played {s} ({s}), nodes {d} ({d}), makes {d} ({d}), line {s}\n{s}", .{ scenario, k, played, want.played, e.root.nodes, want.nodes, e.root.makes, want.makes, if (std.mem.eql(u8, &line, want.line)) "equal" else "differs", cap.text() });
        if (reporting) {
            const last = cap.lastScoreLine() orelse return error.NoInfoLine;
            try std.testing.expect(std.mem.indexOf(u8, last, " pv ") != null);
            try std.testing.expect(std.mem.indexOf(u8, last, " nodes ") != null);
            try std.testing.expect(std.mem.indexOf(u8, last, " hashfull ") != null);
        }
        if (!ok) break;
    }
    // Every search after the first continued the held game.
    if (res.ran > 1 and e.continued - continued0 != res.ran - 1) {
        std.debug.print("uci game {s}: {d} searches, {d} continued\n", .{ scenario, res.ran, e.continued - continued0 });
        return error.NotContinued;
    }
    return res;
}

fn maxNodes(gpa: std.mem.Allocator) !?u64 {
    if (try std.testing.environ.containsUnempty(gpa, "MCHESS_LONG_TESTS")) return null;
    return if (builtin.mode == .debug) 16_000 else null;
}

test "uci game: games of tests/golden/normal1.jsonl replayed as a GUI sends them (position ... moves growing by two plies, go depth N) are the original's normal play" {
    const gpa = std.testing.allocator;
    const e = try gpa.create(E);
    defer gpa.destroy(e);
    e.* = try E.init(gpa);
    defer e.deinit();
    const mx = try maxNodes(gpa);
    // The program Black from startpos; White from a FEN (Black to move, the program
    // answers); more from FENs.
    const games = [_][]const u8{ "np-open-black-d4", "np-open-white-d3", "np-checks-white-d3", "np-middle-white-d4", "np-ending-black-d5" };
    var bad: u32 = 0;
    var ran: u32 = 0;
    for (games) |g| {
        const r = try replayGame(gpa, e, g, true, mx);
        std.debug.print("uci game {s}: {d} searches run ({d} nodes), {d} equal; the rest {s}\n", .{ g, r.ran, r.nodes, r.equal, if (r.not_run > 0) "not run in this build (a search above the node limit; MCHESS_LONG_TESTS=1 runs all)" else "none" });
        if (r.equal != r.ran or (r.ran == 0 and r.not_run == 0)) bad += 1;
        ran += r.ran;
    }
    try std.testing.expectEqual(@as(u32, 0), bad);
    try std.testing.expect(ran > 0);
}

test "uci game: reporting changes nothing: np-open-white-d3 with info lines off and on, the same nodes, makes and line hash" {
    const gpa = std.testing.allocator;
    const e = try gpa.create(E);
    defer gpa.destroy(e);
    e.* = try E.init(gpa);
    defer e.deinit();
    const mx = try maxNodes(gpa);
    const off = try replayGame(gpa, e, "np-open-white-d3", false, mx);
    const on = try replayGame(gpa, e, "np-open-white-d3", true, mx);
    std.debug.print("uci game: reporting off {d}/{d} equal ({d} nodes), on {d}/{d} ({d} nodes)\n", .{ off.equal, off.ran, off.nodes, on.equal, on.ran, on.nodes });
    try std.testing.expect(off.ran > 0);
    try std.testing.expectEqual(off.ran, off.equal);
    try std.testing.expectEqual(on.ran, on.equal);
    try std.testing.expectEqual(off.nodes, on.nodes);
}

/// `go depth d` on `position fen f`; returns the final line with a score.
fn searchFen(e: anytype, cap: *Capture, f: []const u8, moves: []const []const u8, depth: u32, sig: *uci_engine.Signals) !?fen.UciMove {
    const d = try fen.parse(f);
    var ms: [16]fen.UciMove = undefined;
    for (moves, 0..) |m, i| ms[i] = try fen.parseMove(m);
    const eng = e.engine();
    if (eng.setPosition(&d, .setup, ms[0..moves.len])) |why| {
        std.debug.print("rejected {s}: {s}\n", .{ f, why });
        return error.Rejected;
    }
    return eng.search(&.{ .depth = depth }, sig, cap.out()).best;
}

test "uci: mate scores are score mate N on the final info line (the mating side's moves; negative when mated)" {
    const gpa = std.testing.allocator;
    const e = try gpa.create(engine_mod.Engine);
    defer gpa.destroy(e);
    e.* = try engine_mod.Engine.init(gpa);
    defer e.deinit();
    const cases = [_]struct { []const u8, u32, []const u8 }{
        .{ "6k1/5ppp/8/8/8/8/5PPP/3R2K1 w", 4, "score mate 1 " },
        .{ "3r2k1/5ppp/8/8/8/8/5PPP/6K1 b", 4, "score mate 1 " },
        .{ "k7/8/2K5/8/8/8/8/6R1 w", 6, "score mate 2 " },
        .{ "6r1/8/8/8/8/2k5/8/K7 b", 6, "score mate 2 " },
        .{ "k7/8/8/3K4/8/8/8/6R1 w", 7, "score mate 3 " },
        .{ "6r1/8/8/8/3k4/8/8/K7 b", 7, "score mate 3 " },
        .{ "k7/8/1K6/8/8/8/8/6R1 b", 6, "score mate -1 " },
        .{ "K7/8/1k6/8/8/8/8/6r1 w", 6, "score mate -1 " },
        .{ "k7/8/2K5/8/8/8/8/6R1 b", 7, "score mate -2 " },
        .{ "K7/8/2k5/8/8/8/8/6r1 w", 7, "score mate -2 " },
    };
    var bad: u32 = 0;
    for (cases) |c| {
        var cap: Capture = .{};
        var sig: uci_engine.Signals = .{};
        const best = try searchFen(e, &cap, c[0], &.{}, c[1], &sig);
        const last = cap.lastScoreLine() orelse "";
        var mb: [5]u8 = undefined;
        std.debug.print("uci mate: {s} go depth {d}: bestmove {s}; {s}\n", .{ c[0], c[1], if (best) |b| moveText(b, &mb) else "none", last });
        if (std.mem.indexOf(u8, last, c[2]) == null) bad += 1;
    }
    try std.testing.expectEqual(@as(u32, 0), bad);
}

test "uci: score cp is the original's displayed score, half the raw one (startpos go depth 1: raw 103, score cp 51; DEV-F23)" {
    const gpa = std.testing.allocator;
    const e = try gpa.create(engine_mod.Engine);
    defer gpa.destroy(e);
    e.* = try engine_mod.Engine.init(gpa);
    defer e.deinit();
    var cap: Capture = .{};
    var sig: uci_engine.Signals = .{};
    const start = try fen.parse(fen.startpos);
    try std.testing.expect(e.engine().setPosition(&start, .new_game, &.{}) == null);
    const r = e.engine().search(&.{ .depth = 1 }, &sig, cap.out());
    const last = cap.lastScoreLine() orelse "";
    var mb: [5]u8 = undefined;
    std.debug.print("uci score: startpos go depth 1: bestmove {s}, raw {?d}; {s}\n", .{ if (r.best) |b| moveText(b, &mb) else "none", e.last_score, last });
    try std.testing.expectEqual(@as(?i16, 103), e.last_score);
    try std.testing.expect(std.mem.indexOf(u8, last, " score cp 51 ") != null);
}

test "uci: KQK, KRK and KPK positions are played from the embedded tablebases without a search, with a scored info line" {
    const gpa = std.testing.allocator;
    const e = try gpa.create(engine_mod.Engine);
    defer gpa.destroy(e);
    e.* = try engine_mod.Engine.init(gpa);
    defer e.deinit();
    const cases = [_][]const u8{ "8/8/8/4k3/8/8/8/R3K3 w", "8/8/8/4k3/8/8/8/1Q2K3 w", "8/8/8/4k3/8/8/4P3/4K3 w", "8/8/8/4k3/8/8/8/R3K3 b" };
    for (cases) |c| {
        var cap: Capture = .{};
        var sig: uci_engine.Signals = .{};
        const best = try searchFen(e, &cap, c, &.{}, 4, &sig);
        const last = cap.lastScoreLine() orelse "";
        var mb: [5]u8 = undefined;
        std.debug.print("uci tablebase material: {s} go depth 4: bestmove {s}; {s}\n", .{ c, if (best) |b| moveText(b, &mb) else "none", last });
        try std.testing.expect(best != null);
        try std.testing.expect(std.mem.indexOf(u8, last, " score ") != null);
        try std.testing.expect(std.mem.indexOf(u8, cap.text(), "info string tablebase move") != null);
        try std.testing.expectEqual(@as(u64, 0), e.root.nodes);
    }
}

test "uci: a stop at different node counts gives one legal move of the root list, and a search not stopped is unchanged" {
    const gpa = std.testing.allocator;
    const e = try gpa.create(engine_mod.Engine);
    defer gpa.destroy(e);
    e.* = try engine_mod.Engine.init(gpa);
    defer e.deinit();
    const eng = e.engine();
    const start = try fen.parse(fen.startpos);
    const f = "r1bq1rk1/ppp2ppp/2n5/3np3/1b6/2NP1NP1/PP2PPBP/R1BQ1RK1 w - - 0 1";
    const d = try fen.parse(f);
    // The counter's phase decides which node entry reads the request first.
    const offsets = [_]u32{ 1, 3, 200, 700, 1023, 0 };
    for (offsets, 0..) |off, i| {
        const use_fen = i % 2 == 1;
        if (eng.setPosition(if (use_fen) &d else &start, if (use_fen) .setup else .new_game, &.{})) |why| {
            std.debug.print("rejected: {s}\n", .{why});
            return error.Rejected;
        }
        e.root.node_tick = 1024 - off;
        var cap: Capture = .{};
        var sig: uci_engine.Signals = .{};
        sig.stop.store(true, .release);
        const r = eng.search(&.{ .depth = 8 }, &sig, cap.out());
        const best = r.best orelse return error.NoMove;
        const nodes = e.root.nodes;
        var mb: [5]u8 = undefined;
        std.debug.print("uci stop: offset {d}: stopped after {d} nodes: bestmove {s}; {s}\n", .{ off, nodes, moveText(best, &mb), cap.lastScoreLine() orelse "(no line)" });
        try std.testing.expect(nodes < 5000);
        // Legal: the engine accepts the position with the move played.
        const one = [_]fen.UciMove{best};
        try std.testing.expect(eng.setPosition(if (use_fen) &d else &start, if (use_fen) .setup else .new_game, &one) == null);
    }
}

test "uci game: after a rebuild of 0, 1, 2, 3 or 6 plies, with the program White or Black, the next position that adds the opponent's one move continues the held game (docs/OPEN_QUESTIONS.md question 19)" {
    const gpa = std.testing.allocator;
    const e = try gpa.create(engine_mod.Engine);
    defer gpa.destroy(e);
    e.* = try engine_mod.Engine.init(gpa);
    defer e.deinit();
    e.reporting = false;
    const eng = e.engine();
    const start = try fen.parse(fen.startpos);
    const lines = [_][]const u8{ "", "e2e4", "e2e4 d7d5", "e2e4 d7d5 g1f3", "e2e4 e7e5 g1f3 b8c6 f1b5 a7a6" };
    for (lines) |ln| {
        var g: [16]fen.UciMove = undefined;
        var n: usize = 0;
        var it = std.mem.tokenizeScalar(u8, ln, ' ');
        while (it.next()) |t| : (n += 1) g[n] = try fen.parseMove(t);
        eng.newGame();
        const rebuilt0 = e.rebuilt;
        try std.testing.expect(eng.setPosition(&start, .new_game, g[0..n]) == null);
        try std.testing.expectEqual(rebuilt0 + 1, e.rebuilt);
        var sig: uci_engine.Signals = .{};
        var cap: Capture = .{};
        const r = eng.search(&.{ .depth = 2 }, &sig, cap.out());
        g[n] = r.best orelse return error.NoMove;
        // The opponent plays the reply the program predicted (legal by set_predicted_reply).
        g[n + 1] = r.ponder orelse return error.NoPonderMove;
        const c0 = e.continued;
        try std.testing.expect(eng.setPosition(&start, .new_game, g[0 .. n + 2]) == null);
        std.debug.print("uci game: rebuilt [{s}], then +2 plies: continued {d}, rebuilt {d}\n", .{ ln, e.continued - c0, e.rebuilt - rebuilt0 - 1 });
        try std.testing.expectEqual(c0 + 1, e.continued);
        try std.testing.expectEqual(rebuilt0 + 1, e.rebuilt);
        // The example of the question: White's 3.exd5 Qxd5 continued after 1.e4 d5 rebuilt.
        const r2 = eng.search(&.{ .depth = 1 }, &sig, cap.out());
        try std.testing.expect(r2.best != null);
    }
}

test "uci game: DEV-050 at engine level: a rook captured on its corner keeps the castling right in the original's tree; corrected (DEV-050, with DEV-001: the two corrections the shipped engine had when this test was written) it searches differently" {
    const gpa = std.testing.allocator;
    const d = try fen.parse("4k3/8/8/8/4b3/7R/8/4K2R b K - 0 1");
    var nodes: [2]u64 = undefined;
    // The shipped engine corrects every class C bug since 2026-11-20, so the count below is
    // taken with DEV-050 and DEV-001 alone (src/engine_fixes_test.zig takes each switch).
    const fix050: pos.Fixes = .{ .dev001_ep_hash_square = true, .dev050_corner_rook_capture = true };
    inline for (.{ engine_mod.EngineOf(fix050), engine_mod.OriginalEngine }, 0..) |T, k| {
        const e = try gpa.create(T);
        defer gpa.destroy(e);
        e.* = try T.init(gpa);
        defer e.deinit();
        const eng = e.engine();
        var o: uci_engine.Options = .{};
        eng.applyOptions(&o);
        try std.testing.expect(eng.setPosition(&d, .setup, &.{}) == null);
        var sig: uci_engine.Signals = .{};
        var cap: Capture = .{};
        const res = eng.search(&.{ .depth = 4 }, &sig, cap.out());
        try std.testing.expect(res.best != null);
        nodes[k] = e.root.nodes;
        var mb: [5]u8 = undefined;
        std.debug.print("uci game: DEV-050 {s}: {s}, {d} nodes\n", .{ if (k == 0) "corrected" else "original", fen.formatMove(res.best.?, &mb), nodes[k] });
    }
    // 2561 until 2026-11-20, when only the search node made its moves under DEV-050; the root's
    // own makes (the root move ...Bxh1 here) take the right away too since task integrate-fixes.
    try std.testing.expectEqual(@as(u64, 2438), nodes[0]);
    try std.testing.expectEqual(@as(u64, 2465), nodes[1]);
}
