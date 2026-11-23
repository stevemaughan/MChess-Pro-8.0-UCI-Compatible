//! The joined engine behind the UCI interface (src/engine.zig): `position startpos
//! [moves]` and `go depth N` give the original's moves, and node counts, of
//! tests/golden/smoke.jsonl scenario start-d3 (Fixed depth 3, auto-play). Each position
//! here is a rebuild (docs/UCI.md, "The operator script"): no move and two or more on the
//! auto-play path, one move entered as the opponent's (normal play), which gives the same
//! search as auto-play at this point of the game. The UCI game itself, normal play
//! continued from move to move, is src/engine_uci_test.zig.

const std = @import("std");
const si = @import("state_image.zig");
const fen = @import("fen.zig");
const uci_engine = @import("uci_engine.zig");
const engine_mod = @import("engine.zig");

/// The engine with every class C fix off: the tests that compare a search with numbers
/// recorded from the original run it (the shipped `engine_mod.Engine` corrects the bugs
/// of docs/DEVIATIONS.md and searches different trees). The other tests here are about
/// behaviour (legality, refusals, reporting) and run the shipped engine.
const Original = engine_mod.EngineOf(pos.Fixes.original);

const Capture = struct {
    buf: [4096]u8 = undefined,
    len: usize = 0,
    fn lineFn(ctx: ?*anyopaque, line: []const u8) void {
        const c: *Capture = @ptrCast(@alignCast(ctx.?));
        const n = @min(line.len, c.buf.len - c.len);
        @memcpy(c.buf[c.len..][0..n], line[0..n]);
        c.len += n;
        if (c.len < c.buf.len) {
            c.buf[c.len] = '\n';
            c.len += 1;
        }
    }
    fn text(c: *const Capture) []const u8 {
        return c.buf[0..c.len];
    }
};

fn moveText(m: fen.UciMove, buf: *[5]u8) []const u8 {
    buf[0] = 'a' + m.from % 10 - 1;
    buf[1] = '1' + m.from / 10 - 2;
    buf[2] = 'a' + m.to % 10 - 1;
    buf[3] = '1' + m.to / 10 - 2;
    return buf[0..4];
}

test "engine: go depth 3 from startpos, and after the moves played, are the original's (start-d3)" {
    const gpa = std.testing.allocator;
    var e = try Original.init(gpa);
    defer e.deinit();
    const eng = e.engine();
    const start = try fen.parse(fen.startpos);
    // start-d3: the program's moves and node counts (tests/golden/smoke.jsonl).
    const want = [_]struct { []const u8, []const u8 }{
        .{ "d2d4", "nodes 1421 " },
        .{ "d7d5", "nodes 873 " },
        .{ "c1f4", "nodes 1417 " },
        .{ "c8f5", "nodes 2163 " },
    };
    var moves: [4]fen.UciMove = undefined;
    for (want, 0..) |w, k| {
        try std.testing.expect(eng.setPosition(&start, .new_game, moves[0..k]) == null);
        var cap: Capture = .{};
        var sig: uci_engine.Signals = .{};
        const r = eng.search(&.{ .depth = 3 }, &sig, .{ .ctx = &cap, .lineFn = Capture.lineFn });
        var mb: [5]u8 = undefined;
        const best = r.best orelse return error.NoMove;
        std.debug.print("engine: position startpos moves ({d}) go depth 3: bestmove {s}; {s}", .{ k, moveText(best, &mb), cap.text() });
        try std.testing.expectEqualStrings(w[0], moveText(best, &mb));
        try std.testing.expect(std.mem.indexOf(u8, cap.text(), w[1]) != null);
        moves[k] = try fen.parseMove(w[0]);
    }
}

test "engine: an illegal move is rejected with a reason" {
    const gpa = std.testing.allocator;
    var e = try engine_mod.Engine.init(gpa);
    defer e.deinit();
    const eng = e.engine();
    const start = try fen.parse(fen.startpos);
    const bad = [_]fen.UciMove{try fen.parseMove("e2e5")};
    try std.testing.expect(eng.setPosition(&start, .new_game, &bad) != null);
    const pinned = [_]fen.UciMove{ try fen.parseMove("e2e4"), try fen.parseMove("f7f6"), try fen.parseMove("d1h5"), try fen.parseMove("g7g6") };
    // 2...g6?? is legal; the position after 3.Qh5+ g6 is accepted.
    try std.testing.expect(eng.setPosition(&start, .new_game, &pinned) == null);
    const into_check = [_]fen.UciMove{ try fen.parseMove("e2e4"), try fen.parseMove("f7f6"), try fen.parseMove("d1h5"), try fen.parseMove("a7a6") };
    try std.testing.expect(eng.setPosition(&start, .new_game, &into_check) != null);
}

/// Runs `position fen <f> moves ...` and `go depth <depth>` on `eng`; returns the move and
/// checks the node count.
fn fenSearch(eng: uci_engine.Engine, f: []const u8, moves: []const []const u8, depth: u32, want_move: []const u8, want_nodes: []const u8) !void {
    const d = try fen.parse(f);
    var ms: [8]fen.UciMove = undefined;
    for (moves, 0..) |m, i| ms[i] = try fen.parseMove(m);
    if (eng.setPosition(&d, .setup, ms[0..moves.len])) |why| {
        std.debug.print("engine: position fen {s}: rejected: {s}\n", .{ f, why });
        return error.Rejected;
    }
    var cap: Capture = .{};
    var sig: uci_engine.Signals = .{};
    const r = eng.search(&.{ .depth = depth }, &sig, .{ .ctx = &cap, .lineFn = Capture.lineFn });
    var mb: [5]u8 = undefined;
    const best = r.best orelse return error.NoMove;
    std.debug.print("engine: position fen {s} ({d} moves) go depth {d}: bestmove {s}; {s}", .{ f, moves.len, depth, moveText(best, &mb), cap.text() });
    try std.testing.expectEqualStrings(want_move, moveText(best, &mb));
    try std.testing.expect(std.mem.indexOf(u8, cap.text(), want_nodes) != null);
}

test "engine: position fen and go depth N give the original's moves and node counts (tests/golden/corpus2.jsonl)" {
    const gpa = std.testing.allocator;
    var e = try Original.init(gpa);
    defer e.deinit();
    const eng = e.engine();
    // back-rank-mate-d4 search 1; check-evasion-d4 search 1 (the start position's rights
    // are on the board: KQkq is what Setup mode gives it); pawn-ending-d5 searches 1 and 2.
    try fenSearch(eng, "6k1/5ppp/8/8/8/8/5PPP/3R2K1 w - - 0 1", &.{}, 4, "d1d8", "nodes 4 ");
    try fenSearch(eng, "rnbqkbnr/ppp2ppp/8/1B1pp3/4P3/8/PPPP1PPP/RNBQK1NR b KQkq - 0 1", &.{}, 4, "c7c6", "nodes 4757 ");
    try fenSearch(eng, "8/5pk1/6p1/8/8/6PP/5PK1/8 b - - 0 1", &.{}, 5, "g7f6", "nodes 2010 ");
    try fenSearch(eng, "8/5pk1/6p1/8/8/6PP/5PK1/8 b - - 0 1", &.{"g7f6"}, 5, "f2f4", "nodes 2047 ");
    // A FEN without its last fields (as Shredder and other GUIs send it) is the same position.
    try fenSearch(eng, "8/5pk1/6p1/8/8/6PP/5PK1/8 b", &.{}, 5, "g7f6", "nodes 2010 ");
    try fenSearch(eng, "8/5pk1/6p1/8/8/6PP/5PK1/8 b - -", &.{"g7f6"}, 5, "f2f4", "nodes 2047 ");
    try fenSearch(eng, "6k1/5ppp/8/8/8/8/5PPP/3R2K1", &.{}, 4, "d1d8", "nodes 4 ");
    // kings-attack-d4 search 1 (19,556 nodes: not in Debug builds).
    if (@import("builtin").mode != .debug) {
        try fenSearch(eng, "r1bq1rk1/ppp2ppp/2n5/3np3/1b6/2NP1NP1/PP2PPBP/R1BQ1RK1 w - - 0 1", &.{}, 4, "f3e5", "nodes 19556 ");
        // castle-rooks-only-d5 search 1 of tests/golden/castling.jsonl, from a FEN that
        // stops after the castling field: the original castles.
        try fenSearch(eng, "r3k2r/p6p/8/8/8/8/P6P/R3K2R w KQkq", &.{}, 5, "e1g1", "nodes 66067 ");
    }
}

test "engine: position fen with fields Setup mode cannot give says what it did with each" {
    const gpa = std.testing.allocator;
    var e = try engine_mod.Engine.init(gpa);
    defer e.deinit();
    const eng = e.engine();
    const d = try fen.parse("r3k2r/8/8/8/8/8/8/R3K2R w Kq - 7 30");
    try std.testing.expect(eng.setPosition(&d, .setup, &.{}) == null);
    // The withheld rights are stamped lost (0EF8:6AAB): White O-O-O and Black O-O. The
    // engine's commands run on the members (Stage B step 8, stage 6): the image is made
    // current before it is read.
    si.toImage(e.root);
    const img = e.root.test_img;
    std.debug.print("engine: stamps after Kq: {X} {X} {X} {X}\n", .{ std.mem.readInt(u16, img[0xB426..][0..2], .little), std.mem.readInt(u16, img[0x3A30..][0..2], .little), std.mem.readInt(u16, img[0xB428..][0..2], .little), std.mem.readInt(u16, img[0x3A32..][0..2], .little) });
    try std.testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, img[0xB426..][0..2], .little));
    try std.testing.expectEqual(@as(u16, 0xFFFF), std.mem.readInt(u16, img[0x3A30..][0..2], .little));
    try std.testing.expectEqual(@as(u16, 0xFFFF), std.mem.readInt(u16, img[0xB428..][0..2], .little));
    try std.testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, img[0x3A32..][0..2], .little));
    var cap: Capture = .{};
    var sig: uci_engine.Signals = .{};
    _ = eng.search(&.{ .depth = 1 }, &sig, .{ .ctx = &cap, .lineFn = Capture.lineFn });
    std.debug.print("engine: position fen r3k2r/8/8/8/8/8/8/R3K2R w Kq - 7 30, go depth 1:\n{s}", .{cap.text()});
    try std.testing.expect(std.mem.indexOf(u8, cap.text(), "castling rights") != null);
    try std.testing.expect(std.mem.indexOf(u8, cap.text(), "halfmove clock 7 not used") != null);
    try std.testing.expect(std.mem.indexOf(u8, cap.text(), "move number 30 not used") != null);
    try std.testing.expect(std.mem.indexOf(u8, cap.text(), "en-passant") == null);
    // An en-passant square goes to ep_square_by_ply[0] (DG:9EC8) as the loader puts it.
    const ep = try fen.parse("4k3/8/8/3pP3/8/8/8/4K3 w - d6 0 1");
    try std.testing.expect(eng.setPosition(&ep, .setup, &.{}) == null);
    si.toImage(e.root);
    std.debug.print("engine: ep_square_by_ply[0] after d6: {d}\n", .{img[0x9EC8]});
    try std.testing.expectEqual(@as(u8, 74), img[0x9EC8]);
    const exd6 = [_]fen.UciMove{try fen.parseMove("e5d6")};
    if (eng.setPosition(&ep, .setup, &exd6)) |why| std.debug.print("engine: e5d6 after d6: {s}\n", .{why});
    try std.testing.expect(eng.setPosition(&ep, .setup, &exd6) == null);
}

test "engine: position fen: each of Setup mode's ten refusals (38C0:6542) is the rejection's reason" {
    const gpa = std.testing.allocator;
    var e = try engine_mod.Engine.init(gpa);
    defer e.deinit();
    const eng = e.engine();
    const cases = [_]struct { []const u8, []const u8 }{
        .{ "4k3/8/8/8/8/8/8/8 w - - 0 1", "NO WHITE KING" },
        .{ "4k3/8/8/8/8/8/8/K3K3 w - - 0 1", "Too many WHITE KINGS" },
        .{ "8/8/8/8/8/8/8/4K3 w - - 0 1", "NO BLACK KING" },
        .{ "k3k3/8/8/8/8/8/8/4K3 w - - 0 1", "Too many BLACK KINGS" },
        .{ "4k3/8/8/8/P7/8/PPPPPPPP/4K3 w - - 0 1", "Too many WHITE PAWNS" },
        .{ "4k3/8/8/8/8/NNN5/PPPPPPPP/4K3 w - - 0 1", "Too many WHITE PIECES" },
        .{ "4k3/pppppppp/p7/8/8/8/8/4K3 w - - 0 1", "Too many BLACK PAWNS" },
        .{ "4k3/pppppppp/nnn5/8/8/8/8/4K3 w - - 0 1", "Too many BLACK PIECE" },
        .{ "4k3/8/8/8/8/8/8/r3K3 b - - 0 1", "WHITE IS IN CHECK" },
        .{ "R3k3/8/8/8/8/8/8/4K3 w - - 0 1", "BLACK IS IN CHECK" },
        .{ "8/8/8/8/8/8/3k4/4K3 w - - 0 1", "BLACK IS IN CHECK" }, // kings side by side
    };
    for (cases) |c| {
        const d = try fen.parse(c[0]);
        const why = eng.setPosition(&d, .setup, &.{}) orelse return error.Accepted;
        std.debug.print("engine: position fen {s}: rejected: {s}\n", .{ c[0], why });
        try std.testing.expect(std.mem.endsWith(u8, why, c[1]));
    }
    // The side to move may be in check.
    const chk = try fen.parse("4k3/8/8/8/8/8/8/r3K3 w - - 0 1");
    try std.testing.expect(eng.setPosition(&chk, .setup, &.{}) == null);
}

test "engine: castling after position fen: a right the FEN gives can be played, a right it withholds cannot" {
    const gpa = std.testing.allocator;
    var e = try engine_mod.Engine.init(gpa);
    defer e.deinit();
    const eng = e.engine();
    const Case = struct { fen: []const u8, moves: []const []const u8, legal: bool };
    const cases = [_]Case{
        // All four rights, which is what Setup mode gives this board.
        .{ .fen = "r3k2r/8/8/8/8/8/8/R3K2R w KQkq - 0 1", .moves = &.{"e1g1"}, .legal = true },
        .{ .fen = "r3k2r/8/8/8/8/8/8/R3K2R w KQkq - 0 1", .moves = &.{"e1c1"}, .legal = true },
        .{ .fen = "r3k2r/8/8/8/8/8/8/R3K2R w KQkq - 0 1", .moves = &.{ "e1g1", "e8c8" }, .legal = true },
        .{ .fen = "r3k2r/8/8/8/8/8/8/R3K2R w KQkq - 0 1", .moves = &.{ "e1c1", "e8g8" }, .legal = true },
        // After O-O-O the rook on d1 attacks d8: Black may not castle long (the rule, not a right).
        .{ .fen = "r3k2r/8/8/8/8/8/8/R3K2R w KQkq - 0 1", .moves = &.{ "e1c1", "e8c8" }, .legal = false },
        // The FEN withholds White O-O-O and Black O-O (the loader's lines, 0EF8:6AAB).
        .{ .fen = "r3k2r/8/8/8/8/8/8/R3K2R w Kq - 0 1", .moves = &.{"e1g1"}, .legal = true },
        .{ .fen = "r3k2r/8/8/8/8/8/8/R3K2R w Kq - 0 1", .moves = &.{"e1c1"}, .legal = false },
        .{ .fen = "r3k2r/8/8/8/8/8/8/R3K2R w Kq - 0 1", .moves = &.{ "e1g1", "e8c8" }, .legal = true },
        .{ .fen = "r3k2r/8/8/8/8/8/8/R3K2R w Kq - 0 1", .moves = &.{ "e1g1", "e8g8" }, .legal = false },
        // The FEN withholds every right.
        .{ .fen = "r3k2r/8/8/8/8/8/8/R3K2R w - - 0 1", .moves = &.{"e1g1"}, .legal = false },
        .{ .fen = "r3k2r/8/8/8/8/8/8/R3K2R w - - 0 1", .moves = &.{"e1c1"}, .legal = false },
        .{ .fen = "r3k2r/8/8/8/8/8/8/R3K2R w - - 0 1", .moves = &.{ "e1e2", "e8g8" }, .legal = false },
        // A right is lost by a move as in any game: the king goes out and back.
        .{ .fen = "r3k2r/8/8/8/8/8/8/R3K2R w KQkq - 0 1", .moves = &.{ "e1e2", "a8b8", "e2e1", "b8a8", "e1g1" }, .legal = false },
        .{ .fen = "r3k2r/8/8/8/8/8/8/R3K2R w KQkq - 0 1", .moves = &.{ "e1e2", "a8b8", "e2e1", "b8a8", "a1b1", "e8g8" }, .legal = true },
        .{ .fen = "r3k2r/8/8/8/8/8/8/R3K2R w KQkq - 0 1", .moves = &.{ "e1e2", "a8b8", "e2e1", "b8a8", "a1b1", "e8c8" }, .legal = false },
        // Castling out of check, as the first of two moves (the replay's own legality test,
        // `findLegal`, where gen_all_moves would offer it) and as the only move (the
        // original's check_entered_move). The king's step out of check is the control.
        .{ .fen = "4k3/8/8/8/1b6/8/8/R3K2R w KQ - 0 1", .moves = &.{ "e1g1", "e8e7" }, .legal = false },
        .{ .fen = "4k3/8/8/8/1b6/8/8/R3K2R w KQ - 0 1", .moves = &.{ "e1c1", "e8e7" }, .legal = false },
        .{ .fen = "4k3/8/8/8/1b6/8/8/R3K2R w KQ - 0 1", .moves = &.{"e1g1"}, .legal = false },
        .{ .fen = "4k3/8/8/8/1b6/8/8/R3K2R w KQ - 0 1", .moves = &.{ "e1f1", "e8e7" }, .legal = true },
        .{ .fen = "r3k2r/8/8/8/8/8/8/4KR2 b kq - 0 1", .moves = &.{ "e8g8", "e1e2" }, .legal = false },
        .{ .fen = "r3k2r/8/8/8/8/5R2/8/4K3 b kq - 0 1", .moves = &.{ "e8c8", "e1e2" }, .legal = true },
    };
    for (cases) |c| {
        const d = try fen.parse(c.fen);
        var ms: [8]fen.UciMove = undefined;
        for (c.moves, 0..) |m, i| ms[i] = try fen.parseMove(m);
        const why = eng.setPosition(&d, .setup, ms[0..c.moves.len]);
        std.debug.print("engine: castling: {s}, last of {d} move(s) {s}: {s}\n", .{ c.fen, c.moves.len, c.moves[c.moves.len - 1], why orelse "accepted" });
        try std.testing.expectEqual(c.legal, why == null);
    }
}

const pos = @import("position.zig");
const ert_test = @import("engine_root_test.zig");

/// Every search of the named scenarios of tests/golden/corpus2.jsonl through the UCI
/// interface: search k is `position fen <scenario fen> moves <the moves played before it>`
/// and `go depth <depth>`, compared on the move, node entries, makes and line hash.
/// Returns the number of searches that differ; `tb` false unbinds the tablebase files.
fn corpus2ThroughEngine(gpa: std.mem.Allocator, scenarios: []const []const u8, tb: bool) !struct { ran: u32, differ: u32 } {
    const E = engine_mod.EngineOf(pos.Fixes.original); // the golden files record DEV-001 uncorrected
    const e = try gpa.create(E);
    defer gpa.destroy(e);
    e.* = try E.init(gpa);
    defer e.deinit();
    if (!tb) e.root.tb_files = null;
    const eng = e.engine();
    const jl = try ert_test.readGolden(gpa, "corpus2.jsonl");
    defer gpa.free(jl);
    var ran: u32 = 0;
    var differ: u32 = 0;
    for (scenarios) |name| {
        var lines = std.mem.splitScalar(u8, jl, '\n');
        var start: fen.Description = undefined;
        var depth: u32 = 0;
        var played: [16]fen.UciMove = undefined;
        var n: usize = 0;
        while (lines.next()) |text| {
            if (text.len == 0) continue;
            const parsed = try std.json.parseFromSlice(std.json.Value, gpa, text, .{});
            defer parsed.deinit();
            const o = parsed.value.object;
            if (!std.mem.eql(u8, o.get("scenario").?.string, name)) continue;
            if (o.get("search") == null) {
                start = try fen.parse(o.get("fen").?.string);
                // Setup mode gives the rights the board allows (none in these endings).
                start.castling = @import("adapt_setup.zig").rightsFromBoard(&start.board);
                depth = @intCast(o.get("depth").?.integer);
                continue;
            }
            const want = ert_test.expectedOf(parsed.value);
            if (eng.setPosition(&start, .setup, played[0..n])) |why| {
                std.debug.print("engine tb: {s}: position rejected: {s}\n", .{ name, why });
                return error.Rejected;
            }
            var cap: Capture = .{};
            var sig: uci_engine.Signals = .{};
            const r = eng.search(&.{ .depth = depth }, &sig, .{ .ctx = &cap, .lineFn = Capture.lineFn });
            const best = r.best orelse return error.NoMove;
            var mb: [5]u8 = undefined;
            const got = fen.formatMove(best, &mb);
            const line = e.root.lineHex();
            const ok = std.mem.eql(u8, got, want.played) and e.root.nodes == want.nodes and e.root.makes == want.makes and std.mem.eql(u8, &line, want.line);
            ran += 1;
            if (!ok) differ += 1;
            std.debug.print("engine tb{s}: {s} search {d}: played {s} ({s}), nodes {d} ({d}), makes {d} ({d}), line {s}\n{s}", .{ if (tb) "" else " (files unbound)", name, o.get("search").?.integer, got, want.played, e.root.nodes, want.nodes, e.root.makes, want.makes, if (std.mem.eql(u8, &line, want.line)) "equal" else "differs", cap.text() });
            played[n] = try fen.parseMove(want.played);
            n += 1;
        }
    }
    return .{ .ran = ran, .differ = differ };
}

test "engine: the embedded tablebases: the KRK, KQK, KPK and promotion-race searches of tests/golden/corpus2.jsonl through position fen ... moves and go depth N" {
    const gpa = std.testing.allocator;
    const r = try corpus2ThroughEngine(gpa, &.{ "krk-d4", "kqk-d4", "kpk-d4", "promotion-race-d5" }, true);
    std.debug.print("engine tb: {d} searches, {d} differ\n", .{ r.ran, r.differ });
    try std.testing.expectEqual(@as(u32, 18), r.ran);
    try std.testing.expectEqual(@as(u32, 0), r.differ);
}

test "engine: without the tablebase files the KRK position is searched, unlike the original" {
    const gpa = std.testing.allocator;
    const r = try corpus2ThroughEngine(gpa, &.{"krk-d4"}, false);
    try std.testing.expect(r.ran >= 1);
    try std.testing.expect(r.differ >= 1);
}

test "engine: a tablebase move is reported with its score and an info string" {
    const gpa = std.testing.allocator;
    var e = try engine_mod.Engine.init(gpa);
    defer e.deinit();
    const eng = e.engine();
    const d = try fen.parse("8/5k2/8/8/3R4/8/5K2/8 w - - 0 1");
    try std.testing.expect(eng.setPosition(&d, .setup, &.{}) == null);
    var cap: Capture = .{};
    var sig: uci_engine.Signals = .{};
    const r = eng.search(&.{ .depth = 4 }, &sig, .{ .ctx = &cap, .lineFn = Capture.lineFn });
    var mb: [5]u8 = undefined;
    std.debug.print("engine tb: KRK go depth 4: bestmove {s}\n{s}", .{ fen.formatMove(r.best.?, &mb), cap.text() });
    try std.testing.expectEqualStrings("d4e4", fen.formatMove(r.best.?, &mb));
    // Rd4-e4 scores 19978: the opponent is mated after ten more of its moves.
    try std.testing.expect(std.mem.indexOf(u8, cap.text(), "score mate 11 nodes 0 nps 0 ") != null);
    try std.testing.expect(std.mem.indexOf(u8, cap.text(), "info string tablebase move") != null);
}
