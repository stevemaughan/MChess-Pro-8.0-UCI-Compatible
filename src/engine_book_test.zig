//! The opening book through the UCI interface (src/engine.zig with `OwnBook` on): games of
//! tests/golden/book1.jsonl, the original's normal play with its tournament book on and
//! learning off (tools/oracle/oracle.py, `"book": "tournament"`), replayed as a GUI sends
//! them (`position startpos moves ...` growing by two plies, `go depth N`). The engine is
//! given the original's random input: `Seed` = the value srand had at start-up (the
//! emulator's tick count 17, or the scenario's `seed`). Every book move must be the
//! original's, with the random seed DG:2DC8 and the book-exit ply DG:9FBC after it as the
//! original left them; every search after the book must equal the original's on the
//! move, node entries, makes and line hash; and every position after the first must be
//! reached by continuing the held game.
//!
//! Also: the five illegal moves of the shipped book are refused by the legality guard,
//! and a game in which the draw falls on one of them ends in a legal move.

const std = @import("std");
const builtin = @import("builtin");
const fen = @import("fen.zig");
const pos = @import("position.zig");
const book = @import("book.zig");
const uci_engine = @import("uci_engine.zig");
const engine_mod = @import("engine.zig");
const engine_data = @import("engine_data.zig");
const ert_test = @import("engine_root_test.zig");
const dgroup = @import("dgroup.zig");

const E = engine_mod.EngineOf(pos.Fixes.original);

const Capture = struct {
    buf: [1 << 15]u8 = undefined,
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

fn newEngine(gpa: std.mem.Allocator, seed: i32) !*E {
    return newEngineBook(gpa, seed, .tournament);
}

fn newEngineBook(gpa: std.mem.Allocator, seed: i32, kind: uci_engine.BookKind) !*E {
    const e = try gpa.create(E);
    errdefer gpa.destroy(e);
    e.* = try E.init(gpa);
    var o: uci_engine.Options = .{};
    o.own_book = true;
    o.seed = seed;
    o.book = kind;
    e.engine().applyOptions(&o);
    return e;
}

const Counts = struct { book: u32 = 0, searches: u32 = 0, differ: u32 = 0, not_run: u32 = 0 };

/// Replays one scenario of book1.jsonl; returns the counts.
fn replay(gpa: std.mem.Allocator, scenario: []const u8, max_nodes: ?u64) !Counts {
    return replayFile(gpa, "book1.jsonl", scenario, max_nodes);
}

/// Replays one scenario of a golden file of normal play with the book on (book1.jsonl,
/// book2.jsonl): the header's `book` (absent: tournament) is the `Book` option, its
/// `program` (absent: Black) the side the program plays; returns the counts.
fn replayFile(gpa: std.mem.Allocator, file: []const u8, scenario: []const u8, max_nodes: ?u64) !Counts {
    const jl = try ert_test.readGolden(gpa, file);
    defer gpa.free(jl);
    var header: ?std.json.Parsed(std.json.Value) = null;
    defer if (header) |h| h.deinit();
    var records: std.ArrayList(std.json.Parsed(std.json.Value)) = .empty;
    defer {
        for (records.items) |r| r.deinit();
        records.deinit(gpa);
    }
    var lines = std.mem.splitScalar(u8, jl, '\n');
    while (lines.next()) |text| {
        if (text.len == 0) continue;
        const parsed = try std.json.parseFromSlice(std.json.Value, gpa, text, .{});
        const o = parsed.value.object;
        if (!std.mem.eql(u8, o.get("scenario").?.string, scenario)) {
            parsed.deinit();
            continue;
        }
        if (o.get("search") == null) header = parsed else try records.append(gpa, parsed);
    }
    const h = (header orelse return error.NoScenario).value.object;
    const depth: u32 = @intCast(h.get("depth").?.integer);
    const seed: i32 = switch (h.get("seed") orelse .null) {
        .integer => |v| @intCast(v),
        else => 17, // the emulator's BIOS tick count at start-up (DG:2DC8 = 11h)
    };
    const game_v = h.get("game").?.array.items;
    var game: [200]fen.UciMove = undefined;
    for (game_v, 0..) |m, i| game[i] = try fen.parseMove(m.string);
    const calls = h.get("book_calls").?.array.items;

    const kind: uci_engine.BookKind = switch (h.get("book") orelse .null) {
        .string => |s| uci_engine.BookKind.parse(s) orelse return error.BadBook,
        else => .tournament,
    };
    const program_white = switch (h.get("program") orelse .null) {
        .string => |s| std.mem.eql(u8, s, "w"),
        else => false,
    };
    const e = try newEngineBook(gpa, seed, kind);
    defer {
        e.deinit();
        gpa.destroy(e);
    }
    const eng = e.engine();
    const start = try fen.parse(fen.startpos);
    var c: Counts = .{};
    var next_search: usize = 0;
    const continued0 = e.continued;
    var asked: u32 = 0;
    // The program's moves are at the odd plies when it is Black, the even plies when White.
    var ply: usize = if (program_white) 0 else 1;
    while (ply < game_v.len) : (ply += 2) {
        // The original's book call in mode 1 at this ply, if any.
        var call: ?std.json.ObjectMap = null;
        for (calls) |cv| {
            const co = cv.object;
            if (co.get("mode").?.integer == 1 and co.get("ply").?.integer == @as(i64, @intCast(ply))) call = co;
        }
        const is_book = if (call) |co| co.get("move") != null else false;
        var want_nodes: u64 = 0;
        if (!is_book) {
            if (next_search >= records.items.len) break;
            const want = ert_test.expectedOf(records.items[next_search].value);
            if (max_nodes) |mx| if (want.nodes > mx) {
                c.not_run += 1;
                break;
            };
            want_nodes = want.nodes;
        }
        if (eng.setPosition(&start, .new_game, game[0..ply])) |why| {
            std.debug.print("book {s}: ply {d}: position rejected: {s}\n", .{ scenario, ply, why });
            return error.Rejected;
        }
        asked += 1;
        var cap: Capture = .{};
        var sig: uci_engine.Signals = .{};
        const r = eng.search(&.{ .depth = depth }, &sig, cap.out());
        // Stage B step 8, stage 5: book_probe, its legality test and play_best_move from
        // main, like every other callee, run in the node domain: no image bracket.
        try std.testing.expectEqual(@as(u64, 0), e.root.search_exits);
        var mb: [5]u8 = undefined;
        const played = if (r.best) |b| fen.formatMove(b, &mb) else "none";
        // At their homes (Stage B step 8, stage 6: the engine's commands leave the image
        // as it was; read through `EngineRoot.Home`, which changes nothing).
        const seed_now = dgroup.memDword(e.root.home(), 0x2DC8);
        const exit_now: i16 = @bitCast(dgroup.memWord(e.root.home(), 0x9FBC));
        var ok = true;
        if (call) |co| {
            const want_seed: u32 = @intCast(co.get("seed_after").?.integer);
            const want_exit: i16 = @intCast(co.get("exit_out").?.integer);
            if (seed_now != want_seed or exit_now != want_exit) ok = false;
        }
        if (is_book) {
            const want_move = call.?.get("move").?.string;
            c.book += 1;
            if (!std.mem.eql(u8, played, want_move) or std.mem.indexOf(u8, cap.text(), "info string book move") == null) ok = false;
            std.debug.print("book {s}: ply {d}: book move {s} ({s}), seed {X} ({X}), exit ply {d}\n", .{ scenario, ply, played, want_move, seed_now, call.?.get("seed_after").?.integer, exit_now });
        } else {
            const want = ert_test.expectedOf(records.items[next_search].value);
            next_search += 1;
            c.searches += 1;
            const line = e.root.lineHex();
            if (!std.mem.eql(u8, played, want.played) or e.root.nodes != want.nodes or e.root.makes != want.makes or !std.mem.eql(u8, &line, want.line)) ok = false;
            std.debug.print("book {s}: ply {d}: search: played {s} ({s}), nodes {d} ({d}), makes {d} ({d}), line {s}, seed {X}, exit ply {d}\n", .{ scenario, ply, played, want.played, e.root.nodes, want.nodes, e.root.makes, want.makes, if (std.mem.eql(u8, &line, want.line)) "equal" else "differs", seed_now, exit_now });
        }
        if (!ok) {
            c.differ += 1;
            std.debug.print("{s}", .{cap.text()});
            break;
        }
    }
    if (asked > 1 and e.continued - continued0 != asked - 1) {
        std.debug.print("book {s}: {d} positions, {d} continued\n", .{ scenario, asked, e.continued - continued0 });
        c.differ += 1;
    }
    return c;
}

test "book: games of tests/golden/book1.jsonl through the UCI interface with OwnBook on: the original's book moves, seeds and exit plies, then its searches" {
    const gpa = std.testing.allocator;
    const mx: ?u64 = if (builtin.mode == .debug) 3_000 else null;
    const names = [_][]const u8{ "book-sicilian-black-d4", "book-qgd-black-d4", "book-seed1000-black-d4" };
    var bad: u32 = 0;
    var books: u32 = 0;
    var searches: u32 = 0;
    for (names) |n| {
        const r = try replay(gpa, n, mx);
        std.debug.print("book {s}: {d} book moves, {d} searches, {d} differ, {d} not run in this build\n", .{ n, r.book, r.searches, r.differ, r.not_run });
        bad += r.differ;
        books += r.book;
        searches += r.searches;
    }
    try std.testing.expectEqual(@as(u32, 0), bad);
    try std.testing.expect(books >= 10);
    if (builtin.mode != .debug) try std.testing.expect(searches >= 9);
}

test "book: games of tests/golden/book2.jsonl (the Standard and Variety books, and the program White) through the UCI interface with OwnBook on and Book as recorded" {
    const gpa = std.testing.allocator;
    const mx: ?u64 = if (builtin.mode == .debug) 3_000 else null;
    const names = [_][]const u8{ "book-std-fourknights-black-d4", "book-std-grunfeld-black-d4", "book-var-sicilian-black-d4", "book-var-qgd-black-d4", "book-tour-white-d4" };
    var bad: u32 = 0;
    var books: u32 = 0;
    var searches: u32 = 0;
    for (names) |n| {
        const r = try replayFile(gpa, "book2.jsonl", n, mx);
        std.debug.print("book2 {s}: {d} book moves, {d} searches, {d} differ, {d} not run in this build\n", .{ n, r.book, r.searches, r.differ, r.not_run });
        bad += r.differ;
        books += r.book;
        searches += r.searches;
    }
    try std.testing.expectEqual(@as(u32, 0), bad);
    try std.testing.expectEqual(@as(u32, 14), books);
    if (builtin.mode != .debug) try std.testing.expectEqual(@as(u32, 20), searches);
}

test "book: with OwnBook off (the default) the start position is searched, as before the book was joined" {
    const gpa = std.testing.allocator;
    const e = try gpa.create(E);
    defer gpa.destroy(e);
    e.* = try E.init(gpa);
    defer e.deinit();
    const eng = e.engine();
    const start = try fen.parse(fen.startpos);
    const m = [_]fen.UciMove{try fen.parseMove("e2e4")};
    try std.testing.expect(eng.setPosition(&start, .new_game, &m) == null);
    var cap: Capture = .{};
    var sig: uci_engine.Signals = .{};
    const r = eng.search(&.{ .depth = 2 }, &sig, cap.out());
    try std.testing.expect(r.best != null);
    try std.testing.expect(e.root.nodes > 0);
    try std.testing.expect(std.mem.indexOf(u8, cap.text(), "book move") == null);
}

test "book: the same Seed gives the same book moves; position fen never uses the book (Setup mode sets DG:70E4)" {
    const gpa = std.testing.allocator;
    var firsts: [2][4]fen.UciMove = undefined;
    for (0..2) |k| {
        const e = try newEngine(gpa, 4242);
        defer {
            e.deinit();
            gpa.destroy(e);
        }
        const eng = e.engine();
        const start = try fen.parse(fen.startpos);
        var game: [8]fen.UciMove = undefined;
        var n: usize = 0;
        // The program White from the start position, the opponent answering 1...e5 etc.
        const replies = [_][]const u8{ "e7e5", "b8c6", "g8f6" };
        for (0..4) |i| {
            try std.testing.expect(eng.setPosition(&start, .new_game, game[0..n]) == null);
            var cap: Capture = .{};
            var sig: uci_engine.Signals = .{};
            const r = eng.search(&.{ .depth = 2 }, &sig, cap.out());
            firsts[k][i] = r.best.?;
            game[n] = r.best.?;
            n += 1;
            if (i < replies.len) {
                // The reply only if it is legal after the program's move: else stop.
                game[n] = try fen.parseMove(replies[i]);
                if (eng.setPosition(&start, .new_game, game[0 .. n + 1]) != null) break;
                n += 1;
            } else break;
        }
    }
    for (0..4) |i| try std.testing.expect(firsts[0][i].eql(firsts[1][i]));
    // A FEN: Setup mode disables the book.
    const e = try newEngine(gpa, 17);
    defer {
        e.deinit();
        gpa.destroy(e);
    }
    const d = try fen.parse("rnbqkbnr/pppppppp/8/8/4P3/8/PPPP1PPP/RNBQKBNR b KQkq - 0 1");
    try std.testing.expect(e.engine().setPosition(&d, .setup, &.{}) == null);
    var cap: Capture = .{};
    var sig: uci_engine.Signals = .{};
    _ = e.engine().search(&.{ .depth = 2 }, &sig, cap.out());
    try std.testing.expect(std.mem.indexOf(u8, cap.text(), "book move") == null);
}

/// The five moves the shipped book lists that pass the original's move check 4793:59FE
/// but are not legal (found by walking the book from the start position with an
/// independent move generator): FEN, move, grade, the line that reaches it.
const illegal_book_moves = [_]struct { fen: []const u8, move: []const u8, grade: u8, line: []const u8 }{
    .{ .fen = "rnbqk2r/ppp2ppp/1b3n2/3P4/1PB1pP2/8/P1PPN1PP/RNBQK2R w KQkq - 2 7", .move = "e1g1", .grade = 0, .line = "e2e4 e7e5 f1c4 f8c5 b2b4 c5b6 f2f4 d7d5 e4d5 e5e4 g1e2 g8f6" },
    .{ .fen = "rnbqkb1r/1pp2ppp/4pn2/3p4/2P5/1p3NP1/PB1PPPBP/RN1QK2R b KQkq - 1 7", .move = "e8g8", .grade = 3, .line = "g1f3 g8f6 g2g3 d7d5 c2c4 e7e6 b2b3 a7a5 f1g2 a5a4 c1a3 a4b3 a3b2" },
    .{ .fen = "r2qkb1r/pppB1ppp/3p1n2/8/3nP3/2N5/PPP2PPP/R1BQ1RK1 b kq - 0 8", .move = "c7c6", .grade = 3, .line = "d2d4 d7d6 e2e4 g8f6 b1c3 e7e5 g1f3 e5d4 f3d4 b8c6 f1b5 c8d7 e1g1 c6d4 b5d7" },
    .{ .fen = "r1bq1rk1/1p2ppbp/1npp2pn/p5N1/P2PP2P/1BN2Q2/1PP2PP1/R1B1K2R b KQ h3 0 10", .move = "f7f5", .grade = 0, .line = "d2d4 g7g6 e2e4 f8g7 b1c3 d7d6 g1f3 b8d7 f1c4 d7b6 c4b3 c7c6 a2a4 a7a5 f3g5 g8h6 d1f3 e8g8 h2h4" },
    .{ .fen = "1r2n3/pB1k2q1/3pn1p1/6N1/1P4Q1/2r1N1P1/P4P1P/4R1K1 b - - 6 35", .move = "e6c7", .grade = 3, .line = "d2d4 f7f5 g1f3 g8f6 g2g3 g7g6 f1g2 f8g7 c2c4 e8g8 b1c3 d7d6 d4d5 c7c6 e1g1 e7e5 d5e6 c8e6 d1d3 b8a6 f3g5 e6c8 c1f4 f6e8 f1d1 h7h6 g5f3 c8e6 d3e3 e6c4 f4h6 g7h6 e3h6 d8f6 f3g5 f6g7 h6h4 c4f7 e2e4 f5e4 c3e4 f7d5 d1d5 c6d5 e4c3 a6c7 c3d5 f8f5 a1d1 e8f6 d5e3 f5c5 b2b4 c5c3 h4d4 f6e8 g2d5 g8f8 d4f4 f8e7 d1e1 e7d8 d5b7 a8b8 g5f7 d8d7 f4g4 c7e6 f7g5" },
};

/// Plays `line` from the start position through the engine's auto-play rebuild and
/// returns the engine at main 0526 of that position, the program to move.
fn engineAt(gpa: std.mem.Allocator, line: []const u8, seed: i32) !*E {
    const e = try newEngine(gpa, seed);
    errdefer {
        e.deinit();
        gpa.destroy(e);
    }
    var ms: [80]fen.UciMove = undefined;
    var n: usize = 0;
    var it = std.mem.tokenizeScalar(u8, line, ' ');
    while (it.next()) |t| : (n += 1) ms[n] = try fen.parseMove(t);
    const start = try fen.parse(fen.startpos);
    if (e.engine().setPosition(&start, .new_game, ms[0..n])) |why| {
        std.debug.print("book: line rejected: {s}\n", .{why});
        return error.Rejected;
    }
    return e;
}

test "book: the legality guard refuses the five illegal moves the book lists (each passes the original's own check 4793:59FE)" {
    const gpa = std.testing.allocator;
    for (illegal_book_moves) |c| {
        const e = try engineAt(gpa, c.line, 17);
        defer {
            e.deinit();
            gpa.destroy(e);
        }
        // The position is the FEN's: the domain's (the engine's commands run on it).
        const p = e.root.node.dom.p;
        const side: pos.Side = if (e.root.home().get(0x8DDE) == 0) .white else .black;
        const bp = book.BookPosition.fromPosition(&p, side);
        const entry = book.lookup(&engine_data.book_files, book.bookKey(bp)) orelse return error.NotInBook;
        const list = book.readList(&engine_data.book_files, entry);
        const m = try fen.parseMove(c.move);
        var seen = false;
        var prefix: u16 = 0;
        for (list.words[0..list.count]) |w| {
            const from: u6 = @truncate(w);
            const to: u6 = @truncate(w >> 6);
            if (prefix == 0 and from == to) {
                prefix = from;
                continue;
            }
            const mv: book.BookMove = (prefix << 12) | (w & 0x0FFF);
            prefix = 0;
            const real = book.realMove(&p.board, mv, side);
            if (real.from != m.from or real.to != m.to) continue;
            seen = true;
            const ep_file: u8 = if (p.ep_square_by_ply[1] != 0) p.ep_square_by_ply[1] % 10 else 0;
            _ = ep_file;
            const legal = e.root.bookMoveLegal(real, side);
            std.debug.print("book: illegal book move {s} after {d} plies: in the list, guard says {s}\n", .{ c.move, std.mem.count(u8, c.line, " ") + 1, if (legal) "legal" else "illegal" });
            try std.testing.expect(!legal);
        }
        try std.testing.expect(seen);
    }
}

test "book: a draw that falls on an illegal book move is a book miss: the engine searches and plays a legal move" {
    const gpa = std.testing.allocator;
    // The drawable cases (grade 3): find a seed whose first draw at that position picks
    // the illegal move, then let the engine play there.
    var cases: u32 = 0;
    for (illegal_book_moves) |c| {
        if (c.grade == 0) continue;
        const probe_e = try engineAt(gpa, c.line, 17);
        const p = probe_e.root.node.dom.p;
        const side: pos.Side = if (probe_e.root.home().get(0x8DDE) == 0) .white else .black;
        probe_e.deinit();
        gpa.destroy(probe_e);
        const bp = book.BookPosition.fromPosition(&p, side);
        const entry = book.lookup(&engine_data.book_files, book.bookKey(bp)).?;
        const list = book.readList(&engine_data.book_files, entry);
        const d = book.buildDraw(bp, &list, .{});
        const m = try fen.parseMove(c.move);
        // A seed s with the tournament draw from s landing on the illegal move.
        var seed: ?u32 = null;
        var s: u32 = 0;
        while (s < 65536) : (s += 1) {
            var r: book.Rand = .{ .seed = s };
            const mv = book.choose(&d, .{}, &r) orelse continue;
            const real = book.realMove(&p.board, mv, side);
            if (real.from == m.from and real.to == m.to) {
                seed = s;
                break;
            }
        }
        const sd = seed orelse return error.NoSeedDrawsIt;
        // The engine at that position, the seed in DG:2DC8 just before the program's turn.
        const e = try engineAt(gpa, c.line, 17);
        defer {
            e.deinit();
            gpa.destroy(e);
        }
        dgroup.memSetDword(e.root.home(), 0x2DC8, sd);
        var cap: Capture = .{};
        var sig: uci_engine.Signals = .{};
        const r = e.engine().search(&.{ .depth = 2 }, &sig, cap.out());
        try std.testing.expectEqual(@as(u64, 0), e.root.search_exits); // the book miss too
        var mb: [5]u8 = undefined;
        const best = r.best orelse return error.NoMove;
        std.debug.print("book: {s} drawn with seed {d}: bestmove {s}\n{s}", .{ c.move, sd, fen.formatMove(best, &mb), cap.text() });
        try std.testing.expect(std.mem.indexOf(u8, cap.text(), "info string book miss") != null);
        try std.testing.expect(e.root.nodes > 0);
        try std.testing.expect(!std.mem.eql(u8, fen.formatMove(best, &mb), c.move));
        // Legal: the engine accepts the line with the move played.
        var ms: [80]fen.UciMove = undefined;
        var n: usize = 0;
        var it = std.mem.tokenizeScalar(u8, c.line, ' ');
        while (it.next()) |t| : (n += 1) ms[n] = try fen.parseMove(t);
        ms[n] = best;
        const start = try fen.parse(fen.startpos);
        try std.testing.expect(e.engine().setPosition(&start, .new_game, ms[0 .. n + 1]) == null);
        cases += 1;
    }
    try std.testing.expectEqual(@as(u32, 3), cases);
}

// ---- Seed at the start of every game (DEV-F13; review findings 7 and 8) ------------------

/// An engine as the UCI shell starts one (src/uci.zig `Session.init`): the default options
/// applied, then the start position, a rebuild made before the GUI sends anything.
fn shellEngine(gpa: std.mem.Allocator, io: ?std.Io) !*E {
    const e = try gpa.create(E);
    errdefer gpa.destroy(e);
    e.* = try E.init(gpa);
    errdefer e.deinit();
    e.io = io;
    const o: uci_engine.Options = .{};
    e.engine().applyOptions(&o);
    const start = try fen.parse(fen.startpos);
    if (e.engine().setPosition(&start, .new_game, &.{}) != null) return error.Rejected;
    return e;
}

fn freeShell(gpa: std.mem.Allocator, e: *E) void {
    e.deinit();
    gpa.destroy(e);
}

/// `go depth 1` on the position held; the move must come from the book.
fn bookGo(e: *E) !fen.UciMove {
    var cap: Capture = .{};
    var sig: uci_engine.Signals = .{};
    const r = e.engine().search(&.{ .depth = 1 }, &sig, cap.out());
    if (std.mem.indexOf(u8, cap.text(), "info string book move") == null) return error.NotABookMove;
    return r.best orelse error.NoMove;
}

/// The first book move of the first game after start-up: each of `opts` applied in turn
/// (as successive `setoption`s), then `ucinewgame` if asked (the shell's: the engine's
/// newGame and the start position), then `position startpos`, then `seed_late`, if given,
/// as a `Seed` sent between that `position` and the `go`.
fn firstBookMove(gpa: std.mem.Allocator, opts: []const uci_engine.Options, ucinewgame: bool, seed_late: ?i32) !fen.UciMove {
    const e = try shellEngine(gpa, null);
    defer freeShell(gpa, e);
    for (opts) |*o| e.engine().applyOptions(o);
    const start = try fen.parse(fen.startpos);
    if (ucinewgame) {
        e.engine().newGame();
        if (e.engine().setPosition(&start, .new_game, &.{}) != null) return error.Rejected;
    }
    if (e.engine().setPosition(&start, .new_game, &.{}) != null) return error.Rejected;
    if (seed_late) |s| {
        var o = opts[opts.len - 1];
        o.seed = s;
        e.engine().applyOptions(&o);
    }
    return bookGo(e);
}

test "book: Seed holds from the first game after start-up: Seed and OwnBook in either order, with Book Tournament or Variety, give the book move ucinewgame gives" {
    const gpa = std.testing.allocator;
    for ([_]uci_engine.BookKind{ .tournament, .variety }) |kind| {
        const all: uci_engine.Options = .{ .own_book = true, .book = kind, .seed = 42 };
        const ref = try firstBookMove(gpa, &.{all}, true, null);
        const seed_first = try firstBookMove(gpa, &.{ .{ .seed = 42 }, .{ .seed = 42, .own_book = true }, all }, false, null);
        const book_first = try firstBookMove(gpa, &.{ .{ .own_book = true }, .{ .own_book = true, .book = kind }, all }, false, null);
        // A Seed sent between `position` and the first `go` counts too.
        const late = try firstBookMove(gpa, &.{.{ .own_book = true, .book = kind }}, false, 42);
        var b: [4][5]u8 = undefined;
        std.debug.print("book seed: {s}: Seed 42 after ucinewgame {s}; first game, Seed first {s}, OwnBook first {s}, Seed after position {s}\n", .{ kind.name(), fen.formatMove(ref, &b[0]), fen.formatMove(seed_first, &b[1]), fen.formatMove(book_first, &b[2]), fen.formatMove(late, &b[3]) });
        try std.testing.expect(seed_first.eql(ref));
        try std.testing.expect(book_first.eql(ref));
        try std.testing.expect(late.eql(ref));
    }
    // The seed decides the draw here: Seed 42 and Seed 17 (the start-up value, which the first
    // game drew from before 2026-11-22) open differently in the Tournament book.
    const s42 = try firstBookMove(gpa, &.{.{ .own_book = true, .seed = 42 }}, true, null);
    const s17 = try firstBookMove(gpa, &.{.{ .own_book = true, .seed = 17 }}, true, null);
    try std.testing.expect(!s42.eql(s17));
}

test "book: a Seed set after the game's first search waits for the next game" {
    const gpa = std.testing.allocator;
    const start = try fen.parse(fen.startpos);
    var second: [2]fen.UciMove = undefined;
    for (0..2) |k| {
        const e = try shellEngine(gpa, null);
        defer freeShell(gpa, e);
        const o: uci_engine.Options = .{ .own_book = true, .seed = 42 };
        e.engine().applyOptions(&o);
        try std.testing.expect(e.engine().setPosition(&start, .new_game, &.{}) == null);
        const m1 = try bookGo(e);
        if (k == 1) {
            const o7: uci_engine.Options = .{ .own_book = true, .seed = 7 };
            e.engine().applyOptions(&o7);
        }
        const game = [_]fen.UciMove{ m1, try fen.parseMove("c7c5") };
        try std.testing.expect(e.engine().setPosition(&start, .new_game, &game) == null);
        try std.testing.expect(e.by_continuation);
        second[k] = try bookGo(e);
        if (k == 1) {
            // The next game starts with Seed 7.
            e.engine().newGame();
            try std.testing.expect(e.engine().setPosition(&start, .new_game, &.{}) == null);
            try std.testing.expectEqual(@as(u32, 7), dgroup.memDword(e.root.home(), 0x2DC8));
        }
    }
    try std.testing.expect(second[0].eql(second[1]));
}

test "book: with Seed -1 the first game after start-up is seeded from the clock (startSeed), not from the start-up value 17" {
    const gpa = std.testing.allocator;
    const e = try shellEngine(gpa, std.testing.io);
    defer freeShell(gpa, e);
    const t0 = e.startSeed();
    const o: uci_engine.Options = .{ .own_book = true };
    e.engine().applyOptions(&o);
    const start = try fen.parse(fen.startpos);
    try std.testing.expect(e.engine().setPosition(&start, .new_game, &.{}) == null);
    const live: u16 = @intCast(dgroup.memDword(e.root.home(), 0x2DC8));
    const t1 = e.startSeed();
    std.debug.print("book seed: Seed -1: clock ticks {d} to {d}, live seed {d}\n", .{ t0, t1, live });
    // A tick is 1/18.2 s: the seed written lies between the two readings (the low word wraps).
    try std.testing.expect(live -% t0 <= t1 -% t0);
}
