//! A game as long as the original can play: every search of tests/golden/longgame.jsonl
//! through the joined engine's game-move path (src/engine_root.zig), compared on the move
//! played, node entries, makes and the line hash; and the same game through the UCI
//! engine (src/engine.zig), up to the original's last position and one ply past it.
//!
//! The game (tests/scenarios/longgame.json, made by tools/research/gamemove/longgame.py)
//! is 397 quiet moves from the start position: no capture, check, castling, promotion or
//! double pawn step, no position twice, a pawn step at least every 28 plies. The oracle
//! types them in the original's monitor mode and lets it play on in auto-play at Fixed
//! depth 3: three searches from game ply 258 (`long-ply258-d3`, past the 256 plies the port
//! once held of the irreversible-move flags DG:3490) and five from ply 397
//! (`long-ply397-d3`), the last at ply 401, the last position the original searches
//! (docs/arch/34-game-move-path.md, "How long a game can be").
//!
//! Each scenario starts from the oracle's DGROUP snapshot at main 0000:0526 of its first
//! search, with the far segment 5A7B and the main hash tables' non-zero slots from the
//! subtree file of that search's first node (tests/golden/whole/longgame/, recorded with
//! `--snapshot main --snapshot prepared --subtree 1`); its later searches follow the
//! program's move and the auto-play turn. The first search's last irreversible ply DG:7464
//! (find_last_irreversible_ply, 0000:887E, which reads DG:3490 at game plies 230..258 and
//! 371..397 here), and the root ply DG:A000 it writes, are compared with the oracle's
//! snapshot just after prepare_eval (`-s1-prepared.bin`). From game ply 300 the turn
//! routines slide the game record (owner decision 26, DEV-F19; src/gameslide.zig), so the
//! searches of long-ply397-d3 after its first run on a slid record and must still equal
//! the original's. After the search at ply 401 the program plays its move; where the
//! original's command loop ends the game (38C0:1974: the oracle, asked for more searches,
//! saw no further move), the engine plays on and searches again.

const std = @import("std");
const si = @import("state_image.zig");
const builtin = @import("builtin");
const ert = @import("engine_root.zig");
const ert_test = @import("engine_root_test.zig");
const sn = @import("searchnode.zig");
const fen = @import("fen.zig");
const pos = @import("position.zig");
const uci_engine = @import("uci_engine.zig");
const engine_mod = @import("engine.zig");

const R = ert_test.R;
const dir = "whole/longgame";

/// The far data segment 5A7B and the main hash tables' non-zero slots at the first node
/// entry of a search, from the oracle's subtree file of node 1 (as in
/// src/engine_root_corpus1_test.zig).
fn farFromSubtree(gpa: std.mem.Allocator, name: []const u8, far: *ert.Far, tables: *[2]sn.HashTable) !void {
    const compressed = try ert_test.readGolden(gpa, name);
    defer gpa.free(compressed);
    var in: std.Io.Reader = .fixed(compressed);
    const window = try gpa.alloc(u8, std.compress.zstd.default_window_len + std.compress.zstd.block_size_max);
    defer gpa.free(window);
    var zd = std.compress.zstd.Decompress.init(&in, window, .{});
    const raw = try zd.reader.allocRemaining(gpa, .limited(64 << 20));
    defer gpa.free(raw);
    if (!std.mem.eql(u8, raw[0..8], "MCSUBT1\x00")) return error.BadSubtree;
    @memcpy(far, raw[25 + 0x10000 ..][0..0x10000]);
    for (tables) |*x| x.clear();
    var i: usize = 25 + 0x20000;
    const n = std.mem.readInt(u32, raw[i..][0..4], .little);
    i += 4;
    for (0..n) |_| {
        const table = raw[i];
        const idx = std.mem.readInt(u32, raw[i + 1 ..][0..4], .little);
        tables[table].put(idx, raw[i + 5 ..][0..10].*);
        i += 15;
    }
}

fn word(img: []const u8, addr: u16) u16 {
    return std.mem.readInt(u16, img[addr..][0..2], .little);
}

const Totals = struct { ran: u32 = 0, matched: u32 = 0, unexpected: u32 = 0, nodes: u64 = 0, ended: u32 = 0, not_run: u32 = 0 };

/// Debug, at about 1,500 nodes a second, runs the searches up to 60,000 nodes (the first
/// four of long-ply397-d3: about 75 s) unless MCHESS_LONG_TESTS is set and not empty; the
/// other builds run all eight (414,542 nodes).
fn maxNodes(gpa: std.mem.Allocator) !?u64 {
    if (try std.testing.environ.containsUnempty(gpa, "MCHESS_LONG_TESTS")) return null;
    return if (builtin.mode == .debug) 60_000 else null;
}

fn runLongGame(gpa: std.mem.Allocator, s: *R, max_nodes: ?u64) !Totals {
    const known = try ert_test.readKnownFailures(gpa);
    defer gpa.free(known);
    const jl = try ert_test.readGolden(gpa, "longgame.jsonl");
    defer gpa.free(jl);
    var lines = std.mem.splitScalar(u8, jl, '\n');
    var scenario_buf: [64]u8 = undefined;
    var current: []const u8 = "";
    var skip = false;
    var last_ply: u16 = 0;
    var t: Totals = .{};
    while (lines.next()) |text| {
        if (text.len == 0) continue;
        const parsed = try std.json.parseFromSlice(std.json.Value, gpa, text, .{});
        defer parsed.deinit();
        const o = parsed.value.object;
        if (o.get("search") == null) {
            const d = o.get("dev003") orelse return error.GoldenNotDev003Move;
            try std.testing.expectEqualStrings("move", d.string);
            try std.testing.expectEqualStrings("zero", o.get("hash_tail").?.object.get("mode").?.string);
            continue;
        }
        const scenario = o.get("scenario").?.string;
        const search = o.get("search").?.integer;
        var name_buf: [160]u8 = undefined;
        var prepared: ?[2]u16 = null;
        if (!std.mem.eql(u8, scenario, current)) {
            @memcpy(scenario_buf[0..scenario.len], scenario);
            current = scenario_buf[0..scenario.len];
            skip = false;
            const snap = try ert_test.readGolden(gpa, try std.fmt.bufPrint(&name_buf, "{s}/{s}-s1-main.bin", .{ dir, scenario }));
            defer gpa.free(snap);
            si.fromImage(s, snap[0..0x10000], null);
            try farFromSubtree(gpa, try std.fmt.bufPrint(&name_buf, "{s}/{s}-s1-subtree-1.zst", .{ dir, scenario }), s.test_far, s.tables);
            si.refreshRecord(s);
            const prep = try ert_test.readGolden(gpa, try std.fmt.bufPrint(&name_buf, "{s}/{s}-s1-prepared.bin", .{ dir, scenario }));
            defer gpa.free(prep);
            prepared = .{ word(prep, 0x7464), word(prep, 0xA000) };
        } else {
            if (skip) continue;
            s.playMove();
            s.nextTurnAutoPlay();
            si.toImage(s); // the turn runs on the members (Stage B step 8, stage 4)
            if (s.failure) |f| {
                std.debug.print("longgame: {s} search {d}: the turn failed: {s}\n", .{ scenario, search, f });
                t.unexpected += 1;
                skip = true;
                continue;
            }
        }
        const want = ert_test.expectedOf(parsed.value);
        if (max_nodes) |mx| if (want.nodes > mx) {
            std.debug.print("longgame: {s} search {d}: {d} nodes, above the {d} this build runs (MCHESS_LONG_TESTS=1 runs all): it and the rest of the scenario not run\n", .{ scenario, search, want.nodes, mx });
            skip = true;
            t.not_run += 1;
            continue;
        };
        s.failure = null;
        s.trace = false;
        // The ply counted from the game's start: the held game ply plus the plies slid off.
        last_ply = word(s.test_img, 0x9FC8) + @as(u16, @intCast(s.dropped_plies));
        const out = s.search(.own);
        si.toImage(s);
        t.ran += 1;
        t.nodes += out.nodes;
        if (prepared) |w| {
            // Written only by find_last_irreversible_ply (0000:889E, 88A5) and New game.
            const got = [2]u16{ word(s.test_img, 0x7464), word(s.test_img, 0xA000) };
            std.debug.print("longgame: {s}: game ply {d}, last irreversible ply [7464] {d} (original {d}), root ply [A000] {d} ({d})\n", .{ scenario, last_ply, got[0], w[0], got[1], w[1] });
            if (!std.mem.eql(u16, &got, &w)) t.unexpected += 1;
        }
        const v = ert_test.verdictOf(s, out, want);
        var id_buf: [128]u8 = undefined;
        const id = try std.fmt.bufPrint(&id_buf, "whole-path-longgame:{s}:{d}", .{ scenario, search });
        if (ert_test.allEqual(v) and s.failure == null) {
            t.matched += 1;
            if (ert_test.knownFailure(known, id)) t.unexpected += 1;
            continue;
        }
        var mb: [5]u8 = undefined;
        std.debug.print("longgame: FIRST DIFFERENCE in {s}, search {d} (game ply {d}): played {s} ({s}), nodes {d} ({d}), makes {d} ({d}), line {s}{s}{s}\n", .{ scenario, search, last_ply, ert_test.moveText(out.best, &mb), want.played, out.nodes, want.nodes, out.makes, want.makes, if (v.line) "equal" else "differs", if (s.failure != null) "; " else "", s.failure orelse "" });
        if (!ert_test.knownFailure(known, id)) t.unexpected += 1;
        skip = true;
    }
    // The last search was at game ply 401: the program plays its move. The original's
    // command loop ends the game here, at move number 202 (38C0:1974); the engine, whose
    // record has been slid, takes the next move and searches it.
    if (!skip and last_ply == 401) {
        s.playMove();
        try std.testing.expect(s.failure == null);
        s.nextTurnAutoPlay();
        si.toImage(s);
        try std.testing.expect(s.failure == null);
        try std.testing.expect(s.dropped_plies > 0);
        try std.testing.expectEqual(@as(u64, 402), word(s.test_img, 0x9FC8) + s.dropped_plies);
        try std.testing.expectEqual(@as(u16, 0), word(s.test_img, 0xA6AE));
        const out = s.search(.own);
        si.toImage(s);
        try std.testing.expect(s.failure == null and out.best[0] != 0);
        var mb: [5]u8 = undefined;
        std.debug.print("longgame: past the original's end, game ply 402 (held as {d}): {s}, {d} nodes\n", .{ word(s.test_img, 0x9FC8) - 1, ert_test.moveText(out.best, &mb), out.nodes });
        t.ended += 1;
    }
    return t;
}

test "join-root: a game to the original's last searchable ply (tests/golden/longgame.jsonl: searches at game plies 258..260 and 397..401) through the game-move path" {
    const gpa = std.testing.allocator;
    const s = try R.init(gpa, ert_test.golden_slots);
    defer s.deinit();
    const max_nodes = try maxNodes(gpa);
    const t = try runLongGame(gpa, s, max_nodes);
    std.debug.print("longgame: {d} searches run ({d} nodes), {d} equal on all four values, {d} not run, {d} unexpected results; played on past ply 402: {s}\n", .{ t.ran, t.nodes, t.matched, t.not_run, t.unexpected, if (t.ended == 1) "yes" else "not reached" });
    try std.testing.expectEqual(@as(u32, 0), t.unexpected);
    if (max_nodes == null) {
        try std.testing.expectEqual(@as(u32, 8), t.ran);
        try std.testing.expectEqual(@as(u32, 1), t.ended);
    }
}

// ---------------------------------------------------------------------------
// Through the UCI engine
// ---------------------------------------------------------------------------

/// The golden files record DEV-001 uncorrected.
const E = engine_mod.EngineOf(pos.Fixes.original);

const Capture = struct {
    buf: [1 << 14]u8 = undefined,
    len: usize = 0,
    fn lineFn(ctx: ?*anyopaque, line: []const u8) void {
        const c: *Capture = @ptrCast(@alignCast(ctx.?));
        if (c.len + line.len + 1 > c.buf.len) c.len = 0;
        @memcpy(c.buf[c.len..][0..line.len], line);
        c.len += line.len;
        c.buf[c.len] = '\n';
        c.len += 1;
    }
    fn out(c: *Capture) uci_engine.Output {
        return .{ .ctx = c, .lineFn = lineFn };
    }
    fn text(c: *const Capture) []const u8 {
        return c.buf[0..c.len];
    }
};

/// The game of long-ply397-d3: its 397 set-up moves and the moves the original played in
/// its five searches (401 + 1 plies).
fn longGameMoves(gpa: std.mem.Allocator, moves: []fen.UciMove) !usize {
    const sc = try ert_test.readGolden(gpa, "../scenarios/longgame.json");
    defer gpa.free(sc);
    const parsed = try std.json.parseFromSlice(std.json.Value, gpa, sc, .{});
    defer parsed.deinit();
    var n: usize = 0;
    for (parsed.value.array.items) |item| {
        if (!std.mem.eql(u8, item.object.get("name").?.string, "long-ply397-d3")) continue;
        for (item.object.get("setup").?.array.items) |m| {
            moves[n] = try fen.parseMove(m.string);
            n += 1;
        }
    }
    const jl = try ert_test.readGolden(gpa, "longgame.jsonl");
    defer gpa.free(jl);
    var lines = std.mem.splitScalar(u8, jl, '\n');
    while (lines.next()) |text| {
        if (text.len == 0) continue;
        const p = try std.json.parseFromSlice(std.json.Value, gpa, text, .{});
        defer p.deinit();
        const o = p.value.object;
        if (o.get("search") == null or !std.mem.eql(u8, o.get("scenario").?.string, "long-ply397-d3")) continue;
        moves[n] = try fen.parseMove(o.get("played").?.string);
        n += 1;
    }
    return n;
}

test "engine: positions past 254 plies are accepted and searched, and so are positions past the original's last searchable ply (401): the engine plays on (DEV-F19)" {
    const gpa = std.testing.allocator;
    var moves: [410]fen.UciMove = undefined;
    const n = try longGameMoves(gpa, &moves);
    try std.testing.expectEqual(@as(usize, 402), n);
    var e = try E.init(gpa);
    defer e.deinit();
    e.reporting = false;
    const eng = e.engine();
    var sig: uci_engine.Signals = .{};
    var mb: [5]u8 = undefined;
    // The start position, and the same through Setup mode (`position fen`): Setup makes
    // the move number 1 and the game ply the side to move (src/setup.zig, 38C0:67F8-6851),
    // as start-up's first command loop does, so the original's end falls at the same ply.
    const starts = [_]struct { d: fen.Description, route: uci_engine.Route }{
        .{ .d = try fen.parse(fen.startpos), .route = .new_game },
        .{ .d = try fen.parse("rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1"), .route = .setup },
    };
    for (&starts) |*st| {
        // 300 plies, past the old limit of 254; 401, the last position the original
        // searches (Black's 201st move); 402, where the original's command loop ends the
        // game: the record is slid as the moves are replayed, and the game goes on.
        for ([_]usize{ 300, 401, 402 }) |k| {
            try std.testing.expect(eng.setPosition(&st.d, st.route, moves[0..k]) == null);
            var cap: Capture = .{};
            const r = eng.search(&.{ .depth = 2 }, &sig, cap.out());
            const b = r.best orelse {
                std.debug.print("{s}", .{cap.text()});
                return error.NoMove;
            };
            std.debug.print("longgame engine: {s}, {d} plies: bestmove {s}, {d} nodes, {d} plies slid off\n", .{ @tagName(st.route), k, fen.formatMove(b, &mb), e.root.nodes, e.root.dropped_plies });
            // After its move the program waits for the opponent's: the game is held.
            try std.testing.expectEqual(engine_mod.Phase.waiting, e.phase);
            // At their homes: the engine's commands leave the image as it was (Stage B step
            // 8, stage 6).
            const h = e.root.home();
            try std.testing.expectEqual(@as(u16, 0), @import("dgroup.zig").memWord(h, 0xA6AE));
            try std.testing.expectEqual(@as(u64, k + 1), @import("dgroup.zig").memWord(h, 0x9FC8) + e.root.dropped_plies);
        }
    }
}
