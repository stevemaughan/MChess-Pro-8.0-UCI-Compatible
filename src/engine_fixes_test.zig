//! The class C fixes at engine level (AGENTS.md sections 9.2 and 11, item 4): for each
//! switch of `pos.Fixes`, a position that the engine with every fix off
//! (`EngineOf(pos.Fixes.original)`, the original the golden files record) and the engine
//! with that one switch on search differently: the move, the node count or the score. A
//! `pos.Fixes` with one field true is the engine with that fix alone, so a difference is
//! that fix's and no other's.
//!
//! The measurement of how much the fixes change play (docs/BUG_TRIAGE.md, "Measured,
//! 2026-11-20") is the last test here: every search of the golden files, from its
//! position, by the original and by each one-switch engine and the shipped engine. It is
//! long (several minutes on 16 threads) and runs only with MCHESS_MEASURE_FIXES set.

const std = @import("std");
const builtin = @import("builtin");
const fen = @import("fen.zig");
const pos = @import("position.zig");
const uci_engine = @import("uci_engine.zig");
const engine_mod = @import("engine.zig");
const adapt_setup = @import("adapt_setup.zig");
const build_options = @import("build_options");

/// The class C switches of `pos.Fixes` other than DEV-001 (owner decisions 11 and 27).
pub const switches = [_][]const u8{
    "dev004_promotion_capture_score",
    "dev005_bishop_check_score",
    "dev007_black_pawn_push",
    "dev008_castling_mark",
    "dev010_passed_h_pawn",
    "dev011_blocked_wing_table",
    "dev012_white_pawn_table",
    "dev017_king_square",
    "dev019_activity_mirror",
    "dev020_threat_table_index",
    "dev021_knight_escape_order",
    "dev022_captured_pieces",
    "dev023_pinned_bishop",
    "dev024_attacked_counter",
    "dev026_promotion_prefix",
    "dev027_loader_key",
    "dev031_scaling_overflow",
    "dev035_ply2_mate",
    "dev040_hanging_ray_start",
    "dev041_threat_mirror",
    "dev043_prescore_sign",
    "dev046_reply_sign",
    "dev050_corner_rook_capture",
    "dev052_line_tables",
    "dev053_line_tables_other",
    "dev054_unstoppable_passer_mirror",
    "dev055_passer_block_extra_test",
    "dev056_king_ring_wrap",
    "dev058_lifted_knight_entry",
    "dev059_opposite_bishops_flag",
    "dev062_king_test_rank",
    "dev067_illegal_root_sentinel",
};

/// Switches of `pos.Fixes` that no routine reads yet, so no search can show them: not
/// listed above, and named here so that the omission is visible. Owner decision 30
/// (2026-11-20): DEV-019, DEV-021 and DEV-052 are being implemented; each task moves its
/// own name to `switches` and adds its engine-level case when its fix lands. All three
/// have landed (DEV-021 and DEV-052: task fix-021-052); none is pending.
pub const pending = [_][]const u8{};

fn isPending(comptime n: []const u8) bool {
    for (pending) |s| {
        if (std.mem.eql(u8, s, n)) return true;
    }
    return false;
}

/// Every fix off but the one named.
pub fn only(comptime name: []const u8) pos.Fixes {
    var f = pos.Fixes.original;
    @field(f, name) = true;
    return f;
}

comptime {
    @setEvalBranchQuota(100_000);
    // Every switch of pos.Fixes is either DEV-001 or listed here.
    for (@typeInfo(pos.Fixes).@"struct".field_names) |n| {
        if (std.mem.eql(u8, n, "dev001_ep_hash_square")) continue;
        if (isPending(n)) continue;
        var found = false;
        for (switches) |s| {
            if (std.mem.eql(u8, s, n)) found = true;
        }
        if (!found) @compileError("engine_fixes_test: switch not listed: " ++ n);
    }
}

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
};

pub const Result = struct {
    move: [5]u8 = @splat(0),
    move_len: u8 = 0,
    nodes: u64 = 0,
    /// The raw score of the last info line that has one (`Engine.last_score`, the
    /// evaluation's units: the line shows it halved, DEV-F23), as "raw N"; empty if none.
    /// Raw, so that two scores one apart, which the line can show alike, still differ.
    score: [16]u8 = @splat(0),
    score_len: u8 = 0,
    ponder: [5]u8 = @splat(0),
    ponder_len: u8 = 0,
    rejected: bool = false,
    /// The search's makes and line hash (`EngineRoot.makes`, `EngineRoot.lineHex`), for the DEV-067
    /// measurement; `same` does not compare them.
    makes: u64 = 0,
    line: [64]u8 = @splat(0),

    fn moveText(r: *const Result) []const u8 {
        return r.move[0..r.move_len];
    }
    fn ponderText(r: *const Result) []const u8 {
        return r.ponder[0..r.ponder_len];
    }
    fn scoreText(r: *const Result) []const u8 {
        return r.score[0..r.score_len];
    }
    fn same(a: *const Result, b: *const Result) bool {
        return a.rejected == b.rejected and std.mem.eql(u8, a.moveText(), b.moveText()) and a.nodes == b.nodes and std.mem.eql(u8, a.scoreText(), b.scoreText());
    }
};

/// One search: `position fen <f> [moves ...]` (Setup mode's route) and `go depth <depth>`,
/// on the engine `e`.
fn searchOn(e: anytype, f: []const u8, moves: []const []const u8, depth: u32) !Result {
    var d = try fen.parse(f);
    // A FEN without a castling field takes the rights the board allows, as Setup mode
    // gives them (the golden files' positions carry no castling field).
    if (std.mem.count(u8, f, " ") < 2) d.castling = adapt_setup.rightsFromBoard(&d.board);
    var ms: [16]fen.UciMove = undefined;
    for (moves, 0..) |m, i| ms[i] = try fen.parseMove(m);
    const eng = e.engine();
    var r: Result = .{};
    if (eng.setPosition(&d, .setup, ms[0..moves.len]) != null) {
        r.rejected = true;
        return r;
    }
    var cap: Capture = .{};
    var sig: uci_engine.Signals = .{};
    const res = eng.search(&.{ .depth = depth }, &sig, cap.out());
    if (res.ponder) |pm| {
        const t = fen.formatMove(pm, &r.ponder);
        r.ponder_len = @intCast(t.len);
    }
    const best = res.best;
    if (best) |b| {
        const t = fen.formatMove(b, &r.move);
        r.move_len = @intCast(t.len);
    }
    r.nodes = e.root.nodes;
    r.makes = e.root.makes;
    r.line = e.root.lineHex();
    if (e.last_score) |raw| {
        const s = std.fmt.bufPrint(&r.score, "raw {d}", .{raw}) catch unreachable;
        r.score_len = @intCast(s.len);
    }
    return r;
}

fn searchWith(comptime fixes: pos.Fixes, gpa: std.mem.Allocator, f: []const u8, moves: []const []const u8, depth: u32) !Result {
    const E = engine_mod.EngineOf(fixes);
    const e = try gpa.create(E);
    defer gpa.destroy(e);
    e.* = try E.init(gpa);
    defer e.deinit();
    e.reporting = true;
    return searchOn(e, f, moves, depth);
}

/// `searchWith` from the start position with the book on (OwnBook, Seed 17) and the moves
/// given (the new-game route).
fn bookSearchWith(comptime fixes: pos.Fixes, gpa: std.mem.Allocator, moves: []const []const u8, depth: u32) !Result {
    const E = engine_mod.EngineOf(fixes);
    const e = try gpa.create(E);
    defer gpa.destroy(e);
    e.* = try E.init(gpa);
    defer e.deinit();
    var o: uci_engine.Options = .{};
    o.own_book = true;
    o.seed = 17;
    e.engine().applyOptions(&o);
    const start = try fen.parse(fen.startpos);
    var ms: [16]fen.UciMove = undefined;
    for (moves, 0..) |m, i| ms[i] = try fen.parseMove(m);
    var r: Result = .{};
    if (e.engine().setPosition(&start, .new_game, ms[0..moves.len]) != null) {
        r.rejected = true;
        return r;
    }
    var cap: Capture = .{};
    var sig: uci_engine.Signals = .{};
    const res = e.engine().search(&.{ .depth = depth }, &sig, cap.out());
    if (res.best) |b| r.move_len = @intCast(fen.formatMove(b, &r.move).len);
    r.nodes = e.root.nodes;
    return r;
}

/// A position where the switch `name` alone changes the search.
const Case = struct {
    name: []const u8,
    fen: []const u8,
    moves: []const []const u8 = &.{},
    depth: u32,
    /// The original's node count: a case above 15,000 runs only in optimised builds, as
    /// the other long tests limit Debug.
    nodes: u64,
};

fn tooLong(c: Case) bool {
    if (builtin.mode == .debug and c.nodes > 15_000) {
        std.debug.print("fixes: {s}: {d} nodes, not run in Debug\n", .{ c.name, c.nodes });
        return true;
    }
    return false;
}

fn expectDiffers(comptime name: []const u8, comptime c: Case) !void {
    if (tooLong(c)) return;
    const gpa = std.testing.allocator;
    const o = try searchWith(pos.Fixes.original, gpa, c.fen, c.moves, c.depth);
    const x = try searchWith(only(name), gpa, c.fen, c.moves, c.depth);
    std.debug.print("fixes: {s}: {s} go depth {d}: original {s} {d} nodes {s}; corrected {s} {d} nodes {s}\n", .{ name, c.fen, c.depth, o.moveText(), o.nodes, o.scoreText(), x.moveText(), x.nodes, x.scoreText() });
    try std.testing.expect(!o.rejected and !x.rejected);
    try std.testing.expect(!o.same(&x));
}

fn expectSame(comptime name: []const u8, comptime c: Case) !void {
    if (tooLong(c)) return;
    const gpa = std.testing.allocator;
    const o = try searchWith(pos.Fixes.original, gpa, c.fen, c.moves, c.depth);
    const x = try searchWith(only(name), gpa, c.fen, c.moves, c.depth);
    std.debug.print("fixes: {s}: {s} go depth {d}: original {s} {d} nodes {s}; corrected {s} {d} nodes {s} (the same)\n", .{ name, c.fen, c.depth, o.moveText(), o.nodes, o.scoreText(), x.moveText(), x.nodes, x.scoreText() });
    try std.testing.expect(!o.rejected and !x.rejected);
    try std.testing.expect(o.same(&x));
}

// ---- the measurement --------------------------------------------------------------------

/// One search of a golden file: its position (the board and side the record gives, the
/// castling rights the board allows) and the scenario's Fixed depth.
const Search = struct { file: []const u8, scenario: []const u8, index: u32, fen: []const u8, depth: u32 };

const golden_files = [_][]const u8{ "smoke", "corpus1", "corpus2", "normal1", "castling", "longgame" };

fn loadSearches(arena: std.mem.Allocator) ![]Search {
    return loadSearchesOf(arena, &golden_files);
}

fn loadSearchesOf(arena: std.mem.Allocator, files: []const []const u8) ![]Search {
    var list: std.ArrayList(Search) = .empty;
    const dir = build_options.golden_dir;
    for (files) |name| {
        const path = try std.fmt.allocPrint(arena, "{s}/{s}.jsonl", .{ dir, name });
        const text = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, arena, .limited(1 << 24));
        var depth: u32 = 0;
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            const v = try std.json.parseFromSliceLeaky(std.json.Value, arena, line, .{});
            const o = v.object;
            if (o.get("search") == null) {
                depth = @intCast(o.get("depth").?.integer);
                continue;
            }
            const f = try std.fmt.allocPrint(arena, "{s} {s}", .{ o.get("board").?.string, o.get("side").?.string });
            try list.append(arena, .{ .file = name, .scenario = o.get("scenario").?.string, .index = @intCast(o.get("search").?.integer), .fen = f, .depth = depth });
        }
    }
    return list.items;
}

fn Runner(comptime fixes: pos.Fixes) type {
    return struct {
        fn run(searches: []const Search, out: []Result, failed: *bool) void {
            runAll(fixes, searches, out, failed);
        }
    };
}

fn runAll(comptime fixes: pos.Fixes, searches: []const Search, out: []Result, failed: *bool) void {
    const gpa = std.heap.page_allocator;
    const E = engine_mod.EngineOf(fixes);
    const e = gpa.create(E) catch {
        failed.* = true;
        return;
    };
    defer gpa.destroy(e);
    e.* = E.init(gpa) catch {
        failed.* = true;
        return;
    };
    defer e.deinit();
    for (searches, out) |s, *r| {
        r.* = searchOn(e, s.fen, &.{}, s.depth) catch {
            failed.* = true;
            return;
        };
    }
}

test "fixes: measured: every golden search by the original, by each switch alone and by the shipped engine (MCHESS_MEASURE_FIXES)" {
    const gpa = std.testing.allocator;
    if (!try std.testing.environ.containsUnempty(gpa, "MCHESS_MEASURE_FIXES")) return;
    var arena_state: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const searches = try loadSearches(arena);
    const n_variants = switches.len + 2; // the original, each switch, every switch
    const results = try arena.alloc([]Result, n_variants);
    for (results) |*r| r.* = try arena.alloc(Result, searches.len);
    var failed: [n_variants]bool = @splat(false);
    var threads: [n_variants]std.Thread = undefined;
    threads[0] = try std.Thread.spawn(.{}, Runner(pos.Fixes.original).run, .{ searches, results[0], &failed[0] });
    inline for (switches, 1..) |name, k| {
        threads[k] = try std.Thread.spawn(.{}, Runner(only(name)).run, .{ searches, results[k], &failed[k] });
    }
    threads[n_variants - 1] = try std.Thread.spawn(.{}, Runner(pos.Fixes.corrected).run, .{ searches, results[n_variants - 1], &failed[n_variants - 1] });
    for (threads) |t| t.join();
    for (failed) |f| try std.testing.expect(!f);

    const base = results[0];
    std.debug.print("\nfixes measured: {d} searches of {d} golden files, each from its position (fresh rebuild, rights from the board), at its Fixed depth\n", .{ searches.len, golden_files.len });
    std.debug.print("| Engine | Move differs | Nodes differ | Score differs |\n| --- | ---: | ---: | ---: |\n", .{});
    for (1..n_variants) |k| {
        var mv: u32 = 0;
        var nd: u32 = 0;
        var sc: u32 = 0;
        for (base, results[k]) |a, b| {
            if (!std.mem.eql(u8, a.moveText(), b.moveText())) mv += 1;
            if (a.nodes != b.nodes) nd += 1;
            if (!std.mem.eql(u8, a.scoreText(), b.scoreText())) sc += 1;
        }
        const label = if (k == n_variants - 1) "every fix (shipped)" else switches[k - 1];
        std.debug.print("| {s} | {d} | {d} | {d} |\n", .{ label, mv, nd, sc });
    }
    // The differing searches of each switch, for the per-fix tests above.
    for (1..n_variants - 1) |k| {
        var shown: u32 = 0;
        for (searches, base, results[k]) |s, a, b| {
            if (a.same(&b)) continue;
            if (shown == 6) break;
            shown += 1;
            std.debug.print("  {s}: {s}/{s} {d}: \"{s}\" depth {d}: {s} {d} {s} -> {s} {d} {s}\n", .{ switches[k - 1], s.file, s.scenario, s.index, s.fen, s.depth, a.moveText(), a.nodes, a.scoreText(), b.moveText(), b.nodes, b.scoreText() });
        }
    }
}

// ---- one test per switch -------------------------------------------------------------
// Positions: the golden files' searches (tests/golden/*.jsonl; the measurement below lists
// those each switch changes), each as `position fen <board> <side>` with the rights the
// board allows, at the scenario's depth; and, where no golden search changes, a position
// found for the purpose. "Corrected" is the engine with that one switch on.

test "fixes: DEV-004 (promotion-capture order) changes the search of open-game-d4 1" {
    try expectDiffers("dev004_promotion_capture_score", .{ .name = "DEV-004", .fen = "r1bqkbnr/pppp1ppp/2n5/4p3/4P3/5N2/PPPP1PPP/RNBQKB1R w", .depth = 4, .nodes = 29_590 });
}

test "fixes: DEV-005 (Black bishop check order) changes the search of start-d3 2" {
    try expectDiffers("dev005_bishop_check_score", .{ .name = "DEV-005", .fen = "rnbqkbnr/pppppppp/8/8/3P4/8/PPP1PPPP/RNBQKBNR b", .depth = 3, .nodes = 907 });
}

test "fixes: DEV-007 (Black pawn-push test) changes the search of start-d3 3" {
    try expectDiffers("dev007_black_pawn_push", .{ .name = "DEV-007", .fen = "rnbqkbnr/ppp1pppp/8/3p4/3P4/8/PPP1PPPP/RNBQKBNR w", .depth = 3, .nodes = 1_188 });
}

test "fixes: DEV-008 (castling order) changes the search of open-game-d4 1" {
    try expectDiffers("dev008_castling_mark", .{ .name = "DEV-008", .fen = "r1bqkbnr/pppp1ppp/2n5/4p3/4P3/5N2/PPPP1PPP/RNBQKB1R w", .depth = 4, .nodes = 29_590 });
}

test "fixes: DEV-010 (passed h-pawn tables) changes the search of a rook ending with a passed h-pawn" {
    // No golden search has a passed h-pawn at the root. Here the score moves by 1 and
    // the count by 1; at depth 4 from `6k1/1p3p2/2r5/7P/8/2N5/5PP1/3R2K1 w` the move
    // changes (d1d8 to c3d5), too long for this test.
    try expectDiffers("dev010_passed_h_pawn", .{ .name = "DEV-010", .fen = "r5k1/1p3p2/8/7P/8/8/5PP1/R5K1 w", .depth = 3, .nodes = 4_115 });
}

test "fixes: DEV-011 (blocked-wing table) changes the search of evans-gambit-d4 2" {
    try expectDiffers("dev011_blocked_wing_table", .{ .name = "DEV-011", .fen = "r1bqk1nr/pppp1ppp/2n5/b7/2BpP3/2P2N2/P4PPP/RNBQK2R w", .depth = 4, .nodes = 108_365 });
}

test "fixes: DEV-012 (White's pawn table) changes the search of castle-one-wing-d4 1" {
    try expectDiffers("dev012_white_pawn_table", .{ .name = "DEV-012", .fen = "1r2k2r/ppp2ppp/2n1bn2/3qp3/8/2NP1N2/PPP1BPPP/R2QK1R1 b", .depth = 4, .nodes = 13_257 });
}

test "fixes: DEV-017 (king square after a diagonal hit) changes the search of advanced-pawns-d3 3" {
    try expectDiffers("dev017_king_square", .{ .name = "DEV-017", .fen = "r2qkbnr/pbppppp1/2n5/8/8/5N2/1PPPPPBP/RNBQK2R w", .depth = 3, .nodes = 1_800 });
}

test "fixes: DEV-019 (the activity routines' mirror) changes the search of a position the original evaluated" {
    // A Black rook behind its own pawn on d2 (1E30 adds the pawn square's entry, §4.3 item
    // 3; src/activity_test.zig): a position of the recorded activity calls (tests/golden/
    // evalpieces/), not a golden search.
    try expectDiffers("dev019_activity_mirror", .{ .name = "DEV-019", .fen = "3rkbnr/ppp2ppp/2n1B3/8/4P3/8/PP1p1PPP/R1BK2NR w", .depth = 3, .nodes = 2_218 });
}

test "fixes: DEV-020 (threat table index) changes the search of selfplay-d3 27" {
    try expectDiffers("dev020_threat_table_index", .{ .name = "DEV-020", .fen = "r4rk1/ppp1nppp/3qp3/3p3Q/3P4/P2PP3/1P1N1PPP/2R2RK1 w", .depth = 3, .nodes = 7_918 });
}

test "fixes: DEV-022 (captured enemy pieces) changes the search of selfplay-d3 51" {
    try expectDiffers("dev022_captured_pieces", .{ .name = "DEV-022", .fen = "2rr2k1/p4npp/q4p2/2ppp3/8/P2PPQ2/1PN2PPP/2RR2K1 w", .depth = 3, .nodes = 11_939 });
}

test "fixes: DEV-023 (pinned bishop in the exchange) changes no search found; the same search with it on" {
    // No golden search changes, nor any of 14 positions with pins tried at depths 3 and 4
    // (task integrate-fixes, 2026-11-20); the unit test changes 41 of 2,000,344 generated
    // calls (src/pinexchange_test.zig).
    try expectSame("dev023_pinned_bishop", .{ .name = "DEV-023", .fen = "r2q1rk1/ppp2ppp/2np1n2/2b1p1B1/2B1P1b1/2NP1N2/PPP2PPP/R2Q1RK1 w", .depth = 3, .nodes = 17_949 });
}

test "fixes: DEV-024 (attacked-piece counter) changes the search of kings-indian-d4 1" {
    try expectDiffers("dev024_attacked_counter", .{ .name = "DEV-024", .fen = "rnbqk2r/ppp1ppbp/3p1np1/8/2PPP3/2N2N2/PP3PPP/R1BQKB1R b", .depth = 4, .nodes = 34_807 });
}

test "fixes: DEV-026 (book promotion prefix) cannot change a search: the book game is the same with it on" {
    // The shipped book never leaves a prefix pending (src/book_test.zig "DEV-026" builds one).
    const gpa = std.testing.allocator;
    const line = [_][]const u8{ "e2e4", "c7c5", "g1f3" };
    for (0..line.len + 1) |k| {
        const o = try bookSearchWith(pos.Fixes.original, gpa, line[0..k], 2);
        const x = try bookSearchWith(only("dev026_promotion_prefix"), gpa, line[0..k], 2);
        std.debug.print("fixes: DEV-026: book after {d} moves: original {s} {d} nodes; corrected {s} {d} nodes\n", .{ k, o.moveText(), o.nodes, x.moveText(), x.nodes });
        try std.testing.expect(o.same(&x));
    }
}

test "fixes: DEV-027 (loader key) cannot change a search: a FEN with a withheld right searched alike" {
    try expectSame("dev027_loader_key", .{ .name = "DEV-027", .fen = "r3k2r/pppq1ppp/2npbn2/2b1p3/2B1P3/2NPBN2/PPPQ1PPP/R3K2R w Kq - 0 1", .depth = 3, .nodes = 3_372 });
}

test "fixes: DEV-031 (4/5 scaling) changes no search: a tablebase ending searched alike" {
    // The root plays a tablebase move without a search where the scaled scores arise
    // (src/rootprep_test.zig "DEV-031": 1 of 56 recorded preparations changes, krk).
    try expectSame("dev031_scaling_overflow", .{ .name = "DEV-031", .fen = "8/5k2/8/8/3R4/8/5K2/8 w - - 0 1", .depth = 4, .nodes = 0 });
}

test "fixes: DEV-035 (mate at ply 2) cannot change a search: pawnless mates in one are found alike" {
    // A root mate in one is scored in iteration 1 by the general node and the root's mate
    // test ends the search before the ply-2 node runs (docs/DEVIATIONS.md, DEV-035).
    inline for (.{ "6k1/8/6K1/8/8/8/8/1RB5 w - - 0 1", "1rb5/8/8/8/8/6k1/8/6K1 b - - 0 1" }) |f| {
        inline for (.{ 2, 3, 4 }) |d| {
            try expectSame("dev035_ply2_mate", .{ .name = "DEV-035", .fen = f, .depth = d, .nodes = 0 });
        }
    }
}

test "fixes: DEV-040 (hanging-piece ray start) changes the search of evans-gambit-d4 4" {
    try expectDiffers("dev040_hanging_ray_start", .{ .name = "DEV-040", .fen = "r1bqk2r/pppp1ppp/2n2n2/b7/2BNP3/2P5/P4PPP/RNBQK2R w", .depth = 4, .nodes = 175_747 });
}

test "fixes: DEV-043 (root pre-score sign) changes the search of selfplay-d3 86" {
    try expectDiffers("dev043_prescore_sign", .{ .name = "DEV-043", .fen = "1r4k1/5qpp/5p2/p1R5/3rp3/PP2P3/4Q1PP/N5K1 b", .depth = 3, .nodes = 5_650 });
}

test "fixes: DEV-046 (predicted reply sign) changes no search found; the same search with it on" {
    // It changes which reply set_predicted_reply predicts (7 of 28 recorded calls,
    // src/gamemove_test.zig "DEV-046"); that reaches a search only through DG:73FE, and
    // no search of the normal1 games played through the engine as White changed.
    try expectSame("dev046_reply_sign", .{ .name = "DEV-046", .fen = "r1bqkbnr/pppp1ppp/2n5/4p3/4P3/5N2/PPPP1PPP/RNBQKB1R w", .depth = 3, .nodes = 2_402 });
}

test "fixes: DEV-041 (Black threat evaluator's mirror) changes the search of a queen and knight ending with the king in the corner" {
    // The king on h7 with the queen near: the first of DEV-041's places (0EF8:D117, D32D;
    // src/evalthreats_test.zig "DEV-041, a position for each place corrected").
    try expectDiffers("dev041_threat_mirror", .{ .name = "DEV-041", .fen = "8/pp5k/6N1/4Q3/8/8/PPP5/1K6 b - - 0 1", .depth = 2, .nodes = 149_848 });
}
test "fixes: DEV-021 (knight escape order) changes the search of castle-italian-d4 5" {
    // 3 of the 405 golden searches change (nodes only). Also, outside the golden files:
    // `5rk1/ppp1bppp/8/2Qn4/2P5/3B1N2/PP3PPP/5RK1 w` at depth 3, 5,499 nodes to 5,471
    // (the generated call A.zst 7595 of src/evalthreats_test.zig).
    try expectDiffers("dev021_knight_escape_order", .{ .name = "DEV-021", .fen = "r1bqk2r/ppp2ppp/1bnp1n2/4p3/N1B1P3/3P1N2/PPP2PPP/R1BQK2R w", .depth = 4, .nodes = 35_750 });
}

test "fixes: DEV-052 (the line tables' pseudo-lines) changes the search of start-d4 3" {
    // 60 of the 405 golden searches change (nodes only). Also `r5r1/6R1/8/2k5/8/8/8/1K6 w`
    // at depth 2, 913 nodes to 873: the rooks a8 and g7 differ by -4, which the orthogonal
    // table takes for a rank (src/evalthreats_test.zig "DEV-021 and DEV-052, a position
    // for each").
    try expectDiffers("dev052_line_tables", .{ .name = "DEV-052", .fen = "rnbqkbnr/ppp1pppp/8/3p4/3P4/8/PPP1PPPP/RNBQKBNR w", .depth = 4, .nodes = 10_003 });
}
test "fixes: DEV-053 (the line tables' pseudo-lines in the counters and static_eval) changes the search of selfplay-d3 14" {
    // 32 of the 405 golden searches change (nodes only), with every other fix off; most
    // through the attacked-piece counter, where a bishop on a pseudo-line keeps the second
    // bishop from being tried (src/helpers_test.zig "DEV-053"). With every other fix on (the
    // shipped engine), 3 change: selfplay-d3 131 and np-ending-black-d5 4 and 6.
    try expectDiffers("dev053_line_tables_other", .{ .name = "DEV-053", .fen = "rn1qk2r/ppp1bppp/4p3/3p1b2/3PnB2/3BP3/PPPN1PPP/RN1Q1RK1 b", .depth = 3, .nodes = 4_786 });
}
test "fixes: DEV-050 (corner rook capture) changes the search of the perft position" {
    try expectDiffers("dev050_corner_rook_capture", .{ .name = "DEV-050", .fen = "4k3/8/8/8/4b3/7R/8/4K2R b K - 0 1", .depth = 4, .nodes = 2_465 });
}

test "fixes: DEV-054 (White's unstoppable passer without the test of Black's passers, Black's form) changes the search of np-checks-white-d3 1" {
    // 6 of the 416 golden and deep searches change (nodes only), alone and on top of the
    // shipped set; here 4,027 nodes to 4,028. The evaluation itself: "a position for each
    // difference", DEV-054, in src/eval_mirror_main_test.zig (the original, 1260 against the
    // mirror's 1560) and src/eval_mirror_test.zig (corrected, 1560 and 1560).
    try expectDiffers("dev054_unstoppable_passer_mirror", .{ .name = "DEV-054", .fen = "6k1/5pp1/7p/3q4/8/6P1/5PKP/3Q4 w", .depth = 3, .nodes = 4_027 });
}

test "fixes: DEV-055 (the extra test at 2B9F:39EA) changes the search of castle-both-wings-d4 4" {
    try expectDiffers("dev055_passer_block_extra_test", .{ .name = "DEV-055", .fen = "r3k2r/pppq1ppp/2n1bn2/1Bp1p3/4P3/2NP1N2/PPPQ1PPP/R3K2R b", .depth = 4, .nodes = 37_100 });
}

test "fixes: DEV-056 (the king rings' wrap) changes the search of selfplay-d3 92" {
    try expectDiffers("dev056_king_ring_wrap", .{ .name = "DEV-056", .fen = "1r5k/3q2pp/5p2/p7/2Q1p3/PP2P3/3r2PP/N3R1K1 b", .depth = 3, .nodes = 8_208 });
}

test "fixes: DEV-058 (a lifted knight's entry 0) changes the search of selfplay-d3 68" {
    try expectDiffers("dev058_lifted_knight_entry", .{ .name = "DEV-058", .fen = "1r1r2k1/p5pp/4np2/2pqp3/6Q1/PP1P4/5PPP/N1R1R1K1 b", .depth = 3, .nodes = 9_513 });
}

test "fixes: DEV-059 (the opposite-bishops flag of 0EF8:1ABA) changes a search of Q against B+N+N" {
    // No golden search changes. The position of src/eval_mirror_test.zig's DEV-059 case.
    try expectDiffers("dev059_opposite_bishops_flag", .{ .name = "DEV-059", .fen = "kn5Q/4P3/8/8/5p1n/1b1KP3/8/8 b", .depth = 3, .nodes = 62_342 });
}
test "fixes: DEV-062 (Black's general king test without 2BA6's rank test) changes no search found; the same search with it on" {
    // Parked (off in `corrected`). No golden search changes, nor this one, built for the
    // test: a Black rook-file passer with Black to move, the kings on one rank. Independent
    // of DEV-054 in Black's form (decision 44): on top of it, still no node of the mirror
    // test changes.
    try expectSame("dev062_king_test_rank", .{ .name = "DEV-062", .fen = "8/p7/8/8/1P6/k5Kp/8/8 b - - 0 1", .depth = 4, .nodes = 1_611 });
}
test "fixes: DEV-067 (the illegal root moves' sentinel) changes the search of dev067-b8-d3" {
    // No golden search of the files measured changes; tests/golden/dev067.jsonl's faulty
    // positions do (src/engine_dev067_test.zig): the original searches b8c7, illegal, in 2
    // nodes (the guard then plays b8b7); corrected, b8b7 is searched (14 nodes). At depth 1
    // both count 2 nodes and score -20000, and only the line differs.
    try expectDiffers("dev067_illegal_root_sentinel", .{ .name = "DEV-067", .fen = "1K4k1/2nqq3/8/7q/8/2q1q3/2q5/r5q1 w", .depth = 3, .nodes = 2 });
}

/// The shipped engine without DEV-067.
const before_dev067: pos.Fixes = blk: {
    var f = pos.Fixes.corrected;
    f.dev067_illegal_root_sentinel = false;
    break :blk f;
};

test "fixes: measured: DEV-067 alone against the original, and the shipped engine against it without DEV-067 (MCHESS_MEASURE_DEV067)" {
    const gpa = std.testing.allocator;
    if (!try std.testing.environ.containsUnempty(gpa, "MCHESS_MEASURE_DEV067")) return;
    var arena_state: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const searches = try loadSearchesOf(arena, &(golden_files ++ [_][]const u8{"deep"}));
    const n = 4;
    const results = try arena.alloc([]Result, n);
    for (results) |*r| r.* = try arena.alloc(Result, searches.len);
    var failed: [n]bool = @splat(false);
    var threads: [n]std.Thread = undefined;
    threads[0] = try std.Thread.spawn(.{}, Runner(pos.Fixes.original).run, .{ searches, results[0], &failed[0] });
    threads[1] = try std.Thread.spawn(.{}, Runner(only("dev067_illegal_root_sentinel")).run, .{ searches, results[1], &failed[1] });
    threads[2] = try std.Thread.spawn(.{}, Runner(before_dev067).run, .{ searches, results[2], &failed[2] });
    threads[3] = try std.Thread.spawn(.{}, Runner(pos.Fixes.corrected).run, .{ searches, results[3], &failed[3] });
    for (threads) |t| t.join();
    for (failed) |f| try std.testing.expect(!f);
    std.debug.print("\nDEV-067 measured: {d} searches (the golden files and deep.jsonl)\n| Engine | against | Move differs | Nodes differ | Score differs | Makes differ | Line differs |\n| --- | --- | ---: | ---: | ---: | ---: | ---: |\n", .{searches.len});
    var total: u32 = 0;
    for ([_][2]usize{ .{ 0, 1 }, .{ 2, 3 } }, 0..) |pair, k| {
        var mv: u32 = 0;
        var nd: u32 = 0;
        var sc: u32 = 0;
        var mk: u32 = 0;
        var ln: u32 = 0;
        for (searches, results[pair[0]], results[pair[1]]) |s, a, b| {
            const d = [_]bool{ !std.mem.eql(u8, a.moveText(), b.moveText()), a.nodes != b.nodes, !std.mem.eql(u8, a.scoreText(), b.scoreText()), a.makes != b.makes, !std.mem.eql(u8, &a.line, &b.line) };
            if (d[0]) mv += 1;
            if (d[1]) nd += 1;
            if (d[2]) sc += 1;
            if (d[3]) mk += 1;
            if (d[4]) ln += 1;
            if (std.mem.indexOfScalar(bool, &d, true) != null)
                std.debug.print("  {s}/{s} {d}: {s} {d} -> {s} {d}\n", .{ s.file, s.scenario, s.index, a.moveText(), a.nodes, b.moveText(), b.nodes });
        }
        total += mv + nd + sc + mk + ln;
        std.debug.print("| {s} | {s} | {d} | {d} | {d} | {d} | {d} |\n", .{ if (k == 0) "dev067_illegal_root_sentinel alone" else "every fix (shipped)", if (k == 0) "original" else "every fix but DEV-067", mv, nd, sc, mk, ln });
    }
    try std.testing.expectEqual(@as(u32, 0), total);
}

// ---- the five colour-mirror fixes (owner decisions 34 and 35) ----

/// The switches of the five candidates found by the colour mirror (DEV-054, 055, 056, 058,
/// 059; docs/arch/50-evaluation-map.md section 14).
const mirror_switches = [_][]const u8{
    "dev054_unstoppable_passer_mirror",
    "dev055_passer_block_extra_test",
    "dev056_king_ring_wrap",
    "dev058_lifted_knight_entry",
    "dev059_opposite_bishops_flag",
    "dev062_king_test_rank",
};

/// The shipped engine without the five: what main shipped before decision 35.
const before_mirror_fixes: pos.Fixes = blk: {
    var f = pos.Fixes.corrected;
    for (mirror_switches) |n| @field(f, n) = false;
    break :blk f;
};

/// The shipped engine without DEV-054: what main shipped before decision 44.
const before_dev054: pos.Fixes = blk: {
    var f = pos.Fixes.corrected;
    f.dev054_unstoppable_passer_mirror = false;
    break :blk f;
};

test "fixes: measured: the five mirror fixes, each alone and together against the engine without them (MCHESS_MEASURE_MIRROR_FIXES)" {
    const gpa = std.testing.allocator;
    if (!try std.testing.environ.containsUnempty(gpa, "MCHESS_MEASURE_MIRROR_FIXES")) return;
    var arena_state: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const searches = try loadSearchesOf(arena, &(golden_files ++ [_][]const u8{"deep"}));
    // The original, each switch alone, the engine without the five, the engine without
    // DEV-054, the shipped engine.
    const n = mirror_switches.len + 4;
    const results = try arena.alloc([]Result, n);
    for (results) |*r| r.* = try arena.alloc(Result, searches.len);
    var failed: [n]bool = @splat(false);
    var threads: [n]std.Thread = undefined;
    threads[0] = try std.Thread.spawn(.{}, Runner(pos.Fixes.original).run, .{ searches, results[0], &failed[0] });
    inline for (mirror_switches, 1..) |name, k| {
        threads[k] = try std.Thread.spawn(.{}, Runner(only(name)).run, .{ searches, results[k], &failed[k] });
    }
    threads[n - 3] = try std.Thread.spawn(.{}, Runner(before_mirror_fixes).run, .{ searches, results[n - 3], &failed[n - 3] });
    threads[n - 2] = try std.Thread.spawn(.{}, Runner(before_dev054).run, .{ searches, results[n - 2], &failed[n - 2] });
    threads[n - 1] = try std.Thread.spawn(.{}, Runner(pos.Fixes.corrected).run, .{ searches, results[n - 1], &failed[n - 1] });
    for (threads) |t| t.join();
    for (failed) |f| try std.testing.expect(!f);
    std.debug.print("\nmirror fixes measured: {d} searches (the golden files and deep.jsonl)\n| Engine | against | Move differs | Nodes differ | Score differs |\n| --- | --- | ---: | ---: | ---: |\n", .{searches.len});
    // Each switch alone against the original; the shipped engine against it without the
    // five and against it without DEV-054.
    const rows = [_][3]usize{ .{ 1, 0, 0 }, .{ 2, 0, 0 }, .{ 3, 0, 0 }, .{ 4, 0, 0 }, .{ 5, 0, 0 }, .{ 6, 0, 0 }, .{ n - 3, 0, 1 }, .{ n - 1, n - 3, 2 }, .{ n - 1, n - 2, 3 } };
    comptime std.debug.assert(mirror_switches.len == 6);
    for (rows) |row| {
        const k = row[0];
        const base = results[row[1]];
        var mv: u32 = 0;
        var nd: u32 = 0;
        var sc: u32 = 0;
        for (searches, base, results[k]) |s, a, b| {
            if (!std.mem.eql(u8, a.moveText(), b.moveText())) mv += 1;
            if (a.nodes != b.nodes) nd += 1;
            if (!std.mem.eql(u8, a.scoreText(), b.scoreText())) sc += 1;
            if (row[2] == 3 and !a.same(&b))
                std.debug.print("  DEV-054 on the shipped set: {s}/{s} {d}: \"{s}\" depth {d}: {s} {d} {s} -> {s} {d} {s}\n", .{ s.file, s.scenario, s.index, s.fen, s.depth, a.moveText(), a.nodes, a.scoreText(), b.moveText(), b.nodes, b.scoreText() });
        }
        const label = switch (row[2]) {
            0 => mirror_switches[k - 1],
            1 => "every fix but the five",
            else => "every fix (shipped)",
        };
        const against = switch (row[2]) {
            0, 1 => "original",
            2 => "every fix but the five",
            else => "every fix but DEV-054",
        };
        std.debug.print("| {s} | {s} | {d} | {d} | {d} |\n", .{ label, against, mv, nd, sc });
    }
    for (1..mirror_switches.len + 1) |k| {
        var shown: u32 = 0;
        for (searches, results[0], results[k]) |s, a, b| {
            if (a.same(&b)) continue;
            if (shown == 4) break;
            shown += 1;
            std.debug.print("  {s}: {s}/{s} {d}: \"{s}\" depth {d}: {s} {d} {s} -> {s} {d} {s}\n", .{ mirror_switches[k - 1], s.file, s.scenario, s.index, s.fen, s.depth, a.moveText(), a.nodes, a.scoreText(), b.moveText(), b.nodes, b.scoreText() });
        }
    }
}
