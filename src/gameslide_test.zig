//! The slide of the game record (src/gameslide.zig) against the original, up to its own
//! limit, and beyond it.
//!
//! **Against the original.** The long game of tests/golden/longgame.jsonl (searches at
//! game plies 258..260 and 397..401, docs/arch/34-game-move-path.md "How long a game can
//! be") is run from the oracle's snapshot at main 0526 of each scenario's first search,
//! once as recorded and once after each of several slides of that snapshot. Every search
//! of a slid run must equal the original's on the move, node entries, makes and line hash;
//! and at every point between turns (main 0526 before each search, and after the last
//! move) the slid run's whole state must equal the slide of the unslid run's state at the
//! same point: every byte of DGROUP and of the far segment 5A7B, and the main hash tables.
//! That is: sliding commutes with the search, play_best_move and the auto-play turn, so no
//! routine they run reads the absolute game ply or move number in a way the slide changes.
//! After the original's last search (ply 401) the unslid run's command loop ends the game;
//! the slid run goes on and searches again.
//!
//! The same is run with the game record changed so that a third repetition (the record's
//! keys) and the fifty-move count (the irreversible-move flags DG:3490) are found across
//! the slide: their effects differ from the recorded searches, and slid and unslid agree.
//!
//! **Beyond the limit.** Games are played on in auto-play through `EngineRoot`'s own turn
//! routines, sliding by three different policies: the long game from its ply-397 snapshot
//! at Fixed depth 2 to its end (mate at what would be ply 428), and an ending of corpus2
//! (bishops of opposite colours, set up at ply 0) at depth 2 for 700 plies. The moves,
//! node counts and makes must be the same whichever policy is used, and no turn may fail.
//!
//! Debug, at about 1,500 nodes a second, runs only the unit checks unless
//! MCHESS_LONG_TESTS is set and not empty.

const std = @import("std");
const si = @import("state_image.zig");
const builtin = @import("builtin");
const ert = @import("engine_root.zig");
const ert_test = @import("engine_root_test.zig");
const sn = @import("searchnode.zig");
const dgroup = @import("dgroup.zig");
const rp = @import("rootprep.zig");
const gs = @import("gameslide.zig");

const R = ert_test.R;
const Image = dgroup.Image;
const dir = "whole/longgame";

fn word(img: []const u8, addr: u16) u16 {
    return std.mem.readInt(u16, img[addr..][0..2], .little);
}
fn setWord(img: []u8, addr: u16, v: u16) void {
    std.mem.writeInt(u16, img[addr..][0..2], v, .little);
}

fn longTests(gpa: std.mem.Allocator) !bool {
    if (builtin.mode != .debug) return true;
    return std.testing.environ.containsUnempty(gpa, "MCHESS_LONG_TESTS");
}

/// The far data segment 5A7B and the main hash tables' non-zero slots at the first node
/// entry of a search, from the oracle's subtree file of node 1 (as in
/// src/engine_root_longgame_test.zig).
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

/// The scenario's start: the oracle's DGROUP at main 0526 of its first search, the far
/// segment and hash tables of its first node.
fn loadStart(gpa: std.mem.Allocator, s: *R, scenario: []const u8) !void {
    return loadStartIn(gpa, s, dir, scenario);
}

fn loadStartIn(gpa: std.mem.Allocator, s: *R, in_dir: []const u8, scenario: []const u8) !void {
    var name_buf: [160]u8 = undefined;
    const snap = try ert_test.readGolden(gpa, try std.fmt.bufPrint(&name_buf, "{s}/{s}-s1-main.bin", .{ in_dir, scenario }));
    defer gpa.free(snap);
    si.imageBegin(s);
    defer si.imageEnd(s);
    si.fromImage(s, snap[0..0x10000], null);
    try farFromSubtree(gpa, try std.fmt.bufPrint(&name_buf, "{s}/{s}-s1-subtree-1.zst", .{ in_dir, scenario }), s.test_far, s.tables);
}

fn tablesDigest(s: *const R) u64 {
    var h: std.hash.Wyhash = .init(0);
    for (s.tables) |*t| h.update(std.mem.sliceAsBytes(t.slots));
    return h.final();
}

/// The engine's state between turns, as the comparison needs it.
const Snap = struct {
    img: *Image,
    far: *ert.Far,
    tables: u64,

    fn take(gpa: std.mem.Allocator, s: *R) !Snap {
        si.toImage(s); // the turn runs on the members (Stage B step 8, stage 4)
        const img = try gpa.create(Image);
        img.* = s.test_img.*;
        const far = try gpa.create(ert.Far);
        far.* = s.test_far.*;
        return .{ .img = img, .far = far, .tables = tablesDigest(s) };
    }
    fn free(x: Snap, gpa: std.mem.Allocator) void {
        gpa.destroy(x.img);
        gpa.destroy(x.far);
    }
};

/// The bytes of the slid run's state that differ from the slide of the unslid run's state
/// at the same point (the first few are printed).
fn differences(gpa: std.mem.Allocator, s: *R, unslid: Snap, d: u16, label: []const u8) !u32 {
    si.toImage(s);
    const img = try gpa.create(Image);
    defer gpa.destroy(img);
    const far = try gpa.create(ert.Far);
    defer gpa.destroy(far);
    img.* = unslid.img.*;
    far.* = unslid.far.*;
    try gs.slide(img, far, d);
    var n: u32 = 0;
    for (img, s.test_img, 0..) |want, got, a| if (want != got) {
        if (n < 8) std.debug.print("gameslide: {s}, slide {d}: DG:{X:0>4} is {X:0>2}, the slid original's {X:0>2}\n", .{ label, d, a, got, want });
        n += 1;
    };
    for (far, s.test_far, 0..) |want, got, a| if (want != got) {
        if (n < 8) std.debug.print("gameslide: {s}, slide {d}: 5A7B:{X:0>4} is {X:0>2}, the slid original's {X:0>2}\n", .{ label, d, a, got, want });
        n += 1;
    };
    if (tablesDigest(s) != unslid.tables) {
        std.debug.print("gameslide: {s}, slide {d}: the main hash tables differ\n", .{ label, d });
        n += 1;
    }
    return n;
}

const Search = struct { number: i64, want: ert_test.Expected };

/// The recorded searches of `scenario`, in order (the strings live in `arena`).
fn searchesOf(arena: std.mem.Allocator, scenario: []const u8) ![]Search {
    const jl = try ert_test.readGolden(arena, "longgame.jsonl");
    var list: std.ArrayList(Search) = .empty;
    var lines = std.mem.splitScalar(u8, jl, '\n');
    while (lines.next()) |text| {
        if (text.len == 0) continue;
        const parsed = try std.json.parseFromSliceLeaky(std.json.Value, arena, text, .{});
        const o = parsed.object;
        if (o.get("search") == null) continue;
        if (!std.mem.eql(u8, o.get("scenario").?.string, scenario)) continue;
        try list.append(arena, .{ .number = o.get("search").?.integer, .want = ert_test.expectedOf(parsed) });
    }
    return list.toOwnedSlice(arena);
}

/// Changes made to the scenario's start before the run (and before any slide).
const Variant = enum {
    /// As recorded.
    none,
    /// The record's keys at game plies g - 4 and g - 8 are the key of the position two
    /// plies on in the game as recorded: the search's repetition test (is_repetition
    /// 0000:1B88) finds it twice among the earlier positions when its line reaches it.
    repetition,
    /// The irreversible-move flags of the last 120 plies are all set (reversible):
    /// find_last_irreversible_ply (0000:887E) finds none in the last 100 plies, and the
    /// node's fifty-move tests (game ply - [7464] > 100, 0000:3B8C..) hold.
    fifty,

    fn apply(v: Variant, s: *R, key: [6]u8) void {
        const g: usize = word(s.test_img, gs.game_ply_addr);
        switch (v) {
            .none => {},
            .repetition => {
                for ([_]usize{ g - 4, g - 8 }) |p| s.test_far[0x3A34 + 6 * p ..][0..6].* = key;
            },
            .fifty => @memset(s.test_img[gs.flags_addr + g - 120 ..][0..121], 0xFF),
        }
    }
};

const RunResult = struct {
    /// Searches equal to the recorded ones on all four values.
    equal: u32 = 0,
    searches: u32 = 0,
    /// Bytes differing from the slid unslid state, over every point compared.
    state_differences: u32 = 0,
    nodes: [8]u64 = @splat(0),
    best: [8][4]u8 = @splat(@splat(0)),
    /// After the last recorded search and its move: whether the command loop ended the
    /// game, and if not, the move and nodes of one more search.
    ended: bool = false,
    extra_best: [4]u8 = @splat(0),
    extra_nodes: u64 = 0,
};

/// One run of a scenario: unslid (`d` = 0), recording its state at every point into
/// `snaps`; or slid by `d` at its start, comparing with the slide of `snaps`.
fn runScenario(gpa: std.mem.Allocator, scenario: []const u8, searches: []const Search, variant: Variant, key: [6]u8, d: u16, snaps: *std.ArrayList(Snap)) !RunResult {
    const s = try R.init(gpa, ert_test.golden_slots);
    defer s.deinit();
    s.slide_when_due = false; // the slides of this test are made by hand
    si.imageBegin(s);
    try loadStart(gpa, s, scenario);
    variant.apply(s, key);
    if (d != 0) {
        try gs.slide(s.test_img, s.test_far, d);
    }
    si.imageEnd(s);
    var r: RunResult = .{};
    var point: usize = 0;
    var label_buf: [96]u8 = undefined;
    for (searches, 0..) |x, k| {
        if (k > 0) {
            s.playMove();
            s.nextTurnAutoPlay();
            if (s.failure) |f| {
                std.debug.print("gameslide: {s} slide {d}: the turn before search {d} failed: {s}\n", .{ scenario, d, x.number, f });
                return error.TurnFailed;
            }
        }
        if (d == 0) try snaps.append(gpa, try Snap.take(gpa, s)) else {
            const label = try std.fmt.bufPrint(&label_buf, "{s} ({s}) before search {d}", .{ scenario, @tagName(variant), x.number });
            r.state_differences += try differences(gpa, s, snaps.items[point], d, label);
        }
        point += 1;
        s.failure = null;
        const out = s.search(.own);
        r.searches += 1;
        r.nodes[k] = out.nodes;
        r.best[k] = out.best;
        if (s.failure) |f| std.debug.print("gameslide: {s} slide {d}: search {d}: {s}\n", .{ scenario, d, x.number, f });
        const v = ert_test.verdictOf(s, out, x.want);
        if (ert_test.allEqual(v) and s.failure == null) r.equal += 1;
    }
    s.playMove();
    if (d == 0) try snaps.append(gpa, try Snap.take(gpa, s)) else {
        const label = try std.fmt.bufPrint(&label_buf, "{s} ({s}) after the last move", .{ scenario, @tagName(variant) });
        r.state_differences += try differences(gpa, s, snaps.items[point], d, label);
    }
    s.nextTurnAutoPlay();
    if (s.failure != null) {
        r.ended = true;
        return r;
    }
    const out = s.search(.own);
    r.extra_best = out.best;
    r.extra_nodes = out.nodes;
    if (s.failure) |f| std.debug.print("gameslide: {s} slide {d}: the search after the record: {s}\n", .{ scenario, d, f });
    return r;
}

const Case = struct {
    scenario: []const u8,
    variant: Variant,
    /// Slides that keep every threshold (asserted equal).
    slides: []const u16,
    /// Slides below `gameslide.min_ply` (reported only).
    below: []const u16 = &.{},
};

fn runCase(gpa: std.mem.Allocator, c: Case) !void {
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const searches = try searchesOf(arena_state.allocator(), c.scenario);
    var snaps: std.ArrayList(Snap) = .empty;
    defer {
        for (snaps.items) |x| x.free(gpa);
        snaps.deinit(gpa);
    }
    var key: [6]u8 = @splat(0);
    if (c.variant == .repetition) {
        // The key the record holds two plies on, after the game's own moves.
        var first: std.ArrayList(Snap) = .empty;
        defer {
            for (first.items) |x| x.free(gpa);
            first.deinit(gpa);
        }
        _ = try runScenario(gpa, c.scenario, searches, .none, key, 0, &first);
        const g: usize = word(first.items[0].img, gs.game_ply_addr);
        key = first.items[2].far[0x3A34 + 6 * (g + 2) ..][0..6].*;
    }
    const base = try runScenario(gpa, c.scenario, searches, c.variant, key, 0, &snaps);
    const g0 = word(snaps.items[0].img, gs.game_ply_addr);
    std.debug.print("gameslide: {s} ({s}) from game ply {d}, unslid: {d} of {d} searches equal to the original's; the game {s}\n", .{ c.scenario, @tagName(c.variant), g0, base.equal, base.searches, if (base.ended) "ended at the command loop" else "went on" });
    if (c.variant == .none) {
        try std.testing.expectEqual(base.searches, base.equal);
    } else {
        // The change must reach the search: some search differs from the recorded one.
        try std.testing.expect(base.equal < base.searches);
    }
    try std.testing.expect(gs.maxSlide(snaps.items[0].img) >= c.slides[c.slides.len - 1]);
    for (c.slides) |d| {
        const r = try runScenario(gpa, c.scenario, searches, c.variant, key, d, &snaps);
        std.debug.print("gameslide: {s} ({s}) slid by {d} (game ply {d}): {d} of {d} searches equal to the original's, {d} state bytes differ from the slid unslid run; after the record: {s}", .{ c.scenario, @tagName(c.variant), d, g0 - d, r.equal, r.searches, r.state_differences, if (r.ended) "ended" else "played on" });
        if (!r.ended) {
            var mb: [5]u8 = undefined;
            std.debug.print(" ({s}, {d} nodes)", .{ ert_test.moveText(r.extra_best, &mb), r.extra_nodes });
        }
        std.debug.print("\n", .{});
        try std.testing.expectEqual(base.equal, r.equal);
        try std.testing.expectEqual(base.nodes, r.nodes);
        try std.testing.expectEqual(base.best, r.best);
        try std.testing.expectEqual(@as(u32, 0), r.state_differences);
        // Past the original's end, a slid game goes on.
        if (base.ended) {
            try std.testing.expect(!r.ended);
            try std.testing.expect(r.extra_best[0] != 0);
        } else {
            try std.testing.expectEqual(base.extra_best, r.extra_best);
            try std.testing.expectEqual(base.extra_nodes, r.extra_nodes);
        }
    }
    for (c.below) |d| {
        const r = try runScenario(gpa, c.scenario, searches, c.variant, key, d, &snaps);
        std.debug.print("gameslide: {s} ({s}) slid by {d} to game ply {d}, below the minimum {d} (not asserted): {d} of {d} searches equal, {d} state bytes differ\n", .{ c.scenario, @tagName(c.variant), d, g0 - d, gs.min_ply, r.equal, r.searches, r.state_differences });
    }
}

test "gameslide: the long game's searches from slid snapshots equal the original's, and the state commutes with the slide (tests/golden/longgame.jsonl)" {
    const gpa = std.testing.allocator;
    if (!try longTests(gpa)) {
        std.debug.print("gameslide: whole searches not run in Debug (MCHESS_LONG_TESTS=1 runs them)\n", .{});
        return;
    }
    try runCase(gpa, .{ .scenario = "long-ply258-d3", .variant = .none, .slides = &.{ 2, 56 } });
    try runCase(gpa, .{ .scenario = "long-ply397-d3", .variant = .none, .slides = &.{ 2, 100, 194 } });
}

test "gameslide: a third repetition and the fifty-move count found across a slide" {
    const gpa = std.testing.allocator;
    if (!try longTests(gpa)) return;
    try runCase(gpa, .{ .scenario = "long-ply258-d3", .variant = .repetition, .slides = &.{56} });
    try runCase(gpa, .{ .scenario = "long-ply258-d3", .variant = .fifty, .slides = &.{56} });
}

// ---------------------------------------------------------------------------
// Beyond the original's limit
// ---------------------------------------------------------------------------

const Policy = struct {
    name: []const u8,
    /// Slide when the game ply is at least this...
    at: u16,
    /// ...by this many plies (0: by `maxSlide`).
    by: u16,
};

const played_searches = 700;

const Played = struct {
    best: [played_searches][4]u8 = @splat(@splat(0)),
    nodes: [played_searches]u64 = @splat(0),
    makes: [played_searches]u64 = @splat(0),
    n: usize = 0,
    slides: u32 = 0,
    dropped: u32 = 0,
    max_ply: u16 = 0,
    start_ply: u16 = 0,
    /// The game ply held after the last move.
    end_ply: u16 = 0,
    /// DG:7328 when the game ended (8 or more), else 0.
    status: i8 = 0,
};

fn slideIfDue(s: *R, p: Policy, out: *Played) !void {
    si.imageBegin(s);
    defer si.imageEnd(s);
    const g = word(s.test_img, gs.game_ply_addr);
    if (g < p.at) return;
    const d = if (p.by == 0) gs.maxSlide(s.test_img) else p.by;
    if (d == 0) return;
    if (d > gs.maxSlide(s.test_img)) {
        std.debug.print("gameslide: play on: a slide of {d} at game ply {d}, more than the {d} allowed\n", .{ d, g, gs.maxSlide(s.test_img) });
        return error.SlideTooFar;
    }
    try gs.slide(s.test_img, s.test_far, d);
    out.slides += 1;
    out.dropped += d;
}

/// From the snapshot of `scenario` at Fixed depth `depth`, at most `max` searches in
/// auto-play, sliding by `p` between turns, to the end of the game.
fn playOn(gpa: std.mem.Allocator, p: Policy, in_dir: []const u8, scenario: []const u8, depth: u8, max: usize) !Played {
    const s = try R.init(gpa, ert_test.golden_slots);
    defer s.deinit();
    s.slide_when_due = false; // the slides of this test are made by hand
    try loadStartIn(gpa, s, in_dir, scenario);
    si.imageBegin(s);
    s.test_img[0x1E02] = depth; // Fixed depth
    si.imageEnd(s);
    var out: Played = .{};
    // The variables read below at their homes (Stage B step 8, stage 7: the move number,
    // the sides and the status are `RootVars`', the game ply `Position`'s).
    const h = s.home();
    out.start_ply = dgroup.memWord(h, gs.game_ply_addr);
    try slideIfDue(s, p, &out);
    while (out.n < max) {
        s.failure = null;
        const r = s.search(.own);
        if (s.failure) |f| {
            std.debug.print("gameslide: play on ({s}): search {d}: {s}\n", .{ p.name, out.n + 1, f });
            return error.SearchFailed;
        }
        out.best[out.n] = r.best;
        out.nodes[out.n] = r.nodes;
        out.makes[out.n] = r.makes;
        out.n += 1;
        if (r.best[0] == 0) break;
        s.playMove();
        const status: i8 = @bitCast(h.get(0x7328));
        if (status >= 8) {
            var mb: [5]u8 = undefined;
            std.debug.print("gameslide: play on ({s}): search {d} ({s}) at game ply {d}: status [7328] {d}, last irreversible ply {d}\n", .{ p.name, out.n, ert_test.moveText(r.best, &mb), dgroup.memWord(h, gs.game_ply_addr), status, dgroup.memWord(h, gs.last_irreversible_addr) });
        }
        out.end_ply = dgroup.memWord(h, gs.game_ply_addr);
        if (status >= 8) {
            out.status = status;
            break;
        }
        try slideIfDue(s, p, &out);
        out.end_ply = dgroup.memWord(h, gs.game_ply_addr);
        s.nextTurnAutoPlay();
        if (s.failure) |f| {
            std.debug.print("gameslide: play on ({s}): the turn after search {d}: {s}\n", .{ p.name, out.n, f });
            return error.TurnFailed;
        }
        // Every write of the game-move path lands in its table: the game ply is below the
        // original's 402 and the move number below 202 (docs/arch/34-game-move-path.md,
        // "Every structure indexed by the game ply or the move number").
        const g = dgroup.memWord(h, gs.game_ply_addr);
        const mn = dgroup.memWord(h, gs.move_number_addr);
        if (!((g >= gs.scan_room or out.slides == 0) and g < 402 and mn < 202 and g == 2 * (mn - 1) + h.get(0x8DDE))) {
            std.debug.print("gameslide: play on ({s}): after search {d}: game ply {d}, move number {d}, side to move {d}\n", .{ p.name, out.n, g, mn, h.get(0x8DDE) });
            return error.OutsideTheRecord;
        }
        out.max_ply = @max(out.max_ply, g);
    }
    return out;
}

test "gameslide: playing on past move 201 in auto-play: the same moves and node counts whatever the slides" {
    const gpa = std.testing.allocator;
    if (!try longTests(gpa)) return;
    const policies = [_]Policy{
        .{ .name = "at 300, as far as allowed", .at = gs.due_ply, .by = 0 },
        .{ .name = "at 390, by 2", .at = 390, .by = 2 },
        .{ .name = "at 350, by 100", .at = 350, .by = 100 },
    };
    const games = [_]struct { dir: []const u8, scenario: []const u8, depth: u8, max: usize }{
        // The long game played on at depth 2: mate past the original's end.
        .{ .dir = dir, .scenario = "long-ply397-d3", .depth = 2, .max = played_searches },
        // An ending with bishops of opposite colours, set up at ply 0 and played at depth 2
        // for `played_searches` plies, through two or more slides.
        .{ .dir = "whole/corpus2", .scenario = "minor-ending-d4", .depth = 2, .max = played_searches },
    };
    for (games) |game| try playGames(gpa, &policies, game.dir, game.scenario, game.depth, game.max);
}

fn playGames(gpa: std.mem.Allocator, policies: []const Policy, in_dir: []const u8, scenario: []const u8, depth: u8, max: usize) !void {
    const runs = try gpa.alloc(Played, policies.len);
    defer gpa.free(runs);
    for (policies, 0..) |p, i| {
        runs[i] = try playOn(gpa, p, in_dir, scenario, depth, max);
        var total: u64 = 0;
        for (runs[i].nodes[0..runs[i].n]) |x| total += x;
        std.debug.print("gameslide: play on from {s} at depth {d} ({s}): {d} searches ({d} nodes) from game ply {d} to what would be ply {d}, {s}; {d} slides dropping {d} plies, the highest game ply held {d}\n", .{ scenario, depth, p.name, runs[i].n, total, runs[i].start_ply, runs[i].end_ply + runs[i].dropped, if (runs[i].status >= 8) "the game ended" else "searches left to play", runs[i].slides, runs[i].dropped, runs[i].max_ply });
    }
    // The game went past the original's last searchable ply (401).
    try std.testing.expect(runs[0].end_ply + runs[0].dropped > 402);
    for (runs[1..]) |r| {
        try std.testing.expectEqual(runs[0].n, r.n);
        try std.testing.expectEqualSlices([4]u8, runs[0].best[0..runs[0].n], r.best[0..r.n]);
        try std.testing.expectEqualSlices(u64, runs[0].nodes[0..runs[0].n], r.nodes[0..r.n]);
        try std.testing.expectEqualSlices(u64, runs[0].makes[0..runs[0].n], r.makes[0..r.n]);
    }
}

// ---------------------------------------------------------------------------
// The readers across a slide, on the record alone
// ---------------------------------------------------------------------------

/// find_last_irreversible_ply (0000:887E) as the listing reads: from the game ply down
/// to the first reversible-flag 0, at most to g - 101.
fn lastIrreversible(img: *const Image) i16 {
    const g: i16 = @bitCast(word(img, gs.game_ply_addr));
    var at: i16 = g;
    while (!(g - 100 > at) and img[gs.flags_addr + @as(u16, @intCast(at))] != 0) at -= 1;
    return at;
}

test "gameslide: the repetition count and the last irreversible ply read the same across a slide (the ply-258 snapshot)" {
    const gpa = std.testing.allocator;
    const s = try R.init(gpa, ert_test.golden_slots);
    defer s.deinit();
    s.slide_when_due = false; // the slides of this test are made by hand
    try loadStart(gpa, s, "long-ply258-d3");
    // The image alone, as data: no search.
    si.imageBegin(s);
    defer si.imageEnd(s);
    const g: u16 = word(s.test_img, gs.game_ply_addr);
    // A third repetition: the current key at g - 4 and g - 8; a last irreversible move
    // more than 100 plies back.
    for ([_]u16{ g - 4, g - 8 }) |p| @memcpy(s.test_far[0x3A34 + 6 * @as(usize, p) ..][0..6], s.test_img[0x8CCC..][0..6]);
    for ([_]bool{ false, true }) |fifty| {
        if (fifty) @memset(s.test_img[gs.flags_addr + g - 120 ..][0..121], 0xFF);
        const last = lastIrreversible(s.test_img);
        setWord(s.test_img, gs.last_irreversible_addr, @bitCast(last));
        const hist: [*]const [6]u8 = @ptrCast(&s.test_far[0x3A34]);
        const reps = rp.repetitionCount(hist[0..1997], @bitCast(g), last, s.test_img[0x8CCC..][0..6].*);
        try std.testing.expectEqual(@as(u16, 2), reps);
        if (fifty) try std.testing.expectEqual(@as(i16, @bitCast(g)) - 101, last);
        var d: u16 = 2;
        while (@as(i32, g) - d >= gs.scan_room) : (d += 2) {
            const img = try gpa.create(Image);
            defer gpa.destroy(img);
            const far = try gpa.create(ert.Far);
            defer gpa.destroy(far);
            img.* = s.test_img.*;
            far.* = s.test_far.*;
            try gs.slide(img, far, d);
            const g2: i16 = @bitCast(word(img, gs.game_ply_addr));
            const last2 = lastIrreversible(img);
            try std.testing.expectEqual(last - @as(i16, @intCast(d)), last2);
            try std.testing.expectEqual(@as(i16, @intCast(d)), @as(i16, @bitCast(g)) - g2);
            const hist2: [*]const [6]u8 = @ptrCast(&far[0x3A34]);
            try std.testing.expectEqual(reps, rp.repetitionCount(hist2[0..1997], g2, last2, img[0x8CCC..][0..6].*));
        }
    }
}
