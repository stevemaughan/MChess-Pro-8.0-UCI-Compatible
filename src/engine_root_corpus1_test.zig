//! Every search of tests/golden/corpus1.jsonl (212 searches in 16 scenarios: openings from
//! the start position at depths 4 and 5, and one whole game at depth 3 that ends in mate)
//! through the joined engine's game-move path (src/engine_root.zig), compared on the four
//! values of the golden file: the move played, node entries, makes and the line hash.
//!
//! Each scenario starts from the oracle's DGROUP snapshot at main 0000:0526 of its first
//! search, with the far segment 5A7B and the main hash tables' non-zero slots from the
//! oracle's subtree file of that search's first node (tests/golden/whole/corpus1/,
//! recorded with `--dev003 move --hash-tail zero --snapshot main --subtree 1`; the
//! self-play game's with `"searches": 1`, since the oracle writes a scenario only when it
//! finishes). Its later searches follow the program's move and the auto-play turn
//! (`EngineRoot.playMove`, `EngineRoot.nextTurnAutoPlay`), as in src/engine_root_test.zig.
//!
//! The first difference in a scenario ends that scenario (the later searches start from a
//! different state); it is named with its scenario and search, and is an error unless
//! tests/known_failures.txt lists `whole-path-corpus1:<scenario>:<search>`.
//!
//! The longest searches run only with MCHESS_LONG_TESTS set (`maxNodes`). The game's
//! search 18 found the one difference so far, in prepare_eval (src/evaltables.zig,
//! `kingWings`: 0000:B8A7 adds 18h, not 18, to WP[b4] and WP[b5]).

const std = @import("std");
const si = @import("state_image.zig");
const builtin = @import("builtin");
const ert = @import("engine_root.zig");
const ert_test = @import("engine_root_test.zig");
const sn = @import("searchnode.zig");
const tablebase = @import("tablebase.zig");

const R = ert_test.R;

/// The far data segment 5A7B (the game record) and the main hash tables' non-zero slots at
/// the first node entry of a search, from the oracle's subtree file of node 1
/// (tools/oracle/oracle.py SUBTREE_FORMAT): DGROUP follows a 25-byte header, the far
/// segment follows DGROUP, then the slots. Returns false if the file is not recorded.
fn farFromSubtree(gpa: std.mem.Allocator, name: []const u8, far: *ert.Far, tables: *[2]sn.HashTable) !bool {
    const compressed = ert_test.readGolden(gpa, name) catch return false;
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
    return true;
}

/// The six tablebase files of the shipped TB folder (reference/original/M80/TB): the root
/// probes them in every search with five men or fewer (docs/arch/41-tablebases.md).
const TbFiles = struct {
    const names = [_][]const u8{ "KPK.TBW", "KPK.TBB", "KQK.TBW", "KQK.TBB", "KRK.TBW", "KRK.TBB" };
    data: [names.len]?[]u8 = @splat(null),

    fn lookup(ctx: ?*const anyopaque, loc: tablebase.Location, name: []const u8) ?[]const u8 {
        const self: *const TbFiles = @ptrCast(@alignCast(ctx.?));
        if (loc != .program_tb) return null;
        for (names, 0..) |n, i| if (std.ascii.eqlIgnoreCase(n, name)) return self.data[i];
        return null;
    }
    fn files(self: *const TbFiles) tablebase.Files {
        return .{ .ctx = self, .lookupFn = lookup };
    }
    fn load(gpa: std.mem.Allocator) !TbFiles {
        var t: TbFiles = .{};
        errdefer t.deinit(gpa);
        for (names, 0..) |n, i| {
            var buf: [256]u8 = undefined;
            const path = try std.fmt.bufPrint(&buf, "{s}/../../reference/original/M80/TB/{s}", .{ @import("build_options").golden_dir, n });
            t.data[i] = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, gpa, .limited(1 << 20));
        }
        return t;
    }
    fn deinit(self: *TbFiles, gpa: std.mem.Allocator) void {
        for (&self.data) |*d| if (d.*) |x| gpa.free(x);
    }
};

const Totals = struct {
    ran: u32 = 0,
    matched: u32 = 0,
    not_run: u32 = 0,
    unexpected: u32 = 0,
    nodes: u64 = 0,
};

/// Runs the searches of corpus1.jsonl whose scenario `pick` accepts. `max_nodes`: a search
/// the golden file gives more node entries than this, and the rest of its scenario, are not
/// run (each is printed).
fn runCorpus1(gpa: std.mem.Allocator, s: *R, pick: *const fn ([]const u8) bool, max_nodes: ?u64) !Totals {
    const dir = "whole/corpus1";
    const known = try ert_test.readKnownFailures(gpa);
    defer gpa.free(known);
    const jl = try ert_test.readGolden(gpa, "corpus1.jsonl");
    defer gpa.free(jl);
    var lines = std.mem.splitScalar(u8, jl, '\n');
    var scenario_buf: [64]u8 = undefined;
    var current: []const u8 = "";
    var skip_scenario = false;
    var t: Totals = .{};
    while (lines.next()) |text| {
        if (text.len == 0) continue;
        const parsed = try std.json.parseFromSlice(std.json.Value, gpa, text, .{});
        defer parsed.deinit();
        const o = parsed.value.object;
        if (o.get("search") == null) {
            // A scenario header: the recording must be the corrected original.
            const d = o.get("dev003") orelse return error.GoldenNotDev003Move;
            try std.testing.expectEqualStrings("move", d.string);
            try std.testing.expectEqualStrings("zero", o.get("hash_tail").?.object.get("mode").?.string);
            continue;
        }
        const scenario = o.get("scenario").?.string;
        if (!pick(scenario)) continue;
        const search = o.get("search").?.integer;
        var name_buf: [160]u8 = undefined;
        if (!std.mem.eql(u8, scenario, current)) {
            @memcpy(scenario_buf[0..scenario.len], scenario);
            current = scenario_buf[0..scenario.len];
            const snap = ert_test.readGolden(gpa, try std.fmt.bufPrint(&name_buf, "{s}/{s}-s1-main.bin", .{ dir, scenario })) catch {
                std.debug.print("join-root corpus1: {s}: no snapshot at main of search 1 recorded: scenario not run\n", .{scenario});
                skip_scenario = true;
                t.not_run += 1;
                t.unexpected += 1;
                continue;
            };
            defer gpa.free(snap);
            skip_scenario = false;
            si.fromImage(s, snap[0..0x10000], null);
            if (!try farFromSubtree(gpa, try std.fmt.bufPrint(&name_buf, "{s}/{s}-s1-subtree-1.zst", .{ dir, scenario }), s.test_far, s.tables)) {
                std.debug.print("join-root corpus1: {s}: no subtree of node 1 recorded: scenario not run\n", .{scenario});
                skip_scenario = true;
                t.not_run += 1;
                t.unexpected += 1;
                continue;
            }
            si.refreshRecord(s);
        } else {
            if (skip_scenario) {
                t.not_run += 1;
                continue;
            }
            s.playMove();
            s.nextTurnAutoPlay();
        }
        const want = ert_test.expectedOf(parsed.value);
        if (max_nodes) |mx| if (want.nodes > mx) {
            std.debug.print("join-root corpus1: {s} search {d}: {d} nodes, above the {d} this build runs (MCHESS_LONG_TESTS=1 runs all): it and the rest of the scenario not run\n", .{ scenario, search, want.nodes, mx });
            skip_scenario = true;
            t.not_run += 1;
            continue;
        };
        s.failure = null;
        s.trace = false;
        const out = s.search(.own);
        t.ran += 1;
        t.nodes += out.nodes;
        const v = ert_test.verdictOf(s, out, want);
        var id_buf: [128]u8 = undefined;
        const id = try std.fmt.bufPrint(&id_buf, "whole-path-corpus1:{s}:{d}", .{ scenario, search });
        const ok = ert_test.allEqual(v) and s.failure == null;
        if (ok) {
            t.matched += 1;
            if (ert_test.knownFailure(known, id)) {
                std.debug.print("join-root corpus1: {s} is listed in tests/known_failures.txt but now matches: remove it\n", .{id});
                t.unexpected += 1;
            }
            continue;
        }
        var mb: [5]u8 = undefined;
        std.debug.print("join-root corpus1: FIRST DIFFERENCE in {s}, search {d}: played {s} ({s}), nodes {d} ({d}), makes {d} ({d}), line {s}{s}{s}; the rest of the scenario not run\n", .{ scenario, search, ert_test.moveText(out.best, &mb), want.played, out.nodes, want.nodes, out.makes, want.makes, if (v.line) "equal" else "differs", if (s.failure != null) "; " else "", s.failure orelse "" });
        if (!ert_test.knownFailure(known, id)) t.unexpected += 1;
        skip_scenario = true;
    }
    return t;
}

fn report(label: []const u8, s: *R, t: Totals) void {
    std.debug.print("join-root corpus1: {s}: {d} searches run ({d} nodes), {d} equal on all four values, {d} not run, {d} unexpected results\n", .{ label, t.ran, t.nodes, t.matched, t.not_run, t.unexpected });
    std.debug.print("join-root corpus1: bindings never called: main before the loop:", .{});
    for (std.enums.values(@import("rootprep.zig").Callee)) |c| if (s.prep_calls[@backingInt(c)] == 0) std.debug.print(" {s}", .{@tagName(c)});
    std.debug.print("; the loop and root_search:", .{});
    for (std.enums.values(@import("rootsearch.zig").Callee)) |c| if (s.loop_calls[@backingInt(c)] == 0) std.debug.print(" {s}", .{@tagName(c)});
    std.debug.print("\n", .{});
}

/// The largest search run, by the golden file's node count: a search above it is left out
/// with the rest of its scenario, and each one left out is printed. The whole corpus is
/// 8,951,688 nodes, about 2.5 minutes in ReleaseFast; by default the other builds run the
/// searches up to 200,000 nodes (194 of 212, 4,500,588 nodes: left out are queens-off-d5
/// and selfplay-d3 from search 139), and Debug, at about 1,500 nodes a second, those up to
/// 15,000 (52 searches, 319,845 nodes; selfplay-d3 to search 46). With the environment
/// variable MCHESS_LONG_TESTS set and not empty, every search is run in every build.
fn maxNodes(gpa: std.mem.Allocator) !?u64 {
    if (try std.testing.environ.containsUnempty(gpa, "MCHESS_LONG_TESTS")) return null;
    return if (builtin.mode == .debug) 15_000 else 200_000;
}

fn isOpening(name: []const u8) bool {
    return !std.mem.eql(u8, name, "selfplay-d3");
}
fn isGame(name: []const u8) bool {
    return std.mem.eql(u8, name, "selfplay-d3");
}

test "join-root: every search of tests/golden/corpus1.jsonl's openings through the game-move path (15 scenarios, 58 searches)" {
    const gpa = std.testing.allocator;
    const s = try R.init(gpa, ert_test.golden_slots);
    defer s.deinit();
    var tbf = try TbFiles.load(gpa);
    defer tbf.deinit(gpa);
    s.tb_files = tbf.files();
    const t = try runCorpus1(gpa, s, &isOpening, try maxNodes(gpa));
    report("openings", s, t);
    try std.testing.expectEqual(@as(u32, 0), t.unexpected);
}

test "join-root: every search of the whole game in tests/golden/corpus1.jsonl (selfplay-d3, 154 searches) through the game-move path" {
    const gpa = std.testing.allocator;
    const s = try R.init(gpa, ert_test.golden_slots);
    defer s.deinit();
    var tbf = try TbFiles.load(gpa);
    defer tbf.deinit(gpa);
    s.tb_files = tbf.files();
    const t = try runCorpus1(gpa, s, &isGame, try maxNodes(gpa));
    report("the whole game", s, t);
    try std.testing.expectEqual(@as(u32, 0), t.unexpected);
}
