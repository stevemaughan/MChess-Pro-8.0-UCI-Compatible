//! A position entered through Setup mode by the engine (src/adapt_setup.zig) against the
//! oracle's corpus2 (tests/golden/corpus2.jsonl: positions typed into the original's
//! Setup mode, then Ctrl-A): for every scenario, the engine's image at main 0000:0526 of
//! search 1, after its own start-up, Setup mode with the header's FEN and Ctrl-A, equals
//! the oracle's snapshot (tests/golden/whole/corpus2/<scenario>-s1-main.bin) on every byte
//! a unit holds but the listed exceptions, and its game record the oracle's; then every
//! search of corpus2 from that start, without the snapshot, is equal on the move, the
//! node entries, the makes and the line hash.

const std = @import("std");
const si = @import("state_image.zig");
const ert = @import("engine_root.zig");
const ert_test = @import("engine_root_test.zig");
const ngt = @import("newgame_test.zig");
const fen = @import("fen.zig");
const setup = @import("setup.zig");
const tablebase = @import("tablebase.zig");
const as = @import("adapt_setup.zig");

const R = ert_test.R;

/// The bytes a unit holds that the engine's Setup path leaves different from the
/// original's image at main of the first search after a set-up, beyond the start-up's
/// (src/newgame_test.zig `exceptions`), each with its reason.
pub const exceptions = [_]ngt.Exception{};

fn isException(a: usize) ?[]const u8 {
    for (ngt.exceptions) |e| if (a >= e.lo and a <= e.hi) return e.why;
    for (exceptions) |e| if (a >= e.lo and a <= e.hi) return e.why;
    return null;
}

fn heldDiffs(label: []const u8, got: []const u8, want: []const u8) usize {
    var bad: usize = 0;
    var excused: usize = 0;
    for (got, want, 0..) |g, w, a| {
        if (g == w or ert_test.isStack(a) or !ert.mappedByAUnit(a)) continue;
        if (isException(a) != null) {
            excused += 1;
            continue;
        }
        if (bad < 60) std.debug.print("  {s}: DG:{X:0>4} engine {X:0>2}, original {X:0>2}\n", .{ label, a, g, w });
        bad += 1;
    }
    std.debug.print("adapt_setup: {s}: {d} bytes a unit holds differ outside the exceptions, {d} inside them\n", .{ label, bad, excused });
    return bad;
}

/// The far segment at the first node entry of search 1 (the oracle's subtree file), or
/// null when none is recorded (the tablebase scenarios play without a search).
fn recordedFar(gpa: std.mem.Allocator, name: []const u8) !?[]u8 {
    const compressed = ert_test.readGolden(gpa, name) catch return null;
    defer gpa.free(compressed);
    var in: std.Io.Reader = .fixed(compressed);
    const window = try gpa.alloc(u8, std.compress.zstd.default_window_len + std.compress.zstd.block_size_max);
    defer gpa.free(window);
    var zd = std.compress.zstd.Decompress.init(&in, window, .{});
    const raw = try zd.reader.allocRemaining(gpa, .limited(64 << 20));
    defer gpa.free(raw);
    return try gpa.dupe(u8, raw[25 + 0x10000 ..][0..0x10000]);
}

/// The six tablebase files of the shipped TB folder.
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

/// The scenario header's FEN (board and side only, as the oracle types it) as a
/// description with the rights Setup mode gives the board.
pub fn descriptionOf(text: []const u8) !fen.Description {
    var buf: [128]u8 = undefined;
    const full = try std.fmt.bufPrint(&buf, "{s} - - 0 1", .{text});
    var d = try fen.parse(full);
    d.castling = as.rightsFromBoard(&d.board);
    return d;
}

/// Start-up at `depth`, Setup mode with `d`, Ctrl-A: the engine at main of search 1.
pub fn startFromSetup(s: *R, d: *const fen.Description, depth: u16) !void {
    s.startUp(.{}, .{}, .{}, depth);
    try std.testing.expectEqual(setup.Legality.legal, as.enter(s, d));
    try std.testing.expect(s.autoPlay());
    try std.testing.expect(s.failure == null);
    // Stage B step 8, stage 4: these run on the members; the image made current.
    si.toImage(s);
}

test "adapt_setup: every corpus2 scenario set up by the engine: the image at main of search 1, then every search" {
    const gpa = std.testing.allocator;
    const s = try R.init(gpa, ert_test.golden_slots);
    defer s.deinit();
    var tbf = try TbFiles.load(gpa);
    defer tbf.deinit(gpa);
    s.tb_files = tbf.files();
    const jl = try ert_test.readGolden(gpa, "corpus2.jsonl");
    defer gpa.free(jl);
    var lines = std.mem.splitScalar(u8, jl, '\n');
    var scenarios: u32 = 0;
    var image_bad: u32 = 0;
    var ran: u32 = 0;
    var matched: u32 = 0;
    var not_run: u32 = 0;
    var current_buf: [64]u8 = undefined;
    var current: []const u8 = "";
    var skip = false;
    const max_nodes: ?u64 = if (@import("builtin").mode == .debug) 25_000 else null;
    while (lines.next()) |text| {
        if (text.len == 0) continue;
        const parsed = try std.json.parseFromSlice(std.json.Value, gpa, text, .{});
        defer parsed.deinit();
        const o = parsed.value.object;
        if (o.get("search") == null) {
            // A scenario header: start-up, Setup mode with its FEN, Ctrl-A.
            try std.testing.expectEqualStrings("move", o.get("dev003").?.string);
            try std.testing.expectEqualStrings("zero", o.get("hash_tail").?.object.get("mode").?.string);
            const name = o.get("scenario").?.string;
            @memcpy(current_buf[0..name.len], name);
            current = current_buf[0..name.len];
            skip = false;
            const d = try descriptionOf(o.get("fen").?.string);
            try startFromSetup(s, &d, @intCast(o.get("depth").?.integer));
            scenarios += 1;
            var nb: [160]u8 = undefined;
            const snap = try ert_test.readGolden(gpa, try std.fmt.bufPrint(&nb, "whole/corpus2/{s}-s1-main.bin", .{name}));
            defer gpa.free(snap);
            var lb: [96]u8 = undefined;
            var bad = heldDiffs(try std.fmt.bufPrint(&lb, "{s}: Setup and Ctrl-A, against main of search 1", .{name}), s.test_img, snap);
            if (try recordedFar(gpa, try std.fmt.bufPrint(&nb, "whole/corpus2/{s}-s1-subtree-1.zst", .{name}))) |far| {
                defer gpa.free(far);
                var far_bad: usize = 0;
                // The search writes its root key into the record at the game ply before
                // node 1 (prepare_eval's caller, 0000:960A); after a set-up the game ply is
                // the side to move, so with Black to move that is ply 1's entry, which must
                // then be the position's key.
                const ply: usize = std.mem.readInt(u16, s.test_img[0x9FC8..][0..2], .little);
                const root_key = ert.keys_offset + 6 * ply;
                for (s.test_far, far, 0..) |g, w, a| {
                    if (a >= 0x43B8 and a < 0x68E6) continue; // past the record's keys: see newgame_test
                    if (ply != 0 and a >= root_key and a < root_key + 6) {
                        if (w != s.test_img[0x8CCC + a - root_key]) far_bad += 1;
                        continue;
                    }
                    if (g != w and ert.GameRecordMap.covers(a)) {
                        if (far_bad < 20) std.debug.print("  {s}: game record 5A7B:{X:0>4} engine {X:0>2}, original {X:0>2}\n", .{ name, a, g, w });
                        far_bad += 1;
                    }
                }
                bad += far_bad;
            }
            if (bad != 0) image_bad += 1;
            continue;
        }
        const search = o.get("search").?.integer;
        if (skip) {
            not_run += 1;
            continue;
        }
        if (search > 1) {
            s.playMove();
            s.nextTurnAutoPlay();
        }
        const want = ert_test.expectedOf(parsed.value);
        if (max_nodes) |mx| if (want.nodes > mx) {
            std.debug.print("adapt_setup: {s} search {d}: {d} nodes, above the {d} this build runs: the rest of the scenario not run\n", .{ current, search, want.nodes, mx });
            skip = true;
            not_run += 1;
            continue;
        };
        s.failure = null;
        const out = s.search(.own);
        ran += 1;
        const v = ert_test.verdictOf(s, out, want);
        const ok = ert_test.allEqual(v) and s.failure == null;
        if (ok) matched += 1;
        var mb: [5]u8 = undefined;
        std.debug.print("adapt_setup: {s} search {d} from the engine's own set-up: played {s} ({s}), nodes {d} ({d}), makes {d} ({d}), line {s}{s}{s}\n", .{ current, search, ert_test.moveText(out.best, &mb), want.played, out.nodes, want.nodes, out.makes, want.makes, if (v.line) "equal" else "differs", if (s.failure != null) "; " else "", s.failure orelse "" });
    }
    std.debug.print("adapt_setup: corpus2: {d} scenarios set up, {d} images differ; {d} searches run, {d} equal on all four values, {d} not run\n", .{ scenarios, image_bad, ran, matched, not_run });
    try std.testing.expectEqual(@as(u32, 16), scenarios);
    try std.testing.expectEqual(@as(u32, 0), image_bad);
    try std.testing.expectEqual(ran, matched);
    if (max_nodes == null) try std.testing.expectEqual(@as(u32, 73), ran);
}

test "DEV-027: a withheld castling right leaves the main key and the record's ply-0 key stale; corrected, they are rebuilt, and no search changes" {
    const builtin = @import("builtin");
    const pos = @import("position.zig");
    const gpa = std.testing.allocator;
    const s = try R.init(gpa, ert_test.golden_slots);
    defer s.deinit();
    const depth: u16 = if (builtin.mode == .debug) 3 else 4;
    const fixed = comptime blk: {
        var f = pos.Fixes.original;
        f.dev027_loader_key = true;
        break :blk f;
    };
    const cases = [_][]const u8{
        "r3k2r/p6p/8/8/8/8/P6P/R3K2R w Kq - 0 1",
        "r3k2r/p6p/8/8/8/8/P6P/R3K2R w - - 0 1",
        "r3k2r/p6p/8/8/8/8/P6P/R3K2R b kq - 0 1",
        "r3k2r/p6p/8/8/8/8/P6P/R3K2R b KQ - 0 1",
    };
    const Out = struct { nodes: u64, makes: u64, best: [4]u8 };
    for (cases) |text| {
        const d = try fen.parse(text);
        var outs: [2][3]Out = undefined;
        inline for (.{ pos.Fixes.original, fixed }, 0..) |fx, k| {
            s.startUp(.{}, .{}, .{}, depth);
            try std.testing.expectEqual(setup.Legality.legal, as.enterFenFixes(fx, s, &d));
            si.toImage(s);
            var p: pos.Position = .{};
            var pb: @import("adapt_position.zig").PositionMap.Snapshot = undefined;
            @import("adapt_position.zig").PositionMap.loadSnap(&p, s.test_img, &pb);
            const want = p.hashFromScratch().main;
            const main_key = std.mem.readInt(u48, s.test_img[0x8CCC..][0..6], .little);
            const record0 = std.mem.readInt(u48, s.test_far[ert.keys_offset..][0..6], .little);
            if (k == 0) {
                // The original: the key counts the withdrawn rights as held.
                try std.testing.expect(main_key != want);
                try std.testing.expect(record0 != want);
                try std.testing.expectEqual(main_key, record0);
            } else {
                try std.testing.expectEqual(want, main_key);
                try std.testing.expectEqual(want, record0);
                try std.testing.expectEqual(want, s.rec.keys[0]);
            }
            try std.testing.expect(s.autoPlay());
            for (0..3) |n| {
                if (n != 0) {
                    s.playMove();
                    s.nextTurnAutoPlay();
                }
                s.failure = null;
                const o = s.search(.own);
                try std.testing.expect(s.failure == null);
                outs[k][n] = .{ .nodes = o.nodes, .makes = o.makes, .best = o.best };
            }
        }
        for (0..3) |n| {
            try std.testing.expectEqual(outs[0][n].nodes, outs[1][n].nodes);
            try std.testing.expectEqual(outs[0][n].makes, outs[1][n].makes);
            try std.testing.expectEqual(outs[0][n].best, outs[1][n].best);
        }
        std.debug.print("DEV-027: {s}: the keys differ with the fix off and are rebuilt with it on; three searches at depth {d} equal ({d}, {d}, {d} nodes)\n", .{ text, depth, outs[1][0].nodes, outs[1][1].nodes, outs[1][2].nodes });
    }
}

/// Every search of a deep golden file (tests/golden/deep.jsonl, deep-long.jsonl: the
/// original at Fixed depth 5 to 30, auto-play): a scenario with a FEN through the set-up
/// route (start-up, Setup mode, Ctrl-A, as corpus2), one without through the game route
/// (`position startpos moves ...` into the engine, then auto-play at the Fixed depth level,
/// as engine_hash_test.zig does); later searches after the program's move and the turn.
/// Returns the number of searches run; fails at the first that differs.
fn runDeep(gpa: std.mem.Allocator, name: []const u8) !u32 {
    const engine_mod = @import("engine.zig");
    const pos = @import("position.zig");
    const E = engine_mod.EngineOf(pos.Fixes.original);
    const s_setup = try R.init(gpa, ert_test.golden_slots);
    defer s_setup.deinit();
    var tbf = try TbFiles.load(gpa);
    defer tbf.deinit(gpa);
    s_setup.tb_files = tbf.files();
    const e = try gpa.create(E);
    defer gpa.destroy(e);
    e.* = try E.init(gpa);
    defer e.deinit();
    e.reporting = false;
    const start = try fen.parse(fen.startpos);
    const jl = try ert_test.readGolden(gpa, name);
    defer gpa.free(jl);
    var lines = std.mem.splitScalar(u8, jl, '\n');
    var s: *R = s_setup;
    var current_buf: [64]u8 = undefined;
    var current: []const u8 = "";
    var ran: u32 = 0;
    var bad: u32 = 0;
    while (lines.next()) |text| {
        if (text.len == 0) continue;
        const parsed = try std.json.parseFromSlice(std.json.Value, gpa, text, .{});
        defer parsed.deinit();
        const o = parsed.value.object;
        if (o.get("search") == null) {
            try std.testing.expectEqualStrings("move", o.get("dev003").?.string);
            try std.testing.expectEqualStrings("zero", o.get("hash_tail").?.object.get("mode").?.string);
            try std.testing.expect(o.get("mode") == null); // auto-play
            const sc = o.get("scenario").?.string;
            @memcpy(current_buf[0..sc.len], sc);
            current = current_buf[0..sc.len];
            const depth: u16 = @intCast(o.get("depth").?.integer);
            const fen_v = o.get("fen");
            if (fen_v != null and fen_v.? == .string) {
                const f = fen_v.?;
                s = s_setup;
                const d = try descriptionOf(f.string);
                try startFromSetup(s, &d, depth);
            } else {
                var game: [64]fen.UciMove = undefined;
                var n: usize = 0;
                for (o.get("setup").?.array.items) |m| {
                    game[n] = try fen.parseMove(m.string);
                    n += 1;
                }
                try std.testing.expect(e.engine().setPosition(&start, .new_game, game[0..n]) == null);
                s = e.root;
                // Auto-play on, the Fixed depth level (what the engine's `go depth` writes).
                s.home().set(0x9FCF, 1);
                s.home().set(0xA274, 3);
                @import("dgroup.zig").memSetWord(s.home(), 0x1E02, depth);
            }
            continue;
        }
        const k = o.get("search").?.integer;
        if (k > 1) {
            s.playMove();
            s.nextTurnAutoPlay();
        }
        const want = ert_test.expectedOf(parsed.value);
        s.failure = null;
        const out = s.search(.own);
        ran += 1;
        const v = ert_test.verdictOf(s, out, want);
        const ok = ert_test.allEqual(v) and s.failure == null;
        if (!ok) bad += 1;
        var mb: [5]u8 = undefined;
        std.debug.print("deep: {s} search {d}: played {s} ({s}), nodes {d} ({d}), makes {d} ({d}), line {s}{s}{s}\n", .{ current, k, ert_test.moveText(out.best, &mb), want.played, out.nodes, want.nodes, out.makes, want.makes, if (v.line) "equal" else "differs", if (s.failure != null) "; " else "", s.failure orelse "" });
    }
    std.debug.print("deep: {s}: {d} searches run, {d} differ\n", .{ name, ran, bad });
    try std.testing.expectEqual(@as(u32, 0), bad);
    return ran;
}

test "adapt_setup: every search of tests/golden/deep.jsonl (Fixed depth 5 to 30; at depth 30 H passes the 40-byte table at DG:3766)" {
    try std.testing.expectEqual(@as(u32, 11), try runDeep(std.testing.allocator, "deep.jsonl"));
}

test "adapt_setup: every search of tests/golden/deep-long.jsonl (Fixed depth 7 to 26; MCHESS_LONG_TESTS=1 only)" {
    const long = try std.testing.environ.containsUnempty(std.testing.allocator, "MCHESS_LONG_TESTS");
    if (!long) {
        std.debug.print("deep-long.jsonl: about 44 million nodes; set MCHESS_LONG_TESTS=1 to run it\n", .{});
        return;
    }
    try std.testing.expectEqual(@as(u32, 12), try runDeep(std.testing.allocator, "deep-long.jsonl"));
}
