//! Whole searches of the joined engine (src/engine_root.zig) against the original's
//! golden files (docs/arch/60-engine-assembly.md section 6).
//!
//! The first test runs search 1 of the smoke scenario `start-d3` from the oracle's
//! snapshot of DGROUP where main begins to prepare it (tests/golden/diagnosis/), and
//! compares the four values of the golden file (move played, node entries, makes, the
//! SHA-256 "line" over every move made). It also compares the image with the oracle's
//! snapshots after prepare_eval and at the first node entry at ply 2, and on a
//! difference names the first differing event of the trace and the first differing
//! checkpoint.

const std = @import("std");
const si = @import("state_image.zig");
const ert = @import("engine_root.zig");
const pos = @import("position.zig");
const sn = @import("searchnode.zig");
const rp = @import("rootprep.zig");
const rs = @import("rootsearch.zig");
const dgroup = @import("dgroup.zig");
const tablebase = @import("tablebase.zig");

pub const R = ert.EngineRoot(pos.Fixes.original);

/// Slots per main hash table: the original's 30,720 KB tables (mask 3FFFFFh, 3/4 mode).
pub const golden_slots = 3_145_728;

pub fn readGolden(gpa: std.mem.Allocator, name: []const u8) ![]u8 {
    var path_buf: [256]u8 = undefined;
    const dir = @import("build_options").golden_dir;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ dir, name });
    return std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, gpa, .limited(64 << 20));
}

/// The stack area of the original in the recordings (CD72..D640) and the scaffold's own
/// (F000..FFFF): left out of image comparisons.
pub fn isStack(a: usize) bool {
    return (a >= 0xC000 and a < 0xD640) or a >= 0xF000;
}

/// Prints up to `max` differing bytes of `got` against `want` outside the stack (and every
/// byte a unit holds, up to 40); returns how many of those a unit holds (`mappedByAUnit`).
pub fn diffImages(label: []const u8, got: []const u8, want: []const u8, max: usize) usize {
    var n: usize = 0;
    var mapped: usize = 0;
    for (got, want, 0..) |g, w, a| {
        if (g == w or isStack(a)) continue;
        const m = ert.mappedByAUnit(a);
        if (n < max or (m and mapped < 40)) std.debug.print("  {s}: DG:{X:0>4} engine {X:0>2}, original {X:0>2}{s}\n", .{ label, a, g, w, if (m) "  (held by a unit)" else "" });
        n += 1;
        if (m) mapped += 1;
    }
    if (n > 0) std.debug.print("  {s}: {d} bytes differ, {d} of them held by a unit\n", .{ label, n, mapped });
    return mapped;
}

const SnapHook = struct {
    s: *R,
    prepared: []const u8,
    node_ply2: []const u8,
    seen_ply2: bool = false,
    diffs_prepared: usize = 0,
    diffs_ply2: usize = 0,
    checked_prepared: bool = false,

    fn self(ctx: *anyopaque) *SnapHook {
        return @ptrCast(@alignCast(ctx));
    }
    fn before(ctx: *anyopaque, site: u16, which: ert.Which, args: []const u16) bool {
        _ = site;
        const h = self(ctx);
        const ply: ?u16 = switch (which) {
            .prep => |c| if (c == .node_white or c == .node_black) args[3] else null,
            .loop => |c| if (c == .node_white or c == .node_black) args[3] else null,
        };
        if (ply) |p| if (p == 2 and !h.seen_ply2) {
            h.seen_ply2 = true;
            h.diffs_ply2 = diffImages("at the first node entry at ply 2", h.s.test_img, h.node_ply2, 40);
        };
        return true;
    }
    fn after(ctx: *anyopaque, site: u16, which: ert.Which, args: []const u16, real: ?u32) u32 {
        _ = site;
        _ = args;
        const h = self(ctx);
        switch (which) {
            .prep => |c| if (c == .prepare_eval) {
                h.checked_prepared = true;
                h.diffs_prepared = diffImages("after prepare_eval", h.s.test_img, h.prepared, 40);
            },
            else => {},
        }
        return real.?;
    }
};

pub const Expected = struct {
    played: []const u8,
    nodes: u64,
    makes: u64,
    line: []const u8,
};

pub fn expectedOf(v: std.json.Value) Expected {
    const o = v.object;
    return .{
        .played = o.get("played").?.string,
        .nodes = @intCast(o.get("nodes").?.integer),
        .makes = @intCast(o.get("makes").?.integer),
        .line = o.get("line").?.string,
    };
}

pub fn squareName(sq: u8, buf: *[2]u8) []const u8 {
    const f: u8 = sq % 10;
    const r: u8 = sq / 10;
    buf[0] = 'a' + f -% 1;
    buf[1] = '0' + r -% 1;
    return buf;
}

/// The move as the golden files write it (from, to and a promotion letter).
pub fn moveText(m: [4]u8, buf: *[5]u8) []const u8 {
    var a: [2]u8 = undefined;
    var b: [2]u8 = undefined;
    @memcpy(buf[0..2], squareName(m[0] & 0x7F, &a));
    @memcpy(buf[2..4], squareName(m[1] & 0x7F, &b));
    const promo: ?u8 = switch (m[2]) {
        2 => 'n',
        3 => 'b',
        4 => 'r',
        5 => 'q',
        else => null,
    };
    if (promo) |p| {
        buf[4] = p;
        return buf[0..5];
    }
    return buf[0..4];
}

fn traceEventEq(e: ert.Event, v: std.json.Value) bool {
    const a = v.array.items;
    const kind = a[0].string;
    switch (e) {
        .make => |m| return std.mem.eql(u8, kind, "m") and a[1].integer == m.ply and a[2].integer == m.from and a[3].integer == m.to and a[4].integer == m.flag,
        .node => |n| {
            const side: []const u8 = if (n.side == sn.white) "w" else "b";
            return std.mem.eql(u8, kind, "n") and std.mem.eql(u8, a[1].string, side) and a[2].integer == n.ply and a[3].integer == n.alpha and a[4].integer == n.beta;
        },
        .ply2 => |r| {
            if (!std.mem.eql(u8, kind, "r")) return false;
            const side_ok = switch (a[1]) {
                .string => |t| std.mem.eql(u8, t, if (r.side == sn.white) "w" else "b"),
                .integer => |i| i == r.side,
                else => false,
            };
            return side_ok and a[2].integer == r.alpha and a[3].integer == r.beta;
        },
    }
}

fn printEvent(e: ert.Event) void {
    switch (e) {
        .make => |m| std.debug.print("[\"m\", {d}, {d}, {d}, {d}]", .{ m.ply, m.from, m.to, m.flag }),
        .node => |n| std.debug.print("[\"n\", \"{s}\", {d}, {d}, {d}]", .{ if (n.side == sn.white) "w" else "b", n.ply, n.alpha, n.beta }),
        .ply2 => |r| std.debug.print("[\"r\", {d}, {d}, {d}]", .{ r.side, r.alpha, r.beta }),
    }
}

/// Compares the engine's trace with the oracle's; prints the first difference. Returns
/// the index of the first difference, or null when the recorded part agrees.
pub var context: usize = 40;

pub fn compareTrace(events: []const ert.Event, trace: []const std.json.Value) ?usize {
    const n = @min(events.len, trace.len);
    for (0..n) |i| {
        if (!traceEventEq(events[i], trace[i])) {
            var nodes: usize = 0;
            var makes: usize = 0;
            for (events[0..i]) |e| switch (e) {
                .node => nodes += 1,
                .make => makes += 1,
                .ply2 => {},
            };
            std.debug.print("  after {d} node entries and {d} makes, first differing event {d}: engine ", .{ nodes, makes, i });
            printEvent(events[i]);
            std.debug.print(", original {f}\n", .{std.json.fmt(trace[i], .{})});
            const lo = if (i >= context) i - context else 0;
            for (lo..@min(i + 4, n)) |k| {
                std.debug.print("    event {d}: ", .{k});
                printEvent(events[k]);
                std.debug.print("   original {f}\n", .{std.json.fmt(trace[k], .{})});
            }
            return i;
        }
    }
    if (events.len < trace.len) {
        std.debug.print("  the engine's trace ends after {d} events, the original's has {d}\n", .{ events.len, trace.len });
        return events.len;
    }
    return null;
}

/// tests/known_failures.txt: lines `<test id> <reason>`; a listed search may differ
/// (it is reported), an unlisted one must match.
pub fn knownFailure(list: []const u8, id: []const u8) bool {
    var it = std.mem.splitScalar(u8, list, '\n');
    while (it.next()) |raw| {
        const l = std.mem.trim(u8, raw, " \r\t");
        if (l.len == 0 or l[0] == '#') continue;
        const end = std.mem.indexOfAny(u8, l, " \t") orelse l.len;
        if (std.mem.eql(u8, l[0..end], id)) return true;
    }
    return false;
}

pub fn readKnownFailures(gpa: std.mem.Allocator) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(std.testing.io, "tests/known_failures.txt", gpa, .limited(1 << 20)) catch |e| switch (e) {
        error.FileNotFound => try gpa.dupe(u8, ""),
        else => return e,
    };
}

pub const Verdict = struct { played: bool, nodes: bool, makes: bool, line: bool };

pub fn verdictOf(s: *R, out: ert.Outcome, want: Expected) Verdict {
    var mb: [5]u8 = undefined;
    const line = s.lineHex();
    return .{
        .played = std.mem.eql(u8, moveText(out.best, &mb), want.played),
        .nodes = out.nodes == want.nodes,
        .makes = out.makes == want.makes,
        .line = std.mem.eql(u8, &line, want.line),
    };
}

pub fn allEqual(v: Verdict) bool {
    return v.played and v.nodes and v.makes and v.line;
}

/// One search of a golden file from the oracle's DGROUP snapshot at main, with the far
/// segment (game record) from the oracle's subtree file of the search's first node when
/// one is recorded, else zeroed.
fn runFromSnapshot(gpa: std.mem.Allocator, s: *R, snap: []const u8, far_name: []const u8, rec: std.json.Value) !ert.Outcome {
    si.fromImage(s, snap[0..0x10000], null);
    for (s.tables) |*t| t.clear();
    if (!try farFromSubtree(gpa, far_name, s.test_far, s.tables)) std.debug.print("join-root: {s} not recorded: the game record starts zeroed\n", .{far_name});
    si.refreshRecord(s);
    s.ticks = 0;
    s.failure = null;
    s.trace = rec.object.get("trace") != null;
    return s.search(.own);
}

test "join-root: every search of the smoke scenarios from the oracle's snapshot at main (DEV-003 as movegen corrects it)" {
    const gpa = std.testing.allocator;
    const s = try R.init(gpa, golden_slots);
    defer s.deinit();
    const known = try readKnownFailures(gpa);
    defer gpa.free(known);
    const jl = try readGolden(gpa, "smoke.jsonl");
    defer gpa.free(jl);
    var lines = std.mem.splitScalar(u8, jl, '\n');
    var ran: u32 = 0;
    var matched: u32 = 0;
    var missing: u32 = 0;
    var unexpected: u32 = 0;
    while (lines.next()) |text| {
        if (text.len == 0) continue;
        const parsed = try std.json.parseFromSlice(std.json.Value, gpa, text, .{});
        defer parsed.deinit();
        const o = parsed.value.object;
        if (o.get("search") == null) continue; // a scenario header
        const scenario = o.get("scenario").?.string;
        const search = o.get("search").?.integer;
        var name_buf: [128]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "whole/{s}-s{d}-main.bin", .{ scenario, search });
        const snap = readGolden(gpa, name) catch {
            missing += 1;
            std.debug.print("join-root: {s} search {d}: no snapshot at main recorded, not run\n", .{ scenario, search });
            continue;
        };
        defer gpa.free(snap);
        const want = expectedOf(parsed.value);
        var far_buf: [128]u8 = undefined;
        const far_name = try std.fmt.bufPrint(&far_buf, "whole/{s}-s{d}-subtree-1.zst", .{ scenario, search });
        const t0 = std.Io.Clock.awake.now(std.testing.io).nanoseconds;
        const out = try runFromSnapshot(gpa, s, snap, far_name, parsed.value);
        const t1 = std.Io.Clock.awake.now(std.testing.io).nanoseconds;
        ran += 1;
        const v = verdictOf(s, out, want);
        var mb: [5]u8 = undefined;
        var id_buf: [128]u8 = undefined;
        const id = try std.fmt.bufPrint(&id_buf, "whole-snapshot:{s}:{d}", .{ scenario, search });
        const ok = allEqual(v) and s.failure == null;
        if (ok) matched += 1;
        const ms = @divTrunc(t1 - t0, std.time.ns_per_ms);
        std.debug.print("join-root: {s} search {d} from main: played {s} ({s}), nodes {d} ({d}), makes {d} ({d}), line {s}; {d} ms, {d} nodes/s{s}{s}\n", .{ scenario, search, moveText(out.best, &mb), want.played, out.nodes, want.nodes, out.makes, want.makes, if (v.line) "equal" else "differs", ms, if (ms > 0) @divTrunc(@as(i128, out.nodes) * 1000, ms) else 0, if (s.failure != null) "; " else "", s.failure orelse "" });
        if (!ok) {
            if (o.get("trace")) |tr| _ = compareTrace(s.events.items, tr.array.items);
            if (!knownFailure(known, id)) unexpected += 1;
        } else if (knownFailure(known, id)) {
            std.debug.print("join-root: {s} is listed in tests/known_failures.txt but now matches: remove it\n", .{id});
            unexpected += 1;
        }
    }
    std.debug.print("join-root: smoke searches from snapshots: {d} run, {d} equal on all four values, {d} without a snapshot, {d} unexpected results\n", .{ ran, matched, missing, unexpected });
    try std.testing.expectEqual(@as(u32, 0), unexpected);
}

/// The far data segment 5A7B (the game record) at the first node entry of a search, from
/// the oracle's subtree file of node 1 (tools/oracle/oracle.py SUBTREE_FORMAT): DGROUP
/// follows a 25-byte header, the far segment follows DGROUP.
fn farFromSubtree(gpa: std.mem.Allocator, name: []const u8, far: *ert.Far, tables: ?*[2]sn.HashTable) !bool {
    const compressed = readGolden(gpa, name) catch return false;
    defer gpa.free(compressed);
    var in: std.Io.Reader = .fixed(compressed);
    const window = try gpa.alloc(u8, std.compress.zstd.default_window_len + std.compress.zstd.block_size_max);
    defer gpa.free(window);
    var zd = std.compress.zstd.Decompress.init(&in, window, .{});
    const raw = try zd.reader.allocRemaining(gpa, .limited(64 << 20));
    defer gpa.free(raw);
    if (!std.mem.eql(u8, raw[0..8], "MCSUBT1\x00")) return error.BadSubtree;
    @memcpy(far, raw[25 + 0x10000 ..][0..0x10000]);
    if (tables) |t| {
        // The main hash tables' non-zero slots at the entry: the tables main kept from
        // the search before (docs/arch/33-root-preparation.md step 9) or cleared.
        for (t) |*x| x.clear();
        var i: usize = 25 + 0x20000;
        const n = std.mem.readInt(u32, raw[i..][0..4], .little);
        i += 4;
        for (0..n) |_| {
            const table = raw[i];
            const idx = std.mem.readInt(u32, raw[i + 1 ..][0..4], .little);
            t[table].put(idx, raw[i + 5 ..][0..10].*);
            i += 15;
        }
    }
    return true;
}

/// The six tablebase files of the shipped TB folder (reference/original/M80/TB, read at
/// test time, as src/tablebase_test.zig reads them).
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

/// Every search of a golden file through the game-move path: each scenario from its first
/// search's snapshot at main (`<dir>/<scenario>-s1-main.bin`, with the far segment and the
/// hash slots of `<dir>/<scenario>-s1-subtree-1.zst`), its later searches after the
/// program's move and the turn. Returns the number of unexpected results.
///
/// `max_nodes`: a search the golden file gives more node entries than this, and the rest
/// of its scenario, are not run (each is printed): Debug builds run about 1,500 nodes a
/// second, and corpus2 has 2.1 million; the other builds run every search.
fn runPath(gpa: std.mem.Allocator, s: *R, golden: []const u8, dir: []const u8, id_prefix: []const u8, label: []const u8, max_nodes: ?u64) !u32 {
    const known = try readKnownFailures(gpa);
    defer gpa.free(known);
    const jl = try readGolden(gpa, golden);
    defer gpa.free(jl);
    var lines = std.mem.splitScalar(u8, jl, '\n');
    var scenario_buf: [64]u8 = undefined;
    var current: []const u8 = "";
    var skip_scenario = false;
    var ran: u32 = 0;
    var matched: u32 = 0;
    var unexpected: u32 = 0;
    var not_run: u32 = 0;
    while (lines.next()) |text| {
        if (text.len == 0) continue;
        const parsed = try std.json.parseFromSlice(std.json.Value, gpa, text, .{});
        defer parsed.deinit();
        const o = parsed.value.object;
        if (o.get("search") == null) {
            // A scenario header: the file must be the original with the DEV-003 correction
            // movegen makes and the hash tail cleared.
            const d = o.get("dev003") orelse return error.GoldenNotDev003Move;
            try std.testing.expectEqualStrings("move", d.string);
            try std.testing.expectEqualStrings("zero", o.get("hash_tail").?.object.get("mode").?.string);
            continue;
        }
        const scenario = o.get("scenario").?.string;
        const search = o.get("search").?.integer;
        var name_buf: [160]u8 = undefined;
        if (!std.mem.eql(u8, scenario, current)) {
            // A new scenario: its first search from the snapshot.
            @memcpy(scenario_buf[0..scenario.len], scenario);
            current = scenario_buf[0..scenario.len];
            const snap = readGolden(gpa, try std.fmt.bufPrint(&name_buf, "{s}/{s}-s1-main.bin", .{ dir, scenario })) catch {
                std.debug.print("join-root: {s}: no snapshot at main of search 1 recorded: scenario not run\n", .{scenario});
                skip_scenario = true;
                not_run += 1;
                continue;
            };
            defer gpa.free(snap);
            skip_scenario = false;
            si.fromImage(s, snap[0..0x10000], null);
            for (s.tables) |*t| t.clear();
            const far_ok = try farFromSubtree(gpa, try std.fmt.bufPrint(&name_buf, "{s}/{s}-s1-subtree-1.zst", .{ dir, scenario }), s.test_far, s.tables);
            if (!far_ok) std.debug.print("join-root: {s}: no far segment recorded; the game record starts zeroed\n", .{scenario});
            si.refreshRecord(s);
        } else {
            if (skip_scenario) {
                not_run += 1;
                continue;
            }
            // The program's move and the turn, then compare with the snapshot at main.
            s.playMove();
            s.nextTurnAutoPlay();
            si.toImage(s); // the turn runs on the members (stage 4)
            if (readGolden(gpa, try std.fmt.bufPrint(&name_buf, "{s}/{s}-s{d}-main.bin", .{ dir, scenario, search }))) |snap| {
                defer gpa.free(snap);
                var label_buf: [96]u8 = undefined;
                _ = diffImages(try std.fmt.bufPrint(&label_buf, "{s} at main of search {d}", .{ scenario, search }), s.test_img, snap, 0);
            } else |_| {}
        }
        const want = expectedOf(parsed.value);
        if (max_nodes) |mx| if (want.nodes > mx) {
            std.debug.print("join-root: {s} search {d}: {d} nodes, above the {d} this build runs: the rest of the scenario not run\n", .{ scenario, search, want.nodes, mx });
            skip_scenario = true;
            not_run += 1;
            continue;
        };
        s.failure = null;
        s.trace = o.get("trace") != null;
        const out = s.search(.own);
        ran += 1;
        const v = verdictOf(s, out, want);
        var mb: [5]u8 = undefined;
        var id_buf: [128]u8 = undefined;
        const id = try std.fmt.bufPrint(&id_buf, "{s}:{s}:{d}", .{ id_prefix, scenario, search });
        const ok = allEqual(v) and s.failure == null;
        if (ok) matched += 1;
        std.debug.print("join-root: {s} search {d} through the game-move path: played {s} ({s}), nodes {d} ({d}), makes {d} ({d}), line {s}{s}{s}\n", .{ scenario, search, moveText(out.best, &mb), want.played, out.nodes, want.nodes, out.makes, want.makes, if (v.line) "equal" else "differs", if (s.failure != null) "; " else "", s.failure orelse "" });
        if (!ok) {
            if (o.get("trace")) |tr| _ = compareTrace(s.events.items, tr.array.items);
            if (!knownFailure(known, id)) unexpected += 1;
        } else if (knownFailure(known, id)) {
            std.debug.print("join-root: {s} is listed in tests/known_failures.txt but now matches: remove it\n", .{id});
            unexpected += 1;
        }
    }
    std.debug.print("join-root: {s} searches through the game-move path: {d} run, {d} equal on all four values, {d} not run, {d} unexpected results\n", .{ label, ran, matched, not_run, unexpected });
    std.debug.print("join-root: bindings never called in these searches: main before the loop:", .{});
    for (std.enums.values(rp.Callee)) |c| if (s.prep_calls[@backingInt(c)] == 0) std.debug.print(" {s}", .{@tagName(c)});
    std.debug.print("; the loop and root_search:", .{});
    for (std.enums.values(rs.Callee)) |c| if (s.loop_calls[@backingInt(c)] == 0) std.debug.print(" {s}", .{@tagName(c)});
    std.debug.print("\n", .{});
    return unexpected;
}

test "join-root: every search of tests/golden/smoke.jsonl through the game-move path, each scenario from its first search's snapshot at main" {
    const gpa = std.testing.allocator;
    const s = try R.init(gpa, golden_slots);
    defer s.deinit();
    try std.testing.expectEqual(@as(u32, 0), try runPath(gpa, s, "smoke.jsonl", "whole", "whole-path", "smoke", null));
}

test "join-root: every search of tests/golden/corpus2.jsonl through the game-move path (set-up positions and endings, the tablebases at the root)" {
    const gpa = std.testing.allocator;
    // The corpus is compared with tests/golden/corpus2.jsonl once that file is the corrected
    // recording (its header says so); until then with this task's own recording of it
    // (tests/golden/whole/corpus2/corpus2.jsonl, --dev003 move --hash-tail zero), if any.
    const jl = try readGolden(gpa, "corpus2.jsonl");
    const corrected = std.mem.indexOf(u8, jl[0 .. std.mem.indexOfScalar(u8, jl, '\n') orelse jl.len], "\"dev003\": \"move\"") != null;
    gpa.free(jl);
    var golden: []const u8 = "corpus2.jsonl";
    if (!corrected) {
        if (readGolden(gpa, "whole/corpus2/corpus2.jsonl")) |own| {
            gpa.free(own);
            golden = "whole/corpus2/corpus2.jsonl";
            std.debug.print("join-root: tests/golden/corpus2.jsonl is not yet the --dev003 move recording: compared with tests/golden/whole/corpus2/corpus2.jsonl\n", .{});
        } else |_| {
            std.debug.print("join-root: no corrected recording of corpus2: not compared (listed in tests/known_failures.txt)\n", .{});
            const known = try readKnownFailures(gpa);
            defer gpa.free(known);
            try std.testing.expect(knownFailure(known, "whole-path:corpus2"));
            return;
        }
    }
    const s = try R.init(gpa, golden_slots);
    defer s.deinit();
    var tbf = try TbFiles.load(gpa);
    defer tbf.deinit(gpa);
    s.tb_files = tbf.files();
    try std.testing.expectEqual(@as(u32, 0), try runPath(gpa, s, golden, "whole/corpus2", "whole-path", "corpus2", if (@import("builtin").mode == .debug) 25_000 else null));
}

test "join-root: start-d3 search 1 from the oracle's snapshot at main: trace, checkpoints and images (tests/golden/whole, --dev003 move)" {
    const gpa = std.testing.allocator;
    const s = try R.init(gpa, golden_slots);
    defer s.deinit();
    const snap = try readGolden(gpa, "whole/start-d3-s1-main.bin");
    defer gpa.free(snap);
    const prepared = try readGolden(gpa, "whole/start-d3-s1-prepared.bin");
    defer gpa.free(prepared);
    const ply2 = try readGolden(gpa, "whole/start-d3-s1-node-ply-2.bin");
    defer gpa.free(ply2);
    const jl = try readGolden(gpa, "whole/start-d3-diagnosis.jsonl");
    defer gpa.free(jl);
    var lines = std.mem.splitScalar(u8, jl, '\n');
    const header = try std.json.parseFromSlice(std.json.Value, gpa, lines.next().?, .{});
    defer header.deinit();
    try std.testing.expectEqualStrings("move", header.value.object.get("dev003").?.string);
    try std.testing.expectEqualStrings("zero", header.value.object.get("hash_tail").?.object.get("mode").?.string);
    const parsed = try std.json.parseFromSlice(std.json.Value, gpa, lines.next().?, .{});
    defer parsed.deinit();
    const want = expectedOf(parsed.value);

    si.fromImage(s, snap[0..0x10000], null);
    // The clock the oracle holds during the search: the start of thinking it recorded.
    s.ticks = std.mem.readInt(u32, prepared[0xA8E8..][0..4], .little);
    s.trace = true;
    var hook: SnapHook = .{ .s = s, .prepared = prepared, .node_ply2 = ply2 };
    s.hook = .{ .ctx = &hook, .before = SnapHook.before, .after = SnapHook.after };
    const out = s.search(.own);
    if (s.failure) |f| std.debug.print("start-d3 s1: {s}\n", .{f});
    var mb: [5]u8 = undefined;
    const played = moveText(out.best, &mb);
    const line = s.lineHex();
    std.debug.print("join-root: start-d3 search 1 from main: exit {s}, played {s} ({s}), nodes {d} ({d}), makes {d} ({d}), line {s} ({s}); bytes a unit holds that differ: {d} after prepare_eval, {d} at the first ply-2 node\n", .{ @tagName(out.exit), played, want.played, out.nodes, want.nodes, out.makes, want.makes, &line, want.line, hook.diffs_prepared, hook.diffs_ply2 });
    const trace = parsed.value.object.get("trace").?.array.items;
    try std.testing.expect(s.failure == null);
    try std.testing.expect(hook.checked_prepared and hook.seen_ply2);
    try std.testing.expectEqual(@as(?usize, null), compareTrace(s.events.items, trace));
    // The checkpoints: every 256th make, the running line hash and the counts.
    var h: std.crypto.hash.sha2.Sha256 = .init(.{});
    var makes: usize = 0;
    var nodes: usize = 0;
    var cps: usize = 0;
    const checkpoints = parsed.value.object.get("checkpoints").?.array.items;
    for (s.events.items) |e| switch (e) {
        .node => nodes += 1,
        .ply2 => {},
        .make => |m| {
            h.update(&.{ m.ply, m.from, m.to, m.flag });
            makes += 1;
            if (makes % 256 == 0 and cps < checkpoints.len) {
                const cp = checkpoints[cps].object;
                var hc = h;
                var d: [32]u8 = undefined;
                hc.final(&d);
                const hex = std.fmt.bytesToHex(d, .lower);
                try std.testing.expectEqualStrings(cp.get("line").?.string, &hex);
                try std.testing.expectEqual(cp.get("makes").?.integer, @as(i64, @intCast(makes)));
                try std.testing.expectEqual(cp.get("nodes").?.integer, @as(i64, @intCast(nodes)));
                cps += 1;
            }
        },
    };
    try std.testing.expectEqual(checkpoints.len, cps);
    const v = verdictOf(s, out, want);
    try std.testing.expect(allEqual(v));
}

test "join-root: the engine's start-up and Ctrl-A from the image of a game in progress (start-d3 before search 4), then search 1 (step 12)" {
    const gpa = std.testing.allocator;
    const s = try R.init(gpa, golden_slots);
    defer s.deinit();
    const snap4 = try readGolden(gpa, "whole/start-d3-s4-main.bin");
    defer gpa.free(snap4);
    const snap1 = try readGolden(gpa, "whole/start-d3-s1-main.bin");
    defer gpa.free(snap1);
    // A game in progress, its hash tables and game record: start-up leaves nothing of it.
    si.fromImage(s, snap4[0..0x10000], null);
    for (s.tables) |*t| t.clear();
    _ = try farFromSubtree(gpa, "whole/start-d3-s4-subtree-1.zst", s.test_far, s.tables);
    s.startUp(.{}, .{}, .{}, 3);
    try std.testing.expect(s.autoPlay());
    si.toImage(s); // start-up and Ctrl-A run on the members (stage 4)
    const ng = @import("newgame_test.zig");
    try std.testing.expectEqual(@as(usize, 0), ng.heldDiffs("start-up and Ctrl-A, against main of a new game's first search", s.test_img, snap1));
    for (s.tables) |*t| try std.testing.expect(std.mem.allEqual(u8, std.mem.sliceAsBytes(t.slots), 0));
    const jl = try readGolden(gpa, "smoke.jsonl");
    defer gpa.free(jl);
    var lines = std.mem.splitScalar(u8, jl, '\n');
    _ = lines.next();
    const parsed = try std.json.parseFromSlice(std.json.Value, gpa, lines.next().?, .{});
    defer parsed.deinit();
    const want = expectedOf(parsed.value);
    const out = s.search(.own);
    const v = verdictOf(s, out, want);
    var mb: [5]u8 = undefined;
    std.debug.print("join-root: start-d3 search 1 after the engine's start-up: played {s} ({s}), nodes {d} ({d}), makes {d} ({d}), line {s}{s}{s}\n", .{ moveText(out.best, &mb), want.played, out.nodes, want.nodes, out.makes, want.makes, if (v.line) "equal" else "differs", if (s.failure != null) "; " else "", s.failure orelse "" });
    try std.testing.expect(allEqual(v) and s.failure == null);
}
