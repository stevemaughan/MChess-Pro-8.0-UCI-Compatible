//! Start-up and the first turn computed by the engine (src/newgame.zig, engine_root
//! `EngineRoot.startUp`, `EngineRoot.autoPlay`) against the oracle (docs/arch/34-game-move-path.md,
//! "Start-up"): the image at main 0000:0526 of start-d3 search 1 on every byte a unit
//! holds but the listed exceptions, the game record, and the four searches of start-d3
//! run from the computed start.

const std = @import("std");
const si = @import("state_image.zig");
const ert = @import("engine_root.zig");
const ert_test = @import("engine_root_test.zig");
const newgame = @import("newgame.zig");
const gamemove = @import("gamemove.zig");

const R = ert_test.R;

/// The bytes a unit holds that the computed start leaves different from the original's
/// image at main 0526 of a new game's first search, each with its reason (the writers
/// are in docs/arch/34-game-move-path.md, "Start-up", table "Not computed").
pub const Exception = struct { lo: u16, hi: u16, why: []const u8 };
pub const exceptions = [_]Exception{
    .{ .lo = 0x005E, .hi = 0x0061, .why = "far pointer of the conventional buffer (hash_setup 7312-7315): an address" },
    .{ .lo = 0x22B4, .hi = 0x22B4, .why = "menu cursor (2B9F:9B19)" },
    .{ .lo = 0x3684, .hi = 0x3697, .why = "display strings and pointers (0000:8552, 4793:969E, 38C0:8979)" },
    .{ .lo = 0x73F4, .hi = 0x73F7, .why = "far pointer to allocated memory (38C0:C282-C285)" },
    .{ .lo = 0x7406, .hi = 0x7409, .why = "far pointer to allocated memory (hash_setup 7540-7543)" },
    .{ .lo = 0x8B98, .hi = 0x8BA7, .why = "display strings (4793:969E)" },
    .{ .lo = 0x8BAE, .hi = 0x8BAE, .why = "menu cursor (2B9F:6E03)" },
    .{ .lo = 0x8BB4, .hi = 0x8BB7, .why = "far pointer to allocated memory (38C0:C334-C337)" },
    .{ .lo = 0x8C2A, .hi = 0x8C2D, .why = "far pointer to allocated memory (38C0:C29D-C2A0)" },
    .{ .lo = 0x8C32, .hi = 0x8C3C, .why = "XMS move structure (hash_setup 7444-7468)" },
    .{ .lo = 0x9314, .hi = 0x9314, .why = "0000:8552 at start-up (8689): not read by the search" },
    .{ .lo = 0x9321, .hi = 0x9321, .why = "hash_setup 73E5: XMS driver state" },
    .{ .lo = 0x9326, .hi = 0x932F, .why = "XMS handles and clear_hash_tables' counters (hash_setup 7407-740A, 0000:8943-89BA)" },
    .{ .lo = 0x9E98, .hi = 0x9EA2, .why = "XMS move structure (hash_setup 7416-743D)" },
    .{ .lo = 0x9EB6, .hi = 0x9EB7, .why = "the move list display's word (38C0:895B)" },
    .{ .lo = 0x9FC2, .hi = 0x9FC5, .why = "far pointer to allocated memory (38C0:C264-C267)" },
    .{ .lo = 0x9FD4, .hi = 0x9FEB, .why = "far pointers to allocated memory (38C0:C309-C30B, 38C0:AA41-AA44)" },
    .{ .lo = 0xA230, .hi = 0xA232, .why = "display (38C0:84DE-84E2, 8589-858C)" },
    .{ .lo = 0xA24C, .hi = 0xA24F, .why = "far pointer to allocated memory (38C0:C2D3-C2D6)" },
    .{ .lo = 0xA3FC, .hi = 0xA3FC, .why = "menu cursor (2B9F:6DFD)" },
    .{ .lo = 0xAB1C, .hi = 0xAB1D, .why = "clock display (4793:359D)" },
};

/// At the later searches, also the bytes the joined engine leaves unwritten after a
/// search (docs/arch/60-engine-assembly.md section 5, "Bytes the engine leaves
/// unwritten"): the clock charge 0000:16EF-1756 and the displays.
pub const later_exceptions = [_]Exception{
    .{ .lo = 0x0058, .hi = 0x0059, .why = "clock charge: ticks to the next second" },
    .{ .lo = 0x77EC, .hi = 0x77F3, .why = "clock charge: time left" },
    .{ .lo = 0xA8E8, .hi = 0xA8EB, .why = "clock charge: start of thinking" },
    .{ .lo = 0x8C3E, .hi = 0x8C41, .why = "display" },
    .{ .lo = 0x9E96, .hi = 0x9EA7, .why = "display (1E9D:A47E)" },
    .{ .lo = 0x9EB6, .hi = 0x9EB9, .why = "display" },
    .{ .lo = 0xA4C2, .hi = 0xA4C3, .why = "comment state (1E9D:A47E)" },
};

pub fn isException(a: usize) ?[]const u8 {
    for (exceptions) |e| if (a >= e.lo and a <= e.hi) return e.why;
    if (later) for (later_exceptions) |e| if (a >= e.lo and a <= e.hi) return e.why;
    return null;
}
var later = false;

/// Compares the engine's image with the original's on every byte a unit holds outside
/// the stack; returns the number that differ outside the exceptions (printed).
pub fn heldDiffs(label: []const u8, got: []const u8, want: []const u8) usize {
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
    std.debug.print("newgame: {s}: {d} bytes a unit holds differ outside the exceptions, {d} inside them\n", .{ label, bad, excused });
    return bad;
}

fn readZstd(gpa: std.mem.Allocator, name: []const u8) ![]u8 {
    const compressed = try ert_test.readGolden(gpa, name);
    defer gpa.free(compressed);
    var in: std.Io.Reader = .fixed(compressed);
    const window = try gpa.alloc(u8, std.compress.zstd.default_window_len + std.compress.zstd.block_size_max);
    defer gpa.free(window);
    var zd = std.compress.zstd.Decompress.init(&in, window, .{});
    return zd.reader.allocRemaining(gpa, .limited(64 << 20));
}

/// The far segment 5A7B at the first node entry of start-d3 search 1 (the oracle's
/// subtree file; the search writes only its root key into the game record before it).
fn recordedFar(gpa: std.mem.Allocator) ![]u8 {
    const raw = try readZstd(gpa, "whole/start-d3-s1-subtree-1.zst");
    defer gpa.free(raw);
    return gpa.dupe(u8, raw[25 + 0x10000 ..][0..0x10000]);
}

test "newgame: the shipped settings files are the defaults of newgame.Settings and UserBooks" {
    const gpa = std.testing.allocator;
    var buf: [256]u8 = undefined;
    const dir = @import("build_options").golden_dir;
    const p = try std.fmt.bufPrint(&buf, "{s}/../../reference/original/M80/SETTINGS.M80", .{dir});
    const text = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, p, gpa, .limited(4096));
    defer gpa.free(text);
    const s = newgame.Settings.parse(text) orelse return error.SettingsUnreadable;
    try std.testing.expectEqualDeep(newgame.Settings{}, s);
    const p2 = try std.fmt.bufPrint(&buf, "{s}/../../reference/original/M80/UBOOKS.M80", .{dir});
    const t2 = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, p2, gpa, .limited(4096));
    defer gpa.free(t2);
    var it = std.mem.tokenizeAny(u8, t2, " \r\n");
    const a = try std.fmt.parseInt(u16, it.next().?, 10);
    const b = try std.fmt.parseInt(u16, it.next().?, 10);
    try std.testing.expectEqual(newgame.UserBooks{}, newgame.UserBooks{ .mchess_book_off = a, .user_books_off = b });
}

test "newgame: start-up and Ctrl-A give the original's image at main of start-d3 search 1; the four searches of start-d3 from it" {
    const gpa = std.testing.allocator;
    const s = try R.init(gpa, ert_test.golden_slots);
    defer s.deinit();
    s.startUp(.{}, .{}, .{}, 3);
    try std.testing.expect(s.autoPlay());
    try std.testing.expect(s.failure == null);
    // Stage B step 8, stage 4: start-up and Ctrl-A run on the members; the image is made
    // current (the members stored to it) for the comparison.
    si.toImage(s);
    const snap1 = try ert_test.readGolden(gpa, "whole/start-d3-s1-main.bin");
    defer gpa.free(snap1);
    try std.testing.expectEqual(@as(usize, 0), heldDiffs("start-up and Ctrl-A, against main of start-d3 search 1", s.test_img, snap1));
    // The game record: every byte gamemove.GameRecord holds (only ply 0's key and the
    // first position's entries are written; the search adds nothing before node 1 but
    // its root key, which is the same key).
    const far = try recordedFar(gpa);
    defer gpa.free(far);
    var far_bad: usize = 0;
    for (s.test_far, far, 0..) |g, w, a| {
        // 5A7B:43B8-68E5 lies inside GameRecord.keys as declared but past the keys of the
        // 406 game plies the record holds: at start-up it holds the book's display list
        // of the start position's book moves (4793:5F4E, 6110), with the book on.
        if (a >= 0x43B8 and a < 0x68E6) continue;
        if (g != w and ert.GameRecordMap.covers(a)) {
            if (far_bad < 20) std.debug.print("  game record 5A7B:{X:0>4} engine {X:0>2}, original {X:0>2}\n", .{ a, g, w });
            far_bad += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 0), far_bad);

    // The four searches, the later ones through the game-move path.
    const jl = try ert_test.readGolden(gpa, "smoke.jsonl");
    defer gpa.free(jl);
    var lines = std.mem.splitScalar(u8, jl, '\n');
    var n: u32 = 0;
    var bad: u32 = 0;
    while (lines.next()) |text| {
        if (text.len == 0) continue;
        const parsed = try std.json.parseFromSlice(std.json.Value, gpa, text, .{});
        defer parsed.deinit();
        const o = parsed.value.object;
        if (o.get("search") == null) continue;
        if (!std.mem.eql(u8, o.get("scenario").?.string, "start-d3")) continue;
        const k = o.get("search").?.integer;
        if (k > 1) {
            later = true;
            s.playMove();
            s.nextTurnAutoPlay();
            si.toImage(s);
            var nb: [64]u8 = undefined;
            const snap = try ert_test.readGolden(gpa, try std.fmt.bufPrint(&nb, "whole/start-d3-s{d}-main.bin", .{k}));
            defer gpa.free(snap);
            var lb: [64]u8 = undefined;
            if (heldDiffs(try std.fmt.bufPrint(&lb, "start-d3 at main of search {d}", .{k}), s.test_img, snap) != 0) bad += 1;
        }
        const want = ert_test.expectedOf(parsed.value);
        s.trace = false;
        const out = s.search(.own);
        const v = ert_test.verdictOf(s, out, want);
        var mb: [5]u8 = undefined;
        std.debug.print("newgame: start-d3 search {d} from the computed start: played {s} ({s}), nodes {d} ({d}), makes {d} ({d}), line {s}{s}{s}\n", .{ k, ert_test.moveText(out.best, &mb), want.played, out.nodes, want.nodes, out.makes, want.makes, if (v.line) "equal" else "differs", if (s.failure != null) "; " else "", s.failure orelse "" });
        if (!ert_test.allEqual(v) or s.failure != null) bad += 1;
        n += 1;
    }
    try std.testing.expectEqual(@as(u32, 4), n);
    try std.testing.expectEqual(@as(u32, 0), bad);
}

fn readNg(gpa: std.mem.Allocator, name: []const u8) ![]u8 {
    var b: [128]u8 = undefined;
    return ert_test.readGolden(gpa, try std.fmt.bufPrint(&b, "newgame/{s}", .{name}));
}

test "newgame: the New game command after a game of normal play gives the original's image at main 0526 (tests/golden/newgame)" {
    // tools/research/newgame/trace.py: the repeatable state at depth 3, 1. e4 typed, the
    // program's reply, 2. d4 typed, its reply (pondering off), then Ctrl-N, Enter. The
    // images are DGROUP and the far segment when Ctrl-N is taken, and at main 0526 after
    // the command (where main, with [153C] set, goes back to 013B).
    const gpa = std.testing.allocator;
    const s = try R.init(gpa, 16);
    defer s.deinit();
    const before = try readNg(gpa, "played-before-ctrl-n-dg.bin");
    defer gpa.free(before);
    const before_far = try readNg(gpa, "played-before-ctrl-n-far.bin");
    defer gpa.free(before_far);
    const after = try readNg(gpa, "after-new-game-main-dg.bin");
    defer gpa.free(after);
    const after_far = try readNg(gpa, "after-new-game-main-far.bin");
    defer gpa.free(after_far);
    si.fromImage(s, before[0..0x10000], before_far[0..0x10000]);
    s.newGameCommand(.{});
    si.toImage(s);
    later = true;
    try std.testing.expectEqual(@as(usize, 0), heldDiffs("the New game command, against main 0526 after it", s.test_img, after));
    var far_bad: usize = 0;
    for (s.test_far, after_far, 0..) |g, w, a| {
        if (a >= 0x43B8 and a < 0x68E6) continue;
        if (g != w and ert.GameRecordMap.covers(a)) {
            if (far_bad < 20) std.debug.print("  game record 5A7B:{X:0>4} engine {X:0>2}, original {X:0>2}\n", .{ a, g, w });
            far_bad += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 0), far_bad);
}
