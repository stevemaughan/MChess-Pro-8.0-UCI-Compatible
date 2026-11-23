//! Normal play: every search of tests/golden/normal1.jsonl (64 searches in six games, the
//! program White in three and Black in three, depths 3 to 5, pondering off through the
//! program's own key `!`) through the joined engine (src/engine_root.zig), compared on the
//! four values of the golden file (the move played, node entries, makes, the line hash),
//! and on two more the oracle records in normal play: the reply set_predicted_reply left
//! after the program's move (`predicted`, DG:8FDE..8FE0) and whether main kept the main
//! hash tables before the search (`hash_kept`: no call of clear_hash_tables).
//!
//! Each game starts from the oracle's DGROUP snapshot at main 0000:0526 of its first
//! search, with the far segment 5A7B and the main hash tables' non-zero slots from the
//! oracle's subtree file of that search's first node (tests/golden/whole/normal1/). Its
//! later searches follow the program's move with set_predicted_reply (`EngineRoot.playMove`)
//! and the opponent's move as the oracle typed it (the header's `typed`;
//! `EngineRoot.nextTurnNormal`: main's ponder test and the command loop, check_entered_move,
//! play_entered_move, the command loop's exit and main to 0526).
//!
//! The first difference in a game ends that game; it is named with its scenario and
//! search, and is an error unless tests/known_failures.txt lists
//! `whole-normal1:<scenario>:<search>`.
//!
//! A second test plays np-open-black-d4 from the engine's own start (`EngineRoot.startUp`,
//! the key `!`, then 1. e4 entered), without the snapshot, and checks the image at main
//! of searches 1 and 2 against the original's.

const std = @import("std");
const si = @import("state_image.zig");
const builtin = @import("builtin");
const ert = @import("engine_root.zig");
const ert_test = @import("engine_root_test.zig");
const ngt = @import("newgame_test.zig");
const sn = @import("searchnode.zig");
const rp = @import("rootprep.zig");
const pos = @import("position.zig");
const am = @import("adapt_movegen.zig");
const ap = @import("adapt_position.zig");
const gamemove = @import("gamemove.zig");
const dgroup = @import("dgroup.zig");

const R = ert_test.R;

/// The far data segment and the main hash tables' non-zero slots at the first node entry,
/// from the oracle's subtree file of node 1 (tools/oracle/oracle.py SUBTREE_FORMAT).
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

/// A move as the oracle writes it ("e2e4", "e7e8q") as the squares of the 10x12 board.
const Typed = struct { from: u8, to: u8, promo: u8 };

fn parseMove(t: []const u8) !Typed {
    if (t.len < 4) return error.BadMove;
    const sq = struct {
        fn f(file: u8, rank: u8) !u8 {
            if (file < 'a' or file > 'h' or rank < '1' or rank > '8') return error.BadMove;
            return 21 + (file - 'a') + 10 * (rank - '1');
        }
    }.f;
    return .{ .from = try sq(t[0], t[1]), .to = try sq(t[2], t[3]), .promo = if (t.len > 4) t[4] else 0 };
}

/// The reply set_predicted_reply left (DG:8FDE..8FE0) as the oracle writes it.
fn predictedText(s: *R, buf: *[5]u8) ?[]const u8 {
    if (s.test_img[0x8FDE] == 0) return null;
    return ert_test.moveText(s.test_img[0x8FDE..][0..4].*, buf);
}

const Totals = struct {
    ran: u32 = 0,
    matched: u32 = 0,
    not_run: u32 = 0,
    unexpected: u32 = 0,
    nodes: u64 = 0,
    /// Searches before which main kept the main hash tables; predictions that were not
    /// the search's own reply (set_predicted_reply replaced it and set DG:73FE).
    kept: u32 = 0,
    replaced: u32 = 0,
    /// Opponent's moves that gave check, whose evasion count was compared.
    checks: u32 = 0,
};

/// 38C0:4FCE-504E on a copy of the image with the Stage A routines, as `EngineRoot.countEvasions`
/// ran until Stage B step 8, stage 3 (it now runs on the domain): the program's legal
/// evasions, gen_evasions([8DDE], 1), each made at ply 2 and its king tested. The
/// reference for DG:A518 after an entered move that gives check.
fn evasionCountStageA(gpa: std.mem.Allocator, img: *const dgroup.Image) !u8 {
    const copy = try gpa.create(dgroup.Image);
    defer gpa.destroy(copy);
    copy.* = img.*;
    const buf = try gpa.create(am.GenStateBuf);
    defer gpa.destroy(buf);
    buf.* = .{};
    const side = copy[0x8DDE];
    const ps: pos.Side = if (side & 1 == 0) .white else .black;
    const n = am.genEvasions(buf, copy, ps, 1);
    var count: u8 = @truncate(n);
    for (0..n) |k| {
        const mv = std.mem.bytesToValue(pos.Move, copy[0x3BC4 + 4 * k ..][0..4]);
        var u: pos.Undo = .{};
        ap.makeMove(copy, mv, ps, 2, &u);
        var p: pos.Position = .{};
        ap.PositionMap.load(&p, copy);
        if (gamemove.kingAttacked(&p, side) != 0) count -%= 1;
        ap.unmakeMove(copy, mv, ps, &u);
    }
    return count;
}

fn hashClears(s: *R) u64 {
    return s.prep_calls[@backingInt(rp.Callee.hash_clear)];
}

/// Plays the games of normal1.jsonl. `max_nodes`: a search the golden file gives more node
/// entries than this, and the rest of its game, are not run (each is printed).
fn runNormal1(gpa: std.mem.Allocator, s: *R, max_nodes: ?u64) !Totals {
    const dir = "whole/normal1";
    const known = try ert_test.readKnownFailures(gpa);
    defer gpa.free(known);
    const jl = try ert_test.readGolden(gpa, "normal1.jsonl");
    defer gpa.free(jl);
    var lines = std.mem.splitScalar(u8, jl, '\n');
    var t: Totals = .{};
    var header: ?std.json.Parsed(std.json.Value) = null;
    defer if (header) |h| h.deinit();
    var skip = false;
    while (lines.next()) |text| {
        if (text.len == 0) continue;
        const parsed = try std.json.parseFromSlice(std.json.Value, gpa, text, .{});
        defer parsed.deinit();
        const o = parsed.value.object;
        if (o.get("search") == null) {
            // A game's header: the corrected original, normal play, pondering off.
            try std.testing.expectEqualStrings("move", o.get("dev003").?.string);
            try std.testing.expectEqualStrings("zero", o.get("hash_tail").?.object.get("mode").?.string);
            try std.testing.expectEqualStrings("normal", o.get("mode").?.string);
            try std.testing.expectEqualStrings("off", o.get("ponder").?.string);
            try std.testing.expectEqual(@as(i64, 0), o.get("ponder_flag_errors").?.integer);
            if (header) |h| h.deinit();
            header = try std.json.parseFromSlice(std.json.Value, gpa, text, .{});
            skip = false;
            continue;
        }
        const scenario = o.get("scenario").?.string;
        const search: usize = @intCast(o.get("search").?.integer);
        const typed = header.?.value.object.get("typed").?.array.items;
        var name_buf: [160]u8 = undefined;
        if (search == 1) {
            const snap = ert_test.readGolden(gpa, try std.fmt.bufPrint(&name_buf, "{s}/{s}-s1-main.bin", .{ dir, scenario })) catch {
                std.debug.print("normal1: {s}: no snapshot at main of search 1: game not run\n", .{scenario});
                skip = true;
                t.not_run += 1;
                t.unexpected += 1;
                continue;
            };
            defer gpa.free(snap);
            si.fromImage(s, snap[0..0x10000], null);
            if (!try farFromSubtree(gpa, try std.fmt.bufPrint(&name_buf, "{s}/{s}-s1-subtree-1.zst", .{ dir, scenario }), s.test_far, s.tables)) {
                std.debug.print("normal1: {s}: no subtree of node 1: game not run\n", .{scenario});
                skip = true;
                t.not_run += 1;
                t.unexpected += 1;
                continue;
            }
            si.refreshRecord(s);
            s.failure = null;
        } else {
            if (skip) {
                t.not_run += 1;
                continue;
            }
            if (search > typed.len) return error.GoldenTypedTooShort;
            const mv = try parseMove(typed[search - 1].string);
            if (!s.nextTurnNormal(mv.from, mv.to, mv.promo)) {
                std.debug.print("normal1: {s} search {d}: the opponent's move {s} was not taken: {s}\n", .{ scenario, search, typed[search - 1].string, s.failure orelse "refused by check_entered_move" });
                t.unexpected += 1;
                skip = true;
                continue;
            }
            // The turn and the opponent's move run on the members (Stage B step 8, stage 4):
            // the image made current for the reads and the comparison below.
            si.toImage(s);
            // The entered move gave check (DG:8C07): the evasion count the engine made on
            // the domain against the Stage A one on the image (no golden file records it).
            if (s.test_img[0x8C07] != 0) {
                t.checks += 1;
                const want_count = try evasionCountStageA(gpa, s.test_img);
                if (s.test_img[0xA518] != want_count or (want_count == 0) != (s.test_img[0x7328] == 9)) {
                    std.debug.print("normal1: {s} search {d}: after {s}, evasion count {d} (Stage A {d}), status {d}\n", .{ scenario, search, typed[search - 1].string, s.test_img[0xA518], want_count, s.test_img[0x7328] });
                    t.unexpected += 1;
                }
            }
            if (search == 2 and std.mem.eql(u8, scenario, "np-open-black-d4")) {
                const snap2 = try ert_test.readGolden(gpa, dir ++ "/np-open-black-d4-s2-main.bin");
                defer gpa.free(snap2);
                if (heldDiffs("np-open-black-d4 at main of search 2", s.test_img, snap2) != 0) t.unexpected += 1;
            }
        }
        const want = ert_test.expectedOf(parsed.value);
        if (max_nodes) |mx| if (want.nodes > mx) {
            std.debug.print("normal1: {s} search {d}: {d} nodes, above the {d} this build runs (MCHESS_LONG_TESTS=1 runs all): it and the rest of the game not run\n", .{ scenario, search, want.nodes, mx });
            skip = true;
            t.not_run += 1;
            continue;
        };
        s.trace = false;
        const clears = hashClears(s);
        const out = s.search(.own);
        const kept = hashClears(s) == clears;
        // The program's move, and set_predicted_reply (not called after a mate score of
        // 19998 or more: the oracle then records no prediction).
        const calls = s.predict_calls;
        s.playMove();
        // set_predicted_reply runs on the domain (Stage B step 8, stage 3): the image is
        // made current for the reads below.
        si.toImage(s);
        t.ran += 1;
        t.nodes += out.nodes;
        const v = ert_test.verdictOf(s, out, want);
        var pb: [5]u8 = undefined;
        const pred = if (s.predict_calls != calls) predictedText(s, &pb) else null;
        if (kept) t.kept += 1;
        if (pred != null and std.mem.readInt(u16, s.test_img[0x8FDE..][0..2], .little) != std.mem.readInt(u16, s.test_img[0xA416..][0..2], .little)) t.replaced += 1;
        const want_pred: ?[]const u8 = switch (o.get("predicted").?) {
            .string => |x| x,
            else => null,
        };
        const pred_ok = if (pred) |x| (want_pred != null and std.mem.eql(u8, x, want_pred.?)) else want_pred == null;
        const kept_ok = kept == o.get("hash_kept").?.bool;
        var id_buf: [128]u8 = undefined;
        const id = try std.fmt.bufPrint(&id_buf, "whole-normal1:{s}:{d}", .{ scenario, search });
        if (ert_test.allEqual(v) and pred_ok and kept_ok and s.failure == null) {
            t.matched += 1;
            if (ert_test.knownFailure(known, id)) {
                std.debug.print("normal1: {s} is listed in tests/known_failures.txt but now matches: remove it\n", .{id});
                t.unexpected += 1;
            }
            continue;
        }
        var mb: [5]u8 = undefined;
        std.debug.print("normal1: FIRST DIFFERENCE in {s}, search {d}: played {s} ({s}), nodes {d} ({d}), makes {d} ({d}), line {s}, predicted {s} ({s}), hash kept {} ({}){s}{s}; the rest of the game not run\n", .{ scenario, search, ert_test.moveText(out.best, &mb), want.played, out.nodes, want.nodes, out.makes, want.makes, if (v.line) "equal" else "differs", pred orelse "none", want_pred orelse "none", kept, o.get("hash_kept").?.bool, if (s.failure != null) "; " else "", s.failure orelse "" });
        if (!ert_test.knownFailure(known, id)) t.unexpected += 1;
        skip = true;
    }
    return t;
}

/// The largest search run, by the golden file's node count. The six games are 2,286,074
/// nodes (the largest search 192,592); ReleaseFast and ReleaseSafe run them all. Debug, at
/// about 1,500 nodes a second, runs the searches up to 16,000 nodes and leaves out the
/// rest of each game from its first larger search (printed: 11 searches run, 106,343 nodes,
/// about a minute: np-open-black-d4 1 and 2, np-open-white-d3 1 to 5, np-middle-white-d4 1
/// to 3, np-checks-white-d3 1; the first searches of np-middle-black-d5 and
/// np-ending-black-d5 are larger). With MCHESS_LONG_TESTS set and not empty, every search is run in every build.
fn maxNodes(gpa: std.mem.Allocator) !?u64 {
    if (try std.testing.environ.containsUnempty(gpa, "MCHESS_LONG_TESTS")) return null;
    return if (builtin.mode == .debug) 16_000 else null;
}

test "join-root normal play: every search of tests/golden/normal1.jsonl (six games, 64 searches) through set_predicted_reply and the opponent's moves" {
    const gpa = std.testing.allocator;
    const s = try R.init(gpa, ert_test.golden_slots);
    defer s.deinit();
    const t = try runNormal1(gpa, s, try maxNodes(gpa));
    std.debug.print("normal1: {d} searches run ({d} nodes), {d} equal on move, nodes, makes, line, predicted reply and hash kept; {d} not run, {d} unexpected results; hash tables kept before {d}; {d} predictions not the search's own reply; {d} checks by the opponent, each evasion count compared with Stage A's\n", .{ t.ran, t.nodes, t.matched, t.not_run, t.unexpected, t.kept, t.replaced, t.checks });
    try std.testing.expectEqual(@as(u32, 0), t.unexpected);
    try std.testing.expect(t.ran > 0);
    if (builtin.mode != .debug) try std.testing.expect(t.checks > 0);
}

/// The bytes a unit holds that differ between the engine's image and the original's,
/// outside the stack and the exceptions of src/newgame_test.zig (addresses, menu cursors,
/// displays, the XMS driver; with `later`, also the clock charge and the displays the
/// engine leaves unwritten after a search). Each is printed; returns how many.
fn heldDiffsWith(label: []const u8, got: []const u8, want: []const u8, later: bool) usize {
    var bad: usize = 0;
    var excused: usize = 0;
    outer: for (got, want, 0..) |g, w, a| {
        if (g == w or ert_test.isStack(a) or !ert.mappedByAUnit(a)) continue;
        for (ngt.exceptions) |e| if (a >= e.lo and a <= e.hi) {
            excused += 1;
            continue :outer;
        };
        if (later) for (ngt.later_exceptions) |e| if (a >= e.lo and a <= e.hi) {
            excused += 1;
            continue :outer;
        };
        if (bad < 60) std.debug.print("  {s}: DG:{X:0>4} engine {X:0>2}, original {X:0>2}\n", .{ label, a, g, w });
        bad += 1;
    }
    std.debug.print("normal1: {s}: {d} bytes a unit holds differ outside the exceptions, {d} inside them\n", .{ label, bad, excused });
    return bad;
}

fn heldDiffs(label: []const u8, got: []const u8, want: []const u8) usize {
    return heldDiffsWith(label, got, want, true);
}

// np-open-black-d4's searches, ReleaseFast: about 196,000 nodes, 4 seconds; Debug runs
// the first only.
test "join-root normal play: np-open-black-d4 from the engine's own start (start-up, the key !, 1. e4 entered), every search" {
    const gpa = std.testing.allocator;
    const s = try R.init(gpa, ert_test.golden_slots);
    defer s.deinit();
    s.startUp(.{}, .{}, .{}, 4);
    s.togglePondering();
    const e4 = try parseMove("e2e4");
    try std.testing.expect(s.enterMove(e4.from, e4.to, e4.promo));
    try std.testing.expect(s.failure == null);
    si.toImage(s);
    const snap1 = try ert_test.readGolden(gpa, "whole/normal1/np-open-black-d4-s1-main.bin");
    defer gpa.free(snap1);
    try std.testing.expectEqual(@as(usize, 0), heldDiffsWith("own start, at main of search 1", s.test_img, snap1, false));

    const jl = try ert_test.readGolden(gpa, "normal1.jsonl");
    defer gpa.free(jl);
    var lines = std.mem.splitScalar(u8, jl, '\n');
    var typed: ?std.json.Parsed(std.json.Value) = null;
    defer if (typed) |x| x.deinit();
    var n: u32 = 0;
    var bad: u32 = 0;
    const limit: usize = if (builtin.mode == .debug and !try std.testing.environ.containsUnempty(gpa, "MCHESS_LONG_TESTS")) 1 else 10;
    while (lines.next()) |text| {
        if (text.len == 0) continue;
        const parsed = try std.json.parseFromSlice(std.json.Value, gpa, text, .{});
        defer parsed.deinit();
        const o = parsed.value.object;
        if (!std.mem.eql(u8, o.get("scenario").?.string, "np-open-black-d4")) continue;
        if (o.get("search") == null) {
            typed = try std.json.parseFromSlice(std.json.Value, gpa, text, .{});
            continue;
        }
        const k: usize = @intCast(o.get("search").?.integer);
        if (k > limit) {
            std.debug.print("normal1: own start: search {d} and later not run in Debug (MCHESS_LONG_TESTS=1 runs them)\n", .{k});
            break;
        }
        if (k > 1) {
            const mv = try parseMove(typed.?.value.object.get("typed").?.array.items[k - 1].string);
            try std.testing.expect(s.nextTurnNormal(mv.from, mv.to, mv.promo));
            si.toImage(s);
            if (k == 2) {
                const snap2 = try ert_test.readGolden(gpa, "whole/normal1/np-open-black-d4-s2-main.bin");
                defer gpa.free(snap2);
                if (heldDiffs("own start, at main of search 2", s.test_img, snap2) != 0) bad += 1;
            }
        }
        const want = ert_test.expectedOf(parsed.value);
        s.trace = false;
        const out = s.search(.own);
        s.playMove();
        const v = ert_test.verdictOf(s, out, want);
        var mb: [5]u8 = undefined;
        std.debug.print("normal1: own start: np-open-black-d4 search {d}: played {s} ({s}), nodes {d} ({d}), makes {d} ({d}), line {s}{s}{s}\n", .{ k, ert_test.moveText(out.best, &mb), want.played, out.nodes, want.nodes, out.makes, want.makes, if (v.line) "equal" else "differs", if (s.failure != null) "; " else "", s.failure orelse "" });
        if (!ert_test.allEqual(v) or s.failure != null) bad += 1;
        n += 1;
    }
    try std.testing.expect(n >= 1);
    try std.testing.expectEqual(@as(u32, 0), bad);
}
