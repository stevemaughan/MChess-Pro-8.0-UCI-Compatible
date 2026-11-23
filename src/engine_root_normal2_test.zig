//! Normal play in which the opponent gives check: every search of
//! tests/golden/normal2.jsonl (tests/scenarios/normal2.json: eight games from Setup mode,
//! the program White in four and Black in four, Fixed depth 3, pondering off through the
//! program's own key `!`) through the joined engine (src/engine_root.zig), from the engine's
//! own start: start-up, Setup mode with the game's FEN, the key `!`, then the opponent's
//! moves as the oracle typed them (the header's `typed`): the first with `EngineRoot.enterMove`,
//! the rest with `EngineRoot.nextTurnNormal` after the program's move (`EngineRoot.playMove`).
//!
//! Compared with the original, as for normal1.jsonl (src/engine_root_normal_test.zig): the
//! move played, node entries, makes, the line hash, the reply set_predicted_reply left and
//! whether main kept the main hash tables. And, after every entered move that gave check
//! (the record's `evasions`, read by the oracle at main 0000:0526, `"evasions": true`), the
//! two bytes the entered-move path writes there (38C0:4FCE-504E, `countEvasions` in
//! `EngineRoot.enterMoveDomain`): DG:A518, the program's legal replies, and the status DG:7328
//! (9 when there is none). Main overwrites both before it reads them (0660, 0851), so no
//! search shows them; the record is the only comparison. An entered move without a record
//! must not have given check (DG:8C07 = 0). Each count is also compared with the Stage A
//! count made on a copy of the image (as the normal1 test does).
//!
//! A game whose last entered move mates the program ends with a record with no move: main
//! generates the evasions, finds none legal and ends the game (0000:1187). The engine must
//! leave main by the same exit (`main_loop`) with the same node entries, makes and line.
//!
//! The helpers `parseMove`, `predictedText`, `evasionCountStageA` and `hashClears` are
//! copies of the private ones of src/engine_root_normal_test.zig.
//!
//! The first difference in a game ends that game; it is named with its scenario and
//! search, and is an error unless tests/known_failures.txt lists
//! `whole-normal2:<scenario>:<search>`.

const std = @import("std");
const si = @import("state_image.zig");
const builtin = @import("builtin");
const ert_test = @import("engine_root_test.zig");
const ast = @import("adapt_setup_test.zig");
const as = @import("adapt_setup.zig");
const setup = @import("setup.zig");
const rp = @import("rootprep.zig");
const pos = @import("position.zig");
const am = @import("adapt_movegen.zig");
const ap = @import("adapt_position.zig");
const gamemove = @import("gamemove.zig");
const dgroup = @import("dgroup.zig");

const R = ert_test.R;

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

/// 38C0:4FCE-504E on a copy of the image with the Stage A routines: the program's legal
/// evasions, gen_evasions([8DDE], 1), each made at ply 2 and its king tested.
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

const Totals = struct {
    games: u32 = 0,
    ran: u32 = 0,
    matched: u32 = 0,
    not_run: u32 = 0,
    unexpected: u32 = 0,
    nodes: u64 = 0,
    /// Entered moves that gave check, whose count and status were compared; of them, those
    /// with exactly one legal reply and those that mated the program (status 9).
    checks: u32 = 0,
    one_reply: u32 = 0,
    mates: u32 = 0,
    /// Searches before which main kept the main hash tables.
    kept: u32 = 0,
};

/// Plays the games of normal2.jsonl. `max_nodes`: a search the golden file gives more node
/// entries than this, and the rest of its game, are not run (each is printed).
fn runNormal2(gpa: std.mem.Allocator, s: *R, max_nodes: ?u64) !Totals {
    const known = try ert_test.readKnownFailures(gpa);
    defer gpa.free(known);
    const jl = try ert_test.readGolden(gpa, "normal2.jsonl");
    defer gpa.free(jl);
    var lines = std.mem.splitScalar(u8, jl, '\n');
    var t: Totals = .{};
    var header: ?std.json.Parsed(std.json.Value) = null;
    defer if (header) |h| h.deinit();
    var skip = false;
    var over = false;
    while (lines.next()) |text| {
        if (text.len == 0) continue;
        const parsed = try std.json.parseFromSlice(std.json.Value, gpa, text, .{});
        defer parsed.deinit();
        const o = parsed.value.object;
        if (o.get("search") == null) {
            // A game's header: the corrected original, normal play from Setup mode,
            // pondering off, the evasion count recorded.
            try std.testing.expectEqualStrings("move", o.get("dev003").?.string);
            try std.testing.expectEqualStrings("zero", o.get("hash_tail").?.object.get("mode").?.string);
            try std.testing.expectEqualStrings("normal", o.get("mode").?.string);
            try std.testing.expectEqualStrings("off", o.get("ponder").?.string);
            try std.testing.expectEqual(@as(i64, 0), o.get("ponder_flag_errors").?.integer);
            try std.testing.expect(o.get("evasions").?.bool);
            if (header) |h| h.deinit();
            header = try std.json.parseFromSlice(std.json.Value, gpa, text, .{});
            const d = try ast.descriptionOf(o.get("fen").?.string);
            s.startUp(.{}, .{}, .{}, @intCast(o.get("depth").?.integer));
            try std.testing.expectEqual(setup.Legality.legal, as.enter(s, &d));
            s.togglePondering();
            s.failure = null;
            skip = false;
            over = false;
            t.games += 1;
            continue;
        }
        const scenario = o.get("scenario").?.string;
        const search: usize = @intCast(o.get("search").?.integer);
        const typed = header.?.value.object.get("typed").?.array.items;
        if (skip) {
            t.not_run += 1;
            continue;
        }
        if (over) return error.RecordAfterGameOver;
        if (search > typed.len) return error.GoldenTypedTooShort;
        const mv = try parseMove(typed[search - 1].string);
        const taken = if (search == 1) s.enterMove(mv.from, mv.to, mv.promo) else s.nextTurnNormal(mv.from, mv.to, mv.promo);
        if (!taken or s.failure != null) {
            std.debug.print("normal2: {s} search {d}: the opponent's move {s} was not taken: {s}\n", .{ scenario, search, typed[search - 1].string, s.failure orelse "refused by check_entered_move" });
            t.unexpected += 1;
            skip = true;
            continue;
        }
        var id_buf: [128]u8 = undefined;
        const id = try std.fmt.bufPrint(&id_buf, "whole-normal2:{s}:{d}", .{ scenario, search });
        // The turn and the opponent's move run on the members (Stage B step 8, stage 4): the
        // image is made current for the reads below.
        si.toImage(s);
        // The evasion count and the status after the entered move, as main finds them at
        // 0526 (the record), and the Stage A count on the image.
        var evasions_ok = true;
        const gave_check = s.test_img[0x8C07] != 0;
        if (o.get("evasions")) |e| {
            const want_count: u8 = @intCast(e.object.get("count").?.integer);
            const want_status: u8 = @intCast(e.object.get("status").?.integer);
            const stage_a = try evasionCountStageA(gpa, s.test_img);
            t.checks += 1;
            if (want_count == 1) t.one_reply += 1;
            if (want_status == 9) t.mates += 1;
            if (!gave_check or s.test_img[0xA518] != want_count or s.test_img[0x7328] != want_status or stage_a != want_count) {
                std.debug.print("normal2: {s} search {d}: after {s}: in check {}, evasion count {d} (original {d}, Stage A {d}), status {d} (original {d})\n", .{ scenario, search, typed[search - 1].string, gave_check, s.test_img[0xA518], want_count, stage_a, s.test_img[0x7328], want_status });
                evasions_ok = false;
            }
        } else if (gave_check) {
            std.debug.print("normal2: {s} search {d}: after {s} the engine has the program in check (DG:8C07), the original's record has no evasion count\n", .{ scenario, search, typed[search - 1].string });
            evasions_ok = false;
        }
        const want_nodes: u64 = @intCast(o.get("nodes").?.integer);
        if (max_nodes) |mx| if (want_nodes > mx) {
            std.debug.print("normal2: {s} search {d}: {d} nodes, above the {d} this build runs (MCHESS_LONG_TESTS=1 runs all): it and the rest of the game not run\n", .{ scenario, search, want_nodes, mx });
            skip = true;
            t.not_run += 1;
            continue;
        };
        s.trace = false;
        const clears = hashClears(s);
        const out = s.search(.own);
        const kept = hashClears(s) == clears;
        const kept_ok = kept == o.get("hash_kept").?.bool;
        const line = s.lineHex();
        const want_line = o.get("line").?.string;
        const want_makes: u64 = @intCast(o.get("makes").?.integer);
        t.ran += 1;
        t.nodes += out.nodes;
        if (kept) t.kept += 1;
        if (o.get("played").? == .null) {
            // The program is mated: main ends the game without a move (0000:1187).
            over = true;
            const ok = out.exit == .main_loop and out.nodes == want_nodes and out.makes == want_makes and std.mem.eql(u8, &line, want_line) and kept_ok and evasions_ok and s.failure == null;
            if (ok) {
                t.matched += 1;
                continue;
            }
            std.debug.print("normal2: FIRST DIFFERENCE in {s}, search {d} (the program mated): exit {s} (main_loop), nodes {d} ({d}), makes {d} ({d}), line {s}, hash kept {} ({}){s}{s}\n", .{ scenario, search, @tagName(out.exit), out.nodes, want_nodes, out.makes, want_makes, if (std.mem.eql(u8, &line, want_line)) "equal" else "differs", kept, o.get("hash_kept").?.bool, if (s.failure != null) "; " else "", s.failure orelse "" });
            if (!ert_test.knownFailure(known, id)) t.unexpected += 1;
            continue;
        }
        const want = ert_test.expectedOf(parsed.value);
        // The program's move, and set_predicted_reply (not called after a mate score of
        // 19998 or more: the oracle then records no prediction).
        const calls = s.predict_calls;
        s.playMove();
        si.toImage(s);
        const v = ert_test.verdictOf(s, out, want);
        var pb: [5]u8 = undefined;
        const pred = if (s.predict_calls != calls) predictedText(s, &pb) else null;
        const want_pred: ?[]const u8 = switch (o.get("predicted").?) {
            .string => |x| x,
            else => null,
        };
        const pred_ok = if (pred) |x| (want_pred != null and std.mem.eql(u8, x, want_pred.?)) else want_pred == null;
        if (ert_test.allEqual(v) and pred_ok and kept_ok and evasions_ok and s.failure == null) {
            t.matched += 1;
            if (ert_test.knownFailure(known, id)) {
                std.debug.print("normal2: {s} is listed in tests/known_failures.txt but now matches: remove it\n", .{id});
                t.unexpected += 1;
            }
            continue;
        }
        var mb: [5]u8 = undefined;
        std.debug.print("normal2: FIRST DIFFERENCE in {s}, search {d}: played {s} ({s}), nodes {d} ({d}), makes {d} ({d}), line {s}, predicted {s} ({s}), hash kept {} ({}), evasions {s}{s}{s}; the rest of the game not run\n", .{ scenario, search, ert_test.moveText(out.best, &mb), want.played, out.nodes, want.nodes, out.makes, want.makes, if (v.line) "equal" else "differs", pred orelse "none", want_pred orelse "none", kept, o.get("hash_kept").?.bool, if (evasions_ok) "equal" else "differ", if (s.failure != null) "; " else "", s.failure orelse "" });
        if (!ert_test.knownFailure(known, id)) t.unexpected += 1;
        skip = true;
    }
    return t;
}

/// The largest search run, by the golden file's node count. The eight games are 765,791
/// nodes in 43 searches (the largest 108,286); ReleaseFast and ReleaseSafe run them all.
/// Debug, at about 1,500 nodes a second, runs the searches up to 16,000 nodes and leaves
/// out the rest of each game from its first larger search (printed). With
/// MCHESS_LONG_TESTS set and not empty, every search is run in every build.
fn maxNodes(gpa: std.mem.Allocator) !?u64 {
    if (try std.testing.environ.containsUnempty(gpa, "MCHESS_LONG_TESTS")) return null;
    return if (builtin.mode == .debug) 16_000 else null;
}

test "join-root normal play: every search of tests/golden/normal2.jsonl (eight games from Setup mode in which the opponent gives check) and the evasion count after each check" {
    const gpa = std.testing.allocator;
    const s = try R.init(gpa, ert_test.golden_slots);
    defer s.deinit();
    const mx = try maxNodes(gpa);
    const t = try runNormal2(gpa, s, mx);
    std.debug.print("normal2: {d} games, {d} searches run ({d} nodes), {d} equal on move, nodes, makes, line, predicted reply, hash kept and evasion count; {d} not run, {d} unexpected results; {d} checks by the opponent, each count and status compared with the original's ({d} with one legal reply, {d} mates); hash tables kept before {d}\n", .{ t.games, t.ran, t.nodes, t.matched, t.not_run, t.unexpected, t.checks, t.one_reply, t.mates, t.kept });
    try std.testing.expectEqual(@as(u32, 0), t.unexpected);
    try std.testing.expectEqual(@as(u32, 8), t.games);
    try std.testing.expectEqual(t.ran, t.matched);
    try std.testing.expect(t.ran > 0);
    if (mx == null) try std.testing.expectEqual(@as(u32, 0), t.not_run);
    if (mx == null) try std.testing.expect(t.checks >= 30);
}
