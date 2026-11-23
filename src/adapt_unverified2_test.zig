//! Searches recorded to reach code that carried an UNVERIFIED tag (docs/UNVERIFIED.md,
//! "Recordings, 2026-11-22"): every search of tests/golden/unverified2.jsonl
//! (tests/scenarios/unverified2.json, oracle version 4, auto-play from Setup mode), from the
//! engine's own set-up (start-up, Setup mode with the scenario's FEN, Ctrl-A), compared with
//! the original on move, nodes, makes and line hash.
//!
//! - knight-last-rank-white-d3, knight-last-rank-black-d3: a pawn on its seventh rank,
//!   blocked by a rook, and a knight that can step to a last-rank square the pawn attacks:
//!   gen_tactical_moves' second rule for a quiet knight move (a defended square on the
//!   last rank; 1E9D:57C0 White, 58B8 Black; movegen.zig `Tactical.knight`).
//! - null-no-move-d5: a king boxed by enemy pawns (every step onto a pawn-attacked square),
//!   with a rook and a bishop hemmed in by its own blocked pawns (1,800 of material): after
//!   ...f3-f2 White has no pseudo-legal move, and the null move's generation returns 0
//!   (searchnode.zig B7).
//! - null-draw-white-d5, null-draw-black-d5: king, bishop and rook's pawn against a king in
//!   the pawn's corner: static_eval's tail sets the draw flag (2B9F:3EB8 / 3EF4) inside the
//!   null move (searchnode.zig B7).
//! - swap-ten-rounds-black-victim-d1, swap-ten-rounds-white-victim-d1 (its mirror): twelve
//!   men of each side bearing on a bishop on e5 (e4 in the mirror): two pawns, two knights,
//!   and rooks and bishops behind one another on the eight rays. leafTermA's swap-off runs
//!   its ten rounds and stops (2B9F:54D0 with White capturing, 5E06 with Black; leaf.zig).
//!   The search does not see the tenth round (no change to it alters a node count here);
//!   tests/golden/leaf/H5.zst and H6.zst, replayed call by call by src/leaf_test.zig, do.
//!
//! No position has a material the shipped tablebases cover (KPK, KQK, KRK), so the root's
//! probe misses in the original as it does here (no tablebase files are given to the engine).

const std = @import("std");
const ert_test = @import("engine_root_test.zig");
const ast = @import("adapt_setup_test.zig");

const R = ert_test.R;

test "adapt_setup: every search of tests/golden/unverified2.jsonl (sites that carried UNVERIFIED tags) from the engine's own set-up" {
    const gpa = std.testing.allocator;
    const s = try R.init(gpa, ert_test.golden_slots);
    defer s.deinit();
    const jl = try ert_test.readGolden(gpa, "unverified2.jsonl");
    defer gpa.free(jl);
    var lines = std.mem.splitScalar(u8, jl, '\n');
    var scenarios: u32 = 0;
    var ran: u32 = 0;
    var matched: u32 = 0;
    var current_buf: [64]u8 = undefined;
    var current: []const u8 = "";
    while (lines.next()) |text| {
        if (text.len == 0) continue;
        const parsed = try std.json.parseFromSlice(std.json.Value, gpa, text, .{});
        defer parsed.deinit();
        const o = parsed.value.object;
        if (o.get("search") == null) {
            try std.testing.expectEqualStrings("move", o.get("dev003").?.string);
            try std.testing.expectEqualStrings("zero", o.get("hash_tail").?.object.get("mode").?.string);
            const name = o.get("scenario").?.string;
            @memcpy(current_buf[0..name.len], name);
            current = current_buf[0..name.len];
            const d = try ast.descriptionOf(o.get("fen").?.string);
            try ast.startFromSetup(s, &d, @intCast(o.get("depth").?.integer));
            scenarios += 1;
            continue;
        }
        const search = o.get("search").?.integer;
        if (search > 1) {
            s.playMove();
            s.nextTurnAutoPlay();
        }
        const want = ert_test.expectedOf(parsed.value);
        s.failure = null;
        const out = s.search(.own);
        ran += 1;
        const v = ert_test.verdictOf(s, out, want);
        const ok = ert_test.allEqual(v) and s.failure == null;
        if (ok) matched += 1;
        var mb: [5]u8 = undefined;
        std.debug.print("unverified2: {s} search {d}: played {s} ({s}), nodes {d} ({d}), makes {d} ({d}), line {s}{s}{s}\n", .{ current, search, ert_test.moveText(out.best, &mb), want.played, out.nodes, want.nodes, out.makes, want.makes, if (v.line) "equal" else "differs", if (s.failure != null) "; " else "", s.failure orelse "" });
    }
    std.debug.print("unverified2: {d} scenarios; {d} searches run, {d} equal on all four values\n", .{ scenarios, ran, matched });
    try std.testing.expectEqual(@as(u32, 7), scenarios);
    try std.testing.expectEqual(@as(u32, 14), ran);
    try std.testing.expectEqual(ran, matched);
}
