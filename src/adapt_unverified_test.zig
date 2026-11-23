//! Searches recorded to reach code that carried an UNVERIFIED tag (docs/UNVERIFIED.md,
//! "Recordings"): every search of tests/golden/unverified.jsonl (tests/scenarios/
//! unverified.json, oracle version 4, auto-play from Setup mode), from the engine's own
//! set-up (start-up, Setup mode with the scenario's FEN, Ctrl-A), compared with the original
//! on move, nodes, makes and line hash.
//!
//! - boxed-king-d4: a pawn ending in which a Black pawn move leaves White's lone king with
//!   no pseudo-legal move (gen_all_moves leaves out king steps onto squares an enemy pawn
//!   attacks): the full-width node's "no move" return (B16, 3728; searchnode.zig), in the
//!   general node and at ply 2, and the stalemate score (B19).
//! - battery-black-d3, battery-white-d3: a queen with two rooks behind it on the e-file:
//!   leafTermA's second rook behind line queens (2B9F:5391-53A1, 5424-5431; leaf.zig).
//!
//! Every position has seven men or more, so the root never probes the tablebases.

const std = @import("std");
const ert_test = @import("engine_root_test.zig");
const ast = @import("adapt_setup_test.zig");

const R = ert_test.R;

test "adapt_setup: every search of tests/golden/unverified.jsonl (sites that carried UNVERIFIED tags) from the engine's own set-up" {
    const gpa = std.testing.allocator;
    const s = try R.init(gpa, ert_test.golden_slots);
    defer s.deinit();
    const jl = try ert_test.readGolden(gpa, "unverified.jsonl");
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
        std.debug.print("unverified: {s} search {d}: played {s} ({s}), nodes {d} ({d}), makes {d} ({d}), line {s}{s}{s}\n", .{ current, search, ert_test.moveText(out.best, &mb), want.played, out.nodes, want.nodes, out.makes, want.makes, if (v.line) "equal" else "differs", if (s.failure != null) "; " else "", s.failure orelse "" });
    }
    std.debug.print("unverified: {d} scenarios; {d} searches run, {d} equal on all four values\n", .{ scenarios, ran, matched });
    try std.testing.expectEqual(@as(u32, 3), scenarios);
    try std.testing.expectEqual(@as(u32, 9), ran);
    try std.testing.expectEqual(ran, matched);
}
