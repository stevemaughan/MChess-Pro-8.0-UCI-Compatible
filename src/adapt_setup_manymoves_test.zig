//! DEV-063: searches whose move lists pass the original's 100 entries, from the engine's
//! own set-up (start-up, Setup mode with the scenario's FEN, Ctrl-A), compared with the
//! original on move, nodes, makes and line hash: every search of
//! tests/golden/manymoves.jsonl (tests/scenarios/manymoves.json, oracle version 4).
//!
//! The root of `R6R/3Q4/1Q4Q1/4Q3/2Q4Q/Q4Q2/pp1Q4/kBNN1KB1 w` has 218 moves (the most a
//! legal position has): gen_all_moves (1E9D:3938) scores 9 of them and leaves 209
//! unscored, keeps the 9 sorted and the first 91 unscored ones (48D8..4913) and returns
//! 100; the original writes the 209 unscored moves from DG:B106 to DG:B449, over the
//! castling stamps and the variables after them, and its search reads none of those it
//! damaged before the move is played (traced). The line hash covers the 100 root moves
//! made in iteration 1, in the root's order, so an equal line means the same 100 moves.
//! The other scenarios are the mirror for Black, the same at depth 4, and positions whose
//! nodes inside the tree pass 100 moves (the scenario file names them).

const std = @import("std");
const builtin = @import("builtin");
const ert_test = @import("engine_root_test.zig");
const ast = @import("adapt_setup_test.zig");

const R = ert_test.R;

test "adapt_setup: more than 100 moves at a node (DEV-063): every search of tests/golden/manymoves.jsonl from the engine's own set-up" {
    const gpa = std.testing.allocator;
    const s = try R.init(gpa, ert_test.golden_slots);
    defer s.deinit();
    const jl = try ert_test.readGolden(gpa, "manymoves.jsonl");
    defer gpa.free(jl);
    const long = try std.testing.environ.containsUnempty(gpa, "MCHESS_LONG_TESTS");
    const max_nodes: ?u64 = if (builtin.mode == .debug and !long) 25_000 else null;
    var lines = std.mem.splitScalar(u8, jl, '\n');
    var scenarios: u32 = 0;
    var ran: u32 = 0;
    var matched: u32 = 0;
    var not_run: u32 = 0;
    var current_buf: [64]u8 = undefined;
    var current: []const u8 = "";
    var skip = false;
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
            skip = false;
            const d = try ast.descriptionOf(o.get("fen").?.string);
            try ast.startFromSetup(s, &d, @intCast(o.get("depth").?.integer));
            scenarios += 1;
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
            std.debug.print("manymoves: {s} search {d}: {d} nodes, above the {d} this build runs (MCHESS_LONG_TESTS=1 runs all): it and the rest of the scenario not run\n", .{ current, search, want.nodes, mx });
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
        std.debug.print("manymoves: {s} search {d}: played {s} ({s}), nodes {d} ({d}), makes {d} ({d}), line {s}{s}{s}\n", .{ current, search, ert_test.moveText(out.best, &mb), want.played, out.nodes, want.nodes, out.makes, want.makes, if (v.line) "equal" else "differs", if (s.failure != null) "; " else "", s.failure orelse "" });
    }
    std.debug.print("manymoves: {d} scenarios; {d} searches run, {d} equal on all four values, {d} not run\n", .{ scenarios, ran, matched, not_run });
    try std.testing.expect(scenarios >= 3);
    try std.testing.expect(ran >= 3);
    try std.testing.expectEqual(ran, matched);
}
