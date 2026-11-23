//! Castling from a set-up position: every search of tests/golden/castling.jsonl, from the
//! engine's own set-up (start-up, Setup mode with the scenario's FEN, Ctrl-A), compared
//! with the original on move, nodes, makes and line hash.
//!
//! Setup mode gives castling rights from the board alone (38C0:6CBF..6D0A: a king on its
//! e-square and a rook on its corner square hold the right). The five scenarios
//! (tests/scenarios/castling.json, oracle version 4) are positions where rights are held:
//! all four; all four with Black to move; kings and rooks only; and one where each side
//! holds one right (White O-O-O, Black O-O). The original castles in three of the
//! searches (e8g8, e1g1 twice), once as the first move from the set-up position, and
//! castling moves are searched in all of them.

const std = @import("std");
const builtin = @import("builtin");
const ert_test = @import("engine_root_test.zig");
const ast = @import("adapt_setup_test.zig");
const as = @import("adapt_setup.zig");
const fen = @import("fen.zig");
const pos = @import("position.zig");
const setup = @import("setup.zig");

const R = ert_test.R;

/// Castling moves made anywhere in the searches traced so far, by right.
const CastlingMakes = struct {
    white_short: u32 = 0,
    white_long: u32 = 0,
    black_short: u32 = 0,
    black_long: u32 = 0,
    /// A move with the castling flag that is none of the four king moves.
    other: u32 = 0,
    makes: u64 = 0,

    fn add(n: *CastlingMakes, s: *R) void {
        for (s.events.items) |ev| switch (ev) {
            .make => |m| {
                n.makes += 1;
                if (m.flag != pos.flag_castle) continue;
                // The king's move on the 10x12 board: e1 = 25, g1 = 27, c1 = 23; e8 = 95.
                if (m.from == 25 and m.to == 27) {
                    n.white_short += 1;
                } else if (m.from == 25 and m.to == 23) {
                    n.white_long += 1;
                } else if (m.from == 95 and m.to == 97) {
                    n.black_short += 1;
                } else if (m.from == 95 and m.to == 93) {
                    n.black_long += 1;
                } else n.other += 1;
            },
            else => {},
        };
    }
};

test "adapt_setup: a castling right the FEN withholds: no castling move of that right is made anywhere in the search trees" {
    const gpa = std.testing.allocator;
    const s = try R.init(gpa, ert_test.golden_slots);
    defer s.deinit();
    const depth: u16 = if (builtin.mode == .debug) 3 else 4;
    // Kings and rooks on their home squares in every case; only the FEN's rights differ.
    const cases = [_][]const u8{
        "r3k2r/p6p/8/8/8/8/P6P/R3K2R w KQkq - 0 1", // every right held: the control
        "r3k2r/p6p/8/8/8/8/P6P/R3K2R w Kq - 0 1",
        "r3k2r/p6p/8/8/8/8/P6P/R3K2R w Qk - 0 1",
        "r3k2r/p6p/8/8/8/8/P6P/R3K2R w - - 0 1",
        "r3k2r/p6p/8/8/8/8/P6P/R3K2R b kq - 0 1",
        "r3k2r/p6p/8/8/8/8/P6P/R3K2R b KQ - 0 1",
    };
    for (cases, 0..) |text, case| {
        const d = try fen.parse(text);
        s.startUp(.{}, .{}, .{}, depth);
        try std.testing.expectEqual(setup.Legality.legal, as.enterFen(s, &d));
        try std.testing.expect(s.autoPlay());
        var n: CastlingMakes = .{};
        // The first search and the two after it, reached through the game-move path.
        for (0..3) |k| {
            if (k != 0) {
                s.playMove();
                s.nextTurnAutoPlay();
            }
            s.failure = null;
            s.trace = true;
            s.events.clearRetainingCapacity();
            _ = s.search(.own);
            try std.testing.expect(s.failure == null);
            n.add(s);
        }
        s.trace = false;
        s.events.clearRetainingCapacity();
        std.debug.print("castling rights: {s}: three searches at depth {d}, {d} moves made; castling moves made: White O-O {d}, O-O-O {d}, Black O-O {d}, O-O-O {d}\n", .{ text, depth, n.makes, n.white_short, n.white_long, n.black_short, n.black_long });
        try std.testing.expectEqual(@as(u32, 0), n.other);
        if (!d.castling.white_short) try std.testing.expectEqual(@as(u32, 0), n.white_short);
        if (!d.castling.white_long) try std.testing.expectEqual(@as(u32, 0), n.white_long);
        if (!d.castling.black_short) try std.testing.expectEqual(@as(u32, 0), n.black_short);
        if (!d.castling.black_long) try std.testing.expectEqual(@as(u32, 0), n.black_long);
        if (case == 0) {
            // The control: with every right held the same trees do try all four.
            try std.testing.expect(n.white_short > 0 and n.white_long > 0 and n.black_short > 0 and n.black_long > 0);
        }
    }
}

fn isCastling(played: []const u8, board: []const u8) bool {
    // A king's two-square move from e1 or e8; the record's board has the king there.
    const white = std.mem.eql(u8, played, "e1g1") or std.mem.eql(u8, played, "e1c1");
    const black = std.mem.eql(u8, played, "e8g8") or std.mem.eql(u8, played, "e8c8");
    if (!white and !black) return false;
    var ranks = std.mem.splitScalar(u8, board, '/');
    var rank: []const u8 = "";
    var k: usize = 0;
    while (ranks.next()) |r| : (k += 1) {
        if ((black and k == 0) or (white and k == 7)) rank = r;
    }
    // File e: count squares along the rank.
    var file: usize = 0;
    for (rank) |c| {
        if (c >= '1' and c <= '8') {
            file += c - '0';
        } else {
            if (file == 4) return c == (if (white) @as(u8, 'K') else 'k');
            file += 1;
        }
    }
    return false;
}

test "adapt_setup: castling from set-up positions: every search of tests/golden/castling.jsonl from the engine's own set-up" {
    const gpa = std.testing.allocator;
    const s = try R.init(gpa, ert_test.golden_slots);
    defer s.deinit();
    const jl = try ert_test.readGolden(gpa, "castling.jsonl");
    defer gpa.free(jl);
    const long = try std.testing.environ.containsUnempty(gpa, "MCHESS_LONG_TESTS");
    const max_nodes: ?u64 = if (builtin.mode == .debug and !long) 25_000 else null;
    var lines = std.mem.splitScalar(u8, jl, '\n');
    var scenarios: u32 = 0;
    var ran: u32 = 0;
    var matched: u32 = 0;
    var not_run: u32 = 0;
    var castled: u32 = 0;
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
            std.debug.print("castling: {s} search {d}: {d} nodes, above the {d} this build runs (MCHESS_LONG_TESTS=1 runs all): it and the rest of the scenario not run\n", .{ current, search, want.nodes, mx });
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
        const played = ert_test.moveText(out.best, &mb);
        const castles = ok and isCastling(played, o.get("board").?.string);
        if (castles) castled += 1;
        if (!ok or castles) {
            std.debug.print("castling: {s} search {d}: played {s} ({s}){s}, nodes {d} ({d}), makes {d} ({d}), line {s}{s}{s}\n", .{ current, search, played, want.played, if (castles) " castling" else "", out.nodes, want.nodes, out.makes, want.makes, if (v.line) "equal" else "differs", if (s.failure != null) "; " else "", s.failure orelse "" });
        }
    }
    std.debug.print("castling: {d} set-up positions with castling rights; {d} searches run, {d} equal on all four values, {d} not run; castling played in {d}\n", .{ scenarios, ran, matched, not_run, castled });
    try std.testing.expectEqual(@as(u32, 5), scenarios);
    try std.testing.expectEqual(ran, matched);
    try std.testing.expect(castled >= 1);
    if (max_nodes == null) {
        try std.testing.expectEqual(@as(u32, 38), ran);
        try std.testing.expectEqual(@as(u32, 3), castled);
    }
}
