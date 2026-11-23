//! DEV-067 (class C, whose consequence in the original is class B; owner decision 42): main's
//! pre-scoring stores -20500 for a root move that leaves its own king attacked (0000:0A1A,
//! from 0B76 for White) and takes one from the legal count [A518]; the descending sort
//! (0000:668E) then puts the illegal moves past the count root_search stops at. A legal
//! quiet move's pre-score is the static evaluation, which has no floor: in the positions of
//! tests/golden/dev067.jsonl it falls below -20500, the legal moves sort after the illegal
//! ones and the original searches and plays an illegal move. Corrected
//! (`dev067_illegal_root_sentinel`, `pos.rootListScore`), the illegal moves are stored with
//! -32768, below every legal score.
//!
//! - With every fix off the engine equals the original on every record: move (the move the
//!   search gave, which the engine's legality guard then refuses), node entries, makes and
//!   line hash, so the port reproduces the bug.
//! - With the shipped fixes the two faulty positions give a legal move and the guard does
//!   not fire; the boundary position, where every legal pre-score is above -20500, is
//!   searched as the original searches it (b8b7, 52 nodes, 56 makes, the same line).
//! - set_predicted_reply (38C0:0E1A) uses the same sentinel. No recorded or generated
//!   search was found to reach it with a legal reply below -20500 (640 searches of
//!   positions built for it, through mchess-original), so its routine is tested directly
//!   with replies scored by hand: with the fix off an illegal reply becomes the predicted
//!   reply, the ponder move the engine sends; with it on, the legal one.

const std = @import("std");
const fen = @import("fen.zig");
const pos = @import("position.zig");
const gm = @import("gamemove.zig");
const rs = @import("rootsearch.zig");
const uci_engine = @import("uci_engine.zig");
const engine_mod = @import("engine.zig");
const adapt_setup = @import("adapt_setup.zig");
const ert_test = @import("engine_root_test.zig");

const Capture = struct {
    buf: [1 << 15]u8 = undefined,
    len: usize = 0,
    fn lineFn(ctx: ?*anyopaque, line: []const u8) void {
        const c: *Capture = @ptrCast(@alignCast(ctx.?));
        if (c.len + line.len + 1 > c.buf.len) c.len = 0;
        @memcpy(c.buf[c.len..][0..line.len], line);
        c.len += line.len;
        c.buf[c.len] = '\n';
        c.len += 1;
    }
    fn text(c: *const Capture) []const u8 {
        return c.buf[0..c.len];
    }
    fn out(c: *Capture) uci_engine.Output {
        return .{ .ctx = c, .lineFn = lineFn };
    }
};

/// The legal moves of each position of the golden file (python-chess 1.11.2).
const Legal = struct { board: []const u8, moves: []const []const u8 };
const legal_moves = [_]Legal{
    .{ .board = "1K4k1/2nqq3/8/7q/8/2q1q3/2q5/r5q1", .moves = &.{"b8b7"} },
    .{ .board = "b7/Kn6/6b1/2rq1q2/3q4/1n3kr1/5q2/2q5", .moves = &.{ "a7a8", "a7a6", "a7b8", "a7b6" } },
    .{ .board = "1K4k1/2nqq3/8/7q/8/2q1q3/2q5/r7", .moves = &.{"b8b7"} },
};

fn legalOf(board: []const u8) []const []const u8 {
    for (legal_moves) |l| {
        if (std.mem.eql(u8, l.board, board)) return l.moves;
    }
    unreachable;
}

/// Every fix off but DEV-067's.
const dev067_only: pos.Fixes = blk: {
    var f = pos.Fixes.original;
    f.dev067_illegal_root_sentinel = true;
    break :blk f;
};

const Outcome = struct { differ: u32 = 0, ran: u32 = 0 };

/// Every record of tests/golden/dev067.jsonl through the engine `E`: `position fen` (Setup
/// mode's route, the rights the board allows) and `go depth N` on a fresh engine.
/// `original`: compare with the record (the move the search gave, nodes, makes, line).
/// Otherwise: the move is legal and the guard silent; the boundary is the original's.
fn runGolden(comptime E: type, original: bool) !Outcome {
    const gpa = std.testing.allocator;
    const jl = try ert_test.readGolden(gpa, "dev067.jsonl");
    defer gpa.free(jl);
    var res: Outcome = .{};
    var depth: u32 = 0;
    var start: fen.Description = undefined;
    var board: []const u8 = "";
    var lines = std.mem.splitScalar(u8, jl, '\n');
    while (lines.next()) |text| {
        if (text.len == 0) continue;
        const parsed = try std.json.parseFromSlice(std.json.Value, gpa, text, .{});
        defer parsed.deinit();
        const o = parsed.value.object;
        if (o.get("search") == null) {
            const f = o.get("fen").?.string;
            start = try fen.parse(f);
            start.castling = adapt_setup.rightsFromBoard(&start.board);
            board = legal_moves[0].board;
            for (legal_moves) |l| {
                if (std.mem.startsWith(u8, f, l.board) and f[l.board.len] == ' ') board = l.board;
            }
            depth = @intCast(o.get("depth").?.integer);
            continue;
        }
        const want = ert_test.expectedOf(parsed.value);
        const e = try gpa.create(E);
        defer gpa.destroy(e);
        e.* = try E.init(gpa);
        defer e.deinit();
        const eng = e.engine();
        if (eng.setPosition(&start, .setup, &.{})) |why| {
            std.debug.print("DEV-067: {s}: rejected: {s}\n", .{ board, why });
            return error.Rejected;
        }
        var cap: Capture = .{};
        var sig: uci_engine.Signals = .{};
        const best = eng.search(&.{ .depth = depth }, &sig, cap.out()).best orelse return error.NoMove;
        var mb: [5]u8 = undefined;
        const got = fen.formatMove(best, &mb);
        const legal = legalOf(board);
        var is_legal = false;
        for (legal) |m| {
            if (std.mem.eql(u8, m, got)) is_legal = true;
        }
        const guard = std.mem.indexOf(u8, cap.text(), "illegal move") != null;
        const line = e.root.lineHex();
        const same_tree = e.root.nodes == want.nodes and e.root.makes == want.makes and std.mem.eql(u8, &line, want.line);
        // The move the search gave: the guard names it when it refuses it.
        var gave_buf: [64]u8 = undefined;
        const gave = try std.fmt.bufPrint(&gave_buf, "the original's search gave {s},", .{want.played});
        const want_legal = blk: {
            for (legal) |m| {
                if (std.mem.eql(u8, m, want.played)) break :blk true;
            }
            break :blk false;
        };
        var ok: bool = undefined;
        if (original) {
            // The engine plays a legal move in every case (the guard, AGENTS.md 9.3); the
            // search's own move is the original's.
            const searched_same = if (want_legal) std.mem.eql(u8, got, want.played) and !guard else guard and std.mem.indexOf(u8, cap.text(), gave) != null;
            ok = searched_same and same_tree and is_legal;
        } else {
            ok = is_legal and !guard;
            // Where the original's own move is legal (the boundary), its search is unchanged.
            if (want_legal) ok = ok and std.mem.eql(u8, got, want.played) and same_tree;
        }
        res.ran += 1;
        if (!ok) res.differ += 1;
        std.debug.print("DEV-067 ({s}): {s} depth {d}: bestmove {s} ({s}), guard {}, the original played {s}; nodes {d} ({d}), makes {d} ({d}), line {s}\n", .{
            if (original) "every fix off" else "shipped", board,      depth,        got,        if (is_legal) "legal" else "illegal",                          guard, want.played,
            e.root.nodes,                                 want.nodes, e.root.makes, want.makes, if (std.mem.eql(u8, &line, want.line)) "equal" else "differs",
        });
    }
    return res;
}

test "DEV-067: with every fix off the engine equals the original on tests/golden/dev067.jsonl, the illegal moves included" {
    const r = try runGolden(engine_mod.EngineOf(pos.Fixes.original), true);
    try std.testing.expectEqual(@as(u32, 6), r.ran);
    try std.testing.expectEqual(@as(u32, 0), r.differ);
}

test "DEV-067: the shipped engine plays a legal move in the original's two faulty positions without the guard, and searches the boundary as the original" {
    const r = try runGolden(engine_mod.Engine, false);
    try std.testing.expectEqual(@as(u32, 6), r.ran);
    try std.testing.expectEqual(@as(u32, 0), r.differ);
}

test "DEV-067: the fix alone plays a legal move in the faulty positions and searches the boundary as the original" {
    const r = try runGolden(engine_mod.EngineOf(dev067_only), false);
    try std.testing.expectEqual(@as(u32, 6), r.ran);
    try std.testing.expectEqual(@as(u32, 0), r.differ);
}

// ---- set_predicted_reply (38C0:0D22), scored by hand -------------------------------------

/// A `ctx` for `gm.setPredictedReplyFixes` whose replies are legal or not, and scored, as
/// the test says: the evaluators answer from `illegal` and `scores`, and the sort is the
/// port's own sort_root_moves (`rootsearch.sortRootMoves`) on the list and DG:8D0A, as the
/// engine binds it.
const HandScored = struct {
    list: *[100]pos.Move,
    gv: *gm.GameVars,
    king: u8,
    illegal: []const bool,
    scores: []const i16,
    current: usize = 0,

    pub fn genMoves(f: *HandScored, side: u8, in_check: bool) u16 {
        _ = .{ side, in_check };
        return @intCast(f.scores.len);
    }
    pub fn makeMove(f: *HandScored, buf: *[5]u8, side: u8, ply: u16) void {
        _ = .{ side, ply };
        for (f.list[0..f.scores.len], 0..) |m, i| {
            if (m.from == buf[0] and m.to == buf[1]) f.current = i;
        }
        buf[3] = 0;
        buf[4] = 0;
    }
    pub fn unmakeMove(f: *HandScored, move: [5]u8, side: u8) void {
        _ = .{ f, move, side };
    }
    pub fn replyCall(f: *HandScored, c: gm.ReplyCallee, a: u16, b: u16) u16 {
        _ = .{ a, b };
        switch (c) {
            .leaf_attack_map_white, .leaf_attack_map_black => f.gv.leaf_map[f.king] = @intFromBool(f.illegal[f.current]),
            .static_eval => return @bitCast(f.scores[f.current]),
            .sort_root_moves => {
                const moves: *[100][4]u8 = @ptrCast(f.list);
                var s: [100]i16 = undefined;
                for (&s, f.gv.reply_scores) |*x, w| x.* = @bitCast(w);
                rs.sortRootMoves(moves[0..], s[0..], @intCast(a));
                for (f.gv.reply_scores, s) |*w, x| w.* = @bitCast(x);
            },
            else => {},
        }
        return 0;
    }
};

/// White's king on b8 replies to the program (Black): b8c7, b8a8, b8c8 and b8a7 leave it
/// attacked, b8b7 is legal and scored `legal_score` (static_eval's first term alone,
/// DG:A8DE set). The search left no reply (DG:A416 = 0), so the best-scored reply becomes
/// the predicted one. Returns it.
fn predicted(comptime fixes: pos.Fixes, legal_score: i16) ![4]u8 {
    const gpa = std.testing.allocator;
    const img = try gpa.create([0x10000]u8);
    defer gpa.destroy(img);
    @memset(img, 0);
    var gv: gm.GameVars = .{};
    gv.bindImage(img);
    gv.opponent_side.* = 0;
    gv.computer_side.* = 1;
    gv.ba8de.* = 1;
    var p: pos.Position = .{};
    p.piece_list[7] = 92; // b8
    p.total_material = 4000;
    var list: [100]pos.Move = @splat(.{ .from = 0, .to = 0, .flag = 0, .score = 0 });
    const tos = [_]u8{ 83, 91, 93, 81, 82 }; // c7, a8, c8, a7, b7
    for (tos, 0..) |t, i| list[i] = .{ .from = 92, .to = t, .flag = 0, .score = 0 };
    var ctx: HandScored = .{ .list = &list, .gv = &gv, .king = 92, .illegal = &.{ true, true, true, true, false }, .scores = &.{ 0, 0, 0, 0, legal_score } };
    gm.setPredictedReplyFixes(fixes, &p, &gv, &list, &ctx);
    try std.testing.expectEqual(@as(u16, 1), gv.reply_count);
    return gv.predicted_reply;
}

test "DEV-067: set_predicted_reply: an illegal reply is no longer predicted (the ponder move) when the legal one scores below -20500" {
    const only = dev067_only;
    // The original: b7 at -21851 sorts after the four illegal replies at -20500; the first,
    // b8c7, is predicted.
    const o = try predicted(pos.Fixes.original, -21851);
    std.debug.print("DEV-067: set_predicted_reply, legal reply at -21851: original {d}-{d}, corrected {d}-{d}\n", .{ o[0], o[1], (try predicted(only, -21851))[0], (try predicted(only, -21851))[1] });
    try std.testing.expectEqual(@as(u8, 83), o[1]);
    try std.testing.expectEqual(@as(u8, 82), (try predicted(only, -21851))[1]);
    try std.testing.expectEqual(@as(u8, 82), (try predicted(pos.Fixes.corrected, -21851))[1]);
    // -32768, the one legal score the fix moves (to -32767), still sorts first.
    try std.testing.expectEqual(@as(u8, 82), (try predicted(only, -32768))[1]);
    // Above -20500 both predict b8b7.
    try std.testing.expectEqual(@as(u8, 82), (try predicted(pos.Fixes.original, -20499))[1]);
    try std.testing.expectEqual(@as(u8, 82), (try predicted(only, -20499))[1]);
}
