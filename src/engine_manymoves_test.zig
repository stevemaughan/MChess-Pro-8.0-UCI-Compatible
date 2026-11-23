//! DEV-063 through UCI: `position fen` with a root of 218 moves, and its colour mirror,
//! `go depth 2` and `go depth 4`, on the shipped engine (every class C fix on) and on the
//! original's (every fix off). Before the fix the list of 100 moves was written past its
//! end: in ReleaseSafe a panic in gen_all_moves, in ReleaseFast a corrupted search whose
//! legal mate c4a2 the engine's own legality check then refused (it played d2b2).
//!
//! The original (tests/golden/manymoves.jsonl) plays c4a2 (Black: c5a7) after 9 nodes at
//! both depths: a mate in one found in iteration 1.

const std = @import("std");
const fen = @import("fen.zig");
const pos = @import("position.zig");
const uci_engine = @import("uci_engine.zig");
const engine_mod = @import("engine.zig");

const Capture = struct {
    buf: [1 << 16]u8 = undefined,
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

const Case = struct { fen: []const u8, best: []const u8 };
const cases = [_]Case{
    .{ .fen = "R6R/3Q4/1Q4Q1/4Q3/2Q4Q/Q4Q2/pp1Q4/kBNN1KB1 w - - 0 1", .best = "c4a2" },
    .{ .fen = "Kbnn1kb1/PP1q4/q4q2/2q4q/4q3/1q4q1/3q4/r6r b - - 0 1", .best = "c5a7" },
};

fn checkEngine(comptime E: type, label: []const u8) !void {
    const gpa = std.testing.allocator;
    for (cases) |c| {
        for ([_]u32{ 2, 4 }) |depth| {
            const e = try gpa.create(E);
            defer gpa.destroy(e);
            e.* = try E.init(gpa);
            defer e.deinit();
            var cap: Capture = .{};
            const d = try fen.parse(c.fen);
            const eng = e.engine();
            if (eng.setPosition(&d, .setup, &.{})) |why| {
                std.debug.print("rejected {s}: {s}\n", .{ c.fen, why });
                return error.Rejected;
            }
            var sig: uci_engine.Signals = .{};
            const best = eng.search(&.{ .depth = depth }, &sig, cap.out()).best orelse return error.NoMove;
            var mb: [5]u8 = undefined;
            const text = fen.formatMove(best, &mb);
            std.debug.print("DEV-063 ({s}): {s} go depth {d}: bestmove {s}\n", .{ label, c.fen, depth, text });
            try std.testing.expectEqualStrings(c.best, text);
            try std.testing.expect(std.mem.indexOf(u8, cap.text(), "illegal move") == null);
            // The original's 9 nodes, reported on the last line of the search.
            try std.testing.expect(std.mem.indexOf(u8, cap.text(), " nodes 9 ") != null);
        }
    }
}

test "DEV-063: a root of 218 moves through UCI, both colours, depths 2 and 4 (shipped engine)" {
    try checkEngine(engine_mod.Engine, "every fix on");
}

test "DEV-063: a root of 218 moves through UCI, both colours, depths 2 and 4 (every fix off)" {
    try checkEngine(engine_mod.EngineOf(pos.Fixes.original), "every fix off");
}
