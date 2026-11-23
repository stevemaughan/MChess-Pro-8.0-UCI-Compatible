//! Tests of the UCI shell's command handling (src/uci.zig `Session`) with the stub
//! engine, in process. The threads and standard I/O are tested on the built
//! executable by tools/scripts/uci_protocol_test.py.

const std = @import("std");
const uci = @import("uci.zig");
const uci_engine = @import("uci_engine.zig");

/// Collects output lines.
const Capture = struct {
    buf: [16384]u8 = undefined,
    len: usize = 0,

    fn output(c: *Capture) uci_engine.Output {
        return .{ .ctx = c, .lineFn = lineFn };
    }

    fn lineFn(ctx: ?*anyopaque, text: []const u8) void {
        const c: *Capture = @ptrCast(@alignCast(ctx.?));
        if (c.len + text.len + 1 > c.buf.len) return;
        @memcpy(c.buf[c.len..][0..text.len], text);
        c.buf[c.len + text.len] = '\n';
        c.len += text.len + 1;
    }

    fn take(c: *Capture) []const u8 {
        const t = c.buf[0..c.len];
        c.len = 0;
        return t;
    }
};

const Harness = struct {
    stub: uci_engine.StubEngine = .{},
    cap: Capture = .{},
    session: uci.Session = undefined,
    sig: uci_engine.Signals = .{},

    fn init(h: *Harness) void {
        h.* = .{};
        h.session = .init(h.stub.engine(), h.cap.output());
    }

    /// Runs one engine command and returns its output.
    fn run(h: *Harness, line: []const u8) []const u8 {
        h.sig = .{};
        h.session.execute(line, &h.sig, std.testing.io);
        return h.cap.take();
    }
};

const expect = std.testing.expect;
const expectEqualStrings = std.testing.expectEqualStrings;

test "go on the start position answers with the stub's info string and bestmove 0000" {
    var h: Harness = undefined;
    h.init();
    try expectEqualStrings(uci_engine.StubEngine.not_ported ++ "\nbestmove 0000\n", h.run("go depth 3"));
    try expect(h.stub.searches == 1);
}

test "a rejected position is reported, and go repeats the reason and plays no move" {
    var h: Harness = undefined;
    h.init();
    const reason = "info string error: position rejected: FEN side to move is not 'w' or 'b'\n";
    try expectEqualStrings(reason, h.run("position fen 4k3/8/8/8/8/8/8/4K3 x - - 0 1"));
    try expectEqualStrings(reason ++ "bestmove 0000\n", h.run("go"));
    try expect(h.stub.searches == 0);
    try expectEqualStrings("", h.run("position startpos moves e2e4 e7e5"));
    try expect(h.stub.move_count == 2);
    try expectEqualStrings(uci_engine.StubEngine.not_ported ++ "\nbestmove 0000\n", h.run("go"));
}

test "a bad move and too many moves are rejected" {
    var h: Harness = undefined;
    h.init();
    try expectEqualStrings(
        "info string error: position rejected: move 3 'e2e9': move has a square that is not a1..h8\n",
        h.run("position startpos moves e2e4 e7e5 e2e9"),
    );
    var buf: [5 * (uci.max_position_moves + 1) + 32]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try w.writeAll("position startpos moves");
    for (0..uci.max_position_moves + 1) |_| try w.writeAll(" g1f3");
    try expectEqualStrings(std.fmt.comptimePrint("info string error: position rejected: more than {d} moves\n", .{uci.max_position_moves}), h.run(w.buffered()));
}

test "malformed go still gets one bestmove" {
    var h: Harness = undefined;
    h.init();
    try expectEqualStrings("info string error: go parameter without a valid number in 'go depth x'\nbestmove 0000\n", h.run("go depth x"));
    try expectEqualStrings("info string error: searchmoves 'e2e5q': promotion is not from the 7th rank to the 8th or the 2nd to the 1st\nbestmove 0000\n", h.run("go searchmoves e2e4 e2e5q"));
}

test "go infinite holds bestmove until stop" {
    var h: Harness = undefined;
    h.init();
    h.sig = .{};
    const T = struct {
        fn stopLater(sig: *uci_engine.Signals) void {
            std.testing.io.sleep(.fromMilliseconds(50), .awake) catch {};
            sig.setStop(std.testing.io);
        }
        fn storeStopLater(sig: *uci_engine.Signals) void {
            std.testing.io.sleep(.fromMilliseconds(50), .awake) catch {};
            sig.stop.store(true, .release);
        }
    };
    const t = try std.Thread.spawn(.{}, T.stopLater, .{&h.sig});
    h.session.execute("go infinite", &h.sig, std.testing.io);
    t.join();
    try expectEqualStrings(uci_engine.StubEngine.not_ported ++ "\nbestmove 0000\n", h.cap.take());
    // A flag stored without `setStop` still ends the hold (within the 100 ms backstop).
    h.sig = .{};
    const t2 = try std.Thread.spawn(.{}, T.storeStopLater, .{&h.sig});
    h.session.execute("go infinite", &h.sig, std.testing.io);
    t2.join();
    try expectEqualStrings(uci_engine.StubEngine.not_ported ++ "\nbestmove 0000\n", h.cap.take());
}

test "go ponder holds bestmove until ponderhit" {
    var h: Harness = undefined;
    h.init();
    h.sig = .{};
    const T = struct {
        fn hitLater(sig: *uci_engine.Signals) void {
            std.testing.io.sleep(.fromMilliseconds(50), .awake) catch {};
            sig.setPonderhit(std.testing.io);
        }
    };
    const t = try std.Thread.spawn(.{}, T.hitLater, .{&h.sig});
    const t0 = std.Io.Clock.awake.now(std.testing.io).nanoseconds;
    h.session.execute("go ponder", &h.sig, std.testing.io);
    const held = std.Io.Clock.awake.now(std.testing.io).nanoseconds - t0;
    t.join();
    try expectEqualStrings(uci_engine.StubEngine.not_ported ++ "\nbestmove 0000\n", h.cap.take());
    try expect(held >= 40 * std.time.ns_per_ms);
}

test "options are stored and passed to the engine" {
    var h: Harness = undefined;
    h.init();
    try expectEqualStrings("", h.run("setoption name Hash value 16"));
    // Owner decision 25: the class C corrections are always on; the option is gone.
    try expectEqualStrings("info string error: unknown option 'original bugs'\n", h.run("setoption name original bugs value true"));
    try expectEqualStrings("", h.run("setoption name Move Overhead value 100"));
    try expectEqualStrings("", h.run("setoption name OwnBook value false"));
    try expectEqualStrings("", h.run("setoption name Ponder value true"));
    try expect(h.stub.options.hash_mb == 16);
    try expect(h.stub.options.move_overhead_ms == 100);
    try expect(!h.stub.options.own_book);
    try expect(h.stub.options.ponder);
    try expectEqualStrings("info string error: bad value '61' for option Hash\n", h.run("setoption name Hash value 61"));
    try expectEqualStrings("info string error: unknown option 'Threads'\n", h.run("setoption name Threads value 2"));
    try expect(h.stub.options.hash_mb == 16);
}

test "a Seed out of range is refused and the previous Seed stays in force after another option succeeds" {
    var h: Harness = undefined;
    h.init();
    try expectEqualStrings("", h.run("setoption name Seed value 42"));
    try expect(h.stub.options.seed == 42);
    for ([_][]const u8{ "65536", "-2", "abc", "99999999999" }) |bad| {
        var line: [64]u8 = undefined;
        var want: [96]u8 = undefined;
        const cmd = try std.fmt.bufPrint(&line, "setoption name Seed value {s}", .{bad});
        const msg = try std.fmt.bufPrint(&want, "info string error: bad value '{s}' for option Seed\n", .{bad});
        try expectEqualStrings(msg, h.run(cmd));
        // Another option succeeds: what the engine is handed still has Seed 42.
        try expectEqualStrings("", h.run("setoption name OwnBook value true"));
        try expect(h.stub.options.seed == 42);
        try expect(h.session.options.seed == 42);
    }
    try expectEqualStrings("", h.run("setoption name Seed value -1"));
    try expect(h.stub.options.seed == -1);
    try expectEqualStrings("", h.run("setoption name Seed value 65535"));
    try expect(h.stub.options.seed == 65535);
}

test "ucinewgame gives a valid start position" {
    var h: Harness = undefined;
    h.init();
    _ = h.run("position fen nonsense");
    try expectEqualStrings("", h.run("ucinewgame"));
    try expect(h.stub.new_games == 1);
    try expectEqualStrings(uci_engine.StubEngine.not_ported ++ "\nbestmove 0000\n", h.run("go"));
}
