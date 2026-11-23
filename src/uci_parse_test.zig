//! Tests of UCI command parsing (src/uci_parse.zig).

const std = @import("std");
const p = @import("uci_parse.zig");

const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;
const expectEqualStrings = std.testing.expectEqualStrings;
const expectError = std.testing.expectError;

test "simple commands" {
    try expect((try p.parse("uci")) == .uci);
    try expect((try p.parse("  isready \r\n")) == .isready);
    try expect((try p.parse("ucinewgame")) == .ucinewgame);
    try expect((try p.parse("stop")) == .stop);
    try expect((try p.parse("ponderhit")) == .ponderhit);
    try expect((try p.parse("quit")) == .quit);
    try expect((try p.parse("")) == .unknown);
    try expect((try p.parse("   ")) == .unknown);
    try expect((try p.parse("xyzzy")) == .unknown);
    try expect((try p.parse("register later")) == .unknown);
    try expect((try p.parse("ucix")) == .unknown);
    try expectEqual(true, (try p.parse("debug on")).debug);
    try expectEqual(false, (try p.parse("debug off")).debug);
    try expectError(error.BadDebug, p.parse("debug"));
    try expectError(error.BadDebug, p.parse("debug maybe"));
}

test "setoption" {
    const o = (try p.parse("setoption name Move Overhead value 50")).setoption;
    try expectEqualStrings("Move Overhead", o.name);
    try expectEqualStrings("50", o.value.?);
    const b = (try p.parse("setoption name Original Bugs value true")).setoption;
    try expectEqualStrings("Original Bugs", b.name);
    try expectEqualStrings("true", b.value.?);
    const n = (try p.parse("setoption name Clear Hash")).setoption;
    try expectEqualStrings("Clear Hash", n.name);
    try expect(n.value == null);
    const e = (try p.parse("setoption name Hash value")).setoption;
    try expectEqualStrings("", e.value.?);
    try expectError(error.BadSetOption, p.parse("setoption"));
    try expectError(error.BadSetOption, p.parse("setoption Hash value 3"));
    try expectError(error.BadSetOption, p.parse("setoption name"));
    try expectError(error.BadSetOption, p.parse("setoption name value 3"));
}

test "position" {
    const s = (try p.parse("position startpos")).position;
    try expect(s.fen == null);
    try expectEqualStrings("", s.moves);
    const m = (try p.parse("position startpos moves e2e4 e7e5")).position;
    try expectEqualStrings("e2e4 e7e5", m.moves);
    const em = (try p.parse("position startpos moves")).position;
    try expectEqualStrings("", em.moves);
    const f = (try p.parse("position fen 8/8/8/4k3/8/8/8/4K2R w K - 0 1 moves e1g1")).position;
    try expectEqualStrings("8/8/8/4k3/8/8/8/4K2R w K - 0 1", f.fen.?);
    try expectEqualStrings("e1g1", f.moves);
    const g = (try p.parse("position fen 8/8/8/4k3/8/8/8/4K2R w K -")).position;
    try expectEqualStrings("8/8/8/4k3/8/8/8/4K2R w K -", g.fen.?);
    const e = (try p.parse("position fen")).position;
    try expectEqualStrings("", e.fen.?);
    try expectError(error.BadPosition, p.parse("position"));
    try expectError(error.BadPosition, p.parse("position garbage"));
    try expectError(error.BadPosition, p.parse("position startpos e2e4"));
    try expectError(error.BadPosition, p.parse("position startposmoves e2e4"));
}

test "go with every parameter" {
    const g = (try p.parse("go searchmoves e2e4 d2d4 ponder wtime 60000 btime 59000 winc 1000 binc 900 movestogo 20 depth 6 nodes 100000 mate 3 movetime 5000 infinite")).go;
    try expectEqualStrings("e2e4 d2d4", g.searchmoves.?);
    try expect(g.ponder);
    try expectEqual(@as(?u64, 60000), g.wtime);
    try expectEqual(@as(?u64, 59000), g.btime);
    try expectEqual(@as(u64, 1000), g.winc);
    try expectEqual(@as(u64, 900), g.binc);
    try expectEqual(@as(?u32, 20), g.movestogo);
    try expectEqual(@as(?u32, 6), g.depth);
    try expectEqual(@as(?u64, 100000), g.nodes);
    try expectEqual(@as(?u32, 3), g.mate);
    try expectEqual(@as(?u64, 5000), g.movetime);
    try expect(g.infinite);

    const plain = (try p.parse("go")).go;
    try expect(plain.searchmoves == null and !plain.infinite and plain.depth == null);
    const sm = (try p.parse("go depth 3 searchmoves e2e4")).go;
    try expectEqualStrings("e2e4", sm.searchmoves.?);
    try expectEqual(@as(?u64, 0), (try p.parse("go wtime -50 btime 100")).go.wtime);
}

test "malformed go" {
    try expectError(error.BadGoNumber, p.parse("go depth"));
    try expectError(error.BadGoNumber, p.parse("go depth x"));
    try expectError(error.BadGoNumber, p.parse("go depth 99999999999"));
    try expectError(error.BadGoNumber, p.parse("go wtime 99999999999999999999999"));
    try expectError(error.BadGoNumber, p.parse("go movetime infinite"));
    try expectError(error.UnknownGoParameter, p.parse("go fast"));
    try expectError(error.UnknownGoParameter, p.parse("go 100"));
    try expectError(error.RepeatedGoParameter, p.parse("go depth 3 depth 4"));
    try expectError(error.RepeatedGoParameter, p.parse("go infinite infinite"));
}

test "no line makes the parser panic" {
    const words = [_][]const u8{ "go", "position", "fen", "startpos", "moves", "setoption", "name", "value", "debug", "on", "depth", "searchmoves", "wtime", "-1", "e2e4", "18446744073709551616", "infinite", "ponder", "\t", "", "x" };
    var buf: [256]u8 = undefined;
    var prng: std.Random.DefaultPrng = .init(777);
    const r = prng.random();
    var i: usize = 0;
    while (i < 100_000) : (i += 1) {
        var w: std.Io.Writer = .fixed(&buf);
        const n = r.uintLessThan(usize, 8);
        for (0..n) |_| {
            w.writeAll(words[r.uintLessThan(usize, words.len)]) catch break;
            w.writeAll(if (r.boolean()) " " else "  ") catch break;
        }
        _ = p.parse(w.buffered()) catch {};
    }
}
