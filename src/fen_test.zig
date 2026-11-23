//! Tests of FEN and UCI move parsing (src/fen.zig).

const std = @import("std");
const fen = @import("fen.zig");
const position = @import("position.zig");

const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;
const expectError = std.testing.expectError;

test "square numbering: a1 = 21, h1 = 28, a8 = 91, h8 = 98" {
    try expectEqual(@as(u8, 21), fen.parseSquare("a1").?);
    try expectEqual(@as(u8, 28), fen.parseSquare("h1").?);
    try expectEqual(@as(u8, 91), fen.parseSquare("a8").?);
    try expectEqual(@as(u8, 98), fen.parseSquare("h8").?);
    try expectEqual(@as(u8, 55), fen.parseSquare("e4").?);
    try expect(fen.parseSquare("i1") == null);
    try expect(fen.parseSquare("a9") == null);
    try expect(fen.parseSquare("a0") == null);
    try expect(fen.parseSquare("A1") == null);
    try expect(fen.parseSquare("a") == null);
    try expect(fen.parseSquare("a10") == null);
    var buf: [2]u8 = undefined;
    try std.testing.expectEqualStrings("e4", fen.squareName(55, &buf));
    var n: usize = 0;
    for (0..120) |i| {
        if (fen.onBoard(@intCast(i))) n += 1;
    }
    try expectEqual(@as(usize, 64), n);
}

test "the start position" {
    const d = try fen.parse(fen.startpos);
    try expectEqual(position.white_rook, d.board[21]);
    try expectEqual(position.white_knight, d.board[22]);
    try expectEqual(position.white_bishop, d.board[23]);
    try expectEqual(position.white_queen, d.board[24]);
    try expectEqual(position.white_king, d.board[25]);
    try expectEqual(position.white_rook, d.board[28]);
    for (31..39) |s| try expectEqual(position.white_pawn, d.board[s]);
    for (41..79) |s| {
        if (s % 10 == 0 or s % 10 == 9) {
            try expectEqual(position.border, d.board[s]);
        } else try expectEqual(position.empty, d.board[s]);
    }
    for (81..89) |s| try expectEqual(position.black_pawn, d.board[s]);
    try expectEqual(position.black_rook, d.board[91]);
    try expectEqual(position.black_queen, d.board[94]);
    try expectEqual(position.black_king, d.board[95]);
    // Border: ranks 0-1 and 10-11, files 0 and 9.
    for (0..21) |s| try expectEqual(position.border, d.board[s]);
    for (99..120) |s| try expectEqual(position.border, d.board[s]);
    try expectEqual(fen.Side.white, d.side_to_move);
    try expectEqual(fen.Castling.all, d.castling);
    try expect(d.en_passant == null);
    try expectEqual(@as(u16, 0), d.halfmove_clock);
    try expectEqual(@as(u16, 1), d.fullmove_number);
    try fen.checkConsistency(&d);
}

test "a position with en passant, partial castling and counters" {
    const d = try fen.parse("rnbqkbnr/ppp1p1pp/8/3pPp2/8/8/PPPP1PPP/RNBQKBNR w Kq f6 0 3");
    try expectEqual(@as(?u8, fen.parseSquare("f6").?), d.en_passant);
    try expect(d.castling.white_short and !d.castling.white_long and !d.castling.black_short and d.castling.black_long);
    try expectEqual(@as(u16, 3), d.fullmove_number);
    try fen.checkConsistency(&d);

    const b = try fen.parse("4k3/8/8/8/3pP3/8/8/4K3 b - e3 0 1");
    try expectEqual(fen.Side.black, b.side_to_move);
    try expectEqual(@as(?u8, 45), b.en_passant);
    try fen.checkConsistency(&b);
}

test "counters may be left out; whitespace is free" {
    const d = try fen.parse("  8/8/8/4k3/8/8/8/4K3\tb   -  - ");
    try expectEqual(fen.Side.black, d.side_to_move);
    try expectEqual(@as(u16, 0), d.halfmove_clock);
    try expectEqual(@as(u16, 1), d.fullmove_number);
    const e = try fen.parse("8/8/8/4k3/8/8/8/4K3 w - - 99 65535");
    try expectEqual(@as(u16, 99), e.halfmove_clock);
    try expectEqual(@as(u16, 65535), e.fullmove_number);
    // Castling letters in any order.
    const c = try fen.parse("r3k2r/8/8/8/8/8/8/R3K2R w qkQK - 0 1");
    try expectEqual(fen.Castling.all, c.castling);
}

test "a FEN may leave out its last fields: each missing field takes its default" {
    // Shredder and other GUIs send a FEN without the counters; any field after the
    // placement may be missing, with all that follow it.
    const full = try fen.parse("r3k2r/8/8/3pP3/8/8/8/R3K2R w Kq d6 7 30");
    const Case = struct { text: []const u8, side: fen.Side, castling: fen.Castling, ep: ?u8, clock: u16, number: u16 };
    const kq: fen.Castling = .{ .white_short = true, .black_long = true };
    const d6 = fen.parseSquare("d6").?;
    const cases = [_]Case{
        .{ .text = "r3k2r/8/8/3pP3/8/8/8/R3K2R", .side = .white, .castling = .none, .ep = null, .clock = 0, .number = 1 },
        .{ .text = "r3k2r/8/8/3pP3/8/8/8/R3K2R b", .side = .black, .castling = .none, .ep = null, .clock = 0, .number = 1 },
        .{ .text = "r3k2r/8/8/3pP3/8/8/8/R3K2R w", .side = .white, .castling = .none, .ep = null, .clock = 0, .number = 1 },
        .{ .text = "r3k2r/8/8/3pP3/8/8/8/R3K2R w Kq", .side = .white, .castling = kq, .ep = null, .clock = 0, .number = 1 },
        .{ .text = "r3k2r/8/8/3pP3/8/8/8/R3K2R w Kq d6", .side = .white, .castling = kq, .ep = d6, .clock = 0, .number = 1 },
        .{ .text = "r3k2r/8/8/3pP3/8/8/8/R3K2R w Kq d6 7", .side = .white, .castling = kq, .ep = d6, .clock = 7, .number = 1 },
        .{ .text = "r3k2r/8/8/3pP3/8/8/8/R3K2R w Kq d6 7 30", .side = .white, .castling = kq, .ep = d6, .clock = 7, .number = 30 },
        // The side letter in either case.
        .{ .text = "r3k2r/8/8/3pP3/8/8/8/R3K2R B KQkq", .side = .black, .castling = .all, .ep = null, .clock = 0, .number = 1 },
        .{ .text = "r3k2r/8/8/3pP3/8/8/8/R3K2R W -", .side = .white, .castling = .none, .ep = null, .clock = 0, .number = 1 },
    };
    for (cases) |c| {
        const d = try fen.parse(c.text);
        try expectEqual(full.board, d.board);
        try expectEqual(c.side, d.side_to_move);
        try expectEqual(c.castling, d.castling);
        try expectEqual(c.ep, d.en_passant);
        try expectEqual(c.clock, d.halfmove_clock);
        try expectEqual(c.number, d.fullmove_number);
        try fen.checkConsistency(&d);
    }
    // The defaults are the documented ones.
    try expectEqual(fen.Side.white, fen.default_side);
    try expectEqual(fen.Castling.none, fen.default_castling);
    try expectEqual(@as(u16, 0), fen.default_halfmove_clock);
    try expectEqual(@as(u16, 1), fen.default_fullmove_number);
    // A field that is present must still be well formed.
    try expectError(error.BadSideToMove, fen.parse("r3k2r/8/8/3pP3/8/8/8/R3K2R x"));
    try expectError(error.BadCastling, fen.parse("r3k2r/8/8/3pP3/8/8/8/R3K2R w X"));
    try expectError(error.BadEnPassant, fen.parse("r3k2r/8/8/3pP3/8/8/8/R3K2R w - z9"));
    try expectError(error.BadHalfmoveClock, fen.parse("r3k2r/8/8/3pP3/8/8/8/R3K2R w - - x"));
}

test "malformed FENs are rejected with the right error" {
    const cases = .{
        .{ "", error.MissingFields },
        .{ "   ", error.MissingFields },
        .{ "8/8/8/4k3/8/8/8/4K3 w - - 0 1 extra", error.TooManyFields },
        .{ "8/8/8/4k3/8/8/4K3 w - - 0 1", error.BadRankCount },
        .{ "8/8/8/4k3/8/8/8/8/4K3 w - - 0 1", error.BadRankCount },
        .{ "8/8/8/4k3/8/8/8/4K4 w - - 0 1", error.BadRankLength },
        .{ "8/8/8/4k3/8/8/8/4K2 w - - 0 1", error.BadRankLength },
        .{ "8/8/8/4k3/8/8/8/4K3/ w - - 0 1", error.BadRankCount },
        .{ "8/8/8/4k3//8/8/4K3 w - - 0 1", error.BadRankLength },
        .{ "8/8/8/4k3/8/8/8/44K w - - 0 1", error.BadRankLength },
        .{ "8/8/8/4k3/8/8/8/9 w - - 0 1", error.BadPieceLetter },
        .{ "8/8/8/4k3/8/8/8/0K7 w - - 0 1", error.BadPieceLetter },
        .{ "8/8/8/4x3/8/8/8/4K3 w - - 0 1", error.BadPieceLetter },
        .{ "8/8/8/4k3/8/8/8/4K3 x - - 0 1", error.BadSideToMove },
        .{ "8/8/8/4k3/8/8/8/4K3 white - - 0 1", error.BadSideToMove },
        .{ "8/8/8/4k3/8/8/8/4K3 w KX - 0 1", error.BadCastling },
        .{ "8/8/8/4k3/8/8/8/4K3 w HAha - 0 1", error.BadCastling },
        .{ "8/8/8/4k3/8/8/8/4K3 w -K - 0 1", error.BadCastling },
        .{ "8/8/8/4k3/8/8/8/4K3 w KK - 0 1", error.DuplicateCastling },
        .{ "8/8/8/4k3/8/8/8/4K3 w - e9 0 1", error.BadEnPassant },
        .{ "8/8/8/4k3/8/8/8/4K3 w - E6 0 1", error.BadEnPassant },
        .{ "8/8/8/4k3/8/8/8/4K3 w - e3 0 1", error.EnPassantWrongRank },
        .{ "8/8/8/4k3/8/8/8/4K3 b - e6 0 1", error.EnPassantWrongRank },
        .{ "8/8/8/4k3/8/8/8/4K3 w - - -1 1", error.BadHalfmoveClock },
        .{ "8/8/8/4k3/8/8/8/4K3 w - - x 1", error.BadHalfmoveClock },
        .{ "8/8/8/4k3/8/8/8/4K3 w - - 65536 1", error.BadHalfmoveClock },
        .{ "8/8/8/4k3/8/8/8/4K3 w - - 0 +1", error.BadFullmoveNumber },
        .{ "8/8/8/4k3/8/8/8/4K3 w - - 0 1.0", error.BadFullmoveNumber },
    };
    inline for (cases) |c| {
        try expectError(c[1], fen.parse(c[0]));
        _ = fen.fenErrorText(c[1]);
    }
}

test "inconsistent positions" {
    const cases = .{
        .{ "8/8/8/8/8/8/8/4K3 w - - 0 1", error.KingCount },
        .{ "4k3/8/8/8/8/8/8/4KK2 w - - 0 1", error.KingCount },
        .{ "4k3/8/8/8/8/8/8/4K2P w - - 0 1", error.PawnOnBackRank },
        .{ "4k2p/8/8/8/8/8/8/4K3 w - - 0 1", error.PawnOnBackRank },
        .{ "4k3/8/8/8/8/PPPPPPPP/P7/4K3 w - - 0 1", error.TooManyPieces },
        .{ "4k3/8/8/8/QQQQQQQQ/QQQQQQQQ/Q7/4K3 w - - 0 1", error.TooManyPieces },
        .{ "4k3/8/8/8/8/8/8/4K3 w K - 0 1", error.CastlingWithoutPieces },
        .{ "4k3/8/8/8/8/8/8/R3K3 w K - 0 1", error.CastlingWithoutPieces },
    };
    inline for (cases) |c| {
        const d = try fen.parse(c[0]);
        try expectError(c[1], fen.checkConsistency(&d));
        _ = fen.consistencyErrorText(c[1]);
    }
    // Black's long castling with the rook on a8 and king on e8 is consistent.
    try fen.checkConsistency(&(try fen.parse("r3k3/8/8/8/8/8/8/4K3 w q - 0 1")));
    // King off its square for Black's rights.
    try expectError(error.CastlingWithoutPieces, fen.checkConsistency(&(try fen.parse("r2k4/8/8/8/8/8/8/4K3 w q - 0 1"))));
    // En passant without the pawn, and with the passed-over square occupied.
    try expectError(error.EnPassantWithoutPawn, fen.checkConsistency(&(try fen.parse("4k3/8/8/8/8/8/8/4K3 w - e6 0 1"))));
    try expectError(error.EnPassantWithoutPawn, fen.checkConsistency(&(try fen.parse("4k3/8/4n3/4p3/8/8/8/4K3 w - e6 0 1"))));
    try expectError(error.EnPassantWithoutPawn, fen.checkConsistency(&(try fen.parse("4k3/8/8/8/8/8/4P3/4K3 b - e3 0 1"))));
}

fn expectImpossibleCheck(f: []const u8) !void {
    const d = try fen.parse(f);
    fen.checkConsistency(&d) catch |e| {
        if (e == error.ImpossibleCheck) return;
        std.debug.print("{s}: {s}, not ImpossibleCheck\n", .{ f, @errorName(e) });
        return e;
    };
    std.debug.print("{s}: accepted, not ImpossibleCheck\n", .{f});
    return error.TestExpectedError;
}

fn expectAccepted(f: []const u8) !void {
    const d = try fen.parse(f);
    fen.checkConsistency(&d) catch |e| {
        std.debug.print("{s}: {s}\n", .{ f, @errorName(e) });
        return e;
    };
}

test "a check no legal move could have given is rejected (decision 38; DEV-064)" {
    // Two pawns: the positions the stress campaign found (tools/scripts/uci_stress.py; the
    // first crashed the engine: ReleaseSafe, index 124 of 120 in leaf.zig endgameKing; the
    // second reported an illegal first move in its PV; docs/ROBUSTNESS.md, fault 1), and
    // small ones for each colour.
    for ([_][]const u8{
        "Q1b5/4q3/3PR3/2p3r1/8/8/1kp1p3/3KN2n w - - 0 1",
        "3r1q2/2p5/r1p1p3/2P5/3N2kP/5p1n/bn1pp1p1/5K2 w - - 0 1",
        "8/4R3/8/8/5kB1/3pp1p1/1Q3K2/1rN5 w - - 0 1",
        "8/4k3/3P1P2/6K1/8/P7/8/q7 b - - 0 1",
        "4k3/8/8/8/8/8/3p1p2/4K3 w - - 0 1",
        "4k3/3P1P2/8/8/8/8/8/4K3 b - - 0 1",
        // A pawn and a knight; a pawn and a rook (the rook's square is on Black's last
        // rank, so a promotion is tried too).
        "4k3/8/8/8/8/5n2/3p4/4K3 w - - 0 1",
        "4k3/3P4/5N2/8/8/8/8/4K3 b - - 0 1",
        "4k3/8/8/8/8/8/3p4/r3K3 w - - 0 1",
        // Two knights.
        "4k3/8/8/8/8/3n1n2/8/4K3 w - - 0 1",
        "4k3/8/3N1N2/8/8/8/8/4K3 b - - 0 1",
        // Three checkers: bishop, knight and rook.
        "4k3/8/8/8/1b6/5n2/8/4K2r w - - 0 1",
        // Two sliders on one line through the king: rooks either side on the 1st rank,
        // bishop and queen either side on a diagonal.
        "4k3/8/8/8/8/8/8/r3K2r w - - 0 1",
        "4k3/8/8/b7/7q/8/8/4K3 w - - 0 1",
        // A pawn on its own 2nd rank gives check: it has not moved.
        "4k3/3p4/4K3/8/8/8/8/8 w - - 0 1",
        // One knight, every square it can have come from occupied.
        "4k3/8/8/4P1P1/3P3P/5n2/3P3P/4K1N1 w - - 0 1",
        // One rook, boxed in: its only empty square, e2, is also on the line, and no man
        // can have left e2.
        "4k3/8/8/8/4P3/3PrP2/8/4K3 w - - 0 1",
        // The FEN says the last move was d7-d5, but the rook's check was there before it.
        "4r2k/8/8/3p4/4K3/8/8/8 w - d6 0 1",
        // Castling would explain the rook's check, but Black's king was in check on e8
        // (from e4) and could not castle; and with a bishop on h6 it would have crossed
        // f8, an attacked square. The brute-force judge found 31 such positions in 150,000
        // random ones (tools/research/fen/impossible_check.py).
        "1K3rk1/3p1N2/8/8/4R3/5R2/3NR3/8 w - - 0 1",
        "1K3rk1/5p2/7B/8/8/8/8/8 w - - 0 1",
    }) |f| try expectImpossibleCheck(f);
    _ = fen.consistencyErrorText(error.ImpossibleCheck);
}

test "a check a legal move can have given is accepted (decision 38)" {
    for ([_][]const u8{
        // Double check by rook and bishop: the bishop left e7 for b4.
        "4r2k/8/8/8/1b6/8/8/4K3 w - - 0 1",
        // Two rooks: d7xc8=R, the pawn leaving d7 uncovering the rook on d1.
        "2Rk4/8/8/8/8/8/8/3R3K b - - 0 1",
        // A knight promotion gives check; b7, c6 and e6 are Black's, so only d7-d8=N
        // explains it.
        "3N4/1p3k2/2p1p3/8/8/8/8/7K b - - 0 1",
        // Castling gives check (also explained by Re1-f1), and a check only castling
        // explains: the rook on f8 cannot have come from f7 or e8, and nothing left c8-e8.
        "5k2/8/8/8/8/8/8/5RK1 b - - 0 1",
        "1K3rk1/5p2/8/8/8/8/8/8 w - - 0 1",
        // En passant: exd6 e.p. with double check (pawn and rook), and a check only en
        // passant explains (the Black pawn taken on d5 blocked the bishop).
        "8/4k3/3P4/8/8/8/8/4R2K b - - 0 1",
        "8/8/3Pk3/8/P7/1B6/2P5/7K b - - 0 1",
        // Pawn and rook without an en-passant square: ...e6xd5 uncovered the rook. A double
        // step that gives check, with its en-passant square.
        "4r2k/8/8/3p4/4K3/8/8/8 w - - 0 1",
        "7k/8/8/3p4/4K3/8/8/8 w - d6 0 1",
        // One pawn's check (also with the king on the edge, the pawn's other square the
        // border), and two pawns attacking the king of the side not to move (Setup mode's
        // own refusal, not this one).
        "4k3/8/8/8/8/8/3p4/4K3 w - - 0 1",
        "k7/8/8/8/8/8/1p6/K7 w - - 0 1",
        "7k/8/8/8/8/8/6p1/7K w - - 0 1",
        "4k3/3P1P2/8/8/8/8/8/4K3 w - - 0 1",
        "4k3/8/8/8/8/8/3p1p2/4K3 b - - 0 1",
        "K7/1P6/8/8/8/8/8/7k b - - 0 1",
    }) |f| try expectAccepted(f);
}

test "every position of tests/golden/fen/reachable_checks.txt is accepted" {
    // 5,000 positions with the side to move in check after a legal move, from random play
    // and constructed (tools/research/fen/impossible_check.py; every rare kind 250 times or
    // more: double checks, castling, en passant, each promotion with and without a capture,
    // a double step with its en-passant square, discovered checks by a king move).
    const gpa = std.testing.allocator;
    const path = @import("build_options").golden_dir ++ "/fen/reachable_checks.txt";
    const text = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, gpa, .limited(1 << 20));
    defer gpa.free(text);
    var lines = std.mem.tokenizeAny(u8, text, "\r\n");
    var n: usize = 0;
    while (lines.next()) |line| : (n += 1) try expectAccepted(line);
    try expectEqual(@as(usize, 5000), n);
}

test "UCI moves" {
    const m = try fen.parseMove("e2e4");
    try expectEqual(@as(u8, 35), m.from);
    try expectEqual(@as(u8, 55), m.to);
    try expectEqual(@as(u8, 0), m.promotion);
    const q = try fen.parseMove("e7e8q");
    try expectEqual(@as(u8, 85), q.from);
    try expectEqual(@as(u8, 95), q.to);
    try expectEqual(position.white_queen, q.promotion);
    try expectEqual(position.white_knight, (try fen.parseMove("a2b1n")).promotion);
    try expectEqual(position.white_bishop, (try fen.parseMove("h7g8b")).promotion);
    try expectEqual(position.white_rook, (try fen.parseMove("h2h1r")).promotion);
    // Castling is the king's two-square move.
    const c = try fen.parseMove("e1g1");
    try expectEqual(@as(u8, 25), c.from);
    try expectEqual(@as(u8, 27), c.to);

    var buf: [5]u8 = undefined;
    try std.testing.expectEqualStrings("e7e8q", fen.formatMove(q, &buf));
    try std.testing.expectEqualStrings("e2e4", fen.formatMove(m, &buf));
    try std.testing.expectEqualStrings("a2b1n", fen.formatMove(try fen.parseMove("a2b1n"), &buf));
    try std.testing.expectEqualStrings("0000", fen.formatMove(.{ .from = 0, .to = 120 }, &buf));
}

test "malformed UCI moves" {
    const cases = .{
        .{ "", error.BadMoveLength },
        .{ "e2", error.BadMoveLength },
        .{ "e2e4qq", error.BadMoveLength },
        .{ "0000", error.NullMove },
        .{ "e2e9", error.BadMoveSquare },
        .{ "i2e4", error.BadMoveSquare },
        .{ "E2E4", error.BadMoveSquare },
        .{ "e2e2", error.SameSquare },
        .{ "e7e8k", error.BadPromotionPiece },
        .{ "e7e8Q", error.BadPromotionPiece },
        .{ "e7e8p", error.BadPromotionPiece },
        .{ "e2e4q", error.BadPromotionRank },
        .{ "e6e7q", error.BadPromotionRank },
        .{ "e7e8\x00", error.BadPromotionPiece },
        .{ "a7h8q", error.BadPromotionRank },
        .{ "a2a1x", error.BadPromotionPiece },
    };
    inline for (cases) |c| {
        try expectError(c[1], fen.parseMove(c[0]));
        _ = fen.moveErrorText(c[1]);
    }
    // e2e1q is a legal shape for Black (2nd rank to 1st): only the rank pair matters.
    _ = try fen.parseMove("d2e1q");
}

test "no input makes the parsers panic" {
    // Every string of up to 3 bytes over a small alphabet, and random longer ones.
    const alphabet = "pnbrqkPNBRQK12345678/ -wabcdefgh0\t\xff";
    var buf: [96]u8 = undefined;
    var prng: std.Random.DefaultPrng = .init(12345);
    const r = prng.random();
    var i: usize = 0;
    while (i < 200_000) : (i += 1) {
        const len = r.uintLessThan(usize, buf.len);
        for (buf[0..len]) |*b| b.* = if (r.boolean()) alphabet[r.uintLessThan(usize, alphabet.len)] else r.int(u8);
        const t = buf[0..len];
        if (fen.parse(t)) |d| {
            fen.checkConsistency(&d) catch {};
        } else |_| {}
        _ = fen.parseMove(t[0..@min(t.len, 5)]) catch {};
    }
    // Mutations of a valid FEN: one byte changed at every position.
    const base = "r3k2r/pppq1ppp/2n2n2/3pp3/3PP3/2N2N2/PPPQ1PPP/R3K2R b KQkq d3 4 9";
    for (0..base.len) |pos| {
        for (alphabet) |ch| {
            var m: [base.len]u8 = base.*;
            m[pos] = ch;
            if (fen.parse(&m)) |d| {
                fen.checkConsistency(&d) catch {};
            } else |_| {}
        }
    }
}
