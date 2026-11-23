//! FEN and UCI move text, parsed into plain descriptions in the project's square
//! numbering (AGENTS.md §10.4, §12 "Errors").
//!
//! This is platform adaptation (class F): the original was set up from its own
//! keyboard editor. The output of `parse` is a plain description of a position. It
//! is not the search state: the port of the original's set-up code (`setup.zig`)
//! takes a `Description` as its input and builds `position.Position` the way the
//! original does.
//!
//! Squares are 10x12 mailbox indices, as in `position.zig`: a1 = 21, h1 = 28,
//! a8 = 91, h8 = 98. Piece codes: 0 empty, 7 border; White pawn 1, knight 2,
//! bishop 3, rook 4, queen 5, king 6; Black 8..13 in the same order.
//!
//! Every function here returns an error for malformed input and never panics,
//! whatever bytes it is given.

const std = @import("std");
const position = @import("position.zig");

pub const Side = position.Side;

/// The FEN of the standard starting position.
pub const startpos = "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1";

/// Mailbox index of a square from its file (0 = a .. 7 = h) and rank (0 = 1st .. 7 = 8th).
pub fn square(file: u8, rank: u8) u8 {
    std.debug.assert(file < 8 and rank < 8);
    return 21 + file + 10 * rank;
}

/// File (0 = a .. 7 = h) of an on-board mailbox square.
pub fn fileOf(sq: u8) u8 {
    return (sq - 21) % 10;
}

/// Rank (0 = 1st .. 7 = 8th) of an on-board mailbox square.
pub fn rankOf(sq: u8) u8 {
    return (sq - 21) / 10;
}

/// Whether a mailbox index is one of the 64 squares of the board.
pub fn onBoard(sq: u8) bool {
    if (sq < 21 or sq > 98) return false;
    const f = sq % 10;
    return f >= 1 and f <= 8;
}

/// The castling rights of a FEN.
pub const Castling = struct {
    white_short: bool = false,
    white_long: bool = false,
    black_short: bool = false,
    black_long: bool = false,

    pub const none: Castling = .{};
    pub const all: Castling = .{ .white_short = true, .white_long = true, .black_short = true, .black_long = true };
};

/// A position as a FEN describes it.
pub const Description = struct {
    /// 10x12 mailbox of piece codes; the 56 border squares hold 7 (`position.border`).
    board: [120]u8,
    side_to_move: Side,
    castling: Castling,
    /// The square passed over by the last move's double pawn step, or null.
    en_passant: ?u8,
    /// Half-moves since the last capture or pawn move.
    halfmove_clock: u16,
    /// Full-move number as given (FEN starts at 1; 0 is accepted as written).
    fullmove_number: u16,
};

/// An empty board: 7 on the border, 0 on the 64 squares.
pub fn emptyBoard() [120]u8 {
    var b: [120]u8 = @splat(position.border);
    for (0..8) |rank| for (0..8) |file| {
        b[square(@intCast(file), @intCast(rank))] = position.empty;
    };
    return b;
}

/// Why a FEN was not accepted.
pub const FenError = error{
    /// No fields at all: the placement is the one field a FEN must have.
    MissingFields,
    /// More than six fields.
    TooManyFields,
    /// The placement does not have exactly 8 ranks separated by '/'.
    BadRankCount,
    /// A rank of the placement does not describe exactly 8 squares.
    BadRankLength,
    /// A character in the placement that is not a piece letter, a digit 1..8 or '/'.
    BadPieceLetter,
    /// The side to move is not "w" or "b".
    BadSideToMove,
    /// The castling field is not "-" or a non-empty set of the letters K, Q, k, q.
    BadCastling,
    /// A castling letter appears twice.
    DuplicateCastling,
    /// The en-passant field is not "-" or a square name.
    BadEnPassant,
    /// The en-passant square is not on the 6th rank with White to move, or on the
    /// 3rd rank with Black to move.
    EnPassantWrongRank,
    /// The halfmove clock is not a decimal number 0..65535.
    BadHalfmoveClock,
    /// The fullmove number is not a decimal number 0..65535.
    BadFullmoveNumber,
};

/// Text for a rejection message.
pub fn fenErrorText(err: FenError) []const u8 {
    return switch (err) {
        error.MissingFields => "FEN is empty",
        error.TooManyFields => "FEN has more than 6 fields",
        error.BadRankCount => "FEN placement does not have 8 ranks",
        error.BadRankLength => "a rank of the FEN placement does not have 8 squares",
        error.BadPieceLetter => "FEN placement has a character that is not a piece, a digit 1-8 or '/'",
        error.BadSideToMove => "FEN side to move is not 'w' or 'b'",
        error.BadCastling => "FEN castling field is not '-' or letters from KQkq",
        error.DuplicateCastling => "FEN castling field repeats a letter",
        error.BadEnPassant => "FEN en-passant field is not '-' or a square",
        error.EnPassantWrongRank => "FEN en-passant square is not on the 6th rank (White to move) or the 3rd (Black to move)",
        error.BadHalfmoveClock => "FEN halfmove clock is not a number 0-65535",
        error.BadFullmoveNumber => "FEN fullmove number is not a number 0-65535",
    };
}

/// Piece code of a FEN letter, or null.
pub fn pieceFromLetter(c: u8) ?u8 {
    return switch (c) {
        'P' => position.white_pawn,
        'N' => position.white_knight,
        'B' => position.white_bishop,
        'R' => position.white_rook,
        'Q' => position.white_queen,
        'K' => position.white_king,
        'p' => position.black_pawn,
        'n' => position.black_knight,
        'b' => position.black_bishop,
        'r' => position.black_rook,
        'q' => position.black_queen,
        'k' => position.black_king,
        else => null,
    };
}

/// FEN letter of a piece code, or null for empty, border and unused codes.
pub fn letterFromPiece(p: u8) ?u8 {
    return switch (p) {
        1...6 => "PNBRQK"[p - 1],
        8...13 => "pnbrqk"[p - 8],
        else => null,
    };
}

/// What a field a FEN leaves out is taken to be: White to move, no castling rights, no
/// en-passant square, a halfmove clock of 0 and move number 1.
pub const default_side: Side = .white;
pub const default_castling: Castling = .none;
pub const default_halfmove_clock: u16 = 0;
pub const default_fullmove_number: u16 = 1;

/// Parses a FEN. Only the placement is required. Some GUIs send a FEN without its last
/// fields (Shredder leaves out the counters), so each later field may be missing, with
/// every field after it: the fields are read in order and a missing one takes its
/// default above, as the owner's engine Juggernaut reads a FEN (owner, 2026-11-19).
/// Fields are separated by spaces or tabs. A field that is present must be well formed.
pub fn parse(text: []const u8) FenError!Description {
    var fields: [6][]const u8 = undefined;
    var n: usize = 0;
    var it = std.mem.tokenizeAny(u8, text, " \t\r\n");
    while (it.next()) |t| {
        if (n == fields.len) return error.TooManyFields;
        fields[n] = t;
        n += 1;
    }
    if (n == 0) return error.MissingFields;

    var d: Description = .{
        .board = emptyBoard(),
        .side_to_move = default_side,
        .castling = default_castling,
        .en_passant = null,
        .halfmove_clock = default_halfmove_clock,
        .fullmove_number = default_fullmove_number,
    };

    // Placement, from the 8th rank down.
    var rank: u8 = 7;
    var file: u8 = 0;
    for (fields[0]) |c| {
        if (c == '/') {
            if (file != 8) return error.BadRankLength;
            if (rank == 0) return error.BadRankCount;
            rank -= 1;
            file = 0;
        } else if (c >= '1' and c <= '8') {
            file += c - '0';
            if (file > 8) return error.BadRankLength;
        } else if (pieceFromLetter(c)) |p| {
            if (file >= 8) return error.BadRankLength;
            d.board[square(file, rank)] = p;
            file += 1;
        } else return error.BadPieceLetter;
    }
    if (rank != 0) return error.BadRankCount;
    if (file != 8) return error.BadRankLength;

    // Side to move ("W" and "B" are taken too).
    if (n < 2) return d;
    if (std.ascii.eqlIgnoreCase(fields[1], "w")) {
        d.side_to_move = .white;
    } else if (std.ascii.eqlIgnoreCase(fields[1], "b")) {
        d.side_to_move = .black;
    } else return error.BadSideToMove;

    // Castling: "-" or K, Q, k, q in any order, each at most once.
    if (n < 3) return d;
    if (!std.mem.eql(u8, fields[2], "-")) {
        for (fields[2]) |c| {
            const right: *bool = switch (c) {
                'K' => &d.castling.white_short,
                'Q' => &d.castling.white_long,
                'k' => &d.castling.black_short,
                'q' => &d.castling.black_long,
                else => return error.BadCastling,
            };
            if (right.*) return error.DuplicateCastling;
            right.* = true;
        }
    }

    // En passant.
    if (n < 4) return d;
    if (!std.mem.eql(u8, fields[3], "-")) {
        const sq = parseSquare(fields[3]) orelse return error.BadEnPassant;
        const want_rank: u8 = if (d.side_to_move == .white) 5 else 2;
        if (rankOf(sq) != want_rank) return error.EnPassantWrongRank;
        d.en_passant = sq;
    }

    // The counters, each on its own: a clock without a move number is taken.
    if (n < 5) return d;
    d.halfmove_clock = parseCounter(fields[4]) orelse return error.BadHalfmoveClock;
    if (n < 6) return d;
    d.fullmove_number = parseCounter(fields[5]) orelse return error.BadFullmoveNumber;
    return d;
}

/// A decimal number 0..65535 made of digits only (no sign).
fn parseCounter(t: []const u8) ?u16 {
    if (t.len == 0 or t.len > 5) return null;
    for (t) |c| if (c < '0' or c > '9') return null;
    return std.fmt.parseInt(u16, t, 10) catch null;
}

/// Mailbox index of a square name such as "e4" (lower-case file), or null.
pub fn parseSquare(t: []const u8) ?u8 {
    if (t.len != 2) return null;
    if (t[0] < 'a' or t[0] > 'h') return null;
    if (t[1] < '1' or t[1] > '8') return null;
    return square(t[0] - 'a', t[1] - '1');
}

/// Writes the name of an on-board square ("e4") into `buf`.
pub fn squareName(sq: u8, buf: *[2]u8) []const u8 {
    buf[0] = 'a' + fileOf(sq);
    buf[1] = '1' + rankOf(sq);
    return buf;
}

// ---------------------------------------------------------------------------
// Consistency of a description
// ---------------------------------------------------------------------------

/// Why a well-formed FEN describes a position that cannot be set up. These are
/// facts about any chess position; whether the original accepts a position that
/// passes them is decided by the port of its set-up code.
pub const ConsistencyError = error{
    /// A side does not have exactly one king.
    KingCount,
    /// A pawn on the 1st or 8th rank.
    PawnOnBackRank,
    /// A side has more than 16 pieces or more than 8 pawns.
    TooManyPieces,
    /// A castling right whose king and rook are not on their original squares.
    CastlingWithoutPieces,
    /// An en-passant square without the pawn that made the double step in front of
    /// it, or with the square or the one behind it occupied.
    EnPassantWithoutPawn,
    /// The side to move is in check in a way no legal last move could have given: no
    /// single move of the other side can be taken back so that, before it, the side to
    /// move was not in check (`checkExplained`). No game reaches such a position. Two
    /// pawns' check is one (DEV-064), and the original's search cannot take it: its root
    /// plays moves that leave the other pawn's check (an illegal first move in `info ...
    /// pv`), and in about one such position in twelve the evaluation then reads the
    /// board at a king square that is off the board (a crash: docs/ROBUSTNESS.md, fault
    /// 1). The owner's decision 38 widened the rule to every such check. Class E
    /// (AGENTS.md section 9.1): rejected with a reason.
    ImpossibleCheck,
};

pub fn consistencyErrorText(err: ConsistencyError) []const u8 {
    return switch (err) {
        error.KingCount => "a side does not have exactly one king",
        error.PawnOnBackRank => "a pawn stands on the 1st or 8th rank",
        error.TooManyPieces => "a side has more than 16 pieces or more than 8 pawns",
        error.CastlingWithoutPieces => "a castling right without its king and rook on their original squares",
        error.EnPassantWithoutPawn => "the en-passant square does not follow a double pawn step",
        error.ImpossibleCheck => "the side to move is in check in a way no legal move could have given",
    };
}

/// Checks a parsed description for the facts listed in `ConsistencyError`.
pub fn checkConsistency(d: *const Description) ConsistencyError!void {
    var kings: [2]u8 = .{ 0, 0 };
    var pieces: [2]u8 = .{ 0, 0 };
    var pawns: [2]u8 = .{ 0, 0 };
    for (0..8) |r| for (0..8) |f| {
        const rank: u8 = @intCast(r);
        const p = d.board[square(@intCast(f), rank)];
        if (p == position.empty) continue;
        const side: usize = if (p >= position.black_pawn) 1 else 0;
        pieces[side] += 1;
        if (p == position.white_king or p == position.black_king) kings[side] += 1;
        if (p == position.white_pawn or p == position.black_pawn) {
            if (rank == 0 or rank == 7) return error.PawnOnBackRank;
            pawns[side] += 1;
        }
    };
    if (kings[0] != 1 or kings[1] != 1) return error.KingCount;
    if (pieces[0] > 16 or pieces[1] > 16 or pawns[0] > 8 or pawns[1] > 8) return error.TooManyPieces;

    const b = &d.board;
    const c = d.castling;
    if ((c.white_short or c.white_long) and b[25] != position.white_king) return error.CastlingWithoutPieces;
    if (c.white_short and b[28] != position.white_rook) return error.CastlingWithoutPieces;
    if (c.white_long and b[21] != position.white_rook) return error.CastlingWithoutPieces;
    if ((c.black_short or c.black_long) and b[95] != position.black_king) return error.CastlingWithoutPieces;
    if (c.black_short and b[98] != position.black_rook) return error.CastlingWithoutPieces;
    if (c.black_long and b[91] != position.black_rook) return error.CastlingWithoutPieces;

    if (d.en_passant) |ep| {
        // White to move: Black's pawn went from ep + 10 to ep - 10. Black to move:
        // White's pawn went from ep - 10 to ep + 10.
        const ok = if (d.side_to_move == .white)
            b[ep - 10] == position.black_pawn and b[ep] == position.empty and b[ep + 10] == position.empty
        else
            b[ep + 10] == position.white_pawn and b[ep] == position.empty and b[ep - 10] == position.empty;
        if (!ok) return error.EnPassantWithoutPawn;
    }

    if (!checkExplained(d)) return error.ImpossibleCheck;
}

// ---------------------------------------------------------------------------
// A check that no last move explains (owner's decision 38, DEV-064)
// ---------------------------------------------------------------------------

const knight_steps = [8]i8{ -21, -19, -12, -8, 8, 12, 19, 21 };
const king_steps = [8]i8{ -11, -10, -9, -1, 1, 9, 10, 11 };
const diagonal_steps = [4]i8{ -11, -9, 9, 11 };
const straight_steps = [4]i8{ -10, -1, 1, 10 };

/// The square `step` away. Every on-board square is at least 21 from either end of
/// the mailbox, so one step of up to 21 stays inside it.
fn stepFrom(sq: u8, step: i8) u8 {
    return @intCast(@as(i16, sq) + step);
}

/// The piece code of a man of the given colour: 1 pawn .. 6 king.
fn man(white: bool, kind: u8) u8 {
    return if (white) kind else kind + (position.black_pawn - position.white_pawn);
}

fn isMan(p: u8) bool {
    return p != position.empty and p != position.border;
}

fn isWhite(p: u8) bool {
    return p >= position.white_pawn and p <= position.white_king;
}

/// The first square from `sq` along `step` that is not empty: its piece code, or the
/// border's.
fn firstMan(b: *const [120]u8, sq: u8, step: i8) u8 {
    var s = stepFrom(sq, step);
    while (b[s] == position.empty) s = stepFrom(s, step);
    return b[s];
}

/// Whether a man of the given colour attacks `sq` on board `b`.
fn attackedBy(b: *const [120]u8, sq: u8, white: bool) bool {
    // A White pawn attacks from sq - 9 and sq - 11, a Black one from sq + 9 and sq + 11.
    const pawn_steps: [2]i8 = if (white) .{ -9, -11 } else .{ 9, 11 };
    for (pawn_steps) |s| if (b[stepFrom(sq, s)] == man(white, 1)) return true;
    for (knight_steps) |s| if (b[stepFrom(sq, s)] == man(white, 2)) return true;
    for (king_steps) |s| if (b[stepFrom(sq, s)] == man(white, 6)) return true;
    for (diagonal_steps) |s| {
        const p = firstMan(b, sq, s);
        if (p == man(white, 3) or p == man(white, 5)) return true;
    }
    for (straight_steps) |s| {
        const p = firstMan(b, sq, s);
        if (p == man(white, 4) or p == man(white, 5)) return true;
    }
    return false;
}

/// One square of the board before a move: the square and what stood on it.
const Square = struct { sq: u8, piece: u8 };

/// Whether the king on `k` is safe from the men of colour `o_white` on board `b` with
/// the squares of `before` set back as they were before a move.
fn safeBefore(b: *const [120]u8, k: u8, o_white: bool, before: []const Square) bool {
    var board = b.*;
    for (before) |s| board[s.sq] = s.piece;
    return !attackedBy(&board, k, o_white);
}

/// Whether the side to move's check, if it is in check, can have been given by a legal
/// last move: some single move of the other side can be taken back so that, before it,
/// the side to move's king was attacked by no man of the other side. (It was the other
/// side's turn then, so the side to move cannot have been in check.) Nothing else about
/// the earlier position is asked: not that it can be reached, nor that the other side's
/// king was safe, nor that the material allows the man taken back to have been there.
/// Each such demand made wrongly would refuse a position a game can reach.
///
/// The moves taken back, every one of them for every man of the other side:
/// - a knight, bishop, rook, queen or king back along its own movement to an empty
///   square (sliders over empty squares), leaving on its square a man of the side to
///   move that it took. A quiet move leaves the square empty instead, but a man there
///   only blocks lines, so the capture is safe whenever the quiet move is, and it is
///   the one tried;
/// - a pawn back one square, or two from its 4th rank with the square between empty,
///   leaving its square empty; or back diagonally, leaving a man it took. Not from its
///   2nd rank;
/// - a promotion: a knight, bishop, rook or queen on its last rank becomes a pawn
///   straight behind it (the square left empty) or diagonally behind (a man taken);
/// - an en-passant capture: a pawn on its 6th rank goes back diagonally to its 5th, its
///   square left empty, and the pawn it took comes back on the square behind it;
/// - castling: the king on g or c and its rook beside it on f or d go back to their
///   original squares, the squares between empty, the king then not in check and the
///   square it crossed not attacked (whether the FEN still grants the right is not
///   asked).
/// A FEN's en-passant square says what the last move was: that pawn's double step, the
/// only move taken back then.
fn checkExplained(d: *const Description) bool {
    const b = &d.board;
    const s_white = d.side_to_move == .white;
    const o_white = !s_white;
    const k = for (21..99) |s| {
        if (b[s] == man(s_white, 6)) break @as(u8, @intCast(s));
    } else unreachable; // one king per side, checked before this is called
    if (!attackedBy(b, k, o_white)) return true;

    const empty = position.empty;
    const up: i8 = if (o_white) 10 else -10; // the other side's pawns' step forward
    const o_pawn = man(o_white, 1);
    // A man of the side to move, standing where it was taken. Which one does not
    // matter: it only blocks lines, and it is the other side's men that give check.
    const taken = man(s_white, 2);

    if (d.en_passant) |ep| {
        // The other side's pawn passed over ep: it stands on ep + up, from ep - up.
        return safeBefore(b, k, o_white, &.{ .{ .sq = stepFrom(ep, up), .piece = empty }, .{ .sq = stepFrom(ep, -up), .piece = o_pawn } });
    }

    for (21..99) |i| {
        const t: u8 = @intCast(i);
        const p = b[t];
        if (!isMan(p) or isWhite(p) != o_white) continue;
        const kind = if (o_white) p else p - (position.black_pawn - position.white_pawn);
        // The rank from the other side's end: 0 its 1st rank .. 7 its last.
        const rank = if (o_white) rankOf(t) else 7 - rankOf(t);
        const behind = stepFrom(t, -up);
        if (kind == 1) {
            if (rank < 2) continue; // a pawn on its 2nd rank has not moved
            if (b[behind] == empty) {
                if (safeBefore(b, k, o_white, &.{ .{ .sq = t, .piece = empty }, .{ .sq = behind, .piece = o_pawn } })) return true;
                const start = stepFrom(behind, -up);
                if (rank == 3 and b[start] == empty and
                    safeBefore(b, k, o_white, &.{ .{ .sq = t, .piece = empty }, .{ .sq = start, .piece = o_pawn } })) return true;
            }
            for ([2]i8{ -1, 1 }) |side| {
                const s = stepFrom(behind, side);
                if (b[s] != empty) continue;
                if (safeBefore(b, k, o_white, &.{ .{ .sq = t, .piece = taken }, .{ .sq = s, .piece = o_pawn } })) return true;
                // En passant: the pawn taken stood behind t.
                if (rank == 5 and b[behind] == empty and
                    safeBefore(b, k, o_white, &.{ .{ .sq = t, .piece = empty }, .{ .sq = s, .piece = o_pawn }, .{ .sq = behind, .piece = man(s_white, 1) } })) return true;
            }
            continue;
        }
        const steps: []const i8 = switch (kind) {
            2 => &knight_steps,
            3 => &diagonal_steps,
            4 => &straight_steps,
            else => &king_steps, // queen and king: all eight directions
        };
        const slides = kind == 3 or kind == 4 or kind == 5;
        for (steps) |step| {
            var s = stepFrom(t, step);
            while (b[s] == empty) : (s = stepFrom(s, step)) {
                if (safeBefore(b, k, o_white, &.{ .{ .sq = t, .piece = taken }, .{ .sq = s, .piece = p } })) return true;
                if (!slides) break;
            }
        }
        if (kind != 6 and rank == 7) {
            // A promotion: the pawn came from straight behind or took diagonally.
            if (b[behind] == empty and
                safeBefore(b, k, o_white, &.{ .{ .sq = t, .piece = empty }, .{ .sq = behind, .piece = o_pawn } })) return true;
            for ([2]i8{ -1, 1 }) |side| {
                const s = stepFrom(behind, side);
                if (b[s] == empty and
                    safeBefore(b, k, o_white, &.{ .{ .sq = t, .piece = taken }, .{ .sq = s, .piece = o_pawn } })) return true;
            }
        }
    }

    // Castling, short and long: the king's and the rook's squares after it and the
    // rook's before it, as files. a1 (a8) is `row`, the king's original square row + 4.
    const row: u8 = if (o_white) 21 else 91;
    const o_king = man(o_white, 6);
    const o_rook = man(o_white, 4);
    for ([2][3]u8{ .{ 6, 5, 7 }, .{ 2, 3, 0 } }) |c| {
        const king_to = row + c[0];
        const rook_to = row + c[1];
        const rook_from = row + c[2];
        if (b[king_to] != o_king or b[rook_to] != o_rook or b[row + 4] != empty or b[rook_from] != empty) continue;
        if (rook_from == row and b[row + 1] != empty) continue; // b1 (b8) between the rook and the king
        var before = b.*;
        before[king_to] = empty;
        before[rook_to] = empty;
        before[row + 4] = o_king;
        before[rook_from] = o_rook;
        // The king was not in check and did not cross an attacked square (the rook's
        // square after castling); the square it lands on is the position's own.
        if (!attackedBy(&before, k, o_white) and !attackedBy(&before, row + 4, s_white) and
            !attackedBy(&before, rook_to, s_white)) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// UCI moves
// ---------------------------------------------------------------------------

/// A move in UCI long algebraic notation, in mailbox squares.
pub const UciMove = struct {
    from: u8,
    to: u8,
    /// 0 for none; otherwise the promoted piece as a White code, 2 knight ..
    /// 5 queen (the convention of the move's flag byte in `position.zig`).
    promotion: u8 = 0,

    pub fn eql(a: UciMove, b: UciMove) bool {
        return a.from == b.from and a.to == b.to and a.promotion == b.promotion;
    }
};

/// Why a move string was not accepted.
pub const MoveError = error{
    /// Not 4 or 5 characters.
    BadMoveLength,
    /// The from or to square is not a square name.
    BadMoveSquare,
    /// "0000", the null move, where a move is required.
    NullMove,
    /// From and to are the same square.
    SameSquare,
    /// A fifth character that is not n, b, r or q.
    BadPromotionPiece,
    /// A promotion that is not from the 7th to the 8th rank or from the 2nd to
    /// the 1st.
    BadPromotionRank,
};

pub fn moveErrorText(err: MoveError) []const u8 {
    return switch (err) {
        error.BadMoveLength => "move is not 4 or 5 characters",
        error.BadMoveSquare => "move has a square that is not a1..h8",
        error.NullMove => "null move 0000",
        error.SameSquare => "move from a square to itself",
        error.BadPromotionPiece => "promotion piece is not n, b, r or q",
        error.BadPromotionRank => "promotion is not from the 7th rank to the 8th or the 2nd to the 1st",
    };
}

/// Parses a UCI move such as "e2e4" or "e7e8q" (lower case, as UCI writes them).
/// Whether the move is legal is not checked here.
pub fn parseMove(t: []const u8) MoveError!UciMove {
    if (t.len != 4 and t.len != 5) return error.BadMoveLength;
    if (std.mem.eql(u8, t, "0000")) return error.NullMove;
    const from = parseSquare(t[0..2]) orelse return error.BadMoveSquare;
    const to = parseSquare(t[2..4]) orelse return error.BadMoveSquare;
    if (from == to) return error.SameSquare;
    var m: UciMove = .{ .from = from, .to = to };
    if (t.len == 5) {
        m.promotion = switch (t[4]) {
            'n' => position.white_knight,
            'b' => position.white_bishop,
            'r' => position.white_rook,
            'q' => position.white_queen,
            else => return error.BadPromotionPiece,
        };
        const white_promotion = rankOf(from) == 6 and rankOf(to) == 7;
        const black_promotion = rankOf(from) == 1 and rankOf(to) == 0;
        if (!white_promotion and !black_promotion) return error.BadPromotionRank;
        if (fileDistance(from, to) > 1) return error.BadPromotionRank;
    }
    return m;
}

fn fileDistance(a: u8, b: u8) u8 {
    const fa = fileOf(a);
    const fb = fileOf(b);
    return if (fa > fb) fa - fb else fb - fa;
}

/// Writes a move in UCI notation into `buf` and returns the text.
pub fn formatMove(m: UciMove, buf: *[5]u8) []const u8 {
    if (!onBoard(m.from) or !onBoard(m.to)) {
        @memcpy(buf[0..4], "0000");
        return buf[0..4];
    }
    _ = squareName(m.from, buf[0..2]);
    _ = squareName(m.to, buf[2..4]);
    if (m.promotion >= position.white_knight and m.promotion <= position.white_queen) {
        buf[4] = "nbrq"[m.promotion - position.white_knight];
        return buf[0..5];
    }
    return buf[0..4];
}
