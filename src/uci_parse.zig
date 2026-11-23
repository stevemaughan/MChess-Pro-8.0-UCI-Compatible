//! Parsing of UCI command lines (AGENTS.md §10.4). No allocation: strings and move
//! lists are returned as slices of the input line. Parsing never panics; a line
//! that is not well formed gives an error naming what is wrong.
//!
//! Adapted from the UCI layer of Cyrus IS Chess (same owner, MIT licence).

const std = @import("std");

pub const Go = struct {
    /// Text of the `searchmoves` list (space-separated moves), or null.
    searchmoves: ?[]const u8 = null,
    ponder: bool = false,
    wtime: ?u64 = null,
    btime: ?u64 = null,
    winc: u64 = 0,
    binc: u64 = 0,
    movestogo: ?u32 = null,
    depth: ?u32 = null,
    nodes: ?u64 = null,
    mate: ?u32 = null,
    movetime: ?u64 = null,
    infinite: bool = false,
};

pub const Position = struct {
    /// FEN text (the fields between `fen` and `moves`), or null for `startpos`.
    fen: ?[]const u8,
    /// Text after `moves` (space-separated UCI moves), possibly empty.
    moves: []const u8,
};

pub const SetOption = struct {
    name: []const u8,
    value: ?[]const u8,
};

pub const Command = union(enum) {
    uci,
    isready,
    ucinewgame,
    quit,
    stop,
    ponderhit,
    debug: bool,
    setoption: SetOption,
    position: Position,
    go: Go,
    /// Empty line or unknown command (ignored, as UCI requires).
    unknown,
};

pub const ParseError = error{
    /// `debug` not followed by `on` or `off`.
    BadDebug,
    /// `setoption` not followed by `name <id>`.
    BadSetOption,
    /// `position` not followed by `startpos` or `fen <fields>`, or other words
    /// where `moves` belongs.
    BadPosition,
    /// A `go` parameter that is not one of UCI's.
    UnknownGoParameter,
    /// A `go` parameter given twice.
    RepeatedGoParameter,
    /// A `go` parameter without its number, or with something that is not one.
    BadGoNumber,
};

pub fn parseErrorText(err: ParseError) []const u8 {
    return switch (err) {
        error.BadDebug => "debug takes 'on' or 'off'",
        error.BadSetOption => "setoption needs 'name <id> [value <x>]'",
        error.BadPosition => "position needs 'startpos' or 'fen <fen>', then optionally 'moves ...'",
        error.UnknownGoParameter => "unknown go parameter",
        error.RepeatedGoParameter => "go parameter given twice",
        error.BadGoNumber => "go parameter without a valid number",
    };
}

const whitespace = " \t\r\n";

fn trim(s: []const u8) []const u8 {
    return std.mem.trim(u8, s, whitespace);
}

/// Parses one input line.
pub fn parse(line_in: []const u8) ParseError!Command {
    const line = trim(line_in);
    var it = std.mem.tokenizeAny(u8, line, " \t");
    const word = it.next() orelse return .unknown;
    const rest = trim(it.rest());
    if (std.mem.eql(u8, word, "uci")) return .uci;
    if (std.mem.eql(u8, word, "isready")) return .isready;
    if (std.mem.eql(u8, word, "ucinewgame")) return .ucinewgame;
    if (std.mem.eql(u8, word, "quit")) return .quit;
    if (std.mem.eql(u8, word, "stop")) return .stop;
    if (std.mem.eql(u8, word, "ponderhit")) return .ponderhit;
    if (std.mem.eql(u8, word, "debug")) {
        if (std.mem.eql(u8, rest, "on")) return .{ .debug = true };
        if (std.mem.eql(u8, rest, "off")) return .{ .debug = false };
        return error.BadDebug;
    }
    if (std.mem.eql(u8, word, "setoption")) return .{ .setoption = try parseSetOption(rest) };
    if (std.mem.eql(u8, word, "position")) return .{ .position = try parsePosition(rest) };
    if (std.mem.eql(u8, word, "go")) return .{ .go = try parseGo(rest) };
    return .unknown;
}

/// `name <id with spaces> [value <rest of line>]`
fn parseSetOption(rest: []const u8) ParseError!SetOption {
    var it = std.mem.tokenizeAny(u8, rest, " \t");
    const first = it.next() orelse return error.BadSetOption;
    if (!std.mem.eql(u8, first, "name")) return error.BadSetOption;
    // The name runs up to the token `value`, which may be absent.
    const name_start = it.index;
    var name_end = name_start;
    var value: ?[]const u8 = null;
    while (it.next()) |t| {
        if (std.mem.eql(u8, t, "value")) {
            value = trim(it.rest());
            break;
        }
        name_end = it.index;
    }
    const name = trim(rest[name_start..name_end]);
    if (name.len == 0) return error.BadSetOption;
    return .{ .name = name, .value = value };
}

/// `startpos [moves ...]` or `fen <fields> [moves ...]`
fn parsePosition(rest: []const u8) ParseError!Position {
    var it = std.mem.tokenizeAny(u8, rest, " \t");
    const kind = it.next() orelse return error.BadPosition;
    var p: Position = .{ .fen = null, .moves = "" };
    if (std.mem.eql(u8, kind, "startpos")) {
        const next = it.next() orelse return p;
        if (!std.mem.eql(u8, next, "moves")) return error.BadPosition;
    } else if (std.mem.eql(u8, kind, "fen")) {
        const fen_start = it.index;
        var fen_end = fen_start;
        var saw_moves = false;
        while (it.next()) |t| {
            if (std.mem.eql(u8, t, "moves")) {
                saw_moves = true;
                break;
            }
            fen_end = it.index;
        }
        p.fen = trim(rest[fen_start..fen_end]);
        if (!saw_moves) return p;
    } else return error.BadPosition;
    p.moves = trim(it.rest());
    return p;
}

/// The number after a `go` parameter. A negative value (some GUIs send one for a
/// clock that has run out) counts as 0.
fn num(comptime T: type, it: *std.mem.TokenIterator(u8, .any)) ParseError!T {
    const t = it.next() orelse return error.BadGoNumber;
    const v = std.fmt.parseInt(i64, t, 10) catch return error.BadGoNumber;
    if (v < 0) return 0;
    return std.math.cast(T, v) orelse error.BadGoNumber;
}

const go_keywords = [_][]const u8{ "searchmoves", "ponder", "wtime", "btime", "winc", "binc", "movestogo", "depth", "nodes", "mate", "movetime", "infinite" };

fn isKeyword(t: []const u8) bool {
    for (go_keywords) |k| if (std.mem.eql(u8, t, k)) return true;
    return false;
}

fn parseGo(rest: []const u8) ParseError!Go {
    var g: Go = .{};
    var seen: [go_keywords.len]bool = @splat(false);
    var it = std.mem.tokenizeAny(u8, rest, " \t");
    while (it.next()) |t| {
        const k = for (go_keywords, 0..) |kw, i| {
            if (std.mem.eql(u8, t, kw)) break i;
        } else return error.UnknownGoParameter;
        if (seen[k]) return error.RepeatedGoParameter;
        seen[k] = true;
        switch (k) {
            0 => {
                // Moves up to the next keyword.
                const start = it.index;
                var end = start;
                while (it.peek()) |m| {
                    if (isKeyword(m)) break;
                    _ = it.next();
                    end = it.index;
                }
                g.searchmoves = trim(rest[start..end]);
            },
            1 => g.ponder = true,
            2 => g.wtime = try num(u64, &it),
            3 => g.btime = try num(u64, &it),
            4 => g.winc = try num(u64, &it),
            5 => g.binc = try num(u64, &it),
            6 => g.movestogo = try num(u32, &it),
            7 => g.depth = try num(u32, &it),
            8 => g.nodes = try num(u64, &it),
            9 => g.mate = try num(u32, &it),
            10 => g.movetime = try num(u64, &it),
            11 => g.infinite = true,
            else => unreachable,
        }
    }
    return g;
}
