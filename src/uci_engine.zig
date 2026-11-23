//! The interface between the UCI shell (`uci.zig`) and the engine, and a stub
//! engine to stand behind it until the search is ported.
//!
//! The shell owns the protocol: it reads commands, parses positions and moves,
//! keeps the options, holds `bestmove` for `go infinite` and `go ponder`, and
//! prints `bestmove` exactly once per `go`. The engine owns the game: it sets up
//! positions through the port of the original's set-up and move-entry code, and
//! searches.
//!
//! Contract:
//!
//! - Every call is made on the shell's worker thread, one at a time, in the order
//!   the commands arrived. The engine needs no locking of its own.
//! - `search` blocks until the search is over. It polls `Signals.stop` (and
//!   `Signals.ponderhit` when `Limits.ponder` is set) at the original's
//!   interruption point and returns promptly once `stop` is set. The input thread
//!   sets the signals; they are the only state shared between threads.
//! - `search` may print `info` lines through `Output` (thread-safe, one line per
//!   call). It never prints `bestmove`: it returns the move, and the shell prints
//!   it. A `null` move means there is no move to play; the shell prints
//!   `bestmove 0000`.
//! - `setPosition` returns null when the position is accepted, or the reason it
//!   is rejected (static text, or text the engine keeps until its next call). The
//!   shell has already checked the FEN's syntax and consistency and the moves'
//!   syntax; the engine checks what only the original's code can decide (its own
//!   set-up test, the legality of each move, a game already over).
//! - No call is made with a position the engine rejected: after a rejection the
//!   shell answers `go` itself until a position is accepted.

const std = @import("std");
const fen = @import("fen.zig");

pub const UciMove = fen.UciMove;

/// How a position reaches the engine: the original sets up the same position
/// differently by route (docs/OBSERVATIONS.md, "same position searches differently by
/// route": new game puts g1/g8 in knight slot 0, Setup b1/b8, and the generators follow
/// slot order), so the engine must take the route the command names.
pub const Route = enum {
    /// `position startpos [moves ...]` and `ucinewgame`: the original's new game, then
    /// the moves.
    new_game,
    /// `position fen <fen> [moves ...]`: the original's Setup mode, then the moves, even
    /// when the FEN is the start position.
    setup,
};

/// Where the engine's lines go (without the trailing newline).
pub const Output = struct {
    ctx: ?*anyopaque = null,
    lineFn: *const fn (ctx: ?*anyopaque, text: []const u8) void,

    pub fn line(o: Output, text: []const u8) void {
        o.lineFn(o.ctx, text);
    }

    /// Formats one line. A line longer than 8 KiB is cut at 8 KiB.
    pub fn print(o: Output, comptime fmt: []const u8, args: anytype) void {
        var buf: [8192]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        w.print(fmt, args) catch {};
        o.lineFn(o.ctx, w.buffered());
    }
};

/// Signals from the input thread to the search, set at any time. A search polls the
/// two flags; a thread with nothing else to do can sleep until one is set
/// (`changeCount`, `waitForChange`) when it is set with `setStop` or `setPonderhit`.
pub const Signals = struct {
    stop: std.atomic.Value(bool) = .init(false),
    ponderhit: std.atomic.Value(bool) = .init(false),
    /// Counts the calls of `setStop` and `setPonderhit`; a waiter sleeps on it.
    changes: std.atomic.Value(u32) = .init(0),

    pub fn setStop(s: *Signals, io: std.Io) void {
        s.stop.store(true, .release);
        s.notify(io);
    }

    pub fn setPonderhit(s: *Signals, io: std.Io) void {
        s.ponderhit.store(true, .release);
        s.notify(io);
    }

    fn notify(s: *Signals, io: std.Io) void {
        _ = s.changes.fetchAdd(1, .release);
        io.futexWake(u32, &s.changes.raw, std.math.maxInt(u32));
    }

    /// Read before testing the flags, then passed to `waitForChange`, so that a flag set
    /// between the test and the wait is not missed.
    pub fn changeCount(s: *const Signals) u32 {
        return s.changes.load(.acquire);
    }

    /// Sleeps until a flag is set through `setStop` or `setPonderhit` after `seen` was
    /// read, or at most 100 ms (so that a flag stored directly is still seen), or
    /// spuriously. The caller tests the flags again.
    pub fn waitForChange(s: *const Signals, io: std.Io, seen: u32) void {
        const backstop: std.Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(100), .clock = .awake } };
        io.futexWaitTimeout(u32, &s.changes.raw, seen, backstop) catch {};
    }
};

/// The UCI options (AGENTS.md §10.1, provisional). The shell parses and stores
/// them; `applyOptions` hands the engine the whole set after every change.
pub const Options = struct {
    /// `Hash`, MB, 1 to 60 (owner decision 24): N x 1,024 KB typed into the original's
    /// Settings / Hash-tables dialog, the total for its two tables (src/engine.zig
    /// `setHash`; docs/UCI.md). 60, the default, is the original's largest: two tables
    /// of 30,720 KB. Larger sizes are not the original's logic and are not offered.
    hash_mb: u32 = 60,
    /// `OwnBook`: whether the original's opening book is consulted (docs/UCI.md). Off by
    /// default (owner, 2026-11-19), unlike the original, which starts with its tournament
    /// book on.
    own_book: bool = false,
    /// `Book`: which of the original's three ways of drawing from its one book file the
    /// Book menu selects (docs/arch/40-opening-book.md section 6). Read only with
    /// `own_book` on.
    book: BookKind = .tournament,
    /// `Use Tablebases`: the original's "Use tablebases" check box (DG:239C bit 3;
    /// docs/arch/41-tablebases.md section 5). On by default, as the original ships.
    /// An infinite search never uses them (owner decision 22).
    use_tablebases: bool = true,
    /// `Seed`: the value srand is given where the original gives it the BIOS tick count
    /// (start-up; in the engine, every game it builds afresh), 0..65535; -1, the default,
    /// reads it from the clock as the original does. Read only by the book's draw.
    seed: i32 = -1,
    /// `Ponder`: announces pondering to the GUI; `go ponder` works either way.
    ponder: bool = false,
    /// `Move Overhead`, ms: subtracted from the time budget for GUI latency.
    move_overhead_ms: u32 = 30,
};

/// The original's three books (its Book menu's radio group): `[A6A0]` bit 5 set for
/// Tournament, bit 2 set for Variety, both clear for Standard.
pub const BookKind = enum {
    tournament,
    standard,
    variety,

    pub const names = [_][]const u8{ "Tournament", "Standard", "Variety" };

    pub fn name(k: BookKind) []const u8 {
        return names[@backingInt(k)];
    }

    pub fn parse(v: []const u8) ?BookKind {
        for (names, 0..) |n, i| if (std.ascii.eqlIgnoreCase(n, v)) return @fromBackingInt(@intCast(i));
        return null;
    }
};

/// The limits of one `go`, as UCI gives them.
pub const Limits = struct {
    /// Root moves to restrict the search to; empty for no restriction.
    searchmoves: []const UciMove = &.{},
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
    /// When the input thread read the `go` line (`std.Io.Clock.awake`, ns): the search's
    /// elapsed time runs from it (docs/UCI_TIME.md section 4). Null: from the search's start.
    go_ns: ?i96 = null,
};

/// What a search returns.
pub const Result = struct {
    /// The move to play, or null when there is none (`bestmove 0000`).
    best: ?UciMove = null,
    /// The expected reply, printed as `bestmove … ponder …`, or null.
    ponder: ?UciMove = null,
};

/// An engine as the shell sees it: a context pointer and four operations.
pub const Engine = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// The options after a `setoption` changed them, and once at start-up.
        applyOptions: *const fn (ctx: *anyopaque, options: *const Options) void,
        /// `ucinewgame`. The shell follows it with `setPosition` of the start
        /// position.
        newGame: *const fn (ctx: *anyopaque) void,
        /// `position`: the start position, the route it came by, and the moves played
        /// from it. Returns null if accepted, else the reason for rejection.
        setPosition: *const fn (ctx: *anyopaque, start: *const fen.Description, route: Route, moves: []const UciMove) ?[]const u8,
        /// `go`, on the last accepted position. Blocks until the search ends.
        search: *const fn (ctx: *anyopaque, limits: *const Limits, signals: *Signals, out: Output) Result,
    };

    pub fn applyOptions(e: Engine, options: *const Options) void {
        e.vtable.applyOptions(e.ctx, options);
    }

    pub fn newGame(e: Engine) void {
        e.vtable.newGame(e.ctx);
    }

    pub fn setPosition(e: Engine, start: *const fen.Description, route: Route, moves: []const UciMove) ?[]const u8 {
        return e.vtable.setPosition(e.ctx, start, route, moves);
    }

    pub fn search(e: Engine, limits: *const Limits, signals: *Signals, out: Output) Result {
        return e.vtable.search(e.ctx, limits, signals, out);
    }
};

/// The engine until the search is ported: it accepts every position the shell
/// passes it and answers every `go` with an `info string` and no move. With
/// `go movetime T` it first waits T ms, or until `stop`, polling `Signals.stop`
/// as a search would, so that the shell's stop path can be tested.
pub const StubEngine = struct {
    /// Needed only for `movetime`; without it the stub answers at once.
    io: ?std.Io = null,
    options: Options = .{},
    /// Counts of calls, for the tests.
    new_games: u32 = 0,
    positions: u32 = 0,
    searches: u32 = 0,
    /// The last position given.
    side_to_move: fen.Side = .white,
    move_count: usize = 0,

    pub const not_ported = "info string the search is not yet ported: no move";

    pub fn engine(s: *StubEngine) Engine {
        return .{ .ctx = s, .vtable = &vtable };
    }

    const vtable: Engine.VTable = .{
        .applyOptions = applyOptions,
        .newGame = newGame,
        .setPosition = setPosition,
        .search = search,
    };

    fn self(ctx: *anyopaque) *StubEngine {
        return @ptrCast(@alignCast(ctx));
    }

    fn applyOptions(ctx: *anyopaque, options: *const Options) void {
        self(ctx).options = options.*;
    }

    fn newGame(ctx: *anyopaque) void {
        self(ctx).new_games += 1;
    }

    fn setPosition(ctx: *anyopaque, start: *const fen.Description, route: Route, moves: []const UciMove) ?[]const u8 {
        _ = route;
        const s = self(ctx);
        s.positions += 1;
        s.side_to_move = start.side_to_move;
        s.move_count = moves.len;
        return null;
    }

    fn search(ctx: *anyopaque, limits: *const Limits, signals: *Signals, out: Output) Result {
        const s = self(ctx);
        s.searches += 1;
        out.line(not_ported);
        if (s.io) |io| if (limits.movetime) |ms| {
            const start = std.Io.Clock.awake.now(io).nanoseconds;
            const limit_ns: i96 = @as(i96, @min(ms, 3_600_000)) * std.time.ns_per_ms;
            while (!signals.stop.load(.acquire)) {
                if (std.Io.Clock.awake.now(io).nanoseconds - start >= limit_ns) break;
                io.sleep(.fromMilliseconds(1), .awake) catch {};
            }
        };
        return .{};
    }
};

test "the stub accepts a position and answers go with no move" {
    var stub: StubEngine = .{};
    const e = stub.engine();
    const start = try fen.parse(fen.startpos);
    const moves = [_]UciMove{try fen.parseMove("e2e4")};
    try std.testing.expect(e.setPosition(&start, .new_game, &moves) == null);
    try std.testing.expectEqual(@as(usize, 1), stub.move_count);

    const Capture = struct {
        lines: u32 = 0,
        fn lineFn(ctx: ?*anyopaque, text: []const u8) void {
            const c: *@This() = @ptrCast(@alignCast(ctx.?));
            c.lines += 1;
            std.debug.assert(std.mem.startsWith(u8, text, "info string"));
        }
    };
    var cap: Capture = .{};
    var sig: Signals = .{};
    const r = e.search(&.{}, &sig, .{ .ctx = &cap, .lineFn = Capture.lineFn });
    try std.testing.expect(r.best == null);
    try std.testing.expectEqual(@as(u32, 1), cap.lines);

    var o: Options = .{};
    o.move_overhead_ms = 7;
    e.applyOptions(&o);
    try std.testing.expectEqual(@as(u32, 7), stub.options.move_overhead_ms);
}
