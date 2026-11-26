//! The UCI shell (AGENTS.md §10.4): the command loop, its two threads, the
//! options, and the checks of positions and moves done before the engine sees
//! them. The engine is reached through `uci_engine.Engine`; until the search is
//! ported, `uci_engine.StubEngine` stands behind it. Behaviour: docs/UCI.md.
//!
//! The main thread only reads standard input and never waits for the engine. The
//! engine's commands (`setoption`, `ucinewgame`, `position`, `go`) run in order on
//! one worker thread, which owns the engine. `stop`, `ponderhit` and `quit` act at
//! once, even while a search runs or commands are queued behind it; `isready` is
//! answered at once during a search, but never before the effect of a command sent
//! before it that is not a search still running (`Worker.ready`).
//!
//! Adapted from the UCI layer of Cyrus IS Chess (same owner, MIT licence).

const std = @import("std");
const fen = @import("fen.zig");
const uci_parse = @import("uci_parse.zig");
const uci_engine = @import("uci_engine.zig");
const pipe_io = @import("pipe_io.zig");
const threads = @import("threads.zig");

const Output = uci_engine.Output;
const Options = uci_engine.Options;
const UciMove = fen.UciMove;

pub const engine_name = "MChess Pro 8";
pub const engine_author = "Marty Hirsch";

/// Most moves after `go searchmoves`.
pub const max_searchmoves = 256;
/// Size of the input line buffer; a longer line is reported and ignored.
pub const max_line = 64 * 1024;
/// Most moves a `position` command may carry: as many as an input line can hold (owner
/// decision 29, 2026-11-20; it was 2,048). A move is at least four characters and a
/// space, so a line of `max_line` bytes holds fewer than this, and the limit that a GUI
/// meets is the line's length, about 13,100 moves from the start position.
pub const max_position_moves = max_line / 5;
/// User text echoed in an error message is cut to this length.
const max_echo = 80;

/// Standard output shared by both threads: one line at a time, flushed.
const StdOut = struct {
    io: std.Io,
    mutex: std.Io.Mutex = .init,
    stdout: pipe_io.Stdout = undefined,

    fn output(o: *StdOut) Output {
        return .{ .ctx = o, .lineFn = lineFn };
    }

    fn lineFn(ctx: ?*anyopaque, text: []const u8) void {
        const o: *StdOut = @ptrCast(@alignCast(ctx.?));
        o.mutex.lockUncancelable(o.io);
        defer o.mutex.unlock(o.io);
        o.stdout.line(text) catch return;
    }
};

/// `text` cut to `max_echo` bytes, for an error message.
fn echo(text: []const u8) []const u8 {
    return text[0..@min(text.len, max_echo)];
}

/// `Hash`'s largest value, MB: 61,440 KB typed into the original's Settings / Hash-tables
/// dialog gives its largest tables, 2 x 30,720 KB (owner decision 24).
pub const max_hash_mb = 60;

/// The option declarations printed after `uci`.
fn printOptions(out: Output) void {
    const d: Options = .{};
    out.print("option name Hash type spin default {d} min 1 max {d}", .{ d.hash_mb, max_hash_mb });
    out.print("option name OwnBook type check default {}", .{d.own_book});
    out.print("option name Book type combo default {s} var Tournament var Standard var Variety", .{d.book.name()});
    out.print("option name Use Tablebases type check default {}", .{d.use_tablebases});
    out.print("option name Seed type spin default {d} min -1 max 65535", .{d.seed});
    out.print("option name Ponder type check default {}", .{d.ponder});
    out.print("option name Move Overhead type spin default {d} min 0 max 5000", .{d.move_overhead_ms});
}

/// The state of the game as the shell sees it, and the engine behind it. Used only
/// on the worker thread.
pub const Session = struct {
    engine: uci_engine.Engine,
    out: Output,
    options: Options = .{},
    /// Whether the last `position` (or `ucinewgame`) was accepted.
    valid: bool = true,
    /// Why it was rejected (when `valid` is false).
    reject_buf: [256]u8 = undefined,
    reject_len: usize = 0,
    /// The moves of the last `position` command.
    moves: [max_position_moves]UciMove = undefined,
    searchmoves: [max_searchmoves]UciMove = undefined,
    /// When the input thread read the `go` line being executed, if known.
    go_ns: ?i96 = null,

    pub fn init(engine: uci_engine.Engine, out: Output) Session {
        var s: Session = .{ .engine = engine, .out = out };
        s.engine.applyOptions(&s.options);
        const start = fen.parse(fen.startpos) catch unreachable;
        _ = s.engine.setPosition(&start, .new_game, &.{});
        return s;
    }

    fn rejectReason(s: *const Session) []const u8 {
        return s.reject_buf[0..s.reject_len];
    }

    /// Records a rejected position and prints why.
    fn reject(s: *Session, comptime fmt: []const u8, args: anytype) void {
        var w: std.Io.Writer = .fixed(&s.reject_buf);
        w.print(fmt, args) catch {};
        s.reject_len = w.buffered().len;
        s.valid = false;
        s.out.print("info string error: position rejected: {s}", .{s.rejectReason()});
    }

    /// Executes one engine command line (`setoption`, `ucinewgame`, `position`,
    /// `go`, or `isready` queued behind them). `sig` is the running `go`'s.
    pub fn execute(s: *Session, line: []const u8, sig: *uci_engine.Signals, io: std.Io) void {
        const trimmed = std.mem.trim(u8, line, " \t\r\n");
        const cmd = uci_parse.parse(trimmed) catch |err| {
            if (std.mem.startsWith(u8, trimmed, "position")) {
                // No stale position: a malformed `position` is a rejected one.
                s.reject("{s}", .{uci_parse.parseErrorText(err)});
            } else if (std.mem.startsWith(u8, trimmed, "go")) {
                // Every `go` gets exactly one `bestmove`.
                s.out.print("info string error: {s} in '{s}'", .{ uci_parse.parseErrorText(err), echo(trimmed) });
                s.out.line("bestmove 0000");
            }
            return;
        };
        switch (cmd) {
            .setoption => |o| s.setOption(o),
            .ucinewgame => s.newGame(),
            .position => |p| s.position(p),
            .go => |g| s.go(g, sig, io),
            .isready => s.out.line("readyok"),
            else => {},
        }
    }

    fn newGame(s: *Session) void {
        s.engine.newGame();
        const start = fen.parse(fen.startpos) catch unreachable;
        if (s.engine.setPosition(&start, .new_game, &.{})) |why| {
            s.reject("{s}", .{why});
            return;
        }
        s.valid = true;
    }

    fn position(s: *Session, p: uci_parse.Position) void {
        const text = p.fen orelse fen.startpos;
        const start = fen.parse(text) catch |err| return s.reject("{s}", .{fen.fenErrorText(err)});
        fen.checkConsistency(&start) catch |err| return s.reject("{s}", .{fen.consistencyErrorText(err)});
        var n: usize = 0;
        var it = std.mem.tokenizeAny(u8, p.moves, " \t");
        while (it.next()) |t| {
            const m = fen.parseMove(t) catch |err|
                return s.reject("move {d} '{s}': {s}", .{ n + 1, echo(t), fen.moveErrorText(err) });
            if (n == s.moves.len) return s.reject("more than {d} moves", .{max_position_moves});
            s.moves[n] = m;
            n += 1;
        }
        const route: uci_engine.Route = if (p.fen == null) .new_game else .setup;
        if (s.engine.setPosition(&start, route, s.moves[0..n])) |why| return s.reject("{s}", .{why});
        s.valid = true;
    }

    fn go(s: *Session, g: uci_parse.Go, sig: *uci_engine.Signals, io: std.Io) void {
        var limits: uci_engine.Limits = .{
            .ponder = g.ponder,
            .wtime = g.wtime,
            .btime = g.btime,
            .winc = g.winc,
            .binc = g.binc,
            .movestogo = g.movestogo,
            .depth = g.depth,
            .nodes = g.nodes,
            .mate = g.mate,
            .movetime = g.movetime,
            .infinite = g.infinite,
            .go_ns = s.go_ns,
        };
        if (!s.valid) {
            s.out.print("info string error: position rejected: {s}", .{s.rejectReason()});
            return s.finish(&limits, sig, io, .{});
        }
        if (g.searchmoves) |text| {
            var n: usize = 0;
            var it = std.mem.tokenizeAny(u8, text, " \t");
            while (it.next()) |t| {
                const m = fen.parseMove(t) catch |err| {
                    s.out.print("info string error: searchmoves '{s}': {s}", .{ echo(t), fen.moveErrorText(err) });
                    return s.finish(&limits, sig, io, .{});
                };
                if (n == s.searchmoves.len) {
                    s.out.print("info string error: more than {d} searchmoves", .{max_searchmoves});
                    return s.finish(&limits, sig, io, .{});
                }
                s.searchmoves[n] = m;
                n += 1;
            }
            limits.searchmoves = s.searchmoves[0..n];
        }
        const result = s.engine.search(&limits, sig, s.out);
        s.finish(&limits, sig, io, result);
    }

    /// Prints `bestmove`, after holding it as UCI requires: `go infinite` until
    /// `stop`, `go ponder` until `ponderhit` or `stop`. The hold sleeps until a signal
    /// is set rather than polling: a 1 ms sleep lasts about 10 ms on Windows, and after
    /// `ponderhit` that delay would be charged to the engine's clock.
    fn finish(s: *Session, limits: *const uci_engine.Limits, sig: *uci_engine.Signals, io: std.Io, r: uci_engine.Result) void {
        while (true) {
            const seen = sig.changeCount();
            if (sig.stop.load(.acquire)) break;
            const pondering = limits.ponder and !sig.ponderhit.load(.acquire);
            if (!limits.infinite and !pondering) break;
            sig.waitForChange(io, seen);
        }
        var b1: [5]u8 = undefined;
        var b2: [5]u8 = undefined;
        if (r.best) |best| {
            if (r.ponder) |p| {
                s.out.print("bestmove {s} ponder {s}", .{ fen.formatMove(best, &b1), fen.formatMove(p, &b2) });
            } else {
                s.out.print("bestmove {s}", .{fen.formatMove(best, &b1)});
            }
        } else s.out.line("bestmove 0000");
    }

    fn setOption(s: *Session, o: uci_parse.SetOption) void {
        const v = o.value orelse "";
        const eq = std.ascii.eqlIgnoreCase;
        if (eq(o.name, "Hash")) {
            s.options.hash_mb = @intCast(spin(v, 1, max_hash_mb) orelse return s.badValue(o));
        } else if (eq(o.name, "OwnBook")) {
            s.options.own_book = check(v) orelse return s.badValue(o);
        } else if (eq(o.name, "Book")) {
            s.options.book = uci_engine.BookKind.parse(v) orelse return s.badValue(o);
        } else if (eq(o.name, "Use Tablebases")) {
            s.options.use_tablebases = check(v) orelse return s.badValue(o);
        } else if (eq(o.name, "Seed")) {
            // Checked before it is kept: a bad value leaves the previous one in force.
            const seed = std.fmt.parseInt(i32, v, 10) catch return s.badValue(o);
            if (seed < -1 or seed > 65535) return s.badValue(o);
            s.options.seed = seed;
        } else if (eq(o.name, "Ponder")) {
            s.options.ponder = check(v) orelse return s.badValue(o);
        } else if (eq(o.name, "Move Overhead")) {
            s.options.move_overhead_ms = @intCast(spin(v, 0, 5000) orelse return s.badValue(o));
        } else {
            s.out.print("info string error: unknown option '{s}'", .{echo(o.name)});
            return;
        }
        s.engine.applyOptions(&s.options);
    }

    fn badValue(s: *Session, o: uci_parse.SetOption) void {
        s.out.print("info string error: bad value '{s}' for option {s}", .{ echo(o.value orelse ""), echo(o.name) });
    }
};

/// A check option's value: `true` / `false` (any case), else null.
fn check(v: []const u8) ?bool {
    if (std.ascii.eqlIgnoreCase(v, "true")) return true;
    if (std.ascii.eqlIgnoreCase(v, "false")) return false;
    return null;
}

/// A spin option's value within `min` … `max` (as declared), else null.
fn spin(v: []const u8, min: u32, max: u32) ?u32 {
    const n = std.fmt.parseInt(u32, v, 10) catch return null;
    return if (n >= min and n <= max) n else null;
}

/// The worker thread and its queue of engine commands. A `go` runs to its end
/// before the next command, so a script may send `go depth 5` and the next
/// `position` at once.
const Worker = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    session: *Session,
    mutex: std.Io.Mutex = .init,
    cond: std.Io.Condition = .init,
    /// Raw command lines, owned (the reader's buffer is reused).
    queue: std.ArrayList(Job) = .empty,
    quitting: bool = false,
    /// Signals of the running `go`.
    sig: uci_engine.Signals = .{},
    /// `go` sequence numbers: the newest queued, the running one (0 = none),
    /// and the newest that `stop` / `ponderhit` have reached.
    queued_go: u64 = 0,
    running_go: u64 = 0,
    stopped_go: u64 = 0,
    ponderhit_go: u64 = 0,
    /// The newest queued `go` holds its `bestmove` (`infinite` / `ponder`).
    queued_go_holds: bool = false,

    const Job = struct {
        line: []u8,
        /// For a `go`: its sequence number.
        go_id: u64 = 0,
        /// For a `go`: when the line was read (the awake clock, ns), where the search's
        /// elapsed time starts (docs/UCI_TIME.md section 4).
        go_ns: ?i96 = null,
    };

    /// Queues an engine command. A `go` that only `stop` would end (`infinite`,
    /// `ponder`) is stopped by any later engine command: a GUI sending one has
    /// abandoned that search.
    fn push(w: *Worker, line: []const u8, is_go: bool, holds: bool) !void {
        const read_ns: ?i96 = if (is_go) std.Io.Clock.awake.now(w.io).nanoseconds else null;
        const copy = try w.gpa.dupe(u8, line);
        errdefer w.gpa.free(copy);
        w.mutex.lockUncancelable(w.io);
        defer w.mutex.unlock(w.io);
        if (w.queued_go_holds) w.stopLocked();
        var job: Job = .{ .line = copy, .go_ns = read_ns };
        if (is_go) {
            w.queued_go += 1;
            job.go_id = w.queued_go;
            w.queued_go_holds = holds;
        } else {
            w.queued_go_holds = false;
        }
        try w.queue.append(w.gpa, job);
        w.cond.signal(w.io);
    }

    /// `stop`: the running `go` and any queued before this point.
    fn stopLocked(w: *Worker) void {
        w.stopped_go = w.queued_go;
        if (w.running_go != 0) w.sig.setStop(w.io);
    }

    fn stop(w: *Worker) void {
        w.mutex.lockUncancelable(w.io);
        defer w.mutex.unlock(w.io);
        w.stopLocked();
    }

    fn ponderhit(w: *Worker) void {
        w.mutex.lockUncancelable(w.io);
        defer w.mutex.unlock(w.io);
        w.ponderhit_go = w.queued_go;
        if (w.running_go != 0) w.sig.setPonderhit(w.io);
    }

    /// `isready` (docs/UCI.md). Returns true when `readyok` is to be printed at once: a
    /// search is running that has not been told to stop, and nothing is queued but searches
    /// not told to stop either. Otherwise the `isready` is queued behind every command it
    /// must not overtake: every queued command but the searches at the queue's end, and a
    /// running search already told to stop (by `stop`, or by a later engine command that
    /// ended a held `go`), whose `bestmove` must come first. It is answered as soon as the
    /// worker reaches it, so it waits for a search only where a command sent before it is
    /// queued behind that search. It never stops a search itself, so it does not go
    /// through `push`.
    fn ready(w: *Worker, line: []const u8) !bool {
        w.mutex.lockUncancelable(w.io);
        defer w.mutex.unlock(w.io);
        // The searches not told to stop at the queue's end may be passed: a GUI sees a
        // queued `go` as a search already under way.
        var at: usize = w.queue.items.len;
        while (at > 0 and w.queue.items[at - 1].go_id > w.stopped_go) at -= 1;
        if (at == 0 and w.running_go > w.stopped_go) return true;
        const copy = try w.gpa.dupe(u8, line);
        errdefer w.gpa.free(copy);
        try w.queue.insert(w.gpa, at, .{ .line = copy });
        w.cond.signal(w.io);
        return false;
    }

    /// `quit` (`drop` true): stop the search and drop the queue. End of input
    /// (`drop` false): stop every search but still run the queue, so that each
    /// `go` piped in gets its `bestmove`.
    fn quit(w: *Worker, drop: bool) void {
        w.mutex.lockUncancelable(w.io);
        defer w.mutex.unlock(w.io);
        w.quitting = true;
        w.stopLocked();
        if (drop) {
            for (w.queue.items) |j| w.gpa.free(j.line);
            w.queue.clearRetainingCapacity();
        }
        w.cond.signal(w.io);
    }

    fn main(w: *Worker) void {
        while (true) {
            w.mutex.lockUncancelable(w.io);
            while (w.queue.items.len == 0 and !w.quitting) w.cond.waitUncancelable(w.io, &w.mutex);
            if (w.queue.items.len == 0) {
                w.mutex.unlock(w.io);
                return;
            }
            const job = w.queue.orderedRemove(0);
            if (job.go_id != 0) {
                w.sig = .{};
                w.running_go = job.go_id;
                if (job.go_id <= w.stopped_go) w.sig.stop.store(true, .release);
                if (job.go_id <= w.ponderhit_go) w.sig.ponderhit.store(true, .release);
            }
            w.mutex.unlock(w.io);
            defer w.gpa.free(job.line);
            w.session.go_ns = job.go_ns;
            w.session.execute(job.line, &w.sig, w.io);
            if (job.go_id != 0) {
                w.mutex.lockUncancelable(w.io);
                w.running_go = 0;
                w.mutex.unlock(w.io);
            }
        }
    }
};

/// Runs the UCI loop on standard input and output with the stub engine until
/// `quit` or the end of input (for the shell's own tests; `mchess` runs `runJoined`).
pub fn run(gpa: std.mem.Allocator, io: std.Io) !void {
    var stub: uci_engine.StubEngine = .{ .io = io };
    return runWith(gpa, io, stub.engine());
}

/// Runs the UCI loop with the joined engine (src/engine.zig, Stage A: normal play at the
/// Fixed depth level; docs/UCI.md). This is what `mchess` runs (src/main.zig).
pub fn runJoined(gpa: std.mem.Allocator, io: std.Io) !void {
    // Every class C correction on (owner decision 25): `engine.Engine`. The engine with
    // them off, `engine.OriginalEngine`, is the one the golden tests prove.
    const E = @import("engine.zig").Engine;
    const e = try gpa.create(E);
    defer gpa.destroy(e);
    // The "cd" tablebase set (owner decision 33): the six installed files and 60 of the
    // CD's (src/tb_store.zig), under the one option `Use Tablebases`.
    e.* = try E.initSet(gpa, .cd);
    defer e.deinit();
    e.io = io;
    return runWithStart(gpa, io, e.engine(), .{ .ctx = e.tb_store, .run = preloadTablebases });
}

/// What the shell does at `uci` before it answers `uciok`.
pub const AtUci = struct {
    ctx: *anyopaque,
    run: *const fn (ctx: *anyopaque, io: std.Io) void,
};

/// Every embedded tablebase file unpacked (owner decision 37, 2026-11-22): at `uci`, so that
/// it is done before `uciok` and so before any `readyok`, and no move pays for it
/// (docs/ROBUSTNESS.md, finding 2). The option comes after `uciok`, and is true by default.
/// A second `uci` finds them held and does nothing; with `Use Tablebases` set false, which
/// freed them (owner decision 44), it does nothing either (src/tb_store.zig `preloadAll`,
/// `setUse`). Setting the option is the worker's (a queued `setoption`), and the store's lock
/// keeps the two apart.
fn preloadTablebases(ctx: *anyopaque, io: std.Io) void {
    const store: *@import("tb_store.zig").TbStore = @ptrCast(@alignCast(ctx));
    store.preloadAll(io);
}

/// Runs the UCI loop with the given engine.
pub fn runWith(gpa: std.mem.Allocator, io: std.Io, engine: uci_engine.Engine) !void {
    return runWithStart(gpa, io, engine, null);
}

/// Runs the UCI loop with the given engine; `at_uci`, if given, runs on the input thread at
/// every `uci` before the reply (no input is read meanwhile).
pub fn runWithStart(gpa: std.mem.Allocator, io: std.Io, engine: uci_engine.Engine, at_uci: ?AtUci) !void {
    var out: StdOut = .{ .io = io };
    out.stdout.init(io);
    const session = try gpa.create(Session);
    defer gpa.destroy(session);
    session.* = .init(engine, out.output());
    var worker: Worker = .{ .gpa = gpa, .io = io, .session = session };
    defer worker.queue.deinit(gpa);
    const thread = try threads.Thread.spawn(Worker, Worker.main, &worker);
    var quit_command = false;
    defer {
        worker.quit(quit_command);
        thread.join();
    }
    var debug = false;

    const in_buf = try gpa.alloc(u8, max_line);
    defer gpa.free(in_buf);
    // Overlapped pipes (fastchess on Windows) need pipe_io: std's reader panics at
    // the first read that has to wait.
    var stdin: pipe_io.Stdin = undefined;
    stdin.init(io, in_buf);
    const reader = stdin.reader();
    const o = out.output();
    while (true) {
        const raw = reader.takeDelimiter('\n') catch |err| switch (err) {
            error.StreamTooLong => {
                // takeDelimiter leaves an over-long line unread: skip it.
                _ = reader.discardDelimiterInclusive('\n') catch break;
                o.line("info string error: input line too long, ignored");
                continue;
            },
            else => return err,
        } orelse break;
        // A byte-order mark may precede the first command.
        const line = if (std.mem.startsWith(u8, raw, "\xEF\xBB\xBF")) raw[3..] else raw;
        const cmd = uci_parse.parse(line) catch |err| {
            // A malformed `position` or `go` still reaches the worker, in order;
            // anything else is reported and ignored.
            const word = std.mem.trim(u8, line, " \r\n\t");
            const is_go = std.mem.startsWith(u8, word, "go");
            if (is_go or std.mem.startsWith(u8, word, "position")) {
                try worker.push(line, is_go, false);
            } else {
                o.print("info string error: {s} in '{s}'", .{ uci_parse.parseErrorText(err), echo(word) });
            }
            continue;
        };
        switch (cmd) {
            .uci => {
                if (at_uci) |a| a.run(a.ctx, io);
                o.line("id name " ++ engine_name);
                o.line("id author " ++ engine_author);
                printOptions(o);
                o.line("uciok");
            },
            .isready => if (try worker.ready(line)) o.line("readyok"),
            .debug => |on| debug = on,
            .unknown => {},
            .stop => worker.stop(),
            .ponderhit => worker.ponderhit(),
            .quit => {
                quit_command = true;
                break;
            },
            .setoption, .ucinewgame, .position => try worker.push(line, false, false),
            .go => |g| try worker.push(line, true, g.infinite or g.ponder),
        }
    }
}
