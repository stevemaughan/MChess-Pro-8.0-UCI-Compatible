//! What the joined engine tells the GUI while it searches (AGENTS.md §10.6): `info` lines
//! gathered by observing the root (src/engine_root.zig `Observer`), never read by the
//! search. Where each value comes from is in docs/UCI.md, "Feedback".
//!
//! Lines:
//!
//! - at each new best root move and each root fail high: the original's own display point,
//!   the call of show_score (38C0:9BEA) from root_search at 0000:2C1F (a new best, or the
//!   earlier best restored after a failed fail-high re-search; the score exact) and
//!   0000:2835 (a fail high: the score is the window's top, `lowerbound`);
//! - at the end of each iteration (the loop's root_search returns at 0000:15FA or 165D):
//!   the score exact, or `upperbound` when it is at or below the window's bottom (the
//!   first root move failed low, and the loop re-searches below it);
//! - `currmove` and `currmovenumber` at each root move made (make_move from root_search,
//!   0000:24BC; the original shows the move it considers at 253E just after), once the
//!   search has run a second;
//! - a final line before `bestmove` (`final`).

const std = @import("std");
const fen = @import("fen.zig");
const rs = @import("rootsearch.zig");
const uci_engine = @import("uci_engine.zig");
const engine_root = @import("engine_root.zig");
const timecontrol = @import("timecontrol.zig");
const pos = @import("position.zig");
const mg = @import("movegen.zig");
const see_mod = @import("see.zig");
const dgroup = @import("dgroup.zig");
const gamemove = @import("gamemove.zig");
const legality = @import("legality.zig");

/// The original's mate encoding: a node at ply p (the root's moves are made at ply 2) whose
/// side to move is mated returns p - 20000 (0000:41C2 `self.ply -% 0x4E20`, searchnode.zig;
/// at ply 2 in root_move_search the same, 0000:3674 mov ax, B1E2h = 2 - 20000), and the
/// score is negated up the tree, so
/// a root score s with |s| > `mate_threshold` is a mate found at ply p = 20000 - |s|.
pub const mate_score: i16 = 20000;
/// The original's display shows a score as a mate only above 19700 in magnitude (the
/// default display 38C0:9A7C `cmp si, 4CF4h; jle` and 9AC2 `cmp si, B30Ch; jge`);
/// root_search's own test for a won score (0000:2C77) is `si >= 19700`. No evaluation
/// reaches 19700, and a mate within the 37 plies the PV holds is above 19960.
pub const mate_threshold: i16 = 19700;

/// Whether a root score is shown as a mate (`mate_threshold`).
pub fn isMate(s: i16) bool {
    return s > mate_threshold or s < -mate_threshold;
}

/// The UCI score of a root score `s` (the side to move's view, the evaluation's units, a
/// pawn 200): `mate N`, or `cp` and the score halved, truncated toward zero, as the
/// original's display shows it (DEV-F23): the default display 38C0:9A2E takes the sign
/// (9B5F-9B6C), halves the magnitude (9B89 `sar word [bp+6],1`) and prints it in pawns,
/// and show_score's numeric path 38C0:9BEA does the same (9DB6-9DC0, 9E10-9E13): raw 103
/// is +0.51, -103 is -0.51. N is the mating side's moves: the mated node at ply p is
/// p - 1 plies after the root; a mate given at odd plies after the root is the engine's
/// (N = (p - 1 + 1) / 2), one suffered at even plies the opponent's (N = (p - 1) / 2).
/// With p = 20000 - |s|, N = p / 2 both ways, and at least 1 (a score of exactly -20000,
/// the king-capture value, would give p = 0: reported as a mate in one).
pub fn scoreText(s: i16, buf: []u8) []const u8 {
    if (isMate(s)) {
        const a: i32 = if (s < 0) -@as(i32, s) else s;
        const p: i32 = mate_score - a;
        const n: i32 = @max(1, @divTrunc(p, 2));
        return std.fmt.bufPrint(buf, "mate {d}", .{if (s < 0) -n else n}) catch "cp 0";
    }
    return std.fmt.bufPrint(buf, "cp {d}", .{@divTrunc(s, 2)}) catch "cp 0";
}

/// A move of the 10x12 board in UCI notation.
fn squareOk(sq: u8) bool {
    return sq >= 21 and sq <= 98 and sq % 10 >= 1 and sq % 10 <= 8;
}

/// Appends the PV, from `board` (the root position) with `white` to move, to `w`: each
/// word from | to << 8 (bit 7 of each byte a flag, DG:93B0), `first_flag` the flag byte of
/// the first move (DG:A36C+2: a promotion's piece). The line is cut at the first move that
/// does not start from a man of the side to move or lands on its own man (AGENTS.md §9.3);
/// a later promotion is shown as a queen (the PV words carry no piece).
pub fn writePv(w: *std.Io.Writer, board_in: *const [120]u8, white_in: bool, words: []const u16, first_flag: u8) usize {
    var b = board_in.*;
    var white = white_in;
    var n: usize = 0;
    for (words, 0..) |word, k| {
        const from: u8 = @truncate(word & 0x7F);
        const to: u8 = @truncate((word >> 8) & 0x7F);
        if (!squareOk(from) or !squareOk(to) or from == to) break;
        const p = b[from];
        const own = if (white) p >= 1 and p <= 6 else p >= 8 and p <= 13;
        if (!own) break;
        const t = b[to];
        if (t != 0 and (if (white) t >= 1 and t <= 6 else t >= 8 and t <= 13)) break;
        var promo: u8 = 0;
        const pawn = p == 1 or p == 8;
        b[to] = p;
        b[from] = 0;
        if (pawn and (to >= 91 or to <= 28)) {
            promo = if (k == 0 and first_flag >= 2 and first_flag <= 5) first_flag else 5;
            b[to] = if (white) promo else promo + 7;
        } else if (pawn and t == 0 and (to % 10) != (from % 10)) {
            b[if (white) to - 10 else to + 10] = 0; // en passant
        } else if ((p == 6 or p == 13) and (@as(i16, to) - from == 2 or @as(i16, from) - to == 2)) {
            if (to > from) {
                b[to - 1] = b[to + 1];
                b[to + 1] = 0;
            } else {
                b[to + 1] = b[to - 2];
                b[to - 2] = 0;
            }
        }
        var mb: [5]u8 = undefined;
        w.print(" {s}", .{fen.formatMove(.{ .from = from, .to = to, .promotion = promo }, &mb)}) catch return n;
        n += 1;
        white = !white;
    }
    return n;
}

/// The full legality test of a PV before it is sent (AGENTS.md section 9.3 item 4): each
/// move is played on a scratch position from the root, and must pass src/legality.zig's
/// test: a move of the generator the original uses at that ply (gen_evasions in check,
/// else gen_all_moves with its cap of 100, under the build's class C fixes `fixes`; with
/// the king test these equal true perft: src/perft_test.zig), not castle out of check, and
/// not leave the mover's king attacked (2B9F:4B32, `gamemove.kingAttacked`). Reporting
/// only: the search's own state is read, never written.
pub const PvCheck = struct {
    root: pos.Position = .{},
    p: pos.Position = .{},
    s: see_mod.Scratch = .{},
    v: mg.SearchVars = .{},
    list: mg.MoveList = undefined,
    white: bool = true,

    /// The root position at main 0000:0526 (`root`'s: a `EngineRoot` of src/engine_root.zig, the
    /// domain's `Position`, Stage B step 8, stage 6; before it, loaded from the image), with
    /// the en-passant square and the check record main gives the root from the game record
    /// (0000:0677-0693, `legality.rootRecord`), as `Engine.findLegal` does; the side DG:8DDE
    /// and the move number DG:A84A at their homes. The check record at later plies is the
    /// one make_move writes (`Position.check_by_ply`, 093C-0953).
    pub fn load(c: *PvCheck, root: anytype) void {
        c.root = root.node.dom.p;
        const h = root.home();
        const side: u16 = h.get(0x8DDE);
        c.white = side == 0;
        const r = legality.rootRecord(root, side);
        c.root.ep_square_by_ply[1] = r.ep;
        c.root.check_by_ply[1] = r.check;
    }

    /// How many of `words` (from | to << 8, bit 7 of each byte a flag) are legal one after
    /// the other from the root; `first_flag`: the first move's promotion piece; `fixes`:
    /// the build's class C switches, which order gen_all_moves' list and so decide what its
    /// cap keeps.
    pub fn legalPrefix(c: *PvCheck, comptime fixes: pos.Fixes, words: []const u16, first_flag: u8) usize {
        c.p = c.root;
        var side: pos.Side = if (c.white) .white else .black;
        for (words, 0..) |word, k| {
            const from: u8 = @truncate(word & 0x7F);
            const to: u8 = @truncate((word >> 8) & 0x7F);
            if (!squareOk(from) or !squareOk(to)) return k;
            const ply = k + 1;
            if (ply + 1 >= pos.max_ply) return k;
            const n = legality.generate(fixes, &c.p, &c.s, &c.v, &c.list, side, ply);
            if (n == mg.king_capture) return k;
            const piece = c.p.board[from];
            const promotion = (piece == 1 or piece == 8) and (to >= 91 or to <= 28);
            const want_flag: u8 = if (k == 0 and first_flag >= 2 and first_flag <= 5) first_flag else 5;
            var found: ?pos.Move = null;
            for (c.list[0..@min(n, c.list.len)]) |mv| {
                if (mv.from != from or mv.to != to) continue;
                if (promotion and mv.flag != want_flag) continue;
                found = mv;
                break;
            }
            const mv = found orelse return k;
            if (legality.makeIfKingSafe(&c.p, mv, side, ply + 1) != null) return k;
            side = side.other();
        }
        return words.len;
    }
};

pub fn Reporter(comptime R: type) type {
    return struct {
        const Self = @This();

        root: *R,
        out: uci_engine.Output,
        signals: ?*uci_engine.Signals,
        io: ?std.Io,
        /// Lines are printed only when set (the stop request is read either way).
        enabled: bool = true,
        t0: i96 = 0,
        /// The side to move at the root (the program's side, DG:8DDE).
        white: bool = true,
        /// The root position (DG:9EF6) as the search began.
        board: [120]u8 = @splat(0),
        /// The last score reported and how: for the final line.
        depth: i16 = 0,
        score: i16 = 0,
        bound: Bound = .exact,
        have_score: bool = false,
        /// The deepest iteration completed.
        completed: i16 = 0,
        lines: u32 = 0,
        /// The node count of the last line printed.
        last_nodes: u64 = 0,
        /// The full legality test of the PV (AGENTS.md section 9.3 item 4), if given.
        pv_check: ?*PvCheck = null,
        /// Lines whose PV the legality test cut, and the first such PV's words and the
        /// length kept (the tests).
        pv_cuts: u32 = 0,
        first_cut: ?struct { words: [37]u16, len: usize, kept: usize } = null,

        // ---- the time control (docs/UCI_TIME.md section 4) ----------------------------
        /// The engine's time control, or none (the stop request alone).
        tc: ?*timecontrol.TimeControl = null,
        /// When the `go` line was read (the awake clock, ns), if known: elapsed time runs
        /// from it; otherwise from `begin`.
        go_ns: ?i96 = null,
        /// The scripted clock of the tests: elapsed ms = live nodes × this / 1000 (µs per
        /// node). Used for every time this reporter gives, `info time` included.
        scripted_us_per_node: ?u64 = null,
        /// `go ponder`: no time rule stops the search until `Signals.ponderhit`.
        ponder: bool = false,
        /// The current iteration: the best exact score so far (a new best shown at
        /// 0000:2C1F), and the root re-searches (fail highs shown at 2835, and the loop's
        /// re-search after the first root move failed low, 15FA).
        iter_best: ?i16 = null,
        fail_high_low: u8 = 0,
        /// The score of the last completed iteration of this search (Juggernaut's
        /// fCompletedScore; its depth is `completed`).
        completed_score: i16 = 0,
        /// What the time control was handed and what it decided, for the tests.
        log: TimeLog = .{},

        pub const Bound = enum { exact, lower, upper };

        pub const TimeLog = struct {
            iterations: [64]timecontrol.Iteration = undefined,
            n: usize = 0,
            /// Root trouble was seen true at a 1024-node test.
            trouble_seen: bool = false,
            /// How the time control ended the search: inside an iteration (the stop flag),
            /// or after one (the loop limit), at that depth.
            stopped_in_search: bool = false,
            stopped_after: ?i16 = null,
            /// The elapsed time at the in-search stop.
            stop_elapsed: i64 = 0,
        };

        pub fn observer(r: *Self) engine_root.Observer {
            return .{ .ctx = r, .call = call, .iterationDone = iterationDone, .stopRequested = stopRequested };
        }

        pub fn begin(r: *Self) void {
            r.t0 = r.go_ns orelse r.now();
            // The program's side DG:8DDE at its home; the board the domain's `Position`.
            r.white = r.root.home().get(0x8DDE) == 0;
            @memcpy(&r.board, &r.root.node.dom.p.board);
            if (r.pv_check) |c| c.load(r.root);
            r.pv_cuts = 0;
            r.first_cut = null;
            r.have_score = false;
            r.completed = 0;
            r.depth = 0;
            r.lines = 0;
            r.iter_best = null;
            r.fail_high_low = 0;
            r.completed_score = 0;
            r.log = .{};
        }

        fn now(r: *const Self) i96 {
            return if (r.io) |io| std.Io.Clock.awake.now(io).nanoseconds else 0;
        }

        pub fn elapsedMs(r: *const Self) u64 {
            if (r.scripted_us_per_node) |us| return r.root.live_nodes * us / 1000;
            const d = r.now() - r.t0;
            return if (d <= 0) 0 else @intCast(@divTrunc(d, std.time.ns_per_ms));
        }

        /// Whether the search is pondering: `go ponder` before `ponderhit`.
        pub fn pondering(r: *const Self) bool {
            if (!r.ponder) return false;
            const sig = r.signals orelse return true;
            return !sig.ponderhit.load(.acquire);
        }

        fn self(ctx: *anyopaque) *Self {
            return @ptrCast(@alignCast(ctx));
        }

        /// Juggernaut's RootTrouble as read at the 1024-node test: an iteration of this
        /// search completed, a root move of the current one has an exact score, and the
        /// best so far is more than 50 centipawns below the completed iteration's score:
        /// 100 of the raw scores, in the time control's unit (`TimeControl.score_unit`).
        pub fn rootTrouble(r: *const Self) bool {
            const b = r.iter_best orelse return false;
            const unit: i32 = if (r.tc) |tc| tc.score_unit else 1;
            return timecontrol.rootTrouble(@intCast(@max(r.completed, 0)), r.completed_score, b, unit);
        }

        fn stopRequested(ctx: *anyopaque, nodes: u64, request_test: bool, time_test: bool) bool {
            const r = self(ctx);
            if (request_test) if (r.signals) |sig| if (sig.stop.load(.acquire)) return true;
            const tc = r.tc orelse return false;
            // The time control on this search's own count only (and the loop's first node
            // entry), so that a scripted clock stops a search at the same node whatever
            // the engine searched before.
            if (!time_test) return false;
            const trouble = r.rootTrouble();
            if (trouble) r.log.trouble_seen = true;
            const ms: i64 = @intCast(r.elapsedMs());
            if (tc.shouldStopInSearch(ms, nodes, trouble, r.pondering())) {
                r.log.stopped_in_search = true;
                r.log.stop_elapsed = ms;
                return true;
            }
            return false;
        }

        /// hashfull: the share of used slots among the first 500 of each main table's size
        /// in use (the slots its index reaches: `Hash`, docs/UCI.md; at least 4,096), in
        /// permille (a slot is used when its bound bits, byte 8 & C0h, are set).
        pub fn hashfull(r: *const Self) u32 {
            const in_use = @min(r.root.hashSlotsInUse(), r.root.tables[0].slots.len);
            // As a usize: @min with the constant gives a 9-bit type, and 2 * n would overflow it.
            const n: usize = @min(in_use, 500);
            if (n == 0) return 0;
            var used: u32 = 0;
            for (r.root.tables) |t| {
                for (t.slots[0..n]) |slot| {
                    if (slot[8] & 0xC0 != 0) used += 1;
                }
            }
            return @intCast(@as(u64, used) * 1000 / (2 * n));
        }

        /// One full line: depth, seldepth, score, nodes, nps, time, hashfull, pv.
        fn line(r: *Self, depth: i16, score: i16, bound: Bound, pv_in: []const u16, first_flag: u8) void {
            r.depth = depth;
            r.score = score;
            r.bound = bound;
            r.have_score = true;
            if (!r.enabled) return;
            var pv = pv_in;
            if (r.pv_check) |c| {
                // Cut at the first move that is not legal, the first move too: the root's
                // best move is a move of the root list, and the search can hand back one
                // that is not legal (the guard on `bestmove` then plays another, AGENTS.md
                // section 9.3 item 3); the line is then sent without a pv.
                const keep = c.legalPrefix(R.class_c_fixes, pv, first_flag);
                if (keep < pv.len) {
                    r.pv_cuts += 1;
                    if (r.first_cut == null) {
                        r.first_cut = .{ .words = undefined, .len = @min(pv.len, 37), .kept = keep };
                        @memcpy(r.first_cut.?.words[0..r.first_cut.?.len], pv[0..r.first_cut.?.len]);
                    }
                    pv = pv[0..keep];
                }
            }
            var buf: [1024]u8 = undefined;
            var w: std.Io.Writer = .fixed(&buf);
            const ms = r.elapsedMs();
            const nodes = r.root.nodes;
            const nps = nodes * 1000 / @max(ms, 1);
            var sb: [16]u8 = undefined;
            const sel: i16 = @max(r.root.max_ply - 1, depth);
            const bound_text: []const u8 = switch (bound) {
                .exact => "",
                .lower => " lowerbound",
                .upper => " upperbound",
            };
            const score_text = scoreText(score, &sb);
            const hf = r.hashfull();
            w.print("info depth {d} seldepth {d} score {s}{s} nodes {d} nps {d} time {d} hashfull {d}", .{ @max(depth, 1), sel, score_text, bound_text, nodes, nps, ms, hf }) catch {};
            var pbuf: [600]u8 = undefined;
            var pw: std.Io.Writer = .fixed(&pbuf);
            if (writePv(&pw, &r.board, r.white, pv, first_flag) > 0) w.print(" pv{s}", .{pw.buffered()}) catch {};
            r.out.line(w.buffered());
            r.lines += 1;
            r.last_nodes = nodes;
        }

        fn call(ctx: *anyopaque, site: u16, callee: rs.Callee, args: []const u16, st: *const rs.RootState) void {
            const r = self(ctx);
            switch (callee) {
                .make => if (site == 0x24BC and r.enabled) {
                    const ms = r.elapsedMs();
                    if (ms < 1000) return;
                    const i: usize = st.root_move_number.* -% 1;
                    if (i >= rs.max_root_moves) return;
                    const m = st.root_moves[i];
                    var mb: [5]u8 = undefined;
                    const promo: u8 = if ((r.board[m[0]] == 1 or r.board[m[0]] == 8) and (m[1] >= 91 or m[1] <= 28)) m[2] else 0;
                    r.out.print("info depth {d} currmove {s} currmovenumber {d}", .{ @max(st.depth.*, 1), fen.formatMove(.{ .from = m[0], .to = m[1], .promotion = promo }, &mb), st.root_move_number.* });
                },
                .show_score => {
                    const score: i16 = @bitCast(args[2]);
                    if (site == 0x2835) {
                        // A fail high: the score is the window's top; the move searched.
                        const i: usize = st.root_move_number.* -% 1;
                        if (i >= rs.max_root_moves) return;
                        const m = st.root_moves[i];
                        const word: u16 = @as(u16, m[0]) | @as(u16, m[1]) << 8;
                        // root_search re-searches the move (0000:287E): a root re-search.
                        r.fail_high_low +|= 1;
                        r.line(st.depth.*, score, .lower, &.{word}, m[2]);
                    } else {
                        // 2C1F: a new best (or the earlier best restored after a failed
                        // fail-high re-search), its score exact: the best so far.
                        r.iter_best = score;
                        r.pvLine(st, st.depth.*, score, .exact);
                    }
                },
                else => {},
            }
        }

        /// The move encoding handed to the time control: from | to << 8, 10x12 squares.
        /// What a PV word gives (it holds no promotion piece): the expected move's key.
        pub fn moveKey(from: u8, to: u8) timecontrol.Move {
            return @as(timecontrol.Move, from & 0x7F) | @as(timecontrol.Move, to & 0x7F) << 8;
        }

        /// The key of a root move from the root position `board`: `moveKey`, with the
        /// promotion piece (the flag, 2 to 5) << 16 when the move is a pawn's to its last
        /// rank, so that a rook and a queen promotion are different moves to the clock. Any
        /// other move's key is `moveKey`'s, so it still matches an expected move taken
        /// from a PV word.
        pub fn rootMoveKey(board: *const [120]u8, m: [3]u8) timecontrol.Move {
            const from = m[0] & 0x7F;
            const to = m[1] & 0x7F;
            const pc = if (from < board.len) board[from] else 0;
            const promotion = (pc == 1 or pc == 8) and (to >= 91 or to <= 28) and m[2] >= 2 and m[2] <= 5;
            const piece: timecontrol.Move = if (promotion) m[2] else 0;
            return moveKey(from, to) | piece << 16;
        }

        /// The moves a mate score s (the side to move's view) mates in, for `go mate`:
        /// `scoreText`'s N, for s > 0 only.
        pub fn mateMoves(s: i16) ?u32 {
            if (s <= mate_threshold) return null;
            const p: i32 = mate_score - @as(i32, s);
            return @intCast(@max(1, @divTrunc(p, 2)));
        }

        /// A line with the PV of DG:93B0 (length DG:B42B) when its first move is the best
        /// move DG:A36C, else the best move alone.
        fn pvLine(r: *Self, st: *const rs.RootState, depth: i16, score: i16, bound: Bound) void {
            const best = st.best_move.*;
            const first: u16 = @as(u16, best[0]) | @as(u16, best[1]) << 8;
            const n: usize = @intCast(std.math.clamp(@as(i16, st.pv_length.*), 1, 37));
            if (st.pv[0] & 0x7F7F == first) {
                r.line(depth, score, bound, st.pv[0..n], best[2]);
            } else {
                r.line(depth, score, bound, &.{first}, best[2]);
            }
        }

        /// After the loop's root_search. Returns whether the time control ends the search
        /// after this iteration (engine_root `Observer.iterationDone`).
        fn iterationDone(ctx: *anyopaque, site: u16, hi: i16, lo: i16, res: i16, st: *const rs.RootState) bool {
            _ = hi;
            const r = self(ctx);
            if (st.stop.* != 0) return false; // stopped part-way: the final line says what is kept
            if (res <= lo) {
                r.pvLine(st, st.depth.*, res, .upper);
                if (site == 0x15FA) {
                    // The first root move failed low: the loop re-searches below the window
                    // (0000:165D), the same iteration.
                    r.fail_high_low +|= 1;
                    return false;
                }
            } else {
                r.completed = st.depth.*;
                r.completed_score = res;
                r.pvLine(st, st.depth.*, res, .exact);
            }
            // The iteration is over (Juggernaut's ShouldExit(depth, ...)).
            const it: timecontrol.Iteration = .{
                .depth = @intCast(@max(st.depth.*, 1)),
                .score = res,
                .best_move = rootMoveKey(&r.board, st.best_move[0..3].*),
                .fail_high_low = r.fail_high_low,
                .nodes = r.root.live_nodes,
                .elapsed_ms = @intCast(r.elapsedMs()),
                .pondering = r.pondering(),
                .mate_moves = mateMoves(res),
            };
            r.iter_best = null;
            r.fail_high_low = 0;
            if (r.log.n < r.log.iterations.len) {
                r.log.iterations[r.log.n] = it;
                r.log.n += 1;
            }
            const tc = r.tc orelse return false;
            tc.move_count = @intCast(@max(st.legal_count.*, 0));
            if (tc.shouldStopAfterIteration(it)) {
                r.log.stopped_after = st.depth.*;
                return true;
            }
            return false;
        }

        /// The last line before `bestmove`: the best move [A36C] and the PV, the score of the
        /// last line (or, if none, [A8DA], the root's last score), with the nodes and time
        /// of the whole search. `searched` false: main played without a search (one legal
        /// move at a timed level, a tablebase or book move, 0FF6): depth 0.
        pub fn final(r: *Self, searched: bool) void {
            if (!r.enabled) return;
            const s = r.root;
            // A view of the root's state for `pvLine`, only read here, bound as the loop's
            // view is (Stage B step 8, stage 7: `rootsearch.bindRoot`, `bindDomain`): the PV
            // row of ply 1 is the node's `State.pv[1]`, the best move DG:A36C and the PV's
            // length DG:B42B are `RootVars`'.
            var st: rs.RootState = .{};
            const d = s.node.dom;
            rs.bindRoot(&st, &d.rv, &d.pg);
            rs.bindDomain(&st, s.node_state, &d.p, &d.ev, &d.tv, &d.s);
            if (!searched) {
                // No search, so no score of one: the move alone.
                var mb: [5]u8 = undefined;
                const b = st.best_move.*;
                const promo: u8 = if ((r.board[b[0]] == 1 or r.board[b[0]] == 8) and (b[1] >= 91 or b[1] <= 28)) b[2] else 0;
                r.out.print("info depth 0 nodes {d} time {d} pv {s}", .{ r.root.nodes, r.elapsedMs(), fen.formatMove(.{ .from = b[0], .to = b[1], .promotion = promo }, &mb) });
                return;
            }
            if (!r.have_score) {
                // Stopped before any root move had a score: root_search keeps the first
                // move of the root list (0000:22C0 sets [A36C] to it), ordered by the
                // pre-scoring; there is no score of a search to give.
                var mb: [5]u8 = undefined;
                const b = st.best_move;
                const promo: u8 = if ((r.board[b[0]] == 1 or r.board[b[0]] == 8) and (b[1] >= 91 or b[1] <= 28)) b[2] else 0;
                r.out.print("info depth 1 seldepth {d} nodes {d} time {d} pv {s}", .{ @max(r.root.max_ply - 1, 1), r.root.nodes, r.elapsedMs(), fen.formatMove(.{ .from = b[0], .to = b[1], .promotion = promo }, &mb) });
                r.out.line("info string stopped before the first root move was scored: the first move of the root list, no score");
                return;
            }
            // The last line already says it all when the search has not moved on since.
            if (r.last_nodes == r.root.nodes and r.bound == .exact and r.lines > 0) return;
            r.pvLine(&st, r.depth, r.score, r.bound);
        }
    };
}

test "scoreText: the original's displayed score (half the raw one, truncated toward zero) and its mate scores" {
    var b: [16]u8 = undefined;
    try std.testing.expectEqualStrings("cp 51", scoreText(103, &b));
    try std.testing.expectEqualStrings("cp -51", scoreText(-103, &b));
    try std.testing.expectEqualStrings("cp 0", scoreText(1, &b));
    try std.testing.expectEqualStrings("cp 0", scoreText(-1, &b));
    try std.testing.expectEqualStrings("cp 0", scoreText(0, &b));
    try std.testing.expectEqualStrings("cp 47", scoreText(94, &b));
    try std.testing.expectEqualStrings("cp -9849", scoreText(-19699, &b));
    // The display's boundary: a mate only above 19700 in magnitude.
    try std.testing.expectEqualStrings("cp 9850", scoreText(19700, &b));
    try std.testing.expectEqualStrings("cp -9850", scoreText(-19700, &b));
    try std.testing.expectEqualStrings("mate 149", scoreText(19701, &b));
    try std.testing.expectEqualStrings("mate -149", scoreText(-19701, &b));
    try std.testing.expectEqual(@as(?u32, null), Reporter(struct {}).mateMoves(19700));
    try std.testing.expectEqual(@as(?u32, 149), Reporter(struct {}).mateMoves(19701));
    try std.testing.expectEqual(@as(?u32, 1), Reporter(struct {}).mateMoves(19998));
    try std.testing.expectEqual(@as(?u32, null), Reporter(struct {}).mateMoves(-19998));
    try std.testing.expectEqualStrings("mate 1", scoreText(19998, &b));
    try std.testing.expectEqualStrings("mate 1", scoreText(20000, &b));
    try std.testing.expectEqualStrings("mate 2", scoreText(19996, &b));
    try std.testing.expectEqualStrings("mate 3", scoreText(19994, &b));
    try std.testing.expectEqualStrings("mate -1", scoreText(-19997, &b));
    try std.testing.expectEqualStrings("mate -2", scoreText(-19995, &b));
}
