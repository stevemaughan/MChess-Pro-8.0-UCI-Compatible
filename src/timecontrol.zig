//! UCI time management: Juggernaut's `TTimeControl` as a pure unit (docs/UCI_TIME.md
//! sections 2 to 4; owner decision 20, AGENTS.md section 14).
//!
//! Not a port of MChess code: a port of `..\Juggernaut\uChessTimeControls.pas` as it
//! stood on 2026-11-19, giving the Pascal's results for the same inputs. Its reference is
//! the line-by-line transcription `tools/research/uci_time/juggernaut_tc.py`; line numbers
//! below are the Pascal's. The unit has no clock of its own: every test takes the
//! elapsed milliseconds as a parameter, so a scripted clock can drive it.
//!
//! How the engine uses it (docs/UCI_TIME.md section 4):
//! - `setLimits` with what the `go` line gave, then `start` when the search begins;
//! - `shouldStopInSearch` at the 1024-node test; with `go nodes N`, `nodeLimitReached`
//!   at every node;
//! - `shouldStopAfterIteration` when an iteration's result is observed.
//!
//! Two rules differ from Juggernaut on purpose (docs/UCI_TIME.md section 4): a depth limit
//! applies together with a clock, movetime, nodes or mate limit, whichever comes first;
//! and `go mate N` is decided from the caller's mate distance, not from Juggernaut's
//! mate-score arithmetic, which it is equivalent to.
//!
//! Three faults of the Pascal are corrected in MChess's copy (owner decision 26): two behind
//! the switch `Fixes.juggernaut_faults`, and a third, found 2026-11-22, the reserve kept
//! from the clock, behind `Fixes.clock_reserve`; both are held in the field `fixes`. A
//! `TimeControl` starts corrected (`.{}` and `init()`), so the engine has the corrections;
//! the replay of the Pascal's vectors sets `fixes = .original`, which is the Pascal exactly.
//!
//! Floating point: every expression is evaluated in IEEE double, in the Pascal's order,
//! with the float mode strict (no contraction into fused multiply-add, no reassociation),
//! so the results do not depend on the build mode.

const std = @import("std");

/// A move, in the caller's own encoding: only compared for equality.
pub const Move = u32;

/// MAXSEARCHDEPTH, uChessConstants.pas 49.
pub const max_search_depth: u16 = 255;
/// MAX_BRANCHING_FACTOR, line 98.
pub const max_branching_factor: f64 = 4.0;
/// ROOT_TROUBLE_MARGIN, uChessSearch.pas 133.
pub const root_trouble_margin: i32 = 50;
/// The Move Overhead option's default for MChess (docs/UCI_TIME.md section 4; Juggernaut's is 10).
pub const default_move_overhead: u32 = 30;

/// TSearchType, line 10 (stPerft is not used).
pub const Kind = enum { clock, movetime, depth, nodes, mate, infinite };

/// What the `go` line set (the TTimeControl properties, lines 74-86).
pub const Limits = struct {
    kind: Kind = .infinite,
    wtime: u32 = 0,
    btime: u32 = 0,
    winc: u32 = 0,
    binc: u32 = 0,
    movestogo: u16 = 0,
    movetime: u32 = 0,
    /// With `.depth` the limit itself; with any other kind, an extra limit (0: none).
    depth: u16 = 0,
    nodes: u64 = 0,
    /// `go mate N`: stop once an iteration's score is a mate in N moves or fewer.
    mate: u8 = 0,
    move_overhead: u32 = default_move_overhead,
};

pub const Side = enum { white, black };

/// The move expected before the search (Juggernaut's hash move, line 371), and its
/// target square, for the recapture test of line 272.
pub const Expected = struct { move: Move, to: u8 };

/// One completed iteration, as the root loop hands it over (uChessSearch.pas 2361).
pub const Iteration = struct {
    /// The iteration number, 1 or more.
    depth: u16,
    /// The root score (stored as a SmallInt, line 262).
    score: i32,
    best_move: Move,
    /// Root re-searches in this iteration (Byte).
    fail_high_low: u8,
    nodes: u64,
    elapsed_ms: i64,
    pondering: bool = false,
    /// The score is a mate in this many moves for the side to move; null otherwise.
    mate_moves: ?u32 = null,
};

/// The corrections of Juggernaut's faults (owner decision 26, 2026-11-20; the reserve,
/// 2026-11-22).
pub const Fixes = struct {
    /// Two faults of uChessTimeControls.pas, corrected together:
    /// - the opponent's-clock adjustment (line 396) runs after the `Max(1, ...)` of line
    ///   392, so the target can round down to 0; corrected, it is at least 1 afterwards too;
    /// - fBestMove / fBestScore are never cleared, and an iteration ending while pondering
    ///   returns (line 256) before recording its move, score and fail count (260-262), so
    ///   after `ponderhit` the stability tests (291, 294, 297) could read a previous
    ///   search's entries; corrected, `start` clears the history and a pondered iteration
    ///   records its results before returning false. Nothing stops on time while pondering.
    juggernaut_faults: bool,
    /// A third fault, found 2026-11-22 (a game lost on time on the last move before a
    /// control): `panic` and `max` (402) may be the whole clock but twice the Move Overhead,
    /// so with one move to go, or an increment larger than the clock, a move may use all but
    /// 60 ms. Corrected, neither exceeds the clock less a reserve of a fifth of it, and at
    /// least the Move Overhead: `reserveCap`. The target is left as it is: it is not a
    /// limit (it only decides whether another iteration is begun, and an iteration begun is
    /// still cut at `panic`), and capping it would change the cells where the limits are
    /// already inside the reserve.
    clock_reserve: bool,

    pub const original: Fixes = .{ .juggernaut_faults = false, .clock_reserve = false };
    /// The two corrections of decision 26 alone: what tests/golden/timecontrol/
    /// timecontrol_fixed.zst records.
    pub const decision26: Fixes = .{ .juggernaut_faults = true, .clock_reserve = false };
    pub const corrected: Fixes = .{ .juggernaut_faults = true, .clock_reserve = true };
};

/// The most `panic` and `max` may be with the clock reserve on (`Fixes.clock_reserve`): the
/// mover's clock less a fifth of it, and less at least the Move Overhead. It binds only
/// where `panic` is over four fifths of a clock of more than five times the overhead
/// (`max` exceeds `panic` only up to a fifth of the clock); below that, the Pascal's
/// `x - 2 * ovh` is already the tighter limit.
pub fn reserveCap(x_time: i64, move_overhead: i64) i64 {
    return x_time - @max(move_overhead, @divTrunc(x_time, 5));
}

pub const TimeControl = struct {
    /// Which of the Pascal's faults are corrected; the engine keeps the default.
    fixes: Fixes = .corrected,
    /// The caller's score units to the centipawn, the unit of Juggernaut's margins (its pawn
    /// is 100: the 25 of StableScore, line 349, and ROOT_TROUBLE_MARGIN, 50). 1, the
    /// default, is the Pascal's own, which the recorded vectors replay; MChess sets 2, its
    /// pawn being 200 (the piece values at DG:1498; docs/UCI_TIME.md section 4), so that
    /// the margins are 50 and 100 of its units: exact, with no rounding of a score.
    score_unit: i32 = 1,
    limits: Limits = .{},
    /// fTargetTime, fPanicTime, fMaxTime (Int64), lines 383-402.
    target: i64 = 0,
    panic: i64 = 0,
    max: i64 = 0,
    root_trouble: bool = false,
    fail_high_low: u8 = 0,
    /// fHashMove and its target square; null: no expected move.
    expected: ?Expected = null,
    /// RawMoveList[fPreviousMove].ToSquare; null: no previous move.
    previous_to: ?u8 = null,
    /// fMoveCount (Byte).
    move_count: u8 = 0,
    /// fBestMove / fBestScore, lines 43-44. In the Pascal never cleared: they carry over
    /// from one search to the next; corrected, `start` clears them. Slot 0 is never
    /// written (iterations start at 1).
    best_move: [max_search_depth + 1]?Move = @splat(null),
    best_score: [max_search_depth + 1]i16 = @splat(0),
    /// The scaling factor and branching factor of the last end-of-iteration test with a
    /// clock (diagnostics; read by the tests and by reporting, never by the rules).
    last_factor: f64 = 0,
    last_branching: f64 = 0,

    pub fn init() TimeControl {
        return .{};
    }

    pub fn setLimits(self: *TimeControl, limits: Limits) void {
        self.limits = limits;
    }

    /// StartSearch, lines 358-405, without the stopwatch (the caller owns the clock).
    pub fn start(self: *TimeControl, side_to_move: Side, expected: ?Expected, previous_to: ?u8, root_move_count: u8) void {
        @setFloatMode(.strict);
        const lim = self.limits;
        if (self.fixes.juggernaut_faults) {
            // Corrected: the history of this search starts empty.
            self.best_move = @splat(null);
            self.best_score = @splat(0);
        }
        if (lim.kind != .clock) return; // 367
        self.expected = expected; // 371
        self.previous_to = previous_to; // 372
        self.move_count = root_move_count; // 373
        const white = side_to_move == .white;
        // 376-379: Max(0, Cardinal) is the Cardinal itself.
        const x_time: i64 = if (white) lim.wtime else lim.btime;
        const o_time: i64 = if (white) lim.btime else lim.wtime;
        const x_inc: i64 = if (white) lim.winc else lim.binc;
        const x_ovh: i64 = lim.move_overhead;
        if (lim.movestogo > 0) {
            // 383: Int64 arithmetic; div truncates (all operands here are non-negative).
            self.target = @max(1, @divTrunc(x_time, lim.movestogo) + @divTrunc(x_inc * 4, 5) - x_ovh);
            // 384: `2 * fMoveOverhead` uses the Cardinal field, not the Int64 xOverhead:
            // Cardinal times a constant is a Cardinal product, which wraps modulo 2^32
            // (overflow checks off); it is then widened and subtracted in Int64.
            const two_ovh: i64 = @as(u32, 2 *% lim.move_overhead);
            self.panic = @min(x_time - two_ovh, @divTrunc(self.target * 3, 2));
        } else {
            const base_time = @divTrunc(x_time, 25); // 390
            const increment_bonus = @divTrunc(x_inc * 4, 5); // 391
            self.target = @max(1, base_time + increment_bonus - x_ovh); // 392
            // 395-396: Round(sqrt(xTime / oTime) * fTargetTime) in Double; Round is
            // CVTSD2SI on Win64, round to nearest with ties to even.
            if (lim.winc == lim.binc and o_time > 0 and x_time > 0) {
                const ratio = @as(f64, @floatFromInt(x_time)) / @as(f64, @floatFromInt(o_time));
                self.target = roundHalfEven(@sqrt(ratio) * @as(f64, @floatFromInt(self.target)));
                // Corrected: at least 1 after the adjustment too (the Pascal can give 0).
                if (self.fixes.juggernaut_faults) self.target = @max(1, self.target);
            }
            self.panic = @min(x_time - 2 * x_ovh, @divTrunc(self.target * 3, 2)); // 398
        }
        // 402
        self.max = @max(self.panic, @min(x_time - 2 * x_ovh, @min(self.target * 4, @divTrunc(x_time, 5))));
        if (self.fixes.clock_reserve) {
            // Corrected: no move may use the reserve (docs/UCI_TIME.md section 2).
            const cap = reserveCap(x_time, x_ovh);
            self.panic = @min(self.panic, cap);
            self.max = @min(self.max, cap);
        }
        self.root_trouble = false; // 403
    }

    /// ShouldExit(state), lines 222-237: the test inside an iteration, made where UCI
    /// `stop` is tested. `root_trouble` is Juggernaut's RootTrouble (see `rootTrouble`).
    pub fn shouldStopInSearch(self: *TimeControl, elapsed_ms: i64, nodes: u64, root_trouble: bool, pondering: bool) bool {
        self.root_trouble = root_trouble;
        const lim = self.limits;
        return switch (lim.kind) {
            .clock => !pondering and elapsed_ms >= (if (self.root_trouble) self.max else self.panic), // 230
            .movetime => !pondering and elapsed_ms >= @max(1, @as(i64, lim.movetime) - @as(i64, lim.move_overhead)), // 231
            .nodes => nodes >= lim.nodes, // 234
            .depth, .infinite, .mate => false,
        };
    }

    /// `go nodes N`: the same comparison as line 234, which the caller makes at every
    /// node so that the same N always stops at the same node (docs/UCI_TIME.md section 4).
    pub fn nodeLimitReached(self: *const TimeControl, nodes: u64) bool {
        return self.limits.kind == .nodes and nodes >= self.limits.nodes;
    }

    /// ShouldExit(depth, ...), lines 240-322: the test at the end of an iteration, plus
    /// the MChess depth limit that applies together with any other kind.
    pub fn shouldStopAfterIteration(self: *TimeControl, it: Iteration) bool {
        var r = self.juggernautIteration(it);
        const lim = self.limits;
        if (lim.kind != .depth and lim.depth > 0 and it.depth >= lim.depth) r = true;
        return r;
    }

    fn juggernautIteration(self: *TimeControl, it: Iteration) bool {
        @setFloatMode(.strict);
        std.debug.assert(it.depth >= 1);
        if (it.depth >= max_search_depth) return true; // 247
        const lim = self.limits;
        switch (lim.kind) {
            .clock => {
                // Corrected: lines 260-262 run before the pondering exit, so that after
                // `ponderhit` the stability tests read this search's own iterations.
                if (it.pondering and !self.fixes.juggernaut_faults) return false; // 256
                const d: usize = it.depth;
                self.fail_high_low = it.fail_high_low; // 260
                self.best_move[d] = it.best_move; // 261
                // 262: an Integer stored in a SmallInt keeps its low 16 bits (range checks off);
                // the same truncation passes AScore to StableScore's SmallInt parameter (297).
                const score16: i16 = @truncate(it.score);
                self.best_score[d] = score16;
                if (it.pondering) return false; // 256, corrected
                var f: f64 = 1; // 265
                if (self.expected) |e| {
                    if (e.move == it.best_move) { // 268
                        // 272: the expected move lands on the square the opponent just moved to
                        if (self.previous_to != null and self.previous_to.? == e.to)
                            f = f * 0.5 // 273
                        else
                            f = f * 0.9; // 275
                    }
                }
                f = f * (if (self.move_count == 1) @as(f64, 0.15) else 1.0); // 280
                switch (self.fail_high_low) { // 283-288
                    0 => {},
                    1 => f = f * 1.2,
                    else => f = f * 1.4,
                }
                // 291-294 (ADepth > 0 always holds here)
                if (self.best_move[d - 1] == null or self.best_move[d - 1].? != it.best_move)
                    f = f * 1.3
                else
                    f = f * (if (self.stableMove(d, it.best_move)) @as(f64, 0.7) else 1.2);
                f = f * (if (self.stableScore(d, score16)) @as(f64, 0.8) else 1.3); // 297
                // 301: EnsureRange(ScalingFactor, 0.15 / 1.4, 2.0 / 1.4), the bounds taken
                // as the Double quotient of the Double literals (a 64-bit compile's Extended
                // is Double). Written as bit patterns because the exact quotient, which Zig's
                // comptime_float arithmetic and an 80-bit fold both give, is one unit in the
                // last place smaller for the lower bound (0x1.b6db6db6db6dbp-4).
                const lo: f64 = 0x1.b6db6db6db6dcp-4; // 0.15 / 1.4 in Double
                const hi: f64 = 0x1.6db6db6db6db7p+0; // 2.0 / 1.4 in Double (both ways)
                if (f < lo) f = lo;
                if (f > hi) f = hi;
                // 305: Min(Power(ANodes, 1 / ADepth), MAX_BRANCHING_FACTOR)
                const exponent = 1.0 / @as(f64, @floatFromInt(it.depth));
                const b = @min(delphiPower(@floatFromInt(it.nodes), exponent), max_branching_factor);
                self.last_factor = f;
                self.last_branching = b;
                // 306: left to right in Double
                const lhs = @as(f64, @floatFromInt(it.elapsed_ms)) * b;
                const rhs = ((@as(f64, @floatFromInt(self.target)) * 1.5) * 1.4) * f;
                return lhs >= rhs;
            },
            .movetime => {
                if (it.pondering) return false; // 312
                return it.elapsed_ms >= lim.movetime; // 315
            },
            .depth => return it.depth >= lim.depth, // 317
            .infinite => return false, // 318
            .nodes => return it.nodes >= lim.nodes, // 319
            // 320: AScore >= CHECKMATESCORE - 2 * fMate + 1; a mate in M moves scores
            // CHECKMATESCORE - (2M - 1) there, so this holds exactly when M <= fMate.
            .mate => return if (it.mate_moves) |m| m <= lim.mate else false,
        }
    }

    /// StableMove, lines 324-339.
    fn stableMove(self: *const TimeControl, depth: usize, move: Move) bool {
        if (depth < 7) return false;
        for (self.best_move[depth - 6 .. depth]) |m| {
            if (m == null or m.? != move) return false;
        }
        return true;
    }

    /// StableScore, lines 341-356 (the difference is taken in Integer): within 25
    /// centipawns, `25 * score_unit` of the caller's units.
    fn stableScore(self: *const TimeControl, depth: usize, score: i16) bool {
        if (depth < 7) return false;
        for (self.best_score[depth - 6 .. depth]) |s| {
            if (@abs(@as(i32, s) - @as(i32, score)) > 25 * self.score_unit) return false;
        }
        return true;
    }

    /// `rootTrouble` in this time control's score unit.
    pub fn rootTroubleOf(self: *const TimeControl, completed_depth: u16, completed_score: i32, best_score: i32) bool {
        return rootTrouble(completed_depth, completed_score, best_score, self.score_unit);
    }
};

/// Juggernaut's RootTrouble (uChessSearch.pas 2342): an iteration has been completed and
/// the best score so far in this one is more than 50 centipawns (`root_trouble_margin`
/// times `score_unit` of the caller's units) below its score. Cleared at the end of an
/// iteration (2348), which the caller does by passing false.
pub fn rootTrouble(completed_depth: u16, completed_score: i32, best_score: i32, score_unit: i32) bool {
    return completed_depth > 0 and best_score < completed_score - root_trouble_margin * score_unit;
}

test "time control: the score unit scales StableScore's 25 and RootTrouble's 50 (MChess: 2, a pawn 200)" {
    // Six iterations within 40 of the last: not stable at unit 1 (40 > 25), stable at unit
    // 2 (40 <= 50).
    var tc: TimeControl = .{};
    for (1..8) |d| tc.best_score[d] = if (d % 2 == 0) 140 else 100;
    try std.testing.expect(!tc.stableScore(7, 100));
    tc.score_unit = 2;
    try std.testing.expect(tc.stableScore(7, 100));
    try std.testing.expect(!tc.stableScore(7, 89)); // 140 - 89 = 51 > 50
    // Root trouble: a drop of more than 50 centipawns. Unit 2: a raw drop of exactly 100
    // is not trouble, 101 is; unit 1: 51 is, 50 is not.
    try std.testing.expect(!rootTrouble(3, 200, 100, 2));
    try std.testing.expect(rootTrouble(3, 200, 99, 2));
    try std.testing.expect(rootTrouble(3, 200, 149, 1));
    try std.testing.expect(!rootTrouble(3, 200, 150, 1));
    try std.testing.expect(!rootTrouble(0, 200, -1000, 2)); // no iteration completed
    try std.testing.expect(!tc.rootTroubleOf(3, 200, 100));
    try std.testing.expect(tc.rootTroubleOf(3, 200, 99));
}

/// System.Round on Win64 (System.pas 11691, `CVTSD2SI RAX, XMM0`): round to nearest, ties
/// to even, the default MXCSR mode. Only non-negative values below 2^52 occur here.
fn roundHalfEven(x: f64) i64 {
    @setFloatMode(.strict);
    const fl = @floor(x);
    const frac = x - fl; // exact for |x| < 2^52
    var n: i64 = @intFromFloat(fl);
    if (frac > 0.5 or (frac == 0.5 and (n & 1) != 0)) n += 1;
    return n;
}

/// System.Math.Power(Double, Double) (System.Math.pas 4018-4036, the Win64 path): 1 for
/// exponent 0; 0 for base 0 and exponent > 0; IntPower for an integral exponent; else
/// Exp(Exponent * Ln(Base)). Delphi's Win64 Exp and Ln are its own SSE routines; @exp and
/// @log stand in for them and may differ from them in the last bit.
fn delphiPower(base: f64, exponent: f64) f64 {
    @setFloatMode(.strict);
    if (exponent == 0.0) return 1.0;
    if (base == 0.0 and exponent > 0.0) return 0.0;
    if (exponent == @trunc(exponent) and @abs(exponent) <= 2147483647.0) {
        // IntPower (System.Math.pas 1599): square and multiply.
        const n: i64 = @intFromFloat(exponent);
        var k: u64 = @abs(n);
        var r: f64 = 1.0;
        var b = base;
        while (k != 0) : (k >>= 1) {
            if (k & 1 != 0) r = r * b;
            b = b * b;
        }
        return if (n < 0) 1.0 / r else r;
    }
    return @exp(exponent * @log(base));
}
