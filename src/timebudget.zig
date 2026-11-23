//! The original's time budget, as pure functions over the level settings and the clock
//! state: moves to go (0000:8B7E), the clock helpers of segment 1E9D, the start-of-move
//! block and main's adjustments, `set_time_budget` (0000:8C3E), the first-move fail-low
//! extension, the ponder credit, the clock charge and the two control renewals.
//!
//! Specification: docs/arch/31-root-iteration-time.md §4, whose executable form is
//! tools/research/rootmodel/timebudget.py (matched the original on every real call of
//! 35 runs covering every level, §7.2). Test: src/timebudget_test.zig, which replays
//! calls recorded from the original (tests/golden/timebudget/).
//!
//! **Unit of time.** Every time here is in ticks of the original's INT 8 clock,
//! 18.2065 Hz (91 ticks = 5 s, 1,092 ticks = 1 minute). The rules depend on it: the
//! 30-tick reserve, the 54-tick margin of the fail-low extension, the 35/40/45/50
//! thresholds at 2,730/1,638/1,092 ticks, the 364-tick test and the 3,400/speed term
//! of the book exit, and the minutes-to-ticks factor 1,092 of the time controls. A
//! caller with a clock in milliseconds converts at the boundary (ticks = ms ×
//! 18.2065 / 1000) and keeps everything in between in ticks.
//!
//! **Integer arithmetic is the original's:** words are `i16`, dwords `i32`, "/" is the
//! C run-time's signed long division 4793:8AF0 (toward zero), multiplications keep the
//! low 32 bits. Wrapping operators mark the places where the original wraps; with real
//! clock values nothing comes near the limits.
//!
//! There are no class C corrections in this unit (none was found, §"Suspected bugs"),
//! so it has no `Fixes` parameter.

const std = @import("std");
const dg = @import("original.zig").dgroup;

/// Ticks per minute (0x444), the factor the time-control helpers use.
pub const ticks_per_minute: i32 = 1092;

/// DG:1240: the preset seconds per move, dword[10], read from the original:
/// {0, 2, 5, 10, 15, 30, 45, 60, 120, 180}.
pub const preset_seconds_table: [10]i32 = blk: {
    const raw = dg(0x1240, 40);
    var t: [10]i32 = undefined;
    for (0..10) |i| t[i] = std.mem.readInt(i32, raw[4 * i ..][0..4], .little);
    break :blk t;
};

/// Level type DG:A274.
pub const level_per_move: u8 = 0;
pub const level_game_in: u8 = 1;
pub const level_time_controls: u8 = 2;
pub const level_fixed_depth: u8 = 3;
pub const level_mate_in: u8 = 4;
pub const level_shortest_mate: u8 = 5;
pub const level_infinite: u8 = 6;
pub const level_correspondence: u8 = 7;

/// A level-2 time-control record of one side, DG:B4C2 + 14·side: "M1 moves in T1
/// minutes, then M2 in T2, then M3 in T3", and the move number after which the next
/// control is no longer advanced (moves to go then comes from the time-left thresholds).
pub const ControlRecord = extern struct {
    m1: i16 = 0, // +00
    m2: i16 = 0, // +02
    m3: i16 = 0, // +04
    t1: i16 = 0, // +06 minutes
    t2: i16 = 0, // +08
    t3: i16 = 0, // +0A
    last: i16 = 0, // +0C
};

/// The inputs and outputs of the time budget, by DGROUP address (side 0 White, 1 Black).
/// The level settings and clock state are inputs; `mtg`, `last_before_control`,
/// `clear_best`, `single_move`, `base`, `hard`, `soft`, `fail_high`, `time_left` and
/// `next_control` are what the functions write.
///
/// Since Stage B step 8, stage 5 (docs/arch/60-engine-assembly.md section 10.7.13), the
/// value fields are the variables no other struct of the engine declares: `TimeState` is
/// their one home (in the engine, the persistent `engine_state.Members.ts`). Every other
/// field is a pointer to the variable's one home, bound before use, as `gamemove.GameVars`'
/// are: the member of the node domain that holds it (pondering and the clock side, the game
/// ply: `Position`; `hard`: `EvalVars`; the book-exit ply, analysis, `clear_best`: the
/// threat evaluators' tails; `engine_state` `bindTimeState`), or, for a variable the root's
/// views, main's low page or the game-move path also declare, its home since Stage B step 8,
/// stage 7, `rootvars.RootVars` (an image's bytes for a routine run on an image,
/// `bindImage`). A routine run without
/// the engine (the replay test, a computation on copied values) binds them to a `Values`
/// (`bindValues`). A side or flag is a byte, read as the original's narrow test reads it
/// (`computerSide`, `isPondering`, ...); a multi-byte pointer is `align(1)`: it points at
/// the original's bytes.
pub const TimeState = struct {
    // ---- the level -------------------------------------------------------------
    /// DG:A274: 0 per move (preset), 1 game in, 2 time controls; 3.. untimed.
    level: *u8 = undefined,
    /// DG:A8C6: preset index 0..9 (level 0; 0 is "Instant response").
    preset: *u8 = undefined,
    /// DG:1240: preset seconds, dword[10].
    preset_seconds: [10]i32 = preset_seconds_table,
    /// DG:1DFC: Game in N minutes.
    game_in: i16 = 0,
    /// DG:B4C2 + 14·side: the level-2 records (DG:B4CE and B4DC are also `PrepState`'s).
    tc: *align(1) [2]ControlRecord = undefined,
    // ---- sides and modes -------------------------------------------------------
    /// DG:8DDE: the side the computer moves for (bit 0: `computerSide`).
    computer_side: *u8 = undefined,
    /// DG:717C: the opponent's side (bit 0: `opponentSide`).
    opponent_side: *u8 = undefined,
    /// DG:9EEC: the side whose clock runs (bit 0: `clockSide`).
    clock_side: *u8 = undefined,
    /// DG:3676: pondering (non-zero: `isPondering`).
    pondering: *u8 = undefined,
    /// DG:9FCF: analysis mode (non-zero: `inAnalysis`).
    analysis: *u8 = undefined,
    // ---- the game and the clocks -------------------------------------------------
    /// DG:A84A: move number (full moves).
    move_number: *align(1) i16 = undefined,
    /// DG:73FA + 2·side: move number of the side's next time control.
    next_control: *align(1) [2]i16 = undefined,
    /// DG:77EC + 4·side: time left, ticks.
    time_left: *align(1) [2]i32 = undefined,
    /// DG:9FC8: game ply.
    game_ply: *align(1) i16 = undefined,
    /// DG:9FBC: game ply at which the book was left (0 while in book).
    book_exit_ply: *align(1) i16 = undefined,
    /// DG:7258: machine-speed calibration from start-up (1,252 on the emulated machine
    /// with the exact clock, 1,378 with `--fast`). Must be non-zero.
    speed: i32 = 1252,
    /// DG:2902: right shift applied to the base (its low byte); 0 in every run.
    base_shift: u16 = 0,
    /// DG:58 + side: ticks to the next second of the displayed clock (signed byte), in
    /// main's low page.
    tick58: *[2]i8 = undefined,
    /// DG:8DD2 + 6·side: the displayed clock h, m, s.
    display: [2][3]i16 = .{ .{ 0, 0, 0 }, .{ 0, 0, 0 } },
    // ---- outputs (also inputs: stale values are kept at the untimed levels) ------
    /// DG:A22C: "clear best move" (the easy-move flag).
    clear_best: *u8 = undefined,
    /// DG:1480: 1 for a level-2 one-move control with no second period.
    single_move: *align(1) i16 = undefined,
    /// DG:A3F6: 1 when moves to go ≤ 1 (the last move before the control).
    last_before_control: *u8 = undefined,
    /// DG:7102: moves to go.
    mtg: *align(1) i16 = undefined,
    /// DG:8D06: base time.
    base: *align(1) i32 = undefined,
    /// DG:9DB8: hard limit.
    hard: *align(1) i32 = undefined,
    /// DG:A362: soft limit.
    soft: *align(1) i32 = undefined,
    /// DG:B59A: fail-high limit.
    fail_high: *align(1) i32 = undefined,

    /// Storage for every pointer field, for a `TimeState` that runs on values of its own
    /// (`bindValues`): the replay test, and root_search's fail-low extension, which runs
    /// on copies of the loop's variables. The defaults are those of a fresh game at 5 s
    /// per move.
    pub const Values = struct {
        level: u8 = level_per_move,
        preset: u8 = 2,
        tc: [2]ControlRecord = .{ .{}, .{} },
        computer_side: u8 = 1,
        opponent_side: u8 = 0,
        clock_side: u8 = 1,
        pondering: u8 = 0,
        analysis: u8 = 0,
        move_number: i16 = 1,
        next_control: [2]i16 = .{ 0, 0 },
        time_left: [2]i32 = .{ 0, 0 },
        game_ply: i16 = 0,
        book_exit_ply: i16 = 0,
        tick58: [2]i8 = .{ 0, 0 },
        clear_best: u8 = 0,
        single_move: i16 = 0,
        last_before_control: u8 = 0,
        mtg: i16 = 0,
        base: i32 = 0,
        hard: i32 = 0,
        soft: i32 = 0,
        fail_high: i32 = 0,
    };

    /// Points every pointer field at its storage in `v`.
    pub fn bindValues(st: *TimeState, v: *Values) void {
        inline for (@typeInfo(TimeState).@"struct".field_names) |name| {
            if (comptime isPointerVar(name)) @field(st, name) = &@field(v, name);
        }
    }

    /// Points every pointer field at its variable in the DGROUP image `img` (the time
    /// budget run on the image: inside an image bracket, or a test outside the domain).
    pub fn bindImage(st: *TimeState, img: *[0x10000]u8) void {
        inline for (@typeInfo(TimeState).@"struct".field_names) |name| {
            if (comptime isPointerVar(name)) {
                const n = comptime varBytes(name);
                @field(st, name) = @ptrCast(img[@field(var_addresses, name)..][0..n]);
            }
        }
    }

    /// The side bytes as the original's helpers test them: bit 0 (a side is 0 or 1).
    pub fn computerSide(st: *const TimeState) u1 {
        return @truncate(st.computer_side.*);
    }
    pub fn opponentSide(st: *const TimeState) u1 {
        return @truncate(st.opponent_side.*);
    }
    pub fn clockSide(st: *const TimeState) u1 {
        return @truncate(st.clock_side.*);
    }
    /// The flag bytes: any non-zero value is set.
    pub fn isPondering(st: *const TimeState) bool {
        return st.pondering.* != 0;
    }
    pub fn inAnalysis(st: *const TimeState) bool {
        return st.analysis.* != 0;
    }

    /// The move number every clock helper uses (1E9D:6BB9, 6CA2, 6D14, 6DDF, 6E51,
    /// 7082): while Black's clock runs, White's count is one ahead, and one behind
    /// again while pondering.
    pub fn adjustedMoveNumber(st: *const TimeState, side: u1) i16 {
        var c: i32 = st.move_number.*;
        if (st.clockSide() == 1) {
            if (side == 0) c += 1;
            if (st.isPondering()) c -= 1;
        }
        return @truncate(c);
    }

    /// The four limits, ticks of elapsed time since the start of thinking.
    pub fn limits(st: *const TimeState) Limits {
        return .{ .base = st.base.*, .hard = st.hard.*, .soft = st.soft.*, .fail_high = st.fail_high.* };
    }
};

/// Whether `name` is a pointer field of `TimeState` (its home is another struct or the
/// image), and the number of the original's bytes a field covers.
pub fn isPointerVar(comptime name: []const u8) bool {
    return @typeInfo(@FieldType(TimeState, name)) == .pointer;
}
pub fn varBytes(comptime name: []const u8) usize {
    const F = @FieldType(TimeState, name);
    const T = if (@typeInfo(F) == .pointer) @typeInfo(F).pointer.child else F;
    return @sizeOf(T);
}

/// DGROUP address of each `TimeState` field (for the binding, the maps and the tests).
pub const var_addresses = .{
    .level = 0xA274,
    .preset = 0xA8C6,
    .preset_seconds = 0x1240,
    .game_in = 0x1DFC,
    .tc = 0xB4C2,
    .computer_side = 0x8DDE,
    .opponent_side = 0x717C,
    .clock_side = 0x9EEC,
    .pondering = 0x3676,
    .analysis = 0x9FCF,
    .move_number = 0xA84A,
    .next_control = 0x73FA,
    .time_left = 0x77EC,
    .game_ply = 0x9FC8,
    .book_exit_ply = 0x9FBC,
    .speed = 0x7258,
    .base_shift = 0x2902,
    .tick58 = 0x0058,
    .display = 0x8DD2,
    .clear_best = 0xA22C,
    .single_move = 0x1480,
    .last_before_control = 0xA3F6,
    .mtg = 0x7102,
    .base = 0x8D06,
    .hard = 0x9DB8,
    .soft = 0xA362,
    .fail_high = 0xB59A,
};

/// The limits the search is run against (§4.4).
pub const Limits = struct {
    /// DG:8D06: no new iteration once elapsed ≥ base (and none begun past 60% of it).
    base: i32,
    /// DG:9DB8: stop at once.
    hard: i32,
    /// DG:A362: stop after the first root move when the score holds.
    soft: i32,
    /// DG:B59A: the hard limit while a root fail high is being re-searched.
    fail_high: i32,
};

// ---------------------------------------------------------------------------
// Arithmetic of the C run-time
// ---------------------------------------------------------------------------

/// 4793:8AF0: signed 32-bit division, truncating toward zero (C `long /`). The
/// divisors here are never 0 (a period's move count when its time is non-zero, moves
/// to go when positive, and the speed calibration).
fn ldiv(a: i32, b: i32) i32 {
    return @truncate(@divTrunc(@as(i64, a), @as(i64, b)));
}

/// `imul r/m16`: 16×16 signed, 32-bit result.
fn imul16(a: i16, b: i16) i32 {
    return @as(i32, a) * @as(i32, b);
}

// ---------------------------------------------------------------------------
// The clock helpers
// ---------------------------------------------------------------------------

/// Port of moves_to_go (0000:8B7E). `[73FA + 2·side] − [A84A]`; at level 1, and at
/// level 2 once past the record's last counted control, 35, 40, 45 or 50 by the time
/// left (> 150 s, > 90 s, > 60 s, else). Every caller passes the computer's side, and
/// the level-2 test and the time left are always the computer's side's (§"Suspected
/// bugs").
pub fn movesToGo(st: *const TimeState) i16 {
    const cs = st.computerSide();
    const level = st.level.*;
    if (level == level_game_in or (level == level_time_controls and st.tc[cs].last < st.move_number.*)) {
        const left = st.time_left[cs];
        if (left > 2730) return 35;
        if (left > 1638) return 40;
        if (left > 1092) return 45;
        return 50;
    }
    return st.next_control[cs] -% st.move_number.*;
}

/// The current period's time and move count.
pub const Period = struct { ticks: i32, moves: i16 };

/// Port of control_period (1E9D:6B8C). Level 1: (0, game-in minutes). Level 2: from
/// the side's record. Every other level: five moves at the preset seconds each.
pub fn controlPeriod(st: *const TimeState, side: u1) Period {
    if (st.level.* == level_game_in) return .{ .ticks = 0, .moves = st.game_in };
    if (st.level.* == level_time_controls) {
        const c = st.adjustedMoveNumber(side);
        const r = st.tc[side];
        if (r.m1 == 0) return .{ .ticks = 0, .moves = r.t1 };
        if (c < r.m1 or r.t2 == 0) return .{ .ticks = imul16(1092, r.t1), .moves = r.m1 };
        if (r.m2 == 0) return .{ .ticks = 0, .moves = r.t2 };
        if (r.m1 +% r.m2 > c or r.t3 == 0) return .{ .ticks = imul16(1092, r.t2), .moves = r.m2 };
        if (r.m3 == 0) return .{ .ticks = 0, .moves = r.t3 };
        return .{ .ticks = imul16(1092, r.t3), .moves = r.m3 };
    }
    return .{ .ticks = st.preset_seconds[st.preset.*] *% 91, .moves = 5 };
}

/// The moves in the current period and the first move number after it.
pub const PeriodLength = struct { moves: i16, first: i16 };

/// Port of control_period_length_tc (1E9D:6D00), the level-2 part of 6DB4.
fn periodLengthTc(st: *const TimeState, side: u1) PeriodLength {
    const c = st.adjustedMoveNumber(side);
    const r = st.tc[side];
    if (r.m1 == 0) return .{ .moves = 35, .first = 1 };
    if (r.m1 > c or r.t2 == 0) return .{ .moves = r.m1, .first = 1 };
    var first: i16 = r.m1 +% 1;
    if (r.m2 == 0) return .{ .moves = r.m1, .first = first };
    if (r.m2 +% r.m1 > c or r.t3 == 0) return .{ .moves = r.m2, .first = first };
    first +%= r.m2;
    if (r.m3 == 0) return .{ .moves = r.m2, .first = first };
    return .{ .moves = r.m3, .first = first };
}

/// Port of control_period_length (1E9D:6DB4): 60 moves when the preset is under a
/// minute, else 40, and 20 from move 40 at level 0; at level 2 the record decides.
pub fn periodLength(st: *const TimeState, side: u1) PeriodLength {
    var p: i16 = if (st.preset_seconds[st.preset.*] < 60) 60 else 40;
    if (st.level.* == level_per_move and st.adjustedMoveNumber(side) >= 40 and p == 40) p = 20;
    if (st.level.* == level_time_controls) {
        const r = periodLengthTc(st, side);
        if (r.moves != 0) return r;
    }
    return .{ .moves = p, .first = p + 1 };
}

/// Port of control_period_index (1E9D:6C92): which period of the level-2 record
/// applies at move number − a: 0, 1 or 2.
pub fn periodIndex(st: *const TimeState, a: i16, side: u1) u2 {
    var c: i32 = st.move_number.* -% a;
    if (st.clockSide() == 1) {
        if (side == 0) c += 1;
        if (st.isPondering()) c -= 1;
    }
    const r = st.tc[side];
    if (r.m1 == 0 or c < r.m1 or r.t2 == 0) return 0;
    if (r.m2 == 0) return 1;
    if (r.m1 +% r.m2 > c or r.t3 == 0) return 1;
    // The third period: tests/golden/timebudget/levels.zst, "2 moves in 1 minute, then 2 in
    // 1, then all in 2" (two renewals into the third period).
    return 2;
}

/// Port of add_control_time (1E9D:6F48, with advance_next_control 7004): at levels 0
/// and 2, move the side's next control on by a period and add that period's time to
/// its time left. The clock display it redraws (4793:34EA, 38AA) is not ported
/// (platform): 34EA also sets the displayed time DG:8DD2 + 6·side and the ticks to its
/// next second DG:58 + side from the new time left, which a later `clockToTicks` reads at
/// the timed levels (the engine runs none of them).
pub fn addControlTime(st: *TimeState, side: u1) void {
    if (st.level.* >= 3 or st.level.* == level_game_in) return;
    st.next_control[side] +%= periodLength(st, side).moves;
    const per = controlPeriod(st, side);
    const add: i32 = if (per.ticks != 0)
        ldiv(per.ticks *% periodLength(st, side).moves, per.moves)
    else blk: {
        const r = st.tc[side];
        const t = switch (periodIndex(st, 0, side)) {
            0 => r.t1,
            1 => r.t2,
            else => r.t3,
        };
        break :blk imul16(1092, t);
    };
    st.time_left[side] +%= add;
}

/// Port of clock_to_ticks (1E9D:6AF4): the displayed clock h:m:s in ticks,
/// ((h·60 + m)·60 + s)·91/5 + the ticks to the next second.
pub fn clockToTicks(st: *const TimeState, side: u1) i32 {
    const d = st.display[side];
    var x: i32 = imul16(60, d[0]) +% d[1];
    x = (x *% 60) +% d[2];
    x = ldiv(x *% 91, 5);
    return x +% st.tick58[side];
}

/// Port of check_new_control (1E9D:6EB2(arg)), called when a move has been played and
/// on a ponder hit: unless in analysis, re-read the opponent's time left from its
/// displayed clock and, at level 0 (or 2 within the record's counted controls), add
/// its next period when the control is at most `arg` moves away.
pub fn checkNewControl(st: *TimeState, arg: i16) void {
    if (st.inAnalysis()) return;
    const side = st.opponentSide();
    const c = st.adjustedMoveNumber(side);
    st.time_left[side] = clockToTicks(st, side);
    if (st.time_left[side] <= 0) return;
    if (st.level.* == level_per_move or (st.level.* == level_time_controls and st.tc[side].last >= c)) {
        // The opponent's period added: levels.zst, "1 move in 1 minute" with typed moves
        // (the program never renews the typing side's control at main 04A0).
        if (st.next_control[side] -% c <= arg) addControlTime(st, side);
    }
}

// ---------------------------------------------------------------------------
// Before the search
// ---------------------------------------------------------------------------

/// Port of main 0000:0588–0648, the start of the move (after [A8E8] = clock and
/// [A3F5] = [AE36] = [A3F6] = 0): moves to go, a new control at levels 0 and 2 when one
/// begins with this move, and `last_before_control` when moves to go ≤ 1.
pub fn startOfMove(st: *TimeState) void {
    st.last_before_control.* = 0;
    const s = st.computerSide();
    st.mtg.* = movesToGo(st);
    if (st.level.* > 2 or (st.preset.* == 0 and st.level.* == level_per_move)) return;
    if (!st.inAnalysis()) {
        if (st.level.* == level_time_controls) {
            if (st.tc[s].last +% 1 >= st.move_number.* and st.next_control[s] <= st.move_number.*) {
                // 6F48 from 05FD: levels.zst, "1 move in 1 minute" with typed moves.
                addControlTime(st, s);
                st.mtg.* = movesToGo(st);
            }
        } else {
            // At level 1 addControlTime does nothing and moves to go is ≥ 35.
            while (st.mtg.* <= 0) {
                // 6F48 from 061D: levels.zst, 2 s per move, the program taking White at
                // move 62 after 61 moves typed in monitor mode (normal play).
                addControlTime(st, s);
                st.mtg.* = movesToGo(st);
            }
        }
    }
    if (st.mtg.* <= 1) st.last_before_control.* = 1;
}

/// Port of set_time_budget (0000:8C3E): base, hard, soft and fail-high from the time
/// left, moves to go, the period cap and the book exit. Returns at once at Instant and
/// at the untimed levels, leaving every limit and `mtg` stale.
pub fn setTimeBudget(st: *TimeState) void {
    st.single_move.* = 0;
    if (st.preset.* == 0 and st.level.* == level_per_move) return;
    if (st.level.* >= 3) return;
    const s = st.computerSide();
    const g = movesToGo(st);
    st.mtg.* = g;
    const left = st.time_left[s];
    if (left <= 30 or g <= 0) {
        // 8C9A: levels.zst, moves to go ≤ 0 in auto-play past a control (no renewal at the
        // start of a move in auto-play: [9FCF] is set). Time left ≤ 30 was not recorded.
        st.base.* = 0;
    } else {
        st.base.* = ldiv(left -% 30, g);
    }
    const per = controlPeriod(st, s);
    var t = per.ticks;
    // 8CED-8D07: the records of BOTH sides are tested, whatever the side.
    if (st.level.* == level_time_controls and st.tc[0].t2 == 0 and st.tc[1].t2 == 0 and
        st.tc[0].m1 == 1 and st.tc[1].m1 == 1) st.single_move.* = 1;
    if (t > 0) {
        t = if (g < 6) ldiv(t *% 3, per.moves) else ldiv(ldiv(t *% 5, per.moves), 2);
        if (t < st.base.* and st.single_move.* == 0) {
            // 8D8C: levels.zst, "28 moves in 1 minute" with the book on (the book's moves
            // take no time, so the base passes the cap after it).
            st.base.* = t;
        }
    }
    const k: u8 = @truncate(st.base_shift);
    if (st.base_shift != 0 and st.base.* > 3) {
        // 8DB0: [2902] is (2205 − the rating typed in Levels / Set rating) / 100 (0EF8:8591);
        // levels.zst, a rating of 2005 (shift 2). A shift of 32 or more leaves 0 (base − 3 is
        // positive here).
        if (k != 0) st.base.* = (if (k >= 32) 0 else (st.base.* - 3) >> @intCast(k)) + 3;
    }
    const b = st.base.*;
    st.hard.* = if (g <= 2) b else if (g == 3) ldiv(b, 2) +% b else if (g <= 10) b *% 2 else b *% 3;
    const ply = st.game_ply.*;
    const exit_ply = st.book_exit_ply.*;
    if (st.clear_best.* == 0 and ply > 6 and g >= 6 and exit_ply > 0) {
        const kk = @divTrunc(@as(i32, ply) - exit_ply, 2);
        if (kk < 1) {
            st.base.* = st.base.* *% 2;
            st.hard.* +%= st.base.*;
        } else if (kk < 3) {
            st.base.* +%= ldiv(st.base.*, 2);
        } else if (kk < 8) {
            st.base.* +%= ldiv(st.base.*, 4);
        }
        if (st.base.* < 364 and ply -% 11 < exit_ply) st.base.* +%= ldiv(3400, st.speed);
    }
    if (t > 0 and g >= 6) {
        // Not gated by `single_move` (§"Corrections").
        const t2 = t +% ldiv(t, 5);
        if (t2 < st.base.*) {
            // 8F28: levels.zst, after the book exit's factor (the book on at level 2, and
            // after 61 moves typed in monitor mode, which count as the book).
            st.base.* = t2;
        }
    }
    st.soft.* = ldiv(st.hard.* +% st.base.*, 2);
    st.fail_high.* = ldiv(st.base.*, 2) +% st.hard.*;
}

/// The easy-move inputs of main 0000:10A9.
pub const EasyMove = struct {
    /// Main's [bp−6] and [bp−4]: the best and second root pre-scores.
    best: i16,
    second: i16,
    /// The signed byte at [3056]:22EE + 0xCB·[717C] + [A84A] (a per-side, per-move
    /// table; meaning not determined).
    byte: i8,
    /// The DGROUP byte [4A + byte].
    flag: u8,

    /// No easy move: the values when the table holds 0 (every timed run but one).
    pub const none: EasyMove = .{ .best = 0, .second = 0, .byte = 0, .flag = 0 };
};

/// Port of main 0000:10A9–1187: `clear_best` ([A22C]), `set_time_budget`, the halving
/// of the base for an easy move, and the overrides of soft and hard when few moves are
/// left or the best move is clear. At the untimed levels these run on the stale values
/// and nothing reads them.
pub fn mainBudget(st: *TimeState, easy: EasyMove) void {
    const gap = easy.best -% easy.second;
    st.clear_best.* = @intFromBool(easy.flag != 0 and gap > 300);
    setTimeBudget(st);
    // 10EB: the table byte itself, not the flag [4A + b] (§"Corrections").
    if (st.single_move.* == 0 and easy.byte != 0 and gap > 300) st.base.* >>= 1;
    if (st.clear_best.* != 0 or st.mtg.* <= 2) {
        st.soft.* = st.base.*;
        st.hard.* = st.base.*;
    } else if (st.mtg.* <= 4) {
        st.soft.* = st.base.*;
        st.hard.* = ldiv(st.base.*, 2) +% st.base.*;
    } else {
        st.soft.* = ldiv(st.hard.* +% st.base.*, 2);
    }
}

// ---------------------------------------------------------------------------
// During and after the search
// ---------------------------------------------------------------------------

/// The search state the ponder credit reads.
pub const PonderInputs = struct {
    /// Clock − [A8E8]: ticks since the ponder search began.
    elapsed: i32,
    /// DG:A3F4: the iteration number.
    iteration: u8,
    /// DG:A05C: the iteration given the fail-low extension (0 = none).
    ext_iteration: u8,
    /// DG:A3F5: a root fail-high re-search is pending.
    fail_high_pending: bool,
    /// DG:934E: the current root score.
    root_score: i16,
    /// DG:933C: the reference score.
    reference_score: i16,
};

/// Port of 1E9D:8680–8733, when the opponent's move is complete during pondering, hit
/// or miss alike: the stop test, then the elapsed ponder time credited to the time
/// left and all four limits (the charge after the search removes it again). Returns
/// true when the original sets the stop flag [A4FA] = 1. The caller stores `elapsed`
/// in DG:9FBE. Untimed levels: nothing.
pub fn ponderCredit(st: *TimeState, in: PonderInputs) bool {
    if (st.level.* >= 3) return false;
    const e = in.elapsed;
    var stop = false;
    if (e > st.base.*) {
        if (st.last_before_control.* != 0) {
            stop = true;
        } else if (in.iteration == in.ext_iteration or in.fail_high_pending) {
            // the extension iteration or a fail-high re-search runs on
        } else if (in.root_score >= in.reference_score) {
            stop = true;
        } else if (e > st.hard.* and in.reference_score -% 400 < in.root_score) {
            stop = true;
        }
    }
    const s = st.computerSide();
    st.time_left[s] +%= e;
    st.base.* +%= e;
    st.hard.* +%= e;
    st.soft.* +%= e;
    st.fail_high.* +%= e;
    return stop;
}

/// Port of root_search 0000:2CA3–2DCE, when the first root move of an iteration fails
/// low: extra time from what is left, shared over the moves to go. `elapsed` is clock −
/// [A8E8] read at 2CB1, `depth` the iteration depth [744E]. Returns true when the time
/// was extended; the caller then sets [A05C] = depth and [A4FA] = 0. The test is made at
/// every level, on the stale `mtg` at the untimed ones, where the time left of 0 makes
/// it give nothing.
pub fn failLowExtension(st: *TimeState, elapsed: i32, depth: i8) bool {
    const g = st.mtg.*;
    if (g <= 1) return false;
    const s = st.computerSide();
    var extra = ldiv(st.time_left[s] -% elapsed -% 54, g);
    if (extra <= 0) return false;
    if (g <= 6) extra >>= 1;
    const a = @min(extra, elapsed);
    st.base.* +%= a;
    // The first branch: the easy flag with depth < 3 in timebudget.zst (5 calls), g ≤ 4 in
    // levels.zst (4).
    const a2 = if (g <= 4 or (st.clear_best.* != 0 and depth < 3))
        a
    else if (st.clear_best.* != 0 or g <= 12)
        a *% 2
    else
        a *% 3;
    st.fail_high.* +%= a2;
    st.hard.* +%= a2;
    st.soft.* = ldiv(st.hard.* +% st.base.*, 2);
    return true;
}

/// Port of main 0000:16FE–1756, after the search: the computer's time left, re-read
/// from the displayed clock, or reduced by the elapsed time when the clocks did not run
/// (`clocks_running` = DG:B629) or in the clock mode `[1B8B]` = 2 ("stop chess clocks";
/// `debug_mode` here).
pub fn chargeClock(st: *TimeState, elapsed: i32, debug_mode: bool, clocks_running: bool) void {
    const s = st.computerSide();
    if (debug_mode or !clocks_running) {
        // 1711: levels.zst, the clock mode "stop chess clocks" ([1B8B] = 2, set by the key
        // `x` during the program's own search; main 0654 resets it before each search).
        st.time_left[s] -%= elapsed;
    } else {
        st.time_left[s] = clockToTicks(st, s);
    }
}

test "preset seconds come from the original" {
    try std.testing.expectEqualSlices(i32, &.{ 0, 2, 5, 10, 15, 30, 45, 60, 120, 180 }, &preset_seconds_table);
}

test "5 sec per move at move 1: 60 moves to go, base 90, hard 270, soft 180, fail-high 315" {
    // docs/arch/31-root-iteration-time.md §4.3, the measured table.
    var v: TimeState.Values = .{ .level = level_per_move, .preset = 2, .move_number = 1, .next_control = .{ 61, 61 }, .time_left = .{ 5460, 5460 } };
    var st: TimeState = .{};
    st.bindValues(&v);
    startOfMove(&st);
    mainBudget(&st, EasyMove.none);
    try std.testing.expectEqual(@as(i16, 60), v.mtg);
    try std.testing.expectEqual(Limits{ .base = 90, .hard = 270, .soft = 180, .fail_high = 315 }, st.limits());
}

test "TimeState: every pointer field is bound by bindValues and bindImage, to the variable's address" {
    var v: TimeState.Values = .{};
    var st: TimeState = .{};
    st.bindValues(&v);
    var img: [0x10000]u8 = @splat(0);
    var si: TimeState = .{};
    si.bindImage(&img);
    inline for (@typeInfo(TimeState).@"struct".field_names) |name| {
        if (comptime isPointerVar(name)) {
            try std.testing.expectEqual(@intFromPtr(&@field(v, name)), @intFromPtr(@field(st, name)));
            try std.testing.expectEqual(@intFromPtr(&img[@field(var_addresses, name)]), @intFromPtr(@field(si, name)));
            try std.testing.expectEqual(@sizeOf(@TypeOf(@field(v, name))), varBytes(name));
        }
    }
    // The level-2 records are the original's 14 bytes a side, as the image holds them.
    try std.testing.expectEqual(@as(usize, 28), varBytes("tc"));
    std.mem.writeInt(u16, img[0xB4C2 + 14 + 12 ..][0..2], 0x1234, .little);
    try std.testing.expectEqual(@as(i16, 0x1234), si.tc[1].last);
}
