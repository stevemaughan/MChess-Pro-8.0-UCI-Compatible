//! The threat evaluators 0EF8:A026 (eval_threats_white) and 0EF8:CD20
//! (eval_threats_black), written by hand.
//!
//! Specification: docs/arch/54-evaluation-threats.md. The machine-lifted port in
//! src/threats.zig (one statement per instruction on an emulated machine) is the
//! reference this file is proved against: src/evalthreats_test.zig replays every call
//! recorded from the original (tests/golden/evalthreats/) and compares both routines on
//! generated calls.
//!
//! `A026` scores the threats by Black against White (White to move, result <= 0) and
//! `CD20` the threats by White against Black (result >= 0); both results are in White's
//! view. The code below is one body with a compile-time side `S` (the side examined) and
//! its enemy `E`. Squares are real 10x12 mailbox squares; the board geometry that the
//! colours mirror (ranks, forward steps, fixed squares) goes through `sq`, `st` and
//! `rel`, which are the identity for White. Where `CD20` is not the mirror of `A026` the
//! difference is written out at the code site.
//!
//! What the routine leaves behind, besides its result: the flag byte (set to 1 at entry,
//! one more for each serious threat), the weak-pawn mask `EvalVars.weak_pawns` (DG:8EB6,
//! bits cleared as the endgame loop takes them), the work areas of the far routines it
//! calls, and its own argument slot `[bp+6]` (`ply`, overwritten with 100 in the first
//! two iterations unless the routine returned at its entry; the caller never reads it). Every
//! square and piece-list entry it lifts during a test is put back with the code of the
//! piece the slot is meant to hold, as the original writes it.
//!
//! The bug candidates of the specification (section 7) are reproduced exactly with
//! `pos.Fixes.original`, which `evalThreats`, `evalThreatsWhite` and `evalThreatsBlack`
//! use. Two are corrected behind their switches (owner decision 27), read through the
//! `comptime fixes` parameter of `evalThreatsFixes`:
//! - DEV-020 (7.1), `dev020_threat_table_index`: the result word is read at DG:0388 +
//!   2(n - m) with no bound (`settleWord`), from the executable's initialised data
//!   around the table. Corrected (`settleWordFixed`): the 13 that selects the second
//!   table is counted once, and the index is held inside the selected table.
//! - DEV-021 (7.2), `dev021_knight_escape_order` (owner decision 30): `CD20` visits the
//!   knight's escape squares in the negation of `A026`'s order, not its mirror
//!   (`knight_escape_order`). Corrected by the rule: Black's order is White's mirrored.
//! - DEV-022 (7.3), `dev022_captured_pieces`: the attack prefilters index the line
//!   tables by (target - entry) for every enemy piece-list entry, captured pieces
//!   included, and the x-ray test reads a captured bishop's or rook's king-ray byte past
//!   the end of the ray map (`kingRayAt`). Every read of an enemy knight's, bishop's or
//!   rook's entry, or of the enemy queen's square, against a line table goes through
//!   `foeKnight`, `foeDiag` and `foeOrth` (the x-ray test through `foeLive`); corrected,
//!   a captured entry (above 62h) reaches nothing, as the routine already treats its
//!   own captured pieces and the queen in the king section.
//!
//! - DEV-041, `dev041_threat_mirror` (owner decision 28): the places where `CD20` is not
//!   the colour mirror of `A026` and a result can differ, listed below. Corrected,
//!   `CD20` is `A026`'s mirror at each (spec 54, the note of 2026-11-20, fix-041).
//!
//! Places where `CD20` is not the colour mirror of `A026`, besides those of the
//! specification's section 6 (each written out at the code site). `CD20` was evidently
//! written by negating `A026`'s board steps (a half turn of the board), not by reversing
//! the ranks; where the order of a search, or a step tested, depends on that, the two
//! colours differ:
//! - the king on a7 / h7 with the queen on a diagonal through b7 / g7 (`kingA2`,
//!   `kingH2`): `CD20` tests the step -11 / -9 (D117, D32D) where the mirror of `A026`'s
//!   +11 / +9 (A401, A613) is -9 / -11 (DEV-041, corrected: the corner tested lies on
//!   the queen's line only with the mirrored step);
//! - the queen above the king's rank (`queenAbove`): `CD20` tries K-11 before K-9
//!   (D720, D760), the mirror would try K-9 first (DEV-041, corrected by the rule);
//! - the back-rank rook on the second rank (`backRankSecond`): `CD20` looks left first
//!   (DA66), `A026` right first (AD0F) (listed in DEV-041; the same result and flag for
//!   every input, so left as it is);
//! - a rook pinned on a diagonal by the queen, the bishop looked for on the other
//!   diagonal (`rookBlock`, A026 B4F8-B598, CD20 E250-E2F0, and the slot-4 copies):
//!   both walk up the board first, so `CD20` is not the mirror (DEV-041, corrected by
//!   the rule; it matters only with two enemy bishops on one diagonal);
//! - the knight squares (7.2, DEV-021, corrected by the rule; owner decision 30);
//! - the rook, bishop and queen escape directions (spec 6 item 2): the search stops at
//!   the first safe square with no penalty on the way, so the result is the same;
//! - which enemy bishop is tested against a square follows the colour mirror (slot 2 on
//!   dark squares for `A026`, on light for `CD20`), and only the slot-2 test skips a
//!   captured bishop (`bishopSlot2For`).
//!
//! Not a difference of the code: the line tables DG:0B66 and DG:0C64 are indexed by the
//! difference of two squares and accept some pairs that are not on one line (spec 7.4);
//! the set they accept is not symmetric under reversing the ranks (a8 to g7 is a "rank"
//! at -4, its mirror a1 to g2 at +16 is not), so the prefilters can call the attacker
//! routine for one colour and not for the other, and in the king section a pseudo-line
//! through the enemy queen ends a test early (the walk that follows does not reach the
//! queen) for one colour only. Both routines read the same tables. DEV-052,
//! `dev052_line_tables` (owner decision 30): corrected by evidence, a pseudo-line is no
//! line in either colour (`exactLine`); the tables, which other routines read, are not
//! changed.

const std = @import("std");
const pos = @import("position.zig");
const see = @import("see.zig");
const dg = @import("original.zig").dgroup;
const EvalVars = @import("evalvars.zig").EvalVars;

const Position = pos.Position;
pub const Side = pos.Side;

// ---------------------------------------------------------------------------
// State read that `Position` and `EvalVars` do not declare
// ---------------------------------------------------------------------------

/// The variables the threat evaluators read besides the position and `EvalVars`.
/// Other units declare some of them too (src/searchnode.zig, src/rootsearch.zig,
/// src/evaltables.zig); they are to be unified by address.
pub const ThreatVars = struct {
    /// DG:A272: ply limit 1 (depth + 2). Most penalties of 300 and more, and the flag,
    /// apply only when ply <= this. Signed word.
    ply_limit1: i16 = 0,
    /// DG:9356: ply limit 2 (depth + 4), the horizon of the full search.
    ply_limit2: i16 = 0,
    /// DG:A5EC: ply limit 3 (depth + 6): the extra queen-pin and rook-trap penalties.
    ply_limit3: i16 = 0,
    /// DG:A40E: when non-zero the mate threat near a king on the third rank always
    /// returns -5000.
    mate_switch: u8 = 0,
    /// DG:A3F4: the iteration number, a signed byte. At 1 or less the ply is taken as 100.
    iteration: i8 = 0,
    /// DG:A38E (White) and DG:A38F (Black): the pawn slot of a promoted queen, 0 for none.
    promoted_queen_slot: [2]u8 = .{ 0, 0 },
    /// DG:A116..A163: the 78 bytes after White's king-ray map (DG:A09E). The x-ray test
    /// (spec 4.3) reads `[A09E + entry]` for the enemy bishops and rooks without testing
    /// for a captured piece, whose entry is its square + 63h (78h..C5h), so it reads
    /// these (DEV-022). 0 in every recorded call. An entry of C6h or more would read
    /// Black's map (DG:A164), which `kingRayAt` does.
    white_rays_after: [78]u8 = @splat(0),
    /// DG:A1DC..A263: the bytes after Black's king-ray map (DG:A164), read the same way by
    /// `CD20` for entries up to FFh. 0 in every recorded call (the first 78).
    black_rays_after: [136]u8 = @splat(0),
    /// DG:9F6E..9FEB: the bytes after the search board (DG:9EF6). Read only if the x-ray
    /// test starts a walk from a captured piece's entry, which needs a non-zero byte in
    /// `white_rays_after` / `black_rays_after`; never in the recordings. The first 78
    /// were also `EvalState.past_board` and `LeafVars.past_board`, which are no longer read;
    /// this is their one home. Entries 90 and 91 are the game ply (DG:9FC8), which
    /// `boardAt` reads from `Position`. Beyond them the walk would read the exchange work
    /// area DG:9FEC (`see.Scratch.attackers`), which `boardAt` does.
    board_after: [126]u8 = @splat(0),
};

/// The routines the evaluators call, bound by the caller. `C` is any type with
///
///     fn see(c: C, side: Side, square: u8, value: u16) u16
///         2B9F:C32A (side white: White captures on `square`) / 2B9F:CAC2 (black),
///         src/see.zig `see`;
///     fn att(c: C, side: Side, square: u8, value: u16) u16
///         4793:41B6 (white) / 4793:4CEC (black), the exchange evaluation with pins
///         (src/attackers.zig, lifted, or the hand-written src/pinexchange.zig).
///
/// Both read the position the evaluator is working on, with its lifted pieces, so the
/// caller binds them to the same `Position` and to the `see.Scratch` it passes here.
/// `A026` calls `see(.black)` and `att(.white)`; `CD20` the other two.
pub fn evalThreats(
    comptime side: Side,
    p: *Position,
    v: *EvalVars,
    t: *const ThreatVars,
    scratch: *const see.Scratch,
    callees: anytype,
    ply: *u16,
    m: u16,
    flag: *u8,
) i16 {
    return evalThreatsFixes(pos.Fixes.original, side, p, v, t, scratch, callees, ply, m, flag);
}

/// `evalThreats` with this unit's class C fixes as `fixes` says
/// (`dev020_threat_table_index`, `dev021_knight_escape_order`, `dev022_captured_pieces`,
/// `dev041_threat_mirror`, `dev052_line_tables`; no other switch is read here). With `pos.Fixes.original` it is the original.
pub fn evalThreatsFixes(
    comptime fixes: pos.Fixes,
    comptime side: Side,
    p: *Position,
    v: *EvalVars,
    t: *const ThreatVars,
    scratch: *const see.Scratch,
    callees: anytype,
    ply: *u16,
    m: u16,
    flag: *u8,
) i16 {
    return evalThreatsProbe(fixes, .{}, side, p, v, t, scratch, callees, ply, m, flag);
}

/// The places of DEV-041, for `Probe.dev041_only`.
pub const Site041 = enum {
    /// D117: the king on a7, the corner a8 (A026 A401).
    corner_a7,
    /// D32D: the king on h7, the corner h8 (A026 A613).
    corner_h7,
    /// D720, D760: the order of the diagonals to the squares in front of the king
    /// (A026 A918-AA3A).
    queen_above,
    /// E250-E2F0 (and the slot-4 copy): the side of a pinned rook's other diagonal
    /// walked first (A026 B4F8-B598).
    rook_other_diagonal,
};

/// Test-only variations, for the colour-mirror tests (src/evalthreats_test.zig). The
/// engine and every replay use the default, which changes nothing. (Its switches for the
/// pseudo-lines and the knight order became DEV-052 and DEV-021 in `pos.Fixes`.)
pub const Probe = struct {
    /// With `dev041_threat_mirror` on, correct only this place (null: all of them).
    dev041_only: ?Site041 = null,
};

/// `evalThreatsFixes` with a test-only `Probe`.
pub fn evalThreatsProbe(
    comptime fixes: pos.Fixes,
    comptime probe: Probe,
    comptime side: Side,
    p: *Position,
    v: *EvalVars,
    t: *const ThreatVars,
    scratch: *const see.Scratch,
    callees: anytype,
    ply: *u16,
    m: u16,
    flag: *u8,
) i16 {
    var e: Evaluator(side, @TypeOf(callees), fixes, probe) = .{ .p = p, .v = v, .t = t, .scratch = scratch, .c = callees, .ply = @bitCast(ply.*), .ply_slot = ply, .m = m, .flag = flag };
    return e.run();
}

/// 0EF8:A026–CD1F, eval_threats_white.
pub fn evalThreatsWhite(p: *Position, v: *EvalVars, t: *const ThreatVars, scratch: *const see.Scratch, callees: anytype, ply: *u16, m: u16, flag: *u8) i16 {
    return evalThreats(.white, p, v, t, scratch, callees, ply, m, flag);
}

/// 0EF8:CD20–FA5B, eval_threats_black.
pub fn evalThreatsBlack(p: *Position, v: *EvalVars, t: *const ThreatVars, scratch: *const see.Scratch, callees: anytype, ply: *u16, m: u16, flag: *u8) i16 {
    return evalThreats(.black, p, v, t, scratch, callees, ply, m, flag);
}

// ---------------------------------------------------------------------------
// Constant tables, from the executable's initialised data (DG:0000..1AFF)
// ---------------------------------------------------------------------------

/// DGROUP's initial contents up to DG:1AFF. Every table the evaluators read lies here;
/// the readers below name each one. The line tables are indexed by the difference of
/// two squares, one of which may be a captured piece's entry (DEV-022), so a read can
/// land anywhere from DG:09B8 to DG:0D61; all of that is constant data.
const consts = dg(0, 0x1B00);

inline fn cbyte(addr: i32) u8 {
    return consts[@intCast(addr)];
}
inline fn sbyte(addr: i32) i8 {
    return @bitCast(cbyte(addr));
}

/// DG:0A68 + d (the table at DG:09B8 indexed t + B0h - s): non-zero when d is a knight's
/// move.
inline fn knightRel(d: i32) u8 {
    return cbyte(0x0A68 + d);
}
/// DG:0B66 + d (DG:0AB6 + B0h): the diagonal step for a difference d, 0 if none.
inline fn diagRel(d: i32) i8 {
    return sbyte(0x0B66 + d);
}
/// DG:0C64 + d (DG:0BB4 + B0h): the orthogonal step for a difference d, 0 if none.
inline fn orthRel(d: i32) i8 {
    return sbyte(0x0C64 + d);
}
/// DG:0CFF + d: non-zero when d is a king's step.
inline fn kingRel(d: i32) u8 {
    return cbyte(0x0CFF + d);
}
/// DG:0D4E + (q - king file): 4, 2, 1 for the queen on the file left of the king's, on
/// it, right of it.
inline fn queenFileBits(d: i32) u8 {
    return cbyte(0x0D4E + d);
}
/// DG:0490 + code: the step of a king-ray direction code.
inline fn rayStep(code: u8) i16 {
    return sbyte(0x0490 + @as(i32, code));
}
/// DG:047E + code: the slider bit of a king-ray direction code.
inline fn raySlider(code: u8) u8 {
    return cbyte(0x047E + @as(i32, code));
}
/// DG:0470 + piece code: the piece's slider bits.
inline fn pieceSlider(code: u8) u8 {
    return cbyte(0x0470 + @as(i32, code));
}
/// DG:0E16 + sq: 1 on dark squares.
inline fn dark(s: i16) u8 {
    return cbyte(0x0E16 + @as(i32, s));
}
/// DG:0850 + sq: square class, 0 on the a- and h-files.
inline fn squareClass(s: i16) u8 {
    return cbyte(0x0850 + @as(i32, s));
}
/// DG:100A + sq: the file of a square.
inline fn fileOf(s: i16) u8 {
    return cbyte(0x100A + @as(i32, s));
}
/// DG:128C + code: the value passed to the attacker routine for a piece (P 6, N 18,
/// B 18, R 30, Q 54).
inline fn attValue(code: u8) u16 {
    return cbyte(0x128C + @as(i32, code));
}
/// DG:01AC + mask: the pawn slot (8..15) of the lowest set bit, 0 for none.
inline fn lowestSlot(mask: u8) u8 {
    return cbyte(0x01AC + @as(i32, mask));
}
/// DG:019C + slot: the mask that clears the slot's bit.
inline fn slotClearMask(slot: u8) u8 {
    return cbyte(0x019C + @as(i32, slot));
}
/// The word at DG:0388 + 2(n - m), the result table (DEV-020: no bound on n - m; the
/// words past either end are the executable's, read as the original reads them).
inline fn settleWord(n: i16, m: u16) i16 {
    const a: u16 = 0x0388 +% (@as(u16, @bitCast(n)) -% m) *% 2;
    return @bitCast(@as(u16, consts[a]) | @as(u16, consts[a + 1]) << 8);
}
/// DEV-020 corrected (`Fixes.dev020_threat_table_index`). The original indexes the
/// result words by n - m alone (CD08; CD20 FA41). They are two tables of 14 (spec 3.4):
/// T1, centred at DG:0388, for n - m = -7 .. +6, and T2, centred at DG:03A2 = 0388 +
/// 2*13, for n - m = 7 .. 20, which a queen or rook attacked by a pawn selects by adding
/// 13 to n (B1C9, B5B1, BA11). The 13 is the offset of T2, not a count: one such piece
/// with nothing else (n - m = 14) reads T2's 24, as one threat reads T1's (n - m = 1),
/// and both tables go on one step per threat. Two such pieces add 13 twice and read
/// past T2 (n - m = 28 and 29 seen: words of the next table); seven to twelve threats
/// beyond m with none would read T2's bonuses as T1's penalties.
/// Corrected: the 13 counts once (`selects` is the number of times it was added), and
/// the threats beyond m are held inside the selected table (T1 -7 .. +6, T2 -6 .. +7).
/// Wherever the original's index lies inside the table it selects, the word is the same.
inline fn settleWordFixed(n: i16, m: u16, selects: u8) i16 {
    const d: i32 = @as(i32, n) - @as(i32, m) - 13 * @as(i32, selects);
    const a: i32 = if (selects == 0)
        0x0388 + 2 * std.math.clamp(d, -7, 6)
    else
        0x03A2 + 2 * std.math.clamp(d, -6, 7);
    const u: usize = @intCast(a);
    return @bitCast(@as(u16, consts[u]) | @as(u16, consts[u + 1]) << 8);
}
/// DEV-052 corrected: `step`, the line tables' step from `target` toward `entry`, if the
/// two squares are on that line (the same rank for +-1, the same file for +-10, a true
/// diagonal for +-9 and +-11), else 0 (a pseudo-line, `exactLine`).
/// With d = entry - target = 10 dr + df, where df is the difference of the files: a
/// rank (+-1) needs dr = 0, so d = df; a file (+-10) has one form only; a diagonal of
/// +-11 needs df = dr, so d = 11 df, and one of +-9 needs df = -dr, so d = -9 df.
inline fn realLine(target: i16, entry: i16, step: i8) i8 {
    if (step == 0) return 0;
    const d = entry - target;
    const df = @as(i16, file_of[@intCast(entry)]) - file_of[@intCast(target)];
    const ok = switch (step) {
        1, -1 => d == df,
        11, -11 => d == 11 * df,
        9, -9 => d == -9 * df,
        else => true,
    };
    return if (ok) step else 0;
}
/// sq mod 10 for every byte a square or piece-list entry can hold.
const file_of: [256]i8 = blk: {
    var t: [256]i8 = undefined;
    for (&t, 0..) |*x, i| x.* = @intCast(i % 10);
    break :blk t;
};
/// The word at DG:03EA + 2m: the bonus the caller added for m attacked pieces.
inline fn countBonusWord(m: u16) i16 {
    const a: u16 = 0x03EA +% m *% 2;
    return @bitCast(@as(u16, consts[a]) | @as(u16, consts[a + 1]) << 8);
}

// ---------------------------------------------------------------------------
// The evaluator
// ---------------------------------------------------------------------------

/// Where a test of the king section (spec 4.2-4.4) goes on.
const Next = enum {
    /// A11A: a threat (`L08 += 1`), then the mate test.
    threat,
    /// A11D: the mate test.
    mate,
    /// A49A: the rook result (the rook lifted at `rook_sq` is put back first).
    rook,
    /// AB94: the back-rank tests.
    back_rank,
    /// AD90.
    done,
};

/// Where a piece block of spec 4.6-4.7 goes on.
const After = enum { next_piece, tail };

fn Evaluator(comptime S: Side, comptime C: type, comptime fixes: pos.Fixes, comptime probe: Probe) type {
    return struct {
        const Self = @This();
        const E = S.other();
        const white = S == .white;

        /// DEV-041 corrected at `site`: Black's routine is White's mirror there.
        inline fn mirror041(comptime site: Site041) bool {
            return !white and fixes.dev041_threat_mirror and (probe.dev041_only == null or probe.dev041_only.? == site);
        }

        // piece codes
        const ob: u8 = if (white) 0 else 7;
        const eb: u8 = if (white) 7 else 0;
        const own_pawn = 1 + ob;
        const own_knight = 2 + ob;
        const own_bishop = 3 + ob;
        const own_rook = 4 + ob;
        const own_queen = 5 + ob;
        const foe_pawn = 1 + eb;
        const foe_bishop = 3 + eb;
        const foe_rook = 4 + eb;
        const foe_queen = 5 + eb;
        // king-ray direction codes: 1..8 for White, 9..16 for Black
        const ro: u8 = if (white) 0 else 8;
        // piece-list slots
        const own_list = if (white) 0 else 16;
        const foe_list = if (white) 16 else 0;

        p: *Position,
        v: *EvalVars,
        t: *const ThreatVars,
        scratch: *const see.Scratch,
        c: C,
        ply: i16,
        /// [bp+6], the argument slot.
        ply_slot: *u16,
        m: u16,
        flag: *u8,
        /// [bp-2]: the main score.
        l02: i16 = 0,
        /// [bp-4]: the secondary score, added only if no serious threat was counted.
        l04: i16 = 0,
        /// [bp-6], [bp-8]: the two threat counters.
        l06: i16 = 0,
        l08: i16 = 0,
        /// [bp-0Ch]: the enemy queen's square (or a captured queen's entry).
        q: i16 = 0,
        /// [bp-12h]: an escape square was found for the knight examined.
        l12: bool = false,
        /// The square of the rook lifted before a `Next.rook`.
        rook_sq: i16 = 0,
        /// DEV-020 corrected: how many times 13 was added to `l06` (the queen or a rook
        /// attacked by a pawn). Not a variable of the original; kept only with the fix.
        selects: u8 = 0,

        // ---- geometry -------------------------------------------------------

        /// A square of White's code, for the side examined.
        inline fn sq(comptime x: i16) i16 {
            return if (white) x else mirror(x);
        }
        fn mirror(x: i16) i16 {
            return 110 - 10 * @divTrunc(x, 10) + @mod(x, 10);
        }
        /// A step of White's code (+10 forward), for the side examined.
        inline fn st(comptime d: i16) i16 {
            if (white) return d;
            const r = @divTrunc(d + if (d >= 0) 5 else -5, 10);
            return -10 * r + (d - 10 * r);
        }
        /// A square as White's code compares it.
        inline fn rel(x: i16) i16 {
            return if (white) x else mirror(x);
        }
        /// The direction code of a step in the own king's ray map.
        inline fn rayCode(comptime d: i16) u8 {
            inline for (1..9) |k| {
                if (rayStep(@intCast(k + ro)) == d) return @intCast(k + ro);
            }
            unreachable;
        }

        // ---- piece classes (A026's single comparisons; CD20 tests the same sets) ----

        /// Own piece or empty (A026 `cmp c, 7; jl`).
        inline fn ownOrEmpty(c: u8) bool {
            return if (white) c < 7 else (c == 0 or c > 7);
        }
        /// An enemy piece (A026 `cmp c, 7; jg`).
        inline fn foePiece(c: u8) bool {
            return if (white) c > 7 else (c != 0 and c < 7);
        }
        /// An enemy piece other than a pawn (A026 `cmp c, 8; jg`).
        inline fn foeNonPawn(c: u8) bool {
            return if (white) c > 8 else (c >= 2 and c <= 6);
        }
        /// Own knight, bishop, rook or queen (A026 `1 < c < 6`).
        inline fn ownMinorOrMajor(c: u8) bool {
            return c > 1 + ob and c < 6 + ob;
        }
        /// DG:1270 (White) / DG:127E (Black) + code: own rook, queen or king.
        inline fn ownHeavyOrKing(c: u8) bool {
            return cbyte(@as(i32, if (white) 0x1270 else 0x127E) + c) != 0;
        }

        // ---- state ------------------------------------------------------------

        inline fn at(e: *const Self, s: i16) u8 {
            return e.p.board[@intCast(s)];
        }
        inline fn put(e: *Self, s: i16, code: u8) void {
            e.p.board[@intCast(s)] = code;
        }
        inline fn own(e: *const Self, slot: u8) i16 {
            return e.p.piece_list[own_list + slot];
        }
        inline fn foe(e: *const Self, slot: u8) i16 {
            return e.p.piece_list[foe_list + slot];
        }
        inline fn king(e: *const Self) i16 {
            return e.own(7);
        }
        inline fn foeKing(e: *const Self) i16 {
            return e.foe(7);
        }
        inline fn foePawnAttacks(e: *const Self, s: i16) u8 {
            return e.p.pawn_attacks[@backingInt(E)][@intCast(s)];
        }
        inline fn ownPawnAttacks(e: *const Self, s: i16) u8 {
            return e.p.pawn_attacks[@backingInt(S)][@intCast(s)];
        }
        inline fn kingRay(e: *const Self, s: i16) u8 {
            return e.p.king_rays[@backingInt(S)][@intCast(s)];
        }
        /// The own king's ray map at a piece-list entry, which may be a captured
        /// piece's (DEV-022): past the map the bytes that follow it.
        fn kingRayAt(e: *const Self, entry: i16) u8 {
            const i: usize = @intCast(entry);
            if (i < 120) return e.kingRay(entry);
            if (white) {
                if (i < 198) return e.t.white_rays_after[i - 120];
                return e.p.king_rays[1][i - 198];
            }
            return e.t.black_rays_after[i - 120];
        }
        /// The board for the x-ray walk from a captured piece's entry: the board, then
        /// the bytes that follow it in DGROUP (`ThreatVars.board_after`, then the
        /// exchange work area at DG:9FEC with the piece lists inside it).
        fn boardAt(e: *const Self, s: i16) u8 {
            const i: usize = @intCast(s);
            if (i < 120) return e.p.board[i];
            // DG:9FC8, 9FC9 (`board_after[90]`, `[91]`): the game ply, whose home is
            // `Position` (Stage B step 5: nothing refreshes `board_after` in the search).
            if (i == 210 or i == 211) return std.mem.asBytes(&e.p.game_ply)[i - 210];
            if (i < 246) return e.t.board_after[i - 120];
            const a = i - 246; // DG:9FEC + a
            if (a >= 0x4E and a < 0x6E) return e.p.piece_list[a - 0x4E];
            if (a < e.scratch.attackers.len) return e.scratch.attackers[a];
            return e.scratch.defenders[a - e.scratch.attackers.len];
        }
        inline fn bump(e: *Self) void {
            e.flag.* +%= 1;
        }
        /// A penalty against the side examined, in White's view: CD20 adds what A026
        /// subtracts.
        inline fn pen(x: i16) i16 {
            return if (white) x else -%x;
        }

        // ---- far calls ------------------------------------------------------------

        /// The exchange evaluator of the enemy's captures on `s` (A026: 2B9F:CAC2).
        inline fn seeE(e: *Self, s: i16, value: u16) i16 {
            return @bitCast(e.c.see(E, @intCast(s), value));
        }
        /// The attacker routine of the side examined (A026: 4793:41B6).
        inline fn att(e: *Self, s: i16, value: u16) i16 {
            return @bitCast(e.c.att(S, @intCast(s), value));
        }

        /// The first occupied square from `s` in steps of `d`.
        inline fn walk(e: *const Self, s: i16, d: i16) i16 {
            var x = s + d;
            while (e.at(x) == 0) x += d;
            return x;
        }

        // ---- DEV-022: the line tables against an enemy entry ------------------------
        //
        // The original indexes the tables by (target - entry) for every enemy knight,
        // bishop and rook and for the enemy queen's square `q`, captured or not (A026:
        // ADEF-AE54, AEC8-AF72, B043-B205, B3E7, B4C0-B747, B920-BBA7, BDC6-BE11,
        // C334-C37F, C8B2-C919, CB0C-CB73; CD20 the mirror of each). A captured piece's
        // entry is its last square + 63h, so the table byte means nothing; it can report
        // a line or a knight's move that does not exist, and the attacker routine is then
        // called on a square the piece cannot reach. Corrected
        // (`Fixes.dev022_captured_pieces`), a captured entry reaches nothing, as the
        // routine already skips its own captured pieces (B41B and the other block
        // entries), the enemy queen in the king section (A0A4, A39D) and the slot-2 bishop
        // beside its own queen and rooks (B053, B627, and in rook slot 4; there after the
        // table test, which gives the same result). Every read of an enemy entry, or of
        // `q`, against a line table goes through these three (the king section uses `q`
        // only after A0A4 / A39D, and the enemy king is never captured).

        /// A captured entry is used (the original), or not (corrected).
        inline fn foeLive(entry: i16) bool {
            return !fixes.dev022_captured_pieces or entry <= 0x62;
        }
        /// For a knight the test changes nothing: a captured entry (78h..C5h) is never a
        /// knight's move from a board square (src/pinexchange.zig checks the table at
        /// compile time). It is kept so that every enemy entry takes the same path.
        inline fn foeKnight(target: i16, entry: i16) u8 {
            return if (foeLive(entry)) knightRel(target - entry) else 0;
        }
        inline fn foeDiag(target: i16, entry: i16) i8 {
            return if (foeLive(entry)) exactLine(target, entry, diagRel(target - entry)) else 0;
        }
        inline fn foeOrth(target: i16, entry: i16) i8 {
            return if (foeLive(entry)) exactLine(target, entry, orthRel(target - entry)) else 0;
        }
        /// DEV-052 (`Fixes.dev052_line_tables`): the line tables DG:0B66 (diagonal) and
        /// DG:0C64 (orthogonal) are indexed by the difference of two squares alone. On a
        /// board ten squares wide a difference has more than one form: -66 is six steps of
        /// -11 (a1-type diagonal) and also seven ranks down and four files right (c8 to
        /// g1), so the tables report a line for pairs that are not on one ("pseudo-lines":
        /// rank differences 3 to 7 across the border column, diagonal differences of 3 to
        /// 7 steps the same way; file differences have one form only). Under the colour
        /// mirror (ranks reversed) a pseudo-line's difference becomes one the tables do
        /// not accept, so the two colours score mirrored positions differently. The code
        /// that reads them means a real line: in the king section it walks the step from
        /// the square and expects to meet the queen, and when a pseudo-line's walk misses
        /// it gives up the test (A0C8: the diagonal is not tried after a pseudo-rank), and
        /// in the prefilters a pseudo-line only lets the attacker routine find an attack
        /// of a kind the prefilter does not look for. Corrected, a step the tables give for
        /// two squares not on that line is taken as none, in both colours. The tables
        /// themselves are not changed: other routines read them (0000:1FFC-2218,
        /// 1E9D:CC9E-CFDA, 2B9F:1AEE-1BA1 and 2762-2815, 4793:5B21-5D35).
        inline fn exactLine(target: i16, entry: i16, step: i8) i8 {
            return if (fixes.dev052_line_tables) realLine(target, entry, step) else step;
        }

        /// The enemy pieces that the prefilters test against `target`.
        inline fn knightsReach(e: *const Self, target: i16) bool {
            return (foeKnight(target, e.foe(1)) | foeKnight(target, e.foe(0))) != 0;
        }
        inline fn rooksOnLine(e: *const Self, target: i16) u8 {
            return @bitCast(foeOrth(target, e.foe(4)) | foeOrth(target, e.foe(5)));
        }
        inline fn bishopsOnDiag(e: *const Self, target: i16) u8 {
            return @bitCast(foeDiag(target, e.foe(2)) | foeDiag(target, e.foe(3)));
        }
        /// B03A / B611: which enemy bishop is tested against a piece on `s`: slot 2 on a
        /// dark square for A026, on a light one for CD20 (the colour mirror), else slot 3.
        /// Only the slot-2 test skips a captured bishop in the original (DEV-022).
        inline fn bishopSlot2For(s: i16) bool {
            return (dark(s) != 0) == white;
        }
        inline fn queenOnLineOrDiag(e: *const Self, target: i16) bool {
            return (foeOrth(target, e.q) | foeDiag(target, e.q)) != 0;
        }

        // ---- the routine ------------------------------------------------------------

        fn run(e: *Self) i16 {
            // 4.1 entry (A026)
            e.flag.* = 1;
            const q0: i16 = e.foe(6);
            e.q = q0;
            if (q0 > 0x62) {
                const slot = e.t.promoted_queen_slot[@backingInt(E)];
                if (slot != 0) e.q = e.p.piece_list[@intCast(foe_list + @as(i16, @as(i8, @bitCast(slot))))];
                if (e.p.piece_count[@backingInt(S)] == 0 and e.q > 0x62) return 0;
            }
            if (e.t.iteration <= 1) {
                e.ply = 100; // A07B: the argument itself is overwritten
                e.ply_slot.* = 100;
            }

            // 4.2-4.4 the king (A080-AD8F)
            if (e.kingSection()) |r| return r;
            // AD90
            if (e.p.piece_count[@backingInt(S)] == 0) return e.l02;
            // 4.5 centre and weak pawns (ADCC)
            e.pawns();
            // 4.6 the queen, 4.7 the pieces (B004-CCA5); a block may go straight to the tail
            e.pieces();
            return e.tail();
        }

        fn pieces(e: *Self) void {
            if (e.queenBlock() == .tail) return;
            if (e.rookBlock(5) == .tail) return;
            if (e.rookBlock(4) == .tail) return;
            if (e.knightBlock(0) == .tail) return;
            if (e.knightBlock(1) == .tail) return;
            if (e.bishopBlock(2) == .tail) return;
            _ = e.bishopBlock(3);
        }

        /// 4.8 the tail (CCA6).
        fn tail(e: *Self) i16 {
            e.l06 +%= e.l08;
            if (e.l06 != 0 and e.ply <= e.t.ply_limit1 and
                (e.l06 > 1 or (e.l08 != 0 and e.p.piece_material_sum < 7000)))
            {
                e.bump();
                e.l02 -%= pen(if (e.m == 0) 300 else 500);
            }
            if (e.flag.* == 1) e.l02 +%= e.l04;
            if (e.v.passer_flags & 0x10 != 0) e.l06 +%= 1;
            if (e.l06 == 0) return e.l02;
            // CCFD: DEV-020, the result word (see `settleWordFixed`)
            const settle = if (fixes.dev020_threat_table_index) settleWordFixed(e.l06, e.m, e.selects) else settleWord(e.l06, e.m);
            return e.l02 -% pen(settle) -% pen(countBonusWord(e.m));
        }

        /// The mate return (ADBD).
        fn mateReturn(e: *Self) i16 {
            e.bump();
            return e.l02 -% pen(5000);
        }

        // ---- 4.2-4.4 the king ----------------------------------------------------------

        /// A080-AD8F. Returns the result when the routine returns from this section, null
        /// to go on at AD90.
        fn kingSection(e: *Self) ?i16 {
            const k = e.king();
            const kr = rel(k);
            var next: Next = undefined;
            if (kr > 0x26) {
                // 4.2 king beyond the second rank: only a3, b3, g3, h3
                if (kr > 0x30) return null;
                if (kr > 0x2A and kr < 0x2F) return null;
                next = e.thirdRank(k);
            } else {
                // 4.3 x-ray (A29A)
                if (e.ply <= e.t.ply_limit1) {
                    if (e.xray()) {
                        e.bump();
                        return e.l02 -% pen(2000);
                    }
                }
                // 4.4 (A39A)
                next = e.queenNearKing(k);
                if (next == .back_rank) next = e.backRank(k);
            }
            return e.finish(next);
        }

        /// The common exits of the king section: the mate test (A11D) and the rook result
        /// (A49A).
        fn finish(e: *Self, next: Next) ?i16 {
            switch (next) {
                .done => return null,
                .back_rank => unreachable,
                .threat, .mate => {
                    if (next == .threat) e.l08 +%= 1;
                    e.put(e.q, foe_queen);
                    const k = e.king();
                    if (e.at(k + st(20)) == foe_pawn or knightRel(k - e.q) != 0) {
                        // A13C
                        if (e.ply > e.t.ply_limit2 and e.t.mate_switch == 0) {
                            e.l04 -%= pen(60); // AD84
                            e.l02 -%= pen(60);
                            return null;
                        }
                        return e.mateReturn();
                    }
                    // AD9E
                    if (e.ply <= e.t.ply_limit1 or e.t.mate_switch != 0) return e.mateReturn();
                    if (e.ply > e.t.ply_limit2 or @as(i16, @bitCast(e.p.piece_material[@backingInt(E)])) > 3800) {
                        e.l02 -%= pen(60); // AD88
                        return null;
                    }
                    return e.mateReturn();
                },
                .rook => {
                    e.put(e.rook_sq, foe_rook);
                    e.l08 +%= 1;
                    if (e.ply >= e.t.ply_limit2) {
                        e.l02 -%= pen(30); // AD8C
                        return null;
                    }
                    if (e.ply <= e.t.ply_limit1 or e.m != 0) return e.mateReturn();
                    if (@as(i16, @bitCast(e.p.piece_material[@backingInt(E)])) > 3800) {
                        e.l02 -%= pen(30);
                        return null;
                    }
                    return e.mateReturn();
                },
            }
        }

        /// The enemy queen is lifted from `e.q` for a test.
        inline fn liftQueen(e: *Self) void {
            e.put(e.q, 0);
        }
        inline fn restoreQueen(e: *Self) void {
            e.put(e.q, foe_queen);
        }

        /// 4.2 (A0A4-A297): the king on a3, b3, g3 or h3.
        fn thirdRank(e: *Self, k: i16) Next {
            if (e.q >= 0x63) return e.backRankSecond(k + st(-10));
            // A0AD: the second-rank square beside the king
            const t = if (rel(k) <= 0x2A) sq(0x20) else sq(0x25);
            if (!ownOrEmpty(e.at(t))) {
                // A1DE
            } else if (e.lineThroughSquare(t)) |n| return n;
            // A1DE: a king on the a- or h-file, from b3 / g3
            if (squareClass(k) == 0) {
                const t2 = if (rel(k) < 0x2A) sq(0x2A) else sq(0x2F);
                if (ownOrEmpty(e.at(t2))) {
                    if (e.diagonalThroughSquare(t2)) |n| return n;
                }
            }
            return e.backRankSecond(k + st(-10));
        }

        /// A0C8-A1D9: the queen reaching `t` along a line or a diagonal.
        fn lineThroughSquare(e: *Self, t: i16) ?Next {
            const ortho = exactLine(t, e.q, orthRel(t - e.q));
            if (ortho != 0) {
                if (e.walk(t, ortho) != e.q) return null;
                e.liftQueen();
                if (e.at(t) != 0) {
                    if (e.seeE(t, 27) > 0) return .mate;
                    e.restoreQueen();
                    return null;
                }
                if (e.seeE(t, 27) >= 0) return .threat;
                // A154: the next square, along the rank when the queen is on the second
                const q_on_second = rel(e.q) <= 0x26 and rel(e.q) >= 0x1F;
                const t2 = if (q_on_second) t - ortho else t + st(10);
                if (e.at(t2) == 0) {
                    if (e.seeE(t2, 27) >= 0) return .threat;
                } else if (ownOrEmpty(e.at(t2))) {
                    if (e.seeE(t2, 27) > 0) return .mate;
                }
                e.restoreQueen();
                return null;
            }
            const diag = exactLine(t, e.q, diagRel(t - e.q));
            if (diag == 0) return null;
            if (e.walk(t, diag) != e.q) return null;
            e.liftQueen();
            if (e.at(t) != 0) {
                if (e.seeE(t, 27) > 0) return .mate;
            } else {
                if (e.seeE(t, 27) >= 0) return .threat;
            }
            e.restoreQueen();
            return null;
        }

        /// A1FB-A288: the queen reaching `t` (b3 or g3) along a diagonal.
        fn diagonalThroughSquare(e: *Self, t: i16) ?Next {
            const d = exactLine(t, e.q, diagRel(t - e.q));
            if (d == 0) return null;
            if (e.walk(t, d) != e.q) return null;
            e.liftQueen();
            if (e.at(t) != 0) {
                if (e.seeE(t, 27) > 0) return .mate;
            } else {
                if (e.seeE(t, 27) >= 0) return .threat;
                const t2 = t - d; // A255
                if (e.at(t2) == 0) {
                    if (e.seeE(t2, 27) >= 0) return .threat;
                } else if (ownOrEmpty(e.at(t2))) {
                    if (e.seeE(t2, 27) > 0) return .mate;
                }
            }
            e.restoreQueen();
            return null;
        }

        /// 4.3 (A2A5-A392): a bishop on an orthogonal king ray, or a rook on a diagonal
        /// one, with a slider of that line behind it. True for the return of A2D8.
        /// DEV-022: the original reads the ray map at a captured bishop's or rook's
        /// entry (A2A5, A2E8, A31B, A354), past the map; corrected, a captured piece is
        /// skipped (`foeLive`).
        fn xray(e: *Self) bool {
            inline for (.{ 2, 3 }) |slot| {
                const b = e.foe(slot);
                const code = if (foeLive(b)) e.kingRayAt(b) else 0;
                if (code > 4 + ro) {
                    const c = e.boardAt(e.walkAt(b, rayStep(code)));
                    if (c >= foe_rook and c <= foe_queen) return true;
                }
            }
            inline for (.{ 4, 5 }) |slot| {
                const r = e.foe(slot);
                const code = if (foeLive(r)) e.kingRayAt(r) else 0;
                if (code > ro and code <= 4 + ro) {
                    const c = e.boardAt(e.walkAt(r, rayStep(code)));
                    if (c == foe_bishop or c == foe_queen) return true;
                }
            }
            return false;
        }

        /// `walk` through `boardAt`.
        fn walkAt(e: *const Self, s: i16, d: i16) i16 {
            var x = s + d;
            while (e.boardAt(x) == 0) x += d;
            return x;
        }

        /// 4.4 steps 1 and 2 (A39A-AB93).
        fn queenNearKing(e: *Self, k: i16) Next {
            if (e.q > 0x62) return .back_rank; // A3A2 goes to AB9B
            const kr = rel(k);
            if (kr <= 0x1C) return e.firstRank(k);
            if (kr == 0x1F) {
                if (e.kingA2()) |n| return n;
                return e.cornerB1();
            }
            if (kr == 0x20) return e.cornerB1();
            if (kr == 0x26) {
                if (e.kingH2()) |n| return n;
                return e.cornerG1();
            }
            if (kr == 0x25) return e.cornerG1();
            return .back_rank;
        }

        /// A468 / A676: SEE on the square beside the king, the queen lifted.
        fn seeBeside(e: *Self, t: i16) ?Next {
            if (e.seeE(t, 27) <= 0) {
                e.restoreQueen();
                return null;
            }
            return if (e.at(t) == own_pawn) .threat else .mate;
        }

        /// A3B5-A562: the king on a2.
        fn kingA2(e: *Self) ?Next {
            const b2 = sq(0x20);
            const d = exactLine(b2, e.q, diagRel(b2 - e.q));
            if (d != 0) {
                if (!ownOrEmpty(e.at(b2))) return null;
                if (e.walk(b2, d) != e.q) return null;
                e.liftQueen();
                if (e.at(b2) != 0) return e.seeBeside(b2);
                if (e.seeE(b2, 27) >= 0) return .threat;
                // A401: A026 tests +11: the queen beyond b2 on the a1-h8 diagonal, so that
                // it reaches a1, the corner behind b2, through b2. CD20 (D117) tests -11,
                // the queen on a6, and then the corner a8, which a queen on a6 does not
                // reach through b7: the step is A026's negated, the corner its mirror.
                // DEV-041: the mirror of +11 is -9 (the queen on the a8-h1 diagonal, a8
                // behind b7), the only step for which the corner CD20 tests lies on the
                // queen's line; corrected, CD20 tests -9 (`st(11)`). Chosen on that
                // evidence: A026's form, which is coherent.
                const corner_step: i16 = if (white or mirror041(.corner_a7)) st(11) else -11;
                if (d == corner_step) {
                    const a1 = sq(0x15);
                    if (e.at(a1) != 0) {
                        if (e.seeE(a1, 27) > 0) return .threat;
                    } else {
                        if (e.seeE(a1, 27) >= 0) return .threat;
                    }
                }
                e.restoreQueen();
                return null;
            }
            return e.cornerLines(b2, sq(0x21), 1, 1, sq(0x29));
        }

        /// A5C8-A73D: the king on h2.
        fn kingH2(e: *Self) ?Next {
            const g2 = sq(0x25);
            const d = exactLine(g2, e.q, diagRel(g2 - e.q));
            if (d != 0) {
                if (!ownOrEmpty(e.at(g2))) return null;
                if (e.walk(g2, d) != e.q) return null;
                e.liftQueen();
                if (e.at(g2) != 0) return e.seeBeside(g2);
                if (e.seeE(g2, 27) >= 0) return .threat;
                // A613: A026 tests +9: the queen on the h1-a8 diagonal, reaching h1 behind
                // g2. CD20 (D32D) tests -9, the queen on h6, which does not reach h8
                // through g7. DEV-041: the mirror is -11 (the queen on the a1-h8
                // diagonal, h8 behind g7); corrected, CD20 tests -11 (`st(9)`). Chosen on
                // the same evidence as A401 / D117.
                const corner_step: i16 = if (white or mirror041(.corner_h7)) st(9) else -9;
                if (d == corner_step) {
                    const h1 = sq(0x1C);
                    if (e.at(h1) != 0) {
                        if (e.seeE(h1, 27) > 0) return .threat;
                    } else {
                        if (e.seeE(h1, 27) >= 0) return .threat;
                    }
                }
                e.restoreQueen();
                return null;
            }
            return e.cornerLines(g2, sq(0x24), -1, 8, sq(0x30));
        }

        /// A42C-A55D / A63E-A73D: the queen not on a diagonal through b2 (g2): on the
        /// second rank, or on the a- or b-file (h- or g-file). `t` is b2 (g2), `from` the
        /// square beside it away from the king, `dir` the step along the rank, `edge_file`
        /// the king's file, `edge3` a3 (h3).
        fn cornerLines(e: *Self, t: i16, from: i16, comptime dir: i16, comptime edge_file: u8, edge3: i16) ?Next {
            const qr = rel(e.q);
            if (qr <= 0x26) {
                if (qr < 0x1F) return null;
                const c = e.at(t);
                if (c == 0 or !ownOrEmpty(c)) return null;
                var s = from;
                while (e.at(s) == 0) s += dir;
                if (s == e.q) {
                    e.liftQueen();
                    return e.seeBeside(t);
                }
                if (e.at(s) == foe_rook) {
                    e.put(s, 0);
                    if (e.seeE(t, 15) > 0) {
                        e.rook_sq = s;
                        return .rook;
                    }
                    e.put(s, foe_rook);
                }
                return null;
            }
            const f = fileOf(e.q);
            if (f == edge_file) {
                const c = e.at(edge3);
                if (c == 0 or !ownOrEmpty(c)) return null;
                if (e.walk(edge3, st(10)) != e.q) return null;
                e.liftQueen();
                if (e.seeE(edge3, 27) > 0) return if (e.at(edge3) == own_pawn) .threat else .mate;
                e.restoreQueen();
                return null;
            }
            if (f == if (dir > 0) edge_file + 1 else edge_file - 1) {
                if (!ownOrEmpty(e.at(t))) return null;
                if (e.walk(t, st(10)) != e.q) return null;
                e.liftQueen();
                if (e.at(t) != 0) return e.seeBeside(t);
                if (e.seeE(t, 27) >= 0) return .threat;
                e.restoreQueen();
                return null;
            }
            return null;
        }

        /// A563-A5BF: the queen on the first rank, the king on a2 or b2.
        fn cornerB1(e: *Self) Next {
            return e.cornerFirstRank(sq(0x16), sq(0x17), 1, sq(0x15), 0x1C);
        }

        /// A746-A7AD: the queen on the first rank, the king on g2 or h2.
        fn cornerG1(e: *Self) Next {
            return e.cornerFirstRank(sq(0x1B), sq(0x1A), -1, sq(0x1C), 0x1A);
        }

        fn cornerFirstRank(e: *Self, t: i16, from: i16, comptime dir: i16, corner: i16, comptime q_limit: i16) Next {
            if (rel(e.q) > q_limit) return .back_rank;
            var s = from;
            while (e.at(s) == 0) s += dir;
            if (e.at(t) == 0) {
                if (s != e.q) return .back_rank;
                e.liftQueen();
                if (e.seeE(t, 27) >= 0) return .threat;
                return e.aaf8(corner);
            }
            if (!ownOrEmpty(e.at(t))) return .back_rank;
            if (s != e.q) return .back_rank;
            e.liftQueen();
            return e.ab80(t);
        }

        // The shared tails of 4.4, the queen lifted.
        fn aaf8(e: *Self, t: i16) Next {
            return if (e.at(t) != 0) e.ab79(t) else e.aaff(t);
        }
        fn aaff(e: *Self, t: i16) Next {
            if (e.seeE(t, 27) >= 0) return .threat;
            return e.ab8f();
        }
        fn ab79(e: *Self, t: i16) Next {
            if (!ownOrEmpty(e.at(t))) return e.ab8f();
            return e.ab80(t);
        }
        fn ab80(e: *Self, t: i16) Next {
            if (e.seeE(t, 27) > 0) return .mate;
            return e.ab8f();
        }
        fn ab8f(e: *Self) Next {
            e.restoreQueen();
            return .back_rank;
        }
        fn ab46(e: *Self, t: i16) Next {
            if (e.seeE(t, 27) <= 0) return e.ab8f();
            return if (e.at(t) == own_pawn) .threat else .mate;
        }
        fn ab86(e: *Self, t: i16) Next {
            // A86D
            if (!ownOrEmpty(e.at(t))) return e.ab8f();
            return e.ab46(t);
        }

        /// 4.4 step 2 (A7AE-AB93): the king on the first rank.
        fn firstRank(e: *Self, k: i16) Next {
            // the pawn shield attacked by a pawn
            const shield = if (rel(k) >= 0x1A)
                e.shieldPawnAttacked(sq(0x25)) or e.shieldPawnAttacked(sq(0x26))
            else if (rel(k) <= 0x17)
                e.shieldPawnAttacked(sq(0x20)) or e.shieldPawnAttacked(sq(0x1F))
            else
                false;
            if (shield) {
                if (e.ply <= e.t.ply_limit1) {
                    e.l02 -%= pen(300);
                    e.bump();
                }
                e.l04 -%= pen(24);
            }
            const qr = rel(e.q);
            if (qr <= 0x26 and qr >= 0x1F) return e.queenOnSecondRank(k);
            return e.queenAbove(k);
        }

        /// A7B3-A7EF: an own pawn on `s` attacked by an enemy pawn.
        inline fn shieldPawnAttacked(e: *const Self, s: i16) bool {
            return e.foePawnAttacks(s) != 0 and e.at(s) == own_pawn;
        }

        /// A817-A917: the queen on the second rank, the king on the first.
        fn queenOnSecondRank(e: *Self, k: i16) Next {
            var di = k + st(9);
            if (di > e.q) {
                if (e.at(di) != 0) {
                    if (!ownOrEmpty(e.at(di))) return .back_rank;
                    var s = di - 1;
                    while (e.at(s) == 0) s -= 1;
                    if (s != e.q) return .back_rank;
                    e.liftQueen();
                    return e.ab46(di);
                }
                var s = di - 1;
                while (e.at(s) == 0) s -= 1;
                if (s != e.q) return .back_rank;
                e.liftQueen();
                if (e.seeE(di, 27) >= 0) return .threat;
                di += 1;
                if (e.at(di) != 0) return e.ab86(di);
                if (e.seeE(di, 27) >= 0) return .threat;
                di += 1;
                if (e.at(di) != 0) return e.ab86(di);
                return e.aaff(di);
            }
            di += 2;
            if (e.at(di) != 0) {
                if (!ownOrEmpty(e.at(di))) return .back_rank;
                var s = di + 1;
                while (e.at(s) == 0) s += 1;
                if (s != e.q) return .back_rank;
                e.liftQueen();
                if (e.seeE(di, 27) > 0) return if (e.at(di) == own_pawn) .threat else .mate;
                return e.ab8f();
            }
            var s = di + 1;
            while (e.at(s) == 0) s += 1;
            if (s != e.q) return .back_rank;
            e.liftQueen();
            if (e.seeE(di, 27) >= 0) return .threat;
            di -= 1;
            if (e.at(di) != 0) return e.ab86(di);
            if (e.seeE(di, 27) >= 0) return .threat;
            di -= 1;
            if (e.at(di) != 0) return e.ab86(di);
            return e.aaff(di);
        }

        /// A918-AB93: the queen above the second rank, the king on the first.
        fn queenAbove(e: *Self, k: i16) Next {
            // the diagonals to the squares in front of the king: A026 K+10, K+11, K+9;
            // CD20 (D63B, D720, D760) K-10, K-11, K-9, where the mirror would be K-10,
            // K-9, K-11 (A026 tries the file right of the king's second, CD20 the left).
            // The first diagonal that reaches the queen decides (A9B3), so with the
            // queen on two of them the colours differ: B.zst records 2478 (A026, -860)
            // and 3629 (CD20, the same position mirrored, 600).
            // DEV-041, corrected by the rule, not by evidence: both orders are complete
            // and each routine is consistent with itself (its file tests below go the
            // same way, A026 bits 1 then 4, CD20 4 then 1, AAAC / D7DC); CD20's is
            // A026's steps negated. Corrected, CD20 takes A026's order mirrored, K-10,
            // K-9, K-11 (`st(10)`, `st(11)`, `st(9)`).
            const squares = if (white or mirror041(.queen_above))
                [3]i16{ k + st(10), k + st(11), k + st(9) }
            else
                [3]i16{ k - 10, k - 11, k - 9 };
            for (squares, 0..) |t, i| {
                const d = exactLine(t, e.q, diagRel(t - e.q));
                if (d == 0 or !ownOrEmpty(e.at(t))) continue;
                if (e.walk(t, d) != e.q) break; // A9B3
                e.liftQueen();
                if (i == 0) {
                    // A95E: K+10, then the square beyond it along the line
                    if (e.at(t) != 0) {
                        if (e.seeE(t, 27) > 0) return if (e.at(t) == own_pawn) .threat else .mate;
                    } else {
                        if (e.seeE(t, 27) >= 0) return .threat;
                        const t2 = t - d;
                        if (e.at(t2) == 0) {
                            if (e.seeE(t2, 27) >= 0) return .threat;
                        } else if (ownOrEmpty(e.at(t2))) {
                            if (e.seeE(t2, 27) > 0) return .mate;
                        }
                    }
                } else {
                    // AA77
                    if (e.at(t) != 0) {
                        if (e.seeE(t, 27) > 0) return if (e.at(t) == own_pawn) .threat else .mate;
                    } else {
                        if (e.seeE(t, 27) >= 0) return .threat;
                    }
                }
                e.restoreQueen(); // A9AE
                break;
            }
            // A9B3: the queen on the king's file or a file beside it
            const kfile: i16 = @as(i8, @bitCast(e.p.king_file[@backingInt(S)]));
            const bits = queenFileBits(e.q - kfile);
            if (bits & 2 != 0) {
                const t = k + st(10);
                const c = e.at(t);
                if (c == 0 or !ownOrEmpty(c)) return .back_rank;
                if (e.walk(t, st(10)) != e.q) return .back_rank;
                e.liftQueen();
                return e.ab46(t);
            }
            if (bits & 1 != 0) return e.fileBeside(k + st(11));
            if (bits & 4 != 0) return e.fileBeside(k + st(9));
            return .back_rank;
        }

        /// AAB2 / AB18: the queen coming down the file beside the king's to `t`.
        fn fileBeside(e: *Self, t: i16) Next {
            if (!ownOrEmpty(e.at(t))) return .back_rank;
            if (e.walk(t, st(10)) != e.q) return .back_rank;
            e.liftQueen();
            if (e.at(t) != 0) return e.ab46(t);
            if (e.seeE(t, 27) >= 0) return .threat;
            return e.aaf8(t + st(-10));
        }

        /// 4.4 steps 3 and 4 (AB9B-AD8F): the back rank.
        fn backRank(e: *Self, k: i16) Next {
            if (rel(k) <= 0x1C) return e.backRankFirst(k);
            // AB9B: the king on the second rank
            if (e.at(k + st(-10)) != 0) return .done;
            if (!(e.foeRookOnFirstRank(4) or e.foeRookOnFirstRank(5))) return .done;
            var s: i16 = undefined;
            if (rel(k) >= 0x25) {
                s = k + st(-11);
                while (e.at(s) == 0) s -= 1;
            } else if (rel(k) <= 0x20) {
                s = k + st(-9);
                while (e.at(s) == 0) s += 1;
            } else return .done;
            if (e.at(s) != foe_rook) return .done;
            e.put(s, 0);
            if (e.seeE(k + st(-10), 15) < 0) {
                e.put(s, foe_rook);
                return .done;
            }
            e.rook_sq = s;
            return .rook;
        }

        /// ABAA: an enemy rook entry on the first rank (unsigned compare; a captured
        /// piece's entry is not).
        inline fn foeRookOnFirstRank(e: *const Self, comptime slot: u8) bool {
            const r = e.foe(slot);
            // CD20 (D8F0) bounds the entry on both sides
            return if (white) r <= 0x1C else (r >= 0x5B and r <= 0x62);
        }
        /// ACDE: an enemy rook entry on the second rank.
        inline fn foeRookOnSecondRank(e: *const Self, comptime slot: u8) bool {
            const r = e.foe(slot);
            return if (white) (r >= 0x1F and r <= 0x26) else (r >= 0x51 and r <= 0x58);
        }

        /// The rook found at `s` lifted, SEE on `t`: > 0 when `t` is occupied, >= 0 when empty.
        fn rookTest(e: *Self, s: i16, t: i16) bool {
            e.put(s, 0);
            const r = e.seeE(t, 15);
            if (if (e.at(t) != 0) r > 0 else r >= 0) {
                e.rook_sq = s;
                return true;
            }
            e.put(s, foe_rook);
            return false;
        }

        /// AC10-ACDD: the king on the first rank.
        fn backRankFirst(e: *Self, k: i16) Next {
            const front = k + st(10);
            const c = e.at(front);
            if (c != 0 and ownOrEmpty(c) and e.p.pawns_per_file[@backingInt(E)][@intCast(@as(i8, @bitCast(e.p.king_file[@backingInt(S)])))] == 0) {
                const s = e.walk(front, st(10));
                if (e.at(s) == foe_rook) {
                    e.put(s, 0);
                    if (e.seeE(front, 15) > 0) {
                        e.rook_sq = s;
                        return .rook;
                    }
                    e.put(s, foe_rook);
                }
            }
            inline for (.{ 1, -1 }) |side_step| {
                const t = k + side_step;
                if (e.at(t) == 0) {
                    const s = e.walk(t, st(10));
                    if (e.at(s) == foe_rook) {
                        e.put(s, 0);
                        if (e.foePawnAttacks(t) != 0 or e.seeE(t, 15) >= 0) {
                            e.rook_sq = s;
                            return .rook;
                        }
                        e.put(s, foe_rook);
                    }
                }
            }
            return e.backRankSecond(front);
        }

        /// ACDE-AD8F: an enemy rook on the second rank reaching `t` (the square in
        /// front of or below the king) along the rank.
        fn backRankSecond(e: *Self, t: i16) Next {
            if (!(e.foeRookOnSecondRank(4) or e.foeRookOnSecondRank(5))) return .done;
            if (!ownOrEmpty(e.at(t))) return .done;
            // A026 looks right first (AD0F), CD20 left first (DA66): not the mirror
            // (CD20's step is A026's negated). DEV-041 lists it; it is left as it is,
            // because the order cannot change the result or the flag: each rook's test
            // lifts that rook alone and puts it back when it fails, so the board is the
            // same for the second test as for the first; the outcome is `.rook` when
            // either test passes, `.done` when neither does; and `finish` scores `.rook`
            // without regard to which rook it was, putting it back where it stood. Only
            // the order of the exchange calls, and so what they leave in their work
            // area, differs. (Proved here by that reading; the mirrored tests check it
            // on every recorded and generated call.)
            const first: i16 = if (white) 1 else -1;
            var s = t + first;
            while (e.at(s) == 0) s += first;
            if (e.at(s) == foe_rook) {
                if (e.rookTest(s, t)) return .rook;
            }
            s = t - first;
            while (e.at(s) == 0) s -= first;
            if (e.at(s) != foe_rook) return .done;
            if (e.rookTest(s, t)) return .rook;
            return .done;
        }

        // ---- 4.5 centre and weak pawns --------------------------------------------------

        fn pawns(e: *Self) void {
            if (e.p.piece_material_sum >= 6200) {
                // ADD7 e5, AE2A d5: an own pawn not defended by a pawn, attacked by a pawn
                // or a knight
                inline for (.{ 0x41, 0x40 }) |c| {
                    const s = sq(c);
                    if (e.at(s) == own_pawn and e.ownPawnAttacks(s) == 0 and
                        (e.foePawnAttacks(s) != 0 or (e.knightsReach(s) and e.att(s, 6) < 0)))
                    {
                        if (e.ply <= e.t.ply_limit1) {
                            e.l02 -%= pen(300);
                            e.bump();
                        }
                        e.l04 -%= pen(40);
                    }
                }
                return;
            }
            // AE86: the endgame, attacked weak pawns
            if (e.p.piece_count[@backingInt(E)] == 0) return;
            const mat = e.p.piece_material[@backingInt(E)];
            const kind: enum { rooks, pieces, queen } = if (mat == 1100) .rooks else if (e.q > 0x62) .pieces else if (mat == 2000) .queen else return;
            while (true) {
                const slot = lowestSlot(e.v.weak_pawns);
                if (slot == 0) return;
                e.v.weak_pawns &= slotClearMask(slot);
                const s = e.own(slot);
                if (e.boardAt(s) != own_pawn) continue; // a captured pawn's entry reads past the board
                const aimed = switch (kind) {
                    .rooks => e.rooksOnLine(s) != 0,
                    .pieces => (e.rooksOnLine(s) | e.bishopsOnDiag(s) | foeKnight(s, e.foe(0)) | foeKnight(s, e.foe(1))) != 0,
                    .queen => e.queenOnLineOrDiag(s),
                };
                if (!aimed) continue;
                if (e.att(s, 6) >= 0) continue;
                // AFDE
                if (kind == .rooks) {
                    if (e.ply >= e.t.ply_limit2) {
                        e.l04 -%= pen(40);
                        return;
                    }
                } else if (e.ply > e.t.ply_limit1) {
                    e.l04 -%= pen(40);
                    return;
                }
                // AFE6
                if (rel(s) <= 0x30 and e.boardAt(s + st(10)) == foe_pawn) e.l02 -%= pen(100);
                e.l02 -%= pen(200);
                e.bump();
                e.l04 -%= pen(40);
                return;
            }
        }

        // ---- 4.6 the own queen ------------------------------------------------------------

        fn queenBlock(e: *Self) After {
            var qs: i16 = e.own(6);
            if (qs > 0x62) {
                const slot = e.t.promoted_queen_slot[@backingInt(S)];
                if (slot == 0) return .next_piece;
                qs = e.p.piece_list[@intCast(own_list + @as(i16, @as(i8, @bitCast(slot))))];
                if (qs > 0x62) return .next_piece;
            }
            e.put(qs, 0);
            var line: u8 = undefined; // [bp-10h]
            search: {
                // B03A: the bishop of the queen's square colour on a diagonal with it
                const slot2 = bishopSlot2For(qs);
                const bsq = if (slot2) e.foe(2) else e.foe(3);
                const bd = foeDiag(qs, bsq);
                if (bd != 0 and (!slot2 or bsq < 0x63)) {
                    const s = e.walk(qs, bd);
                    if (e.at(s) == foe_bishop) {
                        if (rayStep(e.kingRay(qs)) == bd) {
                            e.l04 -%= pen(400);
                            return e.queenPinned(qs);
                        }
                        var r = qs - bd;
                        while (e.at(r) == 0) r -= bd;
                        if (e.at(r) == own_rook) e.l06 +%= 1;
                        line = @intCast(@abs(bd));
                        break :search;
                    }
                }
                // B0FC: a rook on a line
                if (e.rooksOnLine(qs) != 0) {
                    if (e.at(e.walk(qs, st(10))) == foe_rook) {
                        if (e.kingRay(qs) == rayCode(st(10))) return e.queenPinned(qs);
                        if (e.ply <= e.t.ply_limit1) {
                            e.l02 -%= pen(300);
                            e.bump();
                        }
                        line = 10;
                        break :search;
                    }
                    if (e.at(e.walk(qs, 1)) == foe_rook) {
                        if (e.kingRay(qs) == rayCode(1)) return e.queenPinned(qs);
                        line = 1;
                        break :search;
                    }
                    if (e.at(e.walk(qs, -1)) == foe_rook) {
                        if (e.kingRay(qs) == rayCode(-1)) return e.queenPinned(qs);
                        line = 1;
                        break :search;
                    }
                    if (e.at(e.walk(qs, st(-10))) == foe_rook) {
                        if (e.kingRay(qs) == rayCode(st(-10))) return e.queenPinned(qs);
                        line = 10;
                        break :search;
                    }
                }
                // B1C2: attacked by a pawn
                if (e.foePawnAttacks(qs) != 0) {
                    e.l06 = 13; // B1C9: selects T2 of the result table (DEV-020)
                    if (fixes.dev020_threat_table_index) e.selects +%= 1;
                    if (e.ply <= e.t.ply_limit1) {
                        e.l02 -%= pen(500);
                        e.put(qs, own_queen);
                        e.l06 +%= 1;
                        e.bump();
                        e.l02 -%= pen(1500);
                        return .tail;
                    }
                    e.l06 +%= 1;
                    line = 0;
                    break :search;
                }
                // B1F6: attacked by a knight
                if (e.knightsReach(qs)) {
                    e.l08 +%= 1;
                    line = 0;
                    break :search;
                }
                // B3E0: attacked by the enemy queen
                e.put(qs, own_queen);
                if (e.queenOnLineOrDiag(qs) and e.att(qs, 54) < 0) {
                    e.l08 +%= 1;
                    if (e.ply <= e.t.ply_limit1) {
                        e.l02 -%= pen(300);
                        e.bump();
                    }
                }
                return .next_piece;
            }
            // B21D: the escape search, except along the line of the attack
            if (e.queenEscapes(qs, line)) {
                if (line != 0) e.l08 +%= 1;
                e.put(qs, own_queen);
                return .next_piece;
            }
            return e.queenPinned(qs);
        }

        /// B0A7: the queen pinned or trapped.
        fn queenPinned(e: *Self, qs: i16) After {
            e.put(qs, own_queen);
            e.l02 -%= pen(500);
            if (e.ply < e.t.ply_limit3) {
                e.bump();
                e.l02 -%= pen(1000);
            }
            return .tail;
        }

        /// B21D-B3DF: a safe square for the queen, the same order of directions for both
        /// colours.
        fn queenEscapes(e: *Self, qs: i16, line: u8) bool {
            const pairs = [4]struct { line: u8, a: i16, b: i16 }{
                .{ .line = 9, .a = -9, .b = 9 },
                .{ .line = 11, .a = -11, .b = 11 },
                .{ .line = 1, .a = 1, .b = -1 },
                .{ .line = 10, .a = 10, .b = -10 },
            };
            for (pairs) |pr| {
                if (pr.line == line) continue;
                if (e.safeAlong(qs, pr.a, 27, .any_enemy)) return true;
                if (e.safeAlong(qs, pr.b, 27, .any_enemy)) return true;
            }
            return false;
        }

        const EndTest = enum {
            /// The queen and rooks: an enemy piece ending the line is tried.
            any_enemy,
            /// The bishops: an enemy pawn is tried, another enemy piece is safe.
            bishop,
        };

        /// One direction of an escape search: every empty square, then the piece ending
        /// the line, tried with the attacker routine; true at the first result >= 0.
        fn safeAlong(e: *Self, from: i16, d: i16, value: u16, comptime end: EndTest) bool {
            var s = from + d;
            while (e.at(s) == 0) : (s += d) {
                if (e.att(s, value) >= 0) return true;
            }
            const c = e.at(s);
            if (!foePiece(c)) return false;
            if (end == .bishop and foeNonPawn(c)) return true;
            return e.att(s, value) >= 0;
        }

        // ---- 4.7 rooks ----------------------------------------------------------------------

        /// B415 (slot 5) / B893 (slot 4).
        fn rookBlock(e: *Self, comptime slot: u8) After {
            const r = e.own(slot);
            if (r > 0x62) return .next_piece;
            const code = e.kingRay(r);
            attacked: {
                if (code > ro and code <= 4 + ro) {
                    // B437: on a diagonal king ray
                    const s = e.walk(r, rayStep(code));
                    if (e.at(s) == foe_bishop) {
                        if (e.ply < e.t.ply_limit2) {
                            e.l02 -%= pen(1300);
                            e.bump();
                        } else if (e.foePawnAttacks(r) != 0) {
                            e.l02 -%= pen(800); // B483
                            e.l08 +%= 1;
                            return .tail;
                        }
                        e.l04 -%= pen(300); // B470
                        e.l06 +%= 1;
                        return .next_piece;
                    }
                    if (e.at(s) == foe_queen) {
                        if (e.foePawnAttacks(r) != 0) {
                            if (e.ply < e.t.ply_limit2) { // B49F
                                e.l02 -%= pen(400);
                                e.bump();
                            }
                            e.l02 -%= pen(800);
                            return .tail;
                        }
                        if (e.knightsReach(r)) {
                            e.l04 -%= pen(350);
                            if (e.ply >= e.t.ply_limit2) return .next_piece;
                            e.l02 -%= pen(800);
                            e.bump();
                            return .next_piece;
                        }
                        // B4F8: a bishop on the other diagonal through the rook, walked
                        // up the board first (+11 or +9), then down; the first bishop
                        // found decides whether it stands next to the rook (L04 -= 300).
                        // CD20 (E250-E2F0, slot 4 E6xx) is the same code with the same
                        // steps, so it too walks up first, where the mirror walks down
                        // first. It matters only with an enemy bishop on each side of the
                        // rook on that diagonal (two on one colour of square: a promoted
                        // bishop). DEV-041, corrected by the rule, not by evidence:
                        // Black's walk is White's mirrored (`st(d1)` first).
                        var gap: ?i16 = null;
                        var d1: i16 = 9;
                        if (mirror041(.rook_other_diagonal)) {
                            d1 = if (code == rayCode(st(9)) or code == rayCode(st(-9))) st(11) else st(9);
                        } else if (code == rayCode(9) or code == rayCode(-9)) d1 = 11;
                        const up = e.walk(r, d1);
                        if (e.at(up) == foe_bishop) gap = up - r else {
                            const down = e.walk(r, -d1);
                            if (e.at(down) == foe_bishop) gap = r - down;
                        }
                        if (gap) |g| {
                            if (g == d1) e.l04 -%= pen(300);
                        } else if (e.att(r, 30) >= 0) return .next_piece;
                        return e.rookB52B(r);
                    }
                }
                // B5AA: attacked by a pawn
                if (e.foePawnAttacks(r) != 0) {
                    e.l06 +%= 13; // B5B1 / BA11: selects T2 of the result table (DEV-020)
                    if (fixes.dev020_threat_table_index) e.selects +%= 1;
                    break :attacked;
                }
                // B5F0: by a knight
                if (e.knightsReach(r)) break :attacked;
                // by a bishop of the rook's square colour
                bishop: {
                    const slot2 = bishopSlot2For(r);
                    const bsq = if (slot2) e.foe(2) else e.foe(3);
                    const bd = foeDiag(r, bsq);
                    if (bd == 0 or (slot2 and bsq >= 0x63)) break :bishop;
                    const s = e.walk(r, bd);
                    if (e.at(s) != foe_bishop) break :bishop;
                    var b = r - bd;
                    while (e.at(b) == 0) b -= bd;
                    if (ownHeavyOrKing(e.at(b))) {
                        if (s - bd == r) e.l04 -%= pen(200); // B68A
                        return e.rookB52B(r);
                    }
                    if (e.ply <= e.t.ply_limit1) { // B6BA
                        e.l02 -%= pen(100);
                        e.bump();
                    }
                    break :attacked;
                }
                // B6CA: by the queen on a diagonal
                const qd = foeDiag(r, e.q);
                if (qd != 0 and e.at(e.walk(r, qd)) == foe_queen) {
                    if (e.att(r, 30) >= 0) return .next_piece;
                    e.l08 +%= 1;
                    return e.rookFirstRank(r);
                }
                // B70E: by the king
                if (kingRel(r - e.foeKing()) != 0 and e.att(r, 30) < 0) {
                    if (e.v.passer_flags == 0) {
                        e.l08 +%= 1;
                        return e.rookFirstRank(r);
                    }
                    return e.rookB730();
                }
                // B738: by a rook on the same rank
                if (e.rooksOnLine(r) & 1 == 0) return .next_piece;
                if (e.att(r, 30) >= 0) return .next_piece;
                e.l08 +%= 1;
                if (e.ply > e.t.ply_limit1) return .next_piece;
                e.l02 -%= pen(250);
                e.bump();
                return .next_piece;
            }
            // B5B5
            e.l06 +%= 1;
            return e.rookFirstRank(r);
        }

        /// B52B: the rook in line with a bishop.
        fn rookB52B(e: *Self, r: i16) After {
            e.l04 -%= pen(200);
            if (e.ply >= e.t.ply_limit2) {
                e.l06 +%= 1;
                return e.rookFirstRank(r);
            }
            return e.rookB730();
        }

        /// B730: L02 -= 700 and the flag.
        fn rookB730(e: *Self) After {
            e.l02 -%= pen(700);
            e.bump();
            return .next_piece;
        }

        /// B5B8: the rook on the first rank, then the escape search.
        fn rookFirstRank(e: *Self, r: i16) After {
            if (rel(r) <= 0x1C) {
                const f = e.at(r + st(10));
                if (f == foe_pawn) {
                    if (e.ply < e.t.ply_limit2) return e.rookB730();
                    if (e.l06 != 0) e.l04 -%= pen(200);
                } else if (f != 0 and ownOrEmpty(f)) {
                    if (e.ply <= e.t.ply_limit1) {
                        e.l02 -%= pen(300);
                        e.bump();
                    }
                }
            }
            // B799: the escape search
            e.put(r, 0);
            const order = if (white) [4]i16{ -10, -1, 1, 10 } else [4]i16{ 10, 1, -1, -10 };
            const safe = for (order) |d| {
                if (e.safeAlong(r, d, 15, .any_enemy)) break true;
            } else false;
            if (!safe) {
                e.l04 -%= pen(300);
                if (e.foePawnAttacks(r) != 0) {
                    if (e.ply < e.t.ply_limit3) {
                        e.l02 -%= pen(900);
                        e.bump();
                    }
                } else if (e.ply < e.t.ply_limit2) {
                    e.l02 -%= pen(700);
                    e.bump();
                }
            }
            e.put(r, own_rook);
            return .next_piece;
        }

        // ---- 4.7 knights ----------------------------------------------------------------------

        /// The knight's squares in the order each colour visits them; a knight on the
        /// first three ranks with no safe square found after the first six pays 36.
        /// DEV-021 (`Fixes.dev021_knight_escape_order`): A026 visits -8, -12, +8, +12,
        /// +19, +21, -19, -21 (BE50-C23A, C3BE-C7A8); CD20 visits the negation of that,
        /// +8, +12, -8, -12, -19, -21, +19, +21 (EBAC-EF7B, F10A-F4E1), a half turn of
        /// the board, where the colour mirror (ranks reversed) is +12, +8, -12, -8, -21,
        /// -19, +21, +19: each pair is visited the other way round. The pairs, and so the
        /// six squares before the 36, are the same; within a pair the order matters only
        /// when one square holds an own pawn that is attacked (paid for during the visit)
        /// and the other an own piece that is attacked (which ends the search at once):
        /// the colour that visits the pawn first pays L04 -100, and L02 -200 with the
        /// flag below ply limit 2, and the other does not. Corrected (by the rule of
        /// decisions 28 and 30: the code shows no preferred order), CD20 visits the
        /// mirror of A026's order.
        const knight_escape_order = if (white)
            [8]i16{ -8, -12, 8, 12, 19, 21, -19, -21 }
        else if (fixes.dev021_knight_escape_order)
            [8]i16{ st(-8), st(-12), st(8), st(12), st(19), st(21), st(-19), st(-21) }
        else
            [8]i16{ 8, 12, -8, -12, -19, -21, 19, 21 };

        /// BCF3 (slot 0) / C26E (slot 1).
        fn knightBlock(e: *Self, comptime slot: u8) After {
            const n = e.own(slot);
            if (n > 0x62) return .next_piece;
            const code = e.kingRay(n);
            if (code != 0) {
                // BD0B: pinned to the king by a slider of the line
                const s = e.walk(n, rayStep(code));
                if (pieceSlider(e.at(s)) & raySlider(code) != 0) {
                    if (e.foePawnAttacks(n) != 0) return e.pinnedPawnAttacked();
                    if (e.att(n, 18) >= 0) return .next_piece;
                    e.l08 +%= 1;
                    if (e.ownPawnAttacks(n) != 0) return .next_piece;
                    e.l04 -%= pen(if (@as(i8, @bitCast(e.p.piece_count[@backingInt(S)])) <= 1) 328 else 128);
                    if (e.ply > e.t.ply_limit2) return .next_piece;
                    return e.knightBD89();
                }
            }
            // BD96
            if (e.foePawnAttacks(n) != 0) {
                if (e.ply <= e.t.ply_limit1) {
                    e.l02 -%= pen(250);
                    e.bump();
                }
                e.l06 +%= 1;
            } else {
                if (e.ownPawnAttacks(n) != 0) return .next_piece;
                const reach = (e.rooksOnLine(n) | e.bishopsOnDiag(n) |
                    foeKnight(n, e.foe(0)) | foeKnight(n, e.foe(1)) |
                    @as(u8, @bitCast(foeOrth(n, e.q) | foeDiag(n, e.q))) |
                    kingRel(n - e.foeKing()));
                if (reach == 0) return .next_piece;
                if (e.att(n, 18) >= 0) return .next_piece;
                if (e.ply <= e.t.ply_limit1) return e.knightBD89();
                e.l08 +%= 1;
            }
            // BE44: the escape squares, the knight lifted from the board and its list entry
            e.p.piece_list[own_list + slot] = 0;
            e.put(n, 0);
            e.l12 = false;
            for (knight_escape_order, 0..) |d, i| {
                if (!e.knightSquare(n + d)) {
                    e.p.piece_list[own_list + slot] = @intCast(n);
                    e.put(n, own_knight);
                    e.l08 +%= 1;
                    return .next_piece;
                }
                if (i == 5 and rel(n) <= 0x30 and !e.l12) e.l02 -%= pen(36);
            }
            e.p.piece_list[own_list + slot] = @intCast(n);
            e.put(n, own_knight);
            if (e.l12) return .next_piece;
            e.l04 -%= pen(350);
            if (e.ply >= e.t.ply_limit2) return .next_piece;
            return e.knightBD89();
        }

        /// BD89 / C2F7: L02 -= 500 and the flag.
        fn knightBD89(e: *Self) After {
            e.l02 -%= pen(500);
            e.bump();
            return .next_piece;
        }

        /// One knight square; false when an own piece there is attacked (the search ends).
        fn knightSquare(e: *Self, s: i16) bool {
            const c = e.at(s);
            if (ownMinorOrMajor(c)) return e.att(s, attValue(c)) >= 0;
            if (c == own_pawn) {
                if (e.att(s, 6) < 0) {
                    e.l04 -%= pen(100);
                    if (e.ply < e.t.ply_limit2) {
                        e.l02 -%= pen(200);
                        e.bump();
                    }
                }
                return true;
            }
            if (e.l12) return true;
            if (foeNonPawn(c)) {
                e.l12 = true;
            } else if (c == 0 or c == foe_pawn) {
                if (e.att(s, 9) >= 0) e.l12 = true;
            }
            return true;
        }

        /// C820: a pinned knight or bishop attacked by a pawn.
        fn pinnedPawnAttacked(e: *Self) After {
            e.l04 -%= pen(450);
            if (e.ply < e.t.ply_limit2) {
                e.l02 -%= pen(800);
                e.bump();
            } else e.l06 +%= 1; // CD1A
            return .tail;
        }

        // ---- 4.7 bishops ----------------------------------------------------------------------

        /// C7DC (slot 2) / CA4C (slot 3).
        fn bishopBlock(e: *Self, comptime slot: u8) After {
            const b = e.own(slot);
            if (b > 0x62) return .next_piece;
            const code = e.kingRay(b);
            if (code > 4 + ro) {
                // C7E6: pinned on an orthogonal king ray by a rook or queen
                const c = e.at(e.walk(b, rayStep(code)));
                if (c >= foe_rook and c <= foe_queen) {
                    if (e.foePawnAttacks(b) != 0) {
                        e.l02 -%= pen(50);
                        return e.pinnedPawnAttacked();
                    }
                    if (e.att(b, 18) >= 0) return .next_piece;
                    e.l08 +%= 1;
                    if (e.ownPawnAttacks(b) != 0) return .next_piece;
                    e.l04 -%= pen(if (@as(i8, @bitCast(e.p.piece_count[@backingInt(S)])) <= 1) 328 else 128);
                    if (e.ply >= e.t.ply_limit2) return .next_piece;
                    return e.bishopC877();
                }
            }
            // C884
            if (e.foePawnAttacks(b) != 0) {
                e.l06 +%= 1;
                if (e.ply <= e.t.ply_limit1 and e.p.pawns_per_file[@backingInt(E)][fileOf(b)] == 0) return e.bishopC877();
            } else {
                if (e.knightsReach(b)) {
                    e.l02 -%= pen(24);
                    if (e.ownPawnAttacks(b) != 0) return .next_piece;
                } else {
                    if (e.ownPawnAttacks(b) != 0) return .next_piece;
                    // the other enemy bishop: slot 3 for bishop 2, slot 2 for bishop 3
                    const other_bishop = e.foe(if (slot == 2) 3 else 2);
                    const reach = e.rooksOnLine(b) | @as(u8, @bitCast(foeDiag(b, other_bishop))) |
                        kingRel(b - e.foeKing()) | @as(u8, @bitCast(foeOrth(b, e.q)));
                    if (reach == 0) return .next_piece;
                }
                if (e.att(b, 18) >= 0) return .next_piece;
                if (e.ply <= e.t.ply_limit1) return e.bishopC877();
                e.l08 +%= 1;
            }
            // C942: the escape search
            e.put(b, 0);
            const order = if (white) [4]i16{ -9, -11, 9, 11 } else [4]i16{ 9, 11, -9, -11 };
            const safe = for (order) |d| {
                if (e.safeAlong(b, d, 9, .bishop)) break true;
            } else false;
            if (!safe) {
                e.l04 -%= pen(400);
                if (e.ply <= e.t.ply_limit2) {
                    e.l02 -%= pen(550);
                    e.bump();
                }
            }
            e.put(b, own_bishop);
            return .next_piece;
        }

        /// C877: L02 -= 550 and the flag.
        fn bishopC877(e: *Self) After {
            e.l02 -%= pen(550);
            e.bump();
            return .next_piece;
        }
    };
}

test "evalthreats: DEV-020: the result word, original and corrected" {
    const expectEqual = std.testing.expectEqual;
    // T1 (n - m = -7 .. +6) and T2 (n - m = 7 .. 20, centred at 13), as read from the
    // executable (spec 3.4)
    const t1 = [14]i16{ -1000, -900, -800, -700, -600, -500, -300, 0, 24, 300, 500, 600, 700, 800 };
    const t2 = [14]i16{ -850, -750, -650, -550, -450, -300, 0, 24, 300, 500, 600, 700, 800, 900 };
    for (t1, 0..) |w, i| {
        const n: i16 = @as(i16, @intCast(i)) - 7 + 3; // m = 3
        try expectEqual(w, settleWord(n, 3));
        try expectEqual(w, settleWordFixed(n, 3, 0));
    }
    for (t2, 0..) |w, i| {
        const n: i16 = 13 + @as(i16, @intCast(i)) - 6 + 2; // one pawn attack, m = 2
        try expectEqual(w, settleWord(n, 2));
        try expectEqual(w, settleWordFixed(n, 2, 1));
    }
    // The queen and a rook (or both rooks) attacked by pawns, no other threat, m = 0:
    // n = 14 + 14 = 28. The original reads DG:03C0 in the next table (800, as seven
    // threats); corrected, two threats in T2: 300, as one pawn attack and one other
    // threat (n = 15) give.
    try expectEqual(@as(i16, 800), settleWord(28, 0));
    try expectEqual(@as(i16, 300), settleWordFixed(28, 0, 2));
    try expectEqual(settleWord(15, 0), settleWordFixed(28, 0, 2));
    // n = 29: the original 900 (DG:03C2), corrected 500 (three threats in T2).
    try expectEqual(@as(i16, 900), settleWord(29, 0));
    try expectEqual(@as(i16, 500), settleWordFixed(29, 0, 2));
    // Eight threats beyond m without a pawn attack: the original reads T2's -750, a
    // bonus to the side examined; corrected, T1's last penalty 800.
    try expectEqual(@as(i16, -750), settleWord(8, 0));
    try expectEqual(@as(i16, 800), settleWordFixed(8, 0, 0));
    // Below the tables: T1 at -8 reads DG:0378 (0); corrected -1000. T2 at -7 (n = 14,
    // m = 8) reads T1's 800; corrected T2's -850.
    try expectEqual(@as(i16, 0), settleWord(0, 8));
    try expectEqual(@as(i16, -1000), settleWordFixed(0, 8, 0));
    try expectEqual(@as(i16, 800), settleWord(14, 8));
    try expectEqual(@as(i16, -850), settleWordFixed(14, 8, 1));
}

test "evalthreats: DEV-052: the line tables, their pseudo-lines and their mirrors" {
    // The tables accept exactly the differences of real lines: DG:0C64 the ranks (1..7)
    // and files (10..70), DG:0B66 the diagonals (9k and 11k, k = 1..7), with the step
    // from the target toward the piece (the code walks it from the target).
    var d: i32 = -98;
    while (d <= 98) : (d += 1) {
        const a: u32 = @abs(d);
        const sgn: i8 = if (d < 0) 1 else -1; // the step leads from the target back to the piece
        const rank = a >= 1 and a <= 7;
        const file = a % 10 == 0 and a >= 10 and a <= 70;
        try std.testing.expectEqual(if (rank) sgn else if (file) sgn * 10 else @as(i8, 0), orthRel(d));
        const d9 = a % 9 == 0 and a >= 9 and a <= 63;
        const d11 = a % 11 == 0 and a >= 11 and a <= 77;
        // 99 (9 * 11) is beyond both
        try std.testing.expectEqual(if (d11) sgn * 11 else if (d9) sgn * 9 else @as(i8, 0), diagRel(d));
    }
    // Every pair of board squares the tables put on a line that is not one (a
    // pseudo-line), by difference; and the colour mirror of each such pair is a pair the
    // tables reject, so every pseudo-line is a colour asymmetry.
    var orth_pseudo: [100]u16 = @splat(0);
    var diag_pseudo: [100]u16 = @splat(0);
    var pairs: u32 = 0;
    for (21..99) |s| for (21..99) |t| {
        if (s % 10 == 0 or s % 10 == 9 or t % 10 == 0 or t % 10 == 9) continue;
        const si: i16 = @intCast(s);
        const ti: i16 = @intCast(t);
        const dr = @divTrunc(ti, 10) - @divTrunc(si, 10);
        const df = @mod(ti, 10) - @mod(si, 10);
        const o = orthRel(ti - si);
        const g = diagRel(ti - si);
        const o_real = (o != 0 and (if (@abs(o) == 1) dr == 0 else df == 0));
        const g_real = (g != 0 and @abs(dr) == @abs(df));
        const m_diff = (-10 * dr + df); // the mirrored pair's difference
        if (o != 0 and !o_real) {
            orth_pseudo[@abs(ti - si)] += 1;
            pairs += 1;
            try std.testing.expectEqual(@as(i8, 0), orthRel(m_diff));
            try std.testing.expectEqual(@as(i8, 0), diagRel(m_diff));
        }
        if (g != 0 and !g_real) {
            diag_pseudo[@abs(ti - si)] += 1;
            pairs += 1;
            try std.testing.expectEqual(@as(i8, 0), orthRel(m_diff));
            try std.testing.expectEqual(@as(i8, 0), diagRel(m_diff));
        }
        // the corrected lookup is the table where the line is real, none elsewhere
        try std.testing.expectEqual(if (o_real) o else 0, realLine(ti, si, o));
        try std.testing.expectEqual(if (g_real) g else 0, realLine(ti, si, g));
    };
    std.debug.print("evalthreats DEV-052: {d} ordered pairs of squares on a pseudo-line; orthogonal by |difference|:", .{pairs});
    for (orth_pseudo, 0..) |n, k| if (n != 0) std.debug.print(" {d}:{d}", .{ k, n });
    std.debug.print("; diagonal:", .{});
    for (diag_pseudo, 0..) |n, k| if (n != 0) std.debug.print(" {d}:{d}", .{ k, n });
    std.debug.print("\n", .{});
    // ranks 3..7 across the border column; diagonals 27, 36, 45, 54, 63 (9k, k >= 3) and
    // 33, 44, 55, 66 (11k, 3 <= k <= 6)
    for (0..100) |k| {
        try std.testing.expectEqual(k >= 3 and k <= 7, orth_pseudo[k] != 0);
        const dk = k == 27 or k == 36 or k == 45 or k == 54 or k == 63 or k == 33 or k == 44 or k == 55 or k == 66;
        try std.testing.expectEqual(dk, diag_pseudo[k] != 0);
    }
}
