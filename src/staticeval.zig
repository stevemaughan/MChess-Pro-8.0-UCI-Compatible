//! static_eval (2B9F:000E): the evaluation's material, square sums and passed pawns.
//!
//! Specifications: docs/arch/50-evaluation-map.md 4.1 (the quick path) and
//! docs/arch/52-evaluation-pawns.md section 6, whose executable form is
//! tools/research/evalpawns/static_eval.py with se_white_btm.py, se_black_btm.py,
//! se_white_wtm.py and se_black_wtm.py (proved against the running original on
//! 1,257,865 calls). Tests: src/evalpawns_test.zig (tests/golden/evalpawns/).
//!
//! The whole function: the quick path (000E-01A4), which is all of it whenever neither
//! passed-pawn mask is set; the full body's first section (01A8-0A32: special endings
//! with at most one pawn for a side, the passed-pawn tables and flags); the four
//! passed-pawn loops (White's and Black's pawns, for each side to move: 0A40-2443 with
//! Black to move, 2444-3EB5 with White to move), written as the original's blocks in a
//! labeled switch, one prong per block, named by its address; and the tail (3736-4029).
//! The White-to-move loops share blocks with the Black-to-move ones as the code does
//! (a compile-time `wtm` parameter picks the targets that differ).
//!
//! It calls six routines that are not ported here (`Callees`): the two exchange
//! evaluators of src/see.zig and four that have no model yet. DEV-015 is behind `Fixes`,
//! and so is DEV-053 (the line tables' pseudo-lines in the passed-pawn prefilters), which
//! the engine sets from `pos.Fixes`.

const std = @import("std");
const pos = @import("position.zig");
const dg = @import("original.zig").dgroup;
const EvalVars = @import("evalvars.zig").EvalVars;
const pawnhash = @import("pawnhash.zig");
const scalePercent = pawnhash.scalePercent;
const PawnHash = pawnhash.PawnHash;

const Position = pos.Position;

/// The routines static_eval's full body calls outside itself, as an interface: the test
/// implements it from the calls recorded in the original (src/evalpawns_test.zig
/// `CalleeReplay`); the engine will bind the ported routines. Arguments and results are
/// the original's words. The caller of `see_white`/`see_black` has emptied the pawn's
/// square on the board, as the original does around those calls (and around `4A76`/`4AD4`).
pub const Callees = struct {
    /// 2B9F:C32A, see_capture_by_white(square, value) (call at 2B9F:0C90): ported as
    /// src/see.zig `see(.white)`.
    see_white: *const fn (ctx: *anyopaque, square: u16, value: u16) u16,
    /// 2B9F:CAC2, see_capture_by_black(square, value) (call at 2B9F:330C): ported as
    /// src/see.zig `see(.black)`.
    see_black: *const fn (ctx: *anyopaque, square: u16, value: u16) u16,
    /// 4793:4CEC(square, value) (calls at 2B9F:105F, 1BAA): not ported.
    r4793_4CEC: *const fn (ctx: *anyopaque, square: u16, value: u16) u16,
    /// 4793:41B6(square, value) (calls at 2B9F:281E, 36E5): not ported.
    r4793_41B6: *const fn (ctx: *anyopaque, square: u16, value: u16) u16,
    /// 2B9F:4A76(square) (call at 2B9F:19B1): not ported.
    r2B9F_4A76: *const fn (ctx: *anyopaque, square: u16) u16,
    /// 2B9F:4AD4(square) (call at 2B9F:262B): not ported.
    r2B9F_4AD4: *const fn (ctx: *anyopaque, square: u16) u16,
    ctx: *anyopaque,
};

/// The switchable bug fixes of static_eval (AGENTS.md §9.2).
pub const Fixes = struct {
    /// DEV-015: two blocks of the full body (2B9F:1B74 and 27E8) OR in a never-written
    /// stack byte (`[bp-29h]`, `[bp-2Bh]`) where they meant the knight test stored one
    /// byte away. Corrected: that knight test. Original: the stray byte, an explicit input.
    dev015_knight_test: bool,
    /// DEV-053 (`pos.Fixes.dev053_line_tables_other`, owner decision 31): the passed-pawn
    /// prefilters (2B9F:1AE5-1B79 and 1B8A-1BA1, Black's pawns; 2759-27ED and 27FE-2815,
    /// White's) trust the line tables DG:0B66 and DG:0C64, which also give a step for two
    /// squares on no line and for a captured piece's entry. Corrected, only a real line
    /// between two squares of the board opens the prefilter (`realLineStep`). Not part of
    /// `corrected` (which is DEV-015, an uninitialised read, always fixed): the engine sets
    /// it from `pos.Fixes` (adapt_staticeval.zig `staticEvalFixes`).
    dev053_line_tables_other: bool = false,
    /// DEV-054 (`pos.Fixes.dev054_unstoppable_passer_mirror`, owner decision 44): Black's
    /// passer is unstoppable when White has no pieces (1E04, 398B) whatever White's
    /// passers; White's twins (1469 / 1473 and 2C3B / 2C45, the blocks reached from the
    /// king-position tests) need Black to have none, and go on to the general king tests
    /// (13AF, 2B71) when Black has one. Corrected, Black's form for both colours: White's
    /// passer is unstoppable there whatever Black's passers. Set like DEV-053.
    dev054_unstoppable_passer_mirror: bool = false,
    /// DEV-055 (`pos.Fixes.dev055_passer_block_extra_test`, owner decision 34): the test
    /// at 39EA, which drops a Black passer with White to move when White has a passed
    /// pawn, is in none of the block's three twins. Corrected, it is not made.
    dev055_passer_block_extra_test: bool = false,
    /// DEV-062 (`pos.Fixes.dev062_king_test_rank`, owner decision 34): the general king
    /// test of a White passer with White to move (2B71) counts it unstoppable at 2BA6 when
    /// it stands on or past the enemy king's rank; Black's with Black to move (1ED7) has
    /// no such test. Corrected, 1ED7 makes the mirror test.
    dev062_king_test_rank: bool = false,

    pub const original: Fixes = .{ .dev015_knight_test = false };
    pub const corrected: Fixes = .{ .dev015_knight_test = true };
};

/// The two frame bytes static_eval reads without ever writing them (DEV-015):
/// `[bp-29h]` (read at 2B9F:1B74, Black to move) and `[bp-2Bh]` (27E8, White to move).
/// In the original they hold whatever the stack held; for the replay of the original
/// they are an input, taken from the recorded call. `Fixes.corrected` does not read them.
pub const StrayBytes = struct {
    bp29: u8 = 0,
    bp2B: u8 = 0,
};

/// DG:1DDC: 44 per pawn, by the number of pawns (0..8): the pawn sum used instead of
/// the square sum once the enemy queen has gone since the root.
const pawns_without_enemy_queen: [9]i16 = blk: {
    const raw = dg(0x1DDC, 18);
    var t: [9]i16 = undefined;
    for (&t, 0..) |*x, i| x.* = @bitCast(std.mem.readInt(u16, raw[2 * i ..][0..2], .little));
    break :blk t;
};

/// A piece-list entry at or above this marks a captured piece (its square + 63h).
const captured_mark = 0x63;

/// Port of static_eval (2B9F:000E-4029). Returns the score from White's view.
///
/// `side` is the side to move (`[bp+6]`, 0 White, 1 Black) and `arg2` is ply - [9356]
/// (`[bp+8]`, read only by the passed-pawn loops). `stray` are the never-written frame
/// bytes the original reads (DEV-015), used only with `Fixes.original`: `[0]` for this
/// call, `[1]` for the call it makes to itself when a passed-pawn mask is stale
/// (0A6E / 2472, after storing a fresh pawn evaluation in the pawn hash).
///
/// Clears the five output bytes DG:39AE, A5F5, A8DE, 8CCA, 9EBA, which the full body
/// then sets; a draw sets DG:A8DE. The board is changed only for the duration of a callee
/// call and restored.
pub fn staticEval(p: *Position, v: *EvalVars, h: *PawnHash, callees: *const Callees, side: u16, arg2: u16, comptime fixes: Fixes, stray: [2]StrayBytes) i16 {
    return staticEvalWith(p, v, h, callees, side, arg2, fixes, stray);
}

fn staticEvalWith(p: *Position, v: *EvalVars, h: *PawnHash, callees: *const Callees, side: u16, arg2: u16, fixes: Fixes, stray: [2]StrayBytes) i16 {
    // 0014
    v.black_king_by_passer = 0;
    v.passer_flags = 0;
    v.draw_flag = 0;
    v.promotion_square = 0;
    v.promotion_flags = 0;
    var di: i16 = @bitCast(p.piece_square_sum);
    if (p.pawn_count != 0) { // 002D
        // Once a side's queen has gone since the root, the enemy pawns count 44 each
        // instead of their square sum.
        if (v.queen_gone_at_root[1] == 0 and p.piece_list[16 + 6] >= captured_mark) {
            di +%= pawns_without_enemy_queen[signedCount(p.side_pawn_count[0])];
        } else {
            di +%= @bitCast(v.pawn_square_sum[0]);
        }
        if (v.queen_gone_at_root[0] == 0 and p.piece_list[6] >= captured_mark) {
            di -%= pawns_without_enemy_queen[signedCount(p.side_pawn_count[1])];
        } else {
            di +%= @bitCast(v.pawn_square_sum[1]);
        }
    }
    if (v.style_normal == 0 and v.centrality_weight != 100) di = scalePercent(di, v.centrality_weight); // 0072
    di +%= @as(i16, @bitCast(p.material_balance_2)); // 00A6
    if (v.passed_pawns[0] | v.passed_pawns[1] != 0) { // the full body, 01A8
        var b: Body = .{ .p = p, .v = v, .h = h, .callees = callees, .side = side, .arg2 = arg2, .fixes = fixes, .stray = stray, .di = di };
        if (b.section1()) |x| return x;
        b.f.quick_score = @bitCast(b.di); // 0A33
        b.di = 0;
        if (side == 0) { // 0A38 -> 2444
            if (b.whitePassersWhiteToMove()) |r| return r;
            if (b.blackPassersWhiteToMove()) |r| return r;
        } else {
            if (b.whitePassersBlackToMove()) |r| return r;
            if (b.blackPassersBlackToMove()) |r| return r;
        }
        return b.tail();
    }
    if (p.pawn_count == 0) return noPawns(p, v, di); // 00B6
    if (p.piece_material_sum != 700) return di; // 0116
    return oneBishop(p, v, di);
}

fn signedCount(n: u8) usize {
    // The original indexes the table with 2 * (signed byte); a negative count would be a
    // corrupt position.
    return @intCast(@as(i8, @bitCast(n)));
}

/// 401C: a draw.
fn draw(v: *EvalVars) i16 {
    v.draw_flag = 1;
    v.passer_flags = 0;
    return 0;
}

/// 00B6: no pawns on the board.
fn noPawns(p: *const Position, v: *EvalVars, di: i16) i16 {
    const wm: i16 = @bitCast(p.material[0]);
    const bm: i16 = @bitCast(p.material[1]);
    if (wm <= 1300 and bm <= 1300 and wm != 1100 and bm != 1100) return draw(v);
    const balance: i16 = @bitCast(p.piece_balance);
    if (di >= 150) { // 00E0
        if (balance > 900) return di;
    } else if (di > -150) { // 00EE
        return di;
    } else if (balance < -900) { // 00F7
        return di;
    }
    // 0102: an unsigned compare
    return if (p.total_material < 2900) di >> 2 else di >> 1;
}

/// 0121: one bishop and pawns ([378E] = 700). A side whose pawns are all on the rook's
/// file of the wrong colour for its bishop is 200 worse, and a draw when the enemy king
/// stands in the corner. The code assumes the bishop is in slot 3 when slot 2 is empty.
fn oneBishop(p: *const Position, v: *EvalVars, di0: i16) i16 {
    var di = di0;
    const file = [2]i8{ @bitCast(p.king_file[0]), @bitCast(p.king_file[1]) };
    const rank = [2]i8{ @bitCast(p.king_rank[0]), @bitCast(p.king_rank[1]) };
    if (p.piece_material[0] != 0) { // White's bishop
        if (p.piece_list[2] < captured_mark) {
            if (p.side_pawn_count[0] != p.pawns_per_file[0][8]) return di;
            di -%= 200;
            if (file[1] < 7) return di;
        } else {
            if (p.side_pawn_count[0] != p.pawns_per_file[0][1]) return di; // 0150
            di -%= 200;
            if (file[1] > 2) return di;
        }
        if (rank[1] < 8) return di; // 0143
        return draw(v);
    }
    if (p.piece_list[16 + 2] < captured_mark) { // 0166: Black's bishop
        if (p.side_pawn_count[1] != p.pawns_per_file[1][8]) return di;
        di +%= 200;
        if (file[0] < 7) return di;
    } else {
        if (p.side_pawn_count[1] != p.pawns_per_file[1][1]) return di; // 0184
        di +%= 200;
        if (file[0] > 2) return di;
    }
    if (rank[0] > 3) return di; // 0198
    return draw(v);
}
// ---------------------------------------------------------------------------
// The full body, section 1 (2B9F:01A8-0A32)
// ---------------------------------------------------------------------------

/// DG addresses of the word tables by square that the passed-pawn loops read through
/// `Frame.white_passer_table` and `Frame.black_passer_table` (`word[table + 2 sq]`),
/// built by prepare_eval (docs/arch/50-evaluation-map.md 3.2: readers not traced there).
pub const table_746C: u16 = 0x746C;
pub const table_718C: u16 = 0x718C;
pub const table_90BA: u16 = 0x90BA;
pub const table_AE46: u16 = 0xAE46;
pub const table_A792: u16 = 0xA792;
pub const table_369E: u16 = 0x369E;

/// static_eval's frame locals that section 1 sets (docs/arch/52-evaluation-pawns.md 3.4;
/// the original's `[bp-xx]`).
pub const Frame = struct {
    /// `[bp-2]`: the score of the quick path and section 1, kept at 0A33.
    quick_score: u16 = 0,
    /// `[bp-4]`: the file of the pawn being scored.
    file: u16 = 0,
    /// `[bp-6]`, `[bp-8]`: scratch words of the loops (a knight's square, distances, a
    /// square, a product). Read only after being written in the same pawn's evaluation.
    scratch_a: u16 = 0,
    scratch_b: u16 = 0,
    /// `[bp-18h]`: the passed pawns still to visit.
    mask_left: u8 = 0,
    /// `[bp-1Ah]`: 1 if the enemy king is outside the pawn's band of files, or below it.
    king_outside: u8 = 0,
    /// `[bp-0Ch]`: the highest rank code of a White pawn judged unstoppable (0 none).
    white_unstoppable: u16 = 0,
    /// `[bp-0Eh]`: the lowest rank code of a Black pawn judged unstoppable (0 none).
    black_unstoppable: u16 = 0,
    /// `[bp-10h]`: bonus for a second advanced White passed pawn.
    white_second_passer_bonus: u16 = 240,
    /// `[bp-12h]`: the same for Black.
    black_second_passer_bonus: u16 = 240,
    /// `[bp-14h]`: the table by square for White's passed pawns (746C, 718C or 90BA).
    white_passer_table: u16 = 0,
    /// `[bp-16h]`: the table for Black's passed pawns (AE46, A792 or 369E).
    black_passer_table: u16 = 0,
    /// `[bp-1Ch]`: 1 when each side has one bishop, on different slots (bishop bits 3 or 0Ch).
    opposite_bishops: u8 = 0,
    /// `[bp-1Eh]`: Black's ending flags (1, 2, 4, 6, 8, 10h, 40h, 50h).
    black_flags: u8 = 0,
    /// `[bp-20h]`: White's ending flags.
    white_flags: u8 = 0,
    /// `[bp-22h]`: advanced passed pawns of the side not to move counted so far.
    advanced_passers: u8 = 0,
    /// `[bp-24h]`: bishop bits: 1 Black slot 2, 4 Black slot 3, 2 White slot 2, 8 White slot 3.
    bishop_bits: u8 = 0,
};

// ---------------------------------------------------------------------------
// Constant tables read by the full body, from the original's initialised data
// ---------------------------------------------------------------------------

/// DG:0000..12FF as the executable has it. The full body reads many small constant
/// tables at computed offsets (a square, a square difference, a rank code); they are
/// read here at the same offsets. The vector tool checks, in the running original, that
/// every range read is unchanged and equals the executable.
const low_bytes: [0x1300]u8 = dg(0, 0x1300);

/// The signed byte at DG:addr (the original's `cbw` of a table byte).
fn cb(addr: usize) i16 {
    return @as(i8, @bitCast(low_bytes[addr]));
}

/// The unsigned byte at DG:addr.
fn constByte(addr: usize) u8 {
    return low_bytes[addr];
}

/// The signed word at DG:addr.
fn cw(addr: usize) i16 {
    return @bitCast(std.mem.readInt(u16, low_bytes[addr..][0..2], .little));
}

fn cwAt(addr: isize) i16 {
    return cw(@intCast(addr));
}

/// `tb(base, sq)`: the signed byte of a table by square.
fn tb(base: usize, sq: usize) i16 {
    return cb(base + sq);
}

/// DG:1078 + sq: the rank code (rank + 1, 2..9; 0 off the board from 100).
fn sqRank(sq: usize) i16 {
    return cb(0x1078 + sq);
}

fn rankIndex(sq: usize) usize {
    return @intCast(sqRank(sq));
}

/// DG:100A + sq: the file (1..8).
fn sqFile(sq: usize) i16 {
    return cb(0x100A + sq);
}

/// DG:0850 + sq: the square class (0 on the a- and h-files).
const class_of: [120]u8 = dg(0x0850, 120);

fn sb(x: u8) i16 {
    return @as(i8, @bitCast(x));
}

fn sw16(x: u16) i16 {
    return @bitCast(x);
}

fn wa(p: *const Position, sq: usize) i16 {
    return sb(p.pawn_attacks[0][sq]);
}

fn ba(p: *const Position, sq: usize) i16 {
    return sb(p.pawn_attacks[1][sq]);
}

/// DG:01AC + mask: the slot (8..15) of the lowest set bit of a passed-pawn mask.
fn lowestSlot(mask: u8) usize {
    return 8 + @as(usize, @ctz(mask));
}

/// DG:0194 + slot: the slot's bit in a passed-pawn mask.
fn slotBit(slot: usize) u8 {
    return @as(u8, 1) << @intCast(slot - 8);
}

/// DG:0194 + (signed) byte: what the original reads for the slot byte of a square
/// (DG:A28C + sq, FFh when empty).
fn slotBitByte(slot_byte: u8) u8 {
    return constByte(@intCast(0x0194 + @as(isize, @as(i8, @bitCast(slot_byte)))));
}

comptime {
    // DG:01AC, DG:019C and DG:0194 are the tables lowestSlot and slotBit compute.
    @setEvalBranchQuota(10000);
    for (1..256) |m| std.debug.assert(constByte(0x01AC + m) == lowestSlot(m));
    std.debug.assert(constByte(0x01AC) == 0);
    for (8..16) |s| {
        std.debug.assert(constByte(0x0194 + s) == slotBit(s));
        std.debug.assert(constByte(0x019C + s) == ~slotBit(s));
    }
}

/// What a step of section 1 leads to.
const Step = union(enum) {
    /// Go on in address order.
    next,
    /// 065A: skip the rest of the section's endings, go to the tables.
    tables,
    /// Return from static_eval with this score (without the clamp of 4003).
    ret: i16,
};

const Body = struct {
    p: *Position,
    v: *EvalVars,
    h: *PawnHash,
    callees: *const Callees,
    side: u16,
    arg2: u16,
    fixes: Fixes,
    stray: [2]StrayBytes,
    di: i16,
    f: Frame = .{},

    fn flags(b: *Body, bits: u8) void {
        b.v.passer_flags |= bits;
    }
    fn fileOf(f: *const Frame) i16 {
        return @bitCast(f.file);
    }
    fn fileIndex(f: *const Frame) usize {
        return @intCast(fileOf(f));
    }
    fn add(b: *Body, d: i16) void {
        b.di +%= d;
    }
    fn board(b: *const Body, sq: usize) u8 {
        return b.p.board[sq];
    }

    /// 01C8-040F: Black has at most one pawn.
    fn blackFewPawns(b: *Body) Step {
        const p = b.p;
        if (sb(p.side_pawn_count[1]) > 1) return .next;
        if (p.side_pawn_count[1] == 0) { // 01D2
            if (p.piece_count[1] == 2 and @as(i16, @bitCast(p.piece_material[1])) < 1400) b.add(200);
            return .next;
        }
        if (@as(i16, @bitCast(p.material[1])) > 1300) return .next; // 01F4
        if (p.piece_count[1] == 0) { // 01FF: Black has no pieces
            if (p.side_pawn_count[0] != 0) {
                b.f.black_flags = 2; // 040C
                return .next;
            }
            if (p.material[0] == 1300) { // 0213: White K+N+N
                var slot: usize = 8;
                while (p.piece_list[16 + slot] > 0x62) slot += 1;
                var sq: usize = p.piece_list[16 + slot];
                while (true) { // 0230
                    if (constByte(0x07EC + sq) == 0) return .{ .ret = b.di -% 800 }; // 023E
                    sq -= 10;
                    if (b.board(sq) == pos.white_knight) return .{ .ret = b.di };
                }
            }
            if (p.material_balance != 1800 or p.piece_count[0] != 1 or p.piece_list[16 + 7] > 0x30) { // 024E
                b.f.black_flags = 2;
                return .next;
            }
            // 026D: K+Q against a Black pawn on a2, c2, f2 or h2.
            const bk = p.piece_list[16 + 7];
            const wkr = sb(p.king_rank[0]);
            const wkf = sb(p.king_file[0]);
            if (b.board(31) == pos.black_pawn) {
                if (b.board(21) == pos.white_queen) return .{ .ret = b.di +% 100 }; // 02FF
                if (constByte(0x0D1E - @as(usize, bk)) == 0) return .tables;
                b.add(-200);
                if (wkr >= 7 or wkf >= 6) return .{ .ret = b.di -% 2100 }; // 032C
                return .tables;
            }
            if (b.board(33) == pos.black_pawn) { // 029A
                if (b.board(23) == pos.white_queen) return .{ .ret = b.di +% 100 };
                if (sb(p.king_file[1]) > 4) return .tables;
                b.add(-200);
                if (wkr >= 6 or wkf >= 6) return .{ .ret = b.di -% 2100 };
                return .tables;
            }
            if (b.board(36) == pos.black_pawn) { // 02CA
                if (b.board(26) == pos.white_queen) return .{ .ret = b.di +% 100 };
                if (sb(p.king_file[1]) < 5) return .tables;
                b.add(-200);
                if (wkr >= 6 or wkf <= 3) return .{ .ret = b.di -% 2100 };
                return .tables;
            }
            if (b.board(38) != pos.black_pawn) return .tables; // 02EE
            if (b.board(28) == pos.white_queen) return .{ .ret = b.di +% 100 };
            if (constByte(0x0D25 - @as(usize, bk)) == 0) return .tables; // 0306
            b.add(-200);
            if (wkr >= 7 or wkf <= 3) return .{ .ret = b.di -% 2100 };
            return .tables;
        }
        // 0334: Black has pieces.
        if (p.material[1] == 1300) {
            if (p.piece_material[0] == 1100) b.f.black_flags = 1;
            return .next;
        }
        if (p.material[1] == 850) { // 034E
            var cond = false;
            if (b.board(31) == pos.black_pawn) {
                cond = b.board(21) == pos.black_king;
            } else if (b.board(38) == pos.black_pawn) {
                cond = b.board(28) == pos.black_king;
            }
            if (cond) b.f.black_flags = 2;
            if (p.piece_count[0] != 0) b.f.black_flags |= 8; // 0376
            return .next;
        }
        if (p.piece_count[0] != 0) { // 0388
            b.f.black_flags = 8;
            return .next;
        }
        if (p.pawns_per_file[1][8] != 0) { // 0396: an h-pawn
            if (p.piece_list[16 + 2] >= 0x63) return .next;
            b.add(200);
            if (sb(p.king_file[0]) >= 6 and sb(p.king_rank[0]) <= 3) {
                b.f.black_flags = 2;
                return .next;
            }
            if (b.side != 0) return .next; // 03B6
            if (constByte(0x0D24 - @as(usize, p.piece_list[7])) == 0) return .next;
            if (p.pawn_attacks[1][37] != 0) return .next;
            b.f.black_flags = 2;
            return .next;
        }
        if (p.pawns_per_file[1][1] == 0) return .next; // 03D2: an a-pawn
        if (p.piece_list[16 + 3] >= 0x63) return .next;
        b.add(200);
        if (sb(p.king_file[0]) <= 3 and sb(p.king_rank[0]) <= 3) {
            b.f.black_flags = 2;
            return .next;
        }
        if (b.side != 0) return .next; // 03F2
        if (constByte(0x0D1F - @as(usize, p.piece_list[7])) == 0) return .next;
        if (p.pawn_attacks[1][32] != 0) return .next;
        b.f.black_flags = 2;
        return .next;
    }

    /// 0410-0659: White has at most one pawn (the mirror of 01C8, with differences).
    fn whiteFewPawns(b: *Body) Step {
        const p = b.p;
        if (sb(p.side_pawn_count[0]) > 1) return .next;
        if (p.side_pawn_count[0] == 0) { // 041A
            if (p.piece_count[0] == 2 and @as(i16, @bitCast(p.piece_material[0])) < 1400) b.add(-200);
            return .next;
        }
        if (@as(i16, @bitCast(p.material[0])) > 1300) return .next; // 043E
        if (p.piece_count[0] == 0) { // 0449: White has no pieces
            if (p.side_pawn_count[1] != 0) {
                b.f.white_flags = 2; // 0656
                return .next;
            }
            if (p.material[1] == 1300) { // 045D: Black K+N+N
                var slot: usize = 8;
                while (p.piece_list[slot] > 0x62) slot += 1;
                var sq: usize = p.piece_list[slot];
                while (true) { // 047A
                    if (constByte(0x0788 + sq) == 0) return .{ .ret = b.di +% 800 }; // 0488
                    sq += 10;
                    if (b.board(sq) == pos.black_knight) return .{ .ret = b.di };
                }
            }
            if (p.material_balance != 0xF8F8 or p.piece_count[1] != 1 or p.piece_list[7] < 0x47) { // 0498
                b.f.white_flags = 2;
                return .next;
            }
            // 04B7: K+Q against a White pawn on a7, c7, f7 or h7.
            const wk = p.piece_list[7];
            const bkr = sb(p.king_rank[1]);
            const bkf = sb(p.king_file[1]);
            if (b.board(81) == pos.white_pawn) {
                if (b.board(91) == pos.black_queen) return .{ .ret = b.di -% 100 }; // 054B
                if (constByte(0x0D50 - @as(usize, wk)) == 0) return .next;
                b.add(200);
                if (bkr <= 4 or bkf >= 6) return .{ .ret = b.di +% 2100 }; // 0578
                return .next;
            }
            if (b.board(83) == pos.white_pawn) { // 04E6
                if (b.board(93) == pos.black_queen) return .{ .ret = b.di -% 100 };
                if (sb(p.king_file[0]) > 4) return .next;
                b.add(200);
                if (bkr <= 5 or bkf >= 6) return .{ .ret = b.di +% 2100 };
                return .next;
            }
            if (b.board(86) == pos.white_pawn) { // 0516
                if (b.board(96) == pos.black_queen) return .{ .ret = b.di -% 100 };
                if (sb(p.king_file[0]) < 5) return .next;
                b.add(200);
                if (bkr <= 5 or bkf <= 3) return .{ .ret = b.di +% 2100 };
                return .next;
            }
            if (b.board(88) != pos.white_pawn) return .next; // 053A
            if (b.board(98) == pos.black_queen) return .{ .ret = b.di -% 100 };
            if (constByte(0x0D57 - @as(usize, wk)) == 0) return .next; // 0552
            b.add(200);
            if (bkr <= 4 or bkf <= 3) return .{ .ret = b.di +% 2100 };
            return .next;
        }
        // 0580: White has pieces.
        if (p.material[0] == 1300) {
            if (p.piece_material[1] == 1100) b.f.white_flags = 1;
            return .next;
        }
        if (p.material[0] == 850) { // 059A
            var cond = false;
            if (b.board(81) == pos.white_pawn) {
                cond = b.board(91) == pos.white_king;
            } else if (b.board(88) == pos.white_pawn) {
                cond = b.board(98) == pos.white_king;
            }
            if (cond) b.f.white_flags = 2;
            if (p.piece_count[1] != 0) b.f.white_flags |= 8; // 05C2
            return .next;
        }
        if (p.piece_count[1] != 0) { // 05D4
            b.f.white_flags = 8;
            return .next;
        }
        if (p.pawns_per_file[0][8] != 0) { // 05E2: an h-pawn
            if (p.piece_list[2] >= 0x63) return .next;
            b.add(-200);
            if (sb(p.king_file[1]) >= 6 and sb(p.king_rank[1]) >= 8) {
                b.f.white_flags = 2;
                return .next;
            }
            if (b.side == 0) return .next; // 0602
            if (constByte(0x0D56 - @as(usize, p.piece_list[16 + 7])) == 0) return .next;
            if (p.pawn_attacks[0][87] != 0) return .next;
            b.f.white_flags = 2;
            return .next;
        }
        if (p.pawns_per_file[0][1] == 0) return .next; // 061C: an a-pawn
        if (p.piece_list[3] >= 0x63) return .next;
        b.add(-200);
        if (sb(p.king_file[1]) <= 3 and sb(p.king_rank[1]) >= 8) {
            b.f.white_flags = 2;
            return .next;
        }
        if (b.side == 0) return .next; // 063C
        if (constByte(0x0D51 - @as(usize, p.piece_list[16 + 7])) == 0) return .next;
        if (p.pawn_attacks[0][82] != 0) return .next;
        b.f.white_flags = 2;
        return .next;
    }

    /// 065A-0818: the White passed-pawn table and the flags, from Black's material.
    fn tablesBlack(b: *Body) void {
        const p = b.p;
        const f = &b.f;
        f.white_passer_table = table_746C;
        const ae3a: i16 = @bitCast(p.piece_material[1]);
        const a35e: i16 = @bitCast(p.material_balance);
        const black_pawns = sb(p.side_pawn_count[1]);
        if (ae3a >= 3750) return;
        if (a35e >= -450) f.white_passer_table = table_718C; // 066A
        if (ae3a >= 2000) { // 0677 -> 0800
            if (a35e >= -500) f.white_flags |= 0x10;
            if (@as(i16, @bitCast(p.piece_balance)) < -450) f.white_passer_table = table_746C; // 080C
            return;
        }
        f.white_second_passer_bonus = 540; // 0682
        if (ae3a > 700) { // 07A4
            if (p.piece_material_sum == 2200) {
                f.white_flags |= 0x50;
                f.black_flags |= 0x50;
                return;
            }
            if (a35e > 300) return; // 07B6
            if (ae3a == 1800 or ae3a == 1350) { // 07D6
                f.black_flags |= 0x10;
                f.bishop_bits = if (p.piece_list[16 + 2] >= 0x63) 4 else 1;
                return;
            }
            if (ae3a != 1300 or @as(i16, @bitCast(p.piece_material[0])) < 700) { // 07E8
                f.black_flags |= 0x10; // 078B
                return;
            }
            if (black_pawns > 2) f.black_flags |= 0x10;
            return;
        }
        if (@as(i16, @bitCast(p.piece_material[0])) > 700) f.white_passer_table = table_90BA; // 0692
        if (ae3a != 700) { // 069F -> 0736
            if (ae3a != 0) { // 0792
                if (a35e <= 300 and black_pawns > 1) f.black_flags |= 0x10;
                return;
            }
            f.white_passer_table = table_90BA;
            const bp = p.side_pawn_count[1];
            if (bp == 0) return;
            if (bp == p.pawns_per_file[1][1]) { // 074C: all on the a-file
                f.black_flags |= 2;
                if (sb(p.king_file[0]) <= 2) b.whiteKingInCorner(&f.black_flags); // 0759
                return;
            }
            if (bp == p.pawns_per_file[1][8]) { // 0766: all on the h-file
                f.black_flags |= 2;
                if (sb(p.king_file[0]) >= 7) b.whiteKingInCorner(&f.black_flags); // 06E5
                return;
            }
            if (black_pawns <= 1) return; // 0776
            if (a35e > 300) return;
            f.black_flags |= 0x10;
            return;
        }
        // Black has exactly 700 in pieces: a bishop.
        if (p.piece_list[16 + 2] < 0x63) { // 06AA
            f.bishop_bits = 1;
            if (p.piece_list[2] < 0x63) {
                f.white_passer_table = table_746C;
                f.white_second_passer_bonus = 120;
            }
            if (a35e <= 300 and black_pawns > 1) f.black_flags |= 0x10; // 06C6
            if (p.side_pawn_count[1] != p.pawns_per_file[1][8]) return; // 06D9
            if (sb(p.king_file[0]) >= 7) b.whiteKingInCorner(&f.black_flags); // 06E5
            return;
        }
        f.bishop_bits = 4; // 0700
        if (p.piece_list[3] < 0x63) {
            f.white_passer_table = table_746C;
            f.white_second_passer_bonus = 120;
        }
        if (a35e <= 300 and black_pawns > 1) f.black_flags |= 0x10; // 0715
        if (p.side_pawn_count[1] != p.pawns_per_file[1][1]) return; // 0728
        if (sb(p.king_file[0]) <= 2) b.whiteKingInCorner(&f.black_flags); // 0759
    }

    /// 06EF: with the White king on rank 1 or 2 (rank code <= 3) the flags become 6.
    fn whiteKingInCorner(b: *Body, out: *u8) void {
        if (sb(b.p.king_rank[0]) <= 3) out.* = 6;
    }

    /// 08AE: with the Black king on rank 7 or 8 (rank code >= 8) the flags become 6.
    fn blackKingInCorner(b: *Body, out: *u8) void {
        if (sb(b.p.king_rank[1]) >= 8) out.* = 6;
    }

    /// 0819-0A16: the Black passed-pawn table and the flags, from White's material.
    fn tablesWhite(b: *Body) void {
        const p = b.p;
        const f = &b.f;
        f.black_passer_table = table_AE46;
        const ae38: i16 = @bitCast(p.piece_material[0]);
        const a35e: i16 = @bitCast(p.material_balance);
        const white_pawns = sb(p.side_pawn_count[0]);
        if (ae38 >= 3750) return;
        if (a35e <= 450) f.black_passer_table = table_A792; // 0829
        if (ae38 >= 2000) { // 0836 -> 09FE
            if (a35e <= 500) f.black_flags |= 0x10;
            if (@as(i16, @bitCast(p.piece_balance)) > 450) f.black_passer_table = table_AE46; // 0A0A
            return;
        }
        f.black_second_passer_bonus = 540; // 0841
        if (ae38 > 700) { // 096A
            if (p.piece_material_sum == 2200) return;
            if (a35e < -300) return;
            if (ae38 == 1800) { // 0980
                f.white_flags |= 0x10;
                f.bishop_bits |= if (p.piece_list[2] < 0x63) @as(u8, 2) else 8;
                if (p.total_material != 3800) return; // 099E
                if (f.bishop_bits == 3 or f.bishop_bits == 0x0C) {
                    f.black_flags = 0;
                    f.white_flags = 0;
                    b.di -%= @as(i16, @bitCast(p.material_balance_2));
                }
                return;
            }
            if (ae38 == 1350) { // 09C0
                f.white_flags |= 0x10;
                f.bishop_bits |= if (p.piece_list[2] < 0x63) @as(u8, 2) else 8;
                return;
            }
            if (ae38 != 1300 or @as(i16, @bitCast(p.piece_material[1])) < 700) { // 09E0
                f.white_flags |= 0x10; // 094B
                return;
            }
            if (white_pawns > 2) f.white_flags |= 0x10; // 09F6
            return;
        }
        if (@as(i16, @bitCast(p.piece_material[1])) > 700) f.black_passer_table = table_369E; // 0851
        if (ae38 != 700) { // 085E -> 08F6
            if (ae38 != 0) { // 0952
                if (a35e >= -300 and white_pawns > 1) f.white_flags |= 0x10;
                return;
            }
            f.black_passer_table = table_369E;
            const wp = p.side_pawn_count[0];
            if (wp == 0) return;
            if (wp == p.pawns_per_file[0][1]) { // 090C
                f.white_flags |= 2;
                if (sb(p.king_file[1]) <= 2) b.blackKingInCorner(&f.white_flags); // 0919
                return;
            }
            if (wp == p.pawns_per_file[0][8]) { // 0926
                f.white_flags |= 2;
                if (sb(p.king_file[1]) >= 7) b.blackKingInCorner(&f.white_flags); // 08A4
                return;
            }
            if (white_pawns <= 1) return; // 0936
            if (a35e < -300) return;
            f.white_flags |= 0x10;
            return;
        }
        // White has exactly 700 in pieces: a bishop.
        if (p.piece_list[2] < 0x63) { // 0869
            f.bishop_bits |= 2;
            if (p.piece_list[16 + 2] < 0x63) {
                f.black_passer_table = table_AE46;
                f.black_second_passer_bonus = 120;
            }
            if (a35e >= -300 and white_pawns > 1) f.white_flags |= 0x10; // 0885
            if (p.side_pawn_count[0] != p.pawns_per_file[0][8]) return; // 0898
            if (sb(p.king_file[1]) >= 7) b.blackKingInCorner(&f.white_flags); // 08A4
            return;
        }
        f.bishop_bits |= 8; // 08C0
        if (p.piece_list[16 + 3] < 0x63) {
            f.black_passer_table = table_AE46;
            f.black_second_passer_bonus = 120;
        }
        if (a35e >= -300 and white_pawns > 1) f.white_flags |= 0x10; // 08D5
        if (p.side_pawn_count[0] != p.pawns_per_file[0][1]) return; // 08E8
        if (sb(p.king_file[1]) <= 2) b.blackKingInCorner(&f.white_flags); // 0919
    }

    // -----------------------------------------------------------------------
    // Section 2: White's passed pawns, Black to move (0A40-10AF, 10E4-1803)
    // -----------------------------------------------------------------------

    /// How one pawn's evaluation ends.
    const PawnExit = enum {
        /// Back to the loop head for the next pawn (0A46 / 10B6 / 244A / 2861).
        next_pawn,
        /// Leave this loop for the next (10AD: into Black's loop).
        leave,
        /// 401C: the position is a draw.
        draw,
    };

    /// 0A40-0A83: White's passed pawns with Black to move, from the mask DG:A6C2.
    /// Returns null to go on to Black's loop (10B0), or how static_eval ends.
    fn whitePassersBlackToMove(b: *Body) ?i16 {
        b.f.mask_left = b.v.passed_pawns[0]; // 0A40
        while (true) { // 0A46
            if (b.f.mask_left == 0) return null;
            const slot = lowestSlot(b.f.mask_left);
            b.f.mask_left &= ~slotBit(slot);
            const si = b.p.piece_list[slot];
            // 0A67: the mask names a slot without a White pawn (a stale pawn-hash entry):
            // store a fresh evaluation and start again (0A6E-0A83). A captured pawn's
            // entry (square + 63h) lies past the board; the original reads DG:9EF6 + entry
            // there, program data never seen to hold a pawn code (as in the evaluators).
            if (si >= 120 or b.p.board[si] != pos.white_pawn) return b.restart();
            switch (b.whitePawn(si, false)) {
                .next_pawn => {},
                .leave => return null,
                .draw => return draw(b.v),
            }
        }
    }

    /// 0A6E-0A83 (Black to move): pawn_store_btm (0000:1B24), then static_eval(1,
    /// [bp+8]) again; 2472-247C (White to move): pawn_store_wtm (0000:1AC0), then
    /// static_eval(0, [bp+8]). The new call's stray frame bytes are `stray[1]`.
    fn restart(b: *Body) i16 {
        if (b.side != 0) {
            _ = b.h.store(b.p, b.v, .black);
            return staticEvalWith(b.p, b.v, b.h, b.callees, 1, b.arg2, b.fixes, .{ b.stray[1], .{} });
        }
        _ = b.h.store(b.p, b.v, .white);
        return staticEvalWith(b.p, b.v, b.h, b.callees, 0, b.arg2, b.fixes, .{ b.stray[1], .{} });
    }

    /// 2444-285A: White's passed pawns with White to move, from the mask DG:A6C2.
    /// Returns null to go on to Black's loop (285B), or the score static_eval returns.
    fn whitePassersWhiteToMove(b: *Body) ?i16 {
        b.f.mask_left = b.v.passed_pawns[0]; // 2444
        while (true) { // 244A
            if (b.f.mask_left == 0) return null;
            const slot = lowestSlot(b.f.mask_left);
            b.f.mask_left &= ~slotBit(slot);
            const si = b.p.piece_list[slot];
            if (si >= 120 or b.p.board[si] != pos.white_pawn) return b.restart(); // 246B -> 2472
            switch (b.whitePawn(si, true)) {
                .next_pawn => {},
                .leave => return null,
                .draw => return draw(b.v),
            }
        }
    }

    /// 285B-288C: Black's passed pawns with White to move, from the mask DG:9D8C.
    /// Returns null to go on to the tail (3736), or the score static_eval returns.
    fn blackPassersWhiteToMove(b: *Body) ?i16 {
        b.f.mask_left = b.v.passed_pawns[1]; // 285B
        while (true) { // 2861
            if (b.f.mask_left == 0) return null;
            const slot = lowestSlot(b.f.mask_left);
            b.f.mask_left &= ~slotBit(slot);
            const si = b.p.piece_list[16 + slot];
            if (si >= 120 or b.p.board[si] != pos.black_pawn) return b.restart(); // 2882 -> 2472
            switch (b.blackPawn(si, true)) {
                .next_pawn => {},
                .leave => {
                    b.add(100); // 3733
                    return null;
                },
                .draw => return draw(b.v),
            }
        }
    }

    /// One White passed pawn on `si0`, Black to move (0A84-10AF, 10E4-1803; the model's
    /// `WhitePawnBTM`). Each prong is the original's block at that address.
    fn whitePawn(b: *Body, si0: u8, comptime wtm: bool) PawnExit {
        const p = b.p;
        const f = &b.f;
        var si: usize = si0;
        const wkf = sb(p.king_file[0]); // DG:A22E
        const bkf = sb(p.king_file[1]); // DG:A22F
        const wkr = sb(p.king_rank[0]); // DG:70F0
        const bkr = sb(p.king_rank[1]); // DG:70F1
        const wk: usize = p.piece_list[7]; // DG:A041
        const bk: usize = p.piece_list[16 + 7]; // DG:A051
        const black_pieces: i16 = @bitCast(p.piece_material[1]); // DG:AE3A
        const black_passed = b.v.passed_pawns[1]; // DG:9D8C
        blk: switch (if (wtm) WhiteBlock.b2480 else WhiteBlock.b0A84) {
            .b0A84 => {
                f.file = @bitCast(@as(i16, sqFile(si)));
                if (tb(0x0EDE, si) < bkf or tb(0x0E7A, si) > bkf) {
                    f.king_outside = 1; // 0AA7
                } else if (bk >= si - 1) { // 0A9B
                    f.king_outside = 0;
                } else {
                    f.king_outside = 1;
                }
                if (si < 0x33) continue :blk .b108B; // 0AB2
                if (p.pawn_attacks[0][si + 10] != 0) { // 0ABA
                    var x = sw16(b.v.passer_rank_tables[1][rankIndex(si)]);
                    if (f.king_outside == 0) x >>= 1; // 0AD6
                    b.add(x);
                    if (si >= 0x47) b.flags(4); // 0AEF
                    continue :blk if (wtm) .b25DD else .b0BED;
                }
                if (ba(p, si) < wa(p, si)) continue :blk .b0B05; // 0AF8
                if (p.pawns_per_file[1][fileIndex(f)] != 0) b.add(-80); // 0BE0
                continue :blk if (wtm) .b25DD else .b0BED;
            },
            .b0B05 => {
                if (si < 0x3D) continue :blk if (wtm) .b25DD else .b0BED;
                if (cb(0x0E16 + si) == 0) { // a light square
                    if (f.bishop_bits == 3) continue :blk .b0BAC; // 0BA6
                    if (f.bishop_bits & 3 == 0) continue :blk .b0B29; // 0BBE
                    continue :blk .b0BC7;
                }
                if (f.bishop_bits == 0x0C) continue :blk .b0BAC; // 0B17
                if (f.bishop_bits & 0x0C != 0) continue :blk .b0BC7; // 0B20
                continue :blk .b0B29;
            },
            .b0B29 => {
                if (f.king_outside == 0 or b.v.endgame == 0) continue :blk .b0BCD;
                b.add(sw16(b.v.passer_rank_tables[0][rankIndex(si)])); // 0B3C
                if (p.board[si - 9] == pos.white_pawn) {
                    if (tb(0x0E7A, si) > bkf or tb(0x0FA6, si) < bkf) {
                        if (slotBitByte(p.square_slot[si - 9]) & b.v.passed_pawns[0] != 0) continue :blk .b0B95; // 0B5F
                    }
                }
                if (p.board[si - 11] != pos.white_pawn) continue :blk if (wtm) .b25DD else .b0BED; // 0B6F
                if (!(tb(0x0EDE, si) < bkf) and tb(0x0F42, si) <= bkf) continue :blk if (wtm) .b25DD else .b0BED;
                if (slotBitByte(p.square_slot[si - 11]) & b.v.passed_pawns[0] == 0) continue :blk if (wtm) .b25DD else .b0BED; // 0B85
                continue :blk .b0B95;
            },
            .b0B95 => {
                b.add(if (si >= 0x51) 120 else 80);
                continue :blk if (wtm) .b25DD else .b0BED;
            },
            .b0BAC => {
                b.add(sw16(b.v.passer_rank_tables[0][rankIndex(si)]) >> 2);
                continue :blk if (wtm) .b25DD else .b0BED;
            },
            .b0BC7 => {
                if (f.king_outside == 0) continue :blk .b0BAC;
                continue :blk .b0BCD;
            },
            .b0BCD => {
                b.add(sw16(b.v.passer_rank_tables[0][rankIndex(si)]) >> 1);
                continue :blk if (wtm) .b25DD else .b0BED;
            },
            .b0BED => {
                if (si < 0x47) continue :blk .b108B;
                if (p.pawn_attacks[1][si] != 0) b.flags(8); // 0BF5
                if (p.board[si + 10] != 0) continue :blk .b0F5E; // 0C01
                if (si < 0x51) continue :blk .b0E7A; // 0C0B
                // 0C13: a pawn on the 7th
                if (black_pieces > 700) continue :blk .b0C80;
                if (black_pieces == 0) { // 0C1B
                    b.flags(2);
                    b.add(240);
                    continue :blk .b10F9;
                }
                const l04 = fileOf(f);
                const near = bkr >= 7 and l04 + 2 >= bkf and l04 - 2 <= bkf;
                if (black_pieces == 700) { // 0C2E: a bishop
                    if (near and cb(0x0D09 + si - wk) == 0) continue :blk .b0C80; // 0C57
                    if (cb(0x0E16 + si) != 0) { // 0C64
                        if (p.piece_list[16 + 2] >= 0x63) continue :blk .b0C80;
                        continue :blk .b0E44;
                    }
                    if (p.piece_list[16 + 3] >= 0x63) continue :blk .b0C80;
                    continue :blk .b0E44;
                }
                if (near) continue :blk .b0C80; // 0CAA
                if (class_of[si] != 0 or wkr <= 5) continue :blk .b0D20; // 0CC9
                if (si == 0x51) { // 0CDF
                    if (wkf >= 5) continue :blk .b0D20;
                    if (p.board[82] == pos.white_king) {
                        if (bkr < 5 or bkf > 5) continue :blk .b0E44;
                        if (bk != 0x37) continue :blk .b0D20;
                        continue :blk .b0E44;
                    }
                    if (bkr < 5 or bkf > 6) continue :blk .b0E44; // 0D0C
                    continue :blk .b0D20;
                }
                if (wkf <= 4) continue :blk .b0D20; // 0D96
                if (p.board[87] == pos.white_king) {
                    if (bkr < 5 or bkf < 4) continue :blk .b0E44;
                    if (bk != 0x36) continue :blk .b0D20;
                    continue :blk .b0E44;
                }
                if (bkr < 5 or bkf < 3) continue :blk .b0E44; // 0DC2
                continue :blk .b0D20;
            },
            .b0D20 => {
                // A Black knight against the pawn on the 7th.
                var n: usize = p.piece_list[16 + 0];
                f.scratch_a = @intCast(n);
                if (n > 0x62) {
                    n = p.piece_list[16 + 1];
                    f.scratch_a = @intCast(n);
                }
                if (n >= 0x63) continue :blk .b0C80; // 0D33
                const l08: i16 = cb(0x0144 - @as(usize, @intCast(sqRank(n))));
                f.scratch_b = @bitCast(l08);
                if (l08 > 5) continue :blk .b0E44;
                const bx: i16 = fileOf(f) - sqFile(n) + 7; // 0D55
                const l06: i16 = cb(@intCast(0x0134 + bx));
                f.scratch_a = @bitCast(l06);
                if (l06 > 5) continue :blk .b0E44;
                if (l06 == 3 and l08 == 3) { // 0D75
                    if (bx > 7) {
                        if (p.board[si - 1] == pos.white_king) continue :blk .b0E44;
                        if (p.board[si - 12] == pos.white_king) continue :blk .b0E44;
                        continue :blk .b0C80;
                    }
                    if (p.board[si + 1] == pos.white_king) continue :blk .b0E44; // 0DD6
                    if (p.board[si - 8] == pos.white_king) continue :blk .b0E44;
                    continue :blk .b0C80;
                }
                const sum = l06 + l08; // 0DEA
                f.scratch_a = @bitCast(sum);
                if (sum == 2) {
                    if (l08 - 1 != 0) continue :blk .b0C80;
                    if (class_of[si] == 0) continue :blk .b0E44; // 0DFC
                    if (p.board[si - 1] == pos.black_knight) {
                        if (cb(0x0D0A + si - wk) != 0) continue :blk .b0E44;
                        continue :blk .b0C80;
                    }
                    if (cb(0x0D08 + si - wk) != 0) continue :blk .b0E44; // 0E1A
                    continue :blk .b0C80;
                }
                if (sum > 8) continue :blk .b0E44; // 0E2C
                if (sum & 1 == 0) continue :blk .b0C80;
                if (sum != 3) continue :blk .b0E44;
                continue :blk .b0C80;
            },
            .b0C80 => {
                // The exchange test: can Black take on the promotion square?
                f.advanced_passers +%= 1;
                p.board[si] = 0;
                const x: i16 = @bitCast(b.callees.see_white(b.callees.ctx, @intCast(si + 10), 9)); // 0C90
                if (x >= 0) {
                    b.flags(2);
                    b.add(240);
                    f.advanced_passers -%= 1;
                } else if (f.advanced_passers == 2) { // 0E64
                    b.flags(1);
                    b.add(@bitCast(f.white_second_passer_bonus));
                }
                p.board[si] = pos.white_pawn; // 0E72
                continue :blk .b108B;
            },
            .b0E44 => {
                b.add(120);
                if (black_passed != 0) b.flags(2);
                if (sw16(f.white_unstoppable) < 8) f.white_unstoppable = 8; // 0E53
                continue :blk .b10F9;
            },
            .b0E7A => {
                // A pawn on the 6th, the square in front empty.
                if (p.board[si + 20] != 0) continue :blk .b108B;
                if (black_pieces > 1800) continue :blk .b108B; // 0E84
                f.advanced_passers +%= 1; // 0E8F
                if (f.advanced_passers == 2) continue :blk .b1083;
                if (cb(0x0D13 + si - wk) != 0) continue :blk .b1068; // 0E9B
                if (p.piece_material[1] != 650) { // 0EAD
                    if (black_pieces > 700) continue :blk .b108B; // 0F42
                    if (f.king_outside == 0) continue :blk .b108B;
                    continue :blk .b0F56;
                }
                const l04 = fileOf(f);
                if (bkr >= 6 and l04 + 3 >= bkf and l04 - 3 <= bkf) continue :blk .b0F56; // 0EB8
                var n: usize = p.piece_list[16 + 0]; // 0ED7
                f.scratch_a = @intCast(n);
                if (n > 0x62) {
                    n = p.piece_list[16 + 1];
                    f.scratch_a = @intCast(n);
                }
                if (n >= 0x63) continue :blk .b0F56;
                var cx: i16 = cb(0x0144 - @as(usize, @intCast(sqRank(n))));
                cx += cb(@intCast(0x013B + l04 - sqFile(n)));
                f.scratch_a = @bitCast(cx);
                if (cx <= 7 or cx == 9) continue :blk .b0F56;
                b.add(120); // 0F21
                if (black_passed != 0) b.flags(4);
                if (sw16(f.white_unstoppable) < 7) f.white_unstoppable = 7; // 0F30
                continue :blk .b10F9;
            },
            .b0F56 => {
                b.flags(4);
                continue :blk .b108B;
            },
            .b0F5E => {
                // The square in front is occupied.
                if (si < 0x51) continue :blk .b1072;
                const front = p.board[si + 10];
                if (sb(front) < 7) { // 0F66
                    if (sb(front) < 4) continue :blk .b108B;
                    b.flags(4); // 0F77
                    if (f.white_flags & 0x40 != 0) b.add(-120);
                    continue :blk .b108B;
                }
                if (front == pos.black_king) { // 0F8C
                    if (p.board[si - 10] == pos.white_king) continue :blk .b0F56;
                    continue :blk .b108B;
                }
                if (p.piece_material[1] != 650 or class_of[si] != 0) continue :blk .b104E; // 0FA0
                if (wkr <= 5) continue :blk .b108B; // 0FB5
                if (si == 0x51) { // 0FBF
                    if (wkf >= 5) continue :blk .b108B;
                    if (p.board[82] == pos.white_king) { // 0FCE
                        b.flags(4);
                        if (bkr < 6) continue :blk .b0E44;
                        if (bkf <= 4) continue :blk .b108B;
                        continue :blk .b0E44;
                    }
                    if (bkr < 5) continue :blk .b0E44; // 0FEC
                    if (@as(i16, wkf) + 2 >= bkf) continue :blk .b108B;
                    continue :blk .b0E44;
                }
                if (wkf <= 4) continue :blk .b108B; // 1008
                if (p.board[87] == pos.white_king) {
                    b.flags(4);
                    if (bkr < 6) continue :blk .b0E44;
                    if (bkf >= 5) continue :blk .b108B;
                    continue :blk .b0E44;
                }
                if (bkr < 5) continue :blk .b0E44; // 1030
                if (@as(i16, wkf) - 2 <= bkf) continue :blk .b108B;
                continue :blk .b0E44;
            },
            .b104E => {
                const v: i16 = cb(0x128C + @as(usize, @intCast(sb(p.board[si + 10]))));
                const x: i16 = @bitCast(b.callees.r4793_4CEC(b.callees.ctx, @intCast(si + 10), @bitCast(v))); // 105F
                if (x >= 0) continue :blk .b1072;
                continue :blk .b1068;
            },
            .b1068 => {
                b.flags(4);
                b.add(120);
                continue :blk .b108B;
            },
            .b1072 => {
                if (black_pieces > 700) continue :blk .b108B;
                f.advanced_passers +%= 1;
                if (f.advanced_passers != 2) continue :blk .b108B;
                continue :blk .b1083;
            },
            .b1083 => {
                b.flags(1);
                b.add(@bitCast(f.white_second_passer_bonus));
                continue :blk .b108B;
            },
            .b108B => {
                if (p.pawn_count == 1 and p.piece_material[1] != 0 and sw16(p.piece_material[0]) < 1100 and
                    (f.king_outside == 0 or f.opposite_bishops != 0))
                {
                    b.add(-100); // 10AD
                    return .leave; // falls into Black's loop at 10B0
                }
                continue :blk .b10E4;
            },
            .b10E4 => {
                // Doubled: another White pawn in front of this one (up to rank 7)?
                if (sb(p.pawns_per_file[0][fileIndex(f)]) > 1) {
                    f.scratch_a = @intCast(si);
                    var s = si;
                    while (s <= 0x4E) { // 10F1
                        s += 10; // 116A
                        if (p.board[s] == pos.white_pawn) return .next_pawn;
                    }
                    si = f.scratch_a; // 10F6
                }
                continue :blk .b10F9;
            },
            .b10F9 => {
                if (black_pieces >= 3100) continue :blk .b11D2;
                // 1104: the kings' distances to the pawn.
                var l06: i16 = cb(@intCast(0x11BB + @as(i16, sqFile(si)) - bkf));
                const l08a: i16 = cb(@intCast(0x11CB + @as(i16, sqRank(si)) - bkr));
                if (l06 < l08a) l06 = l08a;
                const cx: i16 = cb(@intCast(0x11EB + @as(i16, sqRank(si)) - wkr)); // 1137
                const l08: i16 = cb(@intCast(0x11AB + @as(i16, sqFile(si)) - wkf));
                f.scratch_b = @bitCast(l08);
                l06 -= if (l08 < cx) cx else l08; // 1164 / 117A
                const t: i16 = @as(i16, cb(0x10DC + si)) *% l06; // 1180: imul, 16 bits
                f.scratch_a = @bitCast(t);
                if (black_pieces > 2500 or f.opposite_bishops != 0) {
                    b.add(t >> 1); // 1199
                    continue :blk .b11D2;
                }
                b.add(t); // 11A2
                if (black_pieces < 700) {
                    b.add(t >> 2);
                    continue :blk .b11D2;
                }
                if (p.piece_balance == 0xFBB4 and p.side_pawn_count[1] == 0) { // 11B6
                    b.add(t);
                    if (sb(p.side_pawn_count[0]) < 3) b.add(t);
                }
                continue :blk .b11D2;
            },
            .b11D2 => {
                const ax: i16 = cb(0x042A + @as(usize, @intCast(sb(p.board[si + 10]))));
                b.add(@as(i16, @bitCast(b.v.passerTable(f.white_passer_table)[si])) -% ax);
                if (black_pieces > 700 and f.white_flags == 0) return .next_pawn; // 11EB
                continue :blk if (wtm) .b299C else .b11FC;
            },
            .b11FC => {
                if (p.board[si + 10] == pos.black_king) { // the Black king in front
                    if (p.material[1] != 0) continue :blk .b15F7;
                    if (class_of[si] == 0) { // 120D: a rook's pawn
                        f.white_flags |= 4;
                        if (si < 0x51) return .next_pawn;
                        if (cb(0x0CFF + si - wk) != 0) return .draw;
                        return .next_pawn;
                    }
                    if (si < 0x51) continue :blk .b15F7; // 1236
                    if (p.board[si - 10] == pos.white_king) return .draw;
                    if (p.board[si - 9] == pos.white_king or p.board[si - 11] == pos.white_king) f.white_unstoppable = 8;
                    return .next_pawn;
                }
                var l06: usize = if (si > 0x26) si else si + 10; // 1262
                f.scratch_a = @intCast(l06);
                var l08 = l06;
                const l04 = fileOf(f);
                if (wkf == l04 and wk >= si) { // 1276
                    l06 -= 10;
                    f.scratch_a = @intCast(l06);
                    if (class_of[si] == 0) {
                        l08 = l06;
                        if (f.white_flags & 1 != 0) l08 = l06 - 10;
                    }
                }
                if (p.pawn_attacks[1][si] != 0) l08 += 10; // 12A4
                f.scratch_b = @intCast(l08);
                const r: i16 = sqRank(l08); // 12AF
                if (r - 1 > bkr or (l04 - r + 10) < bkf or (r + l04 - 10) > bkf) continue :blk .b12E5;
                continue :blk .b138E;
            },
            .b12E5 => {
                if (p.piece_count[1] == 0) continue :blk .b14B8;
                continue :blk .b12EF;
            },
            .b12EF => {
                if (f.white_flags & 0x10 == 0 or si < 0x33) return .next_pawn;
                if (sw16(p.piece_material[0]) < 2000 and wkr < 5) return .next_pawn; // 1300
                if (tb(0x0F42, si) > wkf or tb(0x0FA6, si) < wkf) return .next_pawn; // 1312
                b.add(60); // 1327
                if (si < 0x3D) return .next_pawn;
                if (class_of[si] != 0 or !(black_pieces > 650)) b.add(60); // 1332
                if (sw16(p.material[0]) < 2400 or f.opposite_bishops != 0) { // 1344
                    if (wkr < 6 or black_passed != 0) return .next_pawn; // 1352
                }
                b.add(80); // 1366
                if (sw16(p.piece_balance) < -100 or f.opposite_bishops != 0) return .next_pawn;
                b.add(60); // 137C
                if (si < 0x47) return .next_pawn;
                b.add(60);
                return .next_pawn;
            },
            .b138E => {
                const l04 = fileOf(f);
                if (sqRank(si) - 1 > wkr) {
                    if (sb(p.pawn_count) < 2 and f.white_flags & 0x40 != 0) b.add(-140); // 139E
                    continue :blk .b13AF;
                }
                if (sqRank(si) + 2 < wkr) continue :blk .b13AF; // 1408
                if (l04 + 1 >= bkf) continue :blk .b14F6;
                if (!(bkf > wkf)) continue :blk .b13AF; // 1429
                if (l04 - 2 > wkf) continue :blk .b13AF; // 1435
                if (p.piece_count[0] == 0) continue :blk .b147E; // 1443
                if (wkr >= 6 and class_of[si] != 0) continue :blk .b1469;
                if (l04 + 3 >= bkf) continue :blk .b13AF; // 1458
                continue :blk .b1469;
            },
            .b1469 => {
                if (p.piece_count[1] != 0) continue :blk .b12EF;
                // 1473: the test of Black's passers, which Black's twin (3B5A from 398B) does
                // not make. DEV-054, corrected: Black's form, unstoppable whatever they are.
                if (b.fixes.dev054_unstoppable_passer_mirror or black_passed == 0) continue :blk .b14B8;
                continue :blk .b13AF;
            },
            .b147E => {
                if (p.piece_count[1] != 0) continue :blk .b13AF;
                if (class_of[si] == 0) continue :blk .b14CE;
                continue :blk .b148F;
            },
            .b148F => {
                if (black_passed != 0) continue :blk .b13AF;
                if (sqRank(si) < wkr or wkr >= 8) continue :blk .b14B8; // 1499
                if (bkr - 1 <= wkr) continue :blk .b14B8;
                continue :blk .b13AF;
            },
            .b14CE => {
                if (bkr > wkr) continue :blk .b13AF;
                if (wkf != fileOf(f)) continue :blk .b14B8; // 14DA
                if (bkf - 3 > wkf) continue :blk .b14B8;
                continue :blk .b13AF;
            },
            .b14F6 => {
                const l04 = fileOf(f);
                if (!(l04 - 1 > bkf)) continue :blk .b13AF;
                if (!(bkf < wkf)) continue :blk .b13AF; // 1505
                if (l04 + 2 < wkf) continue :blk .b13AF; // 1511
                if (p.piece_count[0] == 0) continue :blk .b154C; // 151F
                if (wkr >= 6 and class_of[si] != 0) continue :blk .b1469;
                if (l04 - 3 > bkf) continue :blk .b1469; // 1537
                continue :blk .b13AF;
            },
            .b154C => {
                if (p.piece_count[1] != 0) continue :blk .b13AF;
                if (class_of[si] != 0) continue :blk .b148F;
                if (bkr > wkr) continue :blk .b13AF; // 1560
                if (wkf != fileOf(f)) continue :blk .b14B8; // 156C
                if (bkf + 3 < wkf) continue :blk .b14B8; // 1578
                continue :blk .b13AF;
            },
            .b13AF => {
                if (tb(0x0E7A, si) > wkf or tb(0x0EDE, si) < wkf) continue :blk .b178C;
                if (p.piece_count[1] != 0) continue :blk .b1716; // 13C4
                if (p.king_rank[1] != p.king_rank[0]) continue :blk .b158C; // 13CE
                if (class_of[si] != 0) continue :blk .b14B8; // 13DA
                if (wkf != fileOf(f)) continue :blk .b14B8; // 13E4
                if (tb(0x0F42, si) > bkf) continue :blk .b14B8; // 13F0
                if (tb(0x0FA6, si) >= bkf) continue :blk .b15F7; // 13FC
                continue :blk .b14B8;
            },
            .b14B8 => {
                const ax: i16 = sqRank(f.scratch_a);
                if (ax > sw16(f.white_unstoppable)) f.white_unstoppable = @bitCast(ax);
                return .next_pawn;
            },
            .b158C => {
                if (bkr >= wkr) continue :blk .b15FE;
                if (tb(0x0F42, si) > bkf or tb(0x0FA6, si) < bkf) {
                    if (sqRank(si) + 2 < wkr) return .next_pawn; // 15A4
                    continue :blk .b14B8;
                }
                if (class_of[si] == 0 and wkf == fileOf(f)) { // 15BC
                    if (sqRank(si) <= bkr) continue :blk .b15F7;
                    if (bkr >= 7 and bkf != fileOf(f)) continue :blk .b15F7;
                }
                if (sqRank(si) + 2 < wkr) continue :blk .b15F7; // 15E2
                continue :blk .b14B8;
            },
            .b15F7 => {
                f.white_flags |= 4;
                return .next_pawn;
            },
            .b15FE => {
                if (class_of[si] == 0) {
                    if (tb(0x0F42, si) < bkf and tb(0x0FA6, si) > bkf) continue :blk .b15F7;
                    if (sqRank(si) > wkr) continue :blk .b15F7; // 1614
                    if (wkr >= 8) continue :blk .b14B8;
                    return .next_pawn;
                }
                if (sqRank(si) > wkr) continue :blk .b16EE; // 1628
                if (wkr == 8) continue :blk .b14B8;
                if (sqRank(si) + 2 > wkr) { // 163B
                    if (wkr == 7) {
                        if (si < 0x47) continue :blk .b1689;
                        const d = bk -% wk;
                        if (d != 0x13 and d != 0x15) continue :blk .b1689;
                    }
                    if (sqRank(si) >= wkr) continue :blk .b16A4; // 166D
                    if (cb(0x0D13 + wk - bk) != 0) continue :blk .b16A4;
                }
                continue :blk .b1689;
            },
            .b1689 => {
                if (p.material[1] == 0) continue :blk .b14B8;
                if (black_passed != 0) return .next_pawn;
                b.add(100);
                return .next_pawn;
            },
            .b16A4 => {
                if (wkr + 3 < bkr) return .next_pawn;
                if (wkf - 1 > bkf and tb(0x0E7A, si) > bkf) return .next_pawn; // 16B8
                if (wkf + 1 >= bkf) continue :blk .b15F7; // 16D0
                if (tb(0x0EDE, si) >= bkf) continue :blk .b15F7; // 16E2
                return .next_pawn;
            },
            .b16EE => {
                if (tb(0x0E7A, si) > bkf or tb(0x0EDE, si) < bkf) return .next_pawn;
                if (sqRank(si) + 3 >= bkr) continue :blk .b15F7; // 170B
                return .next_pawn;
            },
            .b1716 => {
                if (f.white_flags & 0x0B == 0) return .next_pawn;
                if (p.king_rank[1] == p.king_rank[0]) { // 171F
                    if (class_of[si] != 0) return .next_pawn;
                    continue :blk .b1732;
                }
                if (bkr < wkr) { // 174A
                    if (class_of[si] != 0) return .next_pawn; // 1753
                    if (sqRank(si) > bkr) return .next_pawn;
                    continue :blk .b1732;
                }
                if (class_of[si] == 0) continue :blk .b1732; // 176C
                if (p.king_rank[0] == 8) return .next_pawn;
                if (sqRank(si) < wkr) return .next_pawn; // 177D
                continue :blk .b1732;
            },
            .b1732 => {
                if (tb(0x0F42, si) >= bkf) return .next_pawn;
                if (tb(0x0FA6, si) > bkf) continue :blk .b15F7;
                return .next_pawn;
            },
            .b178C => {
                if (f.white_flags & 0x0B == 0) return .next_pawn;
                if (tb(0x0F42, si) < bkf and tb(0x0FA6, si) > bkf) { // 1795
                    if (class_of[si] == 0) continue :blk .b15F7;
                    if (sqRank(si) + 4 >= bkr) continue :blk .b15F7; // 17AE -> 170B
                    return .next_pawn;
                }
                if (bkf < fileOf(f)) { // 17BA
                    if (bkf < wkf) return .next_pawn;
                    if (bkf > wkf) continue :blk .b15F7; // 17CF
                    continue :blk .b17D4;
                }
                if (bkf > wkf) return .next_pawn; // 17F0
                if (bkf < wkf) continue :blk .b15F7; // 17FC
                continue :blk .b17D4;
            },
            .b17D4 => {
                const r = sqRank(si);
                if (r + 1 < wkr) continue :blk .b15F7;
                if (r - 1 > wkr) continue :blk .b15F7; // 17E9
                return .next_pawn;
            },
            // ---- White to move (2480-30F3; the model's `WhitePawnWTM`) ----
            .b2480 => {
                f.file = @bitCast(sqFile(si));
                if (tb(0x0EDE, si) < bkf or tb(0x0E7A, si) > bkf) {
                    f.king_outside = 1; // 24A3
                } else if (bk >= si - 1) {
                    f.king_outside = 0;
                } else {
                    f.king_outside = 1;
                }
                if (si < 0x33) continue :blk .b2725; // 24AE
                if (p.pawn_attacks[0][si + 10] != 0) { // 24B6 (no DG:A5F5 bit here)
                    var x = sw16(b.v.passer_rank_tables[1][rankIndex(si)]);
                    if (f.king_outside == 0) x >>= 1;
                    b.add(x);
                    continue :blk .b25DD;
                }
                if (ba(p, si) < wa(p, si)) continue :blk .b0B05; // 24E4: 24F1-25DA = 0B05-0BE0
                if (p.pawns_per_file[1][fileIndex(f)] != 0) b.add(-80); // 25D0
                continue :blk .b25DD;
            },
            .b25DD => {
                if (si < 0x47) continue :blk .b2725;
                const l04 = fileOf(f);
                if (wkr >= 6 and l04 - 2 <= wkf and l04 + 2 >= wkf) b.v.black_king_by_passer = 1; // 25E5
                if (si < 0x51) { // 2609 -> 2712
                    if (p.board[si + 10] == 0 and p.board[si + 20] == 0) b.v.promotion_flags |= 2;
                    continue :blk .b2725;
                }
                b.v.promotion_square = @intCast(si + 10); // 2611: a pawn on the 7th
                if (p.board[si + 10] == 0) {
                    b.v.promotion_flags |= 2;
                    p.board[si] = 0;
                    const x = b.callees.r2B9F_4AD4(b.callees.ctx, @intCast(si + 10)); // 262B
                    if (x == 0) b.v.promotion_flags |= 1;
                    p.board[si] = pos.white_pawn; // 2637
                    if (black_pieces <= 1100 and f.white_flags & 0x10 != 0 and cb(0x0D09 + si - wk) != 0) b.add(320);
                } else if (f.white_flags & 0x40 != 0 and p.board[si + 10] == pos.white_rook) { // 2660
                    b.add(-120);
                }
                if (class_of[si] != 0 or p.piece_material[1] != 650 or wkr <= 5) continue :blk .b2725; // 2670
                if (si == 0x51) { // 268F: a7
                    if (wkf >= 5) continue :blk .b2725;
                    if (p.board[82] == pos.white_king) { // 269E
                        if (bkr < 6 or bkf > 4) continue :blk .b2700;
                        if (bk != 0x40) continue :blk .b2725;
                        continue :blk .b2700;
                    }
                    if (bkr < 5) continue :blk .b2700; // 26BC
                    if (bkf <= 5) continue :blk .b2725;
                    continue :blk .b2700;
                }
                if (wkf <= 4) continue :blk .b2725; // 26CC
                if (p.board[87] == pos.white_king) {
                    if (bkr < 6 or bkf < 5) continue :blk .b2700;
                    if (bk != 0x41) continue :blk .b2725;
                    continue :blk .b2700;
                }
                if (bkr < 5) continue :blk .b2700; // 26F2
                if (bkf >= 4) continue :blk .b2725;
                continue :blk .b2700;
            },
            .b2700 => {
                if (sw16(f.white_unstoppable) < 8) f.white_unstoppable = 8;
                continue :blk .b10F9; // 28A5 = 10F9
            },
            .b2725 => {
                const arg2: i16 = @bitCast(b.arg2);
                if (arg2 >= 0 or p.piece_material[1] == 0) continue :blk .b2836;
                const bav = ba(p, si); // 2738
                const wav = wa(p, si);
                if (bav < wav) continue :blk .b2836;
                if (bav > wav) continue :blk .b281B;
                if (!(si >= 0x47) and p.board[si + 10] == 0) { // 274A
                    if (arg2 >= -1 and black_pieces > 1100) continue :blk .b2836; // 27F0
                    if (rooksOnLine(p, 1, si, b.fixes)) continue :blk .b281B; // 27FE
                    continue :blk .b2836;
                }
                // 2759: can a Black piece reach the square? (DEV-015 at 27E8)
                if (blackPieceReaches(p, si, b.fixes, b.stray[0])) continue :blk .b281B;
                continue :blk .b2836;
            },
            .b281B => {
                const x: i16 = @bitCast(b.callees.r4793_41B6(b.callees.ctx, @intCast(si), 6)); // 281E
                if (x < 0) {
                    b.flags(8);
                    if (si >= 0x51) b.flags(0x10);
                }
                continue :blk .b2836;
            },
            .b2836 => {
                if (p.pawn_count == 1 and p.piece_material[1] != 0 and sw16(p.piece_material[0]) < 1100 and
                    (f.king_outside == 0 or f.opposite_bishops != 0))
                {
                    b.add(-100); // 2858
                    return .leave; // into Black's loop at 285B
                }
                if (sb(p.pawns_per_file[0][fileIndex(f)]) > 1) { // 2890
                    f.scratch_a = @intCast(si);
                    var s = si;
                    while (s <= 0x4E) { // 289D
                        s += 10; // 2916
                        if (p.board[s] == pos.white_pawn) return .next_pawn;
                    }
                    si = f.scratch_a; // 28A2
                }
                continue :blk .b10F9; // 28A5 = 10F9
            },
            .b299C => {
                if (p.board[si + 10] != pos.black_king) continue :blk .b2A2A;
                if (p.material[1] != 0 or class_of[si] == 0 or si < 0x51) continue :blk .b2FD0; // 29A6
                if (p.board[si - 10] == pos.white_king) continue :blk .b29F4; // 29C2
                if (p.board[si - 9] == pos.white_king or p.board[si - 11] == pos.white_king) {
                    if (sw16(p.material[0]) > 400) continue :blk .b29F4; // 29D7
                    if (p.material[0] == 200) return .draw;
                    if (p.board[si - 10] == pos.white_pawn) return .draw;
                    continue :blk .b29F4;
                }
                if (wkr < 6 or wkr >= 9) return .next_pawn; // 29FE
                if (tb(0x0F42, si) > wkf or tb(0x0FA6, si) < wkf) return .next_pawn; // 2A12
                continue :blk .b29F4;
            },
            .b29F4 => {
                f.white_unstoppable = 8;
                return .next_pawn;
            },
            .b2A2A => {
                var l06: usize = if (si > 0x26) si else si + 10;
                f.scratch_a = @intCast(l06);
                var l08 = l06;
                const l04 = fileOf(f);
                if (wkf == l04 and wk >= si) { // 2A3E
                    l06 -= 10;
                    f.scratch_a = @intCast(l06);
                    if (class_of[si] == 0) {
                        l08 = l06;
                        if (f.white_flags & 1 != 0) l08 = l06 - 10;
                    }
                }
                f.scratch_b = @intCast(l08);
                const r = sqRank(l08); // 2A6C
                if (r > bkr or (l04 - r + 9) < bkf or (r + l04 - 9) > bkf) continue :blk .b2A9E;
                continue :blk .b2B50;
            },
            .b2A9E => {
                if (p.piece_count[1] == 0) continue :blk .b14B8; // 2C95 = 14B8
                continue :blk .b2AA8;
            },
            .b2AA8 => {
                if (f.king_outside == 0) return .next_pawn;
                continue :blk .b12EF; // 2AB1-2B4C = 12EF-138A
            },
            .b2B50 => {
                const r = sqRank(si);
                if (r - 1 > wkr) {
                    if (sb(p.pawn_count) < 2 and f.white_flags & 0x40 != 0) b.add(-140); // 2B60
                    continue :blk .b2B71;
                }
                if (r + 2 < wkr) continue :blk .b2B71; // 2BCA
                const l04 = fileOf(f);
                if (bkf <= l04) continue :blk .b2CDA; // 2BDE
                if (bkf < wkf) continue :blk .b2B71; // 2BEA
                if (l04 - 2 > wkf) continue :blk .b2B71; // 2BF6
                if (!(bkf > wkf) and r < bkr) continue :blk .b2B71; // 2C04
                if (p.piece_count[0] == 0) continue :blk .b2C50; // 2C13
                if (sqRank(si) > wkr or class_of[si] == 0) {
                    if (l04 + 3 >= bkf) continue :blk .b2B71; // 2C2A
                }
                continue :blk .b2C3B;
            },
            .b2C3B => {
                if (p.piece_count[1] != 0) continue :blk .b2AA8;
                // 2C45: the test of Black's passers, which Black's twin (1FE1 from 1E04) does
                // not make. DEV-054, corrected: Black's form, unstoppable whatever they are.
                if (b.fixes.dev054_unstoppable_passer_mirror or black_passed == 0) continue :blk .b14B8;
                continue :blk .b2B71;
            },
            .b2C50 => {
                if (p.piece_count[1] != 0) continue :blk .b2B71;
                if (class_of[si] == 0) continue :blk .b2CAC;
                continue :blk .b2C61;
            },
            .b2C61 => {
                if (black_passed != 0) continue :blk .b2B71;
                if (si < 0x47 and sqRank(si) > wkr) continue :blk .b2B71; // 2C6B
                if (wkr >= 7) continue :blk .b14B8; // 2C7C
                if (bkr - 1 <= wkr) continue :blk .b14B8;
                continue :blk .b2B71;
            },
            .b2CAC => {
                if (bkr - 1 > wkr) continue :blk .b2B71;
                if (wkf != fileOf(f)) continue :blk .b14B8; // 2CBE
                if (bkf - 2 > wkf) continue :blk .b14B8;
                continue :blk .b2B71;
            },
            .b2CDA => {
                const l04 = fileOf(f);
                if (bkf >= l04) continue :blk .b2B71;
                if (bkf > wkf) continue :blk .b2B71; // 2CE6
                if (l04 + 2 < wkf) continue :blk .b2B71; // 2CF2
                if (bkf >= wkf and sqRank(si) < bkr) continue :blk .b2B71; // 2D00
                if (p.piece_count[0] == 0) continue :blk .b2D40; // 2D12
                if (sqRank(si) <= wkr and class_of[si] != 0) continue :blk .b2C3B;
                if (l04 - 3 > bkf) continue :blk .b2C3B; // 2D2C
                continue :blk .b2B71;
            },
            .b2D40 => {
                if (p.piece_count[1] != 0) continue :blk .b2B71;
                if (class_of[si] != 0) continue :blk .b2C61;
                if (bkr - 1 > wkr) continue :blk .b2B71; // 2D54
                if (wkf != fileOf(f)) continue :blk .b14B8; // 2D66
                if (bkf + 2 < wkf) continue :blk .b14B8; // 2D72
                continue :blk .b2B71;
            },
            .b2B71 => {
                if (tb(0x0E7A, si) > wkf or tb(0x0EDE, si) < wkf) continue :blk .b2FD8;
                if (p.piece_count[1] != 0) continue :blk .b2F4A; // 2B86
                if (p.king_rank[1] != p.king_rank[0]) continue :blk .b2D86; // 2B90
                if (class_of[si] != 0) continue :blk .b14B8; // 2B9C
                if (sqRank(si) >= bkr) continue :blk .b14B8; // 2BA6
                if (tb(0x0F42, si) >= bkf) continue :blk .b14B8; // 2BB2
                if (tb(0x0FA6, si) > bkf) continue :blk .b2FD0; // 2BBE
                continue :blk .b14B8;
            },
            .b2D86 => {
                if (bkr >= wkr) continue :blk .b2E56;
                if (tb(0x0F42, si) < bkf and tb(0x0FA6, si) > bkf) { // 2D92
                    if (cb(0x0CFF + si - bk) != 0) { // 2DC8
                        if (sqRank(si) + 2 < wkr) continue :blk .b2FD0; // 2DDF
                        continue :blk .b14B8;
                    }
                    if (!(bkr + 1 < wkr)) { // 2DF0
                        if (class_of[si] != 0 or wkf != fileOf(f)) continue :blk .b14B8;
                        if (sqRank(si) < bkr) continue :blk .b2FD0; // 2E15
                        continue :blk .b14B8;
                    }
                    const r = sqRank(si); // 2E1E
                    if (r + 1 < bkr) continue :blk .b2FD0;
                    if (class_of[si] == 0 and wkf == fileOf(f) and r < bkr) continue :blk .b2FD0; // 2E33
                    if (r + 3 < wkr) continue :blk .b2FD0; // 2E4C -> 2DDF
                    continue :blk .b14B8;
                }
                if (sqRank(si) + 3 >= wkr) continue :blk .b14B8; // 2DA1
                if (bkr + 1 >= wkr) continue :blk .b14B8; // 2DB6
                return .next_pawn;
            },
            .b2E56 => {
                if (class_of[si] == 0) {
                    if (tb(0x0F42, si) < bkf and tb(0x0FA6, si) > bkf) continue :blk .b2FD0;
                    if (sqRank(si) - 1 > wkr) continue :blk .b2FD0; // 2E6F
                    if (wkr >= 7) continue :blk .b14B8; // 2E82
                    return .next_pawn;
                }
                if (tb(0x0E7A, si) > bkf or tb(0x0EDE, si) < bkf) { // 2E8C
                    if (sqRank(si) > wkr) return .next_pawn; // 2E9B
                    continue :blk .b14B8;
                }
                const wkr_raw = p.king_rank[0];
                if (wkr_raw == 8) continue :blk .b14B8; // 2EAA
                if (si >= 0x51 and wkr_raw == 7) continue :blk .b14B8; // 2EB4
                const d: isize = @as(isize, @intCast(bk)) - @as(isize, @intCast(wk));
                if (wkr_raw == 7) { // 2EC3
                    if (si < 0x47 or d != 0x14) continue :blk .b2F30;
                }
                if (sqRank(si) < wkr) { // 2EE1
                    if (sqRank(si) + 2 <= wkr or d != 0x14) continue :blk .b2F30;
                }
                if (constByte(0x1078 + si) != wkr_raw) continue :blk .b2FD0; // 2F0E
                if (cb(0x0D1D + wk - bk) != 0) continue :blk .b2FD0; // 2F1A
                continue :blk .b2F30;
            },
            .b2F30 => {
                if (p.material[1] == 0) continue :blk .b14B8;
                if (black_passed != 0) return .next_pawn;
                b.add(100);
                return .next_pawn;
            },
            .b2F4A => {
                if (f.white_flags & 0x0B == 0) return .next_pawn;
                if (p.king_rank[1] == p.king_rank[0]) { // 2F53
                    if (class_of[si] != 0) return .next_pawn;
                    continue :blk .b2F66;
                }
                if (bkr < wkr) { // 2F7E
                    if (sqRank(si) + 2 >= wkr) return .next_pawn;
                    continue :blk .b2F66;
                }
                if (p.king_rank[0] == 8) return .next_pawn; // 2F9E
                if (class_of[si] != 0 and sqRank(si) < wkr) return .next_pawn; // 2FA8
                if (tb(0x0E7A, si) > bkf) return .next_pawn; // 2FBB
                if (tb(0x0EDE, si) >= bkf) continue :blk .b2FD0;
                return .next_pawn;
            },
            .b2F66 => {
                if (tb(0x0F42, si) >= bkf) return .next_pawn;
                if (tb(0x0FA6, si) > bkf) continue :blk .b2FD0; // 2F72
                return .next_pawn;
            },
            .b2FD0 => {
                f.white_flags |= 4;
                return .next_pawn;
            },
            .b2FD8 => {
                if (f.white_flags & 0x0B == 0) return .next_pawn;
                const l04 = fileOf(f);
                if (tb(0x0F42, si) < bkf and tb(0x0FA6, si) > bkf) { // 2FE1
                    if (class_of[si] == 0) continue :blk .b2FD0; // 2FF6
                    if (si >= 0x47) {
                        if (p.piece_count[1] != 0) continue :blk .b2FD0;
                        if (bkf == l04) continue :blk .b2FD0; // 3009
                        if (p.material[1] != 0) return .next_pawn;
                        const bx: isize = @as(isize, @intCast(si)) - @as(isize, @intCast(wk)); // 3019
                        if (constByte(@intCast(0x0CFE + bx)) != 0) continue :blk .b29F4;
                        if (constByte(@intCast(0x0D00 + bx)) != 0) continue :blk .b29F4;
                        return .next_pawn;
                    }
                    if (sqRank(si) - bkr == -3) { // 3038
                        if (bkf == l04) continue :blk .b2FD0;
                        const bx: isize = @as(isize, @intCast(si)) - @as(isize, @intCast(wk)); // 3056
                        if (constByte(@intCast(0x0D08 + bx)) == 0 and constByte(@intCast(0x0D0A + bx)) == 0) continue :blk .b2FD0;
                        if (p.material[1] != 0) return .next_pawn; // 306E
                        continue :blk .b14B8;
                    }
                    if (sqRank(si) + 3 <= bkr) return .next_pawn; // 307C
                    if (bkf > l04) { // 3091
                        if (bkf < wkf) continue :blk .b2FD0; // 30A4
                        return .next_pawn;
                    }
                    if (bkf > wkf) continue :blk .b2FD0; // 309A
                    return .next_pawn;
                }
                if (bkf >= l04) { // 30B4
                    if (bkf > wkf) return .next_pawn; // 30E0
                    if (bkf < wkf) continue :blk .b2FD0;
                    continue :blk .b30CE;
                }
                if (bkf < wkf) return .next_pawn;
                if (bkf > wkf) continue :blk .b2FD0; // 30C9
                continue :blk .b30CE;
            },
            .b30CE => {
                if (sqRank(si) - 1 > wkr) continue :blk .b2FD0;
                return .next_pawn;
            },
        }
    }

    // -----------------------------------------------------------------------
    // Section 3: Black's passed pawns, Black to move (10B0-10E1, 1804-2443)
    // -----------------------------------------------------------------------

    /// 10B0-10E1: Black's passed pawns with Black to move, from the mask DG:9D8C.
    /// Returns null to go on to the tail (3736), or how static_eval ends.
    fn blackPassersBlackToMove(b: *Body) ?i16 {
        b.f.mask_left = b.v.passed_pawns[1]; // 10B0
        while (true) { // 10B6
            if (b.f.mask_left == 0) return null;
            const slot = lowestSlot(b.f.mask_left);
            b.f.mask_left &= ~slotBit(slot);
            const si = b.p.piece_list[16 + slot];
            if (si >= 120 or b.p.board[si] != pos.black_pawn) return b.restart(); // 10D7 -> 0A6E
            switch (b.blackPawn(si, false)) {
                .next_pawn => {},
                .leave => {
                    b.add(100); // 3733
                    return null;
                },
                .draw => return draw(b.v),
            }
        }
    }

    /// One Black passed pawn on `si0`, Black to move (1804-2443; the model's
    /// `BlackPawnBTM`). Not a mirror of `whitePawnBlackToMove`: here the pawn belongs to
    /// the side to move.
    fn blackPawn(b: *Body, si0: u8, comptime wtm: bool) PawnExit {
        const p = b.p;
        const f = &b.f;
        const v = b.v;
        var si: usize = si0;
        const wkf = sb(p.king_file[0]); // DG:A22E
        const bkf = sb(p.king_file[1]); // DG:A22F
        const wkr = sb(p.king_rank[0]); // DG:70F0
        const bkr = sb(p.king_rank[1]); // DG:70F1
        const wk: usize = p.piece_list[7]; // DG:A041
        const bk: usize = p.piece_list[16 + 7]; // DG:A051
        const white_pieces: i16 = sw16(p.piece_material[0]); // DG:AE38
        const white_passed = v.passed_pawns[0]; // DG:A6C2
        blk: switch (if (wtm) BlackBlock.b30F4 else BlackBlock.b1804) {
            .b1804 => {
                f.file = @bitCast(sqFile(si));
                if (tb(0x0EDE, si) < wkf or tb(0x0E7A, si) > wkf) {
                    f.king_outside = 1; // 1827
                } else if (wk <= si + 1) { // 181B
                    f.king_outside = 0;
                } else {
                    f.king_outside = 1;
                }
                if (si > 0x44) continue :blk .b1AB1; // 1832
                if (p.pawn_attacks[1][si - 10] != 0) { // 183A
                    var x = sw16(v.passer_rank_tables[3][rankIndex(si)]); // DG:0180
                    if (f.king_outside == 0) x >>= 1; // 1858
                    b.add(-%x);
                    continue :blk if (wtm) .b325D else .b1963;
                }
                if (!(ba(p, si) > wa(p, si))) { // 1868
                    if (p.pawns_per_file[0][fileIndex(f)] != 0) b.add(80); // 1956
                    continue :blk if (wtm) .b325D else .b1963;
                }
                if (si > 0x3A) continue :blk if (wtm) .b325D else .b1963; // 1875
                if (cb(0x0E16 + si) != 0) { // a dark square
                    if (f.bishop_bits == 3) continue :blk .b188D; // 1887
                    if (f.bishop_bits & 3 != 0) continue :blk .b193A; // 18A2
                    continue :blk .b18AB;
                }
                if (f.bishop_bits == 0x0C) continue :blk .b188D; // 1928
                if (f.bishop_bits & 0x0C == 0) continue :blk .b18AB; // 1931
                continue :blk .b193A;
            },
            .b18AB => {
                if (f.king_outside == 0 or v.endgame == 0) continue :blk .b1943;
                b.add(-%sw16(v.passer_rank_tables[2][rankIndex(si)])); // 18BE, DG:016C
                if (p.board[si + 9] == pos.black_pawn) {
                    if (tb(0x0EDE, si) < wkf or tb(0x0F42, si) > wkf) {
                        if (slotBitByte(p.square_slot[si + 9]) & v.passed_pawns[1] != 0) continue :blk .b1917; // 18E1
                    }
                }
                if (p.board[si + 11] != pos.black_pawn) continue :blk if (wtm) .b325D else .b1963; // 18F1
                if (!(tb(0x0E7A, si) > wkf) and tb(0x0FA6, si) >= wkf) continue :blk if (wtm) .b325D else .b1963;
                if (slotBitByte(p.square_slot[si + 11]) & v.passed_pawns[1] == 0) continue :blk if (wtm) .b325D else .b1963; // 1907
                continue :blk .b1917;
            },
            .b1917 => {
                b.add(if (si <= 0x26) -120 else -80);
                continue :blk if (wtm) .b325D else .b1963;
            },
            .b188D => {
                b.add(-%(sw16(v.passer_rank_tables[2][rankIndex(si)]) >> 2));
                continue :blk if (wtm) .b325D else .b1963;
            },
            .b193A => {
                if (f.king_outside == 0) continue :blk .b188D;
                continue :blk .b1943;
            },
            .b1943 => {
                b.add(-%(sw16(v.passer_rank_tables[2][rankIndex(si)]) >> 1));
                continue :blk if (wtm) .b325D else .b1963;
            },
            .b1963 => {
                if (si > 0x30) continue :blk .b1AB1;
                const l04 = fileOf(f);
                if (bkr <= 5 and l04 - 2 <= bkf and l04 + 2 >= bkf) v.black_king_by_passer = 1; // 196B
                if (si > 0x26) { // 198F
                    if (p.board[si - 10] == 0 and p.board[si - 20] == 0) v.promotion_flags |= 2; // 1A9E
                    continue :blk .b1AB1;
                }
                // 1997: a pawn on the 2nd rank
                v.promotion_square = @intCast(si - 10);
                if (p.board[si - 10] == 0) {
                    v.promotion_flags |= 2;
                    p.board[si] = 0;
                    const x = b.callees.r2B9F_4A76(b.callees.ctx, @intCast(si - 10)); // 19B1
                    if (x == 0) v.promotion_flags |= 1;
                    p.board[si] = pos.black_pawn; // 19BD
                    if (white_pieces <= 1100 and f.black_flags & 0x10 != 0 and cb(0x0CF5 + si - bk) != 0) b.add(-320);
                } else if (f.black_flags & 0x40 != 0 and p.board[si - 10] == pos.black_rook) { // 19E6
                    b.add(120);
                }
                if (class_of[si] != 0 or p.piece_material[0] != 650) continue :blk .b1AB1; // 19F6
                if (bkr >= 6) continue :blk .b1AB1; // 1A0B
                if (si == 0x1F) { // 1A15: a2
                    if (bkf >= 5) continue :blk .b1AB1;
                    if (p.board[32] == pos.black_king) { // 1A24
                        if (wkr > 5 or wkf > 4) continue :blk .b1A86;
                        if (wk != 0x36) continue :blk .b1AB1;
                        continue :blk .b1A86;
                    }
                    if (wkr > 6) continue :blk .b1A86; // 1A42
                    if (wkf <= 5) continue :blk .b1AB1;
                    continue :blk .b1A86;
                }
                if (bkf <= 4) continue :blk .b1AB1; // 1A52
                if (p.board[37] == pos.black_king) {
                    if (wkr > 5 or wkf < 5) continue :blk .b1A86;
                    if (wk != 0x37) continue :blk .b1AB1;
                    continue :blk .b1A86;
                }
                if (wkr > 6) continue :blk .b1A86; // 1A78
                if (wkf >= 4) continue :blk .b1AB1;
                continue :blk .b1A86;
            },
            .b1A86 => {
                const l0e = sw16(f.black_unstoppable);
                if (l0e == 0 or l0e > 3) f.black_unstoppable = 3;
                continue :blk .b1BFF;
            },
            .b1AB1 => {
                const arg2: i16 = @bitCast(b.arg2);
                if (arg2 >= 0) continue :blk .b1BC2;
                if (p.piece_material[0] == 0) continue :blk .b1BC2; // 1ABA
                const bav = ba(p, si); // 1AC4
                const wav = wa(p, si);
                if (bav > wav) continue :blk .b1BC2;
                if (bav < wav) continue :blk .b1BA7;
                if (si > 0x30 and p.board[si - 10] == 0) { // 1AD6
                    if (arg2 >= -1 and white_pieces > 1100) continue :blk .b1BC2; // 1B7C
                    if (rooksOnLine(p, 0, si, b.fixes)) continue :blk .b1BA7; // 1B8A
                    continue :blk .b1BC2;
                }
                // 1AE5: can a White piece reach the square? (DEV-015 at 1B74)
                if (whitePieceReaches(p, si, b.fixes, b.stray[0])) continue :blk .b1BA7;
                continue :blk .b1BC2;
            },
            .b1BA7 => {
                const x: i16 = @bitCast(b.callees.r4793_4CEC(b.callees.ctx, @intCast(si), 6)); // 1BAA
                if (x < 0) {
                    b.flags(8);
                    if (si <= 0x26) b.flags(0x10);
                }
                continue :blk .b1BC2;
            },
            .b1BC2 => {
                if (p.pawn_count == 1 and p.piece_material[0] != 0 and sw16(p.piece_material[1]) < 1100 and
                    (f.king_outside == 0 or f.opposite_bishops != 0))
                {
                    return .leave; // 3733: di += 100 into the tail
                }
                if (sb(p.pawns_per_file[1][fileIndex(f)]) > 1) { // 1BEA
                    f.scratch_a = @intCast(si);
                    var s = si;
                    while (s >= 0x29) { // 1BF7
                        s -= 10; // 1C70
                        if (p.board[s] == pos.black_pawn) return .next_pawn;
                    }
                    si = f.scratch_a; // 1BFC
                }
                continue :blk .b1BFF;
            },
            .b1BFF => {
                if (white_pieces >= 3100) continue :blk .b1CD8;
                var l06: i16 = cb(@intCast(0x11BB + sqFile(si) - wkf));
                const l08a: i16 = cb(@intCast(0x11DB + sqRank(si) - wkr)); // 1C0A
                if (l06 < l08a) l06 = l08a;
                const cx: i16 = cb(@intCast(0x11FB + sqRank(si) - bkr)); // 1C3D
                const l08: i16 = cb(@intCast(0x11AB + sqFile(si) - bkf));
                f.scratch_b = @bitCast(l08);
                l06 -= if (l08 < cx) cx else l08;
                const t: i16 = cb(0x1140 + si) *% l06; // 1C86: imul, 16 bits
                f.scratch_a = @bitCast(t);
                if (white_pieces > 2500 or f.opposite_bishops != 0) {
                    b.add(-%(t >> 1));
                    continue :blk .b1CD8;
                }
                b.add(-%t); // 1CA8
                if (white_pieces < 700) {
                    b.add(-%(t >> 2));
                    continue :blk .b1CD8;
                }
                if (p.piece_balance == 1100 and p.side_pawn_count[0] == 0) { // 1CBC
                    b.add(-%t);
                    if (sb(p.side_pawn_count[1]) < 3) b.add(-%t);
                }
                continue :blk .b1CD8;
            },
            .b1CD8 => {
                const ax: i16 = cb(0x0438 + @as(usize, @intCast(sb(p.board[si - 10]))));
                b.add(ax -% sw16(v.passerTable(f.black_passer_table)[si]));
                if (white_pieces > 700 and f.black_flags == 0) return .next_pawn;
                continue :blk if (wtm) .b38A6 else .b1D00;
            },
            .b1D00 => {
                if (p.board[si - 10] == pos.white_king) { // the White king in front
                    if (p.material[0] != 0 or class_of[si] == 0 or si > 0x26) continue :blk .b2328;
                    if (p.board[si + 9] == pos.black_king or p.board[si + 11] == pos.black_king) { // 1D26
                        if (sw16(p.material[1]) > 400) continue :blk .b1D5B;
                        if (p.material[1] == 200) return .draw;
                        if (p.board[si + 10] == pos.black_pawn) return .draw;
                        continue :blk .b1D5B;
                    }
                    if (p.board[si + 10] == pos.black_king) continue :blk .b1D5B; // 1D54
                    if (bkr > 5 or bkr <= 2) return .next_pawn; // 1D64
                    if (tb(0x0F42, si) > bkf or tb(0x0FA6, si) < bkf) return .next_pawn;
                    continue :blk .b1D5B;
                }
                var l06: usize = if (si < 0x51) si else si - 10; // 1D90
                f.scratch_a = @intCast(l06);
                var l08 = l06;
                const l04 = fileOf(f);
                if (bkf == l04 and bk <= si) { // 1DA4
                    l06 += 10;
                    f.scratch_a = @intCast(l06);
                    if (class_of[si] == 0) {
                        l08 = l06;
                        if (f.black_flags & 1 != 0) l08 = l06 + 10;
                    }
                }
                f.scratch_b = @intCast(l08);
                const r = sqRank(l08); // 1DD2
                if (r < wkr or r + l04 - 2 < wkf or (l04 - r + 2) > wkf) continue :blk .b1E04;
                continue :blk .b1EB6;
            },
            .b1D5B => {
                f.black_unstoppable = 3;
                return .next_pawn;
            },
            .b1E04 => {
                if (p.piece_count[0] == 0) continue :blk .b1FE1; // 1E0B (DEV-054: the form both colours take)
                if (f.king_outside == 0 or f.black_flags & 0x10 == 0 or si > 0x44) return .next_pawn;
                if (sw16(p.piece_material[1]) < 2000 and bkr > 6) return .next_pawn; // 1E28
                if (tb(0x0F42, si) > bkf or tb(0x0FA6, si) < bkf) return .next_pawn; // 1E3A
                b.add(-60); // 1E4F
                if (si > 0x3A) return .next_pawn;
                if (class_of[si] != 0 or !(white_pieces > 650)) b.add(-60); // 1E5A
                if (sw16(p.material[1]) < 2400 or f.opposite_bishops != 0) { // 1E6C
                    if (bkr > 5 or white_passed != 0) return .next_pawn; // 1E7A
                }
                b.add(-80); // 1E8E
                if (sw16(p.piece_balance) > 100 or f.opposite_bishops != 0) return .next_pawn;
                b.add(-60); // 1EA4
                if (si > 0x30) return .next_pawn;
                b.add(-60);
                return .next_pawn;
            },
            .b1EB6 => {
                if (sqRank(si) + 1 >= bkr) continue :blk .b1F24;
                if (sb(p.pawn_count) < 2 and f.black_flags & 0x40 != 0) b.add(140); // 1EC6
                continue :blk .b1ED7;
            },
            .b1ED7 => {
                if (tb(0x0E7A, si) > bkf or tb(0x0EDE, si) < bkf) continue :blk .b2330;
                if (p.piece_count[0] != 0) continue :blk .b22A2; // 1EEC
                if (p.king_rank[1] != p.king_rank[0]) continue :blk .b20E4; // 1EF6
                if (class_of[si] != 0) continue :blk .b1FE1; // 1F02
                // DEV-062: the rank test its mirror 2B71 makes at 2BA6.
                if (b.fixes.dev062_king_test_rank and sqRank(si) <= wkr) continue :blk .b1FE1;
                if (tb(0x0F42, si) >= wkf) continue :blk .b1FE1; // 1F0C
                if (tb(0x0FA6, si) > wkf) continue :blk .b2328; // 1F18
                continue :blk .b1FE1;
            },
            .b1F24 => {
                const r = sqRank(si);
                if (r - 2 > bkr) continue :blk .b1ED7;
                const l04 = fileOf(f);
                if (!(wkf > l04)) continue :blk .b2034; // 1F38
                if (bkf > wkf) continue :blk .b1ED7; // 1F44
                if (l04 - 2 > bkf) continue :blk .b1ED7;
                if (bkf >= wkf and r > wkr) continue :blk .b1ED7; // 1F5B
                if (p.piece_count[1] == 0) continue :blk .b1F9C; // 1F6D
                if (sqRank(si) >= bkr and class_of[si] != 0) continue :blk .b1E04;
                if (l04 + 3 >= wkf) continue :blk .b1ED7; // 1F87
                continue :blk .b1E04;
            },
            .b1F9C => {
                if (p.piece_count[0] != 0) continue :blk .b1ED7;
                if (class_of[si] == 0) continue :blk .b2006;
                continue :blk .b1FAD;
            },
            .b1FAD => {
                if (white_passed != 0) continue :blk .b1ED7;
                if (si > 0x30 and sqRank(si) < bkr) continue :blk .b1ED7; // 1FB7
                if (bkr <= 4) continue :blk .b1FE1; // 1FC8
                if (wkr + 1 >= bkr) continue :blk .b1FE1;
                continue :blk .b1ED7;
            },
            .b1FE1 => {
                const r = sqRank(f.scratch_a);
                const l0e = sw16(f.black_unstoppable);
                if (l0e != 0 and r >= l0e) return .next_pawn;
                f.black_unstoppable = @bitCast(r); // 1FF7
                return .next_pawn;
            },
            .b2006 => {
                if (wkr + 1 < bkr) continue :blk .b1ED7;
                if (bkf != fileOf(f)) continue :blk .b1FE1; // 2018
                if (wkf - 2 > bkf) continue :blk .b1FE1; // 2021
                continue :blk .b1ED7;
            },
            .b2034 => {
                const l04 = fileOf(f);
                if (wkf >= l04) continue :blk .b1ED7;
                if (bkf < wkf) continue :blk .b1ED7; // 2040
                if (l04 + 2 < bkf) continue :blk .b1ED7; // 2049
                if (bkf <= wkf and sqRank(si) > wkr) continue :blk .b1ED7; // 205A
                if (p.piece_count[1] == 0) continue :blk .b209E; // 206F
                if (sqRank(si) >= bkr and class_of[si] != 0) continue :blk .b1E04;
                if (l04 - 3 > wkf) continue :blk .b1E04; // 2089
                continue :blk .b1ED7;
            },
            .b209E => {
                if (p.piece_count[0] != 0) continue :blk .b1ED7;
                if (class_of[si] != 0) continue :blk .b1FAD;
                if (wkr + 1 < bkr) continue :blk .b1ED7; // 20B2
                if (bkf != fileOf(f)) continue :blk .b1FE1; // 20C4
                if (wkf + 2 >= bkf) continue :blk .b1ED7; // 20D0
                continue :blk .b1FE1;
            },
            .b20E4 => {
                if (bkr >= wkr) continue :blk .b21AE;
                if (tb(0x0F42, si) < wkf and tb(0x0FA6, si) > wkf) continue :blk .b2120; // 20F0
                if (sqRank(si) - 3 <= bkr) continue :blk .b1FE1; // 20FF
                if (bkr + 1 >= wkr) continue :blk .b1FE1; // 2114
                return .next_pawn;
            },
            .b2120 => {
                if (cb(0x0CFF + si - wk) != 0) {
                    if (sqRank(si) - 2 > bkr) continue :blk .b2328; // 2137
                    continue :blk .b1FE1;
                }
                if (bkr + 1 >= wkr) { // 2148
                    if (class_of[si] != 0) continue :blk .b1FE1;
                    if (bkf != fileOf(f)) continue :blk .b1FE1; // 2161
                    if (sqRank(si) > wkr) continue :blk .b2328; // 216D
                    continue :blk .b1FE1;
                }
                const r = sqRank(si); // 2176
                if (r - 1 > wkr) continue :blk .b2328;
                if (class_of[si] == 0 and bkf == fileOf(f) and r > wkr) continue :blk .b2328; // 218B
                if (r - 3 > bkr) continue :blk .b2328; // 21A4 -> 2137
                continue :blk .b1FE1;
            },
            .b21AE => {
                if (class_of[si] == 0) {
                    if (tb(0x0F42, si) < wkf and tb(0x0FA6, si) > wkf) continue :blk .b2328;
                    if (sqRank(si) + 1 < bkr) continue :blk .b2328; // 21C7
                    if (bkr <= 4) continue :blk .b1FE1; // 21DA
                    return .next_pawn;
                }
                if (tb(0x0E7A, si) > wkf or tb(0x0EDE, si) < wkf) { // 21E4
                    if (sqRank(si) >= bkr) continue :blk .b1FE1; // 21F3
                    return .next_pawn;
                }
                const bkr_raw = p.king_rank[1];
                if (bkr_raw == 3) continue :blk .b1FE1; // 2202
                if (si <= 0x26 and bkr_raw == 4) continue :blk .b1FE1; // 220C
                const d: isize = @as(isize, @intCast(bk)) - @as(isize, @intCast(wk));
                if (bkr_raw == 4) { // 221B
                    if (si > 0x30 or d != 0x14) continue :blk .b2288;
                }
                if (sqRank(si) > bkr) { // 2239
                    if (sqRank(si) - 2 >= bkr or d != 0x14) continue :blk .b2288;
                }
                if (constByte(0x1078 + si) != bkr_raw) continue :blk .b2328; // 2266
                if (constByte(@intCast(0x0CE1 + d)) != 0) continue :blk .b2328; // 2272
                continue :blk .b2288;
            },
            .b2288 => {
                if (p.material[0] == 0) continue :blk .b1FE1;
                if (white_passed != 0) return .next_pawn;
                b.add(-100);
                return .next_pawn;
            },
            .b22A2 => {
                if (f.black_flags & 0x0B == 0) return .next_pawn;
                if (p.king_rank[1] == p.king_rank[0]) { // 22AB
                    if (class_of[si] != 0) return .next_pawn;
                    continue :blk .b22BE;
                }
                if (bkr < wkr) { // 22D6
                    if (sqRank(si) - 2 <= bkr) return .next_pawn;
                    continue :blk .b22BE;
                }
                if (p.king_rank[1] == 3) return .next_pawn; // 22F6
                if (class_of[si] != 0 and sqRank(si) > bkr) return .next_pawn; // 2300
                if (tb(0x0E7A, si) > wkf) return .next_pawn; // 2313
                if (tb(0x0EDE, si) >= wkf) continue :blk .b2328;
                return .next_pawn;
            },
            .b22BE => {
                if (tb(0x0F42, si) >= wkf) return .next_pawn;
                if (tb(0x0FA6, si) > wkf) continue :blk .b2328; // 22CA
                return .next_pawn;
            },
            .b2328 => {
                f.black_flags |= 4;
                return .next_pawn;
            },
            .b2330 => {
                if (f.black_flags & 0x0B == 0) return .next_pawn;
                const l04 = fileOf(f);
                if (tb(0x0F42, si) < wkf and tb(0x0FA6, si) > wkf) { // 2339
                    if (class_of[si] == 0) continue :blk .b2328; // 234E
                    if (si <= 0x30) {
                        if (p.piece_count[0] != 0) continue :blk .b2328;
                        if (wkf == l04) continue :blk .b2328; // 2361
                        if (p.material[0] != 0) return .next_pawn;
                        const bx: isize = @as(isize, @intCast(si)) - @as(isize, @intCast(bk)); // 2371
                        if (constByte(@intCast(0x0CFE + bx)) != 0) continue :blk .b1D5B;
                        if (constByte(@intCast(0x0D00 + bx)) != 0) continue :blk .b1D5B;
                        return .next_pawn;
                    }
                    if (sqRank(si) - wkr == 3) { // 2390
                        if (wkf == l04) continue :blk .b2328;
                        const bx: isize = @as(isize, @intCast(si)) - @as(isize, @intCast(bk)); // 23AE
                        if (constByte(@intCast(0x0CF6 + bx)) == 0 and constByte(@intCast(0x0CF4 + bx)) == 0) continue :blk .b2328;
                        if (p.material[0] != 0) return .next_pawn; // 23C6
                        continue :blk .b1FE1;
                    }
                    if (sqRank(si) - 3 >= wkr) return .next_pawn; // 23D4
                    if (wkf > l04) { // 23E9
                        if (bkf > wkf) continue :blk .b2328; // 23F8
                        return .next_pawn;
                    }
                    if (bkf < wkf) continue :blk .b2328; // 23F2
                    return .next_pawn;
                }
                if (wkf >= l04) { // 2402
                    if (bkf < wkf) return .next_pawn; // 2430
                    if (bkf > wkf) continue :blk .b2328;
                    continue :blk .b2419;
                }
                if (bkf > wkf) return .next_pawn;
                if (bkf < wkf) continue :blk .b2328; // 2414
                continue :blk .b2419;
            },
            .b2419 => {
                if (sqRank(si) + 1 < bkr) continue :blk .b2328;
                return .next_pawn;
            },
            // ---- White to move (30F4-3735, 378E-3EB5; the model's `BlackPawnWTM`) ----
            .b30F4 => {
                f.file = @bitCast(sqFile(si));
                if (tb(0x0EDE, si) < wkf or tb(0x0E7A, si) > wkf) {
                    f.king_outside = 1; // 3117
                } else if (wk <= si + 1) {
                    f.king_outside = 0;
                } else {
                    f.king_outside = 1;
                }
                if (si > 0x44) continue :blk .b3711; // 3122
                if (p.pawn_attacks[1][si - 10] != 0) { // 312A
                    var x = sw16(v.passer_rank_tables[3][rankIndex(si)]);
                    if (f.king_outside == 0) x >>= 1;
                    b.add(-%x);
                    if (si <= 0x30) b.flags(4); // 315F
                    continue :blk .b325D;
                }
                if (!(ba(p, si) > wa(p, si))) { // 3168
                    if (p.pawns_per_file[0][fileIndex(f)] != 0) b.add(80); // 3250
                    continue :blk .b325D;
                }
                if (si > 0x3A) continue :blk .b325D; // 3175: 3175-324E = 1875-1954
                if (cb(0x0E16 + si) != 0) {
                    if (f.bishop_bits == 3) continue :blk .b188D;
                    if (f.bishop_bits & 3 != 0) continue :blk .b193A;
                    continue :blk .b18AB;
                }
                if (f.bishop_bits == 0x0C) continue :blk .b188D; // 3216
                if (f.bishop_bits & 0x0C == 0) continue :blk .b18AB;
                continue :blk .b193A;
            },
            .b325D => {
                if (si > 0x30) continue :blk .b3711;
                if (p.pawn_attacks[0][si] != 0) b.flags(8); // 3265
                if (p.board[si - 10] != 0) continue :blk .b35E2; // 3271
                if (si > 0x26) continue :blk .b34F4; // 327B
                // 3283: a pawn on the 2nd
                if (white_pieces > 700) continue :blk .b32FC;
                if (white_pieces == 0) { // 328B
                    b.flags(2);
                    b.add(-240);
                    continue :blk .b1BFF; // 37A3 = 1BFF
                }
                const l04 = fileOf(f);
                const near = wkr <= 4 and l04 + 2 >= wkf and l04 - 2 <= wkf;
                if (white_pieces == 700) { // 329E
                    if (near and cb(0x0CF5 + si - bk) == 0) continue :blk .b32FC; // 32A9
                    if (p.piece_material[0] != 700) continue :blk .b32FC; // 32D7
                    if (cb(0x0E16 + si) != 0) {
                        if (p.piece_list[3] >= 0x63) continue :blk .b32FC;
                        continue :blk .b34CE;
                    }
                    if (p.piece_list[2] >= 0x63) continue :blk .b32FC; // 32F2
                    continue :blk .b34CE;
                }
                if (near) continue :blk .b32FC; // 3336
                if (class_of[si] != 0 or bkr >= 6) continue :blk .b33AC; // 3355
                if (si == 0x1F) { // 336B: a2
                    if (bkf >= 5) continue :blk .b33AC;
                    if (p.board[32] == pos.black_king) {
                        if (wkr > 6 or wkf > 5) continue :blk .b34CE;
                        if (wk != 0x41) continue :blk .b33AC;
                        continue :blk .b34CE;
                    }
                    if (wkr > 6 or wkf > 6) continue :blk .b34CE; // 3398
                    continue :blk .b33AC;
                }
                if (bkf <= 4) continue :blk .b33AC; // 3422
                if (p.board[37] == pos.black_king) {
                    if (wkr > 6 or wkf < 4) continue :blk .b34CE;
                    if (wk != 0x40) continue :blk .b33AC;
                    continue :blk .b34CE;
                }
                if (wkr > 6 or wkf < 3) continue :blk .b34CE; // 344C
                continue :blk .b33AC;
            },
            .b33AC => {
                // A White knight against the pawn on the 2nd.
                var n: usize = p.piece_list[0];
                f.scratch_a = @intCast(n);
                if (n > 0x62) {
                    n = p.piece_list[1];
                    f.scratch_a = @intCast(n);
                }
                if (n >= 0x63) continue :blk .b32FC; // 33BF
                const l08: i16 = cb(0x013D - @as(usize, @intCast(sqRank(n))));
                f.scratch_b = @bitCast(l08);
                if (l08 > 5) continue :blk .b34CE;
                const bx: i16 = fileOf(f) - sqFile(n) + 7; // 33E1
                const l06: i16 = cb(@intCast(0x0134 + bx));
                f.scratch_a = @bitCast(l06);
                if (l06 > 5) continue :blk .b34CE;
                if (l06 == 3 and l08 == 3) { // 3401
                    if (bx > 7) {
                        if (p.board[si - 1] == pos.black_king) continue :blk .b34CE;
                        if (p.board[si + 8] == pos.black_king) continue :blk .b34CE;
                        continue :blk .b32FC;
                    }
                    if (p.board[si + 1] == pos.black_king) continue :blk .b34CE; // 3460
                    if (p.board[si + 12] == pos.black_king) continue :blk .b34CE;
                    continue :blk .b32FC;
                }
                const sum = l06 + l08; // 3474
                f.scratch_a = @bitCast(sum);
                if (sum == 2) {
                    if (l08 - 1 != 0) continue :blk .b32FC;
                    if (class_of[si] == 0) continue :blk .b34CE; // 3486
                    if (p.board[si - 1] == pos.white_knight) {
                        if (cb(0x0CF6 + si - bk) != 0) continue :blk .b34CE;
                        continue :blk .b32FC;
                    }
                    if (cb(0x0CF4 + si - bk) != 0) continue :blk .b34CE; // 34A4
                    continue :blk .b32FC;
                }
                if (sum > 8) continue :blk .b34CE; // 34B6
                if (sum & 1 == 0) continue :blk .b32FC;
                if (sum != 3) continue :blk .b34CE;
                continue :blk .b32FC;
            },
            .b32FC => {
                f.advanced_passers +%= 1;
                p.board[si] = 0;
                const x: i16 = @bitCast(b.callees.see_black(b.callees.ctx, @intCast(si - 10), 9)); // 330C
                if (x >= 0) {
                    b.flags(2);
                    b.add(-240);
                    f.advanced_passers -%= 1;
                }
                if (f.advanced_passers == 2) { // 331F (after both outcomes)
                    b.flags(1);
                    b.add(-%sw16(f.black_second_passer_bonus));
                }
                p.board[si] = pos.black_pawn; // 332D
                continue :blk .b3711;
            },
            .b34CE => {
                b.add(-120);
                if (white_passed != 0) b.flags(2);
                const l0e = sw16(f.black_unstoppable); // 34DD
                if (l0e == 0 or l0e > 3) f.black_unstoppable = 3;
                continue :blk .b1BFF;
            },
            .b34F4 => {
                // A pawn on the 3rd, the square in front empty.
                if (p.board[si - 20] != 0 or white_pieces > 1800) continue :blk .b3711;
                f.advanced_passers +%= 1; // 3509
                if (f.advanced_passers == 2) continue :blk .b3709;
                if (cb(0x0CEB + si - bk) != 0) continue :blk .b36EE; // 3515
                if (p.piece_material[0] != 650) { // 3527
                    if (white_pieces > 700 or f.king_outside == 0) continue :blk .b3711; // 35C6
                    continue :blk .b35DA;
                }
                const l04 = fileOf(f);
                if (wkr <= 5 and l04 + 3 >= wkf and l04 - 3 <= wkf) continue :blk .b35DA; // 3532
                var n: usize = p.piece_list[0]; // 3554
                f.scratch_a = @intCast(n);
                if (n > 0x62) {
                    n = p.piece_list[1];
                    f.scratch_a = @intCast(n);
                }
                if (n >= 0x63) continue :blk .b35DA;
                var cx: i16 = cb(0x013D - @as(usize, @intCast(sqRank(n))));
                cx += cb(@intCast(0x013B + l04 - sqFile(n)));
                f.scratch_a = @bitCast(cx);
                if (cx <= 7 or cx == 9) continue :blk .b35DA;
                b.add(-120); // 359E
                if (white_passed != 0) b.flags(4);
                const l0e = sw16(f.black_unstoppable); // 35AD
                if (l0e == 0 or l0e > 4) f.black_unstoppable = 4;
                continue :blk .b1BFF;
            },
            .b35DA => {
                b.flags(4);
                continue :blk .b3711;
            },
            .b35E2 => {
                // The square in front is occupied.
                if (si > 0x26) continue :blk .b36F8;
                const front = p.board[si - 10];
                if (sb(front) > 7) { // 35EA
                    if (sb(front) < 0x0B) continue :blk .b3711; // 35F1
                    b.flags(4);
                    if (f.black_flags & 0x40 != 0) b.add(120);
                    continue :blk .b3711;
                }
                if (front == pos.white_king) { // 3610
                    if (p.board[si + 10] == pos.black_king) continue :blk .b35DA;
                    continue :blk .b3711;
                }
                if (p.piece_material[0] != 650 or class_of[si] != 0) continue :blk .b36D4; // 3624
                if (bkr >= 6) continue :blk .b3711; // 3639
                if (si == 0x1F) { // 3643
                    if (bkf >= 5) continue :blk .b3711;
                    if (p.board[32] == pos.black_king) { // 3652
                        b.flags(4);
                        if (wkr > 5) continue :blk .b34CE;
                        if (wkf <= 4) continue :blk .b3711;
                        continue :blk .b34CE;
                    }
                    if (wkr > 6) continue :blk .b34CE; // 3672
                    if (bkf + 2 >= wkf) continue :blk .b3711;
                    continue :blk .b34CE;
                }
                if (bkf <= 4) continue :blk .b3711; // 368E
                if (p.board[37] == pos.black_king) {
                    b.flags(4);
                    if (wkr > 5) continue :blk .b34CE;
                    if (wkf >= 5) continue :blk .b3711;
                    continue :blk .b34CE;
                }
                if (wkr > 6) continue :blk .b34CE; // 36B6
                if (bkf - 2 <= wkf) continue :blk .b3711;
                continue :blk .b34CE;
            },
            .b36D4 => {
                const val: i16 = cb(0x128C + @as(usize, @intCast(sb(p.board[si - 10]))));
                const x: i16 = @bitCast(b.callees.r4793_41B6(b.callees.ctx, @intCast(si - 10), @bitCast(val))); // 36E5
                if (x >= 0) continue :blk .b36F8;
                continue :blk .b36EE;
            },
            .b36EE => {
                b.flags(4);
                b.add(-120);
                continue :blk .b3711;
            },
            .b36F8 => {
                if (white_pieces > 700) continue :blk .b3711;
                f.advanced_passers +%= 1;
                if (f.advanced_passers != 2) continue :blk .b3711;
                continue :blk .b3709;
            },
            .b3709 => {
                b.flags(1);
                b.add(-%sw16(f.black_second_passer_bonus));
                continue :blk .b3711;
            },
            .b3711 => {
                if (p.pawn_count == 1 and p.piece_material[0] != 0 and sw16(p.piece_material[1]) < 1100 and
                    (f.king_outside == 0 or f.opposite_bishops != 0))
                {
                    return .leave; // 3733: di += 100 into the tail
                }
                if (sb(p.pawns_per_file[1][fileIndex(f)]) > 1) { // 378E
                    f.scratch_a = @intCast(si);
                    var s = si;
                    while (s >= 0x29) { // 379B
                        s -= 10; // 3814
                        if (p.board[s] == pos.black_pawn) return .next_pawn;
                    }
                    si = f.scratch_a; // 37A0
                }
                continue :blk .b1BFF; // 37A3 = 1BFF
            },
            .b38A6 => {
                if (p.board[si - 10] == pos.white_king) { // the White king in front
                    if (p.material[0] != 0) continue :blk .b3CA7;
                    if (class_of[si] == 0) { // 38B7: a rook's pawn
                        f.black_flags |= 4;
                        if (si > 0x26) return .next_pawn;
                        if (cb(0x0CFF + si - bk) != 0) return .draw;
                        return .next_pawn;
                    }
                    if (si > 0x26) continue :blk .b3CA7; // 38E0
                    if (p.board[si + 10] == pos.black_king) return .draw;
                    if (p.board[si + 9] == pos.black_king or p.board[si + 11] == pos.black_king) f.black_unstoppable = 3; // 38F2
                    return .next_pawn;
                }
                var l06: usize = if (si < 0x51) si else si - 10; // 390C
                f.scratch_a = @intCast(l06);
                var l08 = l06;
                const l04 = fileOf(f);
                if (bkf == l04 and bk <= si) { // 3920
                    l06 += 10;
                    f.scratch_a = @intCast(l06);
                    if (class_of[si] == 0) {
                        l08 = l06;
                        if (f.black_flags & 1 != 0) l08 = l06 + 10;
                    }
                }
                if (p.pawn_attacks[0][si] != 0) l08 -= 10; // 394E
                f.scratch_b = @intCast(l08);
                const r = sqRank(l08); // 3959
                if (r + 1 < wkr or r + l04 - 1 < wkf or (l04 - r + 1) > wkf) continue :blk .b398B;
                continue :blk .b3A3E;
            },
            .b398B => {
                if (p.piece_count[0] == 0) continue :blk .b1FE1; // 3992: 3B5A = 1FE1 (DEV-054: the form both colours take)
                if (f.black_flags & 0x10 == 0 or si > 0x44) return .next_pawn; // 3995
                if (sw16(p.piece_material[1]) < 2000 and bkr > 6) return .next_pawn; // 39A6
                if (tb(0x0F42, si) > bkf or tb(0x0FA6, si) < bkf) return .next_pawn; // 39B8
                b.add(-60); // 39CD
                if (si > 0x3A) return .next_pawn;
                if (class_of[si] != 0 or !(white_pieces > 650)) b.add(-60); // 39D8
                if (!b.fixes.dev055_passer_block_extra_test and white_passed != 0) return .next_pawn; // 39EA (DEV-055: in none of the twins)
                if (sw16(p.material[1]) < 2400 or f.opposite_bishops != 0) { // 39F4
                    if (bkr > 5 or white_passed != 0) return .next_pawn; // 3A02
                }
                b.add(-80); // 3A16
                if (sw16(p.piece_balance) > 100 or f.opposite_bishops != 0) return .next_pawn;
                b.add(-60); // 3A2C
                if (si > 0x30) return .next_pawn;
                b.add(-60);
                return .next_pawn;
            },
            .b3A3E => {
                if (sqRank(si) + 1 >= bkr) continue :blk .b3AB8;
                if (sb(p.pawn_count) < 2 and f.black_flags & 0x40 != 0) b.add(140); // 3A4E
                continue :blk .b3A5F;
            },
            .b3AB8 => {
                if (sqRank(si) - 2 > bkr) continue :blk .b3A5F;
                const l04 = fileOf(f);
                if (l04 + 1 >= wkf) continue :blk .b3BA6; // 3ACA
                if (bkf >= wkf) continue :blk .b3A5F; // 3AD9
                if (l04 - 2 > bkf) continue :blk .b3A5F; // 3AE2
                if (p.piece_count[1] == 0) continue :blk .b3B20; // 3AF3
                if (bkr <= 5 and class_of[si] != 0) continue :blk .b398B;
                if (l04 + 3 >= wkf) continue :blk .b3A5F; // 3B0B
                continue :blk .b398B;
            },
            .b3B20 => {
                if (p.piece_count[0] != 0) continue :blk .b3A5F;
                if (class_of[si] == 0) continue :blk .b3B7E;
                continue :blk .b3B31;
            },
            .b3B31 => {
                if (white_passed != 0) continue :blk .b3A5F;
                if (sqRank(si) > bkr or bkr <= 3) continue :blk .b1FE1; // 3B3B
                if (wkr + 1 >= bkr) continue :blk .b1FE1;
                continue :blk .b3A5F;
            },
            .b3B7E => {
                if (bkr > wkr) continue :blk .b3A5F;
                if (bkf != fileOf(f)) continue :blk .b1FE1; // 3B8A
                if (wkf - 3 > bkf) continue :blk .b1FE1;
                continue :blk .b3A5F;
            },
            .b3BA6 => {
                const l04 = fileOf(f);
                if (!(l04 - 1 > wkf)) continue :blk .b3A5F;
                if (!(bkf > wkf)) continue :blk .b3A5F; // 3BB5
                if (l04 + 2 < bkf) continue :blk .b3A5F; // 3BBE
                if (p.piece_count[1] == 0) continue :blk .b3BFC; // 3BCF
                if (bkr <= 5 and class_of[si] != 0) continue :blk .b398B;
                if (l04 - 3 > wkf) continue :blk .b398B; // 3BE7
                continue :blk .b3A5F;
            },
            .b3BFC => {
                if (p.piece_count[0] != 0) continue :blk .b3A5F;
                if (class_of[si] != 0) continue :blk .b3B31;
                if (bkr > wkr) continue :blk .b3A5F; // 3C10
                if (bkf != fileOf(f)) continue :blk .b1FE1; // 3C1C
                if (wkf + 3 < bkf) continue :blk .b1FE1; // 3C28
                continue :blk .b3A5F;
            },
            .b3A5F => {
                if (tb(0x0E7A, si) > bkf or tb(0x0EDE, si) < bkf) continue :blk .b3E3E;
                if (p.piece_count[0] != 0) continue :blk .b3DCC; // 3A74
                if (p.king_rank[1] != p.king_rank[0]) continue :blk .b3C3C; // 3A7E
                if (class_of[si] != 0) continue :blk .b1FE1; // 3A8A
                if (bkf != fileOf(f)) continue :blk .b1FE1; // 3A94
                if (tb(0x0F42, si) > wkf) continue :blk .b1FE1; // 3AA0
                if (tb(0x0FA6, si) >= wkf) continue :blk .b3CA7; // 3AAC
                continue :blk .b1FE1;
            },
            .b3C3C => {
                if (bkr >= wkr) continue :blk .b3CAE;
                if (tb(0x0F42, si) > wkf or tb(0x0FA6, si) < wkf) {
                    if (sqRank(si) - 2 <= bkr) continue :blk .b1FE1; // 3C54
                    return .next_pawn;
                }
                if (class_of[si] == 0 and bkf == fileOf(f)) { // 3C6C
                    if (sqRank(si) >= wkr) continue :blk .b3CA7;
                    if (wkr <= 4 and wkf != fileOf(f)) continue :blk .b3CA7;
                }
                if (sqRank(si) - 2 > bkr) continue :blk .b3CA7; // 3C92
                continue :blk .b1FE1;
            },
            .b3CA7 => {
                f.black_flags |= 4;
                return .next_pawn;
            },
            .b3CAE => {
                if (class_of[si] == 0) {
                    if (tb(0x0F42, si) < wkf and tb(0x0FA6, si) > wkf) continue :blk .b3CA7;
                    if (sqRank(si) < bkr) continue :blk .b3CA7; // 3CC4
                    if (bkr <= 3) continue :blk .b1FE1; // 3CCD
                    return .next_pawn;
                }
                if (sqRank(si) < bkr) continue :blk .b3D9E; // 3CD8
                if (bkr == 3) continue :blk .b1FE1; // 3CE4
                if (sqRank(si) - 2 < bkr) { // 3CEB
                    if (bkr == 4) { // 3CFD
                        if (si > 0x30) continue :blk .b3D39;
                        const d = bk -% wk;
                        if (d != 0x13 and d != 0x15) continue :blk .b3D39;
                    }
                    if (sqRank(si) <= bkr) continue :blk .b3D54; // 3D1D
                    if (cb(0x0CEB + bk - wk) != 0) continue :blk .b3D54; // 3D26
                }
                continue :blk .b3D39;
            },
            .b3D39 => {
                if (p.material[0] == 0) continue :blk .b1FE1;
                if (white_passed != 0) return .next_pawn;
                b.add(-100);
                return .next_pawn;
            },
            .b3D54 => {
                if (bkr - 3 > wkr) return .next_pawn;
                if (bkf - 1 > wkf and tb(0x0E7A, si) > wkf) return .next_pawn; // 3D68
                if (bkf + 1 >= wkf) continue :blk .b3CA7; // 3D80
                if (tb(0x0EDE, si) >= wkf) continue :blk .b3CA7; // 3D92
                return .next_pawn;
            },
            .b3D9E => {
                if (tb(0x0E7A, si) > wkf or tb(0x0EDE, si) < wkf) return .next_pawn;
                if (sqRank(si) - 3 <= wkr) continue :blk .b3CA7; // 3DB3 -> 3DBB
                return .next_pawn;
            },
            .b3DCC => {
                if (f.black_flags & 0x0B == 0) return .next_pawn;
                if (p.king_rank[1] == p.king_rank[0]) { // 3DD5
                    if (class_of[si] != 0) return .next_pawn;
                    continue :blk .b3DE8;
                }
                if (bkr < wkr) { // 3E00
                    if (class_of[si] != 0) return .next_pawn;
                    if (sqRank(si) < wkr) return .next_pawn; // 3E13
                    continue :blk .b3DE8;
                }
                if (class_of[si] == 0) continue :blk .b3DE8; // 3E1E
                if (p.king_rank[1] == 3) return .next_pawn;
                if (sqRank(si) > bkr) return .next_pawn; // 3E2F
                continue :blk .b3DE8;
            },
            .b3DE8 => {
                if (tb(0x0F42, si) >= wkf) return .next_pawn;
                if (tb(0x0FA6, si) > wkf) continue :blk .b3CA7; // 3DF4
                return .next_pawn;
            },
            .b3E3E => {
                if (f.black_flags & 0x0B == 0) return .next_pawn;
                if (tb(0x0F42, si) < wkf and tb(0x0FA6, si) > wkf) { // 3E47
                    if (class_of[si] == 0) continue :blk .b3CA7;
                    if (sqRank(si) - 4 <= wkr) continue :blk .b3CA7; // 3E60 -> 3DBB
                    return .next_pawn;
                }
                if (wkf < fileOf(f)) { // 3E6C
                    if (bkf > wkf) return .next_pawn; // 3E75
                    if (bkf < wkf) continue :blk .b3CA7;
                    continue :blk .b3E83;
                }
                if (bkf < wkf) return .next_pawn; // 3EA4
                if (bkf > wkf) continue :blk .b3CA7;
                continue :blk .b3E83;
            },
            .b3E83 => {
                const r = sqRank(si);
                if (r - 1 > bkr) continue :blk .b3CA7;
                if (r + 1 < bkr) continue :blk .b3CA7; // 3E98
                return .next_pawn;
            },
        }
    }

    // -----------------------------------------------------------------------
    // The tail (3736-378D, 3EB8-4029)
    // -----------------------------------------------------------------------

    /// 3736-4029: the Passed Pawns weight, the score of the quick path and section 1
    /// added back, the lone-side and race terms, the clamp.
    fn tail(b: *Body) i16 {
        const p = b.p;
        const v = b.v;
        const f = &b.f;
        var di = b.di;
        if (v.style_normal == 0 and v.passed_pawns_weight != 100) di = scalePercent(di, v.passed_pawns_weight); // 3736
        di +%= sw16(f.quick_score); // 376A (jns on the sum)
        if (di >= 0) {
            if (p.side_pawn_count[0] == 0) { // 3772
                if (sw16(p.material[0]) < 1100) di = -1; // 3787
            } else if (f.white_flags & 4 != 0) { // 3EB8
                if (f.white_flags & 2 != 0) {
                    di = 0;
                    if (p.side_pawn_count[1] == 0) v.draw_flag = 1;
                } else if (f.white_flags & 9 != 0) { // 3ED4
                    di -%= 100;
                }
            }
        } else {
            if (p.side_pawn_count[1] == 0) { // 3EE0
                if (sw16(p.material[1]) < 1100) di = 1;
            } else if (f.black_flags & 4 != 0) { // 3EF4
                if (f.black_flags & 2 != 0) {
                    di = 0;
                    if (p.side_pawn_count[0] == 0) v.draw_flag = 1;
                } else if (f.black_flags & 9 != 0) { // 3F0A
                    di +%= 100;
                }
            }
        }
        if (v.draw_flag == 0) { // 3F13: the unstoppable-pawn race
            const l0c: isize = sw16(f.white_unstoppable);
            const l0e: isize = sw16(f.black_unstoppable);
            if (b.side != 0) { // 3F23: Black to move
                if (l0e != 0) {
                    v.promotion_flags &= 0xFE;
                    if (l0c != 0) {
                        di +%= cwAt(0x02A0 + 2 * (l0e + l0c));
                    } else { // 3F42
                        const base: isize = if (p.material[0] == 0) 0x02EE else 0x02DA;
                        di -%= cwAt(base - 2 * l0e);
                    }
                } else if (l0c != 0) { // 3F4E
                    di +%= cwAt((if (p.material[1] != 0) @as(isize, 0x02C4) else 0x02D8) + 2 * l0c);
                }
            } else { // 3F68: White to move
                if (l0c != 0) {
                    v.promotion_flags &= 0xFE;
                    if (l0e != 0) {
                        di +%= cwAt(0x02A2 + 2 * (l0e + l0c));
                    } else {
                        di +%= cwAt((if (p.material[1] == 0) @as(isize, 0x02D8) else 0x02C4) + 2 * l0c); // 3F88
                    }
                } else if (l0e != 0) { // 3F9A
                    const base: isize = if (p.material[0] != 0) 0x02DA else 0x02EE;
                    di -%= cwAt(base - 2 * l0e);
                }
            }
        }
        if (p.side_pawn_count[0] == 0 and di > 0) { // 3FB5: White has no pawns
            if (sw16(p.piece_material[0]) < 1100) {
                di = 0;
            } else if (sw16(p.piece_balance) <= 900) {
                di -%= sw16(p.material_balance_2) >> 1;
            }
        }
        if (p.side_pawn_count[1] == 0 and di < 0) { // 3FDD: Black has no pawns
            if (sw16(p.piece_material[1]) < 1100) {
                di = 0;
            } else if (sw16(p.piece_balance) >= -900) {
                di -%= sw16(p.material_balance_2) >> 1;
            }
        }
        return std.math.clamp(di, -14000, 14000); // 4003
    }

    /// 01A8-0A32: section 1. Returns the score when the function returns from it (the
    /// special endings; no clamp), or null to go on to the passed-pawn loops with the
    /// frame in `b.f` and the score in `b.di`.
    fn section1(b: *Body) ?i16 {
        switch (b.blackFewPawns()) { // 01C8
            .ret => |x| return x,
            .tables => {},
            .next => switch (b.whiteFewPawns()) { // 0410
                .ret => |x| return x,
                .tables, .next => {},
            },
        }
        b.tablesBlack(); // 065A
        b.tablesWhite(); // 0819
        if (b.f.bishop_bits == 3 or b.f.bishop_bits == 0x0C) { // 0A17
            b.f.opposite_bishops = 1;
            if (b.p.total_material == 1600) b.di -%= @as(i16, @bitCast(b.p.material_balance_2));
        }
        return null;
    }
};

/// The blocks of White's passed-pawn loops (Black to move 0A84-1803, White to move
/// 2480-30F3, which shares blocks 0B05-0BCD, 10F9, 11D2, 12EF and 14B8), by address.
const WhiteBlock = enum { b0A84, b0B05, b0B29, b0B95, b0BAC, b0BC7, b0BCD, b0BED, b0C80, b0D20, b0E44, b0E7A, b0F56, b0F5E, b104E, b1068, b1072, b1083, b108B, b10E4, b10F9, b11D2, b11FC, b12E5, b12EF, b138E, b13AF, b1469, b147E, b148F, b14B8, b14CE, b14F6, b154C, b158C, b15F7, b15FE, b1689, b16A4, b16EE, b1716, b1732, b178C, b17D4, b2480, b25DD, b2700, b2725, b281B, b2836, b299C, b29F4, b2A2A, b2A9E, b2AA8, b2B50, b2B71, b2C3B, b2C50, b2C61, b2CAC, b2CDA, b2D40, b2D86, b2E56, b2F30, b2F4A, b2F66, b2FD0, b2FD8, b30CE };

/// The blocks of Black's passed-pawn loops (Black to move 1804-2443, White to move
/// 30F4-3EB5, which shares blocks 1875-1954, 1BFF, 1CD8 and 1FE1), by address.
const BlackBlock = enum { b1804, b188D, b18AB, b1917, b193A, b1943, b1963, b1A86, b1AB1, b1BA7, b1BC2, b1BFF, b1CD8, b1D00, b1D5B, b1E04, b1EB6, b1ED7, b1F24, b1F9C, b1FAD, b1FE1, b2006, b2034, b209E, b20E4, b2120, b21AE, b2288, b22A2, b22BE, b2328, b2330, b2419, b30F4, b325D, b32FC, b33AC, b34CE, b34F4, b35DA, b35E2, b36D4, b36EE, b36F8, b3709, b3711, b38A6, b398B, b3A3E, b3A5F, b3AB8, b3B20, b3B31, b3B7E, b3BA6, b3BFC, b3C3C, b3CA7, b3CAE, b3D39, b3D54, b3D9E, b3DCC, b3DE8, b3E3E, b3E83 };

/// The byte of a by-difference table (DG:0B66 diagonal, DG:0A68 knight, DG:0C64
/// orthogonal, DG:0CFF king) for the piece in list entry `side * 16 + slot` and the square
/// `sq`, read at `table + sq - entry` as the original does, for any entry (a captured
/// piece's entry, square + 63h, reads further down; those bytes come from the program).
fn reachByte(p: *const Position, table: usize, sq: usize, entry: usize) u8 {
    return constByte(table + sq - p.piece_list[entry]);
}

/// `reachByte` of a line table (DG:0B66 or DG:0C64), under DEV-053: corrected, the step
/// counts only if the list entry is a square of the board on that line through `sq`.
fn lineByte(p: *const Position, comptime table: usize, sq: usize, entry: usize, fixes: Fixes) u8 {
    const b = reachByte(p, table, sq, entry);
    if (!fixes.dev053_line_tables_other) return b;
    const st = realLineStep(@intCast(sq), p.piece_list[entry], @as(i8, @bitCast(b)));
    return @bitCast(@as(i8, @intCast(st)));
}

/// DEV-053 corrected: `step` (the line tables' step from `target` towards `entry`) if
/// `entry` is a square of the board (at most 62h) on that line through `target`, else 0.
/// A copy of src/helpers.zig `realLineStep` (the rule is explained there), kept here so
/// that static_eval does not import the search helpers; helpers_test.zig compares the two
/// on every target, entry and step.
pub inline fn realLineStep(target: i32, entry: i32, step: i32) i32 {
    if (step == 0 or entry > 0x62 or entry < 0) return 0;
    const d = entry - target;
    const df = @mod(entry, 10) - @mod(target, 10);
    const ok = switch (step) {
        1, -1 => d == df,
        11, -11 => d == 11 * df,
        9, -9 => d == -9 * df,
        else => true,
    };
    return if (ok) step else 0;
}

/// 2B9F:1B8A-1BA1 (`side` = 0: White's rooks towards a Black passed pawn on `sq`) and
/// 27FE-2815 (1: Black's rooks towards a White one): the OR of DG:0C64 for the two rook
/// slots, the prefilter of the exchange call at 1BAA / 281E. DEV-053 as `lineByte`.
pub fn rooksOnLine(p: *const Position, comptime side: usize, sq: usize, fixes: Fixes) bool {
    const l = 16 * side;
    return (lineByte(p, 0x0C64, sq, l + 4, fixes) | lineByte(p, 0x0C64, sq, l + 5, fixes)) != 0;
}

/// 2B9F:1AE5-1B79: whether a White piece can reach `sq` (a Black passed pawn's square,
/// Black to move): bishops and queen by DG:0B66, the knights by DG:0A68, rooks and
/// queen by DG:0C64, the king by DG:0CFF.
///
/// DEV-015: the code keeps the test of the knight in slot 1 at `[bp-2Ah]` and then ORs in
/// `[bp-29h]`, a frame byte it never writes. `Fixes.original` uses `stray.bp29`, the byte
/// the original happened to read; `Fixes.corrected` uses the knight test.
///
/// DEV-053 (`Fixes.dev053_line_tables_other`): the line tables' bytes are taken on trust,
/// with no walk, so a pseudo-line or a captured piece's entry opens the prefilter and the
/// exchange (4793:4CEC) is called; it can then find an attack the prefilter does not look
/// for (pawns, a piece outside its slot), which the colour mirror does not. Corrected as
/// `lineByte`.
pub fn whitePieceReaches(p: *const Position, sq: usize, fixes: Fixes, stray: StrayBytes) bool {
    var al = lineByte(p, 0x0B66, sq, 2, fixes) | lineByte(p, 0x0B66, sq, 3, fixes) | lineByte(p, 0x0B66, sq, 6, fixes);
    const dl = reachByte(p, 0x0A68, sq, 0);
    const knight2 = reachByte(p, 0x0A68, sq, 1); // stored at [bp-2Ah]
    al |= lineByte(p, 0x0C64, sq, 4, fixes) | lineByte(p, 0x0C64, sq, 5, fixes) | lineByte(p, 0x0C64, sq, 6, fixes) | reachByte(p, 0x0CFF, sq, 7);
    al |= if (fixes.dev015_knight_test) knight2 else stray.bp29; // 1B74
    return dl | al != 0;
}

/// 2B9F:2759-27ED: whether a Black piece can reach `sq` (a White passed pawn's square,
/// White to move); the mirror of `whitePieceReaches` for Black's list.
///
/// DEV-015: the test of the knight in slot 0 is stored at `[bp-2Ch]` and not used;
/// `[bp-2Bh]`, never written, is OR-ed in instead (27E8). `Fixes.original` uses
/// `stray.bp2B`; `Fixes.corrected` the knight test. DEV-053 as in `whitePieceReaches`.
pub fn blackPieceReaches(p: *const Position, sq: usize, fixes: Fixes, stray: StrayBytes) bool {
    var al = lineByte(p, 0x0B66, sq, 16 + 2, fixes) | lineByte(p, 0x0B66, sq, 16 + 3, fixes) | lineByte(p, 0x0B66, sq, 16 + 6, fixes);
    const dl = reachByte(p, 0x0A68, sq, 16 + 1);
    al |= lineByte(p, 0x0C64, sq, 16 + 4, fixes) | lineByte(p, 0x0C64, sq, 16 + 5, fixes) | lineByte(p, 0x0C64, sq, 16 + 6, fixes) | reachByte(p, 0x0CFF, sq, 16 + 7);
    al |= if (fixes.dev015_knight_test) reachByte(p, 0x0A68, sq, 16 + 0) else stray.bp2B; // 27E8
    return dl | al != 0;
}

/// The constant byte at DG:addr, for tests.
pub fn constByteForTest(addr: usize) u8 {
    return constByte(addr);
}
