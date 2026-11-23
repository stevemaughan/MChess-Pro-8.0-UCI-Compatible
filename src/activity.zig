//! Piece activity: piece_activity_white (1E9D:16E4), piece_activity_black (1E9D:1E30)
//! and mobility_term (0000:2E72), which combines them.
//!
//! Specification: docs/arch/53-evaluation-pieces-kings.md §4.2–4.4, whose executable
//! form is tools/research/evalpieces/activity.py (proved against the running original on
//! about 798,000 calls of each routine). Tests: src/evalpieces_test.zig, which replays
//! calls recorded from the original (tests/golden/evalpieces/).
//!
//! The two activity routines are hand-written assembly and are not mirror images of
//! each other (§4.3, DEV-019). White's is written once for either colour, as its colour
//! mirror for Black (`Activity`); the original Black routine is written out on its own,
//! as the original has it. DEV-019 corrected (`pos.Fixes.dev019_activity_mirror`, owner
//! decision 30), Black's routine is the mirror of White's, and both take the forms the
//! code shows were meant (`Forms`). Tests: src/activity_test.zig.
//!
//! The helpers are all `inline`, so that each routine compiles to one function whose
//! running sum stays in a register.
//!
//! The sum is the original's 16-bit DX: every addition wraps. Table bytes are added
//! unsigned; board bytes and pawn-attack counts are compared as signed bytes.

const std = @import("std");
const pos = @import("position.zig");
const EvalState = @import("eval_state.zig").EvalState;
const original = @import("original.zig");

const Position = pos.Position;

/// DG:0194 + slot: the passed-pawn mask bit of a pawn slot (0 for slots 0..7).
const slot_passed_bit = original.dgroup(0x0194, 16);
/// DG:100A: file of a square.
const file_of = original.dgroup(0x100A, 120);

/// How a knight's target square counts, by the piece code on it.
const Target = enum(u8) { never, unattacked, always };

/// The White knight's target classes by piece code, forward (1714: nothing at the border
/// or an own pawn; a Black pawn or an empty square only when no Black pawn attacks it;
/// anything else counts) and backward (1788: as forward, but every White piece and the
/// border count nothing). A table lookup in place of the chain of tests, which compiled
/// to a jump table per target square.
const wk_fwd = targetTable(.{ .{ 0, .unattacked }, .{ 1, .never }, .{ 7, .never }, .{ 8, .unattacked } }, .always);
const wk_back = targetTable(.{ .{ 0, .unattacked }, .{ 1, .never }, .{ 2, .never }, .{ 3, .never }, .{ 4, .never }, .{ 5, .never }, .{ 6, .never }, .{ 7, .never }, .{ 8, .unattacked } }, .always);

fn targetTable(comptime codes: anytype, comptime default: Target) [256]Target {
    var tab: [256]Target = @splat(default);
    for (codes) |c| tab[c[0]] = c[1];
    return tab;
}

const knight = 0;
const bishop = 1;
const rook = 2;
const queen = 3;

const Ctx = struct {
    p: *const Position,
    e: *const EvalState,
    /// DX, the running sum.
    dx: i16 = 0,
    /// The activity table of the piece being evaluated.
    tab: []const u8 = undefined,

    inline fn B(c: *const Ctx, sq: i32) u8 {
        return c.p.board[@intCast(sq)];
    }
    inline fn wa(c: *const Ctx, sq: i32) i8 {
        return @bitCast(c.p.pawn_attacks[0][@intCast(sq)]);
    }
    inline fn ba(c: *const Ctx, sq: i32) i8 {
        return @bitCast(c.p.pawn_attacks[1][@intCast(sq)]);
    }
    /// `(BA[sq] - WA[sq])` as a byte, signed.
    inline fn baMinusWa(c: *const Ctx, sq: i32) i8 {
        return @bitCast(c.p.pawn_attacks[1][@intCast(sq)] -% c.p.pawn_attacks[0][@intCast(sq)]);
    }
    inline fn waMinusBa(c: *const Ctx, sq: i32) i8 {
        return @bitCast(c.p.pawn_attacks[0][@intCast(sq)] -% c.p.pawn_attacks[1][@intCast(sq)]);
    }
    /// The White king's (A09E) or the Black king's (A164) ray code at a square.
    inline fn wmap(c: *const Ctx, sq: i32) u8 {
        return c.p.king_rays[0][@intCast(sq)];
    }
    inline fn bmap(c: *const Ctx, sq: i32) u8 {
        return c.p.king_rays[1][@intCast(sq)];
    }
    inline fn add(c: *Ctx, sq: i32) void {
        c.dx +%= c.tab[@intCast(sq)];
    }
    /// Adds T[sq] when `count`, a pawn-attack count, is 0, without a branch: the
    /// count is unpredictable from square to square along a ray.
    inline fn addIfZero(c: *Ctx, sq: i32, count: i8) void {
        c.dx +%= @as(i16, c.tab[@intCast(sq)]) & -@as(i16, @intFromBool(count == 0));
    }
    /// Adds T[sq] when `class` is `always`, or `unattacked` and `free` holds.
    inline fn addWhen(c: *Ctx, sq: i32, class: Target, free: bool) void {
        const take = class == .always or (class == .unattacked and free);
        c.dx +%= @as(i16, c.tab[@intCast(sq)]) & -@as(i16, @intFromBool(take));
    }
    inline fn plus(c: *Ctx, v: i16) void {
        c.dx +%= v;
    }
    /// `test [194h + slot[sq]], [mask]`: the pawn on `sq` is passed. It is called only
    /// at a square holding a pawn, whose slot is 8..15.
    inline fn passed(c: *const Ctx, sq: i32, mask: u8) bool {
        return slot_passed_bit[c.p.square_slot[@intCast(sq)]] & mask != 0;
    }

    /// 17EE / 1F2A: DX >> 2, and once more when the side's non-pawn material < 3500.
    fn result(c: *const Ctx, material: u16) i16 {
        var ax = c.dx >> 2;
        if (@as(i16, @bitCast(material)) < 0xDAC) ax >>= 1;
        return ax;
    }
};

/// The board byte at a piece-list entry, or 0 (nothing to evaluate) for a captured
/// piece. DEV-018 (class A, fixed without a switch, owner decision 27): a captured
/// piece's entry is its square + 63h, beyond the board, and the original reads
/// DG:9EF6 + entry all the same (1E9D:1805 White, 1F41 Black: the entry, then
/// `mov al,[bp+di]` with BP at the board, and no test of the entry). The byte (`EvalState.past_board`,
/// DG:9F6E-9FBB) was 0 in all 4,253,040 such reads recorded, and 0 makes the original
/// skip the slot, so skipping captured pieces gives exactly the recorded behaviour. Were
/// the byte ever one of the side's piece codes, the original would evaluate a phantom
/// piece off the board by reading unrelated memory around it; that is never a correct
/// result, and the port skips the slot instead. `past_board` is no longer read here.
inline fn listedPiece(p: *const Position, e: *const EvalState, entry: u8) u8 {
    _ = e;
    return if (entry < 120) p.board[entry] else pos.empty;
}

// =============================================================================
// White: 1E9D:16E4, and its colour mirror (DEV-019)
// =============================================================================
//
// White's routine is written once, in White's view, for either colour: `Activity(black,
// forms)`. For White it is the original 16E4. For Black every square read is the same,
// with the board's ranks reversed and the colours exchanged: steps are mirrored (+9 is
// -11 for Black, +10 is -10), piece codes are read through `swap_code`, each side's pawn
// attacks, king-ray maps (direction codes mirrored), tables, passed-pawn masks and pawns
// per file are the other side's, and a rank test compares the mirrored square. That is
// the mirror of 16E4 by construction, which DEV-019's correction makes Black's routine.
//
// `Forms` are the places where the original 1E30 is not that mirror (docs/arch/
// 53-evaluation-pieces-kings.md §4.3 and the note of 2026-11-20). With every form set
// (`black_forms`), `Activity(true, ...)` is the original 1E30, which
// src/activity_test.zig proves on every recorded call and on generated ones: so the
// five forms are every difference there is.

/// The places where the original Black routine (1E30) is not the mirror of White's
/// (16E4), each in Black's form when set. White's routine has none set. A sixth
/// difference, the order of the rays, does not change the sum (§4.3 item 2).
pub const Forms = struct {
    /// §4.3 item 1 (Black 1F77 → 1FC2, 2077 → 20BC; White 1857 → 1873, 19E7 → 1A05): a
    /// bishop's backward ray at an enemy pawn not defended by more pawns than attack it:
    /// add its table entry and stop, where White's goes on as an x-ray past the pawn.
    bishop_pawn_stop: bool = false,
    /// §4.3 item 3 (Black 2394–23A1 → 2369; White 1B91–1B9E → 1BDF): a rook's forward ray
    /// at its own pawn on the seventh or eighth rank also adds the pawn square's table
    /// entry.
    rook_pawn_table: bool = false,
    /// §4.3 item 4 (Black 23DD → 23E5; White 1B6D → 1B79): a rook's forward ray, past an
    /// enemy minor piece to an enemy rook attacked by an own pawn: walk on behind the
    /// rook (C8h) where White's adds 118h.
    rook_behind_attacked: bool = false,
    /// §4.3 item 5 (Black 2513–2521, 2575–2583; White 1D9B → 1DAB, 1DF7 → 1E07): a
    /// queen's forward diagonal ending at an enemy queen or king gives nothing, where
    /// White's gives the king-ray bonuses and the table entry.
    queen_diag_queen_king: bool = false,
    /// §4.3 item 6 (Black 2424–2429, 2461–2466; White 1CBE–1CC1, 1CFB–1CFE): a queen's
    /// horizontal ray ending at the border on the enemy king's ray: treated as an enemy
    /// piece, where White's gives 60h only. Border squares carry no ray code, so it
    /// cannot happen.
    queen_side_border: bool = false,
};

/// Every form of the original Black routine.
pub const black_forms: Forms = .{ .bishop_pawn_stop = true, .rook_pawn_table = true, .rook_behind_attacked = true, .queen_diag_queen_king = true, .queen_side_border = true };

/// The forms of both colours under `fixes`. DEV-019 corrected: the rook's two places
/// (items 3 and 4) and the bishop's (item 1) take White's form, the queen's diagonal
/// (item 5) Black's, in both routines; item 6 cannot happen and takes White's.
pub fn formsOf(comptime fixes: pos.Fixes) Forms {
    return if (fixes.dev019_activity_mirror) .{ .queen_diag_queen_king = true } else .{};
}

/// The square with its rank reversed (a1 ↔ a8), on the 10x12 board.
const mirror_sq: [120]u8 = blk: {
    var t: [120]u8 = undefined;
    for (0..120) |s| t[s] = @intCast((11 - s / 10) * 10 + s % 10);
    break :blk t;
};

/// A piece code with its colour exchanged (1..6 ↔ 8..13); empty, border and anything
/// else unchanged.
const swap_code: [256]u8 = blk: {
    var t: [256]u8 = undefined;
    for (0..256) |b| t[b] = if (b >= 1 and b <= 6) b + 7 else if (b >= 8 and b <= 13) b - 7 else b;
    break :blk t;
};

/// A knight's target table indexed by the colour-exchanged code.
fn swappedTable(comptime t: [256]Target) [256]Target {
    var s: [256]Target = undefined;
    for (0..256) |b| s[b] = t[swap_code[b]];
    return s;
}

/// The board step with its rank part reversed: +9 ↔ −11, +11 ↔ −9, +10 ↔ −10, ±1
/// unchanged, +8 ↔ −12, +19 ↔ −21.
fn mirrorStep(comptime s: i32) i32 {
    const a = @divFloor(s + 5, 10);
    return (s - 10 * a) - 10 * a;
}

/// A king-ray direction code (1..8: steps +9, +11, −9, −11, +1, +10, −1, −10 from the
/// king; the Black king's map A164 adds 8) of the mirrored direction, in the other map:
/// a Black-king code 9..16 becomes the White-king code of the mirrored step and back.
pub fn mirrorRayCode(v: u8) u8 {
    const mk = [9]u8{ 0, 4, 3, 2, 1, 5, 8, 7, 6 };
    return if (v >= 1 and v <= 8) 8 + mk[v] else if (v >= 9 and v <= 16) mk[v - 8] else v;
}

const k_knight = 0;
const k_bishop = 1;
const k_rook = 2;
const k_queen = 3;

/// The activity routine of one colour, in White's view (see above).
fn Activity(comptime black: bool, comptime f: Forms) type {
    return struct {
        const Self = @This();
        const own: usize = @intFromBool(black);
        const foe: usize = 1 - own;
        /// The knight's target tables by the raw board byte.
        const knight_fwd = if (black) swappedTable(wk_fwd) else wk_fwd;
        const knight_back = if (black) swappedTable(wk_back) else wk_back;

        p: *const Position,
        e: *const EvalState,
        /// DX, the running sum.
        dx: i16 = 0,
        /// The activity table of the piece being evaluated.
        tab: []const u8 = undefined,

        inline fn st(comptime s: i32) i32 {
            return if (black) comptime mirrorStep(s) else s;
        }
        /// The square for a rank test written for White.
        inline fn vsq(sq: i32) i32 {
            return if (black) mirror_sq[@intCast(sq)] else sq;
        }
        inline fn B(c: *const Self, sq: i32) u8 {
            const b = c.p.board[@intCast(sq)];
            if (!black) return b;
            // Most squares a ray reads are empty: the table only for a piece.
            if (b == 0) return 0;
            return swap_code[b];
        }
        inline fn raw(c: *const Self, sq: i32) u8 {
            return c.p.board[@intCast(sq)];
        }
        /// The side's own pawn attacks (White's WA).
        inline fn wa(c: *const Self, sq: i32) i8 {
            return @bitCast(c.p.pawn_attacks[own][@intCast(sq)]);
        }
        /// The enemy's pawn attacks (White's BA).
        inline fn ba(c: *const Self, sq: i32) i8 {
            return @bitCast(c.p.pawn_attacks[foe][@intCast(sq)]);
        }
        inline fn baMinusWa(c: *const Self, sq: i32) i8 {
            return @bitCast(c.p.pawn_attacks[foe][@intCast(sq)] -% c.p.pawn_attacks[own][@intCast(sq)]);
        }
        /// The enemy king's ray map holds `code` (White's view: A164, 9..16) at `sq`.
        inline fn onRay(c: *const Self, sq: i32, comptime code: u8) bool {
            const want = if (black) comptime mirrorRayCode(code) else code;
            return c.p.king_rays[foe][@intCast(sq)] == want;
        }
        inline fn add(c: *Self, sq: i32) void {
            c.dx +%= c.tab[@intCast(sq)];
        }
        /// Adds T[sq] when `count`, a pawn-attack count, is 0, without a branch: the
        /// count is unpredictable from square to square along a ray.
        inline fn addIfZero(c: *Self, sq: i32, count: i8) void {
            c.dx +%= @as(i16, c.tab[@intCast(sq)]) & -@as(i16, @intFromBool(count == 0));
        }
        /// Adds T[sq] when `class` is `always`, or `unattacked` and `free` holds.
        inline fn addWhen(c: *Self, sq: i32, class: Target, free: bool) void {
            const take = class == .always or (class == .unattacked and free);
            c.dx +%= @as(i16, c.tab[@intCast(sq)]) & -@as(i16, @intFromBool(take));
        }
        inline fn plus(c: *Self, v: i16) void {
            c.dx +%= v;
        }
        /// `test [194h + slot[sq]], [mask]`: the pawn on `sq` is passed. It is called only
        /// at a square holding a pawn, whose slot is 8..15.
        inline fn passed(c: *const Self, sq: i32, mask: u8) bool {
            return slot_passed_bit[c.p.square_slot[@intCast(sq)]] & mask != 0;
        }

        /// 17EE / 1F2A: DX >> 2, and once more when the side's non-pawn material < 3500.
        fn result(c: *const Self, material: u16) i16 {
            var ax = c.dx >> 2;
            if (@as(i16, @bitCast(material)) < 0xDAC) ax >>= 1;
            return ax;
        }

        /// 16E4–1801 (White).
        fn run(p: *const Position, e: *const EvalState) i16 {
            if (p.piece_count[own] == 0) return 0; // 16E6
            var c: Self = .{ .p = p, .e = e };
            // 16F4, 1802: slots 6..0; the piece type is taken from the board.
            var slot: usize = 7;
            while (slot > 0) {
                slot -= 1;
                const sq = p.piece_list[16 * own + slot];
                const b = listedPiece(p, e, sq);
                switch (if (black) swap_code[b] else b) {
                    pos.white_knight => c.knight(sq),
                    pos.white_bishop => c.bishop(sq),
                    pos.white_rook => c.rook(sq),
                    pos.white_queen => c.queen(sq),
                    else => {},
                }
            }
            return c.result(p.piece_material[own]);
        }

        /// 16FB
        inline fn knight(c: *Self, square: u8) void {
            const sq: i32 = square;
            if (c.B(sq + st(-10)) == pos.black_pawn) {
                c.plus(-0x60);
                if (c.ba(sq + st(-10)) != 0) c.plus(-0x30);
            }
            c.tab = c.e.activityTable(own, k_knight);
            c.add(sq);
            // 1714 (+8, +12, +19, +21) and 1788 (−21, −19, −12, −8), without branches.
            inline for (.{ 8, 12, 19, 21 }) |off| c.addWhen(sq + st(off), knight_fwd[c.raw(sq + st(off))], c.ba(sq + st(off)) == 0);
            inline for (.{ -21, -19, -12, -8 }) |off| c.addWhen(sq + st(off), knight_back[c.raw(sq + st(off))], c.ba(sq + st(off)) == 0);
        }

        /// 1873 / 1A05: add T of the blocker and of the empty squares beyond; +80h per
        /// enemy rook, queen or king met, and keep going.
        inline fn backXray(c: *Self, start: i32, comptime step: i32) void {
            var di = start;
            while (true) {
                c.add(di);
                di += st(step);
                var b = c.B(di);
                while (b == 0) {
                    c.add(di);
                    di += st(step);
                    b = c.B(di);
                }
                if (b >= pos.black_rook) {
                    c.plus(0x80);
                    continue;
                }
                return;
            }
        }

        /// The −9 (1833, `first`: adds T[sq] first) and −11 (19C4) bishop rays.
        inline fn bishopBack(c: *Self, sq: i32, comptime step: i32, comptime first: bool) void {
            var di = sq;
            if (first) c.add(di);
            di += st(step);
            var b = c.B(di);
            while (b == 0) {
                c.add(di);
                di += st(step);
                b = c.B(di);
            }
            if (b <= pos.border) return;
            if (b > pos.black_knight) {
                c.add(di);
            } else if (b == pos.black_knight) {
                if (c.ba(di) == 0) c.plus(0x40);
                c.backXray(di, step);
            } else { // an enemy pawn
                c.plus(0x30);
                if (c.baMinusWa(di) < 1) {
                    // DEV-019, §4.3 item 1: 16E4 x-rays past the pawn (1857 → 1873, 19E7
                    // → 1A05); 1E30 adds the pawn's entry and stops (1F77 → 1FC2, 2077 →
                    // 20BC). The code does not show which was meant: both colours' x-ray
                    // loops and their "add and stop" blocks begin alike, and each colour's
                    // knight case x-rays. Corrected by the rule of owner decision 30:
                    // Black's takes White's form.
                    if (f.bishop_pawn_stop) c.add(di) else c.backXray(di, step);
                } else c.plus(-0x80);
            }
        }

        /// The +9 (1892) and +11 (192E) bishop rays; `code` is the enemy king's ray code
        /// (White's view: 0Bh, 0Ch).
        inline fn bishopForward(c: *Self, sq: i32, comptime step: i32, comptime code: u8) void {
            var di = sq;
            while (true) {
                di += st(step);
                var b = c.B(di);
                if (b == 0) {
                    c.addIfZero(di, c.ba(di));
                    continue;
                }
                if (b == pos.white_pawn) { // 18C8
                    if (vsq(di) < 0x33) {
                        c.plus(-0x30);
                        if (c.B(di + st(10)) != 0) c.plus(-0x60);
                    } else if (vsq(di) >= 0x51) {
                        c.plus(0x60);
                        c.add(di);
                    } else if (c.B(di + st(10)) == 0) {
                        c.add(di);
                    } else c.plus(-0x48);
                    return;
                }
                if (b == pos.white_queen) {
                    c.add(di);
                    continue;
                }
                if (b < pos.white_queen) { // N, B, R
                    if (c.onRay(di, code)) c.plus(0x60);
                    c.add(di);
                    return;
                }
                if (b == pos.white_king) {
                    c.plus(-0x48);
                    return;
                }
                if (b == pos.border) return;
                if (b == pos.black_knight) { // 18DC: x-ray past the knight
                    if (c.ba(di) == 0) c.plus(0x40);
                    while (true) {
                        c.add(di);
                        di += st(step);
                        b = c.B(di);
                        while (b == 0) {
                            c.add(di);
                            di += st(step);
                            b = c.B(di);
                        }
                        if (b <= pos.border) return;
                        if (b >= pos.black_rook) {
                            c.plus(0x80);
                            continue;
                        }
                        break;
                    }
                    if (b >= pos.black_knight) {
                        c.add(di);
                        return;
                    }
                    // an enemy pawn: the pawn rule below
                }
                if (b == pos.black_pawn) { // 1902
                    if (c.baMinusWa(di) < 1) {
                        c.plus(0x60);
                        if (c.onRay(di, code)) c.plus(0x60);
                        c.add(di);
                    } else c.plus(-0x48);
                    return;
                }
                c.add(di); // enemy B, R, Q, K
                return;
            }
        }

        /// 182E
        inline fn bishop(c: *Self, square: u8) void {
            const sq: i32 = square;
            c.tab = c.e.activityTable(own, k_bishop);
            c.bishopBack(sq, -9, true);
            c.bishopForward(sq, 9, 0x0B);
            c.bishopForward(sq, 11, 0x0C);
            c.bishopBack(sq, -11, false);
        }

        /// An enemy knight or bishop met by a rook (1A50 and the like): the conditional
        /// x-ray of the ±1 and −10 rays. `di` is the minor piece's square.
        inline fn rookAtMinor(c: *Self, start: i32, comptime step: i32) void {
            var di = start;
            if (!(c.wa(di) != 0 or c.wa(di + st(-10)) != 0)) {
                if (c.ba(di) == 1) {
                    c.add(di);
                    return;
                }
                if (c.ba(di) > 1) return;
            }
            c.plus(0x30); // 1A6D / 1AE3 / 1C79
            var b: u8 = undefined;
            while (true) {
                c.add(di);
                di += st(step);
                b = c.B(di);
                if (b != 0) break;
            }
            if (b < pos.black_knight) return;
            if (b >= pos.black_queen or c.wa(di) != 0 or c.ba(di) == 0) c.plus(0x118);
        }

        /// The +1 (1A25: adds T[sq] first when BA[sq] = 0) and −1 (1AA5) rook rays.
        inline fn rookSide(c: *Self, sq: i32, comptime step: i32) void {
            var di = sq;
            if (step > 0 and c.ba(di) == 0) c.add(di);
            var b: u8 = undefined;
            while (true) {
                di += st(step);
                b = c.B(di);
                if (b == 0 or b == pos.white_queen) {
                    c.addIfZero(di, c.ba(di));
                    continue;
                }
                if (b == pos.white_rook) {
                    c.plus(0x10);
                    c.addIfZero(di, c.ba(di));
                    continue;
                }
                break;
            }
            if (b < pos.black_pawn) return;
            if (b == pos.black_pawn) {
                if (c.ba(di) != 0) return;
                c.plus(0x30);
                c.add(di);
                return;
            }
            if (b > pos.black_bishop) {
                c.add(di);
                return;
            }
            c.rookAtMinor(di, step);
        }

        /// 1A1A
        inline fn rook(c: *Self, square: u8) void {
            const sq: i32 = square;
            c.tab = c.e.activityTable(own, k_rook);
            c.rookSide(sq, 1);
            c.rookSide(sq, -1);
            c.rookUp(sq);
            c.rookDown(sq);
        }

        /// The +10 ray (1B12), forward.
        inline fn rookUp(c: *Self, sq: i32) void {
            var di = sq;
            while (true) {
                di += st(10);
                var b = c.B(di);
                if (b == 0) {
                    c.add(di);
                    continue;
                }
                if (b < pos.black_pawn) {
                    if (b >= pos.white_king) return; // own king, border
                    if (b >= pos.white_rook) { // own R, Q
                        c.add(di);
                        continue;
                    }
                    if (b >= pos.white_knight) { // own N, B
                        c.add(di);
                        return;
                    }
                    // own pawn (1B8C)
                    if (vsq(di) >= 0x51) {
                        c.plus(0x168);
                        if (c.B(di + st(10)) == 0) c.plus(0x78);
                        // DEV-019, §4.3 item 3: 1E30 adds the pawn square's entry here too
                        // (2394–23A1 jump to 2369, "add T[s]", where every other own-pawn
                        // exit of the same routine jumps to 236D or 2405, after it; 16E4's
                        // all go to 1BDF). The evidence is the rest of 1E30 itself and
                        // 16E4: corrected to White's form, no entry.
                        if (f.rook_pawn_table) c.add(di);
                        return;
                    }
                    if (c.passed(di, c.e.passed_pawns[own])) {
                        c.plus(0x78);
                        if (vsq(di) >= 0x3D) {
                            c.plus(0xA0);
                            if (c.B(di + st(10)) == 0) c.plus(0x78);
                        }
                    }
                    return;
                }
                if (b == pos.black_pawn) {
                    if (c.ba(di) == 0) {
                        c.plus(0x60);
                        c.add(di);
                    } else c.plus(-0x30);
                    return;
                }
                if (b > pos.black_bishop) {
                    c.add(di);
                    return;
                }
                // enemy N or B
                if (!(c.wa(di) != 0 or c.wa(di + st(-10)) != 0)) {
                    if (c.ba(di) == 1) {
                        c.add(di);
                        return;
                    }
                    if (c.ba(di) > 1) return;
                }
                c.plus(0x30); // 1B51
                while (true) {
                    c.add(di);
                    di += st(10);
                    b = c.B(di);
                    if (b != 0) break;
                }
                if (b < pos.black_knight) return;
                // DEV-019, §4.3 item 4: at an enemy rook attacked by an own pawn, 16E4 adds
                // 118h (1B6D → 1B79), 1E30 walks on behind the rook (23DD → 23E5, the rook
                // test, not 23E9, the 118h). 1E30's own ±1 rays give 118h in that case
                // (21BB, 2237), as 16E4 does: corrected to White's form.
                if (b >= pos.black_queen or (!f.rook_behind_attacked and c.wa(di) != 0)) {
                    c.plus(0x118);
                    return;
                }
                if (c.ba(di) != 0 and c.wa(di) == 0) return;
                if (b == pos.black_rook) { // 1BA0: walk on behind the rook
                    while (true) {
                        di += st(10);
                        if (c.B(di) != 0) break;
                    }
                    const d = c.B(di);
                    if (d != pos.black_rook and d != pos.black_queen) c.plus(0xC8);
                    return;
                }
                c.plus(0x118);
                return;
            }
        }

        /// The −10 ray (1C0E), backward.
        inline fn rookDown(c: *Self, sq: i32) void {
            var di = sq;
            while (true) {
                di += st(-10);
                const b = c.B(di);
                if (b == 0) {
                    c.add(di);
                    continue;
                }
                if (b == pos.border) return;
                if (b < pos.border) {
                    if (b == pos.white_rook or b == pos.white_queen) {
                        const fl = file_of[@intCast(di)];
                        if (c.p.pawns_per_file[own][fl] == 0) {
                            c.plus(0x20);
                            if (c.p.pawns_per_file[foe][fl] == 0) c.plus(0x40);
                        }
                        c.add(di);
                        continue;
                    }
                    return;
                }
                if (b == pos.black_pawn) { // 1C28
                    if (c.passed(di, c.e.passed_pawns[foe])) {
                        c.plus(0x60);
                        if (c.ba(di) != 0) return;
                        c.plus(0x40);
                        c.plus(if (vsq(di) > 0x3A) 0x50 else 0xA0);
                        c.add(di);
                        return;
                    }
                    if (c.ba(di) != 0) return;
                    c.plus(0x50);
                    c.add(di);
                    return;
                }
                if (b > pos.black_bishop) {
                    c.add(di);
                    return;
                }
                c.rookAtMinor(di, -10);
                return;
            }
        }

        /// The +1 (1CA9: adds T[sq] first) and −1 (1CEA) queen rays, each ending with a
        /// test of the square where the line meets the enemy king's ray `code` (0Fh, 0Dh).
        inline fn queenSide(c: *Self, sq: i32, comptime step: i32, comptime code: u8) void {
            var di = sq;
            if (step > 0) c.add(di);
            di += st(step);
            while (c.B(di) == 0) {
                c.add(di);
                di += st(step);
            }
            if (!c.onRay(di, code)) return;
            const b = c.B(di);
            if (b == pos.white_pawn) {
                if (c.B(di + st(10)) == 0) c.plus(0x60);
                return;
            }
            // DEV-019, §4.3 item 6: 1E30 treats the border as an enemy piece here (2424),
            // 16E4 as its own (1CC1). Border squares carry no ray code, so neither runs;
            // corrected by the rule to White's form.
            if (b < pos.black_pawn and !(f.queen_side_border and b == pos.border)) {
                c.plus(0x60);
                return;
            }
            if (b != pos.black_pawn) c.plus(0x60);
            if (c.wa(di) > 0 or c.ba(di) <= 0) c.plus(0x60); // 1CC8
        }

        /// The +9 (1D8C) and +11 (1DE8) queen rays.
        inline fn queenDiagForward(c: *Self, sq: i32, comptime step: i32, comptime code: u8) void {
            var di = sq;
            var b: u8 = undefined;
            while (true) {
                di += st(step);
                b = c.B(di);
                if (b == 0) {
                    c.addIfZero(di, c.ba(di));
                    continue;
                }
                if (b == pos.white_bishop) {
                    c.add(di);
                    continue;
                }
                break;
            }
            switch (diag_class[b]) {
                .nothing => {},
                .pawn => c.addIfZero(di, c.ba(di)),
                .bonus => c.diagBonus(di, code),
            }
        }

        const Diag = enum(u8) { nothing, pawn, bonus };
        /// What a queen's forward diagonal does at the piece that ends it (1D97–1DA9):
        /// nothing at an own pawn, queen or king, an enemy bishop or the border; the
        /// enemy pawn's entry if no enemy pawn attacks it; else the ray bonuses and the
        /// entry (own N, R; enemy N, R, Q, K). A table in place of the chain of tests.
        ///
        /// DEV-019, §4.3 item 5: 16E4 gives an enemy queen or king the ray bonuses and its
        /// entry (1D9B: every enemy piece but the bishop, 1D97); 1E30 gives them nothing
        /// (2513–2521 and 24F4–24FC: the knight and rook of either colour only). 1E30's form is the
        /// evidence: 16E4 itself excludes the enemy bishop here and its own queen and king,
        /// and on the queen's +10 ray (1D3F–1D4D) it rewards the pieces of either colour
        /// that do not move along that line (N, B), and no queen or king. Corrected to
        /// Black's form, in both routines.
        const diag_class: [256]Diag = blk: {
            var t: [256]Diag = @splat(.bonus);
            for ([_]u8{ pos.white_pawn, pos.black_bishop, pos.white_queen, pos.white_king, pos.border }) |b| t[b] = .nothing;
            t[pos.black_pawn] = .pawn;
            if (f.queen_diag_queen_king) {
                t[pos.black_queen] = .nothing;
                t[pos.black_king] = .nothing;
            }
            break :blk t;
        };

        inline fn diagBonus(c: *Self, di: i32, comptime code: u8) void {
            if (c.onRay(di, code)) {
                c.plus(0x60);
                if (c.ba(di) <= 0) c.plus(0x60);
            }
            c.add(di);
        }

        /// Only the empty squares of a ray.
        inline fn emptyRay(c: *Self, sq: i32, comptime step: i32) void {
            var di = sq + st(step);
            while (c.B(di) == 0) {
                c.add(di);
                di += st(step);
            }
        }

        /// 1CA4
        inline fn queen(c: *Self, square: u8) void {
            const sq: i32 = square;
            c.tab = c.e.activityTable(own, k_queen);
            c.queenSide(sq, 1, 0x0F);
            c.queenSide(sq, -1, 0x0D);
            // +10 (1D34)
            var di = sq;
            var b: u8 = undefined;
            while (true) {
                di += st(10);
                b = c.B(di);
                if (b == 0) {
                    c.addIfZero(di, c.ba(di));
                    continue;
                }
                if (b == pos.white_rook) {
                    c.add(di);
                    continue;
                }
                break;
            }
            switch (b) {
                pos.white_knight, pos.white_bishop, pos.black_knight, pos.black_bishop => { // 1D4F
                    if (c.onRay(di, 0x10)) {
                        c.plus(0x60);
                        if (c.ba(di) <= 0) c.plus(0x60);
                    }
                    c.add(di);
                },
                pos.black_pawn => c.addIfZero(di, c.ba(di)),
                else => {},
            }
            c.emptyRay(sq, -10); // 1D6E
            c.queenDiagForward(sq, 9, 0x0B);
            c.emptyRay(sq, -9); // 1DCA
            c.queenDiagForward(sq, 11, 0x0C);
            c.emptyRay(sq, -11); // 1E26
        }
    };
}

/// The activity routine of one colour with the given forms: White's (16E4) with none
/// set; the original Black routine (1E30) with `black_forms`, Black's; with `formsOf`,
/// either colour under DEV-019. For tests and for the variants below.
pub fn pieceActivityForms(comptime black: bool, comptime f: Forms, p: *const Position, e: *const EvalState) i16 {
    return Activity(black, f).run(p, e);
}

/// Port of piece_activity_white (1E9D:16E4–1801).
pub fn pieceActivityWhite(p: *const Position, e: *const EvalState) i16 {
    return pieceActivityWhiteFixes(pos.Fixes.original, p, e);
}

/// `pieceActivityWhite` under the class C fixes `fixes` (DEV-019: the queen's forward
/// diagonals, §4.3 item 5).
pub fn pieceActivityWhiteFixes(comptime fixes: pos.Fixes, p: *const Position, e: *const EvalState) i16 {
    return Activity(false, formsOf(fixes)).run(p, e);
}

/// Port of piece_activity_black (1E9D:1E30–1F3D). Not the mirror of the White routine:
/// see the specification §4.3 and `Forms`.
pub fn pieceActivityBlack(p: *const Position, e: *const EvalState) i16 {
    return pieceActivityBlackFixes(pos.Fixes.original, p, e);
}

/// `pieceActivityBlack` under the class C fixes `fixes`. With DEV-019 corrected it is
/// the colour mirror of `pieceActivityWhiteFixes(fixes)`; otherwise the original,
/// written out below as 1E30 has it.
pub fn pieceActivityBlackFixes(comptime fixes: pos.Fixes, p: *const Position, e: *const EvalState) i16 {
    if (fixes.dev019_activity_mirror) return Activity(true, formsOf(fixes)).run(p, e);
    return pieceActivityBlackOriginal(p, e);
}

// =============================================================================
// Black: 1E9D:1E30
// =============================================================================

/// Port of piece_activity_black (1E9D:1E30–1F3D) as the original has it: not the mirror of
/// the White routine (§4.3; `Forms`).
fn pieceActivityBlackOriginal(p: *const Position, e: *const EvalState) i16 {
    if (p.piece_count[1] == 0) return 0; // 1E32
    var c: Ctx = .{ .p = p, .e = e };
    var slot: usize = 7;
    while (slot > 0) {
        slot -= 1;
        const sq = p.piece_list[16 + slot];
        switch (listedPiece(p, e, sq)) {
            pos.black_knight => bKnight(&c, sq),
            pos.black_bishop => bBishop(&c, sq),
            pos.black_rook => bRook(&c, sq),
            pos.black_queen => bQueen(&c, sq),
            else => {},
        }
    }
    return c.result(p.piece_material[1]);
}

/// 1E47
inline fn bKnight(c: *Ctx, square: u8) void {
    const sq: i32 = square;
    if (c.B(sq + 10) == pos.white_pawn) {
        c.plus(-0x60);
        if (c.wa(sq + 10) != 0) c.plus(-0x30);
    }
    c.tab = c.e.activityTable(1, knight);
    c.add(sq);
    for ([_]i32{ 8, 12, 19, 21 }) |off| { // 1E60
        const t = sq + off;
        const b = c.B(t);
        if (b >= pos.border) continue;
        if (b >= pos.white_knight or c.wa(t) == 0) c.add(t);
    }
    for ([_]i32{ -21, -19, -12, -8 }) |off| { // 1EBC
        const t = sq + off;
        const b = c.B(t);
        if (b == pos.border or b == pos.black_pawn) continue;
        if (b >= pos.white_knight or c.wa(t) == 0) c.add(t);
    }
}

/// The +9 (1F85, adds T[sq] first) and +11 (2084) bishop rays: backward for Black.
inline fn bBishopBack(c: *Ctx, sq: i32, step: i32, first: bool) void {
    var di = sq;
    if (first) c.add(di);
    di += step;
    var b = c.B(di);
    while (b == 0) {
        c.add(di);
        di += step;
        b = c.B(di);
    }
    if (b == pos.white_pawn) { // 1F6A / 206A: no x-ray past the pawn (§4.3 item 1)
        c.plus(0x30);
        if (c.waMinusBa(di) < 1) c.add(di) else c.plus(-0x80);
        return;
    }
    if (b >= pos.border) return;
    if (b > pos.white_knight) {
        c.add(di);
        return;
    }
    // White knight: 1F9C / 2097
    if (c.wa(di) == 0) c.plus(0x40);
    while (true) {
        c.add(di);
        di += step;
        b = c.B(di);
        while (b == 0) {
            c.add(di);
            di += step;
            b = c.B(di);
        }
        if (b >= pos.border or b < pos.white_rook) return;
        c.plus(0x80);
    }
}

/// White king ray test at the end of a forward ray (`_f_king` of the model).
inline fn bAtKingRay(c: *Ctx, di: i32, code: u8) void {
    if (c.wmap(di) == code) c.plus(0x60);
    c.add(di);
}

/// The −9 (1FD4) and −11 (20CE) bishop rays; `code` is the White king's ray code (1, 2).
inline fn bBishopForward(c: *Ctx, sq: i32, step: i32, code: u8) void {
    var di = sq;
    var b: u8 = undefined;
    while (true) {
        di -= step;
        b = c.B(di);
        if (b == 0) {
            c.addIfZero(di, c.wa(di));
            continue;
        }
        if (b == pos.black_queen) {
            c.add(di);
            continue;
        }
        break;
    }
    while (true) {
        if (b == pos.border) return;
        if (b >= pos.white_bishop and b <= pos.white_king) {
            c.add(di);
            return;
        }
        if (b > pos.black_queen) {
            c.plus(-0x48);
            return;
        }
        if (b >= pos.black_knight) { // Black N, B, R
            bAtKingRay(c, di, code);
            return;
        }
        if (b == pos.black_pawn) { // own pawn 2006 / 211C
            if (di > 0x44) {
                c.plus(-0x30);
                if (c.B(di - 10) != 0) c.plus(-0x60);
            } else if (di <= 0x26) {
                c.plus(0x60);
                c.add(di);
            } else if (c.B(di - 10) == 0) {
                c.add(di);
            } else c.plus(-0x48);
            return;
        }
        if (b == pos.white_knight) { // 2042 / 213E: x-ray past the knight
            if (c.wa(di) == 0) c.plus(0x40);
            while (true) {
                c.add(di);
                di -= step;
                b = c.B(di);
                while (b == 0) {
                    c.add(di);
                    di -= step;
                    b = c.B(di);
                }
                if (b >= pos.border) return;
                if (b >= pos.white_rook) {
                    c.plus(0x80);
                    continue;
                }
                break;
            }
            if (b >= pos.white_knight) {
                c.add(di);
                return;
            }
            continue; // a White pawn: 2028 / 20EE
        }
        // White pawn: 2028 / 20EE
        if (c.waMinusBa(di) >= 1) {
            c.plus(-0x48);
            return;
        }
        c.plus(0x60);
        bAtKingRay(c, di, code);
        return;
    }
}

/// 1F80
inline fn bBishop(c: *Ctx, square: u8) void {
    const sq: i32 = square;
    c.tab = c.e.activityTable(1, bishop);
    bBishopBack(c, sq, 9, true);
    bBishopForward(c, sq, 9, 1);
    bBishopBack(c, sq, 11, false);
    bBishopForward(c, sq, 11, 2);
}

/// The +1 (2171: adds T[sq] first when WA[sq] = 0) and −1 (21F7) rook rays.
inline fn bRookSide(c: *Ctx, sq: i32, step: i32) void {
    var di = sq;
    if (step > 0 and c.wa(di) == 0) c.add(di);
    var b: u8 = undefined;
    while (true) {
        di += step;
        b = c.B(di);
        if (b == 0 or b == pos.black_queen) {
            c.addIfZero(di, c.wa(di));
            continue;
        }
        if (b == pos.black_rook) {
            c.plus(0x10);
            c.addIfZero(di, c.wa(di));
            continue;
        }
        break;
    }
    if (b >= pos.border) return;
    if (b <= pos.white_pawn) {
        if (c.wa(di) != 0) return;
        c.plus(0x30);
        c.add(di);
        return;
    }
    if (b > pos.white_bishop) {
        c.add(di);
        return;
    }
    bRookAtMinor(c, di, step);
}

/// A White knight or bishop met by a Black rook on the ±1 rays (21BB / 2237).
inline fn bRookAtMinor(c: *Ctx, start: i32, step: i32) void {
    var di = start;
    if (!(c.ba(di) != 0 or c.ba(di + 10) != 0)) {
        if (c.wa(di) == 1) {
            c.add(di);
            return;
        }
        if (c.wa(di) > 1) return;
    }
    c.plus(0x30);
    var b: u8 = undefined;
    while (true) {
        c.add(di);
        di += step;
        b = c.B(di);
        if (b != 0) break;
    }
    if (b > pos.white_king or b < pos.white_knight) return;
    if (b >= pos.white_queen or c.ba(di) != 0 or c.wa(di) == 0) c.plus(0x118);
}

/// 2166
inline fn bRook(c: *Ctx, square: u8) void {
    const sq: i32 = square;
    c.tab = c.e.activityTable(1, rook);
    bRookSide(c, sq, 1);
    bRookSide(c, sq, -1);
    bRookUp(c, sq);
    bRookDown(c, sq);
}

/// The +10 ray (2296): backward for Black.
inline fn bRookUp(c: *Ctx, sq: i32) void {
    var di = sq;
    while (true) {
        di += 10;
        const b = c.B(di);
        if (b == 0) {
            c.add(di);
            continue;
        }
        if (b == pos.border) return;
        if (b > pos.border) {
            if (b == pos.black_rook or b == pos.black_queen) { // 226C
                const f = file_of[@intCast(di)];
                if (c.p.pawns_per_file[1][f] == 0) {
                    c.plus(0x20);
                    if (c.p.pawns_per_file[0][f] == 0) c.plus(0x40);
                }
                c.add(di);
                continue;
            }
            return;
        }
        if (b > pos.white_pawn) { // 22E2
            if (b > pos.white_bishop) {
                c.add(di);
                return;
            }
            bRookAtMinor(c, di, 10);
            return;
        }
        // White pawn 22A9
        if (c.passed(di, c.e.passed_pawns[0])) {
            c.plus(0x60);
            if (c.wa(di) != 0) return;
            c.plus(0x40);
            c.plus(if (di < 0x3D) 0x50 else 0xA0);
            c.add(di);
            return;
        }
        if (c.wa(di) != 0) return;
        c.plus(0x50);
        c.add(di);
        return;
    }
}

/// The −10 ray (2374): forward for Black.
inline fn bRookDown(c: *Ctx, sq: i32) void {
    var di = sq;
    while (true) {
        di -= 10;
        var b = c.B(di);
        if (b == 0) {
            c.add(di);
            continue;
        }
        if (b == pos.border or b == pos.black_king) return;
        if (b >= pos.black_rook) {
            c.add(di);
            continue;
        }
        if (b > pos.black_pawn) {
            c.add(di);
            return;
        }
        if (b == pos.black_pawn) { // own pawn 238F
            if (di > 0x26) {
                if (!c.passed(di, c.e.passed_pawns[1])) return; // 232C
                c.plus(0x78);
                if (di > 0x3A) return;
                c.plus(0xA0);
                if (c.B(di - 10) != 0) return;
                c.plus(0x78);
                return;
            }
            c.plus(0x168); // 2394: and T[s] (§4.3 item 3)
            if (c.B(di - 10) == 0) c.plus(0x78);
            c.add(di);
            return;
        }
        if (b <= pos.white_pawn) { // 2356: White pawn
            if (c.wa(di) == 0) {
                c.plus(0x60);
                c.add(di);
            } else c.plus(-0x30);
            return;
        }
        if (b > pos.white_bishop) { // 23A4
            c.add(di);
            return;
        }
        // White N or B
        if (!(c.ba(di) != 0 or c.ba(di + 10) != 0)) {
            if (c.wa(di) == 1) {
                c.add(di);
                return;
            }
            if (c.wa(di) > 1) return;
        }
        c.plus(0x30); // 23BD
        while (true) {
            c.add(di);
            di -= 10;
            b = c.B(di);
            if (b != 0) break;
        }
        if (b >= pos.border or b < pos.white_knight) return;
        if (b < pos.white_queen and c.ba(di) == 0 and c.wa(di) != 0) return;
        if (b == pos.white_rook) { // 23F0 (§4.3 item 4)
            while (true) {
                di -= 10;
                if (c.B(di) != 0) break;
            }
            const d = c.B(di);
            if (d != pos.white_rook and d != pos.white_queen) c.plus(0xC8);
            return;
        }
        c.plus(0x118);
        return;
    }
}

/// The +1 and −1 queen rays (2408), with the White king's ray `code` (7, 5).
inline fn bQueenSide(c: *Ctx, sq: i32, step: i32, code: u8) void {
    var di = sq;
    if (step > 0) c.add(di);
    di += step;
    while (c.B(di) == 0) {
        c.add(di);
        di += step;
    }
    if (c.wmap(di) != code) return;
    const b = c.B(di);
    if (b > pos.black_pawn) {
        c.plus(0x60);
        return;
    }
    if (b == pos.black_pawn) {
        if (c.B(di - 10) == 0) c.plus(0x60);
        return;
    }
    if (b != pos.white_pawn) c.plus(0x60);
    if (c.ba(di) > 0 or c.wa(di) <= 0) c.plus(0x60); // 242C
}

/// The −9 (2508) and −11 (256A) queen rays: forward for Black.
inline fn bQueenDiagForward(c: *Ctx, sq: i32, step: i32, code: u8) void {
    var di = sq;
    var b: u8 = undefined;
    while (true) {
        di -= step;
        b = c.B(di);
        if (b == 0) {
            c.addIfZero(di, c.wa(di));
            continue;
        }
        if (b == pos.black_bishop) {
            c.add(di);
            continue;
        }
        break;
    }
    switch (b) {
        pos.white_pawn => c.addIfZero(di, c.wa(di)),
        pos.white_knight, pos.white_rook, pos.black_knight, pos.black_rook => { // 2523 / 2585
            if (c.wmap(di) == code) {
                c.plus(0x60);
                if (c.wa(di) <= 0) c.plus(0x60);
            }
            c.add(di);
        },
        else => {}, // §4.3 item 5: nothing at a White queen or king
    }
}

/// Only the empty squares of a ray.
inline fn emptyRay(c: *Ctx, sq: i32, step: i32) void {
    var di = sq + step;
    while (c.B(di) == 0) {
        c.add(di);
        di += step;
    }
}

/// 2408
inline fn bQueen(c: *Ctx, square: u8) void {
    const sq: i32 = square;
    c.tab = c.e.activityTable(1, queen);
    bQueenSide(c, sq, 1, 7);
    bQueenSide(c, sq, -1, 5);
    emptyRay(c, sq, 10); // 248A
    // −10 (24A8)
    var di = sq;
    var b: u8 = undefined;
    while (true) {
        di -= 10;
        b = c.B(di);
        if (b == 0) {
            c.addIfZero(di, c.wa(di));
            continue;
        }
        if (b == pos.black_rook) {
            c.add(di);
            continue;
        }
        break;
    }
    switch (b) {
        pos.white_pawn => c.addIfZero(di, c.wa(di)),
        pos.white_knight, pos.white_bishop, pos.black_knight, pos.black_bishop => { // 24C1
            if (c.wmap(di) == 6) {
                c.plus(0x60);
                if (c.wa(di) <= 0) c.plus(0x60);
            }
            c.add(di);
        },
        else => {},
    }
    emptyRay(c, sq, 9); // 24E0
    bQueenDiagForward(c, sq, 9, 1);
    emptyRay(c, sq, 11); // 2542
    bQueenDiagForward(c, sq, 11, 2);
}

// =============================================================================
// mobility_term: 0000:2E72
// =============================================================================

/// Port of mobility_term (0000:2E72–2EC6): White's activity minus Black's, scaled by the
/// Mobility weight in a custom style, plus a sixteenth of itself.
pub fn mobilityTerm(p: *const Position, e: *const EvalState) i16 {
    return mobilityTermFixes(pos.Fixes.original, p, e);
}

/// `mobilityTerm` under the class C fixes `fixes` (DEV-019, in both activity routines).
pub fn mobilityTermFixes(comptime fixes: pos.Fixes, p: *const Position, e: *const EvalState) i16 {
    var x = pieceActivityWhiteFixes(fixes, p, e) -% pieceActivityBlackFixes(fixes, p, e); // 2E7A
    if (e.style_normal == 0 and e.mobility_weight != 100) {
        // 2E9D: the run-time long multiply (low 32 bits) and signed divide (toward zero).
        const product: i32 = @as(i32, x) *% @as(i32, @bitCast(e.mobility_weight));
        x = @truncate(@divTrunc(product, 100));
    }
    return x +% (x >> 4); // 2EBC
}

test {
    _ = std;
}
