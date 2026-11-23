//! TEST ONLY: src/activity.zig as it was before the speed pass of 2026-11-18, kept as the
//! reference that src/evalpieces_test.zig compares the faster routines with on states
//! beyond the recorded ones. Not part of the engine; do not change it.
//!
//! Piece activity: piece_activity_white (1E9D:16E4), piece_activity_black (1E9D:1E30)
//! and mobility_term (0000:2E72), which combines them.
//!
//! Specification: docs/arch/53-evaluation-pieces-kings.md §4.2–4.4, whose executable
//! form is tools/research/evalpieces/activity.py (proved against the running original on
//! about 798,000 calls of each routine). Tests: src/activity_test.zig, which replays
//! calls recorded from the original (tests/golden/evalpieces/).
//!
//! The two activity routines are hand-written assembly and are not mirror images of
//! each other (six differences, §4.3, DEV-019, undecided). Each colour is therefore
//! written out on its own, as the original has it.
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

/// The board byte at a piece-list entry. A captured piece's entry is its square + 63h,
/// beyond the board; the original reads DG:9EF6 + entry all the same (DEV-018). The
/// byte has been 0 in every recorded read, so the piece is skipped. Were it ever a
/// piece code, the original would evaluate a phantom piece by reading unrelated memory
/// around it; the port cannot reproduce that, and its board index then traps in safe
/// builds (a class A defect, not behaviour to keep).
inline fn listedPiece(p: *const Position, e: *const EvalState, entry: u8) u8 {
    return if (entry < 120) p.board[entry] else e.past_board[entry - 120];
}

// =============================================================================
// White: 1E9D:16E4
// =============================================================================

/// Port of piece_activity_white (1E9D:16E4–1801).
pub fn pieceActivityWhite(p: *const Position, e: *const EvalState) i16 {
    if (p.piece_count[0] == 0) return 0; // 16E6
    var c: Ctx = .{ .p = p, .e = e };
    // 16F4, 1802: slots 6..0; the piece type is taken from the board.
    var slot: usize = 7;
    while (slot > 0) {
        slot -= 1;
        const sq = p.piece_list[slot];
        switch (listedPiece(p, e, sq)) {
            pos.white_knight => wKnight(&c, sq),
            pos.white_bishop => wBishop(&c, sq),
            pos.white_rook => wRook(&c, sq),
            pos.white_queen => wQueen(&c, sq),
            else => {},
        }
    }
    return c.result(p.piece_material[0]);
}

/// 16FB
fn wKnight(c: *Ctx, square: u8) void {
    const sq: i32 = square;
    if (c.B(sq - 10) == pos.black_pawn) {
        c.plus(-0x60);
        if (c.ba(sq - 10) != 0) c.plus(-0x30);
    }
    c.tab = c.e.activityTable(0, knight);
    c.add(sq);
    for ([_]i32{ 8, 12, 19, 21 }) |off| { // 1714
        const t = sq + off;
        const b = c.B(t);
        if (b == pos.border or b == pos.white_pawn) continue;
        if (b == pos.black_pawn or b == 0) {
            if (c.ba(t) == 0) c.add(t);
        } else c.add(t);
    }
    for ([_]i32{ -21, -19, -12, -8 }) |off| { // 1788
        const t = sq + off;
        const b = c.B(t);
        if (b == pos.black_pawn or b == 0) {
            if (c.ba(t) == 0) c.add(t);
        } else if (b > pos.black_pawn) c.add(t);
    }
}

/// 1873 / 1A05: add T of the blocker and of the empty squares beyond; +80h per Black
/// rook, queen or king met, and keep going.
fn wBackXray(c: *Ctx, start: i32, step: i32) void {
    var di = start;
    while (true) {
        c.add(di);
        di += step;
        var b = c.B(di);
        while (b == 0) {
            c.add(di);
            di += step;
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
fn wBishopBack(c: *Ctx, sq: i32, step: i32, first: bool) void {
    var di = sq;
    if (first) c.add(di);
    di += step;
    var b = c.B(di);
    while (b == 0) {
        c.add(di);
        di += step;
        b = c.B(di);
    }
    if (b <= pos.border) return;
    if (b > pos.black_knight) {
        c.add(di);
    } else if (b == pos.black_knight) {
        if (c.ba(di) == 0) c.plus(0x40);
        wBackXray(c, di, step);
    } else { // Black pawn
        c.plus(0x30);
        if (c.baMinusWa(di) < 1) wBackXray(c, di, step) else c.plus(-0x80);
    }
}

/// The +9 (1892) and +11 (192E) bishop rays; `code` is the Black king's ray code (0Bh, 0Ch).
fn wBishopForward(c: *Ctx, sq: i32, step: i32, code: u8) void {
    var di = sq;
    while (true) {
        di += step;
        var b = c.B(di);
        if (b == 0) {
            if (c.ba(di) == 0) c.add(di);
            continue;
        }
        if (b == pos.white_pawn) { // 18C8
            if (di < 0x33) {
                c.plus(-0x30);
                if (c.B(di + 10) != 0) c.plus(-0x60);
            } else if (di >= 0x51) {
                c.plus(0x60);
                c.add(di);
            } else if (c.B(di + 10) == 0) {
                c.add(di);
            } else c.plus(-0x48);
            return;
        }
        if (b == pos.white_queen) {
            c.add(di);
            continue;
        }
        if (b < pos.white_queen) { // N, B, R
            if (c.bmap(di) == code) c.plus(0x60);
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
                di += step;
                b = c.B(di);
                while (b == 0) {
                    c.add(di);
                    di += step;
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
            // a Black pawn: the pawn rule below
        }
        if (b == pos.black_pawn) { // 1902
            if (c.baMinusWa(di) < 1) {
                c.plus(0x60);
                if (c.bmap(di) == code) c.plus(0x60);
                c.add(di);
            } else c.plus(-0x48);
            return;
        }
        c.add(di); // Black B, R, Q, K
        return;
    }
}

/// 182E
fn wBishop(c: *Ctx, square: u8) void {
    const sq: i32 = square;
    c.tab = c.e.activityTable(0, bishop);
    wBishopBack(c, sq, -9, true);
    wBishopForward(c, sq, 9, 0x0B);
    wBishopForward(c, sq, 11, 0x0C);
    wBishopBack(c, sq, -11, false);
}

/// A Black knight or bishop met by a White rook (1A50 and the like): the conditional
/// x-ray of the ±1 and −10 rays. `di` is the minor piece's square.
fn wRookAtMinor(c: *Ctx, start: i32, step: i32) void {
    var di = start;
    if (!(c.wa(di) != 0 or c.wa(di - 10) != 0)) {
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
        di += step;
        b = c.B(di);
        if (b != 0) break;
    }
    if (b < pos.black_knight) return;
    if (b >= pos.black_queen or c.wa(di) != 0 or c.ba(di) == 0) c.plus(0x118);
}

/// The +1 (1A25: adds T[sq] first when BA[sq] = 0) and −1 (1AA5) rook rays.
fn wRookSide(c: *Ctx, sq: i32, step: i32) void {
    var di = sq;
    if (step > 0 and c.ba(di) == 0) c.add(di);
    var b: u8 = undefined;
    while (true) {
        di += step;
        b = c.B(di);
        if (b == 0 or b == pos.white_queen) {
            if (c.ba(di) == 0) c.add(di);
            continue;
        }
        if (b == pos.white_rook) {
            c.plus(0x10);
            if (c.ba(di) == 0) c.add(di);
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
    wRookAtMinor(c, di, step);
}

/// 1A1A
fn wRook(c: *Ctx, square: u8) void {
    const sq: i32 = square;
    c.tab = c.e.activityTable(0, rook);
    wRookSide(c, sq, 1);
    wRookSide(c, sq, -1);
    wRookUp(c, sq);
    wRookDown(c, sq);
}

/// The +10 ray (1B12).
fn wRookUp(c: *Ctx, sq: i32) void {
    var di = sq;
    while (true) {
        di += 10;
        var b = c.B(di);
        if (b == 0) {
            c.add(di);
            continue;
        }
        if (b < pos.black_pawn) {
            if (b >= pos.white_king) return; // White king, border
            if (b >= pos.white_rook) { // White R, Q
                c.add(di);
                continue;
            }
            if (b >= pos.white_knight) { // White N, B
                c.add(di);
                return;
            }
            // own pawn (1B8C)
            if (di >= 0x51) {
                c.plus(0x168);
                if (c.B(di + 10) == 0) c.plus(0x78);
                return;
            }
            if (c.passed(di, c.e.passed_pawns[0])) {
                c.plus(0x78);
                if (di >= 0x3D) {
                    c.plus(0xA0);
                    if (c.B(di + 10) == 0) c.plus(0x78);
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
        // Black N or B
        if (!(c.wa(di) != 0 or c.wa(di - 10) != 0)) {
            if (c.ba(di) == 1) {
                c.add(di);
                return;
            }
            if (c.ba(di) > 1) return;
        }
        c.plus(0x30); // 1B51
        while (true) {
            c.add(di);
            di += 10;
            b = c.B(di);
            if (b != 0) break;
        }
        if (b < pos.black_knight) return;
        if (b >= pos.black_queen or c.wa(di) != 0) {
            c.plus(0x118);
            return;
        }
        if (c.ba(di) != 0) return;
        if (b == pos.black_rook) { // 1BA0: walk on behind the rook
            while (true) {
                di += 10;
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

/// The −10 ray (1C0E).
fn wRookDown(c: *Ctx, sq: i32) void {
    var di = sq;
    while (true) {
        di -= 10;
        const b = c.B(di);
        if (b == 0) {
            c.add(di);
            continue;
        }
        if (b == pos.border) return;
        if (b < pos.border) {
            if (b == pos.white_rook or b == pos.white_queen) {
                const f = file_of[@intCast(di)];
                if (c.p.pawns_per_file[0][f] == 0) {
                    c.plus(0x20);
                    if (c.p.pawns_per_file[1][f] == 0) c.plus(0x40);
                }
                c.add(di);
                continue;
            }
            return;
        }
        if (b == pos.black_pawn) { // 1C28
            if (c.passed(di, c.e.passed_pawns[1])) {
                c.plus(0x60);
                if (c.ba(di) != 0) return;
                c.plus(0x40);
                c.plus(if (di > 0x3A) 0x50 else 0xA0);
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
        wRookAtMinor(c, di, -10);
        return;
    }
}

/// The +1 (1CA9: adds T[sq] first) and −1 (1CEA) queen rays, each ending with a test of
/// the square where the line meets the Black king's ray `code` (0Fh, 0Dh).
fn wQueenSide(c: *Ctx, sq: i32, step: i32, code: u8) void {
    var di = sq;
    if (step > 0) c.add(di);
    di += step;
    while (c.B(di) == 0) {
        c.add(di);
        di += step;
    }
    if (c.bmap(di) != code) return;
    const b = c.B(di);
    if (b == pos.white_pawn) {
        if (c.B(di + 10) == 0) c.plus(0x60);
        return;
    }
    if (b < pos.black_pawn) {
        c.plus(0x60);
        return;
    }
    if (b > pos.black_pawn) c.plus(0x60);
    if (c.wa(di) > 0 or c.ba(di) <= 0) c.plus(0x60); // 1CC8
}

/// The +9 (1D8C) and +11 (1DE8) queen rays.
fn wQueenDiagForward(c: *Ctx, sq: i32, step: i32, code: u8) void {
    var di = sq;
    var b: u8 = undefined;
    while (true) {
        di += step;
        b = c.B(di);
        if (b == 0) {
            if (c.ba(di) == 0) c.add(di);
            continue;
        }
        if (b == pos.white_bishop) {
            c.add(di);
            continue;
        }
        break;
    }
    switch (b) {
        pos.white_pawn, pos.black_bishop, pos.white_queen, pos.white_king, pos.border => {},
        pos.black_pawn => if (c.ba(di) == 0) c.add(di),
        else => { // White N, R; Black N, R, Q, K (1DAB / 1E07)
            if (c.bmap(di) == code) {
                c.plus(0x60);
                if (c.ba(di) <= 0) c.plus(0x60);
            }
            c.add(di);
        },
    }
}

/// Only the empty squares of a ray.
fn emptyRay(c: *Ctx, sq: i32, step: i32) void {
    var di = sq + step;
    while (c.B(di) == 0) {
        c.add(di);
        di += step;
    }
}

/// 1CA4
fn wQueen(c: *Ctx, square: u8) void {
    const sq: i32 = square;
    c.tab = c.e.activityTable(0, queen);
    wQueenSide(c, sq, 1, 0x0F);
    wQueenSide(c, sq, -1, 0x0D);
    // +10 (1D34)
    var di = sq;
    var b: u8 = undefined;
    while (true) {
        di += 10;
        b = c.B(di);
        if (b == 0) {
            if (c.ba(di) == 0) c.add(di);
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
            if (c.bmap(di) == 0x10) {
                c.plus(0x60);
                if (c.ba(di) <= 0) c.plus(0x60);
            }
            c.add(di);
        },
        pos.black_pawn => if (c.ba(di) == 0) c.add(di),
        else => {},
    }
    emptyRay(c, sq, -10); // 1D6E
    wQueenDiagForward(c, sq, 9, 0x0B);
    emptyRay(c, sq, -9); // 1DCA
    wQueenDiagForward(c, sq, 11, 0x0C);
    emptyRay(c, sq, -11); // 1E26
}

// =============================================================================
// Black: 1E9D:1E30
// =============================================================================

/// Port of piece_activity_black (1E9D:1E30–1F3D). Not the mirror of the White routine:
/// see the specification §4.3.
pub fn pieceActivityBlack(p: *const Position, e: *const EvalState) i16 {
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
fn bKnight(c: *Ctx, square: u8) void {
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
fn bBishopBack(c: *Ctx, sq: i32, step: i32, first: bool) void {
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
fn bBishopForward(c: *Ctx, sq: i32, step: i32, code: u8) void {
    var di = sq;
    var b: u8 = undefined;
    while (true) {
        di -= step;
        b = c.B(di);
        if (b == 0) {
            if (c.wa(di) == 0) c.add(di);
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
fn bBishop(c: *Ctx, square: u8) void {
    const sq: i32 = square;
    c.tab = c.e.activityTable(1, bishop);
    bBishopBack(c, sq, 9, true);
    bBishopForward(c, sq, 9, 1);
    bBishopBack(c, sq, 11, false);
    bBishopForward(c, sq, 11, 2);
}

/// The +1 (2171: adds T[sq] first when WA[sq] = 0) and −1 (21F7) rook rays.
fn bRookSide(c: *Ctx, sq: i32, step: i32) void {
    var di = sq;
    if (step > 0 and c.wa(di) == 0) c.add(di);
    var b: u8 = undefined;
    while (true) {
        di += step;
        b = c.B(di);
        if (b == 0 or b == pos.black_queen) {
            if (c.wa(di) == 0) c.add(di);
            continue;
        }
        if (b == pos.black_rook) {
            c.plus(0x10);
            if (c.wa(di) == 0) c.add(di);
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
fn bRookAtMinor(c: *Ctx, start: i32, step: i32) void {
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
fn bRook(c: *Ctx, square: u8) void {
    const sq: i32 = square;
    c.tab = c.e.activityTable(1, rook);
    bRookSide(c, sq, 1);
    bRookSide(c, sq, -1);
    bRookUp(c, sq);
    bRookDown(c, sq);
}

/// The +10 ray (2296): backward for Black.
fn bRookUp(c: *Ctx, sq: i32) void {
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
fn bRookDown(c: *Ctx, sq: i32) void {
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
fn bQueenSide(c: *Ctx, sq: i32, step: i32, code: u8) void {
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
fn bQueenDiagForward(c: *Ctx, sq: i32, step: i32, code: u8) void {
    var di = sq;
    var b: u8 = undefined;
    while (true) {
        di -= step;
        b = c.B(di);
        if (b == 0) {
            if (c.wa(di) == 0) c.add(di);
            continue;
        }
        if (b == pos.black_bishop) {
            c.add(di);
            continue;
        }
        break;
    }
    switch (b) {
        pos.white_pawn => if (c.wa(di) == 0) c.add(di),
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

/// 2408
fn bQueen(c: *Ctx, square: u8) void {
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
            if (c.wa(di) == 0) c.add(di);
            continue;
        }
        if (b == pos.black_rook) {
            c.add(di);
            continue;
        }
        break;
    }
    switch (b) {
        pos.white_pawn => if (c.wa(di) == 0) c.add(di),
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
    var x = pieceActivityWhite(p, e) -% pieceActivityBlack(p, e); // 2E7A
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
