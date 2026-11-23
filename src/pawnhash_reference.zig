//! Test-only reference: the pawn hash as it was before the evaluator memo of
//! 2026-11-18 (src/pawnhash.zig, `PawnHash.memo`). The differential tests in
//! src/evalpawns_test.zig compare src/pawnhash.zig, memo attached, with it.
//!
//! The pawn hash: probe, forced store and clear.
//!
//! Specification: docs/arch/52-evaluation-pawns.md section 5 (and
//! docs/arch/50-evaluation-map.md 3.5), whose executable form is
//! tools/research/evalpawns/model.py (proved against the running original on 1,254,377
//! probes). Tests: src/evalpawns_test.zig (tests/golden/evalpawns/).
//!
//! Two tables of 256 entries of 10 bytes, one per side to move, in the original at
//! 5A7B:174E (White to move) and 5A7B:6A7C (Black to move), reached through far
//! pointers; here ordinary memory, directly indexed. The index is byte 4 of the pawn key
//! and the other five bytes are verified, so all 48 bits are checked. A miss always
//! replaces. A hit restores the three masks and the stored score.
//!
//! The entry layout, index and replacement are the original's: a different table gives
//! different results. In particular the masks are stored by piece-list slot while the
//! key is by square (DEV-014, undecided), so a hit can return the masks of another
//! position with the same pawns in other slots; and an entry stored under a key made
//! wrong by DEV-001 holds the score of other pawns. Both are reproduced.

const std = @import("std");
const pos = @import("position.zig");
const EvalVars = @import("evalvars.zig").EvalVars;
const pawnEval = @import("evalpawns.zig").pawnEval;

const Position = pos.Position;
const Side = pos.Side;

/// One entry, exactly as the original stores it.
pub const Entry = extern struct {
    /// +0: bytes 0-3 of the pawn key (the words DG:8CD2, 8CD4); +4: byte 5 (DG:8CD7).
    /// Byte 4 is the index.
    key: [5]u8,
    /// +5: the weak-pawn mask DG:8EB6 after the evaluation.
    weak_pawns: u8,
    /// +6: the evaluator's score (before the probe's scaling), little-endian.
    score: [2]u8,
    /// +8: the White passed-pawn mask DG:A6C2; +9: Black's, DG:9D8C.
    passed_pawns: [2]u8,
};

comptime {
    std.debug.assert(@sizeOf(Entry) == 10);
}

pub const entries = 256;

pub const PawnHash = struct {
    /// `[0]` White to move (5A7B:174E), `[1]` Black to move (5A7B:6A7C).
    tables: [2][entries]Entry = @splat(@splat(std.mem.zeroes(Entry))),

    /// Port of clear_pawn_hash (0000:8B50-8B7D): zero both tables. Called at the end of
    /// prepare_eval, so before every search.
    pub fn clear(h: *PawnHash) void {
        @memset(std.mem.sliceAsBytes(&h.tables), 0);
    }

    fn slot(h: *PawnHash, key: u48, comptime stm: Side) *Entry {
        const index: u8 = @truncate(key >> 32);
        return &h.tables[@backingInt(stm)][index];
    }

    /// The five verified bytes of a key.
    fn check(key: u48) [5]u8 {
        var b: [6]u8 = undefined;
        std.mem.writeInt(u48, &b, key, .little);
        return .{ b[0], b[1], b[2], b[3], b[5] };
    }

    /// Whether the entry holds the key: bytes 0-3 compared as one word, then byte 5.
    inline fn holds(e: *const Entry, key: u48) bool {
        return std.mem.readInt(u32, e.key[0..4], .little) == @as(u32, @truncate(key)) and
            e.key[4] == @as(u8, @truncate(key >> 40));
    }

    /// The miss path: write the key, evaluate, store the score and the masks.
    fn fill(e: *Entry, p: *const Position, v: *EvalVars, comptime stm: Side) i16 {
        e.key = check(p.pawn_hash_key);
        const score = pawnEval(p, v, stm);
        std.mem.writeInt(u16, &e.score, @bitCast(score), .little);
        e.weak_pawns = v.weak_pawns;
        e.passed_pawns = v.passed_pawns;
        return score;
    }

    /// Port of pawn_hash_wtm (0000:18E8-19D3) when `stm` is White and pawn_hash_btm
    /// (0000:19D4-1ABF) when it is Black.
    ///
    /// Returns the pawn score from White's view, scaled: three quarters of it when
    /// `[378E]` <= 5000 (unsigned), then the Pawn Structure weight in the custom style.
    /// Sets the three masks DG:8EB6, DG:A6C2, DG:9D8C, from the entry on a hit and by
    /// evaluating on a miss.
    pub fn probe(h: *PawnHash, p: *const Position, v: *EvalVars, comptime stm: Side) i16 {
        const e = h.slot(p.pawn_hash_key, stm);
        var score: i16 = undefined;
        if (holds(e, p.pawn_hash_key)) {
            // 1966: hit
            v.weak_pawns = e.weak_pawns;
            v.passed_pawns = e.passed_pawns;
            score = @bitCast(std.mem.readInt(u16, &e.score, .little));
        } else {
            score = fill(e, p, v, stm); // 192E: miss, always replace
        }
        // 1985: three quarters when [378E] <= 5000 (an unsigned compare).
        if (p.piece_material_sum <= 5000) score = score -% (score >> 2);
        // 1999: the custom style's Pawn Structure weight, with the C run-time's long
        // multiply and divide (truncation toward zero; the low 16 bits are kept).
        if (v.style_normal == 0 and v.pawn_structure_weight != 100) {
            score = scalePercent(score, v.pawn_structure_weight);
        }
        return score;
    }

    /// Port of pawn_store_wtm (0000:1AC0-1B22) when `stm` is White and pawn_store_btm
    /// (0000:1B24-1B86) when it is Black: evaluate and store without probing. Returns the
    /// original's AX: the evaluator's high byte with DG:9D8C in the low byte (the last
    /// value moved through AL). static_eval ignores it.
    pub fn store(h: *PawnHash, p: *const Position, v: *EvalVars, comptime stm: Side) u16 {
        const e = h.slot(p.pawn_hash_key, stm);
        const score: u16 = @bitCast(fill(e, p, v, stm));
        return (score & 0xFF00) | v.passed_pawns[1];
    }

    /// Prefetch the entry a probe with this key will read.
    pub fn prefetch(h: *const PawnHash, key: u48, comptime stm: Side) void {
        const index: u8 = @truncate(key >> 32);
        @prefetch(&h.tables[@backingInt(stm)][index], .{});
    }
};

/// `(long) x * w / 100` with the Microsoft C run-time (4793:8B8A, 8AF0): a 32-bit
/// product that wraps, a quotient truncated toward zero, the low 16 bits kept.
pub fn scalePercent(x: i16, w: i32) i16 {
    const prod: i32 = @as(i32, x) *% w;
    return @truncate(@divTrunc(prod, 100));
}
