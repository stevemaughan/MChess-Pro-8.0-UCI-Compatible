//! The pawn hash: probe, forced store and clear; and the memo of the pawn evaluator
//! behind it.
//!
//! Specification: docs/arch/52-evaluation-pawns.md section 5 (and
//! docs/arch/50-evaluation-map.md 3.5), whose executable form is
//! tools/research/evalpawns/model.py (proved against the running original on 1,254,377
//! probes). Tests: src/evalpawns_test.zig (tests/golden/evalpawns/, and the memo against
//! src/pawnhash_reference.zig, the pawn hash without it).
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
//!
//! **The memo** (docs/arch/60-engine-assembly.md 9.4) is not the original's: it is a
//! cache of the evaluator's results, consulted only where the original runs the
//! evaluator (a probe that misses, and the forced store). Its key holds every input the
//! evaluator reads, so a memo hit gives exactly what the evaluator would have computed,
//! and the table above is filled with exactly the same bytes. It pays only where the
//! evaluator is slow: the engine attaches `Memo.engine_slots` slots, none on a target
//! with the evaluator's vector path. See `Memo`.

const std = @import("std");
const pos = @import("position.zig");
const EvalVars = @import("evalvars.zig").EvalVars;
const evalpawns = @import("evalpawns.zig");

const Position = pos.Position;
const Side = pos.Side;

/// Build switch: false compiles the memo out (`PawnHash.memo` is then never read).
pub const memo_enabled = true;

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
    /// The evaluator memo (not the original's; see `Memo`). Empty: no memo, and the
    /// pawn hash runs the evaluator on every miss as the original does. The memory is
    /// the caller's (`attachMemo`); `clear` leaves it alone.
    memo: []Memo.Slot = &.{},

    /// Port of clear_pawn_hash (0000:8B50-8B7D): zero both tables. Called at the end of
    /// prepare_eval, so before every search. The memo is not cleared: its entries
    /// depend on nothing a search changes (`Memo`).
    pub fn clear(h: *PawnHash) void {
        @memset(std.mem.sliceAsBytes(&h.tables), 0);
    }

    /// Give the pawn hash a memo of `slots.len` entries (a power of two, or none), owned
    /// by the caller and kept as long as the pawn hash is used; `Memo.engine_slots` is
    /// the size the engine is meant to use. The slots are emptied here, once.
    pub fn attachMemo(h: *PawnHash, slots: []Memo.Slot) void {
        std.debug.assert(slots.len == 0 or std.math.isPowerOfTwo(slots.len));
        @memset(slots, Memo.Slot.empty);
        h.memo = slots;
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
    fn fill(h: *PawnHash, e: *Entry, p: *const Position, v: *EvalVars, comptime stm: Side, comptime lanes: bool) i16 {
        e.key = check(p.pawn_hash_key);
        const score = h.evaluate(p, v, stm, lanes);
        std.mem.writeInt(u16, &e.score, @bitCast(score), .little);
        e.weak_pawns = v.weak_pawns;
        e.passed_pawns = v.passed_pawns;
        return score;
    }

    /// The evaluator (`evalpawns.pawnEvalWith`), answered from the memo when it holds
    /// these inputs. Same return value and same writes to `v` in every case.
    pub inline fn evaluate(h: *PawnHash, p: *const Position, v: *EvalVars, comptime stm: Side, comptime lanes: bool) i16 {
        if (!memo_enabled or h.memo.len == 0) return evalpawns.pawnEvalWith(p, v, stm, lanes);
        return Memo.evaluate(h.memo, p, v, stm, lanes);
    }

    /// Port of pawn_hash_wtm (0000:18E8-19D3) when `stm` is White and pawn_hash_btm
    /// (0000:19D4-1ABF) when it is Black.
    ///
    /// Returns the pawn score from White's view, scaled: three quarters of it when
    /// `[378E]` <= 5000 (unsigned), then the Pawn Structure weight in the custom style.
    /// Sets the three masks DG:8EB6, DG:A6C2, DG:9D8C, from the entry on a hit and by
    /// evaluating on a miss.
    pub fn probe(h: *PawnHash, p: *const Position, v: *EvalVars, comptime stm: Side) i16 {
        return h.probeWith(p, v, stm, evalpawns.lanes_available);
    }

    /// `probe` with the evaluator's way of working chosen (`evalpawns.pawnEvalWith`):
    /// for the tests and benchmarks.
    pub fn probeWith(h: *PawnHash, p: *const Position, v: *EvalVars, comptime stm: Side, comptime lanes: bool) i16 {
        const e = h.slot(p.pawn_hash_key, stm);
        var score: i16 = undefined;
        if (holds(e, p.pawn_hash_key)) {
            // 1966: hit
            v.weak_pawns = e.weak_pawns;
            v.passed_pawns = e.passed_pawns;
            score = @bitCast(std.mem.readInt(u16, &e.score, .little));
        } else {
            score = h.fill(e, p, v, stm, lanes); // 192E: miss, always replace
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
        return h.storeWith(p, v, stm, evalpawns.lanes_available);
    }

    /// `store` with the evaluator's way of working chosen: for the tests and benchmarks.
    pub fn storeWith(h: *PawnHash, p: *const Position, v: *EvalVars, comptime stm: Side, comptime lanes: bool) u16 {
        const e = h.slot(p.pawn_hash_key, stm);
        const score: u16 = @bitCast(h.fill(e, p, v, stm, lanes));
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

/// The memo of the pawn evaluator: a pure-function cache.
///
/// **What the evaluator reads and writes** (`evalpawns.pawnEvalWith`, both of its
/// paths, and docs/arch/52-evaluation-pawns.md 3.1-3.2). It reads, from `Position`:
/// `board` (every read compares a square with a pawn code, so only which squares hold a
/// White pawn and which a Black pawn), the pawn slots `piece_list[8..16]` and
/// `[24..32]`, both `pawn_attacks` tables, both `pawns_per_file` tables and
/// `pawn_count`; from `EvalVars`: `late_endgame` (only whether it is 0); and which
/// evaluator (`stm`). The constant tables are compiled in. It writes `weak_pawns` and
/// both `passed_pawns`, and returns the score; nothing else.
///
/// **The key** holds all of these but the attack tables: the squares of the White and
/// of the Black pawns on the board; the slots, each replaced by FFh when it holds 120 or
/// more (a captured pawn's mark: the evaluator skips such a slot whatever it holds);
/// both pawns-per-file tables; `pawn_count`; `late_endgame != 0`; `stm`; and the
/// evaluator's path (`lanes`). The memo is used only where the attack tables are a
/// function of the key, checked at every lookup (elsewhere the evaluator runs and
/// nothing is recorded):
///
/// 1. every pawn stands on ranks 2-7 of files a-h (squares 31..88, not the border
///    columns, where the evaluator's per-file reads leave the table: file 0 - 1, file
///    9 + 1). Both paths of the evaluator then read the attack tables only on the 64
///    squares of the board: a White pawn on sq reads sq - 10 only when sq >= 51,
///    sq + 30 and sq + 40 only when sq <= 58, sq + 20 only with its own pawn on sq + 10
///    or when sq < 41, sq + 10 always; a Black pawn the mirror; the space terms fixed
///    squares of ranks 3-6 (read from `whitePawn`, `blackPawn` and `byLane`);
/// 2. on those 64 squares each `pawn_attacks` byte is the number of that colour's pawns
///    attacking the square (White from sq - 9 and sq - 11, Black from sq + 9 and
///    sq + 11). The bytes on the border are not checked and not read. (The original
///    builds the tables at the root without the border squares, so its border bytes
///    are 0 there and count only what make_move added since; the port's set-up counts
///    them; neither matters.)
///
/// make_move and unmake_move keep 2, and pawns never stand on ranks 1 and 8; the tests
/// check that every position of their random walks and every recorded call is in the
/// domain. A state written directly that is not (a test, the set-up code, the lifted
/// routines) is evaluated, not looked up: slower, never wrong. Within the domain the
/// board's pawns lie on squares 31..88, so the key keeps their squares as 58-bit sets.
///
/// **Lifetime.** The memo is the caller's memory, handed to `PawnHash.attachMemo` once
/// (the engine is meant to allocate `engine_slots` slots with the rest of its state).
/// Its entries depend on none of the root's tables, so it is never cleared, between
/// searches or games: an entry stays right for as long as the evaluator is the same
/// code. Direct-mapped; a new result always replaces. No allocation when it is used.
pub const Memo = struct {
    /// The size measured: 2^12 slots of 64 bytes, 256 KB. Emptied at the start of each
    /// recorded run, it answers 47% of the evaluator's calls there (2^14: 51%).
    pub const slots_measured = 1 << 12;

    /// The slots the engine should attach. Measured on the recorded calls (`bench:
    /// evalpawns: pawn memo`, ReleaseFast, three runs): a lookup costs about 12 ns. With
    /// the evaluator's per-slot path (94-99 ns a call) the memo takes the calls to 85-90
    /// ns and the pawn-hash operations from 24.8-25.5 to 23.3-24.7 ns; with the vector
    /// path (38.5-39 ns a call) the calls take 36.7-38.5 ns but the operations are
    /// slower (11.7-12.3 to 13.4-14.2 ns). So the memo is used only without the vector
    /// path.
    pub const engine_slots: usize = if (evalpawns.lanes_available) 0 else slots_measured;

    pub const Key = [7]u64;

    pub const Slot = extern struct {
        /// The packed key (`key`); all zero when empty, which no key is.
        key: Key align(64),
        /// The evaluator's return value and what it left in the three masks.
        score: i16,
        weak_pawns: u8,
        passed_pawns: [2]u8,
        _pad: [3]u8 = .{ 0, 0, 0 },

        pub const empty: Slot = .{ .key = @splat(0), .score = 0, .weak_pawns = 0, .passed_pawns = .{ 0, 0 } };
    };

    comptime {
        std.debug.assert(@sizeOf(Slot) == 64);
    }

    /// The evaluator, through the memo `slots`.
    fn evaluate(slots: []Slot, p: *const Position, v: *EvalVars, comptime stm: Side, comptime lanes: bool) i16 {
        const k = key(p, v.late_endgame, stm, lanes) orelse return evalpawns.pawnEvalWith(p, v, stm, lanes);
        const s = &slots[index(k) & (slots.len - 1)];
        if (@reduce(.And, @as(@Vector(7, u64), s.key) == @as(@Vector(7, u64), k))) {
            v.weak_pawns = s.weak_pawns;
            v.passed_pawns = s.passed_pawns;
            return s.score;
        }
        const score = evalpawns.pawnEvalWith(p, v, stm, lanes);
        s.* = .{ .key = k, .score = score, .weak_pawns = v.weak_pawns, .passed_pawns = v.passed_pawns };
        return score;
    }

    /// The 64 squares of the board, and those of ranks 2-7.
    const board64: u128 = squareSet(21, 98);
    const pawn_squares: u128 = squareSet(31, 88);

    fn squareSet(comptime lo: usize, comptime hi: usize) u128 {
        var m: u128 = 0;
        for (lo..hi + 1) |sq| {
            if (sq % 10 >= 1 and sq % 10 <= 8) m |= @as(u128, 1) << sq;
        }
        return m;
    }

    const V = @Vector(64, u8);

    /// A 120-byte table as two 64-byte vectors, bytes 0..63 and 56..119.
    inline fn halves(t: *const [120]u8) [2]V {
        return .{ t[0..64].*, t[56..120].* };
    }

    /// The bits of a square set for the two halves.
    inline fn split(m: u128) [2]u64 {
        return .{ @truncate(m), @truncate(m >> 56) };
    }

    inline fn bits(x: @Vector(64, bool)) u64 {
        return @bitCast(x);
    }

    /// The squares of `board` holding `code`, bit i for square i.
    inline fn squaresOf(board: [2]V, comptime code: u8) u128 {
        const c: V = @splat(code);
        return @as(u128, bits(board[0] == c)) | @as(u128, bits(board[1] == c) >> 8) << 64;
    }

    /// Whether every byte of `attacks` on the 64 squares is the number of attackers in
    /// the two masks (bit i of `a` and of `b` set: an attacker of square i).
    inline fn attacksAre(attacks: *const [120]u8, a: u128, b: u128) bool {
        const t = halves(attacks);
        const odd = split(a ^ b);
        const two = split(a & b);
        const on = comptime split(board64);
        const zero: V = @splat(0);
        var wrong: u64 = 0;
        inline for (0..2) |i| {
            const ones = bits(t[i] & @as(V, @splat(1)) != zero);
            const twos = bits(t[i] & @as(V, @splat(2)) != zero);
            const more = bits(t[i] & @as(V, @splat(0xFC)) != zero);
            wrong |= ((ones ^ odd[i]) | (twos ^ two[i]) | more) & on[i];
        }
        return wrong == 0;
    }

    /// Eight slots, each FFh where it holds 120 or more (the evaluator skips such a slot).
    inline fn kept(slots: *const [8]u8) u64 {
        const E = @Vector(8, u8);
        const s: E = slots.*;
        return @bitCast(@select(u8, s < @as(E, @splat(120)), s, @as(E, @splat(0xFF))));
    }

    /// The key of the evaluator's inputs, or null when the attack tables are not what
    /// the key implies (see `Memo`).
    pub fn key(p: *const Position, late_endgame: u8, comptime stm: Side, comptime lanes: bool) ?Key {
        const board = halves(&p.board);
        const white = squaresOf(board, pos.white_pawn);
        const black = squaresOf(board, pos.black_pawn);
        if ((white | black) & ~pawn_squares != 0) return null;
        if (!attacksAre(&p.pawn_attacks[0], white << 9, white << 11)) return null;
        if (!attacksAre(&p.pawn_attacks[1], black >> 9, black >> 11)) return null;
        const files = std.mem.asBytes(&p.pawns_per_file);
        comptime std.debug.assert(files.len == 20);
        const tail: u64 = std.mem.readInt(u32, files[16..20], .little) |
            @as(u64, p.pawn_count) << 32 |
            @as(u64, @intFromBool(late_endgame != 0)) << 40 |
            @as(u64, @backingInt(stm)) << 41 |
            @as(u64, @intFromBool(lanes)) << 42 |
            1 << 63;
        return .{
            // The pawns stand on squares 31..88: 58 bits.
            @truncate(white >> 31),
            @truncate(black >> 31),
            kept(p.piece_list[8..16]),
            kept(p.piece_list[24..32]),
            std.mem.readInt(u64, files[0..8], .little),
            std.mem.readInt(u64, files[8..16], .little),
            tail,
        };
    }

    /// The slot a key goes to is `index(k) & (slots.len - 1)`.
    pub inline fn index(k: Key) usize {
        const rotl = std.math.rotl;
        const a = k[0] ^ rotl(u64, k[1], 29) ^ rotl(u64, k[4], 13);
        const b = k[2] ^ rotl(u64, k[3], 32) ^ rotl(u64, k[5], 7) ^ k[6];
        const x = (a *% 0x9E37_79B9_7F4A_7C15) ^ (b *% 0xC2B2_AE3D_27D4_EB4F);
        return @truncate(((x ^ (x >> 32)) *% 0xFF51_AFD7_ED55_8CCD) >> 32);
    }
};
