//! The search node: search_white_to_move (0000:3AC6) and search_black_to_move
//! (0000:5036), as one routine parameterised by the side to move.
//! Specification: docs/arch/30-search-node.md. Model: tools/research/searchnode/model.py,
//! which this follows label for label (the `L_xxxx` methods there are the `Label`s here).
//!
//! The node is alpha-beta with principal-variation search, the null move, the check and
//! pawn-ending extensions, the hash probe and store, killers and the `[781A]` move marks,
//! the triangular principal variation, and the quiescence search with its staged
//! stand-pat. Everything the node calls (the move generators, make and unmake, the
//! evaluation terms, the hash table, the other node) is reached through `Ctx`, the
//! interface documented at `Node`. The state the node reads and writes besides its own
//! locals is `State`, one named field per original variable with its `DG:` address.
//!
//! Branches that never ran in the replay test of the model (the specification's
//! coverage table) are ported from the model and marked `UNVERIFIED`.
//!
//! No class C fix applies to the node itself (docs/DEVIATIONS.md lists none). One byte
//! the original stores without writing it is an explicit input, `stale_move_to` (see
//! `search`).
//!
//! The same code is also root_move_search (0000:2EC8), the ply-2 node the root calls from
//! the second iteration on (`Node(Ctx).searchPly2`; docs/arch/32-root-move-search.md,
//! model tools/research/rootmove/model.py). The original wrote it as a separate routine:
//! the node at ply 2 for either side, with nine differences listed in that specification.
//! Here it is one instantiation of the node with `ply2` set at compile time; every place
//! where it differs is an `if (ply2)` naming the original's address, so the general node
//! is compiled exactly as before.

const std = @import("std");
const pos = @import("position.zig");
const mg = @import("movegen.zig");
const evm = @import("evalvars.zig");
const EvalState = @import("eval_state.zig").EvalState;
const leaf = @import("leaf.zig");
const et = @import("evalthreats.zig");

pub const Move = pos.Move;
pub const Undo = pos.Undo;

/// Entries of the per-ply arrays (DEV-002: the original's arrays end where the next
/// variable begins, 35 to 44 plies; the node's ply ceiling `DG:0062` is 35).
pub const max_ply = 64;

/// The ply-2 node's mate score, 0000:3674 `mov ax, B1E2h`: -19998, which is 2 - 20000.
const mate_ply2: i16 = @bitCast(@as(u16, 0xB1E2));

pub const Side = u1;
pub const white: Side = 0;
pub const black: Side = 1;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// Every variable outside its own frame that the node reads or writes. Words are
/// little-endian as in the original, so `dg_fields` can map a DGROUP address to a byte
/// of this struct (used by the replay test).
pub const State = extern struct {
    /// The position the node reads and writes (board, piece lists, ray maps, counts,
    /// material, keys, the per-ply move records, game ply): `position.Position`, the
    /// one home of those variables (Stage B step 2). Not a DGROUP variable: the caller
    /// points it at its position before the node runs.
    p: *pos.Position = undefined,
    /// The move marks and the generators' hint bytes (bishop, rook and queen hints, check
    /// flag, king rule): `movegen.SearchVars`, their one home (Stage B step 3), which the
    /// generators read; `search_rooms` gives their addresses. Not a DGROUP variable: the
    /// caller points it at its `SearchVars`.
    sv: *mg.SearchVars = undefined,
    /// The evaluation's flags and sums the node reads, saves and restores (the pawn square
    /// sums, the weak-pawn and passed-pawn masks, the passer, draw and promotion flags,
    /// the promotion square): `evalvars.EvalVars`, their one home (Stage B step 4), which
    /// the evaluation writes; `eval_vars_rooms` gives their addresses. Not storage.
    ev: *evm.EvalVars = undefined,
    /// The leaf map and the key history: `leaf.LeafVars`, their one home (Stage B step 5),
    /// which the leaf terms and the repetition test read; `leaf_vars_rooms` gives their
    /// addresses. Not storage.
    lv: *leaf.LeafVars = undefined,
    /// The three ply limits and the iteration: `evalthreats.ThreatVars`, their one home
    /// (Stage B step 5), which the threat evaluators read; `threat_vars_rooms` gives their
    /// addresses. Not storage.
    tv: *et.ThreatVars = undefined,
    /// DG:0062 ply ceiling: at ply >= this the node evaluates at once (B3). 35.
    ply_ceiling: i16 = 35,
    /// DG:03EA stand-pat bonus by the count of `count_attacked` (initialised data).
    standpat_bonus: [8]i16 = .{ 0, 24, 300, 500, 600, 700, 800, 900 },
    /// DG:0C88 king-adjacency table, centred on DG:0CFF: entry 119 + (wk - bk).
    king_adjacent: [239]u8 = @splat(0),
    /// DG:0E16 by square: non-zero selects the first bishop slot in the 579A pin hint.
    bishop_square_sel: [120]u8 = @splat(0),
    /// DG:1A80 row of the move-mark table for each from square.
    mark_row: [120]u16 = @splat(0),
    /// DG:1E08 search mode; 0 in every run (its paths are UNVERIFIED).
    mode_1e08: u16 = 0,
    /// DG:239C tablebase setting (10 in every run; the probe needs >= 11).
    tb_setting: i16 = 0,
    /// DG:3766 by horizon: the last ply that may be searched past it. 40 bytes, as
    /// prepare_eval writes them (`evaltables.Tables.table_3766`); the node reads it
    /// through `qsMaxPly`, which gives the bytes that follow for H of 40 or more.
    qs_max_ply: [40]u8 = @splat(0),
    /// DG:3790 killer move (from | to << 8) by ply.
    killer: [max_ply]u16 = @splat(0),
    /// DG:3A34 move list of each ply (100 moves).
    move_list: [max_ply][100]Move = @splat(@splat(.{ .from = 0, .to = 0, .flag = 0, .score = 0 })),
    /// DG:740A node counter.
    node_count: u32 = 0,
    /// DG:741B..741D the three bytes below `extension` (read as extensions of plies -3..-1).
    ext_below: [3]u8 = @splat(0),
    /// DG:741E extension made at each ply: 0, 1, 2, or 3 (pawn ending, one ply).
    extension: [max_ply]u8 = @splat(0),
    /// DG:744E working horizon H (signed byte).
    horizon: i8 = 0,
    _pad1: u8 = 0,
    /// DG:7466 score from the tablebase probe 2B9F:BB76.
    tb_score: i16 = 0,
    /// DG:75B6 keyboard poll requests pending.
    poll_pending: u8 = 0,
    _pad2: u8 = 0,
    /// DG:77FE hash entry buffer (10 bytes, layout in the specification).
    hash_entry: [10]u8 = @splat(0),
    _pad3: u8 = 0,
    /// DG:8DE8 previous iteration's score from Black's view.
    prev_score_black: i16 = 0,
    _pad4: u8 = 0,
    /// DG:9316 hash size mode (index scaled by 3/4 when non-zero).
    hash_size_mode: u8 = 0,
    _pad6: u8 = 0,
    /// DG:9366 triangular principal variation: 37 words per ply.
    pv: [max_ply][37]u16 = @splat(@splat(0)),
    _pad7: u8 = 0,
    _pad8: u8 = 0,
    /// DG:A05A material balance at the root.
    root_material_balance: i16 = 0,
    /// DG:A35A total material at the root.
    root_material_total: i16 = 0,
    _pad9: u8 = 0,
    /// DG:A3F8 hash tables present.
    hash_enabled: u16 = 0,
    /// DG:A418 previous iteration's score from White's view.
    prev_score_white: i16 = 0,
    /// DG:A4FA stop flag.
    stop: u8 = 0,
    _pad10: u8 = 0,
    /// DG:A6C6 both sides had pieces at the root.
    both_had_pieces: u8 = 0,
    _pad11: u8 = 0,
    /// DG:AAF6 by ply: last ply of the PV held in that row.
    pv_end: [max_ply]u8 = @splat(0),
    /// DG:AB9C conventional-memory index mask.
    conv_mask: u16 = 0,
    /// DG:AC28 > 1 selects the conventional-memory tables (0 in every run).
    conv_tables: u8 = 0,
    _pad13: u8 = 0,
    /// DG:B624 hash index mask (dword).
    hash_mask: u32 = 0,
};

/// The four variables the ply-2 node's time test D reads (0000:2EEA-2F46) and no other
/// part of the node: the root's and the level's, passed by the root with each call
/// (`Node(Ctx).searchPly2`). Not in `State`, whose address table `dg_fields` is shared
/// with the generated maps of src/dgroup_maps.zig; the assembly may move them there.
pub const Ply2Clock = struct {
    /// DG:A356 elapsed ticks at the first root move of the iteration, set by the root
    /// (docs/arch/31-root-iteration-time.md 3.2, test B) and 0 for every other root
    /// move (`rootsearch.RootState.iter_start_elapsed`).
    iter_start_elapsed: u32 = 0,
    /// DG:8D06 base time, ticks (`rootsearch.RootState.base`).
    base_time: u32 = 0,
    /// DG:3676 pondering: non-zero skips test D (`rootsearch.RootState.pondering`).
    pondering: u8 = 0,
    /// DG:1480 single-move control: non-zero skips test D.
    single_move: u16 = 0,
};

/// The original's room of the per-ply arrays of the position the node reads (DEV-002):
/// the entries before the next variable begins, as the node's `State` declared them
/// (searchnode.dg_fields before Stage B step 2). `Position` declares 64 entries.
pub const room_quiet_move = 40; // DG:3626, 80 bytes, up to DG:3676
pub const room_reversible = 36; // DG:8BBE, 72 bytes, up to DG:8C06 (the in-check flags)
pub const room_check = 44; // DG:8C06, 44 bytes, up to DG:8C32
pub const room_ep = 46; // DG:9EC8, 46 bytes, up to DG:9EF6 (the board)

/// B(3766 + H), the read of 0000:4306-430C (White) and 587E (Black): the last ply that may
/// be searched past the horizon H, with H the signed byte DG:744E. H is never negative:
/// it starts at 1 (0000:13A3) and grows by one an iteration (1699, 16B3) and by one for
/// each extension (at most two a ply, below the ply ceiling 35), and falls only when an
/// extension is taken back or by the null move's R (1 or 2), which is made only when
/// H > ply >= 1 (2EC8: iteration > 2). It can pass 39: the table of 40 bytes is followed in
/// the original by the non-pawn material DG:378E (H 40, 41), the killers DG:3790 (H 42 to
/// 115) and the Black pawn-attack counts DG:37DA (H 116 to 127); every one of them is
/// read here where the original reads it.
pub fn qsMaxPly(st: *const State, h: i8) u8 {
    const i: usize = @intCast(h);
    return switch (i) {
        0...39 => st.qs_max_ply[i],
        40...41 => std.mem.asBytes(&st.p.piece_material_sum)[i - 40],
        42...115 => std.mem.asBytes(&st.killer)[i - 42],
        116...127 => st.p.pawn_attacks[1][i - 116],
        else => unreachable,
    };
}

/// An index of a per-ply array, checked against the original's room in Debug and
/// ReleaseSafe: past it the original would read the next variable.
inline fn atRoom(comptime room: usize, i: usize) usize {
    std.debug.assert(i < room);
    return i;
}

/// Word `k` (0, 1, 2) of a 48-bit key as the original stores it, little-endian: the
/// key's bytes 2k and 2k+1.
pub inline fn keyWord(key: u48, comptime k: u6) u16 {
    return @truncate(key >> (16 * k));
}

/// Byte 4 of a 48-bit key (DG:8CD0 for the main key).
pub inline fn keyByte4(key: u48) u8 {
    return @truncate(key >> 32);
}

/// The node's position variables, now in `Position`, with the DGROUP ranges the node's
/// `State` declared for them (the original's room), for the replay tests' address maps.
pub const position_rooms = [_]DgField{
    .{ .name = "men", .addr = 0x154A, .len = 1 },
    .{ .name = "reverse_move", .addr = 0x3626, .len = 0x50 },
    .{ .name = "nonpawn_total", .addr = 0x378E, .len = 2 },
    .{ .name = "sum_7182", .addr = 0x7182, .len = 2 },
    .{ .name = "black_pawns", .addr = 0x741A, .len = 1 },
    .{ .name = "reversible", .addr = 0x8BBE, .len = 0x48 },
    .{ .name = "in_check", .addr = 0x8C06, .len = 0x2C },
    .{ .name = "keys", .addr = 0x8CCC, .len = 12 },
    .{ .name = "material", .addr = 0x8DE4, .len = 4 },
    .{ .name = "pawns", .addr = 0x90AA, .len = 1 },
    .{ .name = "pieces", .addr = 0x931A, .len = 2 },
    .{ .name = "pawn_file_black", .addr = 0x9EA8, .len = 10 },
    .{ .name = "ep_square", .addr = 0x9EC8, .len = 0x2E },
    .{ .name = "board", .addr = 0x9EF6, .len = 120 },
    .{ .name = "game_ply", .addr = 0x9FC8, .len = 2 },
    .{ .name = "piece_list", .addr = 0xA03A, .len = 32 },
    .{ .name = "white_map", .addr = 0xA09E, .len = 120 },
    .{ .name = "black_map", .addr = 0xA164, .len = 120 },
    .{ .name = "king_file", .addr = 0xA22E, .len = 2 },
    .{ .name = "material_balance", .addr = 0xA35E, .len = 2 },
    .{ .name = "material_total", .addr = 0xA420, .len = 2 },
    .{ .name = "pawn_file_white", .addr = 0xA8C8, .len = 10 },
    .{ .name = "nonpawn_balance", .addr = 0xA8D2, .len = 2 },
    .{ .name = "white_pawns", .addr = 0xAB1E, .len = 1 },
    .{ .name = "nonpawn", .addr = 0xAE38, .len = 4 },
};

/// The node's variables now in `movegen.SearchVars` (Stage B step 3), with their
/// DGROUP ranges, for the replay tests' address maps. The marks' room is the
/// original's: 4,990 bytes, which main's clear_move_marks (1E9D:54CE) zeroes, up to
/// DG:8B97. No mark index past it can be formed (`Node.mark`).
pub const search_rooms = [_]DgField{
    .{ .name = "bishop_hint", .addr = 0x725C, .len = 1 },
    .{ .name = "check_flag", .addr = 0x73F2, .len = 1 },
    .{ .name = "marks", .addr = 0x781A, .len = mg.marks_len },
    .{ .name = "queen_hint", .addr = 0xA846, .len = 2 },
    .{ .name = "rook_hint", .addr = 0xA8D8, .len = 2 },
};

/// The node's variables now in `evalvars.EvalVars` (Stage B step 4), named as there, with
/// their DGROUP ranges, for the replay tests' address maps.
pub const eval_vars_rooms = [_]DgField{
    .{ .name = "black_king_by_passer", .addr = 0x39AE, .len = 1 },
    .{ .name = "pawn_square_sum[1]", .addr = 0x369A, .len = 2 },
    .{ .name = "promotion_square", .addr = 0x8CCA, .len = 1 },
    .{ .name = "weak_pawns", .addr = 0x8EB6, .len = 1 },
    .{ .name = "pawn_square_sum[0]", .addr = 0x90B6, .len = 2 },
    .{ .name = "passed_pawns[1]", .addr = 0x9D8C, .len = 1 },
    .{ .name = "promotion_flags", .addr = 0x9EBA, .len = 1 },
    .{ .name = "passer_flags", .addr = 0xA5F5, .len = 1 },
    .{ .name = "passed_pawns[0]", .addr = 0xA6C2, .len = 1 },
    .{ .name = "draw_flag", .addr = 0xA8DE, .len = 1 },
};

/// The node's variables now in `EvalVars` (Stage B step 4: `eval_state.EvalState`, which
/// is `EvalVars` since step 6), with their
/// DGROUP ranges (`ply_flag` in the 40 bytes the node's `State` declared, up to DG:9DBB;
/// the key history begins at DG:9DBE), for the replay tests' address maps.
pub const eval_state_rooms = [_]DgField{
    .{ .name = "ply_flag", .addr = 0x9D94, .len = room_last_irrev },
    .{ .name = "no_pawns_at_root", .addr = 0xA6A3, .len = 1 },
    .{ .name = "last_irreversible_ply", .addr = 0x7464, .len = 2 },
};

/// The node's variables now in `leaf.LeafVars` (Stage B step 5), with their DGROUP ranges
/// (the key history in the 36 entries the node's `State` declared), for the replay tests.
pub const leaf_vars_rooms = [_]DgField{
    .{ .name = "leaf_map", .addr = 0x8FE4, .len = 120 },
    .{ .name = "key_history", .addr = 0x9DBE, .len = room_key_history * 6 },
};

/// The node's variables now in `evalthreats.ThreatVars` (Stage B step 5), with their
/// DGROUP ranges, for the replay tests.
pub const threat_vars_rooms = [_]DgField{
    .{ .name = "ply_limit2", .addr = 0x9356, .len = 2 },
    .{ .name = "ply_limit1", .addr = 0xA272, .len = 2 },
    .{ .name = "iteration", .addr = 0xA3F4, .len = 1 },
    .{ .name = "ply_limit3", .addr = 0xA5EC, .len = 2 },
};

/// The original's room of the key history at DG:9DBE (DEV-002): 36 entries of three words,
/// as the node's `State` declared them before step 5, up to DG:9E95.
pub const room_key_history = 36;

/// The original's room of the per-ply last-irreversible plies at DG:9D94 (DEV-002), as
/// the node's `State` declared them before step 4.
pub const room_last_irrev = 40;

/// DGROUP address and length (as the original lays it out) of each `State` field.
pub const DgField = struct { name: []const u8, addr: u16, len: u16 };

pub const dg_fields = [_]DgField{
    .{ .name = "ply_ceiling", .addr = 0x0062, .len = 2 },
    .{ .name = "standpat_bonus", .addr = 0x03EA, .len = 16 },
    .{ .name = "king_adjacent", .addr = 0x0C88, .len = 239 },
    .{ .name = "bishop_square_sel", .addr = 0x0E16, .len = 120 },
    .{ .name = "mark_row", .addr = 0x1A80, .len = 240 },
    .{ .name = "mode_1e08", .addr = 0x1E08, .len = 2 },
    .{ .name = "tb_setting", .addr = 0x239C, .len = 2 },
    .{ .name = "qs_max_ply", .addr = 0x3766, .len = 40 },
    .{ .name = "killer", .addr = 0x3790, .len = 0x4A },
    .{ .name = "move_list", .addr = 0x3A34, .len = 35 * 400 },
    .{ .name = "node_count", .addr = 0x740A, .len = 4 },
    .{ .name = "ext_below", .addr = 0x741B, .len = 3 },
    .{ .name = "extension", .addr = 0x741E, .len = 36 },
    .{ .name = "horizon", .addr = 0x744E, .len = 1 },
    .{ .name = "tb_score", .addr = 0x7466, .len = 2 },
    .{ .name = "poll_pending", .addr = 0x75B6, .len = 1 },
    .{ .name = "hash_entry", .addr = 0x77FE, .len = 10 },
    .{ .name = "prev_score_black", .addr = 0x8DE8, .len = 2 },
    .{ .name = "hash_size_mode", .addr = 0x9316, .len = 1 },
    .{ .name = "pv", .addr = 0x9366, .len = 35 * 0x4A },
    .{ .name = "root_material_balance", .addr = 0xA05A, .len = 2 },
    .{ .name = "root_material_total", .addr = 0xA35A, .len = 2 },
    .{ .name = "hash_enabled", .addr = 0xA3F8, .len = 2 },
    .{ .name = "prev_score_white", .addr = 0xA418, .len = 2 },
    .{ .name = "stop", .addr = 0xA4FA, .len = 1 },
    .{ .name = "both_had_pieces", .addr = 0xA6C6, .len = 1 },
    .{ .name = "pv_end", .addr = 0xAAF6, .len = 0x28 },
    .{ .name = "conv_mask", .addr = 0xAB9C, .len = 2 },
    .{ .name = "conv_tables", .addr = 0xAC28, .len = 1 },
    .{ .name = "hash_mask", .addr = 0xB624, .len = 4 },
};

comptime {
    if (@import("builtin").cpu.arch.endian() != .little) @compileError("State mirrors the original's little-endian words");
    @setEvalBranchQuota(100000);
    for (dg_fields, 0..) |f, i| {
        if (!@hasField(State, f.name)) @compileError("no State field " ++ f.name);
        if (f.len > @sizeOf(@FieldType(State, f.name))) @compileError("DG length beyond field " ++ f.name);
        for (dg_fields[0..i]) |g| {
            if (f.addr < @as(u32, g.addr) + g.len and g.addr < @as(u32, f.addr) + f.len)
                @compileError("DG ranges overlap: " ++ f.name ++ " and " ++ g.name);
        }
    }
}

// ---------------------------------------------------------------------------
// The interface: every routine the node calls
// ---------------------------------------------------------------------------

/// The generators the node chooses between (B15).
pub const Gen = enum(u8) {
    /// 1E9D:3938 all moves (interior nodes and full-width re-entry).
    all = 6,
    /// 38C0:E260 check evasions.
    evasions = 7,
    /// 1E9D:579A quiescence, H < ply <= L1.
    q1 = 8,
    /// 1E9D:25A0 quiescence, L1 < ply <= L2.
    q2 = 9,
    /// 0EF8:9528 quiescence, L2 < ply <= L3.
    q3 = 10,
    /// 1E9D:4954 quiescence, beyond L3.
    q4 = 11,
};

/// The node, generic over the interface `Ctx`. `Ctx` must provide these methods
/// (`self: *Ctx`); White and Black routine pairs are one entry taking the side:
///
/// - `poll()`: 1E9D:7514, the keyboard poll; may set `stop`.
/// - `isRepetition(ply: i16) bool`: 0000:1B88.
/// - `attacks(side, sq: u8) bool`: 0000:1C76 (White) / 1DE6 (Black): does `side`
///   attack `sq` with a non-pawn.
/// - `hashMovePlausible(side, mv: *u16) bool`: 0000:1F56 / 211E; on false it has cleared
///   the from byte of `mv.*`.
/// - `probe(side, index: u32)`: read the 10-byte slot `index` of the side's table into
///   `State.hash_entry` (the original: XMS copy 0000:6A91 at offset 10*index).
/// - `store(side, index: u32)`: write `State.hash_entry` to slot `index`.
/// - `prefetchProbe(side, index: u32)`: no routine of the original. A hint that the
///   next node will probe slot `index` of the side's table (docs/arch/60-engine-assembly.md
///   section 9.3); called where the child's key is final, under the child's probe test,
///   and before the null move. It must change no state; it may do nothing.
/// - `generate(gen: Gen, side, ply: i16) u16`: fill `State.move_list[ply]`; returns the
///   count, or FFFFh if the opponent's king can be captured.
/// - `sortList(ply: i16, count: u16)`: 0000:65BC, Shell sort of the list by score byte.
/// - `makeNull(ply: i16)`: 1E9D:16BE.
/// - `child(side, legal: *i16, beta: i16, alpha: i16, ply: i16) i16`: the other node
///   function (0000:5036 / 3AC6), with `side` the child's side to move. The real
///   implementation is `Node(Ctx).search` with `stale_move_to` 0.
/// - `applyMove(side, ply: i16, mv: Move, undo: *Undo)`: 0000:678A, 4793:3EA2 and
///   1E9D:000C, the three calls the node makes for every move with nothing between
///   them (0000:3FA8-3FC5, 4DF2-4E0D; 551A-5537, 6378-6393): update_square_sums and
///   update_hash_key with `mv`, then make_move for `side` at `ply` (the child's ply).
///   The engine's is `Position.applyMove`.
/// - `unmake(side, mv: Move, undo: *Undo)`: 1E9D:0960. The node restores the saved keys
///   and square sums straight after it.
/// - `pawnEval(side) i16`: 0000:18E8 / 19D4.
/// - `staticEval(side, arg: i16) i16`: 2B9F:000E, White's view.
/// - `pieceEval(side, ply: i16) i16`: 0EF8:0006, White's view.
/// - `countAttacked(side) u16`: 1E9D:CE3E / CC4E, index into `standpat_bonus`.
/// - `threats(side, ply: i16, count: u16, counter: *u8) i16`: 0EF8:A026 / CD20;
///   writes 1 + threats found to `counter`.
/// - `kingSafety() i16`: 0000:2E72, White's view.
/// - `endgameKing(side) i16`: 1E9D:3416 / 35FB, White's view.
/// - `leafAttackMap(side)`: 2B9F:40A8 / 42DA, fills the leaf map (`LeafVars.leaf_map`).
/// - `leafTermA(side) i16`: 2B9F:4BFE / 5534, side-to-move view.
/// - `leafTermB(side) i16`: 2B9F:450E / 454C (result unused by the node).
/// - `pawnEndingTerm(side) i16`: 1E9D:1E30 / 16E4.
/// - `tablebase(side_arg: u16, ply: i16) bool`: 2B9F:BB76 (side_arg 1 from White).
///
/// The ply-2 node (`searchPly2`) calls a subset of these (no `poll`, `isRepetition`,
/// quiescence generators, `sortList` or leaf terms); the inputs of its time test D are
/// an argument, `Ply2Clock`.
pub fn Node(comptime Ctx: type) type {
    return NodeOf(Ctx, false);
}

/// The node's code. `ply2` = false is the general node (3AC6 / 5036); true is
/// root_move_search (2EC8), which differs only where `ply2` is tested.
fn NodeOf(comptime Ctx: type, comptime ply2: bool) type {
    return struct {
        const Self = @This();
        /// The class C fixes the node reads (DEV-035 only): `Ctx.node_fixes` if the
        /// context declares it, else the original.
        const node_fixes: pos.Fixes = if (@hasDecl(Ctx, "node_fixes")) Ctx.node_fixes else pos.Fixes.original;

        ctx: *Ctx,
        st: *State,
        side: Side,
        sg: i16,
        ply: i16,
        legal: *i16,

        // the original's frame, by offset
        beta: i16, // [bp+6]
        alpha: i16, // [bp+8]
        beta0: i16, // [bp-12h]
        best: i16 = 0, // SI
        child_legal: i16 = 0, // [bp-4]
        count: i16 = 0, // [bp-8]
        stage: u16 = 0, // [bp-0Ah]
        threat: i16 = 0, // [bp-0Ch]
        idx: i16 = 0, // [bp-0Eh]
        attacked: u16 = 0, // [bp-10h]
        pawn_term: i16 = 0, // [bp-1Ah]
        best_quiet: BestQuiet = .none, // [bp-1Eh]
        undo: Undo = .{}, // [bp-20h], [bp-2Ah]
        full_width: u8 = 0, // [bp-22h]
        counter: u8 = 0, // [bp-24h]
        reasons: u8 = 0, // [bp-26h]
        slot_depth: u8 = 0, // [bp-28h]
        saved_a6c2: u8 = 0, // [bp-2Ch]
        saved_9d8c: u8 = 0, // [bp-2Eh]
        saved_a5f5: u8 = 0, // [bp-30h]
        saved_8eb6: u8 = 0, // [bp-32h]
        undo_move: u16 = 0, // [bp-34h]
        saved_key: u48 = 0, // [bp-42h], the main key (DG:8CCC)
        saved_pawn_key: u48 = 0, // [bp-3Ch], the pawn key (DG:8CD2)
        bound: u8 = 0, // [bp-44h]
        hash_move: u16, // [bp-48h]
        hash_flag: u8 = 0, // [bp-46h]
        hash_index: u32 = 0, // [bp-4Ch]
        sums: [3]i16 = @splat(0), // [bp-14h], [bp-16h], [bp-18h]
        partial: i16 = 0, // [bp-6]
        clock: if (ply2) Ply2Clock else void = if (ply2) .{} else {},

        const BestQuiet = union(enum) { none, hash_move, list: u16 };
        const Label = enum { probe, l3D47, l3F1C, l3F22, hashmove, l4246, l4318, l4593, l464F, l45A3, l4662, l48D5, l4BC4, l4BCA, l4C1C, l40D6, l40E0, l4E64, l4F8E, ret0_ptr };
        const Next = union(enum) { go: Label, ret: i16 };

        /// One node (0000:3AC6 for White, 0000:5036 for Black): `legal` is the parent's
        /// "legal move seen" word ([bp+4]), beta and alpha are from the side to move's
        /// view. `stale_move_to` is the byte the original has at [bp-47h] on entry: the
        /// node clears only the low byte of the hash-move word, so when no move is
        /// stored the high byte, never written, goes into the hash entry (harmless: a
        /// move with from = 0 is no move). The replay passes the recorded byte; the
        /// engine passes 0.
        pub fn search(ctx: *Ctx, st: *State, side: Side, legal: *i16, beta: i16, alpha: i16, ply: i16, stale_move_to: u8) i16 {
            comptime std.debug.assert(!ply2);
            var n: Self = .{
                .ctx = ctx,
                .st = st,
                .side = side,
                .sg = if (side == white) 1 else -1,
                .ply = ply,
                .legal = legal,
                .beta = beta,
                .alpha = alpha,
                .beta0 = beta,
                .hash_move = @as(u16, stale_move_to) << 8,
            };
            return n.run();
        }

        /// Port of root_move_search (0000:2EC8-3AC5), the ply-2 node for either side:
        /// `(beta, alpha, side)` as the root passes them (-si, -hi, [717C]), the score
        /// from `side`'s view; `clock` holds the inputs of time test D. It is this node
        /// at ply 2 with the differences of docs/arch/32-root-move-search.md (Summary,
        /// 1-9), each marked `ply2` below.
        ///
        /// Two frame bytes are read before the routine writes them: `stale_move_to`,
        /// [bp-2Fh], the high byte of the hash move, which can reach the hash entry
        /// (DEV-034, as the node's [bp-47h]); and `stale_slot`, [bp-1Ah], make_move's
        /// captured-slot byte, which is unmake_move's input for a quiet move (it does not
        /// read it there; unmake_move writes it, 0 or 80h, before the principal variation
        /// reads it at 35E0/3888). The replay passes the recorded bytes; the engine
        /// passes 0, the owner's correction of uninitialised reads.
        pub fn searchPly2(ctx: *Ctx, st: *State, side: Side, beta: i16, alpha: i16, clock: Ply2Clock, stale_move_to: u8, stale_slot: u8) i16 {
            return NodeOf(Ctx, true).ply2Entry(ctx, st, side, beta, alpha, clock, stale_move_to, stale_slot);
        }

        fn ply2Entry(ctx: *Ctx, st: *State, side: Side, beta: i16, alpha: i16, clock: Ply2Clock, stale_move_to: u8, stale_slot: u8) i16 {
            comptime std.debug.assert(ply2);
            // No parent's legal-move word: setLegal does nothing at ply 2.
            var no_parent: i16 = 0;
            var n: Self = .{
                .ctx = ctx,
                .st = st,
                .side = side,
                .sg = if (side == white) 1 else -1,
                .ply = 2,
                .legal = &no_parent,
                .beta = beta,
                .alpha = alpha,
                .beta0 = beta,
                .hash_move = @as(u16, stale_move_to) << 8,
                .undo = .{ .captured_slot = stale_slot },
                .clock = clock,
            };
            return n.run();
        }

        inline fn run(n: *Self) i16 {
            var next: Next = n.entry();
            while (true) {
                switch (next) {
                    .ret => |v| return v,
                    .go => |l| next = switch (l) {
                        .probe => n.probe(),
                        .l3D47 => n.nullMove(),
                        .l3F1C => n.l3F1C(),
                        .l3F22 => n.l3F22(),
                        .hashmove => n.hashMoveFirst(),
                        .l4246 => n.l4246(),
                        .l4318 => n.leaf(),
                        .l4593 => n.quiescence(),
                        .l464F => n.l464F(),
                        .l45A3 => n.standPatCutoff(),
                        .l4662 => n.standPat(),
                        .l48D5 => n.generatorChoice(),
                        .l4BC4 => if (n.count != 0) .{ .go = .l4C1C } else .{ .go = .l4BCA },
                        .l4BCA => n.l4BCA(),
                        .l4C1C => n.moveLoop(),
                        .l40D6 => n.l40D6(),
                        .l40E0 => n.l40E0(),
                        .l4E64 => n.quiescenceEnd(),
                        .l4F8E => n.l4F8E(),
                        .ret0_ptr => blk: {
                            n.setLegal();
                            break :blk .{ .ret = 0 };
                        },
                    },
                }
            }
        }

        // ---- helpers ---------------------------------------------------------------

        fn w(x: i32) i16 {
            return @truncate(x);
        }
        fn s8(x: u8) i16 {
            return @as(i8, @bitCast(x));
        }
        fn uw(x: i16) u16 {
            return @bitCast(x);
        }
        fn other(self: *const Self) Side {
            return self.side ^ 1;
        }
        fn pu(self: *const Self) usize {
            return @intCast(self.ply);
        }
        fn H(self: *const Self) i16 {
            return self.st.horizon;
        }
        fn setLegal(self: *Self) void {
            if (ply2) return; // 2EC8 has no parent's legal word
            self.legal.* = self.ply;
        }
        /// The square of the opponent's king ([A051] for White, [A041] for Black).
        fn oppKing(self: *const Self) u8 {
            return self.st.p.piece_list[@as(usize, self.other()) * 16 + 7];
        }
        fn ownNonpawn(self: *const Self) i16 {
            return @as(i16, @bitCast(self.st.p.piece_material[self.side]));
        }
        fn oppNonpawn(self: *const Self) i16 {
            return @as(i16, @bitCast(self.st.p.piece_material[self.other()]));
        }
        /// Extension byte of ply `i`; plies -3..-1 read the bytes below the array, -4 the
        /// Black pawn count, as in the original.
        fn extAt(self: *const Self, i: i16) u8 {
            if (i >= 0) return self.st.extension[@intCast(i)];
            if (i >= -3) return self.st.ext_below[@intCast(i + 3)];
            std.debug.assert(i == -4);
            return self.st.p.side_pawn_count[1];
        }
        /// H and the three limits move together.
        fn ext(self: *Self, d: i16) void {
            self.st.horizon = @truncate(@as(i16, self.st.horizon) +% d);
            self.extLimits(d);
        }
        fn extLimits(self: *Self, d: i16) void {
            self.st.tv.ply_limit1 +%= d;
            self.st.tv.ply_limit2 +%= d;
            self.st.tv.ply_limit3 +%= d;
        }
        /// B(781A + W(1A80 + 2*from) + to) = value, from and to sign-extended. The move
        /// is always one of a move list or the hash move the node has just made (the
        /// killer `DG:3790` holds only such moves), so from and to are board squares and
        /// the index is at most 4,892 + 97 = 4,989 (from h8 to g8): inside the table's
        /// 4,990 bytes, which the index check of Debug and ReleaseSafe confirms.
        fn mark(self: *Self, mv: u16, value: u8) void {
            const frm: i16 = s8(@truncate(mv));
            const to: i16 = s8(@truncate(mv >> 8));
            const row = self.st.mark_row[@intCast(frm)];
            self.st.sv.marks[row +% uw(to)] = value;
        }
        fn undoExt41D2(self: *Self) void {
            const p = self.pu();
            const e = self.st.extension[p];
            if (e == 0) return;
            self.ext(-1);
            if (e == 2) self.ext(-1);
            self.st.extension[p] = 0;
        }
        fn adjacent(self: *const Self) bool {
            const d: i16 = @as(i16, self.st.p.piece_list[7]) - @as(i16, self.st.p.piece_list[23]);
            return self.st.king_adjacent[@intCast(119 + d)] != 0;
        }
        fn halve(self: *const Self, s: i16) i16 {
            if (self.st.ev.ply_flag[atRoom(room_last_irrev, self.pu())] == 0 and w(@as(i32, @as(i16, @bitCast(self.st.p.game_ply))) - @as(i16, @bitCast(self.st.ev.last_irreversible_ply))) >= 0x50) return s >> 1;
            return s;
        }
        fn adjust(self: *const Self, s0: i16) i16 {
            var s = s0;
            if (self.st.ev.passer_flags & 2 != 0) s -%= 0x578; // UNVERIFIED in the null move (B7); proved in the leaf
            if (self.st.ev.promotion_flags & 1 != 0) s +%= 0x4B0; // UNVERIFIED in the null move (B7); proved for Black in the leaf
            return s;
        }
        fn listMove(self: *const Self, i: u16) Move {
            return self.st.move_list[self.pu()][i];
        }
        fn word(mv: Move) u16 {
            return @as(u16, mv.from) | @as(u16, mv.to) << 8;
        }
        fn hashMoveAsMove(self: *const Self) Move {
            return .{ .from = @truncate(self.hash_move), .to = @truncate(self.hash_move >> 8), .flag = self.hash_flag, .score = 0 };
        }
        /// The slot index of the probe (B6 step 14) for the current keys.
        fn slotIndex(self: *const Self) u32 {
            const st = self.st;
            if (s8(st.conv_tables) > 1) {
                // UNVERIFIED: the conventional-memory tables never ran (16-bit index, carry lost).
                var v: u16 = st.conv_mask & keyWord(st.p.hash_key, 2);
                if (st.hash_size_mode != 0) v = ((v >> 1) +% v) >> 1;
                return v;
            }
            return hashIndexOfKey(st.p.hash_key, st.hash_mask, st.hash_size_mode);
        }
        /// After the move into the child is made, its keys are final (make_move's
        /// castling-key XORs included): the hint for the child's probe, under the
        /// probe's own test at the child (B6 step 13: L1 > ply + 1, the tables present,
        /// no e.p. square at ply + 1). Changes no state.
        fn prefetchChild(self: *Self) void {
            const st = self.st;
            if (st.tv.ply_limit1 > self.ply + 1 and st.hash_enabled != 0 and st.p.ep_square_by_ply[atRoom(room_ep, self.pu() + 1)] == 0)
                self.ctx.prefetchProbe(self.other(), self.slotIndex());
        }
        fn restoreAfterUnmake(self: *Self) void {
            self.st.p.hash_key = self.saved_key;
            self.st.p.pawn_hash_key = self.saved_pawn_key;
            self.st.p.piece_square_sum = @bitCast(self.sums[0]);
            self.st.ev.pawn_square_sum[0] = @bitCast(self.sums[1]);
            self.st.ev.pawn_square_sum[1] = @bitCast(self.sums[2]);
        }
        fn childSearch(self: *Self) i16 {
            return 0 -% self.ctx.child(self.other(), &self.child_legal, 0 -% self.best, 0 -% self.beta, self.ply + 1);
        }
        /// 4004 / 4C52, the tablebase test. UNVERIFIED: never ran ([239C] was 10).
        fn tbTest(self: *Self, flag: u8) ?i16 {
            if (s8(self.st.p.men) < 5 and self.st.tb_setting >= 0x0B) {
                if ((uw(s8(self.undo.captured)) | flag) != 0) {
                    if (self.ctx.tablebase(if (self.side == white) 1 else 0, self.ply)) {
                        const v = 0 -% self.st.tb_score;
                        self.child_legal +%= 1;
                        self.st.pv_end[self.pu() + 1] = @truncate(uw(self.ply));
                        return v;
                    }
                }
            }
            return null;
        }
        /// 3138-3141 and 3489-3492 (ply 2 only, difference 5): an exact hash hit or a
        /// null-move fail high with a hash move leaves that move, the whole word, as the
        /// one-move PV of row 2: W(93FA) = move, B(AAF8) = 2.
        fn pvHashMove(self: *Self) void {
            self.st.pv[2][0] = self.hash_move;
            self.st.pv_end[2] = 2;
        }
        /// 4D62 / 417C: the PV word and the copy of the child's row.
        fn pvUpdate(self: *Self, mvword: u16) void {
            const p = self.pu();
            const ax = ((@as(u16, self.st.p.check_by_ply[atRoom(room_check, p + 1)]) << 8 | self.undo.captured_slot) & 0x8080) | mvword;
            self.st.pv[p][0] = ax;
            const al = self.st.pv_end[p + 1];
            self.st.pv_end[p] = al;
            const n = s8(al) - self.ply;
            if (n > 0) {
                const bytes = std.mem.asBytes(&self.st.pv);
                const dst = p * 0x4A + 2;
                const src = (p + 1) * 0x4A;
                const len: usize = @intCast(n * 2);
                std.mem.copyForwards(u8, bytes[dst..][0..len], bytes[src..][0..len]);
            }
        }

        // ---- B1-B5 entry --------------------------------------------------------------

        fn entry(self: *Self) Next {
            const st = self.st;
            st.node_count +%= 1;
            st.pv_end[self.pu()] = @truncate(uw(self.ply - 1));
            if (ply2) {
                // 2EEA: time test D (difference 1). 2EC8 has no B2, B3 or B4: the root
                // has tested repetition and material, ply 2 is below the ceiling, and
                // it does not poll the keyboard.
                if (self.timeTestD()) return .{ .ret = self.alpha };
            } else {
                // B2 insufficient material. UNVERIFIED: never ran.
                if (st.p.pawn_count == 0 and st.p.piece_material_sum <= 0x2BC) {
                    if (st.p.piece_count[self.side] != 0) {
                        if (self.ctx.attacks(self.side, self.oppKing())) return .{ .ret = 0x4E20 };
                    } else if (self.adjacent()) return .{ .ret = 0x4E20 };
                    return .{ .go = .ret0_ptr };
                }
                // B3 ply ceiling
                if (!(st.ply_ceiling > self.ply)) return .{ .go = .l4318 };
                // B4 keyboard poll
                if (st.poll_pending != 0) self.ctx.poll();
            }
            // B5 repetition and the 50-move rule; 2F4A-2FAC at ply 2, which does not
            // test [1E08] (difference 9) or repetition.
            if (ply2 or st.mode_1e08 == 0) {
                const p = self.pu();
                // The key's three words, which is the 48-bit key itself.
                st.lv.key_history[atRoom(room_key_history, p)] = st.p.hash_key;
                if (st.p.reversible_by_ply[atRoom(room_reversible, p)] == 0) {
                    st.ev.ply_flag[atRoom(room_last_irrev, p)] = @truncate(uw(self.ply));
                } else {
                    st.ev.ply_flag[atRoom(room_last_irrev, p)] = st.ev.ply_flag[atRoom(room_last_irrev, p - 1)];
                    if (!ply2 and self.ctx.isRepetition(self.ply)) return .{ .go = .ret0_ptr };
                }
                if (st.ev.ply_flag[atRoom(room_last_irrev, p)] == 0 and w(@as(i32, @as(i16, @bitCast(st.p.game_ply))) - @as(i16, @bitCast(st.ev.last_irreversible_ply))) > 100) {
                    // UNVERIFIED at ply 2 (2F79-2FAC): never ran.
                    if (self.ctx.attacks(self.side, self.oppKing())) return .{ .ret = 0x4E20 };
                    return .{ .go = .ret0_ptr };
                }
            }
            return .{ .go = .probe };
        }

        /// 2EEA-2F46, test D (ply 2 only): if the root recorded an elapsed time at the
        /// start of this iteration ([A356] non-zero), and neither pondering ([3676]) nor
        /// the single-move control ([1480]) is on, stop when 5 x elapsed >= 3 x base,
        /// both products modulo 2^32 and compared as signed 32-bit numbers; set the stop
        /// flag. The caller returns alpha (2F43). Proved on 71 tests (10 fired); the
        /// case 5 x elapsed = 3 x base never occurred.
        fn timeTestD(self: *Self) bool {
            const c = self.clock;
            if (c.iter_start_elapsed == 0 or c.pondering != 0 or c.single_move != 0) return false;
            const b3: i32 = @bitCast(c.base_time *% 3);
            const e5: i32 = @bitCast(c.iter_start_elapsed *% 5);
            if (e5 < b3) return false;
            self.st.stop = 1;
            return true;
        }

        // ---- B6 hash probe ------------------------------------------------------------

        fn probe(self: *Self) Next {
            const st = self.st;
            self.slot_depth = 0xCE;
            self.hash_move &= 0xFF00;
            // 2FB8: the ply-2 node does not test L1 > ply (difference 7).
            if ((!ply2 and !(st.tv.ply_limit1 > self.ply)) or st.hash_enabled == 0 or st.p.ep_square_by_ply[atRoom(room_ep, self.pu())] != 0) return .{ .go = .l3D47 };
            const k0 = keyWord(st.p.hash_key, 0);
            const k1 = keyWord(st.p.hash_key, 1);
            const i = self.slotIndex();
            self.hash_index = i;
            self.ctx.probe(self.side, i);
            const e = &st.hash_entry;
            self.bound = e[8] & 0xC0;
            if (self.bound == 0) return .{ .go = .l3D47 };
            self.slot_depth = e[8] & 0x3F;
            if (std.mem.readInt(u16, e[2..4], .little) != k0 or std.mem.readInt(u16, e[4..6], .little) != k1 or
                ((keyByte4(st.p.hash_key) ^ e[9]) & 0xFC) != 0) return .{ .go = .l3D47 };
            self.hash_move = std.mem.readInt(u16, e[6..8], .little);
            if (@as(u8, @truncate(self.hash_move)) != 0) {
                if (!self.ctx.hashMovePlausible(self.side, &self.hash_move)) {
                    self.hash_move &= 0xFF00;
                    self.slot_depth = 0xCE;
                }
            }
            if (self.H() - self.ply > s8(self.slot_depth)) return .{ .go = .l3D47 };
            const si: i16 = @bitCast(std.mem.readInt(u16, e[0..2], .little));
            self.best = si;
            if (self.bound == 0x40) {
                if (ply2) {
                    // 3130-3146 (difference 5): with a move, a one-move PV; without one,
                    // the score is returned only outside the window.
                    if (@as(u8, @truncate(self.hash_move)) != 0) {
                        self.pvHashMove();
                        return .{ .ret = si };
                    }
                    if (self.alpha >= si or !(self.beta0 > si)) return .{ .ret = si };
                    return .{ .go = .l3D47 };
                }
                self.setLegal();
                return .{ .ret = si };
            }
            if (self.bound == 0xC0) {
                self.setLegal();
                if (!(self.beta0 > si)) return .{ .ret = self.beta0 };
                if (!(self.alpha >= si)) self.alpha = si;
                return .{ .go = .l3D47 };
            }
            if (!(self.alpha < si)) {
                // UNVERIFIED at ply 2 (3176): the upper-bound return never ran there.
                self.setLegal();
                return .{ .ret = self.alpha };
            }
            if (self.beta0 > si) self.beta = si +% 1;
            return .{ .go = .l3D47 };
        }

        // ---- B7 null move -------------------------------------------------------------

        fn nullMove(self: *Self) Next {
            const st = self.st;
            const p = self.pu();
            self.best = self.alpha;
            self.child_legal = self.ply;
            self.best_quiet = .none;
            self.count = 0;
            const own_np = self.ownNonpawn();
            if (st.p.check_by_ply[atRoom(room_check, p)] != 0 or !(own_np > 0x28A) or st.p.pawn_count == 0) return .{ .go = .l3F22 };
            const h = self.H();
            if (ply2) {
                // 31BB (difference 6): the iteration, not H > ply, and no [1E08] test.
                if (!(st.tv.iteration > 2)) return .{ .go = .l3F22 };
            } else {
                if (!(h > self.ply) or st.mode_1e08 != 0) return .{ .go = .l3F22 };
            }
            if (own_np >= 0x7D0) {
                if (self.ctx.attacks(self.side, self.oppKing())) return .{ .ret = 0x4E20 };
                self.setLegal();
            } else {
                if (!(own_np > 0x2BC)) {
                    if (self.ply + 2 > h) return .{ .go = .l3F22 };
                }
                if (st.killer[p] != 0) self.mark(st.killer[p], 3);
                const c = self.ctx.generate(.all, self.side, self.ply);
                self.count = @bitCast(c);
                if (c == 0xFFFF) return .{ .ret = 0x4E20 };
                self.setLegal();
                if (c == 0) return .{ .ret = 0 };
                self.full_width = 1;
                if (!(self.count >= 0x0E)) return .{ .go = .l3F22 };
            }
            self.pawn_term = self.ctx.pawnEval(self.side);
            var d: i16 = self.sg *% self.ctx.staticEval(self.side, 0);
            if (st.ev.draw_flag != 0) return .{ .go = .l3F1C };
            d = self.halve(d); // UNVERIFIED here: never ran in the null move
            d = self.adjust(d);
            const b0 = self.beta0;
            if (!(b0 +% 0xF0 < d)) {
                if (!(b0 -% 0x140 <= d)) return .{ .go = .l3F1C };
                const r = self.ctx.pieceEval(self.side, self.ply) +% self.pawn_term;
                d = d +% self.sg *% r;
                if (!(d >= b0 -% 0xA0)) return .{ .go = .l3F1C };
            }
            // 3E97: R
            var inc = false;
            // 33CB: at ply 2 also R = 2 from the eighth iteration (difference 6).
            // (Decided R once in the recordings: rookminor9.zst.)
            if ((ply2 and st.tv.iteration >= 8) or self.count > 0x18 or own_np >= 0xC1C) {
                inc = true;
            } else if (own_np >= 0x7D0) {
                inc = if (self.side == white) !(@as(i16, @bitCast(st.p.piece_balance)) < -0x32) else !(@as(i16, @bitCast(st.p.piece_balance)) > 0x32);
            }
            const R: i16 = if (inc) 2 else 1;
            self.ext(-R);
            // The null move's child probes the other side's table with the keys as they
            // are (1E9D:16BE changes no key and clears the child's e.p. square).
            if (st.tv.ply_limit1 > self.ply + 1 and st.hash_enabled != 0) self.ctx.prefetchProbe(self.other(), self.slotIndex());
            self.ctx.makeNull(self.ply + 1);
            const v = 0 -% self.ctx.child(self.other(), &self.child_legal, 1 -% b0, 0 -% b0, self.ply + 1);
            st.p.game_ply -%= 1;
            self.ext(R);
            if (!(self.beta0 > v)) {
                self.best = v;
                // 3489 (difference 5): with a hash move, it is the PV of row 2.
                if (ply2 and @as(u8, @truncate(self.hash_move)) != 0) self.pvHashMove();
                return .{ .ret = v };
            }
            return .{ .go = .l3F1C };
        }

        fn l3F1C(self: *Self) Next {
            self.child_legal = self.ply;
            return .{ .go = .l3F22 };
        }

        // ---- B8, B9 -------------------------------------------------------------------

        fn l3F22(self: *Self) Next {
            const st = self.st;
            const p = self.pu();
            self.sums = .{ @bitCast(st.p.piece_square_sum), @as(i16, @bitCast(st.ev.pawn_square_sum[0])), @as(i16, @bitCast(st.ev.pawn_square_sum[1])) };
            self.undo_move = st.p.reversible_by_ply[atRoom(room_reversible, p)] & st.p.quiet_move_by_ply[atRoom(room_quiet_move, p - 1)];
            self.saved_key = st.p.hash_key;
            self.saved_pawn_key = st.p.pawn_hash_key;
            if (@as(u8, @truncate(self.hash_move)) == 0) return .{ .go = .l4246 };
            // 325F: the ply-2 node keeps the hash move whatever H (difference 7).
            if (!ply2 and self.H() < self.ply) {
                self.hash_move &= 0xFF00;
                return .{ .go = .l4246 };
            }
            return .{ .go = .hashmove };
        }

        fn hashMoveFirst(self: *Self) Next {
            const st = self.st;
            const p = self.pu();
            self.hash_flag = 0;
            self.setLegal();
            // B9 step 44: the bits come from the shared buffer, not this node's probe.
            const e = st.hash_entry[9] & 3;
            st.extension[p] = e;
            if (e != 0) {
                self.ext(1);
                if (e == 2) self.ext(1);
            }
            self.ctx.applyMove(self.side, self.ply + 1, self.hashMoveAsMove(), &self.undo);
            self.prefetchChild();
            var v: i16 = undefined;
            while (true) {
                if (self.hash_move == self.undo_move and self.undo.captured == 0) {
                    if (self.best >= -1) {
                        v = -1;
                    } else {
                        v = self.childSearch();
                        if (v > -1) v = -1;
                    }
                } else {
                    v = self.tbTest(self.hash_flag) orelse self.childSearch();
                }
                if (v > self.best and self.beta0 > self.beta) {
                    self.beta = self.beta0;
                    continue;
                }
                break;
            }
            self.ctx.unmake(self.side, self.hashMoveAsMove(), &self.undo);
            self.restoreAfterUnmake();
            if (v > self.best) {
                self.best = v;
                if (!(self.beta0 > v)) {
                    if (self.undo.captured == 0 and st.p.check_by_ply[atRoom(room_check, p)] == 0) st.killer[p] = self.hash_move;
                    return .{ .go = .l40D6 };
                }
                self.beta = v +% 1;
                self.best_quiet = if (self.undo.captured != 0) .none else .hash_move;
                self.pvUpdate(self.hash_move);
            }
            if (st.stop != 0) {
                self.undoExt41D2();
                return .{ .ret = self.best };
            }
            self.undoExt41D2();
            return .{ .go = .l4246 };
        }

        // ---- B10, B11 -----------------------------------------------------------------

        fn l4246(self: *Self) Next {
            const st = self.st;
            const p = self.pu();
            if (st.p.check_by_ply[atRoom(room_check, p)] != 0) {
                const c = self.ctx.generate(.evasions, self.side, self.ply);
                self.count = @bitCast(c);
                if (c == 0xFFFF) return .{ .ret = 0x4E20 }; // UNVERIFIED at ply 2: never ran
                self.setLegal();
                // 3674: mate at ply 2 is B1E2h = -19998, the general node's ply - 20000
                // at ply 2 (DEV-036 read B1E2h as -20000; the port returned -20000 until
                // 2026-11-20). UNVERIFIED at ply 2: never ran.
                if (c == 0) return .{ .ret = if (ply2) mate_ply2 else self.ply -% 0x4E20 };
                self.full_width = 1;
                // 367E-3695: no L1 > ply test at ply 2 (difference 7).
                // At ply 2 with no pawns: proved (pawnless.zst, 13 times); [1E08] never ran.
                if ((!ply2 and !(st.tv.ply_limit1 > self.ply)) or st.p.pawn_count == 0 or st.mode_1e08 != 0) return .{ .go = .l4C1C };
                self.ext(1);
                st.extension[p] +%= 1;
                // No H >= ply test at ply 2 (difference 7).
                if (self.count > 2 or (!ply2 and self.H() < self.ply)) return .{ .go = .l4C1C };
                if (self.ply >= 6 and s8(self.extAt(self.ply - 2)) + s8(self.extAt(self.ply - 4)) >= 3) return .{ .go = .l4C1C };
                if (self.count > 1) {
                    if (self.side == white) {
                        if (!(st.p.piece_list[7] >= 0x29)) return .{ .go = .l4C1C };
                    } else {
                        if (!(st.p.piece_list[23] <= 0x4E)) return .{ .go = .l4C1C };
                    }
                }
                self.ext(1);
                st.extension[p] +%= 1;
                return .{ .go = .l4C1C };
            }
            // 36E4: no quiescence or leaf at ply 2; the list of the null-move test is
            // used if there is one (UNVERIFIED at ply 2: never happened), else generate.
            if (ply2) return if (self.count != 0) .{ .go = .l4C1C } else .{ .go = .l4BCA };
            const h = self.H();
            if (s8(qsMaxPly(st, @intCast(h))) < self.ply) return .{ .go = .l4318 };
            if (h >= self.ply) return .{ .go = .l4BC4 };
            return .{ .go = .l4593 };
        }

        // ---- B12 leaf -----------------------------------------------------------------

        fn leaf(self: *Self) Next {
            const st = self.st;
            const sg = self.sg;
            const side = self.side;
            if (st.mode_1e08 != 0) {
                // UNVERIFIED: the [1E08] mode never ran.
                if (st.p.piece_count[side] != 0) {
                    self.ctx.leafAttackMap(side);
                    if (st.lv.leaf_map[self.oppKing()] != 0) return .{ .ret = 0x4E20 };
                } else if (self.adjacent()) return .{ .ret = 0x4E20 };
                self.setLegal();
                return .{ .ret = sg *% @as(i16, @bitCast(st.p.material_balance)) };
            }
            if (st.p.piece_count[side] != 0) {
                self.ctx.leafAttackMap(side);
                if (st.lv.leaf_map[self.oppKing()] != 0) return .{ .ret = 0x4E20 };
                self.setLegal();
                self.pawn_term = self.ctx.pawnEval(side);
                var si: i16 = sg *% self.ctx.staticEval(side, 0);
                if (st.ev.draw_flag != 0) return .{ .ret = si };
                si = self.adjust(self.halve(si));
                const b0 = self.beta0;
                if (!(b0 +% 0x140 >= si)) return .{ .ret = si };
                si +%= self.ctx.leafTermA(side);
                if (!(si >= self.alpha -% 0x140)) return .{ .ret = si };
                if (!(si <= b0 +% 0x140)) return .{ .ret = si };
                si +%= sg *% (self.ctx.pieceEval(side, self.ply) +% self.pawn_term);
                if (!(si > self.alpha -% 0xA0)) return .{ .ret = si };
                if (!(si < b0 +% 0xA0)) return .{ .ret = si };
                if (st.ev.no_pawns_at_root != 0) return .{ .ret = si };
                si +%= sg *% self.ctx.kingSafety();
                if (self.oppNonpawn() > 0xE10) return .{ .ret = si };
                return .{ .ret = si +% sg *% self.ctx.endgameKing(side) };
            }
            if (@as(i16, @bitCast(st.p.material[self.other()])) != 0) {
                if (self.adjacent()) return .{ .ret = 0x4E20 };
                self.setLegal();
                self.pawn_term = self.ctx.pawnEval(side);
                var si: i16 = sg *% self.ctx.staticEval(side, 0);
                if (st.ev.draw_flag != 0) return .{ .ret = si };
                si = self.adjust(self.halve(si));
                _ = self.ctx.leafTermB(side);
                const t4e = self.ctx.leafTermA(side);
                const ax = self.ctx.pieceEval(side, self.ply);
                si +%= if (side == white) ax +% t4e +% self.pawn_term else (0 -% (ax -% t4e)) -% self.pawn_term;
                const b0 = self.beta0;
                if (!(si > self.alpha -% 0xA0)) return .{ .ret = si };
                if (!(si < b0 +% 0xA0)) return .{ .ret = si };
                if (st.ev.no_pawns_at_root != 0) return .{ .ret = si };
                // The two functions call these in a different order (specification, mirror table).
                const first = if (side == white) self.ctx.pawnEndingTerm(side) else self.ctx.endgameKing(side);
                const tmp = si -% first;
                const second = if (side == white) self.ctx.endgameKing(side) else self.ctx.pawnEndingTerm(side);
                return .{ .ret = tmp +% sg *% second };
            }
            // The other side bare, this side with pawns only. The kings-adjacent exit and
            // the evaluation are proved by whole searches. The return of 0 below needs both
            // sides bare, which the node's entry answers first (B2: 3AF1 White, 5061 Black).
            // UNVERIFIED: the return of 0 for bare kings cannot run (docs/UNVERIFIED.md).
            if (self.adjacent()) return .{ .ret = 0x4E20 };
            self.setLegal();
            self.pawn_term = self.ctx.pawnEval(side);
            if (@as(i16, @bitCast(st.p.material[side])) == 0) return .{ .ret = 0 };
            const si = self.halve(sg *% self.ctx.staticEval(side, 0));
            var a: i16 = undefined;
            var b: i16 = undefined;
            if (side == white) {
                a = self.ctx.endgameKing(side);
                b = self.ctx.pieceEval(side, self.ply);
            } else {
                a = self.ctx.pieceEval(side, self.ply);
                b = self.ctx.endgameKing(side);
            }
            return .{ .ret = si +% sg *% (b +% a +% self.pawn_term) };
        }

        // ---- B13 quiescence before the stand-pat --------------------------------------

        fn quiescence(self: *Self) Next {
            const st = self.st;
            if (st.mode_1e08 != 0) {
                // UNVERIFIED: the [1E08] mode never ran.
                const si = self.sg *% @as(i16, @bitCast(st.p.material_balance));
                if (!(si < self.beta0)) return .{ .go = .l45A3 };
                self.partial = si;
                self.best = self.alpha;
                st.ev.black_king_by_passer = 0;
                st.sv.bishop_hint = 0;
                st.sv.rook_hint = 0;
                st.sv.queen_hint = 0;
                const c = self.ctx.generate(.q1, self.side, self.ply);
                return self.afterQgen(c);
            }
            if (st.p.pawn_count == 0 and st.tv.ply_limit1 < self.ply) {
                const bal = @as(i16, @bitCast(st.p.piece_balance));
                if (if (self.side == white) bal > 0 else bal < 0) return .{ .go = .l4318 };
            }
            if (self.ownNonpawn() == 0 and st.tv.ply_limit2 > self.ply) {
                if (st.tv.ply_limit1 >= self.ply) {
                    if (@as(i16, @bitCast(st.p.material[self.side])) == 0 or self.oppNonpawn() >= 0x44C) return .{ .go = .l464F };
                }
                if (st.p.piece_material_sum == 0 and st.both_had_pieces != 0 and
                    (st.tv.ply_limit1 >= self.ply or s8(self.extAt(self.ply - 2)) < 2) and s8(self.extAt(self.ply - 3)) < 2)
                {
                    self.ext(1);
                    st.extension[self.pu()] = 3;
                    return .{ .go = .l464F };
                }
            }
            return .{ .go = .l4662 };
        }

        fn l464F(self: *Self) Next {
            self.best = self.alpha;
            self.beta = self.beta0;
            self.hash_move &= 0xFF00;
            return .{ .go = .l4BCA };
        }

        fn standPatCutoff(self: *Self) Next {
            if (self.legal.* == self.ply) return .{ .ret = self.beta0 };
            if (self.ctx.attacks(self.side, self.oppKing())) return .{ .ret = 0x4E20 };
            self.setLegal();
            return .{ .ret = self.beta0 };
        }

        fn threatsTerm(self: *Self) void {
            self.threat +%= self.ctx.threats(self.side, self.ply, self.attacked, &self.counter);
        }

        // ---- B14 staged stand-pat -----------------------------------------------------

        fn standPat(self: *Self) Next {
            const st = self.st;
            const sg = self.sg;
            const side = self.side;
            self.threat = 0;
            self.reasons = 0;
            self.counter = 0;
            self.pawn_term = self.ctx.pawnEval(side);
            self.attacked = self.ctx.countAttacked(side);
            const ev = self.ctx.staticEval(side, self.ply -% st.tv.ply_limit2);
            var si: i16 = st.standpat_bonus[self.attacked] +% sg *% ev;
            self.saved_a5f5 = st.ev.passer_flags;
            self.saved_8eb6 = st.ev.weak_pawns;
            si = self.halve(si);
            const a5 = st.ev.passer_flags;
            if (a5 != 0) {
                var pen: enum { none, c, c4719, d } = .none;
                if (st.tv.ply_limit3 >= self.ply) {
                    if ((a5 & 2) != 0 or ((a5 & 0x10) != 0 and @as(i16, @bitCast(st.p.total_material)) == 0x514)) {
                        pen = .c;
                    } else if (st.tv.ply_limit2 > self.ply) {
                        self.reasons +%= 1;
                        if (a5 & 0x17 != 0) {
                            pen = .c4719;
                        } else {
                            self.threat = sg *% -400;
                            pen = .d;
                        }
                    }
                } else if (st.p.piece_material_sum <= 0x44C and (a5 & 2) != 0 and s8(st.p.pawn_count) < 6 and st.tv.ply_limit3 +% 2 >= self.ply) {
                    pen = .c; // UNVERIFIED for White (ran once for Black)
                }
                if (pen == .c or pen == .c4719) {
                    if (pen == .c) self.reasons +%= 1;
                    self.threat = sg *% -4000;
                    pen = .d;
                }
                if (pen == .d and st.ev.promotion_flags != 0) self.reasons +%= 10;
            }
            if (st.ev.draw_flag != 0) {
                self.stage = 3;
                self.partial = si;
                self.best = self.alpha;
                return .{ .go = .l48D5 };
            }
            if (!(self.oppNonpawn() > 0xE10)) {
                si +%= sg *% self.ctx.endgameKing(side);
                const a = st.ev.passer_flags;
                if (a != 0 and st.tv.ply_limit3 >= self.ply) {
                    var go = false;
                    if (st.tv.ply_limit1 >= self.ply) {
                        go = true;
                    } else if (!(self.ownNonpawn() > 0x2BC) or s8(a) > 0x0A) {
                        if (st.tv.ply_limit2 >= self.ply or self.ownNonpawn() == 0) go = true;
                    }
                    if (go) {
                        self.reasons +%= 1;
                        self.threat -%= if (self.ownNonpawn() != 0) sg *% 300 else sg *% 600;
                        if (s8(a) > 0x0A) {
                            self.threat -%= sg *% 4000;
                            self.reasons +%= 10;
                        }
                    }
                }
                st.ev.passer_flags = self.saved_a5f5;
            }
            const b0 = self.beta0;
            if (!(b0 +% 0x140 >= si)) {
                self.threatsTerm();
                si +%= sg *% self.threat;
                if (si > b0 +% 0x140) return .{ .go = .l45A3 };
            }
            var stage: u16 = undefined;
            if (b0 -% 0x140 >= si) {
                stage = 0;
            } else {
                si +%= sg *% self.ctx.pieceEval(side, self.ply);
                if (si > b0 +% 0xF0) {
                    if (self.counter != 0) return .{ .go = .l45A3 };
                    self.threatsTerm();
                    si +%= sg *% self.threat;
                    if (si > b0 +% 0xF0) return .{ .go = .l45A3 };
                }
                if (b0 -% 0xF0 >= si) {
                    stage = 1;
                } else {
                    si +%= sg *% self.pawn_term;
                    if (si > b0 +% 0xA0) {
                        if (self.counter != 0) return .{ .go = .l45A3 };
                        self.threatsTerm();
                        si +%= sg *% self.threat;
                        if (si > b0 +% 0xA0) return .{ .go = .l45A3 };
                    }
                    if (b0 -% 0xA0 >= si or st.ev.no_pawns_at_root != 0) {
                        stage = 2;
                    } else {
                        si +%= sg *% self.ctx.kingSafety();
                        if (si < b0) {
                            stage = 3;
                        } else {
                            if (self.counter != 0) return .{ .go = .l45A3 };
                            self.threatsTerm();
                            si +%= sg *% self.threat;
                            if (!(si < b0)) return .{ .go = .l45A3 };
                            // 48AB: the full stand-pat raises the floor
                            self.stage = 3;
                            self.partial = si;
                            self.best = if (self.alpha <= si) si else self.alpha;
                            return .{ .go = .l48D5 };
                        }
                    }
                }
            }
            self.stage = stage;
            self.partial = si;
            self.best = self.alpha;
            return .{ .go = .l48D5 };
        }

        // ---- B15 generator choice -----------------------------------------------------

        fn generatorChoice(self: *Self) Next {
            const st = self.st;
            const own_np = self.ownNonpawn();
            if (st.tv.ply_limit3 < self.ply) {
                if (st.tv.ply_limit3 +% 1 < self.ply or own_np > 0x28A) {
                    st.sv.check_flag = if (st.tv.ply_limit3 +% 2 > self.ply) 1 else 0;
                    return self.afterQgen(self.ctx.generate(.q4, self.side, self.ply));
                }
                // 9528 in place of 4954 (falls to 490A, where L2 < ply holds)
            }
            if (st.tv.ply_limit2 < self.ply) {
                st.sv.check_flag = if (own_np <= 0xC1C) 1 else 0;
                return self.afterQgen(self.ctx.generate(.q3, self.side, self.ply));
            }
            if (st.tv.ply_limit1 < self.ply) {
                const own_pawns = if (self.side == white) st.p.side_pawn_count[1] else st.p.side_pawn_count[0];
                if (!(st.p.piece_material_sum == 0 and s8(own_pawns) <= 2)) {
                    st.sv.rook_hint = 0;
                    const kf: usize = @intCast(s8(st.p.king_file[self.other()]));
                    const pf = if (self.side == white) &st.p.pawns_per_file[1] else &st.p.pawns_per_file[0];
                    if (pf[kf] == 0) st.sv.rook_hint = 1;
                    return self.afterQgen(self.ctx.generate(.q2, self.side, self.ply));
                }
                // Otherwise 579A in place of 25A0.
            }
            st.sv.bishop_hint = st.ev.promotion_square;
            st.sv.rook_hint = 0;
            st.sv.queen_hint = 0;
            if (st.tv.iteration > 1 and own_np >= 0x708) self.hints579A();
            return self.afterQgen(self.ctx.generate(.q1, self.side, self.ply));
        }

        fn hints579A(self: *Self) void {
            const st = self.st;
            const B = &st.p.board;
            const W = self.side == white;
            // (square in front, queen code, file guard, back square, map guard, target)
            const Pat = struct { sq2: u8, code: u8, g1: u8, sq1: u8, g2: u8, target: u16 };
            const q_ok = if (W) st.p.piece_list[0x16] <= 0x26 else (st.p.piece_list[6] >= 0x51 and st.p.piece_list[6] <= 0x58);
            const pats: [2]Pat = if (W) .{
                .{ .sq2 = 0x20, .code = 0x0C, .g1 = st.p.pawns_per_file[0][2], .sq1 = 0x16, .g2 = st.p.king_rays[1][0x16], .target = 0x16 },
                .{ .sq2 = 0x25, .code = 0x0C, .g1 = st.p.pawns_per_file[0][7], .sq1 = 0x1B, .g2 = st.p.king_rays[1][0x1B], .target = 0x1B },
            } else .{
                .{ .sq2 = 0x52, .code = 5, .g1 = st.p.pawns_per_file[1][2], .sq1 = 0x5C, .g2 = st.p.king_rays[0][0x5C], .target = 0x5C },
                .{ .sq2 = 0x57, .code = 5, .g1 = st.p.pawns_per_file[1][7], .sq1 = 0x61, .g2 = st.p.king_rays[0][0x61], .target = 0x61 },
            };
            if (q_ok) {
                const a = pats[0];
                if (B[a.sq2] == a.code) {
                    if (a.g1 == 0 and B[a.sq1] == 0 and a.g2 == 0) st.sv.rook_hint = a.target;
                } else {
                    const b = pats[1];
                    if (B[b.sq2] == b.code and b.g1 == 0 and B[b.sq1] == 0 and b.g2 == 0) st.sv.rook_hint = b.target;
                }
            }
            const K = self.oppKing();
            const rank_ok = if (W) K >= 0x5B else K <= 0x1C;
            if (!rank_ok) return;
            const bsq: u8 = if (st.bishop_square_sel[K] != 0)
                (if (W) st.p.piece_list[2] else st.p.piece_list[0x13])
            else
                (if (W) st.p.piece_list[3] else st.p.piece_list[0x12]);
            const nb: [2]u8 = if (W) .{ 9, 10 } else .{ 2, 3 };
            const att: [2]u8 = if (W) .{ 4, 5 } else .{ 11, 12 };
            const vstep: i16 = if (W) -10 else 10;
            if (bsq < 0x63) {
                for ([3]i16{ -1, 1, vstep }) |step| {
                    const nsq: usize = @intCast(@as(i16, K) + step);
                    if (nb[0] <= B[nsq] and B[nsq] <= nb[1]) {
                        var p: i16 = @as(i16, K) + step;
                        while (true) {
                            p += step;
                            const pc = B[@intCast(p)];
                            if (pc == 0 or p == bsq) continue;
                            break;
                        }
                        const pc = B[@intCast(p)];
                        if (att[0] <= pc and pc <= att[1]) {
                            st.sv.bishop_hint = @intCast(@as(i16, K) + step);
                            return;
                        }
                    }
                }
            }
            // castled-king patterns (4AB1)
            const Cp = struct { qsq: u8, q: u8, pc: [2]u8, osq: u8, g1: u8, t1: u16, g2: u8, t2: u16, qh: u8 };
            var P: Cp = undefined;
            if (W) {
                if (K >= 0x61) {
                    P = .{ .qsq = 0x4E, .q = 5, .pc = .{ 1, 3 }, .osq = 0x4C, .g1 = st.p.king_rays[1][0x4C], .t1 = 0x4C, .g2 = st.p.king_rays[1][0x4E], .t2 = 0x4E, .qh = 0x58 };
                } else if (K <= 0x5C) {
                    P = .{ .qsq = 0x47, .q = 5, .pc = .{ 1, 3 }, .osq = 0x49, .g1 = st.p.king_rays[1][0x49], .t1 = 0x49, .g2 = st.p.king_rays[1][0x47], .t2 = 0x47, .qh = 0x51 };
                } else return;
            } else {
                if (K >= 0x1B) {
                    P = .{ .qsq = 0x30, .q = 0x0C, .pc = .{ 8, 10 }, .osq = 0x2E, .g1 = st.p.king_rays[0][0x2E], .t1 = 0x2E, .g2 = st.p.king_rays[0][0x30], .t2 = 0x30, .qh = 0x26 };
                } else if (K <= 0x16) {
                    P = .{ .qsq = 0x29, .q = 0x0C, .pc = .{ 8, 10 }, .osq = 0x2B, .g1 = st.p.king_rays[0][0x2B], .t1 = 0x2B, .g2 = st.p.king_rays[0][0x29], .t2 = 0x29, .qh = 0x1F };
                } else return;
            }
            const qv = B[P.qsq];
            if (qv == P.q) {
                st.sv.bishop_hint = P.qh; // UNVERIFIED for White
                return;
            }
            if (qv == P.pc[0] or qv == P.pc[1]) {
                if (B[P.osq] == 0 and P.g1 == 0) st.sv.queen_hint = P.t1; // UNVERIFIED for White
                return;
            }
            const ov = B[P.osq];
            if ((ov == P.pc[0] or ov == P.pc[1]) and qv == 0 and P.g2 == 0) st.sv.queen_hint = P.t2; // UNVERIFIED for White
        }

        /// 4B7D.
        fn afterQgen(self: *Self, c: u16) Next {
            const st = self.st;
            self.count = @bitCast(c);
            if (c == 0xFFFF) return .{ .ret = 0x4E20 };
            self.setLegal();
            self.full_width = 0;
            self.saved_a6c2 = st.ev.passed_pawns[0];
            self.saved_9d8c = st.ev.passed_pawns[1];
            if (c == 0) return .{ .go = .l4E64 };
            if (self.count > 1) self.ctx.sortList(self.ply, c);
            return .{ .go = .l4C1C };
        }

        // ---- B16, B17 -----------------------------------------------------------------

        fn l4BCA(self: *Self) Next {
            const st = self.st;
            const p = self.pu();
            if (st.killer[p] != 0) self.mark(st.killer[p], 3);
            const c = self.ctx.generate(.all, self.side, self.ply);
            self.count = @bitCast(c);
            if (c == 0xFFFF) {
                // 3718 -> 2FA9 at ply 2: 20000, the extension byte untouched.
                // UNVERIFIED at ply 2: never ran.
                if (ply2) return .{ .ret = 0x4E20 };
                self.best = 0x4E20;
                self.undoExt41D2();
                return .{ .ret = self.best };
            }
            self.setLegal();
            if (c == 0) {
                // 3728 (difference 8): at ply 2, 0 without a hash store.
                if (ply2) return .{ .ret = 0 };
                self.best = 0;
                return .{ .go = .l40E0 };
            }
            self.full_width = 1;
            return .{ .go = .l4C1C };
        }

        fn moveLoop(self: *Self) Next {
            const st = self.st;
            const p = self.pu();
            self.idx = 0;
            while (self.idx < self.count) : (self.idx += 1) {
                const i: u16 = @intCast(self.idx);
                const m = self.listMove(i);
                const mw = word(m);
                if (mw == self.hash_move) continue;
                self.ctx.applyMove(self.side, self.ply + 1, m, &self.undo);
                self.prefetchChild();
                var v: i16 = undefined;
                while (true) {
                    if (mw == self.undo_move and self.undo.captured == 0) {
                        if (self.best >= -1) {
                            v = -1;
                        } else {
                            v = self.childSearch();
                            if (v > -1) v = -1;
                        }
                    } else {
                        v = self.tbTest(m.flag) orelse self.childSearch();
                    }
                    if (v > self.best and self.beta0 > self.beta) {
                        self.beta = self.beta0;
                        continue;
                    }
                    break;
                }
                self.ctx.unmake(self.side, m, &self.undo);
                self.restoreAfterUnmake();
                if (v > self.best) {
                    if (m.flag != 0) {
                        self.hash_move &= 0xFF00;
                    } else {
                        self.hash_move = mw;
                    }
                    self.best = v;
                    if (!(self.beta0 > v)) {
                        // 3856: no ply < L2 test at ply 2 (difference 7).
                        if ((ply2 or self.ply < st.tv.ply_limit2) and self.undo.captured == 0 and st.p.check_by_ply[atRoom(room_check, p)] == 0) st.killer[p] = mw;
                        return .{ .go = .l40D6 };
                    }
                    if (self.full_width != 0) {
                        self.beta = v +% 1;
                        self.best_quiet = if (self.undo.captured != 0) .none else .{ .list = i };
                    }
                    self.pvUpdate(mw);
                }
                if (st.stop != 0) {
                    // 38BB: at ply 2 a stop skips the loop-end tests and goes to 3981
                    // (tests/golden/rootmove/ponder.zst: a stop after a quiet move raised
                    // the best, whose mark the loop-end tests would have written).
                    if (ply2) return .{ .go = .l40E0 };
                    break;
                }
            }
            // 4DB7; 3922 at ply 2
            if (self.full_width == 0) return .{ .go = .l4E64 };
            if (self.ply == self.child_legal) {
                if (ply2) {
                    // 3922-395E (difference 4, DEV-035): the original scores "no legal
                    // move" as mate only if a check extension was made ([7420] != 0),
                    // otherwise 0, even in check: with no pawns on the board ([90AA] = 0)
                    // or [1E08] set no extension is made, so a checkmate is a draw.
                    // Corrected (`dev035_ply2_mate`), the test is the general node's,
                    // the in-check flag [8C08] (4DC8); an extension is made only in
                    // check (364E-36E0), so this only adds the case without one. The
                    // score is 3674's AX, B1E2h = 2 - 20000, what the general node's
                    // `ply - 20000` (4DCF) gives at ply 2. The test is proved (pawnless
                    // positions); the mate return needs a mate in one, which the depth-1
                    // search finds and ends on before root_move_search is called.
                    // UNVERIFIED: the mate return cannot run at the Fixed depth level.
                    const mated = if (node_fixes.dev035_ply2_mate) st.p.check_by_ply[atRoom(room_check, p)] != 0 else st.extension[p] != 0;
                    if (mated) {
                        self.undoExt41D2();
                        return .{ .ret = mate_ply2 };
                    }
                } else if (st.p.check_by_ply[atRoom(room_check, p)] != 0) {
                    self.best = self.ply -% 0x4E20;
                    self.undoExt41D2();
                    return .{ .ret = self.best };
                }
                self.best = 0; // stalemate
            }
            switch (self.best_quiet) {
                .none => {},
                .hash_move => self.mark(self.hash_move, 2),
                .list => |i| self.mark(word(self.listMove(i)), 2),
            }
            return .{ .go = .l40E0 };
        }

        /// A cutoff: 40D6 in the node; 35BA-35C2 at ply 2 (both cutoffs), where the
        /// score is left as it is (the store clamps it to beta0; without a store the
        /// ply-2 node returns the child's score, the node beta0).
        fn l40D6(self: *Self) Next {
            self.st.pv_end[self.pu()] = @truncate(uw(self.ply - 1));
            // UNVERIFIED at ply 2: no recorded cutoff was followed by a return without a store.
            if (!ply2) self.best = self.beta0;
            return .{ .go = .l40E0 };
        }

        // ---- B22 undo the extension, hash store ---------------------------------------

        fn l40E0(self: *Self) Next {
            const st = self.st;
            const p = self.pu();
            const e = st.extension[p];
            st.hash_entry[9] = e;
            if (e != 0) {
                self.ext(-1);
                if (e == 2) self.ext(-1);
                st.extension[p] = 0;
            }
            if (st.hash_enabled == 0) return .{ .ret = self.best }; // UNVERIFIED at ply 2: never ran
            const h = self.H();
            // 39B4-39D7: no H >= ply test at ply 2 (difference 7).
            if ((!ply2 and h < self.ply) or st.p.ep_square_by_ply[atRoom(room_ep, p)] != 0) return .{ .ret = self.best };
            if (h - self.ply < s8(self.slot_depth)) return .{ .ret = self.best };
            self.slot_depth = @as(u8, @bitCast(st.horizon)) -% @as(u8, @truncate(uw(self.ply)));
            self.bound = 0x40;
            var si = self.best;
            if (self.alpha >= si) {
                self.bound = 0x80;
                si = self.alpha;
            } else if (!(self.beta0 > si)) {
                self.bound = 0xC0;
                si = self.beta0;
            }
            self.best = si;
            const e2 = &st.hash_entry;
            std.mem.writeInt(u16, e2[0..2], uw(si), .little);
            e2[8] = self.bound | self.slot_depth;
            std.mem.writeInt(u32, e2[2..6], @truncate(st.p.hash_key), .little);
            e2[9] |= keyByte4(st.p.hash_key) & 0xFC;
            std.mem.writeInt(u16, e2[6..8], self.hash_move, .little);
            if (s8(st.conv_tables) > 1) {
                // UNVERIFIED: the conventional-memory store never ran; same slot index.
            }
            self.ctx.store(self.side, self.hash_index);
            return .{ .ret = si };
        }

        // ---- B21 quiescence end -------------------------------------------------------

        fn quiescenceEnd(self: *Self) Next {
            const st = self.st;
            const sg = self.sg;
            const p = self.pu();
            var d = self.partial;
            var si = self.best;
            if (st.mode_1e08 != 0) {
                // UNVERIFIED: the [1E08] mode never ran.
                if (d > si) {
                    self.best = d;
                    st.pv_end[p] = @truncate(uw(self.ply - 1));
                }
                return .{ .ret = self.best };
            }
            if (self.counter != 0) d -%= sg *% self.threat;
            st.ev.passed_pawns[0] = self.saved_a6c2;
            st.ev.passed_pawns[1] = self.saved_9d8c;
            const stage = self.stage;
            if (stage > 3) return .{ .ret = si };
            if (stage == 0) {
                if (si -% 0x140 > d) return .{ .ret = si };
                d +%= sg *% self.ctx.pieceEval(self.side, self.ply);
            }
            if (stage <= 1) d +%= sg *% self.pawn_term;
            if (stage <= 2) {
                if (!(si -% 0xA0 > d) and st.ev.no_pawns_at_root == 0) d +%= sg *% self.ctx.kingSafety();
            }
            if (s8(self.reasons) > 0x0A) return .{ .go = .l464F };
            if (si -% 0xF0 > d) return .{ .ret = si };
            if (!(d > si)) {
                if (self.ply >= st.tv.ply_limit1 or st.root_material_total == @as(i16, @bitCast(st.p.total_material))) return .{ .ret = si };
                return .{ .go = .l4F8E };
            }
            if (self.counter == 0) {
                st.ev.passer_flags = self.saved_a5f5;
                st.ev.weak_pawns = self.saved_8eb6;
                self.threatsTerm();
            }
            d +%= sg *% self.threat;
            if (self.reasons != 0 or s8(self.counter) > 1) {
                if (self.beta0 > d) return .{ .go = .l464F };
                si = d;
                st.pv_end[p] = @truncate(uw(self.ply - 1));
            } else if (d > si) {
                si = d;
                st.pv_end[p] = @truncate(uw(self.ply - 1));
            }
            self.best = si;
            if (self.ply >= st.tv.ply_limit1 or st.root_material_total == @as(i16, @bitCast(st.p.total_material))) return .{ .ret = si };
            const prev = if (self.side == white) st.prev_score_white else st.prev_score_black;
            const e = si -% prev;
            if (-0x3C <= e and e <= 0x3C) return .{ .go = .l464F };
            return .{ .go = .l4F8E };
        }

        fn l4F8E(self: *Self) Next {
            const e = @as(i16, @bitCast(self.st.p.material_balance)) -% self.st.root_material_balance;
            if (e < -0x32) return .{ .ret = self.best };
            if (e <= 0x32) return .{ .go = .l464F };
            return .{ .ret = self.best };
        }
    };
}

// ---------------------------------------------------------------------------
// The hash tables, directly indexed
// ---------------------------------------------------------------------------

/// The slot index of the XMS tables (B6 step 14): the key's words 2 and 1 masked by
/// `mask`, scaled by 3/4 when `size_mode` is non-zero (the original's 32-bit
/// `shr/rcr/add/adc/shr/rcr`, carry kept). `keys` is DG:8CCC.
pub fn hashIndexOfKey(key: u48, mask: u32, size_mode: u8) u32 {
    var i: u32 = mask & @as(u32, @truncate(key >> 16));
    if (size_mode != 0) i = ((i >> 1) +% i) >> 1;
    return i;
}

/// `hashIndexOfKey` with the key as the bytes at DG:8CCC.
pub fn hashIndex(keys: *const [12]u8, mask: u32, size_mode: u8) u32 {
    const k1 = std.mem.readInt(u16, keys[2..4], .little);
    const k2 = std.mem.readInt(u16, keys[4..6], .little);
    var i: u32 = mask & (@as(u32, k2) << 16 | k1);
    if (size_mode != 0) i = ((i >> 1) +% i) >> 1;
    return i;
}

/// One table (White to move or Black to move) of 10-byte entries in ordinary memory,
/// laid out as the original's XMS block: slot `i` is bytes 10i .. 10i+9. The entry
/// layout is the specification's (score, key words 0 and 1, move, bound|depth,
/// key-byte-4 bits | extension). Replacement is decided by the node (B22 step 88),
/// so `store` always writes.
///
/// The clear costs what was written, not the table's size: the table notes the slots
/// written since the last clear (`written`, while there is room, and in any case the
/// highest, `high`), and `clear` zeroes those slots only, or, when more were written than
/// `written` holds, every slot below `high`. Every slot it does not touch is already zero,
/// so the bytes after a clear are the bytes a full `@memset` leaves. That holds only if
/// every write goes through `store` or `put`; a table made with slots of unknown content
/// (`pristine` false, the default) is cleared in full the first time.
pub const HashTable = struct {
    slots: [][10]u8,
    /// Room for the indices of the slots written since the last clear; none by default.
    written: []u32 = &.{},
    n_written: usize = 0,
    /// More slots were written than `written` holds.
    overflow: bool = false,
    /// One past the highest slot written since the last clear.
    high: usize = 0,
    /// Every slot not noted since the last clear is zero.
    pristine: bool = false,

    pub fn prefetch(self: *const HashTable, index: u32) void {
        @prefetch(&self.slots[index], .{});
    }
    pub fn probe(self: *const HashTable, index: u32, out: *[10]u8) void {
        out.* = self.slots[index];
    }
    pub fn store(self: *HashTable, index: u32, entry: *const [10]u8) void {
        self.slots[index] = entry.*;
        self.note(index);
    }
    /// A slot written from outside the search (a test preloading recorded slots).
    pub fn put(self: *HashTable, index: u32, entry: [10]u8) void {
        self.store(index, &entry);
    }
    inline fn note(self: *HashTable, index: u32) void {
        if (index >= self.high) self.high = @as(usize, index) + 1;
        if (self.overflow) return;
        if (self.n_written < self.written.len) {
            self.written[self.n_written] = index;
            self.n_written += 1;
        } else self.overflow = true;
    }
    /// clear_hash_tables (0000:88CC) for this table: every byte 0. The original copies a
    /// conventional buffer over the XMS block, 2 KB further each time, through the
    /// driver (0000:6A91); an empty slot is one whose bound bits (byte 8) are 0.
    pub fn clear(self: *HashTable) void {
        if (!self.pristine) {
            @memset(std.mem.sliceAsBytes(self.slots), 0);
        } else if (self.overflow) {
            @memset(std.mem.sliceAsBytes(self.slots[0..self.high]), 0);
        } else {
            for (self.written[0..self.n_written]) |i| self.slots[i] = @splat(0);
        }
        self.n_written = 0;
        self.overflow = false;
        self.high = 0;
        self.pristine = true;
    }
};

/// A slot of `TaggedHashTable`: the 10-byte entry, then the clear count it was written
/// under. 16 bytes, so a 64-byte-aligned table never splits a slot across cache lines.
pub const TaggedSlot = extern struct {
    entry: [10]u8,
    _pad: [2]u8 = .{ 0, 0 },
    clears: u32,
};

/// The same table as `HashTable`, with a clear that costs nothing: each slot records the
/// clear count (`clears`) under which it was written, and a slot written before the
/// latest clear reads as all zeros, which is what `HashTable.clear` leaves. Only when
/// the count wraps is the memory cleared. Probe, store and clear return and leave
/// exactly what `HashTable`'s do (src/searchnode_test.zig compares the two).
pub const TaggedHashTable = struct {
    slots: []align(64) TaggedSlot,
    clears: u32 = 0,

    pub fn prefetch(self: *const TaggedHashTable, index: u32) void {
        @prefetch(&self.slots[index], .{});
    }
    pub fn probe(self: *const TaggedHashTable, index: u32, out: *[10]u8) void {
        const s = &self.slots[index];
        out.* = if (s.clears == self.clears) s.entry else @splat(0);
    }
    pub fn store(self: *TaggedHashTable, index: u32, entry: *const [10]u8) void {
        self.slots[index] = .{ .entry = entry.*, .clears = self.clears };
    }
    /// clear_hash_tables (0000:88CC), as `HashTable.clear`.
    pub fn clear(self: *TaggedHashTable) void {
        self.clears +%= 1;
        if (self.clears == 0) @memset(std.mem.sliceAsBytes(self.slots), 0);
    }
};
