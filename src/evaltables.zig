//! The evaluation's tables, built from the root position before every search:
//! port of prepare_eval (0000:9582-B9DB) and everything it calls that writes DGROUP:
//! prepare_eval_part2 (0000:BB4A-E618) with its helpers E61A, E658, E696, the pawn-table
//! helpers 94FE, 9526, 954E, 9568, prepare_eval_endgame (0000:B9DC-BB48),
//! reset_square_sums (0000:E718-E8D2), scan_root_passed_pawns (2B9F:5E6A-5F7E),
//! hash_from_scratch (4793:4026, `Position.hashFromScratch`) and
//! find_last_irreversible_ply (0000:887E).
//!
//! Specification: docs/arch/51-evaluation-tables.md. The proved model,
//! tools/research/evaltables/model.py, is the reference for what is computed; the
//! port follows its 37 sections (`sections`) in the code's order so that each can be
//! proved separately against the recorded calls (src/evaltables_test.zig).
//!
//! Widths follow the original: byte tables wrap at 8 bits, word tables at 16 bits
//! (`+%`), and each comparison uses the signedness the code uses.
//!
//! Not ported here, because they are outside DGROUP and belong to other units: the
//! copy of the root key into the game record (`[306A]:3A34 + 6 * ply`, 0000:960A) and
//! the clearing of both pawn hash tables (0000:8B50, `5A7B:174E` and `5A7B:6A7C`,
//! 2,560 bytes each). The caller does both after `prepareEval`.

const std = @import("std");
const pos = @import("position.zig");
const original = @import("original.zig");
const sn = @import("searchnode.zig");
const evm = @import("evalvars.zig");
const see = @import("see.zig");
const leaf = @import("leaf.zig");
const evalthreats = @import("evalthreats.zig");
const rvm = @import("rootvars.zig");
const Position = pos.Position;

// ---------------------------------------------------------------------------
// Constant tables, read from the original's file at compile time
// ---------------------------------------------------------------------------

const exe = @embedFile("mcp8_exe");
const header_bytes: usize = @as(usize, std.mem.readInt(u16, exe[8..10], .little)) * 16;

/// The far data segment 5857 (26 constant tables, docs/arch/51 Appendix A), up to
/// 5857:0E60 where the hash random table's segment starts.
const far5857: [0xE60]u8 = exe[header_bytes + 0x58570 ..][0..0xE60].*;
/// 5846:0000, 40 bytes, copied to DG:3766 at 0000:E5D6.
const far5846: [0x28]u8 = exe[header_bytes + 0x58460 ..][0..0x28].*;

inline fn fb(off: usize) u8 {
    return far5857[off];
}
inline fn fsb(off: usize) i8 {
    return @bitCast(far5857[off]);
}
inline fn fw(off: usize) u16 {
    return @as(u16, far5857[off]) | @as(u16, far5857[off + 1]) << 8;
}

fn dgSigned(comptime addr: usize, comptime n: usize) [n]i8 {
    return @bitCast(original.dgroup(addr, n));
}
fn dgWords(comptime addr: usize, comptime n: usize) [n]u16 {
    const b = original.dgroup(addr, 2 * n);
    var out: [n]u16 = undefined;
    for (&out, 0..) |*v, i| v.* = std.mem.readInt(u16, b[2 * i ..][0..2], .little);
    return out;
}

/// DG:100A: file of a square (1..8 on the board).
const file_of = original.dgroup(0x100A, 120);
/// DG:1078: rank code of a square (2 = rank 1 .. 9 = rank 8).
const rank_of = original.dgroup(0x1078, 120);
/// DG:0E16: 1 on dark squares.
const dark = original.dgroup(0x0E16, 100);
/// DG:19DE: the square with the same file on the mirrored rank.
const mirror_sq = dgSigned(0x19DE, 100);
/// DG:1510: the 8 king steps; DG:1508: the 8 knight steps; DG:1518: 8 two-square steps.
const king_steps = dgSigned(0x1510, 8);
const knight_steps = dgSigned(0x1508, 8);
const two_steps = dgSigned(0x1518, 8);
/// DG:1520 and DG:152E: 13 offsets each around White's and Black's king (middlegame).
const king_ring_white = dgSigned(0x1520, 13);
const king_ring_black = dgSigned(0x152E, 13);
/// DG:1540: 1 for a pawn count of 1..8, else 0.
const one_if_pawns = dgSigned(0x1540, 16);
/// DG:0530 and DG:0594: king tables averaged in when the enemy has few pieces.
const king_avg_white = dgSigned(0x0530, 100);
const king_avg_black = dgSigned(0x0594, 100);
/// DG:03FA: 16 signed bytes, divided into DG:7692.
const table_03fa = dgSigned(0x03FA, 16);
/// DG:0850, DG:0F42, DG:0FA6: square tables of the rook-and-pawn ending (BB4A).
const rp_0850 = original.dgroup(0x0850, 100);
const rp_0f42 = dgSigned(0x0F42, 100);
const rp_0fa6 = dgSigned(0x0FA6, 100);
/// DG:1498 and DG:14B4: piece value and promotion gain by piece code.
const piece_value = dgWords(0x1498, 14);
const promotion_gain = dgWords(0x14B4, 14);

inline fn mirror(sq: usize) usize {
    return @intCast(mirror_sq[sq]);
}

/// The low 16 bits of `v` (the original's word stores).
inline fn w16(v: i32) i16 {
    return @truncate(v);
}
/// The low 8 bits of `v` (the original's byte stores).
inline fn b8(v: i32) u8 {
    return @bitCast(@as(i8, @truncate(v)));
}
inline fn s16(v: u16) i16 {
    return @bitCast(v);
}

/// `v * aggression / 100` as the custom style computes it: 32-bit product, C long
/// division (4793:8AF0, truncating toward zero), low 16 bits kept.
fn scaleByAggression(v: i32, aggression: i32) i16 {
    const prod: i32 = @truncate(@as(i64, v) * aggression);
    return w16(@divTrunc(prod, 100));
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// Everything prepare_eval writes in DGROUP outside the position (`Position`), each field
/// a pointer to the variable's one home (Stage B step 7, stage 3c-2): inside a search the
/// node domain's structs where one of them holds the bytes, the image elsewhere
/// (`bindDomain`); outside a search the image (`bindImage`); in the tests a `TableValues`
/// (`bindValues`). Every read and write goes through the pointer.
/// Word tables indexed by square hold 100 words; the byte tables the activity and
/// centrality code writes past square 99 (offsets from a king on the 8th rank) are
/// declared as long as the original's writes reach without meeting the next variable.
/// `dg` gives each field's address; a test checks it against the field's doc comment
/// only by the replay (a wrong address fails it).
pub const Tables = struct {
    /// DG:A38E (White) and DG:A38F (Black): pawn slot holding a promoted queen when
    /// slot 6 is captured, else 0.
    promoted_queen_slot: *align(1) [2]u8 = undefined,
    /// DG:8DDE: computer_side, `1 - [717C]`.
    computer_side: *align(1) u8 = undefined,
    /// DG:7468: base of Black's pawn square sum.
    base_black_pawns: *align(1) i16 = undefined,
    /// DG:A008: base of White's pawn square sum.
    base_white_pawns: *align(1) i16 = undefined,
    /// DG:A5E2: base of the pieces' square sum.
    base_pieces: *align(1) i16 = undefined,
    /// DG:3675: both White castling stamps non-zero.
    white_castling_gone: *align(1) u8 = undefined,
    /// DG:A4F2: both Black castling stamps non-zero.
    black_castling_gone: *align(1) u8 = undefined,
    /// DG:724C: Black passed pawns at the root.
    passed_count_black: *align(1) u8 = undefined,
    /// DG:9D8B: White passed pawns at the root.
    passed_count_white: *align(1) u8 = undefined,
    /// DG:A8E0: highest rank code of a White passed pawn per file (index file - 1).
    passed_rank_by_file_white: *align(1) [8]u8 = undefined,
    /// DG:9EEE: lowest rank code of a Black passed pawn per file (index file - 1).
    passed_rank_by_file_black: *align(1) [8]u8 = undefined,
    /// DG:A3FE: indexed by pawn slot 8..15, the square of a White passed pawn, else 0.
    /// Entries 1..7 are read as per-file flags by B362 (written by nothing here).
    passed_pawn_sq_white: *align(1) [16]u8 = undefined,
    /// DG:8CE6: the same for Black.
    passed_pawn_sq_black: *align(1) [16]u8 = undefined,
    /// DG:8CC4: all passed pawns at the root.
    passed_count_both: *align(1) u8 = undefined,
    /// DG:73FE: set when a castling stamp is this ply or the last, or a phase flag
    /// changed; never cleared here.
    castling_or_phase_changed: *align(1) u8 = undefined,
    /// DG:9EBE: shelter_by_rank, from 5857:0000.
    shelter_by_rank: *align(1) [10]u8 = undefined,
    /// DG:9FC7: development count >= 2.
    phase_developing: *align(1) u8 = undefined,
    /// DG:A8D7: development count >= 5 (the opening).
    phase_opening: *align(1) u8 = undefined,
    /// DG:A360: 1 both sides have only bishop slot 2, 2 only slot 3.
    single_bishops_same_slot: *align(1) u8 = undefined,
    /// DG:B622: bishop and knight against a bare king.
    kbn_vs_king: *align(1) u8 = undefined,
    /// DG:A6A3: no pawns on the board.
    no_pawns: *align(1) u8 = undefined,
    /// DG:A6C3: endgame.
    endgame: *align(1) u8 = undefined,
    /// DG:A72C: late endgame.
    late_endgame: *align(1) u8 = undefined,
    /// DG:A074: mobility weight by piece code, codes 0..5. In the search these 12 bytes
    /// are `see.Scratch.defenders[20..32]`'s.
    mobility_weights: *align(1) [6]i16 = undefined,
    /// DG:A080: mobility weight by piece code, codes 6..13 (`mobility_weights` continued).
    mobility_weights_rest: *align(1) [8]i16 = undefined,
    /// DG:B522: White's centrality bytes, by square.
    centrality_white: *align(1) [120]u8 = undefined,
    /// DG:B5A8: Black's centrality bytes.
    centrality_black: *align(1) [120]u8 = undefined,
    /// DG:A8EC: White's pawn square values.
    pawn_white: *align(1) [100]i16 = undefined,
    /// DG:75CA: White's knight square values.
    knight_white: *align(1) [100]i16 = undefined,
    /// DG:AC2A: White's bishop square values.
    bishop_white: *align(1) [100]i16 = undefined,
    /// DG:9182: White's rook square values.
    rook_white: *align(1) [100]i16 = undefined,
    /// DG:8DEA: White's queen square values.
    queen_white: *align(1) [100]i16 = undefined,
    /// DG:AA2C: Black's pawn square values.
    pawn_black: *align(1) [100]i16 = undefined,
    /// DG:76A2: Black's knight square values.
    knight_black: *align(1) [100]i16 = undefined,
    /// DG:ACF4: Black's bishop square values.
    bishop_black: *align(1) [100]i16 = undefined,
    /// DG:924A: Black's rook square values.
    rook_black: *align(1) [100]i16 = undefined,
    /// DG:8EB8: Black's queen square values.
    queen_black: *align(1) [100]i16 = undefined,
    /// DG:7260: White's king table.
    king_white: *align(1) [100]i16 = undefined,
    /// DG:732A: Black's king table.
    king_black: *align(1) [100]i16 = undefined,
    /// DG:AEFA: White's king zone.
    king_zone_white: *align(1) [100]i16 = undefined,
    /// DG:B03E: Black's king zone.
    king_zone_black: *align(1) [100]i16 = undefined,
    /// DG:7100: White's queen captured (not promoted) at the root.
    root_white_queenless: *align(1) u8 = undefined,
    /// DG:9354: Black's queen captured at the root.
    root_black_queenless: *align(1) u8 = undefined,
    /// DG:B628: Black's king tucked in a corner (1 queen side, 2 king side).
    black_king_tucked: *align(1) u8 = undefined,
    /// DG:8BBC: White's king tucked in a corner.
    white_king_tucked: *align(1) u8 = undefined,
    /// DG:A84E: White knight activity.
    activity_knight_white: *align(1) [120]u8 = undefined,
    /// DG:A2F0: White bishop activity.
    activity_bishop_white: *align(1) [100]u8 = undefined,
    /// DG:ABA0: White rook activity.
    activity_rook_white: *align(1) [120]u8 = undefined,
    /// DG:AB20: White queen activity.
    activity_queen_white: *align(1) [120]u8 = undefined,
    /// DG:A9B4: Black knight activity.
    activity_knight_black: *align(1) [120]u8 = undefined,
    /// DG:A390: Black bishop activity.
    activity_bishop_black: *align(1) [100]u8 = undefined,
    /// DG:AFC6: Black rook activity.
    activity_rook_black: *align(1) [120]u8 = undefined,
    /// DG:ADBE: Black queen activity.
    activity_queen_black: *align(1) [120]u8 = undefined,
    /// DG:A6C8: White rook bytes.
    rook_bytes_white: *align(1) [100]u8 = undefined,
    /// DG:A72E: Black rook bytes.
    rook_bytes_black: *align(1) [100]u8 = undefined,
    /// DG:746C: storm table, squares 31..88, from 5857:006C (mirrored).
    storm_746c: *align(1) [89]i16 = undefined,
    /// DG:AE46: storm table, from 5857:006C.
    storm_ae46: *align(1) [89]i16 = undefined,
    /// DG:718C: from 5857:0120 (mirrored), with corrections.
    storm_718c: *align(1) [89]i16 = undefined,
    /// DG:A792: from 5857:0120, with corrections.
    storm_a792: *align(1) [89]i16 = undefined,
    /// DG:90BA: 5857:099A (mirrored) + 718C.
    table_90ba: *align(1) [89]i16 = undefined,
    /// DG:369E: 5857:099A + A792.
    table_369e: *align(1) [89]i16 = undefined,
    /// DG:7692: 16 bytes from DG:03FA, divided.
    table_7692: *align(1) [16]u8 = undefined,
    /// DG:3766: 40 bytes from 5846:0000.
    table_3766: *align(1) [40]u8 = undefined,
    /// DG:A234: 14 bytes from 5857:0034 / 0042.
    endgame_king_src_white: *align(1) [14]u8 = undefined,
    /// DG:77DA: 14 bytes from 5857:0050 / 005E.
    endgame_king_src_black: *align(1) [14]u8 = undefined,
    /// DG:933E: copy of A234, entry 9 + 16.
    endgame_king_weights_white: *align(1) [14]u8 = undefined,
    /// DG:3A22: copy of 77DA, entry 2 + 16.
    endgame_king_weights_black: *align(1) [14]u8 = undefined,
    /// DG:14D0: piece value by code for the second balance (DG:A4C6).
    piece_value_2: *align(1) [14]u16 = undefined,
    /// DG:14EC: promotion gain by code for the second balance.
    promotion_gain_2: *align(1) [14]u16 = undefined,
    /// DG:1548: copy of the style word DG:153E.
    style_copy: *align(1) u16 = undefined,
    /// DG:90B6: White's pawn square sum.
    square_sum_white_pawns: *align(1) i16 = undefined,
    /// DG:369A: Black's pawn square sum.
    square_sum_black_pawns: *align(1) i16 = undefined,
    /// DG:7464: last ply <= the game ply whose irreversible flag is 0 (887E).
    last_irreversible_ply: *align(1) i16 = undefined,
    /// DG:A000: the root's game ply.
    root_ply: *align(1) u16 = undefined,
    /// DG:8BC0: FFFFh when the root's own irreversible flag is set, else 0.
    root_irreversible_word: *align(1) u16 = undefined,
    /// DG:9D95: 1 when the root's irreversible flag is 0.
    root_reversible: *align(1) u8 = undefined,

    /// The DGROUP address of each field (the same as in its doc comment).
    pub const dg = .{
        .promoted_queen_slot = 0xA38E,
        .computer_side = 0x8DDE,
        .base_black_pawns = 0x7468,
        .base_white_pawns = 0xA008,
        .base_pieces = 0xA5E2,
        .white_castling_gone = 0x3675,
        .black_castling_gone = 0xA4F2,
        .passed_count_black = 0x724C,
        .passed_count_white = 0x9D8B,
        .passed_rank_by_file_white = 0xA8E0,
        .passed_rank_by_file_black = 0x9EEE,
        .passed_pawn_sq_white = 0xA3FE,
        .passed_pawn_sq_black = 0x8CE6,
        .passed_count_both = 0x8CC4,
        .castling_or_phase_changed = 0x73FE,
        .shelter_by_rank = 0x9EBE,
        .phase_developing = 0x9FC7,
        .phase_opening = 0xA8D7,
        .single_bishops_same_slot = 0xA360,
        .kbn_vs_king = 0xB622,
        .no_pawns = 0xA6A3,
        .endgame = 0xA6C3,
        .late_endgame = 0xA72C,
        .mobility_weights = 0xA074,
        .mobility_weights_rest = 0xA080,
        .centrality_white = 0xB522,
        .centrality_black = 0xB5A8,
        .pawn_white = 0xA8EC,
        .knight_white = 0x75CA,
        .bishop_white = 0xAC2A,
        .rook_white = 0x9182,
        .queen_white = 0x8DEA,
        .pawn_black = 0xAA2C,
        .knight_black = 0x76A2,
        .bishop_black = 0xACF4,
        .rook_black = 0x924A,
        .queen_black = 0x8EB8,
        .king_white = 0x7260,
        .king_black = 0x732A,
        .king_zone_white = 0xAEFA,
        .king_zone_black = 0xB03E,
        .root_white_queenless = 0x7100,
        .root_black_queenless = 0x9354,
        .black_king_tucked = 0xB628,
        .white_king_tucked = 0x8BBC,
        .activity_knight_white = 0xA84E,
        .activity_bishop_white = 0xA2F0,
        .activity_rook_white = 0xABA0,
        .activity_queen_white = 0xAB20,
        .activity_knight_black = 0xA9B4,
        .activity_bishop_black = 0xA390,
        .activity_rook_black = 0xAFC6,
        .activity_queen_black = 0xADBE,
        .rook_bytes_white = 0xA6C8,
        .rook_bytes_black = 0xA72E,
        .storm_746c = 0x746C,
        .storm_ae46 = 0xAE46,
        .storm_718c = 0x718C,
        .storm_a792 = 0xA792,
        .table_90ba = 0x90BA,
        .table_369e = 0x369E,
        .table_7692 = 0x7692,
        .table_3766 = 0x3766,
        .endgame_king_src_white = 0xA234,
        .endgame_king_src_black = 0x77DA,
        .endgame_king_weights_white = 0x933E,
        .endgame_king_weights_black = 0x3A22,
        .piece_value_2 = 0x14D0,
        .promotion_gain_2 = 0x14EC,
        .style_copy = 0x1548,
        .square_sum_white_pawns = 0x90B6,
        .square_sum_black_pawns = 0x369A,
        .last_irreversible_ply = 0x7464,
        .root_ply = 0xA000,
        .root_irreversible_word = 0x8BC0,
        .root_reversible = 0x9D95,
    };

    /// The type a field points at (its bytes in the image: the original's widths).
    pub fn Pointee(comptime name: []const u8) type {
        return @typeInfo(@FieldType(Tables, name)).pointer.child;
    }

    /// The field holding DGROUP byte `addr`, and the byte's offset in it.
    fn locate(comptime addr: u16) struct { []const u8, usize } {
        @setEvalBranchQuota(100_000);
        const info = @typeInfo(Tables).@"struct";
        for (info.field_names) |name| {
            const base: usize = @field(dg, name);
            if (addr >= base and addr < base + @sizeOf(Pointee(name))) return .{ name, addr - base };
        }
        @compileError(std.fmt.comptimePrint("DG:{X:0>4} is not in Tables", .{addr}));
    }

    /// The byte at DGROUP address `addr` (resolved at compile time to its field), where
    /// the field points.
    pub inline fn byte(t: *const Tables, comptime addr: u16) *align(1) u8 {
        const loc = comptime locate(addr);
        const F = Pointee(loc[0]);
        if (F == u8) return @field(t, loc[0]);
        if (@typeInfo(F) == .array and @typeInfo(F).array.child == u8) return &@field(t, loc[0])[loc[1]];
        @compileError("not a byte field");
    }

    /// The word at DGROUP address `addr` (resolved at compile time to its field), where
    /// the field points.
    pub inline fn word(t: *const Tables, comptime addr: u16) *align(1) i16 {
        const loc = comptime locate(addr);
        const F = Pointee(loc[0]);
        if (F == i16) return @field(t, loc[0]);
        if (@typeInfo(F) == .array and @typeInfo(F).array.child == i16) {
            if (loc[1] % 2 != 0) @compileError("odd word address");
            return &@field(t, loc[0])[loc[1] / 2];
        }
        @compileError("not a word field");
    }

    /// The mobility weight of piece code `k` (DG:A074 + 2k), in `mobility_weights` or
    /// `mobility_weights_rest`.
    pub inline fn mobilityWeight(t: *const Tables, k: usize) *align(1) i16 {
        return if (k < 6) &t.mobility_weights[k] else &t.mobility_weights_rest[k - 6];
    }

    /// Points every field at its bytes in the DGROUP image `img` (`dg`): prepare_eval
    /// then writes the image where the original writes DGROUP. For the calls made
    /// outside a search (src/adapt_eval.zig).
    pub fn bindImage(t: *Tables, img: *[0x10000]u8) void {
        inline for (@typeInfo(Tables).@"struct".field_names) |name| {
            const n = @sizeOf(Pointee(name));
            @field(t, name) = @ptrCast(img[@field(dg, name)..][0..n]);
        }
    }

    /// Points every field at the same field of `v` (a test's copy of the tables).
    pub fn bindValues(t: *Tables, v: *TableValues) void {
        inline for (@typeInfo(Tables).@"struct".field_names) |name| @field(t, name) = &@field(v, name);
    }
};

/// Points `t` at the bytes of the node domain's structs for every field whose bytes one of
/// them holds (Stage B step 7, stage 3c-2), and at the image `img` for the rest, which no
/// struct of the domain holds or covers (`bindImage`): inside a search prepare_eval writes
/// each variable in its one home. `EvalVars` holds the square values, the king and
/// king-zone tables, the activity tables, the rook bytes, the storm and passer tables, the
/// shelter table, the phase flags A6A3, A6C3, A72C, the queenless flags, the style copy, the
/// pawn square sums, the last irreversible ply 7464 and 9D95 (`ply_flag[1]`); `ThreatVars`
/// the promoted-queen slots A38E and 9FC7 (`board_after[89]`); `see.Scratch` A008
/// (`attackers[28]`) and the first 6 mobility weights A074 (`defenders[20..32]`); `Position`
/// 3675 (`quiet_move_by_ply[39]`, high byte), 9EEE (`ep_square_by_ply[38..46]`) and 8BC0
/// (`reversible_by_ply[1]`); the node's `State` the 40 bytes at 3766 (`qs_max_ply`);
/// `LeafVars` the endgame king tables A234, 77DA, 933E, 3A22 and the root ply A000. Since
/// Stage B step 8, stage 7, every other field is `RootVars`' or `ProgramVars'`
/// (`rootvars.bindView`: the program's side, castling or the phase changed, the passed-pawn
/// counts and squares, the centrality tables, the second balance's tables, ...), so that no
/// field points at the image.
/// src/engine_root_domain_test.zig checks every byte against the domain's layout.
pub fn bindDomain(t: *Tables, st: *sn.State, p: *Position, ev: *evm.EvalVars, s: *see.Scratch, lv: *leaf.LeafVars, tv: *evalthreats.ThreatVars, rv: *rvm.RootVars, pg: *rvm.ProgramVars) void {
    rvm.bindView(Tables, tables_layout, t, rv, pg);
    bindAt(t, "pawn_white", &ev.square_values[0][0], 0xA8EC);
    bindAt(t, "knight_white", &ev.square_values[0][1], 0x75CA);
    bindAt(t, "bishop_white", &ev.square_values[0][2], 0xAC2A);
    bindAt(t, "rook_white", &ev.square_values[0][3], 0x9182);
    bindAt(t, "queen_white", &ev.square_values[0][4], 0x8DEA);
    bindAt(t, "pawn_black", &ev.square_values[1][0], 0xAA2C);
    bindAt(t, "knight_black", &ev.square_values[1][1], 0x76A2);
    bindAt(t, "bishop_black", &ev.square_values[1][2], 0xACF4);
    bindAt(t, "rook_black", &ev.square_values[1][3], 0x924A);
    bindAt(t, "queen_black", &ev.square_values[1][4], 0x8EB8);
    bindAt(t, "king_white", &ev.king_table[0], 0x7260);
    bindAt(t, "king_black", &ev.king_table[1], 0x732A);
    bindAt(t, "king_zone_white", &ev.king_zone[0], 0xAEFA);
    bindAt(t, "king_zone_black", &ev.king_zone[1], 0xB03E);
    bindAt(t, "activity_knight_white", &ev.nrq_activity[0][0], 0xA84E);
    bindAt(t, "activity_rook_white", &ev.nrq_activity[0][1], 0xABA0);
    bindAt(t, "activity_queen_white", &ev.nrq_activity[0][2], 0xAB20);
    bindAt(t, "activity_knight_black", &ev.nrq_activity[1][0], 0xA9B4);
    bindAt(t, "activity_rook_black", &ev.nrq_activity[1][1], 0xAFC6);
    bindAt(t, "activity_queen_black", &ev.nrq_activity[1][2], 0xADBE);
    bindAt(t, "activity_bishop_white", &ev.bishop_activity[0], 0xA2F0);
    bindAt(t, "activity_bishop_black", &ev.bishop_activity[1], 0xA390);
    bindAt(t, "rook_bytes_white", &ev.rook_square[0], 0xA6C8);
    bindAt(t, "rook_bytes_black", &ev.rook_square[1], 0xA72E);
    bindAt(t, "storm_746c", &ev.passer_tables[0], 0x746C);
    bindAt(t, "storm_718c", &ev.passer_tables[1], 0x718C);
    bindAt(t, "table_90ba", &ev.passer_tables[2], 0x90BA);
    bindAt(t, "storm_ae46", &ev.passer_tables[3], 0xAE46);
    bindAt(t, "storm_a792", &ev.passer_tables[4], 0xA792);
    bindAt(t, "table_369e", &ev.passer_tables[5], 0x369E);
    bindAt(t, "shelter_by_rank", &ev.shelter_first_rank, 0x9EBE);
    bindAt(t, "no_pawns", &ev.no_pawns_at_root, 0xA6A3);
    bindAt(t, "endgame", &ev.endgame, 0xA6C3);
    bindAt(t, "late_endgame", &ev.late_endgame, 0xA72C);
    bindAt(t, "root_white_queenless", &ev.queen_gone_at_root[0], 0x7100);
    bindAt(t, "root_black_queenless", &ev.queen_gone_at_root[1], 0x9354);
    bindAt(t, "style_copy", &ev.style_normal, 0x1548);
    bindAt(t, "square_sum_white_pawns", &ev.pawn_square_sum[0], 0x90B6);
    bindAt(t, "square_sum_black_pawns", &ev.pawn_square_sum[1], 0x369A);
    bindAt(t, "last_irreversible_ply", &ev.last_irreversible_ply, 0x7464);
    bindAt(t, "root_reversible", &ev.ply_flag, 0x9D94);
    bindAt(t, "promoted_queen_slot", &tv.promoted_queen_slot, 0xA38E);
    bindAt(t, "phase_developing", &tv.board_after, 0x9F6E);
    bindAt(t, "base_white_pawns", &s.attackers, 0x9FEC);
    bindAt(t, "mobility_weights", &s.defenders, 0xA060);
    bindAt(t, "white_castling_gone", &p.quiet_move_by_ply, 0x3626);
    bindAt(t, "passed_rank_by_file_black", &p.ep_square_by_ply, 0x9EC8);
    bindAt(t, "root_irreversible_word", &p.reversible_by_ply, 0x8BBE);
    bindAt(t, "table_3766", &st.qs_max_ply, 0x3766);
    bindAt(t, "endgame_king_src_white", &lv.wk_diag, 0xA234);
    bindAt(t, "endgame_king_src_black", &lv.bk_diag, 0x77DA);
    bindAt(t, "endgame_king_weights_white", &lv.wk_orth, 0x933E);
    bindAt(t, "endgame_king_weights_black", &lv.bk_orth, 0x3A22);
    bindAt(t, "root_ply", &lv.root_game_ply, 0xA000);
}

/// `Tables`' fields and their addresses (`Tables.dg`), as a layout for `rootvars.bindView`.
const tables_layout = blk: {
    const names = @typeInfo(Tables).@"struct".field_names;
    var out: [names.len]struct { []const u8, u16 } = undefined;
    for (names, 0..) |n, i| out[i] = .{ n, @field(Tables.dg, n) };
    const done = out;
    break :blk done;
};

/// Points field `name` of `t` at its bytes inside `field`, a struct field held in memory as
/// the image holds it (integers of whole bytes, little-endian) whose first byte is DGROUP
/// address `base`.
inline fn bindAt(t: *Tables, comptime name: []const u8, field: anytype, comptime base: u16) void {
    const addr: u16 = @field(Tables.dg, name);
    if (addr < base) @compileError("bindAt: " ++ name ++ " lies before its holder");
    @field(t, name) = @ptrCast(std.mem.asBytes(field)[addr - base ..][0..@sizeOf(Tables.Pointee(name))]);
}

/// The tables as values, one field for each field of `Tables`, of the type it points at,
/// zero by default: storage of the tests' own, outside any image (`Tables.bindValues`).
/// Compared and copied by value; the engine does not use it.
pub const TableValues = blk: {
    const names = @typeInfo(Tables).@"struct".field_names;
    var types: [names.len]type = undefined;
    var attrs: [names.len]std.builtin.Type.Struct.FieldAttributes = undefined;
    for (names, 0..) |name, i| {
        types[i] = Tables.Pointee(name);
        attrs[i] = .{ .default_value_ptr = &std.mem.zeroes(types[i]) };
    }
    break :blk @Struct(.auto, null, names, &types, &attrs);
};

/// A `Tables` bound to `v` (`Tables.bindValues`).
pub fn tablesOf(v: *TableValues) Tables {
    var t: Tables = .{};
    t.bindValues(v);
    return t;
}

/// Entries of the irreversible-move flags DG:3490 (196h, one per game ply 0..405).
pub const irreversible_plies = 0x196;

/// What prepare_eval reads in DGROUP besides the position and its own tables.
pub const Inputs = struct {
    /// DG:717C: the opponent's side, 0 when the program plays Black.
    opponent_side: u8 = 0,
    /// DG:153E: the style, 0 = custom.
    style: u16 = 1,
    /// DG:2906: Aggression (dword), custom style only.
    aggression: i32 = 100,
    /// DG:2922: the custom style's piece values P N B R Q (dwords, read as words).
    custom_piece_values: [5]u32 = @splat(0),
    /// DG:A84A: the move number.
    move_number: i16 = 0,
    /// DG:70E4: read with the move number at E428 (meaning not determined).
    flag_70e4: u8 = 0,
    /// DG:3490: per game ply, non-zero after a reversible move (read by 887E). The whole
    /// table, 196h bytes (3490..3625; New game clears them, 0000:91AD): game plies 0..405,
    /// as `gamemove.GameVars.irreversible` (docs/arch/34-game-move-path.md, "How long a
    /// game can be").
    irreversible_by_ply: [irreversible_plies]u8 = @splat(0),
    /// DG:9D92: compared with the game ply at 95E3.
    reset_ply: u16 = 0,
    /// DG:9D8C: Black's passed-pawn mask left by the last pawn evaluation
    /// (`EvalVars.passed_pawns[1]`; named White's until Stage B step 6).
    passed_mask_black: u8 = 0,
    /// DG:A6C2: White's passed-pawn mask left by the last pawn evaluation
    /// (`EvalVars.passed_pawns[0]`; named Black's until Stage B step 6).
    passed_mask_white: u8 = 0,
    /// DG:9F6E: the 78 bytes after the search board. A captured pawn's list entry is
    /// its square + 63h (up to 197), and the original tests the board byte there
    /// (`9EF6 + entry`) like any other square.
    beyond_board: [78]u8 = @splat(0),

    pub const dg = .{
        .opponent_side = 0x717C,
        .style = 0x153E,
        .aggression = 0x2906,
        .custom_piece_values = 0x2922,
        .move_number = 0xA84A,
        .flag_70e4 = 0x70E4,
        .irreversible_by_ply = 0x3490,
        .reset_ply = 0x9D92,
        .passed_mask_black = 0x9D8C,
        .passed_mask_white = 0xA6C2,
        .beyond_board = 0x9F6E,
    };
};

/// The routine's locals passed between sections (frame offsets in the names).
pub const Locals = struct {
    /// [bp-40h], [bp-3Eh]: White / Black has a queen (slot 6 or promoted).
    qw: bool = false,
    qb: bool = false,
    /// [bp-3Ch]: 1 king side, 2 queen side, as chosen with the pawn tables.
    kside: u8 = 0,
    /// part 2 [bp-0EAh], [bp-0E8h]: as qw, qb.
    qw2: bool = false,
    qb2: bool = false,
    /// part 2 [bp-82h] and [bp-0E6h]: the two 100-byte arrays of BDD1.
    a: [100]u8 = @splat(0),
    b: [100]u8 = @splat(0),
    f14: u8 = 0,
    f16: u8 = 0,
    f1c: u8 = 0,
    f1e: u8 = 0,
    f1a: u8 = 0,
    f18: u8 = 0,
    /// part 2 [bp-2] and [bp-4]: the development score and its first value.
    sc: i16 = 0,
    sc0: i16 = 0,
};

pub const Ctx = struct {
    p: *Position,
    t: *Tables,
    in: *const Inputs,
    l: *Locals,

    inline fn board(c: *const Ctx, sq: usize) u8 {
        return c.p.board[sq];
    }
    /// The board byte at a piece-list entry, which may be a captured piece's
    /// square + 63h, past the board's 120 bytes.
    inline fn boardAt(c: *const Ctx, entry: u8) u8 {
        return if (entry < 120) c.p.board[entry] else c.in.beyond_board[entry - 120];
    }
    inline fn wl(c: *const Ctx, slot: usize) u8 {
        return c.p.piece_list[slot];
    }
    inline fn bl(c: *const Ctx, slot: usize) u8 {
        return c.p.piece_list[16 + slot];
    }
    inline fn wpf(c: *const Ctx, f: usize) u8 {
        return c.p.pawns_per_file[0][f];
    }
    inline fn bpf(c: *const Ctx, f: usize) u8 {
        return c.p.pawns_per_file[1][f];
    }
    inline fn watt(c: *const Ctx, sq: usize) u8 {
        return c.p.pawn_attacks[0][sq];
    }
    inline fn batt(c: *const Ctx, sq: usize) u8 {
        return c.p.pawn_attacks[1][sq];
    }
    /// King files and ranks as signed bytes (DG:A22E/A22F, 70F0/70F1).
    inline fn wkf(c: *const Ctx) i32 {
        return @as(i8, @bitCast(c.p.king_file[0]));
    }
    inline fn bkf(c: *const Ctx) i32 {
        return @as(i8, @bitCast(c.p.king_file[1]));
    }
    inline fn wkr(c: *const Ctx) i32 {
        return @as(i8, @bitCast(c.p.king_rank[0]));
    }
    inline fn bkr(c: *const Ctx) i32 {
        return @as(i8, @bitCast(c.p.king_rank[1]));
    }
    /// Castling stamps: DG:B426 White O-O, 3A30 White O-O-O, B428 / 3A32 Black.
    inline fn wOO(c: *const Ctx) u16 {
        return c.p.oo_lost_at[0];
    }
    inline fn wOOO(c: *const Ctx) u16 {
        return c.p.ooo_lost_at[0];
    }
    inline fn bOO(c: *const Ctx) u16 {
        return c.p.oo_lost_at[1];
    }
    inline fn bOOO(c: *const Ctx) u16 {
        return c.p.ooo_lost_at[1];
    }
    /// Signed views of the material words.
    inline fn wpm(c: *const Ctx) i16 {
        return s16(c.p.piece_material[0]);
    }
    inline fn bpm(c: *const Ctx) i16 {
        return s16(c.p.piece_material[1]);
    }
    inline fn custom(c: *const Ctx) bool {
        return c.in.style == 0;
    }

    inline fn addb(c: *Ctx, comptime addr: u16, v: i32) void {
        const p = c.t.byte(addr);
        p.* +%= b8(v);
    }
    inline fn setb(c: *Ctx, comptime addr: u16, v: i32) void {
        c.t.byte(addr).* = b8(v);
    }
    inline fn addw(c: *Ctx, comptime addr: u16, v: i32) void {
        const p = c.t.word(addr);
        p.* +%= w16(v);
    }
    inline fn setw(c: *Ctx, comptime addr: u16, v: i32) void {
        c.t.word(addr).* = w16(v);
    }
    inline fn addbs(c: *Ctx, comptime addrs: anytype, v: i32) void {
        inline for (addrs) |a| c.addb(a, v);
    }
    inline fn addws(c: *Ctx, comptime addrs: anytype, v: i32) void {
        inline for (addrs) |a| c.addw(a, v);
    }
};

inline fn tadd(table: anytype, sq: anytype, v: i32) void {
    table[@intCast(sq)] +%= w16(v);
}
inline fn badd(table: anytype, sq: anytype, v: i32) void {
    table[@intCast(sq)] +%= b8(v);
}

// ---------------------------------------------------------------------------
// The sections, in the code's order (model.SECTIONS)
// ---------------------------------------------------------------------------

pub const Section = struct {
    start: u16,
    end: u16,
    name: []const u8,
    run: *const fn (*Ctx) void,
};

/// The sections of the original routine, every class C fix off: what the replay tests run.
pub const sections = sectionsFor(pos.Fixes.original);

/// A section that reads class C switches, bound to `fixes`.
fn bind(comptime f: anytype, comptime fixes: pos.Fixes) *const fn (*Ctx) void {
    return &struct {
        fn run(c: *Ctx) void {
            f(c, fixes);
        }
    }.run;
}

/// The sections with the switches of `fixes` (DEV-010, DEV-011, DEV-012; docs/DEVIATIONS.md).
pub fn sectionsFor(comptime fixes: pos.Fixes) [37]Section {
    return .{
        .{ .start = 0x9582, .end = 0x96AD, .name = "queens_castling", .run = queensCastling },
        .{ .start = 0x96AD, .end = 0x96B2, .name = "scan_root_passed_pawns", .run = scanPassedPawns },
        .{ .start = 0x96B2, .end = 0x972B, .name = "flags", .run = flags },
        .{ .start = 0x972B, .end = 0x9970, .name = "shelter_phase", .run = shelterPhase },
        .{ .start = 0x9970, .end = 0x9DF5, .name = "base_tables", .run = baseTables },
        .{ .start = 0x9DF5, .end = 0xA0EA, .name = "kings_pawns", .run = bind(kingsPawns, fixes) },
        .{ .start = 0xA0EA, .end = 0xA31C, .name = "white_pawn_shelter", .run = whitePawnShelter },
        .{ .start = 0xA31C, .end = 0xA581, .name = "black_pawn_table", .run = blackPawnTable },
        .{ .start = 0xA581, .end = 0xA874, .name = "pawn_adjust", .run = pawnAdjust },
        .{ .start = 0xA874, .end = 0xADAA, .name = "king_zone", .run = kingZone },
        .{ .start = 0xADAA, .end = 0xB146, .name = "centrality_kings", .run = bind(centralityKings, fixes) },
        .{ .start = 0xB146, .end = 0xB362, .name = "passed_centrality", .run = bind(passedCentrality, fixes) },
        .{ .start = 0xB362, .end = 0xB55A, .name = "closed_wings", .run = bind(closedWings, fixes) },
        .{ .start = 0xB55A, .end = 0xB96F, .name = "king_wings", .run = kingWings },
        .{ .start = 0xB96F, .end = 0xBB4A, .name = "call_part2", .run = nothing },
        .{ .start = 0xBB4A, .end = 0xBDD1, .name = "rook_pawn_endings", .run = rookPawnEndings },
        .{ .start = 0xBDD1, .end = 0xBFB9, .name = "outposts", .run = outposts },
        .{ .start = 0xBFB9, .end = 0xC268, .name = "activity", .run = activity },
        .{ .start = 0xC268, .end = 0xC636, .name = "queen_attack", .run = queenAttack },
        .{ .start = 0xC636, .end = 0xCA75, .name = "knights_rooks_tables", .run = knightsRooksTables },
        .{ .start = 0xCA75, .end = 0xCD96, .name = "bare_king", .run = bareKing },
        .{ .start = 0xCD96, .end = 0xCFBE, .name = "king_attack_squares", .run = kingAttackSquares },
        .{ .start = 0xCFBE, .end = 0xD2CA, .name = "misc_tables", .run = miscTables },
        .{ .start = 0xD2CA, .end = 0xD7B3, .name = "development", .run = development },
        .{ .start = 0xD7B3, .end = 0xD8E8, .name = "development_black", .run = developmentBlack },
        .{ .start = 0xD8E8, .end = 0xDB87, .name = "storm_tables", .run = stormTables },
        .{ .start = 0xDB87, .end = 0xDE25, .name = "storm_tables_white_king", .run = stormTablesWhiteKing },
        .{ .start = 0xDE25, .end = 0xDE95, .name = "material_queens", .run = materialQueens },
        .{ .start = 0xDE95, .end = 0xE1C8, .name = "pawn_chains", .run = pawnChains },
        .{ .start = 0xE1C8, .end = 0xE428, .name = "rooks", .run = rooks },
        .{ .start = 0xE428, .end = 0xB974, .name = "final", .run = final },
        .{ .start = 0xB974, .end = 0xB980, .name = "endgame_majorities", .run = endgameMajorities },
        .{ .start = 0xB980, .end = 0xB985, .name = "reset_square_sums", .run = resetSquareSums },
        .{ .start = 0xB985, .end = 0xB9CE, .name = "dark_pawns", .run = darkPawns },
        .{ .start = 0xB9CE, .end = 0xB9D3, .name = "clear_pawn_hash", .run = nothing },
        .{ .start = 0xB9D3, .end = 0xB9D8, .name = "last_irreversible", .run = lastIrreversible },
        .{ .start = 0xB9D8, .end = 0xB9DB, .name = "return", .run = nothing },
    };
}

/// Port of prepare_eval (0000:9582-B9DB): builds every evaluation table from the root
/// position. Also sets the position's castling stamps for missing rooks, its hash keys,
/// the second balance and the square sums, and its pawns on dark squares. The original,
/// every class C fix off (`prepareEvalFixes` with `pos.Fixes.original`).
pub fn prepareEval(p: *Position, t: *Tables, in: *const Inputs) void {
    prepareEvalFixes(p, t, in, pos.Fixes.original);
}

/// prepare_eval with the class C fixes of `fixes` that touch it: DEV-010
/// (`dev010_passed_h_pawn`, `passedCentrality`), DEV-011 (`dev011_blocked_wing_table`,
/// `closedWings`) and DEV-012 (`dev012_white_pawn_table`, `kingsPawns`). With
/// `pos.Fixes.original` it is the original.
pub fn prepareEvalFixes(p: *Position, t: *Tables, in: *const Inputs, comptime fixes: pos.Fixes) void {
    var l: Locals = .{};
    var c: Ctx = .{ .p = p, .t = t, .in = in, .l = &l };
    inline for (comptime sectionsFor(fixes)) |s| s.run(&c);
}

fn nothing(_: *Ctx) void {}

/// 0000:9582-96AC: promoted queens, computer_side, the bases, the root keys, castling
/// stamps for rooks missing from their corners.
fn queensCastling(c: *Ctx) void {
    const p = c.p;
    const t = c.t;
    t.promoted_queen_slot.* = .{ 0, 0 };
    if (c.wl(6) > 0x62) {
        var si: u8 = 8;
        while (si <= 15 and c.boardAt(c.wl(si)) != pos.white_queen) si += 1;
        if (si <= 15) t.promoted_queen_slot[0] = si;
    }
    if (c.bl(6) > 0x62) {
        var si: u8 = 8;
        while (si <= 15 and c.boardAt(c.bl(si)) != pos.black_queen) si += 1;
        if (si <= 15) t.promoted_queen_slot[1] = si;
    }
    // 95E3: a game shortened below [9D92] calls 94E4, which with [9D92] non-zero
    // calls 0000:94F2: [9D92] = 0, then 1E9D:74C8, which draws on the screen
    // (38C0:8066). Probed in the original (51- section 5.5): the tables are as with
    // [9D92] = 0 and only screen variables (DG:32DA-33F5) change besides [9D92]. Not
    // ported: `Inputs` is read-only here; the caller must clear [9D92].
    if (s16(p.game_ply) < s16(c.in.reset_ply) and c.in.reset_ply != 0)
        @panic("prepare_eval: 0000:94F2 (game ply below [9D92]) is not ported");
    t.computer_side.* = 1 -% c.in.opponent_side;
    t.base_black_pawns.* = 0;
    t.base_white_pawns.* = 0;
    t.base_pieces.* = 0;
    // 9605: hash_from_scratch (4793:4026).
    const keys = p.hashFromScratch();
    p.hash_key = keys.main;
    p.pawn_hash_key = keys.pawn;
    // 9628-9675 [proved: probe.zst]: a missing rook takes away its wing's castling.
    const ply = p.game_ply;
    if (p.oo_lost_at[0] == 0 and c.wl(4) > 0x62) p.oo_lost_at[0] = ply;
    if (p.ooo_lost_at[0] == 0 and c.wl(5) > 0x62) p.ooo_lost_at[0] = ply;
    if (p.oo_lost_at[1] == 0 and c.bl(4) > 0x62) p.oo_lost_at[1] = ply;
    if (p.ooo_lost_at[1] == 0 and c.bl(5) > 0x62) p.ooo_lost_at[1] = ply;
    t.white_castling_gone.* = @intFromBool(p.oo_lost_at[0] != 0 and p.ooo_lost_at[0] != 0);
    t.black_castling_gone.* = @intFromBool(p.oo_lost_at[1] != 0 and p.ooo_lost_at[1] != 0);
}

/// Port of scan_root_passed_pawns (2B9F:5E6A-5F7E), called at 0000:96AD. A White
/// pawn is passed when no Black pawn stands on, or attacks, any square in front of it
/// below square 91; Black's mirror stops above 28.
fn scanPassedPawns(c: *Ctx) void {
    const t = c.t;
    t.passed_count_black.* = 0;
    t.passed_count_white.* = 0;
    t.passed_rank_by_file_white.* = @splat(0);
    t.passed_rank_by_file_black.* = @splat(0);
    var n: u8 = 0;
    for (8..16) |slot| {
        var sq = c.wl(slot);
        var passed = false;
        if (c.boardAt(sq) == pos.white_pawn) {
            if (sq >= 120) @panic("scan_root_passed_pawns: a captured pawn's entry matches a White pawn past the board");
            var s: usize = sq + 10;
            passed = true;
            while (s < 0x5B) : (s += 10) {
                if (c.batt(s) != 0 or c.board(s) == pos.black_pawn) {
                    passed = false;
                    break;
                }
            }
        }
        if (passed) {
            t.passed_pawn_sq_white[slot] = sq;
            const r: i8 = @bitCast(rank_of[sq]);
            const f = file_of[sq];
            const cur: *u8 = &t.passed_rank_by_file_white[f - 1];
            if (@as(i8, @bitCast(cur.*)) < r) cur.* = @bitCast(r);
            t.passed_count_white.* +%= 1;
            n +%= 1;
        } else t.passed_pawn_sq_white[slot] = 0;

        sq = c.bl(slot);
        passed = false;
        if (c.boardAt(sq) == pos.black_pawn) {
            if (sq >= 120) @panic("scan_root_passed_pawns: a captured pawn's entry matches a Black pawn past the board");
            var s: usize = sq - 10;
            passed = true;
            while (s > 0x1C) : (s -= 10) {
                if (c.watt(s) != 0 or c.board(s) == pos.white_pawn) {
                    passed = false;
                    break;
                }
            }
        }
        if (passed) {
            t.passed_pawn_sq_black[slot] = sq;
            const r: i8 = @bitCast(rank_of[sq]);
            const f = file_of[sq];
            const cur: *u8 = &t.passed_rank_by_file_black[f - 1];
            if (cur.* == 0 or @as(i8, @bitCast(cur.*)) > r) cur.* = @bitCast(r);
            t.passed_count_black.* +%= 1;
            n +%= 1;
        } else t.passed_pawn_sq_black[slot] = 0;
    }
    t.passed_count_both.* = n;
}

/// 0000:96B2-972A: castling state changed at this ply or the one before; the queens.
fn flags(c: *Ctx) void {
    const p = c.p;
    const ply = p.game_ply;
    const stamps = [4]u16{ p.oo_lost_at[0], p.ooo_lost_at[0], p.oo_lost_at[1], p.ooo_lost_at[1] };
    for (stamps) |s| {
        if (ply == s or ply -% s -% 1 == 0) c.t.castling_or_phase_changed.* = 1;
    }
    c.l.qw = c.wl(6) < 0x63 or c.t.promoted_queen_slot[0] != 0;
    c.l.qb = c.bl(6) < 0x63 or c.t.promoted_queen_slot[1] != 0;
}

/// 0000:972B-996F: shelter_by_rank, the development count, A360, the phase flags and
/// the mobility weights.
fn shelterPhase(c: *Ctx) void {
    const p = c.p;
    const t = c.t;
    for (0..10) |i| t.shelter_by_rank[i] = fb(i);
    if (p.pawn_count <= 11) {
        inline for (.{ 5, 7, 8, 9 }) |i| t.shelter_by_rank[i] -%= 30;
    }
    // 975E: development count
    var si: u8 = 0;
    t.phase_developing.* = 0;
    t.phase_opening.* = 0;
    if (p.total_material >= 0x2DB4) {
        if (t.white_castling_gone.* == 0) si = 1;
        if (t.black_castling_gone.* == 0) si += 1;
        const checks = [_][4]u8{
            .{ 0, 0x1B, 28, 4 },     .{ 1, 0x16, 21, 4 },     .{ 2, 0x1A, 28, 4 },     .{ 3, 0x17, 21, 4 },
            .{ 16, 0x61, 98, 0x0B }, .{ 17, 0x5C, 91, 0x0B }, .{ 18, 0x60, 98, 0x0B }, .{ 19, 0x5D, 91, 0x0B },
        };
        for (checks) |k| {
            if (p.piece_list[k[0]] == k[1] and c.board(k[2]) == k[3]) si += 1;
        }
        if (si >= 2) t.phase_developing.* = 1;
        if (si >= 5) t.phase_opening.* = 1;
    }
    // 9810
    t.single_bishops_same_slot.* = 0;
    if (c.wl(2) < 0x63 and c.bl(2) < 0x63 and c.wl(3) > 0x62 and c.bl(3) > 0x62) t.single_bishops_same_slot.* = 1;
    if (c.wl(3) < 0x63 and c.bl(3) < 0x63 and c.wl(2) > 0x62 and c.bl(2) > 0x62) t.single_bishops_same_slot.* = 2;
    // 9857: phase flags
    const old_eg = t.endgame.*;
    const old_late = t.late_endgame.*;
    t.kbn_vs_king.* = 0;
    t.no_pawns.* = 0;
    t.endgame.* = 0;
    t.late_endgame.* = 0;
    if (p.piece_material_sum <= 0x1C20) {
        if (!(c.l.qw and c.l.qb and c.wpm() >= 0xC1C and c.bpm() >= 0xC1C)) {
            t.endgame.* = 1;
            if (p.piece_material_sum <= 0x1388 and !c.l.qw and !c.l.qb) t.late_endgame.* = 1;
            if (p.piece_material_sum >= 0x44C and (p.piece_material[0] == 0 or p.piece_material[1] == 0)) {
                if (p.material[0] == 0x546 and p.side_pawn_count[0] == 0) t.kbn_vs_king.* = 1;
                if (p.material[1] == 0x546 and p.side_pawn_count[1] == 0) t.kbn_vs_king.* = 1;
            }
        }
    }
    if (p.pawn_count == 0) t.no_pawns.* = 1;
    if (old_eg != t.endgame.* or old_late != t.late_endgame.*) t.castling_or_phase_changed.* = 1;
    // 9910: mobility weights by piece code
    const base: usize = if (t.phase_opening.* != 0) 0x0A else if (t.endgame.* != 0) 0x26 else 0x18;
    for (0..14) |i| t.mobilityWeight(i).* = fsb(base + i);
}

/// 0000:9970-9DF4: centrality, knights, rooks, bishops, queens and their first
/// corrections.
fn baseTables(c: *Ctx) void {
    const p = c.p;
    const t = c.t;
    const ph: u8 = if (t.phase_opening.* != 0) 1 else if (t.endgame.* == 0) 2 else 0;
    for (21..99) |sq| {
        const v = fb(0x7A6 + sq) +% ph;
        t.centrality_black[sq] = v;
        t.centrality_white[sq] = v;
    }
    if (t.late_endgame.* == 0) {
        for (21..99) |sq| {
            t.centrality_white[sq] +%= fb(0x80A + mirror(sq));
            t.centrality_black[sq] +%= fb(0x80A + sq);
        }
    }
    for (21..99) |sq| {
        const mi = mirror(sq);
        t.knight_white[sq] = s16(fw(0x8D2 + 2 * mi) +% 0x84);
        t.knight_black[sq] = s16(fw(0x8D2 + 2 * sq) +% 0x84);
        t.rook_black[sq] = 0xB4;
        t.rook_white[sq] = 0xB4;
        t.bishop_white[sq] = @as(i16, fsb(0x86E + mi)) + 0xE4;
        t.bishop_black[sq] = @as(i16, fsb(0x86E + sq)) + 0xE4;
    }
    // 9A3D: rooks on the 4th and 5th ranks against many pawns
    if (@as(i8, @bitCast(p.side_pawn_count[0])) > 5) {
        for (0x33..0x45) |sq| tadd(t.rook_black, sq, -12);
    }
    if (@as(i8, @bitCast(p.side_pawn_count[1])) > 5) {
        for (0x33..0x45) |sq| tadd(t.rook_white, sq, -12);
    }
    if (c.board(36) != pos.white_pawn) tadd(t.bishop_white, 46, 4);
    if (c.board(86) != pos.black_pawn) tadd(t.bishop_black, 76, 4);
    if (c.wpf(1) != 0 and c.board(32) == pos.white_pawn) tadd(t.rook_white, 31, -24);
    if (c.wpf(8) != 0 and c.board(37) == pos.white_pawn) tadd(t.rook_white, 38, -24);
    if (c.bpf(1) != 0 and c.board(82) == pos.black_pawn) tadd(t.rook_black, 81, -24);
    if (c.bpf(8) != 0 and c.board(87) == pos.black_pawn) tadd(t.rook_black, 88, -24);
    // 9ACF-9B76: queens, by distance to both kings
    for (21..99) |sq| {
        const f: i32 = @as(i8, @bitCast(file_of[sq]));
        const r: i32 = @as(i8, @bitCast(rank_of[sq]));
        const dbf = @abs(f - c.bkf());
        const dwf = @abs(f - c.wkf());
        const dbr = @abs(r - c.bkr());
        const dwr = @abs(r - c.wkr());
        const db: i32 = @intCast(@max(dbr, dbf));
        const dw: i32 = @intCast(@max(dwr, dwf));
        const v = w16(0x28C - db - dw);
        t.queen_black[sq] = v;
        t.queen_white[sq] = v;
        var a: i16 = w16(12 - db);
        var b: i16 = w16(12 - dw);
        if (c.custom()) {
            // Custom style (9B18-9B5D): proved by tests/golden/evaltables/custom.zst, the
            // style set in memory at the call site (the dialog could not be confirmed in
            // the emulator, 51- §7.2).
            if (c.in.opponent_side != 0) a = scaleByAggression(a, c.in.aggression) else b = scaleByAggression(b, c.in.aggression);
        }
        t.queen_white[sq] +%= a;
        t.queen_black[sq] +%= b;
    }
    // 9BE4: queen +8 on the squares a lone bishop (colour assumed from its slot) misses
    if (c.wl(2) < 0x63 and c.wl(3) > 0x62) {
        for (21..99) |sq| if (dark[sq] != 0) tadd(t.queen_white, sq, 8);
    }
    if (c.wl(3) < 0x63 and c.wl(2) > 0x62) {
        for (21..99) |sq| if (dark[sq] == 0) tadd(t.queen_white, sq, 8);
    }
    if (c.bl(2) < 0x63 and c.bl(3) > 0x62) {
        for (21..99) |sq| if (dark[sq] == 0) tadd(t.queen_black, sq, 8);
    }
    if (c.bl(3) < 0x63 and c.bl(2) > 0x62) {
        for (21..99) |sq| if (dark[sq] != 0) tadd(t.queen_black, sq, 8);
    }
    // 9C78: the enemy's knight and own queen in the corners
    const Corner = struct { rook_sq: usize, rook: u8, white_knight_tab: bool, att_white: bool, att_sq: usize };
    const corners = [_]Corner{
        .{ .rook_sq = 21, .rook = 4, .white_knight_tab = false, .att_white = true, .att_sq = 42 },
        .{ .rook_sq = 28, .rook = 4, .white_knight_tab = false, .att_white = true, .att_sq = 47 },
        .{ .rook_sq = 91, .rook = 0x0B, .white_knight_tab = true, .att_white = false, .att_sq = 72 },
        .{ .rook_sq = 98, .rook = 0x0B, .white_knight_tab = true, .att_white = false, .att_sq = 77 },
    };
    for (corners) |k| {
        const n_tab = if (k.white_knight_tab) t.knight_white else t.knight_black;
        const q_tab = if (k.white_knight_tab) t.queen_white else t.queen_black;
        if (c.board(k.rook_sq) != k.rook) {
            tadd(n_tab, k.rook_sq, 0x82);
        } else if (t.endgame.* != 0) {
            tadd(n_tab, k.rook_sq, 0x50);
        } else {
            tadd(q_tab, k.rook_sq, -0x30);
        }
        const att = if (k.att_white) c.watt(k.att_sq) else c.batt(k.att_sq);
        if (att == 0) tadd(n_tab, k.rook_sq, 0x32);
    }
    // 9D31: rooks
    if (t.late_endgame.* != 0 or p.pawn_count <= 4) {
        if (p.side_pawn_count[0] <= 2) {
            for (1..9) |f| tadd(t.rook_black, 20 + f, 8);
        } else {
            for (1..9) |f| {
                tadd(t.rook_black, 30 + f, 12);
                tadd(t.rook_black, 20 + f, 12);
            }
        }
        if (p.side_pawn_count[1] <= 2) {
            for (1..9) |f| tadd(t.rook_white, 90 + f, 8);
        } else {
            for (1..9) |f| {
                tadd(t.rook_white, 80 + f, 12);
                tadd(t.rook_white, 90 + f, 12);
            }
        }
    } else {
        var r: usize = 20;
        while (r <= 90) : (r += 10) {
            tadd(t.rook_white, r + 4, 12);
            tadd(t.rook_white, r + 5, 12);
            tadd(t.rook_black, r + 4, 12);
            tadd(t.rook_black, r + 5, 12);
        }
        if (t.phase_opening.* == 0) {
            for (1..9) |f| {
                tadd(t.rook_white, 80 + f, 12);
                tadd(t.rook_white, 90 + f, 12);
                tadd(t.rook_black, 30 + f, 12);
                tadd(t.rook_black, 20 + f, 12);
            }
        }
    }
}

fn fillPawns(table: *align(1) [100]i16, src: usize, comptime mirrored: bool) void {
    for (31..89) |sq| table[sq] = fsb(src + if (mirrored) mirror(sq) else sq);
}

/// 0000:9DF5-A0E9: king tables; pawn tables cleared; White's pawn table chosen.
fn kingsPawns(c: *Ctx, comptime fixes: pos.Fixes) void {
    const p = c.p;
    const t = c.t;
    for (21..99) |sq| {
        t.king_white[sq] = s16(fw(0x1D4 + 2 * mirror(sq)) -% 0x18);
        t.king_black[sq] = s16(fw(0x1D4 + 2 * sq) -% 0x18);
    }
    t.pawn_white.* = @splat(0);
    t.pawn_black.* = @splat(0);
    t.root_white_queenless.* = 0;
    t.root_black_queenless.* = 0;
    c.l.kside = 0;
    if (c.bpm() <= 0xE10 and !c.l.qb) return fillPawns(t.pawn_white, 0x74C, true);
    const kf = c.wkf();
    if (kf >= 6) {
        c.l.kside = 1;
        return fillPawns(t.pawn_white, 0x684, true);
    }
    if (kf <= 3) {
        c.l.kside = 2;
        return fillPawns(t.pawn_white, 0x6E8, true);
    }
    if (kf == 4) return fillPawns(t.pawn_white, 0x620, true);
    // king on the e-file
    const short_ok = p.oo_lost_at[0] == 0 and c.bpf(7) != 0 and c.bpf(8) != 0 and c.wpf(7) != 0 and c.wpf(8) != 0;
    var v6: i32 = if (short_ok) 12 else 24;
    if (c.board(51) == pos.black_pawn or c.board(61) == pos.black_pawn) v6 -= 12;
    if (c.board(52) == pos.black_pawn or c.board(62) == pos.black_pawn) v6 -= 12;
    if (v6 < 0) v6 = 0;
    var v8: i32 = 24;
    if (c.board(58) == pos.black_pawn or c.board(68) == pos.black_pawn) v8 -= 12;
    if (c.board(57) == pos.black_pawn or c.board(67) == pos.black_pawn) v8 -= 12;
    const long_ok = p.ooo_lost_at[0] == 0 and c.bpf(1) != 0 and c.bpf(2) != 0 and c.wpf(1) != 0 and c.wpf(2) != 0;
    if (long_ok) {
        tadd(t.king_white, 22, v6);
        if (c.board(33) == pos.white_pawn) tadd(t.king_white, 23, v6);
    }
    if (p.oo_lost_at[0] != 0) {
        // 9FF4 [proved: probe.zst]: the original's 0620 fill (9FFA-A018) falls through into the
        // 05BC fill (A01A), which overwrites it, so White never gets 0620 here. Black's mirror
        // (A4B4) jumps out after its 0620 fill (A4C6). DEV-012, corrected
        // (`dev012_white_pawn_table`): the 0620 fill stands, as for Black.
        if (long_ok) {
            fillPawns(t.pawn_white, 0x620, true);
            if (fixes.dev012_white_pawn_table) return;
        }
        return fillPawns(t.pawn_white, 0x5BC, true);
    }
    if (short_ok) {
        tadd(t.king_white, 27, v8);
        fillPawns(t.pawn_white, if (long_ok) 0x558 else 0x684, true);
    } else {
        fillPawns(t.pawn_white, if (long_ok) 0x620 else 0x558, true);
    }
}

/// 0000:9526 (sq, v): White pawn table += v; if a White pawn stands there, [A008] -= v.
fn addWhitePawnSq(c: *Ctx, sq: usize, v: i32) void {
    tadd(c.t.pawn_white, sq, v);
    if (c.board(sq) == pos.white_pawn) c.t.base_white_pawns.* -%= w16(v);
}
/// 0000:94FE (sq, v): Black pawn table += v; if a Black pawn stands there, [7468] += v.
fn addBlackPawnSq(c: *Ctx, sq: usize, v: i32) void {
    tadd(c.t.pawn_black, sq, v);
    if (c.board(sq) == pos.black_pawn) c.t.base_black_pawns.* +%= w16(v);
}
/// 0000:9568 (sq, v): White pawn table += v unless a White pawn stands there.
fn addWhitePawnSqIfEmpty(c: *Ctx, sq: usize, v: i32) void {
    if (c.board(sq) != pos.white_pawn) tadd(c.t.pawn_white, sq, v);
}
/// 0000:954E (sq, v): Black pawn table += v unless a Black pawn stands there.
fn addBlackPawnSqIfEmpty(c: *Ctx, sq: usize, v: i32) void {
    if (c.board(sq) != pos.black_pawn) tadd(c.t.pawn_black, sq, v);
}

/// 0000:A0EA-A31B: White's pawn table averaged with 074C; the storm and shelter pushes.
fn whitePawnShelter(c: *Ctx) void {
    const t = c.t;
    const WP = pos.white_pawn;
    if (c.bpm() <= 0xE10) {
        c.l.kside = 0;
        if (c.bl(6) < 0x63) {
            for (31..89) |sq| t.pawn_white[sq] = w16(@as(i16, fsb(0x74C + mirror(sq))) +% t.pawn_white[sq]) >> 1;
        }
    }
    if (c.bl(6) > 0x62) {
        c.l.kside = 0;
        t.root_black_queenless.* +%= 1;
    }
    if (c.l.kside == 1 or c.wOO() == 0) {
        var v: i32 = 24;
        if (c.bkf() >= 5 and c.bOOO() != 0) v = 12;
        if (c.board(58) == WP or c.board(68) == WP) {
            addWhitePawnSq(c, 78, 12);
            addWhitePawnSq(c, 88, 12);
            if (c.board(58) == WP) {
                c.addw(0xA960, 18); // WP[h4]
                t.base_white_pawns.* -%= w16(v);
            }
            if (c.board(68) == WP) {
                c.addw(0xA974, 18); // WP[h5]
                t.base_white_pawns.* -%= w16(v);
            }
        }
        if (c.board(57) == WP or c.board(67) == WP) {
            addWhitePawnSq(c, 77, 12);
            addWhitePawnSq(c, 87, 12);
            if (c.board(57) == WP) {
                c.addw(0xA95E, 18); // WP[g4]
                t.base_white_pawns.* -%= w16(v);
            }
            if (c.board(67) == WP) {
                c.addw(0xA972, 18); // WP[g5]
                t.base_white_pawns.* -%= w16(v);
            }
        }
    } else if (c.l.kside == 2) {
        // [proved: probe.zst]
        var v: i32 = 24;
        if (c.bkf() <= 4) v = 12;
        if (c.board(51) == WP or c.board(61) == WP) {
            addWhitePawnSq(c, 71, 12);
            addWhitePawnSq(c, 81, 12);
            if (c.board(51) == WP) {
                c.addw(0xA952, 18); // WP[a4]
                t.base_white_pawns.* -%= w16(v);
            }
            if (c.board(61) == WP) {
                c.addw(0xA966, 18); // WP[a5]
                t.base_white_pawns.* -%= w16(v);
            }
        }
        if (c.board(52) == WP or c.board(62) == WP) {
            addWhitePawnSq(c, 72, 12);
            addWhitePawnSq(c, 82, 12);
            if (c.board(52) == WP) {
                c.addw(0xA954, 18); // WP[b4]
                t.base_white_pawns.* -%= w16(v);
            }
            if (c.board(62) == WP) {
                c.addw(0xA968, 18); // WP[b5]
                t.base_white_pawns.* -%= w16(v);
            }
        }
    }
    // A27E: the shelter squares in front of the king
    if (c.l.kside == 1 or (c.l.qb and c.wkf() >= 6)) {
        addWhitePawnSq(c, 38, 12);
        addWhitePawnSq(c, 37, 12);
        if (c.board(36) != WP) addWhitePawnSq(c, 37, 12);
    } else if (c.l.kside == 2 or (c.l.qb and c.wkf() <= 3)) {
        addWhitePawnSq(c, 31, 12);
        addWhitePawnSq(c, 32, 12);
        if (c.board(33) != WP) addWhitePawnSq(c, 32, 12);
    } else if (c.wOO() == 0) {
        if (c.board(36) != WP and c.board(46) != WP) addWhitePawnSq(c, 37, if (c.wOOO() == 0) 18 else 24);
    } else if (c.wOOO() == 0) {
        if (c.board(33) != WP and c.board(43) != WP) addWhitePawnSq(c, 32, 24);
    }
}

/// 0000:A31C-A580: Black's pawn table chosen (the 5857 tables unmirrored).
fn blackPawnTable(c: *Ctx) void {
    const t = c.t;
    c.l.kside = 0;
    if (c.wpm() <= 0xE10 and !c.l.qw) return fillPawns(t.pawn_black, 0x74C, false);
    const kf = c.bkf();
    if (kf >= 6) {
        c.l.kside = 1;
        return fillPawns(t.pawn_black, 0x684, false);
    }
    if (kf <= 3) {
        c.l.kside = 2;
        return fillPawns(t.pawn_black, 0x6E8, false);
    }
    if (kf == 4) return fillPawns(t.pawn_black, 0x620, false);
    const WP = pos.white_pawn;
    const short_ok = c.bOO() == 0 and c.bpf(7) != 0 and c.bpf(8) != 0 and c.wpf(7) != 0 and c.wpf(8) != 0;
    var v6: i32 = if (short_ok) 12 else 24;
    if (c.board(51) == WP or c.board(61) == WP) v6 -= 12;
    if (c.board(52) == WP or c.board(62) == WP) v6 -= 12;
    if (v6 < 0) v6 = 0;
    var v8: i32 = 24;
    if (c.board(58) == WP or c.board(68) == WP) v8 -= 12;
    if (c.board(57) == WP or c.board(67) == WP) v8 -= 12;
    const long_ok = c.bOOO() == 0 and c.bpf(1) != 0 and c.bpf(2) != 0 and c.wpf(1) != 0 and c.wpf(2) != 0;
    if (long_ok) {
        c.addw(0x73E2, v6); // BK[b8]
        if (c.board(83) == pos.black_pawn) c.addw(0x73E4, v6); // BK[c8]
    }
    if (c.bOO() != 0) return fillPawns(t.pawn_black, if (long_ok) 0x620 else 0x5BC, false);
    if (short_ok) {
        c.addw(0x73EC, v8); // BK[g8]
        fillPawns(t.pawn_black, if (long_ok) 0x558 else 0x684, false);
    } else {
        fillPawns(t.pawn_black, if (long_ok) 0x620 else 0x558, false);
    }
}

/// 0000:A581-A873: Black's pawn table averaging; +12 on both pawn tables; Black's
/// storm and shelter pushes; central pawn pairs; the king tables averaged with
/// DG:0530 / 0594 when the enemy has few pieces.
fn pawnAdjust(c: *Ctx) void {
    const p = c.p;
    const t = c.t;
    const BP = pos.black_pawn;
    if (c.wpm() <= 0xE10) {
        c.l.kside = 0;
        if (c.wl(6) < 0x63) {
            for (31..89) |sq| t.pawn_black[sq] = w16(@as(i16, fsb(0x74C + sq)) +% t.pawn_black[sq]) >> 1;
        }
    }
    if (c.wl(6) > 0x62) {
        c.l.kside = 0;
        t.root_white_queenless.* +%= 1;
    }
    // A5C2: +12 on squares 31..88 of both pawn tables; 92 for a lone pawn against pieces
    var v6: i32 = 12;
    var v8: i32 = 12;
    if (p.material[0] == 0xC8 and p.piece_material[1] != 0) {
        v6 = 0x5C;
        t.base_white_pawns.* -%= 0x50;
    }
    if (p.material[1] == 0xC8 and p.piece_material[0] != 0) {
        v8 += 0x50;
        t.base_black_pawns.* +%= 0x50;
    }
    for (31..89) |sq| {
        tadd(t.pawn_white, sq, v6);
        tadd(t.pawn_black, sq, v8);
    }
    // A617: Black's pawn storm squares
    if (c.l.kside == 1 or c.bOO() == 0) {
        var v: i32 = 24;
        if (c.wkf() >= 5 and c.wOOO() != 0) v = 12;
        if (c.board(68) == BP or c.board(58) == BP) {
            addBlackPawnSq(c, 48, 12);
            addBlackPawnSq(c, 38, 12);
            if (c.board(68) == BP) {
                c.addw(0xAAB4, 18); // BP[h5]
                t.base_black_pawns.* +%= w16(v);
            }
            if (c.board(58) == BP) {
                c.addw(0xAAA0, 18); // BP[h4]
                t.base_black_pawns.* +%= w16(v);
            }
        }
        if (c.board(67) == BP or c.board(57) == BP) {
            addBlackPawnSq(c, 47, 12);
            addBlackPawnSq(c, 37, 12);
            if (c.board(67) == BP) {
                c.addw(0xAAB2, 18); // BP[g5]
                t.base_black_pawns.* +%= w16(v);
            }
            if (c.board(57) == BP) {
                c.addw(0xAA9E, 18); // BP[g4]
                t.base_black_pawns.* +%= w16(v);
            }
        }
    } else if (c.l.kside == 2) {
        // [proved: probe.zst]
        var v: i32 = 24;
        if (c.wkf() <= 4) v = 12;
        if (c.board(61) == BP or c.board(51) == BP) {
            addBlackPawnSq(c, 41, 12);
            addBlackPawnSq(c, 31, 12);
            if (c.board(61) == BP) {
                c.addw(0xAAA6, 18); // BP[a5]
                t.base_black_pawns.* +%= w16(v);
            }
            if (c.board(51) == BP) {
                c.addw(0xAA92, 18); // BP[a4]
                t.base_black_pawns.* +%= w16(v);
            }
        }
        if (c.board(62) == BP or c.board(52) == BP) {
            addBlackPawnSq(c, 42, 12);
            addBlackPawnSq(c, 32, 12);
            if (c.board(62) == BP) {
                c.addw(0xAAA8, 18); // BP[b5]
                t.base_black_pawns.* +%= w16(v);
            }
            if (c.board(52) == BP) {
                c.addw(0xAA94, 18); // BP[b4]
                t.base_black_pawns.* +%= w16(v);
            }
        }
    }
    // A764
    if (c.l.kside == 1 or (c.l.qw and c.bkf() >= 6)) {
        addBlackPawnSq(c, 88, 12);
        addBlackPawnSq(c, 87, 12);
        if (c.board(86) != BP) addBlackPawnSq(c, 87, 12);
    } else if (c.l.kside == 2 or (c.l.qw and c.bkf() <= 3)) {
        addBlackPawnSq(c, 81, 12);
        addBlackPawnSq(c, 82, 12);
        if (c.board(83) != BP) addBlackPawnSq(c, 82, 12);
    } else if (c.bOO() == 0) {
        if (c.board(86) != BP and c.board(76) != BP) addBlackPawnSq(c, 87, if (c.bOOO() == 0) 18 else 24);
    } else if (c.bOOO() == 0) {
        if (c.board(83) != BP and c.board(73) != BP) addBlackPawnSq(c, 82, 24);
    }
    // A800: pawns on d4 and e4 (d5 and e5)
    if (c.board(54) == pos.white_pawn and c.board(55) == pos.white_pawn) {
        c.addw(0xA96C, -12); // WP[d5]
        c.addw(0xA96E, -12); // WP[e5]
    }
    if (c.board(64) == BP and c.board(65) == BP) {
        c.addw(0xAA98, -12); // BP[d4]
        c.addw(0xAA9A, -12); // BP[e4]
    }
    // A830: king tables averaged with DG:0530 (White) and DG:0594 (Black)
    if (c.bpm() <= 0xED8) {
        for (21..99) |sq| t.king_white[sq] = w16(@as(i16, king_avg_white[sq]) +% t.king_white[sq]) >> 1;
    }
    if (c.wpm() <= 0xED8) {
        for (21..99) |sq| t.king_black[sq] = w16(@as(i16, king_avg_black[sq]) +% t.king_black[sq]) >> 1;
    }
}

fn plainZones(t: *Tables) void {
    for (21..99) |sq| {
        t.king_zone_black[sq] = fb(0x29C + sq);
        t.king_zone_white[sq] = fb(0x29C + mirror(sq));
    }
}

fn cornerZone(table: *align(1) [100]i16, src: usize) void {
    for (21..99) |sq| table[sq] = w16((@as(i32, fw(src + 2 * sq)) - 100) << 1);
}

/// Shelter count of 0000:A8B7 and its mirrors: c >= 2 means the wing is weak.
fn wingCount(c: *const Ctx, comptime white: bool, comptime king_side: bool) i32 {
    const own = if (white) pos.white_pawn else pos.black_pawn;
    // files: edge e, next n, third t (h g f, or a b c); rank steps away from home
    const e: usize = if (king_side) 8 else 1;
    const n: usize = if (king_side) 7 else 2;
    const tf: usize = if (king_side) 6 else 3;
    const r1: usize = if (white) 30 else 80; // second rank
    const r2: usize = if (white) 40 else 70; // third rank
    const ownpf = if (white) c.p.pawns_per_file[0] else c.p.pawns_per_file[1];
    const opppf = if (white) c.p.pawns_per_file[1] else c.p.pawns_per_file[0];
    var k: i32 = if (opppf[e] == 0) 1 else 0;
    if (ownpf[e] == 0 or opppf[n] == 0) k += 2;
    if (c.board(r1 + n) != own) {
        if (c.board(r2 + n) != own) k += 1;
        if (ownpf[n] == 0) k += 1;
        if (c.board(r1 + tf) != own and c.board(r2 + tf) != own) k += 1;
    }
    if (c.board(r1 + e) != own and c.board(r2 + e) != own) k += 1;
    return k;
}

/// 0000:A874-ADA9: king zones; castling-side king and queen corrections (not in the
/// endgame); endgame king zones (driving the bare king).
fn kingZone(c: *Ctx) void {
    const p = c.p;
    const t = c.t;
    if (t.endgame.* == 0) {
        for (21..99) |sq| {
            t.king_zone_white[sq] = fb(0x29C + mirror(sq));
            t.king_zone_black[sq] = fb(0x29C + sq);
        }
        var flag = false;
        if (c.wOO() == 0) {
            c.addw(0x7292, -12); // WK[e1]
            if (wingCount(c, true, true) >= 2) {
                c.addws(.{ 0x7294, 0x7296, 0x7298, 0x72A8, 0x72AA, 0x72AC }, -16); // WK f1 g1 h1 f2 g2 h2
                flag = true;
            }
        }
        if (c.wOOO() == 0) {
            if (wingCount(c, true, false) >= 2) {
                c.addws(.{ 0x728E, 0x728C, 0x728A, 0x72A2, 0x72A0, 0x729E }, -16); // WK c1 b1 a1 c2 b2 a2
            } else if (c.wOO() != 0 or flag) {
                c.addws(.{ 0x8E16, 0x8E18, 0x8E1A }, -12); // WQ b1 c1 d1
            }
        }
        flag = false;
        if (c.bOO() == 0) {
            c.addw(0x73E8, -12); // BK[e8]
            if (wingCount(c, false, true) >= 2) {
                c.addws(.{ 0x73EA, 0x73EC, 0x73EE, 0x73D6, 0x73D8, 0x73DA }, -16); // BK f8 g8 h8 f7 g7 h7
                flag = true;
            }
        }
        if (c.bOOO() == 0) {
            if (wingCount(c, false, false) >= 2) {
                c.addws(.{ 0x73E4, 0x73E2, 0x73E0, 0x73D0, 0x73CE, 0x73CC }, -16); // BK c8 b8 a8 c7 b7 a7
            } else if (c.bOO() != 0 or flag) {
                c.addws(.{ 0x8F70, 0x8F72, 0x8F74 }, -12); // BQ b8 c8 d8
            }
        }
        return;
    }
    // AB38: endgame
    if (t.no_pawns.* == 0) return plainZones(t);
    const bal = s16(p.piece_balance);
    if (bal >= 400) {
        for (21..99) |sq| t.king_zone_white[sq] = fb(0x29C + mirror(sq));
        if (p.material[1] == 0x2BC) {
            cornerZone(t.king_zone_black, if (c.bl(3) < 0x63) 0x3C8 else 0x490);
        } else if (t.kbn_vs_king.* != 0) {
            cornerZone(t.king_zone_black, if (c.wl(2) < 0x63) 0x3C8 else 0x490);
        } else {
            cornerZone(t.king_zone_black, 0x300);
        }
    } else if (bal <= -400) {
        for (21..99) |sq| t.king_zone_black[sq] = fb(0x29C + sq);
        if (p.material[0] == 0x2BC) {
            cornerZone(t.king_zone_white, if (c.wl(3) < 0x63) 0x490 else 0x3C8);
        } else if (t.kbn_vs_king.* != 0) {
            cornerZone(t.king_zone_white, if (c.bl(2) < 0x63) 0x490 else 0x3C8);
        } else {
            cornerZone(t.king_zone_white, 0x300);
        }
    } else plainZones(t);
}

/// Adds `v` to the bytes at the DGROUP addresses `o + k` (k a king square), for a
/// list of (o, v) pairs with o inside the centrality tables.
inline fn centAround(t: *Tables, k: usize, comptime list: anytype) void {
    inline for (list) |e| {
        const o: usize = e[0];
        // The code's offsets are the table's address plus -31..+31: those from 0xB589
        // on are in Black's table (B5A8), the others in White's (B522).
        if (o >= 0xB589) {
            t.centrality_black[o + k - Tables.dg.centrality_black] +%= e[1];
        } else {
            t.centrality_white[o + k - Tables.dg.centrality_white] +%= e[1];
        }
    }
}

fn stepTarget(sq: usize, step: i8) usize {
    return @intCast(@as(isize, @intCast(sq)) + step);
}
/// DEV-056: a ring target `tq` more than 3 files from the king on `k` has wrapped.
fn ringWraps(k: usize, tq: isize) bool {
    const fk: isize = @intCast(k % 10);
    return @abs(fk - @mod(tq, 10)) > 3;
}

fn inBoardRange(sq: isize) bool {
    return sq >= 0x15 and sq <= 0x62;
}

/// The three step tables around square k, in the code's order (k = 7..0; king step,
/// knight step, two-square step only inside 21..98): table `first` += v1, `second` += v2.
fn ringAround(first: *[120]u8, second: *[120]u8, k: usize, kv: [2]u8, nv: [2]u8, tv: [2]u8) void {
    var si: usize = 8;
    while (si > 0) {
        si -= 1;
        var tq = stepTarget(k, king_steps[si]);
        first[tq] +%= kv[0];
        second[tq] +%= kv[1];
        tq = stepTarget(k, knight_steps[si]);
        first[tq] +%= nv[0];
        second[tq] +%= nv[1];
        const t3 = @as(isize, @intCast(k)) + two_steps[si];
        if (inBoardRange(t3)) {
            first[@intCast(t3)] +%= tv[0];
            second[@intCast(t3)] +%= tv[1];
        }
    }
}

/// 0000:ADAA-B145: pawn tables in the late endgame; otherwise centrality around both
/// kings. DEV-056 (`dev056_king_ring_wrap`): the 13-offset rings (DG:1520, DG:152E) are
/// tested only against the index range 21..98, so from a king on the a- or h-file their
/// offsets of 3 files reach a square of the far side of another rank. Corrected, such a
/// target (more than 3 files from the king) is skipped. The other steps here move at
/// most 2 files, so a wrapped one lands on a border column, which no piece reads.
fn centralityKings(c: *Ctx, comptime fixes: pos.Fixes) void {
    const t = c.t;
    if (t.late_endgame.* != 0) {
        for (1..9) |f| {
            tadd(t.pawn_black, 80 + f, -6);
            tadd(t.pawn_black, 70 + f, -6);
            tadd(t.pawn_white, 30 + f, -6);
            tadd(t.pawn_white, 40 + f, -6);
        }
        return;
    }
    const cw = t.centrality_white;
    const cb = t.centrality_black;
    if (t.endgame.* != 0 or t.phase_opening.* != 0) {
        var di: usize = c.wl(7);
        centAround(t, di, .{ .{ 0xB5A8, 0x10 }, .{ 0xB5A9, 0x10 }, .{ 0xB523, 4 }, .{ 0xB5A7, 0x10 }, .{ 0xB521, 4 }, .{ 0xB5B1, 0x10 }, .{ 0xB52B, 4 }, .{ 0xB5B2, 0x10 }, .{ 0xB52C, 4 }, .{ 0xB5B3, 0x10 }, .{ 0xB52D, 4 }, .{ 0xB5BB, 8 }, .{ 0xB535, 4 }, .{ 0xB5BC, 8 }, .{ 0xB536, 4 }, .{ 0xB5BD, 8 }, .{ 0xB537, 4 } });
        ringAround(cb, cw, di, .{ 8, 6 }, .{ 6, 4 }, .{ 6, 4 });
        di = c.bl(7);
        centAround(t, di, .{ .{ 0xB522, 0x10 }, .{ 0xB523, 0x10 }, .{ 0xB5A9, 4 }, .{ 0xB521, 0x10 }, .{ 0xB5A7, 4 }, .{ 0xB519, 0x10 }, .{ 0xB59F, 4 }, .{ 0xB518, 0x10 }, .{ 0xB59E, 4 }, .{ 0xB517, 0x10 }, .{ 0xB59D, 4 }, .{ 0xB50F, 8 }, .{ 0xB595, 4 }, .{ 0xB50E, 8 }, .{ 0xB594, 4 }, .{ 0xB50D, 8 }, .{ 0xB593, 4 } });
        ringAround(cw, cb, di, .{ 8, 6 }, .{ 6, 4 }, .{ 6, 4 });
        return;
    }
    // AF48: middlegame
    var di: usize = c.wl(7);
    centAround(t, di, .{ .{ 0xB5A8, 0x24 }, .{ 0xB5A9, 0x14 }, .{ 0xB523, 8 }, .{ 0xB5A7, 0x14 }, .{ 0xB521, 8 }, .{ 0xB5B1, 0x14 }, .{ 0xB52B, 8 }, .{ 0xB5B2, 0x14 }, .{ 0xB52C, 8 }, .{ 0xB5B3, 0x14 }, .{ 0xB52D, 8 }, .{ 0xB5BB, 12 }, .{ 0xB535, 6 }, .{ 0xB5BC, 12 }, .{ 0xB536, 6 }, .{ 0xB5BD, 12 }, .{ 0xB537, 6 } });
    if (di <= 0x44) {
        centAround(t, di, .{ .{ 0xB5C5, 8 }, .{ 0xB53F, 4 }, .{ 0xB5C6, 8 }, .{ 0xB540, 4 }, .{ 0xB5C7, 8 }, .{ 0xB541, 4 } });
    }
    ringAround(cb, cw, di, .{ 0x10, 12 }, .{ 12, 8 }, .{ 12, 8 });
    var si: usize = 13;
    while (si > 0) {
        si -= 1;
        const tq = @as(isize, @intCast(di)) + king_ring_white[si];
        if (inBoardRange(tq) and !(fixes.dev056_king_ring_wrap and ringWraps(di, tq))) {
            cb[@intCast(tq)] +%= 8;
            cw[@intCast(tq)] +%= 6;
        }
    }
    di = c.bl(7);
    centAround(t, di, .{ .{ 0xB522, 0x24 }, .{ 0xB523, 0x14 }, .{ 0xB5A9, 8 }, .{ 0xB521, 0x14 }, .{ 0xB5A7, 8 }, .{ 0xB519, 0x14 }, .{ 0xB59F, 8 }, .{ 0xB518, 0x14 }, .{ 0xB59E, 8 }, .{ 0xB517, 0x14 }, .{ 0xB59D, 8 }, .{ 0xB50F, 12 }, .{ 0xB595, 6 }, .{ 0xB50E, 12 }, .{ 0xB594, 6 }, .{ 0xB50D, 12 }, .{ 0xB593, 6 } });
    if (di >= 0x33) {
        centAround(t, di, .{ .{ 0xB505, 8 }, .{ 0xB58B, 4 }, .{ 0xB504, 8 }, .{ 0xB58A, 4 }, .{ 0xB503, 8 }, .{ 0xB589, 4 } });
    }
    ringAround(cw, cb, di, .{ 0x10, 12 }, .{ 12, 8 }, .{ 12, 8 });
    si = 13;
    while (si > 0) {
        si -= 1;
        const tq = @as(isize, @intCast(di)) + king_ring_black[si];
        if (inBoardRange(tq) and !(fixes.dev056_king_ring_wrap and ringWraps(di, tq))) {
            cw[@intCast(tq)] +%= 8;
            cb[@intCast(tq)] +%= 6;
        }
    }
}

/// 0000:B146-B361: centrality around the root's passed pawns. After the loop over the
/// three step tables the original reads the rank of [bp-2] (B215; Black B318), which the
/// loop has overwritten with pawn square + [1518] = sq + 2 (51- §6.1): the run of bonuses
/// starts from that square's rank, which is the pawn's own for files a to g and the next
/// rank (Black: the one below) for an h-pawn. DEV-010, corrected (`dev010_passed_h_pawn`):
/// the run starts from the pawn's own rank, as the value is used.
fn passedCentrality(c: *Ctx, comptime fixes: pos.Fixes) void {
    const t = c.t;
    const cw = t.centrality_white;
    const cb = t.centrality_black;
    for (8..16) |slot| {
        var sq: usize = c.wl(slot);
        if (sq < 0x63 and c.board(sq) == pos.white_pawn and sq > 0x30 and t.passed_pawn_sq_white[slot] != 0) {
            const f = file_of[sq];
            cw[sq] +%= 0x10;
            cw[sq + 10] +%= 0x10;
            cb[sq] +%= 0x10;
            cb[sq + 10] +%= 0x10;
            if (sq >= 0x3D) {
                cw[90 + f] +%= 0x10;
                cb[90 + f] +%= 0x10;
            }
            var bp2: isize = @intCast(sq);
            var k: usize = 8;
            while (k > 0) {
                k -= 1;
                const t1 = stepTarget(sq, king_steps[k]);
                const t2 = stepTarget(sq, knight_steps[k]);
                cw[t1] +%= 8;
                cw[t2] +%= 4;
                cb[t1] +%= 8;
                cb[t2] +%= 4;
                bp2 = @as(isize, @intCast(sq)) + two_steps[k];
                if (inBoardRange(bp2)) {
                    cw[@intCast(bp2)] +%= 4;
                    cb[@intCast(bp2)] +%= 4;
                }
            }
            // B215: the rank of [bp-2] = sq + 2 (DEV-010 corrected: of sq).
            const run_from: usize = if (fixes.dev010_passed_h_pawn) sq else @intCast(bp2);
            const r: i32 = @as(i8, @bitCast(rank_of[run_from]));
            var d: i32 = r + 1;
            while (d < 10) : (d += 1) {
                const v = b8(((r - 2) << 2) + d);
                const o: usize = @intCast(d * 10 + f);
                cw[o] +%= v;
                cb[o] +%= v;
            }
        }
        sq = c.bl(slot);
        if (sq < 0x63 and c.board(sq) == pos.black_pawn and sq < 0x47 and t.passed_pawn_sq_black[slot] != 0) {
            const f = file_of[sq];
            cb[sq] +%= 0x10;
            cb[sq - 10] +%= 0x10;
            cw[sq] +%= 0x10;
            cw[sq - 10] +%= 0x10;
            if (sq <= 0x3A) {
                cb[20 + f] +%= 0x10;
                cw[20 + f] +%= 0x10;
            }
            var bp2: isize = @intCast(sq);
            var k: usize = 8;
            while (k > 0) {
                k -= 1;
                const t1 = stepTarget(sq, king_steps[k]);
                const t2 = stepTarget(sq, knight_steps[k]);
                cb[t1] +%= 8;
                cb[t2] +%= 4;
                cw[t1] +%= 8;
                cw[t2] +%= 4;
                bp2 = @as(isize, @intCast(sq)) + two_steps[k];
                if (inBoardRange(bp2)) {
                    cb[@intCast(bp2)] +%= 4;
                    cw[@intCast(bp2)] +%= 4;
                }
            }
            // B318: the mirror (DEV-010 corrected: the rank of sq).
            const run_from: usize = if (fixes.dev010_passed_h_pawn) sq else @intCast(bp2);
            const r6: i32 = 11 - @as(i32, @as(i8, @bitCast(rank_of[run_from])));
            var d: i32 = r6 + 1;
            while (d < 10) : (d += 1) {
                const v = b8(((r6 - 2) << 2) + d);
                const o: usize = @intCast(110 + @as(i32, f) - d * 10);
                cb[o] +%= v;
                cw[o] +%= v;
            }
        }
    }
}

/// "No passed pawn on file f (1..8)" as closed_wings asks it: of the per-slot table read at
/// [base + f] (the original), or of the per-file table, entry f - 1 (DEV-011 corrected).
fn PassedOnFile(comptime per_file: bool) type {
    return struct {
        table: if (per_file) *const [8]u8 else *const [16]u8,
        inline fn none(s: @This(), f: usize) bool {
            return s.table[if (per_file) f - 1 else f] == 0;
        }
    };
}

/// 0000:B362-B559: knights, bishops and rooks on a wing whose castling is gone. Each rule
/// asks "no passed pawn on this file?". The original reads [A3FE + file] and
/// [8CE6 + file], which the passed-pawn scan fills by pawn slot (8..15), not by file
/// (51- §6.2): files 1..7 read bytes nothing here writes, file 8 reads slot 8's square.
/// DEV-011, corrected (`dev011_blocked_wing_table`): the per-file tables the scan fills,
/// [A8DF + file] and [9EED + file], which prepare_eval_endgame (B9DC) reads for the same
/// test.
fn closedWings(c: *Ctx, comptime fixes: pos.Fixes) void {
    const t = c.t;
    const fix = fixes.dev011_blocked_wing_table;
    const pw: PassedOnFile(fix) = .{ .table = if (fix) t.passed_rank_by_file_white else t.passed_pawn_sq_white };
    const pb: PassedOnFile(fix) = .{ .table = if (fix) t.passed_rank_by_file_black else t.passed_pawn_sq_black };
    if (c.wpf(1) != 0 and pw.none(1) and c.wOO() != 0 and c.wOOO() == 0) {
        // B37E-B3DB [proved: probe.zst]
        if (c.board(21) == pos.white_rook) {
            c.addw(0x75F6, -24); // WN[b1]
            c.addw(0xAC56, -24); // WB[b1]
        }
        if (c.wpf(2) != 0 and pw.none(2)) {
            if (c.board(21) == pos.white_rook or c.board(22) == pos.white_rook) {
                c.addw(0x75F8, -24); // WN[c1]
                c.addw(0xAC58, -16); // WB[c1]
            }
            if (c.wkf() <= 4) {
                c.addw(0x91AC, -16); // WR[a1]
                c.addw(0x91AE, -16); // WR[b1]
            }
            if (c.wpf(3) != 0 and pw.none(3) and c.p.king_file[0] == 4) c.addw(0x91B0, -16); // WR[c1]
        }
    }
    if (c.wpf(8) != 0 and pw.none(8) and c.wkf() >= 5) {
        if (c.board(28) == pos.white_rook) {
            c.addw(0x7600, -24); // WN[g1]
            c.addw(0xAC60, -24); // WB[g1]
        }
        if (c.wpf(7) != 0 and pw.none(7)) {
            if (c.board(28) == pos.white_rook or c.board(27) == pos.white_rook) {
                c.addw(0x75FE, -24); // WN[f1]
                c.addw(0xAC5E, -16); // WB[f1]
            }
            if (c.wOO() != 0) {
                c.addw(0x91BA, -16); // WR[h1]
                c.addw(0x91B8, -16); // WR[g1]
            }
            if (c.wpf(6) != 0 and pw.none(6) and c.p.king_file[0] == 5 and c.wOO() != 0) c.addw(0x91B6, -16); // WR[f1]
        }
    }
    if (c.bpf(1) != 0 and pb.none(1) and c.bOO() != 0 and c.bOOO() == 0) {
        if (c.board(91) == pos.black_rook) {
            c.addw(0x775A, -24); // BN[b8]
            c.addw(0xADAC, -24); // BB[b8]
        }
        if (c.bpf(2) != 0 and pb.none(2)) {
            if (c.board(91) == pos.black_rook or c.board(92) == pos.black_rook) {
                c.addw(0x775C, -24); // BN[c8]
                c.addw(0xADAE, -16); // BB[c8]
            }
            if (c.bkf() <= 4) {
                c.addw(0x9300, -16); // BR[a8]
                c.addw(0x9302, -16); // BR[b8]
            }
            if (c.bpf(3) != 0 and pb.none(3) and c.p.king_file[1] == 4) c.addw(0x9304, -16); // BR[c8]
        }
    }
    if (c.bpf(8) != 0 and pb.none(8) and c.bkf() >= 5) {
        if (c.board(98) == pos.black_rook) {
            c.addw(0x7764, -24); // BN[g8]
            c.addw(0xADB6, -24); // BB[g8]
        }
        if (c.bpf(7) != 0 and pb.none(7)) {
            if (c.board(98) == pos.black_rook or c.board(97) == pos.black_rook) {
                c.addw(0x7762, -24); // BN[f8]
                c.addw(0xADB4, -16); // BB[f8]
            }
            if (c.bOO() != 0) {
                c.addw(0x930E, -16); // BR[h8]
                c.addw(0x930C, -16); // BR[g8]
            }
            if (c.bpf(6) != 0 and pb.none(6) and c.p.king_file[1] == 5 and c.bOO() != 0) c.addw(0x930A, -16); // BR[f8]
        }
    }
}

/// 0000:B55A-B96E: kings tucked in a corner, attack squares near the castled kings,
/// fianchetto bonuses with base compensation, central pawn chains, bishop corners.
fn kingWings(c: *Ctx) void {
    const t = c.t;
    t.black_king_tucked.* = 0;
    t.white_king_tucked.* = 0;
    if (t.endgame.* == 0) {
        if (c.wl(2) < 0x63) c.addw(0x9300, -8); // BR[a8]
        if (c.wl(3) < 0x63) c.addw(0x930E, -8); // BR[h8]
        if (c.bl(2) < 0x63) c.addw(0x91AC, -8); // WR[a1]
        if (c.bl(3) < 0x63) c.addw(0x91BA, -8); // WR[h1]
        if (c.board(23) == pos.white_king) c.addw(0x75F6, -16); // WN[b1]
        if (c.board(93) == pos.black_king) c.addw(0x775A, -16); // BN[b8]
        if (c.board(63) == pos.black_bishop and c.board(51) == 0) c.addw(0x7630, 16); // WN[a4]
        if (c.board(53) == pos.white_bishop and c.board(61) == 0) c.addw(0x771C, 16); // BN[a5]
        const bk = c.bl(7);
        if ((bk >= 0x5B and bk <= 0x5D) or bk == 0x51 or bk == 0x52) {
            t.black_king_tucked.* +%= 1;
        } else if (bk >= 0x61 or bk == 0x58 or bk == 0x57) {
            t.black_king_tucked.* = 2;
        } else {
            if (c.bkf() <= 5) c.addbs(.{ 0xB57E, 0xB57E, 0xB57E, 0xB57E, 0xB57F, 0xB57F, 0xB57F, 0xB580, 0xB580 }, 0x10);
            if (c.bkf() >= 5) c.addbs(.{ 0xB581, 0xB581, 0xB582, 0xB582, 0xB582, 0xB583, 0xB583, 0xB583, 0xB583 }, 0x10);
            if (c.p.king_file[1] == 4) c.addb(0xB581, 0x20);
        }
        const wk = c.wl(7);
        if (wk <= 0x17 or wk == 0x1F or wk == 0x20) {
            t.white_king_tucked.* +%= 1;
        } else if (wk == 0x1C or wk == 0x1B or wk == 0x26 or wk == 0x25) {
            t.white_king_tucked.* = 2;
        } else {
            if (c.wkf() <= 5) c.addbs(.{ 0xB5BE, 0xB5BE, 0xB5BE, 0xB5BE, 0xB5BF, 0xB5BF, 0xB5BF, 0xB5C0, 0xB5C0 }, 0x10);
            if (c.wkf() >= 5) c.addbs(.{ 0xB5C1, 0xB5C1, 0xB5C2, 0xB5C2, 0xB5C2, 0xB5C3, 0xB5C3, 0xB5C3, 0xB5C3 }, 0x10);
            if (c.p.king_file[0] == 4) c.addb(0xB5C1, 0x20);
        }
    }
    // B6BC
    if (t.endgame.* == 0) {
        const bkf = c.bkf();
        const wkf = c.wkf();
        if (bkf > 5 or (bkf == 5 and c.bOOO() != 0)) {
            c.addbs(.{ 0xB570, 0xB56F, 0xB56E, 0xB57A, 0xB579, 0xB578, 0xB584, 0xB583, 0xB582 }, 0x10);
            if (c.board(87) != pos.black_pawn and c.bl(2) < 0x63) {
                t.base_pieces.* +%= 0x10;
                c.addw(0xADA2, 8); // BB[g7]
                for (21..99) |sq| if (dark[sq] != 0) tadd(t.bishop_black, sq, 0x10);
            }
        }
        if (bkf < 5 or (bkf == 5 and c.bOO() != 0)) {
            c.addbs(.{ 0xB569, 0xB56A, 0xB56B, 0xB573, 0xB574, 0xB575, 0xB57D, 0xB57E, 0xB57F }, 0x10);
            if (c.board(82) != pos.black_pawn and c.bl(3) < 0x63) {
                t.base_pieces.* +%= 0x10;
                c.addw(0xAD98, 8); // BB[b7]
                for (21..99) |sq| if (dark[sq] == 0) tadd(t.bishop_black, sq, 0x10);
            }
        }
        if (wkf > 5 or (wkf == 5 and c.wOOO() != 0)) {
            c.addbs(.{ 0xB5D8, 0xB5D7, 0xB5D6, 0xB5CE, 0xB5CD, 0xB5CC, 0xB5C4, 0xB5C3, 0xB5C2 }, 0x10);
            if (c.board(37) != pos.white_pawn and c.wl(2) < 0x63) {
                t.base_pieces.* -%= 0x10;
                c.addw(0xAC74, 8); // WB[g2]
                for (21..99) |sq| if (dark[sq] == 0) tadd(t.bishop_white, sq, 0x10);
            }
        }
        if (wkf < 5 or (wkf == 5 and c.wOO() != 0)) {
            c.addbs(.{ 0xB5D1, 0xB5D2, 0xB5D3, 0xB5C7, 0xB5C8, 0xB5C9, 0xB5BD, 0xB5BE, 0xB5BF }, 0x10);
            if (c.board(32) != pos.white_pawn and c.wl(3) < 0x63) {
                t.base_pieces.* -%= 0x10;
                c.addw(0xAC6A, 8); // WB[b2]
                for (21..99) |sq| if (dark[sq] != 0) tadd(t.bishop_white, sq, 0x10);
            }
        }
        const WP = pos.white_pawn;
        const BP = pos.black_pawn;
        if (c.board(54) == WP and c.board(45) == WP and c.board(64) == BP and (c.board(83) == BP or c.board(73) == BP) and
            c.wkf() >= 7 and c.wpf(3) == 0)
        {
            // B8A7/B8AC: add word ptr [..], 18h, that is 24 (corpus1 selfplay-d3 search 18).
            c.addw(0xA954, 24); // WP[b4]
            c.addw(0xA968, 24); // WP[b5]
        }
        if (c.board(64) == BP and c.board(75) == BP and c.board(54) == WP and (c.board(33) == WP or c.board(43) == WP) and
            c.bkf() >= 7 and c.bpf(3) == 0)
        {
            // [proved: probe.zst] B8E2/B8E7: add word ptr [..], 18h, that is 24.
            c.addw(0xAAA8, 24); // BP[b5]
            c.addw(0xAA94, 24); // BP[b4]
        }
    }
    // B8EC
    if (t.late_endgame.* == 0) {
        const bkf = c.bkf();
        const wkf = c.wkf();
        if (bkf > 5 or (bkf == 5 and c.bOOO() != 0)) c.addws(.{ 0xAC62, 0xAC76, 0xAC8A }, -12); // WB h1 h2 h3
        if (bkf < 5 or (bkf == 5 and c.bOO() != 0)) c.addws(.{ 0xAC54, 0xAC68, 0xAC7C }, -12); // WB a1 a2 a3
        if (wkf > 5 or (wkf == 5 and c.wOOO() != 0)) c.addws(.{ 0xADB8, 0xADA4, 0xAD90 }, -12); // BB h8 h7 h6
        if (wkf < 5 or (wkf == 5 and c.wOO() != 0)) c.addws(.{ 0xADAA, 0xAD96, 0xAD82 }, -12); // BB a8 a7 a6
    }
}

/// 0000:BB4A-BDD0: rook and pawn against rook (total material 2400, one pawn).
fn rookPawnEndings(c: *Ctx) void {
    const p = c.p;
    const t = c.t;
    if (t.endgame.* == 0 or p.total_material != 0x960 or p.pawn_count != 1) return;
    if (p.material[0] == 0x514) {
        var si: usize = 8;
        while (si <= 15 and c.wl(si) >= 0x63) si += 1;
        const sq: usize = c.p.piece_list[si];
        if (c.boardAt(@intCast(sq)) != pos.white_pawn) return;
        const bkf = c.bkf();
        if (!(rp_0f42[sq] > bkf or rp_0fa6[sq] < bkf)) {
            if (!(@as(i8, @bitCast(rank_of[sq])) > c.bkr()) and sq >= 0x47) {
                for (1..9) |f| {
                    tadd(t.rook_black, 20 + f, 0x30);
                    tadd(t.rook_black, 30 + f, 0x30);
                }
            }
        } else if (sq >= 0x51 and rp_0850[sq] != 0) {
            for (1..9) |f| {
                tadd(t.rook_white, 50 + f, 0x38);
                tadd(t.rook_black, 50 + f, 0x18);
            }
        }
        if (sq < 0x33) return;
        for (1..9) |f| tadd(t.rook_black, 90 + f, 0x18);
        const f: usize = file_of[sq];
        var edge: usize = undefined;
        var r: usize = sq - f + 10;
        if (f >= 5) {
            edge = 1;
            while (r <= 0x62) : (r += 10) {
                for (f..9) |d| tadd(t.king_zone_black, r + d, 0x28);
            }
        } else {
            edge = 8;
            while (r <= 0x62) : (r += 10) {
                var d = f;
                while (d > 0) : (d -= 1) tadd(t.king_zone_black, r + d, 0x28);
            }
        }
        var s: usize = 0x14;
        while (s < 0x5B) : (s += 10) tadd(t.rook_black, edge + s, 0x24);
        return;
    }
    // [proved: probe.zst]
    if (p.material[1] != 0x514) return;
    var si: usize = 8;
    while (si <= 15 and c.bl(si) >= 0x63) si += 1;
    const sq: usize = c.p.piece_list[16 + si];
    if (c.boardAt(@intCast(sq)) != pos.black_pawn) return;
    const wkf = c.wkf();
    if (!(rp_0f42[sq] > wkf or rp_0fa6[sq] < wkf)) {
        if (!(@as(i8, @bitCast(rank_of[sq])) < c.wkr()) and sq <= 0x30) {
            for (1..9) |f| {
                tadd(t.rook_white, 80 + f, 0x30);
                tadd(t.rook_white, 90 + f, 0x30);
            }
        }
    } else if (sq <= 0x26 and rp_0850[sq] != 0) {
        for (1..9) |f| {
            tadd(t.rook_black, 60 + f, 0x38);
            tadd(t.rook_white, 60 + f, 0x18);
        }
    }
    if (sq > 0x44) return;
    for (1..9) |f| tadd(t.rook_white, 20 + f, 0x18);
    const f: usize = file_of[sq];
    var edge: usize = undefined;
    var r: isize = @as(isize, @intCast(sq)) - @as(isize, @intCast(f)) - 10;
    if (f >= 5) {
        edge = 1;
        while (r >= 0x14) : (r -= 10) {
            for (f..9) |d| tadd(t.king_zone_white, r + @as(isize, @intCast(d)), 0x28);
        }
    } else {
        edge = 8;
        while (r >= 0x14) : (r -= 10) {
            var d = f;
            while (d > 0) : (d -= 1) tadd(t.king_zone_white, r + @as(isize, @intCast(d)), 0x28);
        }
    }
    var s: usize = 0x14;
    while (s < 0x5B) : (s += 10) tadd(t.rook_white, edge + s, 0x24);
}

/// 0000:BDD1-BFB8: queens present; the arrays A ([bp-82h]) and B ([bp-0E6h]); king
/// centrality without pawns; late-endgame knights; the arrays into the centrality
/// bytes (not endgame) or rook +16 on half-open files (endgame).
fn outposts(c: *Ctx) void {
    const t = c.t;
    const l = c.l;
    l.qw2 = c.wl(6) < 0x63 or t.promoted_queen_slot[0] != 0;
    l.qb2 = c.bl(6) < 0x63 or t.promoted_queen_slot[1] != 0;
    l.a = @splat(0);
    l.b = @splat(0);
    const cw = t.centrality_white;
    const cb = t.centrality_black;
    if (t.no_pawns.* != 0) {
        var di: usize = c.bl(7);
        cw[di] +%= 0x10;
        ringAround(cw, cw, di, .{ 0x10, 0 }, .{ 8, 0 }, .{ 8, 0 });
        di = c.wl(7);
        cb[di] +%= 0x10;
        ringAround(cb, cb, di, .{ 0x10, 0 }, .{ 8, 0 }, .{ 8, 0 });
    }
    for (1..9) |f| {
        var si: usize = 0x14;
        while (si <= 0x32 and c.watt(f + si) == 0) : (si += 10) l.a[f + si] = 4;
    }
    for (1..9) |f| {
        var si: usize = 0x5A;
        while (si >= 0x3C and c.batt(f + si) == 0) : (si -= 10) l.b[f + si] = 4;
    }
    if (t.late_endgame.* != 0) {
        for (2..8) |si| {
            tadd(t.knight_white, 90 + si, 0x14);
            tadd(t.knight_white, 80 + si, 0x14);
            tadd(t.knight_black, 20 + si, 0x14);
            tadd(t.knight_black, 30 + si, 0x14);
        }
    }
    if (t.endgame.* == 0) {
        for (0x15..0x63) |si| {
            cw[si] +%= l.b[si];
            cb[si] +%= l.a[si];
        }
    } else if (c.p.piece_material_sum != 0x898) {
        for (0x15..0x63) |si| {
            if (l.a[si] != 0 and c.batt(si) != 0 and c.bpf(file_of[si]) == 0) tadd(t.rook_black, si, 0x10);
            if (l.b[si] != 0 and c.watt(si) != 0 and c.wpf(file_of[si]) == 0) tadd(t.rook_white, si, 0x10);
        }
    }
}

/// 0000:BFB9-C267: the activity byte tables from the centrality bytes and the mobility
/// weights.
fn activity(c: *Ctx) void {
    const t = c.t;
    for (0x15..0x63) |si| {
        const cw: i32 = t.centrality_white[si];
        const cb: i32 = t.centrality_black[si];
        t.activity_bishop_white[si] = b8(w16(cw * t.mobilityWeight(3).*) >> 4);
        t.activity_bishop_black[si] = b8(w16(cb * t.mobilityWeight(10).*) >> 4);
        t.activity_rook_white[si] = b8(w16(cw * t.mobilityWeight(4).*) >> 4);
        t.activity_rook_black[si] = b8(w16(cb * t.mobilityWeight(11).*) >> 4);
    }
    for (0x33..0x45) |si| {
        t.activity_bishop_white[si] +%= 8;
        t.activity_bishop_black[si] +%= 8;
    }
    for (0x29..0x31) |si| {
        t.activity_bishop_white[si] +%= 4;
        t.activity_bishop_black[si] +%= 6;
    }
    for (0x47..0x4F) |si| {
        t.activity_bishop_white[si] +%= 6;
        t.activity_bishop_black[si] +%= 4;
    }
    const ranges = [_][4]i32{
        .{ 0x15, 0x26, 0, 0 },        .{ 0x51, 0x62, 0, 0 },       .{ 0x33, 0x3A, 0xE0, 0x118 },
        .{ 0x3D, 0x44, 0x118, 0xE0 }, .{ 0x47, 0x4E, 0xC0, 0x80 }, .{ 0x29, 0x30, 0x80, 0xC0 },
    };
    for (ranges) |rg| {
        var si: usize = @intCast(rg[0]);
        while (si <= rg[1]) : (si += 1) {
            t.activity_knight_white[si] = b8(w16(@as(i32, t.centrality_white[si]) * t.mobilityWeight(2).* + rg[2]) >> 4);
            t.activity_knight_black[si] = b8(w16(@as(i32, t.centrality_black[si]) * t.mobilityWeight(9).* + rg[3]) >> 4);
        }
    }
    if (t.endgame.* == 0) {
        c.addbs(.{ 0xA898, 0xA899, 0xA9E0, 0xA9E1 }, 12); // WN d6 e6, BN d3 e3
        for (3..7) |si| {
            t.activity_knight_white[0x32 + si] +%= 0x18; // WN c4..f4
            t.activity_knight_white[0x3C + si] +%= 0x18; // WN c5..f5
            t.activity_knight_black[0x32 + si] +%= 0x18; // BN c4..f4
            t.activity_knight_black[0x3C + si] +%= 0x18; // BN c5..f5
        }
    }
    const mode: u2 = if (t.phase_opening.* != 0) 0 else if (t.phase_developing.* != 0) 1 else 2;
    for (0x15..0x63) |si| {
        inline for (.{ t.activity_queen_white, t.activity_queen_black }, .{ t.centrality_white, t.centrality_black }) |dst, src| {
            const x: u32 = src[si];
            dst[si] = @truncate(switch (mode) {
                0 => (x + 0x30) >> 3,
                1 => (x + 0x18) >> 2,
                else => ((x + 0x20) * 3) >> 3,
            });
        }
    }
    for (0x15..0x3B) |si| t.activity_queen_white[si] +%= 8;
    for (0x3D..0x63) |si| t.activity_queen_black[si] +%= 8;
}

fn aggressionScaled3(c: *const Ctx, side_flag: u8, v: *[3]i16, base: [3]i32) void {
    v.* = .{ w16(base[0]), w16(base[1]), w16(base[2]) };
    if (side_flag != 0 and c.custom()) {
        // Custom style (C336-C3A0, C51D-C587): proved by custom.zst (see baseTables).
        for (0..3) |i| v[i] = scaleByAggression(base[i], c.in.aggression);
    }
}

fn addAt(table: *[120]u8, base: usize, d: isize, v: i32) void {
    table[@intCast(@as(isize, @intCast(base)) + d)] +%= b8(v);
}

/// 0000:C268-C635: queen activity and pawn-storm squares near a king that has lost both
/// castlings; rook and knight activity near it, scaled by Aggression in the custom style.
fn queenAttack(c: *Ctx) void {
    const t = c.t;
    const l = c.l;
    if (t.black_castling_gone.* != 0 and l.qw2) {
        var di: usize = c.bl(7);
        const q = t.activity_queen_white;
        q[di] +%= 0x10;
        q[di - 10] +%= 0x10;
        q[di - 1] +%= 12;
        q[di + 1] +%= 12;
        ringAround(q, q, di, .{ 8, 0 }, .{ 6, 0 }, .{ 6, 0 });
        if (di >= 0x51) {
            if (di > 0x58) di -= 10;
            tadd(t.pawn_black, di, 6);
            tadd(t.pawn_black, di - 10, 12);
            if (di != 0x52 and di != 0x58) {
                tadd(t.pawn_black, di + 1, 6);
                tadd(t.pawn_black, di - 9, 12);
            }
            if (di != 0x57 and di != 0x51) {
                tadd(t.pawn_black, di - 1, 6);
                tadd(t.pawn_black, di - 11, 12);
            }
        }
    }
    var v: [3]i16 = undefined; // v4, v6, v8
    aggressionScaled3(c, c.in.opponent_side, &v, .{ 0x18, 12, 0x10 });
    if (t.black_castling_gone.* != 0 and c.wpm() >= 0x1068) {
        const di: usize = c.bl(7);
        const r = t.activity_rook_white;
        addAt(r, di, 0, v[2]);
        addAt(r, di, -10, v[2]);
        addAt(r, di, -1, v[1]);
        addAt(r, di, 1, v[1]);
        if (c.wl(5) < 0x63 or t.promoted_queen_slot[0] != 0) {
            for ([_]isize{ -9, -10, -11 }) |d| addAt(t.activity_knight_white, di, d, v[0]);
            for ([_]isize{ -19, -20, -21 }) |d| addAt(t.activity_knight_white, di, d, v[2]);
        }
        rookRing(r, di, v[0], v[1]);
    }
    if (t.white_castling_gone.* != 0 and l.qb2) {
        var di: usize = c.wl(7);
        const q = t.activity_queen_black;
        q[di] +%= 0x10;
        q[di + 10] +%= 0x10;
        q[di - 1] +%= 12;
        q[di + 1] +%= 12;
        ringAround(q, q, di, .{ 8, 0 }, .{ 6, 0 }, .{ 6, 0 });
        if (di <= 0x26) {
            if (di < 0x1F) di += 10;
            tadd(t.pawn_white, di, 6);
            tadd(t.pawn_white, di + 10, 12);
            if (di != 0x20 and di != 0x26) {
                tadd(t.pawn_white, di + 1, 6);
                tadd(t.pawn_white, di + 11, 12);
            }
            if (di != 0x25 and di != 0x1F) {
                tadd(t.pawn_white, di - 1, 6);
                tadd(t.pawn_white, di + 9, 12);
            }
        }
    }
    aggressionScaled3(c, t.computer_side.*, &v, .{ 0x18, 12, 0x10 });
    if (t.white_castling_gone.* != 0 and c.bpm() >= 0x1068) {
        const di: usize = c.wl(7);
        const r = t.activity_rook_black;
        addAt(r, di, 0, v[2]);
        addAt(r, di, 10, v[2]);
        addAt(r, di, -1, v[1]);
        addAt(r, di, 1, v[1]);
        if (c.bl(5) < 0x63 or t.promoted_queen_slot[1] != 0) {
            for ([_]isize{ 9, 10, 11 }) |d| addAt(t.activity_knight_black, di, d, v[0]);
            for ([_]isize{ 19, 20, 21 }) |d| addAt(t.activity_knight_black, di, d, v[2]);
        }
        rookRing(r, di, v[0], v[1]);
    }
}

/// The step-table loop of C3E9 / C5D0: king steps += v4, knight steps += v6,
/// two-square steps inside 21..98 += v6.
fn rookRing(r: *[120]u8, di: usize, v4: i32, v6: i32) void {
    var si: usize = 8;
    while (si > 0) {
        si -= 1;
        r[stepTarget(di, king_steps[si])] +%= b8(v4);
        r[stepTarget(di, knight_steps[si])] +%= b8(v6);
        const t3 = @as(isize, @intCast(di)) + two_steps[si];
        if (inBoardRange(t3)) r[@intCast(t3)] +%= b8(v6);
    }
}

/// 0000:C636-CA74: knight outposts, rooks on the 7th and 8th ranks, the kings'
/// surroundings in the endgame, the endgame king tables A234/77DA (copied to
/// 933E/3A22), bishop activity, opening pawn and queen corrections.
fn knightsRooksTables(c: *Ctx) void {
    const p = c.p;
    const t = c.t;
    const l = c.l;
    if (t.late_endgame.* == 0) {
        for (0x34..0x3A) |si| {
            if (c.watt(si) != 0 and l.b[si] != 0) t.activity_knight_white[si] +%= 0x10;
            if (c.batt(si) != 0 and l.a[si] != 0) t.activity_knight_black[si] +%= 0x18;
        }
        for (0x3E..0x44) |si| {
            if (c.watt(si) != 0 and l.b[si] != 0) t.activity_knight_white[si] +%= 0x18;
            if (c.batt(si) != 0 and l.a[si] != 0) t.activity_knight_black[si] +%= 0x10;
        }
    }
    const wr = t.activity_rook_white;
    const br = t.activity_rook_black;
    if (t.late_endgame.* != 0 or p.pawn_count <= 4) {
        if (p.pawn_count <= 4) {
            var si: usize = 0x14;
            while (si < 0x5B) : (si += 10) {
                wr[si + 1] +%= 4;
                br[si + 1] +%= 4;
                wr[si + 8] +%= 4;
                br[si + 8] +%= 4;
            }
        } else {
            for (1..9) |si| {
                wr[90 + si] +%= 4; // ABFA + si
                br[20 + si] +%= 4; // AFDA + si
            }
            if (c.bkr() <= 6) {
                for (1..9) |si| wr[90 + si] +%= 4;
            }
            if (c.wkr() >= 5) {
                for (1..9) |si| br[20 + si] +%= 4;
            }
        }
    } else {
        const eg = t.endgame.* != 0;
        const v4: u8 = if (eg) 0x18 else 0x20;
        const v6: u8 = if (eg) 6 else 8;
        const v8: u8 = v6 - 2;
        for (1..9) |si| {
            wr[80 + si] +%= v4; // ABF0
            br[30 + si] +%= v4; // AFE4
            wr[90 + si] +%= v6; // ABFA
            br[20 + si] +%= v6; // AFDA
            wr[30 + si] +%= v8; // ABBE
            br[80 + si] +%= v8; // B016
        }
        if (l.qw2 or l.qb2) {
            for (1..9) |si| {
                wr[40 + si] +%= 8; // ABC8
                br[70 + si] +%= 8; // B00C
            }
        }
    }
    // C78B
    if (t.late_endgame.* == 0 and t.endgame.* != 0) {
        var di: usize = c.bl(7);
        if (t.passed_count_black.* != 0) {
            wr[di - 9] +%= 8;
            wr[di - 10] +%= 8;
            wr[di - 11] +%= 8;
        }
        wr[di] +%= 8;
        var si: usize = 8;
        while (si > 0) {
            si -= 1;
            wr[stepTarget(di, king_steps[si])] +%= 8;
        }
        di = c.wl(7);
        if (t.passed_count_white.* != 0) {
            br[di + 9] +%= 8;
            br[di + 10] +%= 8;
            br[di + 11] +%= 8;
        }
        br[di] +%= 8;
        si = 8;
        while (si > 0) {
            si -= 1;
            br[stepTarget(di, king_steps[si])] +%= 8;
        }
    }
    // C80F: king tables for 1E9D:3416 / 35FB
    if (t.late_endgame.* != 0) {
        for (0..14) |si| {
            t.endgame_king_src_white[si] = fb(0x42 + si);
            t.endgame_king_src_black[si] = fb(0x5E + si);
        }
        if (t.no_pawns.* != 0) {
            if (s16(p.material_balance) > 0x32) {
                c.addbs(.{ 0x77E3, 0x77E4 }, 12);
            } else if (s16(p.material_balance) < -0x32) {
                c.addbs(.{ 0xA236, 0xA237 }, 12);
            }
        }
    } else {
        for (0..14) |si| {
            t.endgame_king_src_white[si] = fb(0x34 + si);
            t.endgame_king_src_black[si] = fb(0x50 + si);
        }
    }
    t.endgame_king_weights_white.* = t.endgame_king_src_white.*;
    t.endgame_king_weights_black.* = t.endgame_king_src_black.*;
    c.addb(0x9347, 0x10);
    c.addb(0x3A24, 0x10);
    // C8A6: bishops in the centre
    const v: i32 = if (t.endgame.* != 0) 4 else 8;
    c.addbs(.{ 0xA33A, 0xA33B, 0xA3BC, 0xA3BD }, v);
    for (3..7) |si| {
        t.activity_bishop_white[0x32 + si] +%= b8(v); // A322 + si
        t.activity_bishop_white[0x3C + si] +%= b8(v); // A32C + si
        t.activity_bishop_black[0x32 + si] +%= b8(v); // A3C2 + si
        t.activity_bishop_black[0x3C + si] +%= b8(v); // A3CC + si
    }
    if (t.endgame.* == 0) {
        c.addbs(.{ 0xA344, 0xA345, 0xA3B2, 0xA3B3 }, 8);
        c.addbs(.{ 0xA319, 0xA320, 0xA3D7, 0xA3DE }, 12);
        if (c.wkf() >= 5) {
            c.addbs(.{ 0xA3D0, 0xA3C7, 0xA315 }, 12);
            if (c.board(37) != pos.white_pawn) c.addbs(.{ 0xA315, 0xA31E }, 0x18);
        } else {
            c.addbs(.{ 0xA3D1, 0xA3C6, 0xA310 }, 12);
            if (c.board(32) != pos.white_pawn) c.addbs(.{ 0xA310, 0xA31B }, 0x18);
        }
        if (c.bkf() >= 5) {
            c.addbs(.{ 0xA331, 0xA326, 0xA3E7 }, 12);
            if (c.board(87) != pos.black_pawn) c.addbs(.{ 0xA3E7, 0xA3DC }, 0x18);
        } else {
            c.addbs(.{ 0xA330, 0xA327, 0xA3E2 }, 12);
            if (c.board(82) != pos.black_pawn) c.addbs(.{ 0xA3E2, 0xA3D9 }, 0x18);
        }
        if (c.board(55) == pos.white_pawn and c.board(76) == pos.black_knight and c.board(65) != pos.black_pawn)
            c.addw(0xAAC0, 0x12); // BP[d6]
        if (c.board(65) == pos.black_pawn and c.board(46) == pos.white_knight and c.board(55) != pos.white_pawn)
            c.addw(0xA944, 0x12); // WP[d3]
    }
    // C9DC
    if (t.phase_developing.* != 0) {
        if (c.board(64) == pos.white_pawn and c.board(74) == 0) {
            c.addw(0xAAD4, -6); // BP[d7]
            c.addw(0xAAC0, 6); // BP[d6]
        }
        if (c.board(54) == pos.black_pawn and c.board(44) == 0) {
            c.addw(0xA930, -6); // WP[d2]
            c.addw(0xA944, 6); // WP[d3]
        }
        if (c.board(82) == pos.black_pawn) c.addw(0x8E8C, -0x18); // WQ[a7]
        if (c.board(32) == pos.white_pawn) c.addw(0x8EF6, -0x18); // BQ[a2]
        c.addw(0x8E8E, -0x34); // WQ[b7]
        c.addw(0x8EF8, -0x34); // BQ[b2]
        if (p.piece_material_sum > 0x2B5C) {
            for (1..9) |si| {
                for ([_]usize{ 50, 60 }) |r| {
                    tadd(t.rook_white, r + si, -12);
                    tadd(t.rook_black, r + si, -12);
                    tadd(t.queen_white, r + si, -12);
                    tadd(t.queen_black, r + si, -12);
                }
            }
        }
    }
}

/// `idiv cl` on a sign-extended byte: the quotient, truncated toward zero.
inline fn idiv8(a: i8, b: i8) i32 {
    return @divTrunc(@as(i32, a), b);
}

/// 0000:CA75-CD95: DG:7692 (16 bytes from DG:03FA); mating patterns against a bare
/// king.
fn bareKing(c: *Ctx) void {
    const p = c.p;
    const t = c.t;
    for (0..16) |si| t.table_7692[si] = b8(idiv8(table_03fa[si], 4));
    if (t.no_pawns.* != 0) {
        if (p.piece_material_sum == 0x44C) {
            for (0..16) |si| t.table_7692[si] = b8(-idiv8(table_03fa[si], 2));
        } else {
            t.table_7692.* = @splat(0);
        }
        if (p.material[1] == 0) {
            if (t.kbn_vs_king.* != 0) {
                if (c.wl(2) < 0x63) {
                    inline for (.{ 0xA8AF, 0xA8A6, 0xA864, 0xA86D }) |o| c.setb(o, 0);
                    c.addbs(.{ 0xA8AE, 0xA8AC, 0xA865, 0xA867, 0xA877, 0xA88B, 0xA888, 0xA89C }, 0x20);
                } else {
                    inline for (.{ 0xA869, 0xA874, 0xA8AA, 0xA89F }) |o| c.setb(o, 0);
                    c.addbs(.{ 0xA8AD, 0xA8AB, 0xA866, 0xA868, 0xA881, 0xA895, 0xA87E, 0xA892 }, 0x20);
                }
            }
            var flag = false;
            if (p.king_file[1] == 1) {
                c.addws(.{ 0x8E52, 0x8E66 }, 0x50);
                flag = true;
            } else if (p.king_file[1] == 8) {
                c.addws(.{ 0x8E5C, 0x8E70 }, 0x50);
                flag = true;
            }
            if (p.king_rank[1] == 2) {
                c.addws(.{ 0x8E2E, 0x8E30 }, 0x50);
                flag = true;
            } else if (p.king_rank[1] == 9) {
                c.addws(.{ 0x8E92, 0x8E94 }, 0x50);
                flag = true;
            }
            if (flag) {
                inline for (2..8) |si| {
                    c.addw(0xAF22 + 2 * si, -0x10);
                    c.addw(0xAFAE + 2 * si, -0x10);
                    c.addw(0xAF4A + 2 * si, 0x10);
                    c.addw(0xAF86 + 2 * si, 0x10);
                }
                inline for (.{ 0x1E, 0x28, 0x32, 0x3C, 0x46, 0x50 }) |si| {
                    c.addw(0xAEFC + 2 * si, -0x10);
                    c.addw(0xAF0A + 2 * si, -0x10);
                    c.addw(0xAF00 + 2 * si, 0x10);
                    c.addw(0xAF06 + 2 * si, 0x10);
                }
                c.addws(.{ 0xAF66, 0xAF68, 0xAF7A, 0xAF7C }, 8);
                c.addws(.{ 0xAF50, 0xAF8C, 0xAF56, 0xAF92 }, -0x10);
            }
        }
        if (p.material[0] == 0) {
            if (t.kbn_vs_king.* != 0) {
                if (c.bl(2) < 0x63) {
                    inline for (.{ 0xA9CF, 0xA9DA, 0xAA10, 0xAA05 }) |o| c.setb(o, 0);
                    c.addbs(.{ 0xAA13, 0xAA11, 0xA9CC, 0xA9CE, 0xA9E7, 0xA9FB, 0xA9E4, 0xA9F8 }, 0x20);
                } else {
                    // CC64-CC95 [proved: probe.zst]
                    inline for (.{ 0xAA15, 0xAA0C, 0xA9CA, 0xA9D3 }) |o| c.setb(o, 0);
                    c.addbs(.{ 0xAA14, 0xAA12, 0xA9CB, 0xA9CD, 0xA9DD, 0xA9F1, 0xA9EE, 0xAA02 }, 0x20);
                }
            }
            var flag = false;
            if (p.king_file[0] == 1) {
                c.addws(.{ 0x8F20, 0x8F34 }, 0x50);
                flag = true;
            } else if (p.king_file[0] == 8) {
                c.addws(.{ 0x8F2A, 0x8F3E }, 0x50);
                flag = true;
            }
            if (p.king_rank[0] == 2) {
                c.addws(.{ 0x8EFC, 0x8EFE }, 0x50);
                flag = true;
            } else if (p.king_rank[0] == 9) {
                c.addws(.{ 0x8F60, 0x8F62 }, 0x50);
                flag = true;
            }
            if (flag) {
                inline for (2..8) |si| {
                    c.addw(0xB066 + 2 * si, -0x10);
                    c.addw(0xB0F2 + 2 * si, -0x10);
                    c.addw(0xB08E + 2 * si, 0x10);
                    c.addw(0xB0CA + 2 * si, 0x10);
                }
                inline for (.{ 0x1E, 0x28, 0x32, 0x3C, 0x46, 0x50 }) |si| {
                    c.addw(0xB044 + 2 * si, 0x10);
                    c.addw(0xB04A + 2 * si, 0x10);
                    c.addw(0xB040 + 2 * si, -0x10);
                    c.addw(0xB04E + 2 * si, -0x10);
                }
                c.addws(.{ 0xB0AA, 0xB0AC, 0xB0BE, 0xB0C0 }, 8);
                c.addws(.{ 0xB094, 0xB0D0, 0xB09A, 0xB0D6 }, -0x10);
            }
        }
    }
    // CD61 [proved: probe.zst]: queen against rook-ish material, either way
    if ((p.piece_material[0] == 0x708 and c.bpm() <= 0x546) or (c.wpm() <= 0x546 and p.piece_material[1] == 0x708)) {
        for (0..16) |si| t.table_7692[si] = b8(idiv8(table_03fa[si], 2));
    }
}

/// 0000:CD96-CFBD (not in the endgame): bishop and knight activity in front of each
/// king, scaled by Aggression in the custom style; queen activity near a pawn on g7/b7
/// (g2/b2) attacked by a pawn; bishop activity on a7/a2.
fn kingAttackSquares(c: *Ctx) void {
    const t = c.t;
    if (t.endgame.* != 0) return;
    var v4: i16 = 0x18;
    var v6: i16 = 0x24;
    if (c.in.opponent_side != 0 and c.custom()) {
        // Custom style (CDB8-CDF3): proved by custom.zst (see baseTables).
        v4 = scaleByAggression(24, c.in.aggression);
        v6 = scaleByAggression(36, c.in.aggression);
    }
    if (c.bkf() >= 5) {
        c.addbs(.{ 0xA33C, 0xA33D, 0xA33E, 0xA89A, 0xA89B, 0xA89C }, v4);
        c.addbs(.{ 0xA346, 0xA347, 0xA348, 0xA350, 0xA351, 0xA352 }, v6);
        c.addbs(.{ 0xA8A4, 0xA8A5, 0xA8A6 }, v4);
        if (c.watt(0x57) != 0) c.addb(0xAB77, 0x30);
    } else {
        c.addbs(.{ 0xA339, 0xA338, 0xA337, 0xA897, 0xA896, 0xA895 }, v4);
        c.addbs(.{ 0xA343, 0xA342, 0xA341, 0xA34D, 0xA34C, 0xA34B }, v6);
        c.addbs(.{ 0xA8A1, 0xA8A0, 0xA89F }, v4);
        if (c.watt(0x52) != 0) c.addb(0xAB72, 0x30);
    }
    v4 = 0x18;
    v6 = 0x24;
    if (t.computer_side.* != 0 and c.custom()) {
        // Custom style (CEB4-CEEF): proved by custom.zst (see baseTables).
        v4 = scaleByAggression(24, c.in.aggression);
        v6 = scaleByAggression(36, c.in.aggression);
    }
    if (c.wkf() >= 5) {
        c.addbs(.{ 0xA3BE, 0xA3BF, 0xA3C0, 0xA9E2, 0xA9E3, 0xA9E4 }, v4);
        c.addbs(.{ 0xA3B4, 0xA3B5, 0xA3B6, 0xA3AA, 0xA3AB, 0xA3AC }, v6);
        c.addbs(.{ 0xA9D8, 0xA9D9, 0xA9DA }, v4);
        if (c.batt(0x25) != 0) c.addb(0xADE3, 0x30);
    } else {
        c.addbs(.{ 0xA3BB, 0xA3BA, 0xA3B9, 0xA9DF, 0xA9DE, 0xA9DD }, v4);
        c.addbs(.{ 0xA3B1, 0xA3B0, 0xA3AF, 0xA3A7, 0xA3A6, 0xA3A5 }, v6);
        c.addbs(.{ 0xA9D5, 0xA9D4, 0xA9D3 }, v4);
        if (c.batt(0x20) != 0) c.addb(0xADDE, 0x30);
    }
    if (c.board(43) == pos.white_knight and c.bpf(2) != 0) c.addb(0xA3E1, 0x40); // Black bishop a7
    if (c.board(73) == pos.black_knight and c.wpf(2) != 0) c.addb(0xA30F, 0x40); // White bishop a2
}

/// 0000:CFBE-D2C9: two knights against a pawn; trapped bishops; rooks beside own pawns;
/// the tables 746C/AE46, 718C/A792 and 90BA/369E.
fn miscTables(c: *Ctx) void {
    const p = c.p;
    const t = c.t;
    if (p.material[1] == 0xC8 and p.material[0] == 0x514 and p.piece_count[0] == 2) knightsVsPawn(c, 16, t.king_zone_black);
    if (p.material[0] == 0xC8 and p.material[1] == 0x514 and p.piece_count[1] == 2) knightsVsPawn(c, 0, t.king_zone_white);
    const BP = pos.black_pawn;
    const WP = pos.white_pawn;
    if (s16(p.piece_balance) <= 0x190) {
        if (c.bl(0) < 0x63 or c.bl(1) < 0x63 or t.single_bishops_same_slot.* == 0) {
            if ((c.board(86) == BP and (c.board(75) == BP or c.board(87) == BP or c.board(77) == BP)) or (c.board(76) == BP and c.board(75) == BP)) {
                c.addw(0xACDA, -0x32); // WB[h7]
                c.addw(0xACEC, -0xFA); // WB[g8]
            }
            if ((c.board(83) == BP and (c.board(74) == BP or c.board(82) == BP or c.board(72) == BP)) or (c.board(73) == BP and c.board(74) == BP)) {
                c.addw(0xACCC, -0x32); // WB[a7]
                c.addw(0xACE2, -0xFA); // WB[b8]
            }
        }
    }
    if (s16(p.piece_balance) >= -0x190) {
        if (c.wl(0) < 0x63 or c.wl(1) < 0x63 or t.single_bishops_same_slot.* == 0) {
            if ((c.board(36) == WP and (c.board(45) == WP or c.board(37) == WP or c.board(47) == WP)) or (c.board(46) == WP and c.board(45) == WP)) {
                c.addw(0xAD40, -0x32); // BB[h2]
                c.addw(0xAD2A, -0xFA); // BB[g1]
            }
            if ((c.board(33) == WP and (c.board(44) == WP or c.board(32) == WP or c.board(42) == WP)) or (c.board(43) == WP and c.board(44) == WP)) {
                c.addw(0xAD32, -0x32); // BB[a2]
                c.addw(0xAD20, -0xFA); // BB[b1]
            }
        }
    }
    if (c.board(41) == pos.white_rook and c.board(31) == WP) c.addw(0xA940, -0x12); // WP[b3]
    if (c.board(48) == pos.white_rook and c.board(38) == WP) c.addw(0xA94A, -0x12); // WP[g3]
    if (c.board(71) == pos.black_rook and c.board(81) == BP) c.addw(0xAABC, -0x12); // BP[b6]
    if (c.board(78) == pos.black_rook and c.board(88) == BP) c.addw(0xAAC6, -0x12); // BP[g6]
    for (31..89) |si| {
        const mi = mirror(si);
        t.storm_746c[si] = s16(fw(0x6C + 2 * mi));
        t.storm_ae46[si] = s16(fw(0x6C + 2 * si));
        t.storm_718c[si] = s16(fw(0x120 + 2 * mi));
        t.storm_a792[si] = s16(fw(0x120 + 2 * si));
    }
    for (31..89) |si| {
        t.table_90ba[si] = @as(i16, fb(0x99A + mirror(si))) +% t.storm_718c[si];
        t.table_369e[si] = @as(i16, fb(0x99A + si)) +% t.storm_a792[si];
    }
}

fn knightsVsPawn(c: *Ctx, list: usize, zone: *align(1) [100]i16) void {
    var si: usize = 8;
    while (c.p.piece_list[list + si] > 0x62) si += 1;
    const sq = c.p.piece_list[list + si];
    const fp: i32 = @as(i8, @bitCast(file_of[sq]));
    const rp: i32 = @as(i8, @bitCast(rank_of[sq]));
    for (0x15..0x63) |s| {
        const df: i32 = @intCast(@abs(@as(i32, @as(i8, @bitCast(file_of[s]))) - fp));
        const dr: i32 = @intCast(@abs(@as(i32, @as(i8, @bitCast(rank_of[s]))) - rp));
        tadd(zone, s, (dr + df + @max(dr, df)) << 2);
    }
}

/// 0000:E61A: fixed values into the 746C and AE46 tables (king side).
fn e61a(c: *Ctx) void {
    inline for (.{ .{ 0x74CA, 0x32 }, .{ 0x74CC, 0x32 }, .{ 0xAEE0, 0x32 }, .{ 0xAEE2, 0x32 }, .{ 0x74DE, 0x3C }, .{ 0x74E0, 0x3C }, .{ 0xAECC, 0x3C }, .{ 0xAECE, 0x3C }, .{ 0x74F2, 0x50 }, .{ 0x74F4, 0x50 }, .{ 0xAEB8, 0x50 }, .{ 0xAEBA, 0x50 }, .{ 0x7506, 0x64 }, .{ 0x7508, 0x64 }, .{ 0xAEA4, 0x64 }, .{ 0xAEA6, 0x64 } }) |e| c.setw(e[0], e[1]);
}
/// 0000:E658: as E61A for the queen side.
fn e658(c: *Ctx) void {
    inline for (.{ .{ 0x74C0, 0x32 }, .{ 0x74BE, 0x32 }, .{ 0xAED6, 0x32 }, .{ 0xAED4, 0x32 }, .{ 0x74D4, 0x3C }, .{ 0x74D2, 0x3C }, .{ 0xAEC2, 0x3C }, .{ 0xAEC0, 0x3C }, .{ 0x74E8, 0x50 }, .{ 0x74E6, 0x50 }, .{ 0xAEAE, 0x50 }, .{ 0xAEAC, 0x50 }, .{ 0x74FC, 0x64 }, .{ 0x74FA, 0x64 }, .{ 0xAE9A, 0x64 }, .{ 0xAE98, 0x64 } }) |e| c.setw(e[0], e[1]);
}
/// 0000:E696: knights and bishops of both sides -30 on 21..98; [A5E2] +30 per White
/// knight or bishop slot present, -30 per Black one.
fn e696(c: *Ctx) void {
    const t = c.t;
    for (0x15..0x63) |sq| {
        tadd(t.knight_white, sq, -0x1E);
        tadd(t.bishop_white, sq, -0x1E);
        tadd(t.knight_black, sq, -0x1E);
        tadd(t.bishop_black, sq, -0x1E);
    }
    for (0..4) |k| if (c.wl(k) < 0x63) {
        t.base_pieces.* +%= 0x1E;
    };
    for (0..4) |k| if (c.bl(k) < 0x63) {
        t.base_pieces.* -%= 0x1E;
    };
}

/// 0000:D2CA-D7B2 (not in the endgame): the development score and, when White is well
/// ahead, the attack on Black's king.
fn development(c: *Ctx) void {
    const p = c.p;
    const t = c.t;
    const l = c.l;
    l.f16 = 0;
    l.f14 = 0;
    l.f1e = 0;
    l.f1c = 0;
    if (t.endgame.* != 0) return;
    var sc: i32 = 1 - 2 * @as(i32, @as(i8, @bitCast(t.computer_side.*)));
    var f12: i32 = 0;
    var v = c.wl(4);
    if (v < 0x63) {
        const f: i32 = file_of[v];
        if (c.wpf(@intCast(f)) != 0 and f > c.wkf() and c.wOO() != 0 and c.wkf() >= 5 and c.wOOO() != 0 and p.king_rank[0] == 2 and c.wl(4) <= 0x26) f12 = 1;
    }
    v = c.wl(5);
    if (v < 0x63) {
        const f: i32 = file_of[v];
        if (c.wpf(@intCast(f)) != 0 and c.wkf() < 5 and f < c.wkf() and p.king_rank[0] == 2 and c.wl(5) <= 0x21) f12 += 1;
    }
    if (f12 != 0) {
        sc -= 1;
    } else {
        if (t.white_king_tucked.* != 0) sc += 1;
        const k: usize = c.wl(7);
        var cnt: i32 = 0;
        if (c.board(k + 9) != 0) cnt = 1;
        if (c.board(k + 10) != 0) cnt += 1;
        if (c.board(k + 11) != 0) cnt += 1;
        if (c.wkf() >= 7 or c.wkf() <= 2) {
            if (c.board(k + 1) != 0) cnt += 1;
            if (c.board(k - 1) != 0) cnt += 1;
        }
        if (cnt >= 2) {
            sc += 1;
            l.f14 +%= 1;
        }
    }
    if (c.wl(2) < 0x63) {
        if (c.board(26) != pos.white_bishop) {
            sc += 1;
        } else if (c.board(35) != 0 and c.board(37) != 0) sc -= 1;
    }
    if (c.wl(3) < 0x63) {
        if (c.board(23) != pos.white_bishop) {
            sc += 1;
        } else if (c.board(32) != 0 and (c.board(34) != 0 or c.board(45) == pos.white_pawn)) sc -= 1;
    }
    for ([_]usize{ 0, 1 }) |k| {
        if (c.wl(k) < 0x63 and c.wl(k) > 0x1C) sc += 1;
    }
    for ([_]usize{ 4, 5 }) |k| {
        if (c.wl(k) < 0x63 and c.wpf(file_of[c.wl(k)]) == 0) sc += 1;
    }
    if (c.wl(6) < 0x63 and c.wl(6) > 0x1C) sc += 1;
    // D4AF: Black
    f12 = 0;
    v = c.bl(4);
    if (v < 0x63) {
        const f: i32 = file_of[v];
        if (c.bpf(@intCast(f)) != 0 and f > c.bkf() and c.bOO() != 0 and c.bkf() >= 5 and c.bOOO() != 0 and p.king_rank[1] == 9 and c.bl(4) >= 0x56) f12 = 1;
    }
    v = c.bl(5);
    if (v < 0x63) {
        const f: i32 = file_of[v];
        if (c.bpf(@intCast(f)) != 0 and c.bkf() < 5 and f < c.bkf() and p.king_rank[1] == 9 and c.bl(5) >= 0x51) f12 += 1;
    }
    if (f12 != 0) {
        sc += 1;
    } else {
        if (t.black_king_tucked.* != 0) sc -= 1;
        const k: usize = c.bl(7);
        var cnt: i32 = 0;
        if (c.board(k - 9) != 0) cnt = 1;
        if (c.board(k - 10) != 0) cnt += 1;
        if (c.board(k - 11) != 0) cnt += 1;
        if (c.bkf() >= 7 or c.bkf() <= 2) {
            if (c.board(k + 1) != 0) cnt += 1;
            if (c.board(k - 1) != 0) cnt += 1;
        }
        if (cnt >= 2) {
            sc -= 1;
            l.f16 +%= 1;
        }
    }
    if (c.bl(2) < 0x63) {
        if (c.board(96) != pos.black_bishop) {
            sc -= 1;
        } else if (c.board(85) != 0 and c.board(87) != 0) sc += 1;
    }
    if (c.bl(3) < 0x63) {
        if (c.board(93) != pos.black_bishop) {
            sc -= 1;
        } else if (c.board(82) != 0 and (c.board(84) != 0 or c.board(75) == pos.black_pawn)) sc += 1;
    }
    for ([_]usize{ 0, 1 }) |k| {
        if (c.bl(k) < 0x63 and c.bl(k) < 0x5B) sc -= 1;
    }
    for ([_]usize{ 4, 5 }) |k| {
        if (c.bl(k) < 0x63 and c.bpf(file_of[c.bl(k)]) == 0) sc -= 1;
    }
    if (c.bl(6) < 0x63 and c.bl(6) < 0x5B) sc -= 1;
    const cl = l.f16;
    var s: i16 = w16(sc + l.f14 - l.f16);
    const s0 = s;
    l.sc0 = s0;
    if (s >= 3 and c.wl(6) < 0x63 and @as(i8, @bitCast(p.piece_count[0])) >= 5 and p.pawn_count <= 14 and
        !(cl != 0 and t.black_king_tucked.* != 0))
    {
        e696(c);
        l.f1c +%= 1;
        t.base_pieces.* -%= 0xA0;
        for (0x15..0x63) |si| tadd(t.queen_white, si, 0xA0);
        s +%= 1;
        var di: i16 = s;
        var ax: i16 = s;
        if (c.in.opponent_side != 0 and c.custom()) {
            // Custom style (D6ED-D708): proved by custom.zst (see baseTables).
            ax = scaleByAggression(s, c.in.aggression);
            s = ax;
        }
        if (s0 > 3) di +%= ax;
        c.addws(.{ 0x73E6, 0x73E8, 0x73EA, 0x73E4, 0x73D2, 0x73D4, 0x73D6, 0x73D0 }, -@as(i32, di)); // BK d8 e8 f8 c8 d7 e7 f7 c7
        ax = di *% 2;
        c.addw(0xAAD4, -@as(i32, ax)); // BP[d7]
        c.addw(0xAAD6, -@as(i32, ax)); // BP[e7]
        ax +%= di;
        s = ax;
        c.addws(.{ 0x775A, 0x775C, 0x775E, 0x7764, 0x7762, 0x7760, 0xADAE, 0xADB4 }, -@as(i32, ax)); // BN b8 c8 d8 g8 f8 e8, BB c8 f8
        c.addw(0x75F6, -12); // WN[b1]
        c.addw(0x7600, -12); // WN[g1]
        t.base_black_pawns.* +%= w16(12 * @as(i32, @as(i8, @bitCast(p.side_pawn_count[1]))));
        for (0x1F..0x59) |si| tadd(t.pawn_black, si, 12);
        if (t.computer_side.* != 0) {
            t.base_white_pawns.* +%= w16(@as(i32, @as(i8, @bitCast(p.side_pawn_count[0]))) * s);
            for (0x1F..0x59) |si| tadd(t.pawn_white, si, -@as(i32, s));
        }
    }
    l.sc = s;
}

/// 0000:D7B3-D8E7: the mirror for Black (development score <= -3).
fn developmentBlack(c: *Ctx) void {
    const p = c.p;
    const t = c.t;
    const l = c.l;
    if (t.endgame.* != 0) return;
    var s = l.sc;
    const s0 = l.sc0;
    if (s <= -3 and c.bl(6) < 0x63 and @as(i8, @bitCast(p.piece_count[1])) >= 5 and p.pawn_count <= 14 and
        !(l.f14 != 0 and t.white_king_tucked.* != 0))
    {
        e696(c);
        l.f1e +%= 1;
        t.base_pieces.* +%= 0xA0;
        for (0x15..0x63) |si| tadd(t.queen_black, si, 0xA0);
        s = (0 -% s) +% 1;
        var di: i16 = s;
        var ax: i16 = s;
        if (t.computer_side.* != 0 and c.custom()) {
            // Custom style (D822-D83D): proved by custom.zst (see baseTables).
            ax = scaleByAggression(s, c.in.aggression);
            s = ax;
        }
        if (s0 < -3) di +%= ax;
        c.addws(.{ 0x7290, 0x7292, 0x7294, 0x728E, 0x72A4, 0x72A6, 0x72A8, 0x72A2 }, -@as(i32, di)); // WK d1 e1 f1 c1 d2 e2 f2 c2
        ax = di *% 2;
        c.addw(0xA930, -@as(i32, ax)); // WP[d2]
        c.addw(0xA932, -@as(i32, ax)); // WP[e2]
        ax +%= di;
        s = ax;
        c.addws(.{ 0x75F6, 0x75F8, 0x75FA, 0x7600, 0x75FE, 0x75FC, 0xAC58, 0xAC5E }, -@as(i32, ax)); // WN b1 c1 d1 g1 f1 e1, WB c1 f1
        c.addw(0x775A, -12); // BN[b8]
        c.addw(0x7764, -12); // BN[g8]
        t.base_white_pawns.* -%= w16(12 * @as(i32, @as(i8, @bitCast(p.side_pawn_count[0]))));
        for (0x1F..0x59) |si| tadd(t.pawn_white, si, 12);
        if (c.in.opponent_side != 0) {
            t.base_black_pawns.* -%= w16(@as(i32, @as(i8, @bitCast(p.side_pawn_count[1]))) * s);
            for (0x1F..0x59) |si| tadd(t.pawn_black, si, -@as(i32, s));
        }
    }
    l.sc = s;
}

/// 0000:D8E8-DB86 (not in the endgame): the 746C/718C entries in front of Black's king;
/// with White's queen on and White's pieces >= 3750, the pawn storm against a castled
/// Black king.
fn stormTables(c: *Ctx) void {
    const t = c.t;
    if (t.endgame.* != 0) return;
    if (c.bkr() >= 8) {
        if (c.bkf() <= 4) {
            if (c.bkf() < 4) {
                c.setw(0x750E, 0x64);
                c.addw(0x722E, -0x64);
            }
            c.setw(0x7512, 0x64);
            c.setw(0x7510, 0x64);
            c.addw(0x7230, -0x64);
            c.addw(0x7232, -0x64);
        } else if (c.bkf() >= 6 or c.bOOO() != 0) {
            if (c.bkf() > 5) {
                c.setw(0x751C, 0x64);
                c.addw(0x723C, -0x64);
            }
            c.setw(0x7518, 0x64);
            c.setw(0x751A, 0x64);
            c.addw(0x723A, -0x64);
            c.addw(0x7238, -0x64);
        }
    }
    if (!(c.wl(6) < 0x63 and c.wpm() >= 0xEA6)) return;
    const bkf = c.bkf();
    if (bkf >= 6 or (bkf == 5 and c.bOOO() != 0)) {
        if (c.wkf() <= 4) {
            if (t.white_king_tucked.* != 0 and c.l.f14 != 0) {
                // DA94-DB0E [proved: probe.zst]
                inline for (.{ .{ 0xA936, -0x2A }, .{ 0xA938, -0x2A }, .{ 0xA934, -12 }, .{ 0xA970, 0x12 }, .{ 0xA94A, -0x24 }, .{ 0xA94C, -0x24 }, .{ 0xA948, -12 }, .{ 0xA95C, 12 }, .{ 0xA95E, 0x1E }, .{ 0xA960, 0x18 }, .{ 0xA972, 0x18 }, .{ 0xA974, 0x1E }, .{ 0xA986, 0x12 }, .{ 0xA988, 0x12 } }) |e| c.addw(e[0], e[1]);
                if (c.wpf(7) != 0) c.addws(.{ 0x91B8, 0x91CC }, 12);
                if (c.wpf(8) != 0) c.addws(.{ 0x91BA, 0x91CE }, 12);
                if (c.wpf(6) != 0) c.addws(.{ 0x91B6, 0x91CA }, 6);
            }
            inline for (.{ .{ 0xAAC6, 0x12 }, .{ 0xAAC8, 0x12 }, .{ 0xAAC4, 0x18 }, .{ 0xAADA, 0x12 }, .{ 0xAADC, 0x12 }, .{ 0xAAD8, 0x1E } }) |e| c.addw(e[0], e[1]);
            inline for (.{ .{ 0x74CA, 0x14 }, .{ 0x74CC, 0x14 }, .{ 0x74B6, 0x14 }, .{ 0x74B8, 0x14 }, .{ 0x74DE, 0x1E }, .{ 0x74E0, 0x1E }, .{ 0x74F2, 0x28 }, .{ 0x74F4, 0x28 }, .{ 0x7506, 0x32 }, .{ 0x7508, 0x32 } }) |e| c.setw(e[0], e[1]);
            c.addws(.{ 0x7228, 0x7226 }, -0x50);
            if (c.bkr() >= 8) {
                c.setw(0x751A, 0x46);
                c.setw(0x751C, 0x46);
            }
        } else {
            e61a(c);
            c.addws(.{ 0x7228, 0x7226 }, -0x50);
        }
    }
    if (c.bkf() <= 4) {
        if (c.wkf() >= 5) {
            if (t.white_king_tucked.* != 0 and c.l.f14 != 0) {
                // [proved: probe.zst]
                inline for (.{ .{ 0xA92C, -0x2A }, .{ 0xA92A, -0x2A }, .{ 0xA92E, -12 }, .{ 0xA96A, 0x12 }, .{ 0xA940, -0x24 }, .{ 0xA93E, -0x24 }, .{ 0xA942, -12 }, .{ 0xA956, 12 }, .{ 0xA954, 0x1E }, .{ 0xA952, 0x18 }, .{ 0xA968, 0x18 }, .{ 0xA966, 0x1E }, .{ 0xA97C, 0x12 }, .{ 0xA97A, 0x12 } }) |e| c.addw(e[0], e[1]);
                if (c.wpf(2) != 0) c.addws(.{ 0x91AE, 0x91C2 }, 12);
                if (c.wpf(1) != 0) c.addws(.{ 0x91AC, 0x91C0 }, 12);
                if (c.wpf(3) != 0) c.addws(.{ 0x91B0, 0x91C4 }, 6);
            }
            inline for (.{ .{ 0xAABC, 0x12 }, .{ 0xAABA, 0x12 }, .{ 0xAABE, 0x18 }, .{ 0xAAD0, 0x12 }, .{ 0xAACE, 0x12 }, .{ 0xAAD2, 0x1E } }) |e| c.addw(e[0], e[1]);
            inline for (.{ .{ 0x74C0, 0x14 }, .{ 0x74BE, 0x14 }, .{ 0x74AC, 0x14 }, .{ 0x74AA, 0x14 }, .{ 0x74D4, 0x1E }, .{ 0x74D2, 0x1E }, .{ 0x74E8, 0x28 }, .{ 0x74E6, 0x28 }, .{ 0x74FC, 0x32 }, .{ 0x74FA, 0x32 } }) |e| c.setw(e[0], e[1]);
            c.addws(.{ 0x721A, 0x721C }, -0x50);
            if (c.bkr() >= 8) {
                c.setw(0x7510, 0x46);
                c.setw(0x750E, 0x46);
            }
        } else {
            e658(c);
            c.addws(.{ 0x721A, 0x721C }, -0x50);
        }
    }
}

/// 0000:DB87-DE24 (not in the endgame): the mirror of D8E8 for White's king.
fn stormTablesWhiteKing(c: *Ctx) void {
    const t = c.t;
    if (t.endgame.* != 0) return;
    if (c.wkr() <= 3) {
        if (c.wkf() <= 4) {
            if (c.wkf() < 4) {
                c.setw(0xAE84, 0x64);
                c.addw(0xA7D0, -0x64);
            }
            c.setw(0xAE88, 0x64);
            c.setw(0xAE86, 0x64);
            c.addw(0xA7D2, -0x64);
            c.addw(0xA7D4, -0x64);
        } else if (c.wkf() >= 6 or c.wOOO() != 0) {
            if (c.wkf() > 5) {
                c.setw(0xAE92, 0x64);
                c.addw(0xA7DE, -0x64);
            }
            c.setw(0xAE8E, 0x64);
            c.setw(0xAE90, 0x64);
            c.addw(0xA7DC, -0x64);
            c.addw(0xA7DA, -0x64);
        }
    }
    if (!(c.bl(6) < 0x63 and c.bpm() >= 0xEA6)) return;
    const wkf = c.wkf();
    if (wkf >= 6 or (wkf == 5 and c.wOOO() != 0)) {
        if (c.bkf() <= 4) {
            if (t.black_king_tucked.* != 0 and c.l.f16 != 0) {
                // DC1E-DD06 [proved: probe.zst]
                inline for (.{ .{ 0xAADA, -0x2A }, .{ 0xAADC, -0x2A }, .{ 0xAAD8, -12 }, .{ 0xAA9C, 0x12 }, .{ 0xAAC6, -0x24 }, .{ 0xAAC8, -0x24 }, .{ 0xAAC4, -12 }, .{ 0xAAB0, 12 }, .{ 0xAAB2, 0x1E }, .{ 0xAAB4, 0x18 }, .{ 0xAA9E, 0x18 }, .{ 0xAAA0, 0x1E }, .{ 0xAA8A, 0x12 }, .{ 0xAA8C, 0x12 } }) |e| c.addw(e[0], e[1]);
                if (c.bpf(7) != 0) c.addws(.{ 0x930C, 0x92F8 }, 12);
                if (c.bpf(8) != 0) c.addws(.{ 0x930E, 0x92FA }, 12);
                if (c.bpf(6) != 0) c.addws(.{ 0x930A, 0x92F6 }, 6);
            }
            inline for (.{ .{ 0xA94A, 0x12 }, .{ 0xA94C, 0x12 }, .{ 0xA948, 0x18 }, .{ 0xA936, 0x12 }, .{ 0xA938, 0x12 }, .{ 0xA934, 0x1E } }) |e| c.addw(e[0], e[1]);
            inline for (.{ .{ 0xAEE0, 0x14 }, .{ 0xAEE2, 0x14 }, .{ 0xAEF4, 0x14 }, .{ 0xAEF6, 0x14 }, .{ 0xAECC, 0x1E }, .{ 0xAECE, 0x1E }, .{ 0xAEB8, 0x28 }, .{ 0xAEBA, 0x28 }, .{ 0xAEA4, 0x32 }, .{ 0xAEA6, 0x32 } }) |e| c.setw(e[0], e[1]);
            c.addws(.{ 0xA7F2, 0xA7F0 }, -0x50);
            if (c.wkr() <= 3) {
                c.setw(0xAE90, 0x46);
                c.setw(0xAE92, 0x46);
            }
        } else {
            e61a(c);
            c.addws(.{ 0xA7F2, 0xA7F0 }, -0x50);
        }
    }
    if (c.wkf() <= 4) {
        if (c.bkf() >= 5) {
            if (t.black_king_tucked.* != 0 and c.l.f16 != 0) {
                // [proved: probe.zst]
                inline for (.{ .{ 0xAAD0, -0x2A }, .{ 0xAACE, -0x2A }, .{ 0xAAD2, -12 }, .{ 0xAA96, 0x12 }, .{ 0xAABC, -0x24 }, .{ 0xAABA, -0x24 }, .{ 0xAABE, -12 }, .{ 0xAAAA, 12 }, .{ 0xAAA8, 0x1E }, .{ 0xAAA6, 0x18 }, .{ 0xAA94, 0x18 }, .{ 0xAA92, 0x1E }, .{ 0xAA80, 0x12 }, .{ 0xAA7E, 0x12 } }) |e| c.addw(e[0], e[1]);
                if (c.bpf(2) != 0) c.addws(.{ 0x9302, 0x92EE }, 12);
                if (c.bpf(1) != 0) c.addws(.{ 0x9300, 0x92EC }, 12);
                if (c.bpf(3) != 0) c.addws(.{ 0x9304, 0x92F0 }, 6);
            }
            inline for (.{ .{ 0xA940, 0x12 }, .{ 0xA93E, 0x12 }, .{ 0xA942, 0x18 }, .{ 0xA92C, 0x12 }, .{ 0xA92A, 0x12 }, .{ 0xA92E, 0x1E } }) |e| c.addw(e[0], e[1]);
            inline for (.{ .{ 0xAED6, 0x14 }, .{ 0xAED4, 0x14 }, .{ 0xAEEA, 0x14 }, .{ 0xAEE8, 0x14 }, .{ 0xAEC2, 0x1E }, .{ 0xAEC0, 0x1E }, .{ 0xAEAE, 0x28 }, .{ 0xAEAC, 0x28 }, .{ 0xAE9A, 0x32 }, .{ 0xAE98, 0x32 } }) |e| c.setw(e[0], e[1]);
            c.addws(.{ 0xA7E4, 0xA7E6 }, -0x50);
            if (c.wkr() <= 3) {
                c.setw(0xAE86, 0x46);
                c.setw(0xAE84, 0x46);
            }
        } else {
            e658(c);
            c.addws(.{ 0xA7E4, 0xA7E6 }, -0x50);
        }
    }
}

/// 0000:DE25-DE94: with queens on both sides, the side ahead by 150 has the opponent's
/// queen table raised by 60, with the base compensated; not for a side whose king
/// attack was applied.
fn materialQueens(c: *Ctx) void {
    const p = c.p;
    const t = c.t;
    if ((c.wl(6) < 0x63 or t.promoted_queen_slot[0] != 0) and (c.bl(6) < 0x63 or t.promoted_queen_slot[1] != 0)) {
        const bal = s16(p.material_balance);
        const pbal = s16(p.piece_balance);
        if (bal >= 0x96 and pbal >= -0x32 and c.l.f1e == 0) {
            t.base_pieces.* +%= 0x3C;
            for (0x15..0x63) |si| tadd(t.queen_black, si, 0x3C);
        }
        if (bal <= -0x96 and pbal <= 0x32 and c.l.f1c == 0) {
            t.base_pieces.* -%= 0x3C;
            for (0x15..0x63) |si| tadd(t.queen_white, si, 0x3C);
        }
    }
}

fn scanToPiece(c: *const Ctx, start: isize, step: isize) usize {
    var t = start + step;
    while (c.board(@intCast(t)) == 0) t += step;
    return @intCast(t);
}

/// 0000:DE95-E1C7: blocked pawn pairs on the files away from the kings. The code is a
/// set of jumps between labels; this follows model.p2_pawn_chains label by label.
fn pawnChains(c: *Ctx) void {
    const t = c.t;
    const l = c.l;
    l.f1a = 0;
    l.f18 = 0;
    if (t.phase_opening.* != 0) return;
    const WP = pos.white_pawn;
    const BP = pos.black_pawn;
    const wp = t.pawn_white;
    const bp = t.pawn_black;
    if (t.endgame.* != 0 or t.white_king_tucked.* != 0) {
        var si: usize = 1;
        var lim: usize = 8;
        if (c.wkf() < 4) {
            si = 5;
        } else if (c.wkf() > 5) {
            lim = 4;
        } else si = 9;
        const Lab = enum { dee4, def9, df53, dfc6 };
        var lab: Lab = .dfc6;
        while (true) {
            const s: isize = @intCast(si);
            switch (lab) {
                .dee4 => {
                    if (c.board(si + 0x3D) == WP) {
                        tadd(wp, si + 0x31, 0x12);
                        tadd(wp, si + 0x26, 12);
                    }
                    lab = .def9;
                },
                .def9 => {
                    const tq = scanToPiece(c, s + 0x33, 10);
                    if (c.board(tq) != pos.white_queen) {
                        if (c.board(si + 0x27) == WP) {
                            tadd(wp, si + 0x33, 12);
                            if (c.board(si + 0x1C) == WP and c.bpf(si - 1) == 0) {
                                tadd(bp, si + 0x3A, 12);
                                tadd(bp, si + 0x30, 0x12);
                            }
                        } else if (c.board(si + 0x3B) == WP) {
                            tadd(wp, si + 0x33, 0x12);
                            tadd(wp, si + 0x2A, 12);
                        }
                    }
                    lab = .df53;
                },
                .df53 => {
                    if (c.board(si + 0x3C) == WP and c.board(si + 0x46) == BP) {
                        var tq = scanToPiece(c, s + 0x3B, 10);
                        if (c.board(tq) != pos.white_queen) {
                            tadd(wp, si + 0x3B, 12);
                            if (c.board(si + 0x3B) == 0) addWhitePawnSqIfEmpty(c, si + 0x31, 12);
                        }
                        tq = scanToPiece(c, s + 0x3D, 10);
                        if (c.board(tq) != pos.white_queen) {
                            tadd(wp, si + 0x3D, 12);
                            if (c.board(si + 0x3D) == 0) addWhitePawnSqIfEmpty(c, si + 0x33, 12);
                        }
                    }
                    si += 1;
                    lab = .dfc6;
                },
                .dfc6 => {
                    if (si > lim) break;
                    if (c.board(si + 0x32) == WP and c.board(si + 0x3C) == BP) {
                        const tq = scanToPiece(c, s + 0x31, 10);
                        if (c.board(tq) == pos.white_queen) {
                            lab = .def9;
                        } else if (c.board(si + 0x29) != WP) {
                            lab = .dee4;
                        } else {
                            tadd(wp, si + 0x31, 12);
                            if (c.board(si + 0x20) == WP and c.bpf(si + 1) == 0) {
                                tadd(bp, si + 0x3E, 12);
                                tadd(bp, si + 0x34, 0x12);
                                if (si == 4) l.f1a +%= 1;
                            }
                            lab = .def9;
                        }
                    } else lab = .df53;
                },
            }
        }
    }
    // E03A
    if (t.endgame.* != 0 or t.black_king_tucked.* != 0) {
        var si: usize = 1;
        var lim: usize = 8;
        if (c.bkf() < 4) {
            si = 5;
        } else if (c.bkf() > 5) {
            lim = 4;
        } else si = 9;
        const Lab = enum { e076, e08b, e0ed, e160 };
        var lab: Lab = .e160;
        while (true) {
            const s: isize = @intCast(si);
            switch (lab) {
                .e076 => {
                    if (c.board(si + 0x31) == BP) {
                        tadd(bp, si + 0x3D, 0x12);
                        tadd(bp, si + 0x48, 12);
                    }
                    lab = .e08b;
                },
                .e08b => {
                    const tq = scanToPiece(c, s + 0x3B, -10);
                    if (c.board(tq) != pos.black_queen) {
                        if (c.board(si + 0x47) == BP) {
                            tadd(bp, si + 0x3B, 12);
                            if (c.board(si + 0x52) == BP and c.wpf(si + 1) == 0) {
                                tadd(wp, si + 0x34, 12);
                                tadd(wp, si + 0x3E, 0x12);
                                if (si == 4) l.f18 +%= 1;
                            }
                        } else if (c.board(si + 0x33) == BP) {
                            tadd(bp, si + 0x3B, 0x12);
                            tadd(bp, si + 0x44, 12);
                        }
                    }
                    lab = .e0ed;
                },
                .e0ed => {
                    if (c.board(si + 0x32) == BP and c.board(si + 0x28) == WP) {
                        var tq = scanToPiece(c, s + 0x33, -10);
                        if (c.board(tq) != pos.black_queen) {
                            tadd(bp, si + 0x33, 12);
                            if (c.board(si + 0x33) == 0) addBlackPawnSqIfEmpty(c, si + 0x3D, 12);
                        }
                        tq = scanToPiece(c, s + 0x31, -10);
                        if (c.board(tq) != pos.black_queen) {
                            tadd(bp, si + 0x31, 12);
                            if (c.board(si + 0x31) == 0) addBlackPawnSqIfEmpty(c, si + 0x3B, 12);
                        }
                    }
                    si += 1;
                    lab = .e160;
                },
                .e160 => {
                    if (si > lim) break;
                    if (c.board(si + 0x32) == WP and c.board(si + 0x3C) == BP) {
                        const tq = scanToPiece(c, s + 0x3D, -10);
                        if (c.board(tq) == pos.black_queen) {
                            lab = .e08b;
                        } else if (c.board(si + 0x45) != BP) {
                            lab = .e076;
                        } else {
                            tadd(bp, si + 0x3D, 12);
                            if (c.board(si + 0x4E) == BP and c.wpf(si - 1) == 0) {
                                tadd(wp, si + 0x30, 12);
                                tadd(wp, si + 0x3A, 0x12);
                            }
                            lab = .e08b;
                        }
                    } else lab = .e0ed;
                },
            }
        }
    }
}

/// 0000:E1C8-E427: the rook byte tables A6C8 / A72E (cleared first) and the rook and
/// queen corrections for two rooks on one rank.
fn rooks(c: *Ctx) void {
    const t = c.t;
    t.rook_bytes_white.* = @splat(0);
    t.rook_bytes_black.* = @splat(0);
    inline for (.{ false, true }) |black| {
        const list: usize = if (black) 16 else 0;
        const own: u8 = if (black) pos.black_queen else pos.white_queen;
        const pf = if (black) &c.p.pawns_per_file[1] else &c.p.pawns_per_file[0];
        const table = if (black) t.rook_black else t.rook_white;
        const rbytes = if (black) t.rook_bytes_black else t.rook_bytes_white;
        const queen = if (black) t.queen_black else t.queen_white;
        const other = if (black) c.l.f1a else c.l.f18;
        const r4: usize = c.p.piece_list[list + 4];
        const r5: usize = c.p.piece_list[list + 5];
        // rank_of is read for r5 even when it is a captured entry (up to 197)
        if (r4 < 0x63 and r4 > r5 and rank_of[r4] == rankOfAny(r5)) {
            const f5: usize = file_of[r5];
            const f4: usize = file_of[r4];
            const base: usize = r5 - f5;
            var cnt: u32 = 0;
            var di = f5 + 1;
            while (f4 > di) : (di += 1) {
                if (c.board(base + di) != 0 and c.board(base + di) != own) cnt += 1;
            }
            if (cnt <= 1) {
                for (f5..f4 + 1) |d| tadd(queen, base + d, -8);
            }
            var gaps: u32 = 0;
            const near = if (black) base >= 0x50 else base <= 0x1E;
            if (pf[f5] != 0 and pf[f4] != 0 and near and f4 - f5 >= 3) {
                for (f5 + 1..f4) |si| if (pf[si] == 0) {
                    gaps += 1;
                };
            }
            if (gaps >= 2) {
                var si = f4;
                while (pf[si] != 0) si -= 1;
                const tsq = base + si;
                si = f5;
                while (pf[si] != 0) si += 1;
                const bsq = base + si;
                if (black) {
                    rbytes[bsq] +%= 8;
                    tadd(table, tsq, 8);
                } else {
                    tadd(table, tsq, 8);
                    rbytes[bsq] +%= 8;
                }
            } else if (other == 0) {
                var d: usize = 0x14;
                while (d < 0x5B) : (d += 10) {
                    for (1..5) |si| rbytes[d + si] +%= 4;
                    for (5..9) |si| tadd(table, d + si, 4);
                }
            }
        }
    }
}

/// rank_of for any list entry r5 < r4 < 99 (always on the board here: r5 < r4).
inline fn rankOfAny(sq: usize) u8 {
    return rank_of[sq];
}

/// 0000:E428-E618: opening centre pawns; knight against bishop; DG:3766 from 5846:0000;
/// the late-endgame flag set whenever [378E] <= 5000.
fn final(c: *Ctx) void {
    const p = c.p;
    const t = c.t;
    if (c.in.move_number <= 3 and c.in.flag_70e4 == 0) {
        inline for (.{ .{ 0xA958, 0x30 }, .{ 0xA96C, 0x24 }, .{ 0xA95A, 0x24 }, .{ 0xA96E, 0x24 }, .{ 0xAA98, 0x24 }, .{ 0xAAAC, 0x30 }, .{ 0xAA9A, 0x24 }, .{ 0xAAAE, 0x24 }, .{ 0x8E1A, 0x20 }, .{ 0x8F74, 0x20 } }) |e| c.addw(e[0], e[1]);
        if (c.board(54) == pos.white_pawn) {
            c.addw(0xA95A, 12);
            c.addw(0xAAAC, 0x18);
        }
        if (c.board(55) == pos.white_pawn) {
            c.addw(0xA958, 12);
            c.addw(0xAAAE, 0x18);
        }
    }
    if (p.piece_material_sum == 0x546) {
        // E49F-E5D3 [proved: probe.zst]
        if (p.piece_balance == 0x32 and s16(p.material_balance) >= 0xFA and c.in.passed_mask_black == 0) {
            t.base_pieces.* +%= 0x32;
            for (0x15..0x63) |si| tadd(t.knight_black, si, 0x32);
            const light = c.wl(2) < 0x63;
            for (0x1F..0x59) |si| {
                const dk = dark[si] != 0;
                const v: i32 = if (light) (if (dk) 0x12 else -0x12) else (if (dk) -0x12 else 0x12);
                tadd(t.storm_718c, si, v);
            }
        }
        if (p.piece_balance == 0xFFCE and s16(p.material_balance) <= -0xFA and c.in.passed_mask_white == 0) {
            t.base_pieces.* -%= 0x32;
            for (0x15..0x63) |si| tadd(t.knight_white, si, 0x32);
            const light = c.bl(2) < 0x63;
            for (0x1F..0x59) |si| {
                const dk = dark[si] != 0;
                const v: i32 = if (light) (if (dk) -0x12 else 0x12) else (if (dk) 0x12 else -0x12);
                tadd(t.storm_a792, si, v);
            }
        }
    }
    t.table_3766.* = far5846;
    if (t.late_endgame.* != 0) {
        t.table_3766[1] +%= 2;
        t.table_3766[2] +%= 3;
        t.table_3766[3] +%= 2;
        t.table_3766[4] +%= 1;
    }
    if (p.piece_material_sum <= 0x1388) t.late_endgame.* = 1;
}

/// B974: if [A6C3], prepare_eval_endgame (0000:B9DC-BB48): a pawn on a file without
/// enemy pawns and without an own passed pawn, the enemy king not within one file,
/// with more own than enemy pawns around (DG:1540), gets +12 on the squares in front
/// of its most advanced pawn while they are not attacked by more enemy than own pawns.
fn endgameMajorities(c: *Ctx) void {
    const t = c.t;
    if (t.endgame.* == 0) return;
    const pfw = &c.p.pawns_per_file[0];
    const pfb = &c.p.pawns_per_file[1];
    const sgn = struct {
        inline fn f(v: u8) i32 {
            return @as(i8, @bitCast(v));
        }
    }.f;
    for (1..9) |f| {
        const fi: i32 = @intCast(f);
        if (pfw[f] != 0 and pfb[f] == 0 and t.passed_rank_by_file_white[f - 1] == 0) {
            const kf = c.bkf();
            if (kf < fi - 1 or kf > fi + 1) {
                const cx = sgn(pfb[f - 1]) + sgn(pfb[f + 1]);
                const si = one_if_pawns[pfw[f - 1]] + @as(i32, one_if_pawns[pfw[f + 1]]) + one_if_pawns[pfw[f]];
                if (si > cx) {
                    var s: usize = f + 0x50;
                    while (c.board(s) != pos.white_pawn) s -= 10;
                    s += 10;
                    if (s < 0x47) {
                        while (true) {
                            if (sgn(c.batt(s)) > sgn(c.watt(s))) break;
                            tadd(t.pawn_white, s, 12);
                            s += 10;
                            if (!(s < 71)) break;
                        }
                    }
                }
            }
        }
        if (pfb[f] != 0 and pfw[f] == 0 and t.passed_rank_by_file_black[f - 1] == 0) {
            const kf = c.wkf();
            if (kf < fi - 1 or kf > fi + 1) {
                const cx = sgn(pfw[f - 1]) + sgn(pfw[f + 1]);
                const si = one_if_pawns[pfb[f - 1]] + @as(i32, one_if_pawns[pfb[f + 1]]) + one_if_pawns[pfb[f]];
                if (si > cx) {
                    // BAFE-BB3B [proved: probe.zst]
                    var s: usize = f + 0x1E;
                    while (c.board(s) != pos.black_pawn) s += 10;
                    s -= 10;
                    if (s > 0x30) {
                        while (true) {
                            if (sgn(c.batt(s)) < sgn(c.watt(s))) break;
                            tadd(t.pawn_black, s, 12);
                            s -= 10;
                            if (!(s > 48)) break;
                        }
                    }
                }
            }
        }
    }
}

/// B980: reset_square_sums (0000:E718-E8D2): men count, style copy, the second
/// balance's tables, and the three square sums and the second balance recomputed from
/// the board.
fn resetSquareSums(c: *Ctx) void {
    const p = c.p;
    const t = c.t;
    p.men = p.pawn_count +% p.piece_count[1] +% p.piece_count[0] +% 2;
    const style = c.in.style;
    t.style_copy.* = style;
    if (style != 0) {
        t.piece_value_2.* = piece_value;
        t.promotion_gain_2.* = promotion_gain;
    } else {
        // Custom style (E752-E7C7): values 2 x the style's piece values, read as words.
        // Proved by custom.zst (see baseTables).
        const cv = &c.in.custom_piece_values;
        for (0..5) |k| {
            const v: u16 = @as(u16, @truncate(cv[k])) *% 2;
            t.piece_value_2[1 + k] = v;
            t.piece_value_2[8 + k] = v;
        }
        const pw: u16 = @truncate(cv[0]);
        for (0..4) |k| {
            const v: u16 = (@as(u16, @truncate(cv[1 + k])) -% pw) *% 2;
            t.promotion_gain_2[2 + k] = v;
            t.promotion_gain_2[9 + k] = v;
        }
    }
    var sum_pieces: u16 = @bitCast(t.base_pieces.*);
    var sum_wp: u16 = @bitCast(t.base_white_pawns.*);
    var sum_bp: u16 = @bitCast(t.base_black_pawns.*);
    var bal2: u16 = 0;
    if (c.wl(6) < 0x63) sum_pieces -%= 0x78;
    if (c.bl(6) < 0x63) sum_pieces +%= 0x78;
    for (21..99) |sq| {
        const code = c.board(sq);
        const v: u16 = switch (code) {
            1 => @bitCast(t.pawn_white[sq]),
            2 => @bitCast(t.knight_white[sq]),
            3 => @bitCast(t.bishop_white[sq]),
            4 => @bitCast(t.rook_white[sq]),
            5 => @bitCast(t.queen_white[sq]),
            8 => @bitCast(t.pawn_black[sq]),
            9 => @bitCast(t.knight_black[sq]),
            10 => @bitCast(t.bishop_black[sq]),
            11 => @bitCast(t.rook_black[sq]),
            12 => @bitCast(t.queen_black[sq]),
            else => continue,
        };
        const white = code < 8;
        const target = if (code == 1) &sum_wp else if (code == 8) &sum_bp else &sum_pieces;
        if (white) {
            target.* +%= v;
            bal2 +%= t.piece_value_2[code];
        } else {
            target.* -%= v;
            bal2 -%= t.piece_value_2[code];
        }
    }
    p.piece_square_sum = sum_pieces;
    t.square_sum_white_pawns.* = @bitCast(sum_wp);
    t.square_sum_black_pawns.* = @bitCast(sum_bp);
    p.material_balance_2 = bal2;
}

/// 0000:B985-B9CD: pawns on dark squares, recounted from the piece lists.
fn darkPawns(c: *Ctx) void {
    const p = c.p;
    p.pawns_on_dark = .{ 0, 0 };
    for (8..16) |si| {
        var sq = c.wl(si);
        if (sq < 0x63 and c.board(sq) == pos.white_pawn) p.pawns_on_dark[0] +%= dark[sq];
        sq = c.bl(si);
        if (sq < 0x63 and c.board(sq) == pos.black_pawn) p.pawns_on_dark[1] +%= dark[sq];
    }
}

/// B9D3: find_last_irreversible_ply (0000:887E).
fn lastIrreversible(c: *Ctx) void {
    const t = c.t;
    const ply: i16 = s16(c.p.game_ply);
    const flags_by_ply = &c.in.irreversible_by_ply;
    var si: i16 = ply;
    while (!((ply -% 100) > si) and flags_by_ply[plyIndex(si)] != 0) si -%= 1;
    t.last_irreversible_ply.* = si;
    t.root_ply.* = c.p.game_ply;
    t.root_irreversible_word.* = 0;
    t.root_reversible.* = 0;
    if (flags_by_ply[plyIndex(ply)] != 0) t.root_irreversible_word.* = 0xFFFF else t.root_reversible.* = 1;
}

/// Index into DG:3490 by game ply: the whole table, plies 0..405 (`Inputs.irreversible_by_ply`).
/// The original reads no other: prepare_eval runs at most at game ply 402 (set_predicted_reply
/// after the program's move at ply 401, the last it can search: docs/arch/34-game-move-path.md,
/// "How long a game can be"), and the loop stops at ply 0 at the latest, whose flag no move
/// writes (38C0:0373 and 55FC write the ply after a move).
fn plyIndex(ply: i16) usize {
    if (ply < 0 or ply >= irreversible_plies) @panic("find_last_irreversible_ply: game ply outside DG:3490..3625");
    return @intCast(ply);
}
