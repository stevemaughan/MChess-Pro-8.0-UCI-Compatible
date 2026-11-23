//! The evaluation variables read or written by the pawn evaluation, the pawn hash,
//! update_square_sums and static_eval's quick path, other than those of the search
//! position (`Position`, src/position.zig).
//!
//! Specifications: docs/arch/50-evaluation-map.md (sections 3 and 4) and
//! docs/arch/52-evaluation-pawns.md. `DG:xxxx` is an address in the original's
//! default data segment (DGROUP, 61E4). Words are 16-bit and wrap, as in the original.

/// Indices of the square-value tables in `EvalVars.square_values[side]`: the piece code
/// minus 1 (White) or minus 8 (Black).
pub const pawn = 0;
pub const knight = 1;
pub const bishop = 2;
pub const rook = 3;
pub const queen = 4;

pub const EvalVars = struct {
    // -- set by prepare_eval (0000:9582) at the root -------------------------------

    /// Square-value tables, a word per square, built by prepare_eval
    /// (docs/arch/50-evaluation-map.md 3.2). `[0]` White, `[1]` Black; then pawn,
    /// knight, bishop, rook, queen:
    /// White DG:A8EC, 75CA, AC2A, 9182, 8DEA; Black DG:AA2C, 76A2, ACF4, 924A, 8EB8.
    /// Black's values are positive numbers, subtracted from the sums.
    square_values: [2][5][100]u16 = @splat(@splat(@splat(0))),
    /// DG:A72C: no queens and `[378E]` <= 5000 at the root (read by the pawn evaluators).
    late_endgame: u8 = 0,
    /// DG:7100 (White) and DG:9354 (Black): 1 if the side had no queen (queen slot
    /// captured) at the root.
    queen_gone_at_root: [2]u8 = .{ 0, 0 },
    /// DG:A6C3: the endgame flag (docs/arch/50-evaluation-map.md 3.3).
    endgame: u8 = 0,
    /// The word tables by square (squares 0..88) static_eval chooses between for the
    /// passed pawns, by the material (docs/arch/52-evaluation-pawns.md 3.4, `[bp-14h]`
    /// and `[bp-16h]`): White's DG:746C, 718C, 90BA; Black's DG:AE46, A792, 369E, in
    /// that order (`passer_table_addresses`).
    passer_tables: [6][89]u16 = @splat(@splat(0)),
    /// Four word tables by rank code (0..9) for passed pawns: DG:0144 and DG:0158
    /// (White's), DG:016C and DG:0180 (Black's mirrors), in that order
    /// (docs/arch/52-evaluation-pawns.md 3.4). Initialised data in the program, but not
    /// constant: DG:0154 was seen to change during a run (the writer is not identified),
    /// so they are state here, recorded with every call. Initially the program's values.
    passer_rank_tables: [4][10]u16 = blk: {
        const raw = @import("original.zig").dgroup(0x0144, 80);
        var t: [4][10]u16 = undefined;
        for (0..4) |k| for (0..10) |r| {
            t[k][r] = @import("std").mem.readInt(u16, raw[20 * k + 2 * r ..][0..2], .little);
        };
        break :blk t;
    },

    // -- style (docs/arch/50-evaluation-map.md section 9) ---------------------------

    /// DG:1548: 1 in the Normal style (a copy of DG:153E made by prepare_eval); the
    /// custom style's weights below apply only when it is 0.
    style_normal: u16 = 1,
    /// DG:290E: Centrality weight, percent (a dword).
    centrality_weight: i32 = 100,
    /// DG:2916: Pawn Structure weight, percent (a dword).
    pawn_structure_weight: i32 = 100,
    /// DG:291A: Passed Pawns weight, percent (a dword).
    passed_pawns_weight: i32 = 100,

    // -- kept move by move ------------------------------------------------------------

    /// DG:90B6 (White) and DG:369A (Black): the pawn square sums. White's is the base
    /// DG:A008 plus the White pawns' values; Black's is the base DG:7468 minus the
    /// Black pawns' values. Kept by update_square_sums (0000:678A).
    pawn_square_sum: [2]u16 = .{ 0, 0 },

    // -- written by the pawn evaluators and the pawn hash ------------------------------

    /// DG:8EB6: weak-pawn mask, bit i = pawn slot 8 + i of the side the evaluator
    /// marks (White with White to move, Black with Black to move).
    weak_pawns: u8 = 0,
    /// DG:A6C2 (White) and DG:9D8C (Black): passed-pawn masks, bit i = pawn slot 8 + i.
    passed_pawns: [2]u8 = .{ 0, 0 },

    // -- outputs of static_eval, cleared by its quick path --------------------------------

    /// DG:39AE: set by the full body when Black's king is near its own advanced passed
    /// pawn (docs/arch/52-evaluation-pawns.md 6.4).
    black_king_by_passer: u8 = 0,
    /// DG:A5F5: passed-pawn flags read by the search node.
    passer_flags: u8 = 0,
    /// DG:A8DE: 1 when static_eval scored a draw.
    draw_flag: u8 = 0,
    /// DG:8CCA: the square in front of a Black pawn on its 7th rank (full body).
    promotion_square: u8 = 0,
    /// DG:9EBA: promotion flags read by the search node.
    promotion_flags: u8 = 0,

    // -- read by evalpieces and activity (until Stage B step 6 `eval_state.EvalState`) ------

    /// The 78 bytes after the 120-byte search board. The original's activity routines
    /// read `board[list[slot]]` for every slot without testing for a captured piece, whose
    /// entry is its square + 63h (78h..C5h), so they read these bytes (DEV-018); the
    /// port skips the slot, so they are no longer read here (only `activity_reference.zig`
    /// does), and they are not part of the shared state (their home is
    /// `evalthreats.ThreatVars.board_after`).
    past_board: [78]u8 = @splat(0),
    /// DG:9EBE + n, n = 0..9: the shelter-sum score used when the king is on its first
    /// rank (only entries 0..9 are built; the three-square sum is at most 9).
    shelter_first_rank: [10]u8 = @splat(0),
    /// DG:A6A3: set by prepare_eval when the root position has no pawns.
    no_pawns_at_root: u8 = 0,
    /// DG:9D94 + ply: a per-ply flag (meaning not determined; the stand pat reads it too).
    ply_flag: [64]u8 = @splat(0),
    /// DG:7464: game ply of the last irreversible move.
    last_irreversible_ply: u16 = 0,
    /// DG:290A (dword): the Mobility weight, percent.
    mobility_weight: u32 = 100,
    /// DG:2912 (dword): the King Placement weight, percent.
    king_placement_weight: u32 = 100,
    /// DG:7260 + 2·sq (White, 101 words) and DG:732A + 2·sq (Black): king-square table.
    king_table: [2][100]u16 = @splat(@splat(0)),
    /// DG:AEFA + 2·sq (White) and DG:B03E + 2·sq (Black): king-zone table used when the
    /// enemy has little material.
    king_zone: [2][100]u16 = @splat(@splat(0)),
    /// DG:A6C8 + sq (White) and DG:A72E + sq (Black): square term of the rook in slot 5,
    /// signed bytes.
    rook_square: [2][100]u8 = @splat(@splat(0)),
    /// Activity by square of the knight, rook and queen, read unsigned: White DG:A84E,
    /// DG:ABA0, DG:AB20; Black DG:A9B4, DG:AFC6, DG:ADBE. 120 bytes each: prepare_eval
    /// writes them past square 99 (offsets from a king on the 8th rank). Read with
    /// `activityTable`.
    nrq_activity: [2][3][120]u8 = @splat(@splat(@splat(0))),
    /// Bishop activity by square, read unsigned: White DG:A2F0, Black DG:A390. The
    /// original's room is 100 bytes each (Stage B step 7, stage 3c-2): prepare_eval writes
    /// and the activity routines read no square past 98, and the root's variables follow
    /// each table.
    bishop_activity: [2][100]u8 = @splat(@splat(0)),

    /// The activity table of piece kind `k` (0 knight, 1 bishop, 2 rook, 3 queen) for
    /// `side` (0 White, 1 Black).
    pub inline fn activityTable(v: anytype, side: usize, comptime k: usize) switch (@TypeOf(v)) {
        *EvalVars => []u8,
        else => []const u8,
    } {
        return switch (k) {
            0 => &v.nrq_activity[side][0],
            1 => &v.bishop_activity[side],
            2 => &v.nrq_activity[side][1],
            3 => &v.nrq_activity[side][2],
            else => @compileError("activityTable: no piece kind"),
        };
    }

    pub const passer_table_addresses = [6]u16{ 0x746C, 0x718C, 0x90BA, 0xAE46, 0xA792, 0x369E };

    /// The passed-pawn table at a DG address the full body keeps in its frame.
    pub fn passerTable(v: *const EvalVars, addr: u16) *const [89]u16 {
        for (passer_table_addresses, 0..) |a, i| {
            if (a == addr) return &v.passer_tables[i];
        }
        unreachable;
    }
};
