//! update_square_sums: the three running square sums kept move by move.
//!
//! Specification: docs/arch/50-evaluation-map.md section 4.2 (and 3.1), proved by
//! tools/research/eval/eval_probe.py on 511,027 calls. Tests: src/evalpawns_test.zig
//! (tests/golden/evalpawns/).
//!
//! The search makes these updates through `Position.applyMove` (src/position.zig), which
//! does them in make_move's pass with update_hash_key's; this routine remains for the
//! replay tests and for callers that need it alone.

const pos = @import("position.zig");
const ev = @import("evalvars.zig");

const Position = pos.Position;
const EvalVars = ev.EvalVars;

/// Port of update_square_sums (0000:678A-69D8).
///
/// Called before make_move, so `board[from]` is the mover and `board[to]` the piece
/// captured. Updates DG:7182 (`Position.piece_square_sum`: White's knights, bishops,
/// rooks and queens minus Black's) and the pawn sums DG:90B6 and DG:369A
/// (`EvalVars.pawn_square_sum`). Kings have no table. Castling moves only the king, so
/// the rook's value stays where it was (a quirk of the original, kept: the "C" term of
/// section 3.1). All sums are 16-bit and wrap.
pub fn updateSquareSums(p: *Position, v: *EvalVars, move: pos.Move) void {
    const from = move.from;
    const to = move.to;
    const t = &v.square_values;
    const mover = p.board[from];
    const captured = p.board[to];
    // 1. The mover (jump table 0000:685A).
    switch (mover) {
        pos.white_pawn => v.pawn_square_sum[0] +%= t[0][ev.pawn][to] -% t[0][ev.pawn][from],
        pos.white_knight...pos.white_queen => p.piece_square_sum +%= t[0][mover - 1][to] -% t[0][mover - 1][from],
        pos.black_pawn => v.pawn_square_sum[1] +%= t[1][ev.pawn][from] -% t[1][ev.pawn][to],
        pos.black_knight...pos.black_queen => p.piece_square_sum +%= t[1][mover - 8][from] -% t[1][mover - 8][to],
        else => {},
    }
    // 2. The captured piece (jump table 0000:68F8).
    switch (captured) {
        pos.white_pawn => v.pawn_square_sum[0] -%= t[0][ev.pawn][to],
        pos.white_knight...pos.white_queen => p.piece_square_sum -%= t[0][captured - 1][to],
        pos.black_pawn => v.pawn_square_sum[1] +%= t[1][ev.pawn][to],
        pos.black_knight...pos.black_queen => p.piece_square_sum +%= t[1][captured - 8][to],
        else => {},
    }
    switch (move.flag) {
        // 3. En passant: the pawn taken stands behind `to`. A mover other than a White
        // pawn is taken to be a Black pawn.
        pos.flag_en_passant => if (mover == pos.white_pawn) {
            v.pawn_square_sum[1] +%= t[1][ev.pawn][to - 10];
        } else {
            v.pawn_square_sum[0] -%= t[0][ev.pawn][to + 10];
        },
        // 4. Promotion to knight, bishop, rook or queen (the flag is the White code). The
        // pawn's own term stays in the pawn sum (the pawn tables are 0 on the 8th rank).
        2...5 => if (mover == pos.white_pawn) {
            p.piece_square_sum +%= t[0][move.flag - 1][to];
        } else {
            p.piece_square_sum -%= t[1][move.flag - 1][to];
        },
        // 5. Flag 0 and castling (6) and above: nothing more.
        else => {},
    }
}
