//! The rewrite's own legality test of a move (AGENTS.md section 9.3; DEV-051, DEV-066): not
//! a port, and never run inside the search. Used by the PV's test before it is sent and the
//! guard on the move handed back (src/uci_report.zig `PvCheck`), by position input
//! (src/engine.zig `findLegal`) and by the book's test (src/engine_root.zig `bookMoveLegal`).
//!
//! A move is legal at a position when
//! 1. it is in the list of the generator the original uses there: gen_evasions (38C0:E260,
//!    `helpers.genEvasions`) when the position's check record is set, as the original's
//!    root (0000:0827-0843), its move entry (check_entered_move, 38C0:5974-5995) and the
//!    search's nodes choose; otherwise gen_all_moves (1E9D:3938) with its cap of 100
//!    (1E9D:4903-4913, DEV-063), generated with the build's own class C fixes, as the root
//!    and the nodes generate (src/engine_state.zig `generate`);
//! 2. a castling move does not start in check (gen_all_moves offers castling without
//!    looking at the king's own square; the original never asks it in check);
//! 3. the mover's king is not attacked after the move (2B9F:4B32, `gamemove.kingAttacked`).
//!
//! Every routine here works on copies: nothing the search reads is written.

const std = @import("std");
const pos = @import("position.zig");
const mg = @import("movegen.zig");
const see_mod = @import("see.zig");
const helpers = @import("helpers.zig");
const gamemove = @import("gamemove.zig");
const dgroup = @import("dgroup.zig");

/// The bytes main reads from the game record for the root position before its search: the
/// en-passant square (0000:0677-0687, [9EC9] = 5A7B:330E + 0CBh * side + move number) and
/// the check record (0693, [8C07] = 5A7B:0B54 + the same), with `side` the side to move and
/// the move number DG:A84A at its home. `root` is a src/engine_root.zig `EngineRoot`.
pub const RootRecord = struct { ep: u8, check: u8 };

pub fn rootRecord(root: anytype, side: u16) RootRecord {
    const at = side *% 0xCB +% dgroup.memWord(root.home(), 0xA84A);
    return .{ .ep = root.farByte(0x330E +% at), .check = root.farByte(0x0B54 +% at) };
}

/// The list of the generator the original uses at ply `ply` of `p` for `side` (rule 1):
/// gen_evasions when `p.check_by_ply[ply]` is set, else gen_all_moves with the class C
/// fixes `fixes` (DEV-003 corrected, as everywhere). The count (at most 100), or
/// `mg.king_capture` when a piece of `side` can take the enemy king. `p`, `s` and `v`
/// are the caller's copies: the generators write the list, the move marks and the
/// unscored group.
pub fn generate(comptime fixes: pos.Fixes, p: *pos.Position, s: *see_mod.Scratch, v: *mg.SearchVars, list: *mg.MoveList, side: pos.Side, ply: usize) u16 {
    if (p.check_by_ply[ply] != 0) return helpers.genEvasions(p, v, list, side, ply);
    return mg.genAllMovesFixes(mg.Fixes.corrected, fixes, p, s, v, list, side, ply, .{});
}

pub const Refusal = enum {
    castling_in_check,
    leaves_king_in_check,

    pub fn text(r: Refusal) []const u8 {
        return switch (r) {
            .castling_in_check => "castling out of check",
            .leaves_king_in_check => "leaves the king in check",
        };
    }
};

/// Rules 2 and 3 for `mv`, a move of `generate`'s list, made on `p` (the caller's copy) at
/// ply `ply` with every correction of make_move on (DEV-050: a later ply's castling right
/// is the true one). Null if the move passes; `p` then holds the position after it.
pub fn makeIfKingSafe(p: *pos.Position, mv: pos.Move, side: pos.Side, ply: usize) ?Refusal {
    const mover: u8 = @backingInt(side);
    if (mv.flag == pos.flag_castle and gamemove.kingAttacked(p, mover) != 0) return .castling_in_check;
    var u: pos.Undo = .{};
    p.makeMoveFixes(mv, side, ply, &u, pos.Fixes.corrected);
    if (gamemove.kingAttacked(p, mover) != 0) return .leaves_king_in_check;
    return null;
}
