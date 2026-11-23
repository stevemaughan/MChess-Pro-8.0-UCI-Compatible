//! Stage A adapters for the position unit (src/position.zig) and update_square_sums
//! (src/squaresums.zig): each fills the unit's structs from the DGROUP image, calls the
//! routine unchanged, and writes back only the bytes that changed
//! (docs/arch/60-engine-assembly.md, section 4.3; src/dgroup.zig).
//!
//! `Undo` is not in DGROUP: in the original its two bytes are in the search node's frame
//! (position.zig), so it stays a parameter.

const builtin = @import("builtin");

// Test-only since Stage B step 8, stage 8: the engine runs on its members (src/engine_state.zig)
// and its build never reaches this file; this block fails the build if it does.
comptime {
    if (!builtin.is_test) @compileError("src/adapt_position.zig is a Stage A adapter, test-only since Stage B step 8, stage 8: the engine build must not reach it");
}

const pos = @import("position.zig");
const ev = @import("evalvars.zig");
const squaresums = @import("squaresums.zig");
const dgroup = @import("dgroup.zig");

const Image = dgroup.Image;

pub const PositionMap = dgroup.Map(pos.Position, &dgroup.maps.position.Position);
pub const EvalVarsMap = dgroup.Map(ev.EvalVars, &dgroup.maps.evalvars.EvalVars);

/// make_move (1E9D:000C) on the image.
pub fn makeMove(img: *Image, move: pos.Move, side: pos.Side, ply: usize, undo: *pos.Undo) void {
    var p: pos.Position = .{};
    var before: PositionMap.Snapshot = undefined;
    PositionMap.loadSnap(&p, img, &before);
    p.makeMove(move, side, ply, undo);
    _ = PositionMap.storeChanged(&p, img, &before);
}

/// unmake_move (1E9D:0960) on the image.
pub fn unmakeMove(img: *Image, move: pos.Move, side: pos.Side, undo: *pos.Undo) void {
    var p: pos.Position = .{};
    var before: PositionMap.Snapshot = undefined;
    PositionMap.loadSnap(&p, img, &before);
    p.unmakeMove(move, side, undo);
    _ = PositionMap.storeChanged(&p, img, &before);
}

/// unmake_move on the image for a move the search made with `Position.applyMove` under
/// `fixes` (DEV-050: a castling right taken away by the capture of a corner rook is given
/// back). With `Fixes.original` it is `unmakeMove`.
pub fn unmakeMoveFixes(img: *Image, move: pos.Move, side: pos.Side, undo: *pos.Undo, comptime fixes: pos.Fixes) void {
    var p: pos.Position = .{};
    var before: PositionMap.Snapshot = undefined;
    PositionMap.loadSnap(&p, img, &before);
    p.unmakeMoveFixes(move, side, undo, fixes);
    _ = PositionMap.storeChanged(&p, img, &before);
}

/// update_hash_key (4793:3EA2) on the image.
pub fn updateHashKey(img: *Image, move: pos.Move, comptime fixes: pos.Fixes) void {
    var p: pos.Position = .{};
    var before: PositionMap.Snapshot = undefined;
    PositionMap.loadSnap(&p, img, &before);
    p.updateHashKey(move, fixes);
    _ = PositionMap.storeChanged(&p, img, &before);
}

/// update_square_sums (0000:678A) on the image.
pub fn updateSquareSums(img: *Image, move: pos.Move) void {
    var p: pos.Position = .{};
    var v: ev.EvalVars = .{};
    var pb: PositionMap.Snapshot = undefined;
    var vb: EvalVarsMap.Snapshot = undefined;
    PositionMap.loadSnap(&p, img, &pb);
    EvalVarsMap.loadSnap(&v, img, &vb);
    squaresums.updateSquareSums(&p, &v, move);
    _ = PositionMap.storeChanged(&p, img, &pb);
    _ = EvalVarsMap.storeChanged(&v, img, &vb);
}
