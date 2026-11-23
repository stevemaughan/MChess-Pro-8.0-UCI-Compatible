//! Stage A adapters for the evaluation units: prepare_eval (src/evaltables.zig), the
//! piece and king evaluation and the activity terms (src/evalpieces.zig,
//! src/activity.zig), the pawn evaluators and the pawn hash (src/evalpawns.zig,
//! src/pawnhash.zig). Each fills the unit's structs from the DGROUP image, calls the
//! routine unchanged, and writes back only the bytes that changed
//! (docs/arch/60-engine-assembly.md, section 4.3; src/dgroup.zig).
//!
//! prepare_eval writes its tables through `Tables`, here bound to the image itself
//! (`Tables.bindImage`; inside a search engine_root binds them to the node domain's structs
//! instead, `evaltables.bindDomain`); the evaluation reads the same bytes
//! through `EvalState` and `EvalVars`, whose tables are declared 120 entries where
//! prepare_eval's are 100 (the original lays them 100 to 108 words apart): through the
//! image each view reads exactly the bytes the original would, the entries past 100
//! included.
//!
//! The pawn hash tables are not in DGROUP (segment 5A7B): the caller keeps a `PawnHash`.

const builtin = @import("builtin");

// Test-only since Stage B step 8, stage 8: the engine runs on its members (src/engine_state.zig)
// and its build never reaches this file; this block fails the build if it does.
comptime {
    if (!builtin.is_test) @compileError("src/adapt_eval.zig is a Stage A adapter, test-only since Stage B step 8, stage 8: the engine build must not reach it");
}

const pos = @import("position.zig");
const et = @import("evaltables.zig");
const ev = @import("evalvars.zig");
const EvalState = @import("eval_state.zig").EvalState;
const evalpieces = @import("evalpieces.zig");
const activity = @import("activity.zig");
const evalpawns = @import("evalpawns.zig");
const PawnHash = @import("pawnhash.zig").PawnHash;
const dgroup = @import("dgroup.zig");
const adapt_position = @import("adapt_position.zig");

const Image = dgroup.Image;
const Side = pos.Side;

pub const PositionMap = adapt_position.PositionMap;
pub const EvalVarsMap = adapt_position.EvalVarsMap;
/// The tables' bytes as values (`evaltables.TableValues`), for the tests that read them
/// from an image: one entry per field of `Tables`, at its address (`Tables.dg`).
pub const TablesMap = dgroup.Map(et.TableValues, &tables_entries);
const tables_entries = blk: {
    const names = @typeInfo(et.Tables).@"struct".field_names;
    var a: [names.len]dgroup.Entry = undefined;
    for (names, 0..) |name, i| {
        const T = et.Tables.Pointee(name);
        a[i] = .{ .field = name, .first = 0, .count = dgroup.flatLen(T), .addr = @field(et.Tables.dg, name), .esize = dgroup.elemSize(dgroup.Flat(T)) };
    }
    const final = a;
    break :blk final;
};
pub const InputsMap = dgroup.Map(et.Inputs, &dgroup.maps.evaltables.Inputs);
/// `EvalState` is `EvalVars` (Stage B step 6): its map is `EvalVars`'.
pub const EvalStateMap = dgroup.Map(EvalState, &dgroup.maps.evalvars.EvalVars);

/// Working storage for the adapters that take several large structs (about 20 KB):
/// allocated once by the caller, off the search stack.
pub const Buf = struct {
    p: pos.Position = .{},
    pb: PositionMap.Snapshot = undefined,
    in: et.Inputs = .{},
    e: EvalState = .{},
    v: ev.EvalVars = .{},
    vb: EvalVarsMap.Snapshot = undefined,
};

/// prepare_eval (0000:9582) on the image. Writes the position's fields it changes and
/// the tables; `Inputs` are only read. The tables are written in the image itself
/// (`Tables.bindImage`). The caller's duties (copying the root key to the game record,
/// clearing the pawn hash) are not part of it.
pub fn prepareEval(b: *Buf, img: *Image) void {
    prepareEvalFixes(b, img, pos.Fixes.original);
}

/// `prepareEval` under the class C fixes `fixes` (DEV-010, 011, 012, 056).
pub fn prepareEvalFixes(b: *Buf, img: *Image, comptime fixes: pos.Fixes) void {
    PositionMap.loadSnap(&b.p, img, &b.pb);
    InputsMap.load(&b.in, img);
    var t: et.Tables = .{};
    t.bindImage(img);
    et.prepareEvalFixes(&b.p, &t, &b.in, fixes);
    _ = PositionMap.storeChanged(&b.p, img, &b.pb);
}

fn loadPieces(b: *Buf, img: *const Image) void {
    PositionMap.load(&b.p, img);
    EvalStateMap.load(&b.e, img);
}

/// eval_pieces_and_kings (0EF8:0006) on the image. Reads only.
pub fn evalPiecesAndKings(b: *Buf, img: *const Image, side: u16, ply: u16) i16 {
    return evalPiecesAndKingsFixes(pos.Fixes.original, b, img, side, ply);
}

/// `evalPiecesAndKings` under the class C fixes `fixes` (DEV-017).
pub fn evalPiecesAndKingsFixes(comptime fixes: pos.Fixes, b: *Buf, img: *const Image, side: u16, ply: u16) i16 {
    loadPieces(b, img);
    return evalpieces.evalPiecesAndKingsFixes(fixes, &b.p, &b.e, side, ply);
}

/// piece_activity_white (1E9D:16E4) on the image. Reads only.
pub fn pieceActivityWhite(b: *Buf, img: *const Image) i16 {
    return pieceActivityWhiteFixes(pos.Fixes.original, b, img);
}

/// `pieceActivityWhite` under the class C fixes `fixes` (DEV-019).
pub fn pieceActivityWhiteFixes(comptime fixes: pos.Fixes, b: *Buf, img: *const Image) i16 {
    loadPieces(b, img);
    return activity.pieceActivityWhiteFixes(fixes, &b.p, &b.e);
}

/// piece_activity_black (1E9D:1E30) on the image. Reads only.
pub fn pieceActivityBlack(b: *Buf, img: *const Image) i16 {
    return pieceActivityBlackFixes(pos.Fixes.original, b, img);
}

/// `pieceActivityBlack` under the class C fixes `fixes` (DEV-019).
pub fn pieceActivityBlackFixes(comptime fixes: pos.Fixes, b: *Buf, img: *const Image) i16 {
    loadPieces(b, img);
    return activity.pieceActivityBlackFixes(fixes, &b.p, &b.e);
}

/// mobility_term (0000:2E72) on the image. Reads only.
pub fn mobilityTerm(b: *Buf, img: *const Image) i16 {
    return mobilityTermFixes(pos.Fixes.original, b, img);
}

/// `mobilityTerm` under the class C fixes `fixes` (DEV-019).
pub fn mobilityTermFixes(comptime fixes: pos.Fixes, b: *Buf, img: *const Image) i16 {
    loadPieces(b, img);
    return activity.mobilityTermFixes(fixes, &b.p, &b.e);
}

fn loadPawns(b: *Buf, img: *const Image) void {
    PositionMap.loadSnap(&b.p, img, &b.pb);
    EvalVarsMap.loadSnap(&b.v, img, &b.vb);
}

fn storePawns(b: *const Buf, img: *Image) void {
    _ = EvalVarsMap.storeChanged(&b.v, img, &b.vb);
    _ = PositionMap.storeChanged(&b.p, img, &b.pb);
}

/// pawn_eval_wtm (0EF8:89DC) / pawn_eval_btm (0EF8:8F82) on the image.
pub fn pawnEval(b: *Buf, img: *Image, side: Side) i16 {
    loadPawns(b, img);
    const r = switch (side) {
        .white => evalpawns.pawnEval(&b.p, &b.v, .white),
        .black => evalpawns.pawnEval(&b.p, &b.v, .black),
    };
    storePawns(b, img);
    return r;
}

/// The pawn-hash probe (0000:18E8 White to move, 19D4 Black), evaluating on a miss.
pub fn pawnHashProbe(b: *Buf, img: *Image, h: *PawnHash, side: Side) i16 {
    loadPawns(b, img);
    const r = switch (side) {
        .white => h.probe(&b.p, &b.v, .white),
        .black => h.probe(&b.p, &b.v, .black),
    };
    storePawns(b, img);
    return r;
}

/// The forced pawn-hash store (0000:1AC0 White to move, 1B24 Black).
pub fn pawnHashStore(b: *Buf, img: *Image, h: *PawnHash, side: Side) u16 {
    loadPawns(b, img);
    const r = switch (side) {
        .white => h.store(&b.p, &b.v, .white),
        .black => h.store(&b.p, &b.v, .black),
    };
    storePawns(b, img);
    return r;
}
