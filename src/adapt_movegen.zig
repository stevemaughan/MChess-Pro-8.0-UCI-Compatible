//! Stage A adapters for the move generators (src/movegen.zig), the exchange evaluator
//! (src/see.zig), the move sort (src/sort.zig) and the search helpers (src/helpers.zig):
//! each fills the unit's structs from the DGROUP image, calls the routine unchanged, and
//! writes back only the bytes that changed (docs/arch/60-engine-assembly.md, section
//! 4.3; src/dgroup.zig).
//!
//! The move list of ply `ply` is DG:3A34 + 400 * ply (the node's `move_list`, 100 moves
//! of 4 bytes). The original has room for plies 0..34 there; a list of ply 35 or more
//! lies over the variables that follow (DG:70E4 on), as in the original (DEV-002).

const builtin = @import("builtin");

// Test-only since Stage B step 8, stage 8: the engine runs on its members (src/engine_state.zig)
// and its build never reaches this file; this block fails the build if it does.
comptime {
    if (!builtin.is_test) @compileError("src/adapt_movegen.zig is a Stage A adapter, test-only since Stage B step 8, stage 8: the engine build must not reach it");
}

const std = @import("std");
const pos = @import("position.zig");
const see_mod = @import("see.zig");
const sort_mod = @import("sort.zig");
const mg = @import("movegen.zig");
const h = @import("helpers.zig");
const dgroup = @import("dgroup.zig");
const adapt_position = @import("adapt_position.zig");

const Image = dgroup.Image;
const Side = pos.Side;

pub const PositionMap = adapt_position.PositionMap;
pub const ScratchMap = dgroup.Map(see_mod.Scratch, &dgroup.maps.see.Scratch);
pub const SearchVarsMap = dgroup.Map(mg.SearchVars, &dgroup.maps.movegen.SearchVars);

/// DG:3A34: the move list of ply 0.
pub const move_lists: u16 = 0x3A34;
pub const list_bytes = @sizeOf(mg.MoveList);

comptime {
    std.debug.assert(list_bytes == 400);
}

/// DGROUP address of the move list of `ply`.
pub fn listAddr(ply: usize) usize {
    return move_lists + list_bytes * ply;
}

/// A move list loaded from the image, written back where it changed.
const ListView = struct {
    list: mg.MoveList,
    before: [list_bytes]u8,
    addr: usize,

    fn load(lv: *ListView, img: *const Image, ply: usize) void {
        lv.addr = listAddr(ply);
        @memcpy(&lv.before, img[lv.addr..][0..list_bytes]);
        @memcpy(std.mem.asBytes(&lv.list), &lv.before);
    }
    fn store(lv: *const ListView, img: *Image) void {
        const after = std.mem.asBytes(&lv.list);
        for (after, lv.before, 0..) |a, b, i| {
            if (a != b) img[lv.addr + i] = a;
        }
    }
};

/// The state every generator takes: the position, the exchange evaluator's work areas,
/// the search variables, the list of the ply.
const GenState = struct {
    p: pos.Position = .{},
    s: see_mod.Scratch = .{},
    v: mg.SearchVars = .{},
    pb: PositionMap.Snapshot = undefined,
    sb: ScratchMap.Snapshot = undefined,
    vb: SearchVarsMap.Snapshot = undefined,
    lv: ListView = undefined,

    fn load(g: *GenState, comptime SVMap: type, img: *const Image, ply: usize) void {
        PositionMap.loadSnap(&g.p, img, &g.pb);
        ScratchMap.loadSnap(&g.s, img, &g.sb);
        SVMap.loadSnap(&g.v, img, &g.vb);
        g.lv.load(img, ply);
    }
    fn store(g: *const GenState, comptime SVMap: type, img: *Image) void {
        // The list first: SEE's attacker list (DG:9FEC, 116 bytes) and the piece lists
        // (DG:A03A) share bytes in the port's declarations, and only changed bytes are
        // written, so the order matters only where two structs change one byte.
        g.lv.store(img);
        _ = SVMap.storeChanged(&g.v, img, &g.vb);
        _ = ScratchMap.storeChanged(&g.s, img, &g.sb);
        _ = PositionMap.storeChanged(&g.p, img, &g.pb);
    }
};

pub const Generator = enum(u8) {
    all_moves = 1, // 38C0:3938
    tactical = 2, // 38C0:579A
    tactical_no_losers = 3, // 38C0:25A0
    quiescence = 4, // 38C0:9528
    captures = 5, // 38C0:4954
};

/// Generator `gen` for `side` at `ply` on the image; returns AX (the count, or FFFFh
/// when a king can be captured). `stray` is DEV-003's input for `all_moves` (unused
/// when `fixes` corrects it). The class C fixes are all off (the original); see
/// `generateFixes`.
pub fn generate(buf: *GenStateBuf, img: *Image, comptime fixes: mg.Fixes, gen: Generator, side: Side, ply: usize, stray: mg.StrayBytes) u16 {
    return generateFixes(buf, img, fixes, pos.Fixes.original, gen, side, ply, stray);
}

/// `generate` under the class C fixes `pfixes` (DEV-004, 005, 007, 008).
pub fn generateFixes(buf: *GenStateBuf, img: *Image, comptime fixes: mg.Fixes, comptime pfixes: pos.Fixes, gen: Generator, side: Side, ply: usize, stray: mg.StrayBytes) u16 {
    return generateWith(SearchVarsMap, buf, img, fixes, pfixes, gen, side, ply, stray);
}

/// `generateFixes` with the search variables moved through `SVMap` (`SearchVarsMap`, or a
/// map broken on purpose in a test).
pub fn generateWith(comptime SVMap: type, buf: *GenStateBuf, img: *Image, comptime fixes: mg.Fixes, comptime pfixes: pos.Fixes, gen: Generator, side: Side, ply: usize, stray: mg.StrayBytes) u16 {
    const g = &buf.g;
    g.load(SVMap, img, ply);
    const ax = switch (gen) {
        .all_moves => mg.genAllMovesFixes(fixes, pfixes, &g.p, &g.s, &g.v, &g.lv.list, side, ply, stray),
        // The king rule DG:39AE, whose home is `EvalVars.black_king_by_passer`.
        .tactical => mg.genTacticalMovesFixes(pfixes, &g.p, &g.s, &g.v, img[0x39AE], &g.lv.list, side, ply),
        .tactical_no_losers => mg.genTacticalMovesNoLosersFixes(pfixes, &g.p, &g.s, &g.v, &g.lv.list, side, ply),
        .quiescence => mg.genQuiescenceMovesFixes(pfixes, &g.p, &g.s, &g.v, &g.lv.list, side, ply),
        .captures => mg.genCapturesFixes(pfixes, &g.p, &g.s, &g.v, &g.lv.list, side, ply),
    };
    g.store(SVMap, img);
    return ax;
}

/// Working storage for `generate` (about 13 KB: kept off the search stack by the
/// caller, allocated once).
pub const GenStateBuf = struct { g: GenState = .{} };

/// see_capture_by_white (2B9F:C32A) / see_capture_by_black (2B9F:CAC2) on the image.
pub fn see(img: *Image, side: Side, sq: u8, v: u16) u16 {
    var p: pos.Position = .{};
    var s: see_mod.Scratch = .{};
    var pb: PositionMap.Snapshot = undefined;
    var sb: ScratchMap.Snapshot = undefined;
    PositionMap.loadSnap(&p, img, &pb);
    ScratchMap.loadSnap(&s, img, &sb);
    const ax = see_mod.see(&p, &s, side, sq, v);
    _ = ScratchMap.storeChanged(&s, img, &sb);
    _ = PositionMap.storeChanged(&p, img, &pb);
    return ax;
}

/// sort_moves (0000:65BC) on the first `n` moves of the list of `ply`.
pub fn sortList(img: *Image, ply: usize, n: i16) void {
    var lv: ListView = undefined;
    lv.load(img, ply);
    sort_mod.sortMoves(&lv.list, n);
    lv.store(img);
}

pub const Helper = enum(u8) {
    attacks_square_no_pawns = 1, // 0000:1C76 / 1DE6
    hash_move_plausible = 3, // 0000:1F56 / 211E
    count_attacked = 5, // 1E9D:CE3E / CC4E
    gen_evasions = 7, // 38C0:E260
    attacks_square = 8, // 2B9F:4A76 / 4AD4
};

/// white_attacks_square_no_pawns (0000:1C76) / black_ (0000:1DE6).
pub fn attacksSquareNoPawns(img: *const Image, side: Side, sq: usize) u16 {
    var p: pos.Position = .{};
    PositionMap.load(&p, img);
    return switch (side) {
        .white => h.attacksSquareNoPawns(&p, .white, sq),
        .black => h.attacksSquareNoPawns(&p, .black, sq),
    };
}

/// white_attacks_square (2B9F:4A76) / black_ (2B9F:4AD4).
pub fn attacksSquare(img: *const Image, side: Side, sq: usize) u16 {
    var p: pos.Position = .{};
    PositionMap.load(&p, img);
    return switch (side) {
        .white => h.attacksSquare(&p, .white, sq),
        .black => h.attacksSquare(&p, .black, sq),
    };
}

/// hash_move_plausible_white (0000:1F56) / _black (0000:211E). The move is the
/// caller's (a frame variable in the original); its from byte is cleared on rejection.
pub fn hashMovePlausible(img: *const Image, side: Side, move: *pos.Move) u16 {
    var p: pos.Position = .{};
    PositionMap.load(&p, img);
    return switch (side) {
        .white => h.hashMovePlausible(&p, .white, move),
        .black => h.hashMovePlausible(&p, .black, move),
    };
}

/// count_attacked (1E9D:CE3E White to move, 1E9D:CC4E Black to move).
pub fn countAttacked(img: *const Image, side: Side) u16 {
    return countAttackedFixes(pos.Fixes.original, img, side);
}

/// `countAttacked` under the class C fixes `fixes` (DEV-024).
pub fn countAttackedFixes(comptime fixes: pos.Fixes, img: *const Image, side: Side) u16 {
    var p: pos.Position = .{};
    PositionMap.load(&p, img);
    return switch (side) {
        .white => h.countAttackedFixes(fixes, &p, .white),
        .black => h.countAttackedFixes(fixes, &p, .black),
    };
}

/// gen_evasions (38C0:E260) for `side` at `ply`.
pub fn genEvasions(buf: *GenStateBuf, img: *Image, side: Side, ply: usize) u16 {
    const g = &buf.g;
    PositionMap.loadSnap(&g.p, img, &g.pb);
    SearchVarsMap.loadSnap(&g.v, img, &g.vb);
    g.lv.load(img, ply);
    const ax = h.genEvasions(&g.p, &g.v, &g.lv.list, side, ply);
    g.lv.store(img);
    _ = SearchVarsMap.storeChanged(&g.v, img, &g.vb);
    _ = PositionMap.storeChanged(&g.p, img, &g.pb);
    return ax;
}
