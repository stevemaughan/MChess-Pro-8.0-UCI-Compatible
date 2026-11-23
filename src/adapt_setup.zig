//! A position entered through the original's Setup mode (docs/arch/60-engine-assembly.md
//! section 5, step 13; specification: docs/arch/23-position-setup.md, "From the command
//! loop to the first search after a set-up"). Since Stage B step 8, stage 4, on the
//! engine's members (`domainBegin`): DGROUP's variables by address at their homes
//! (`EngineRoot.Home`), the build on the domain's `Position` with the set-up variables reached
//! through their homes (`EngineRoot.onPositionAndSetup`), the game record in place
//! (`EngineRoot.RecordHome`); the editor's steps take any store by address.
//!
//! The path the oracle's `fen` scenarios take, and the one `position fen` takes: from the
//! command loop, Ctrl-E opens Setup mode (setup_mode 38C0:5C2E), key 2 clears the board,
//! the men are placed, Esc and 1 choose the side to move, S and Enter save; Setup mode's
//! legality test (38C0:6542) refuses the board or lets 38C0:6354 build the search
//! position from it (build_position_from_setup 38C0:6788, src/setup.zig `build`); back in
//! the command loop, Ctrl-A gives the program the side to move (`EngineRoot.autoPlay`), and main
//! runs to 0526, where the search starts.
//!
//! Only engine state is ported: the screen, the cursor and the dialogs are not.
//!
//! What Setup mode cannot express of a FEN (castling rights, the en-passant square, the
//! halfmove clock, the move number) is not taken from the FEN here: the rights follow from
//! the board, as 38C0:6788 makes them, the en-passant square is 0 (38C0:635F), the move
//! number is 1 and the last irreversible ply 1 (38C0:6851). `Fields` says which of the
//! FEN's fields agree with what Setup makes, so that the caller can refuse or report the
//! others (docs/UCI.md, "position fen").

const std = @import("std");
const pos = @import("position.zig");
const fen = @import("fen.zig");
const setup = @import("setup.zig");
const dgroup = @import("dgroup.zig");
const est = @import("engine_state.zig");
const engine_root = @import("engine_root.zig");

const Image = dgroup.Image;
const PositionMap = est.PositionMap;
const SetupVarsMap = engine_root.SetupVarsMap;

fn word(img: *const Image, a: u16) u16 {
    return std.mem.readInt(u16, img[a..][0..2], .little);
}

/// The messages of Setup mode's refusals (PRBOOK\ENGLISH.T80, shown by 38C0:5CCA), by
/// `setup.Legality` value.
pub fn refusalText(r: setup.Legality) []const u8 {
    return switch (r) {
        .legal => "",
        .no_white_king => "NO WHITE KING",
        .too_many_white_kings => "Too many WHITE KINGS",
        .no_black_king => "NO BLACK KING",
        .too_many_black_kings => "Too many BLACK KINGS",
        .too_many_white_pawns => "Too many WHITE PAWNS",
        .too_many_white_pieces => "Too many WHITE PIECES",
        .too_many_black_pawns => "Too many BLACK PAWNS",
        .too_many_black_pieces => "Too many BLACK PIECE",
        .white_in_check => "WHITE IS IN CHECK",
        .black_in_check => "BLACK IS IN CHECK",
    };
}

/// The castling rights 38C0:6788 gives a board (6CBF..6D0A): a king on its e-square and a
/// rook on its corner square hold the right.
pub fn rightsFromBoard(b: *const [120]u8) fen.Castling {
    return .{
        .white_short = b[0x19] == pos.white_king and b[0x1C] == pos.white_rook,
        .white_long = b[0x19] == pos.white_king and b[0x15] == pos.white_rook,
        .black_short = b[0x5F] == pos.black_king and b[0x62] == pos.black_rook,
        .black_long = b[0x5F] == pos.black_king and b[0x5B] == pos.black_rook,
    };
}

/// Which fields of a FEN Setup mode cannot give as the FEN asks. Each true field is one
/// the position entered through Setup mode differs in from the FEN.
pub const Unsupported = struct {
    /// The FEN's rights differ from the board's (`rightsFromBoard`).
    castling: bool = false,
    /// The FEN names an en-passant square (Setup mode writes 0).
    en_passant: bool = false,
    /// The halfmove clock is not 0 (Setup mode: the last irreversible ply is 1, so the
    /// count starts afresh).
    halfmove_clock: bool = false,
    /// The fullmove number is not 1 (Setup mode: move number 1).
    fullmove_number: bool = false,

    pub fn any(u: Unsupported) bool {
        return u.castling or u.en_passant or u.halfmove_clock or u.fullmove_number;
    }
};

pub fn unsupported(d: *const fen.Description) Unsupported {
    const r = rightsFromBoard(&d.board);
    return .{
        .castling = !std.meta.eql(r, d.castling),
        .en_passant = d.en_passant != null,
        .halfmove_clock = d.halfmove_clock != 0,
        .fullmove_number = d.fullmove_number != 1,
    };
}

/// Ctrl-E from the command loop: setup_mode's entry (38C0:5C5C-5C98) [read; traced by the
/// image at main]: the editor's side ([9FC6], and [A4C8]) is the side to move [717C];
/// [3670] = [1B8C] = 0; the search board's squares 21..98 to the game board (7535), and
/// the game board's to the set-up board (8C57). Key 2 (38C0:6326-6351, then 5C8B): the
/// game board's squares 21..98 to 0, its border files to 7, and again to the set-up board.
pub fn enterAndClear(m: anytype) void {
    m.set(0x9FC6, m.get(0x717C));
    m.set(0xA4C8, m.get(0x717C));
    m.set(0x3670, 0);
    m.set(0x1B8C, 0);
    dgroup.memCopy(m, 0x7535, 0x9F0B, 78);
    dgroup.memCopy(m, 0x8C57, 0x7535, 78);
    dgroup.memFill(m, 0x7535, 78, 0);
    var a: u16 = 0x7583;
    while (a >= 0x753D) : (a -= 10) {
        m.set(a, 7);
        m.set(a - 9, 7);
    }
    dgroup.memCopy(m, 0x8C57, 0x7535, 78);
}

/// The men typed (38C0:5D50..6226: a piece key writes its code on the set-up board at the
/// cursor) and the side chosen (Esc, then 1: 60AC toggles [9FC6]).
pub fn place(m: anytype, d: *const fen.Description) void {
    for (21..99) |sq| {
        if (sq % 10 == 0 or sq % 10 == 9) continue;
        m.set(@intCast(0x8C42 + sq), d.board[sq]);
    }
    m.set(0x9FC6, @backingInt(d.side_to_move));
}

/// S and Enter: setup_legality (38C0:6542 from 62A1) on the set-up board and [9FC6].
pub fn legality(m: anytype) setup.Legality {
    var b: [121]u8 = undefined;
    for (&b, 0..) |*x, k| x.* = m.get(@intCast(0x8C42 + k));
    return setup.legality(&b, m.get(0x9FC6));
}

/// 38C0:6354-6366 and build_position_from_setup (38C0:6788) on the members and the game
/// record (each variable at its home): [717C] = [9FC6], [90B8] = 0, the build (src/setup.zig `build`, the search
/// position and the game variables it writes), and what the build writes outside those
/// structs [traced: tools/research/setup/check.py compares all of DGROUP]: the 198-byte
/// clears of 67AB..67D8 run 78 bytes past each of the four maps; 406 bytes from DG:3490
/// to 0 (67EA); the far writes of the game record (6DCA..6E18; [30F0], [30F2] and
/// [30F4] hold segment 5A7B): the score of position 0 (2484) 0, the key of ply 0 (3A34),
/// the en-passant bytes 330F/3310 and 33DA/33DB, the check bytes 0B54..0B56 and
/// 0C1F..0C21; then clear_hash_tables (0000:88CC).
pub fn save(s: anytype) void {
    saveWithEp(s, 0);
}

/// `save` with the en-passant square `ep` in [90B8] instead of Setup mode's 0, as the
/// position loader (0EF8:6AA0-6AA3) has it before it calls the build.
pub fn saveWithEp(s: anytype, ep: u8) void {
    const m = s.home();
    m.set(0x717C, m.get(0x9FC6));
    m.set(0x90B8, ep);
    s.onPositionAndSetup(setup.build, .{});
    for ([_]u16{ 0xA116, 0xA1DC, 0xA594, 0x3852 }) |a| dgroup.memFill(m, a, 78, 0);
    dgroup.memFill(m, 0x3490, 0x196, 0);
    const fm = s.recordHome();
    dgroup.memFill(fm, 0x2484, 2, 0);
    for (0..6) |k| fm.set(@intCast(engine_root.keys_offset + k), m.get(@intCast(0x8CCC + k)));
    for ([_]u16{ 0x33DA, 0x330F, 0x33DB, 0x3310 }) |a| fm.set(a, 0);
    fm.set(if (m.get(0x717C) == 0) 0x330F else 0x33DA, m.get(0x90B8));
    for ([_]u16{ 0x0C1F, 0x0B54, 0x0C20, 0x0B55, 0x0C21, 0x0B56 }) |a| fm.set(a, m.get(0x8C06));
    for (s.tables) |*t| t.clear();
}

/// The whole of Setup mode for a description: enter, clear, place, choose the side, and
/// save. Returns the refusal (and leaves the build undone) if setup_legality refuses
/// the board, as the original keeps the editor open with the message.
pub fn enter(s: anytype, d: *const fen.Description) setup.Legality {
    const m = s.home();
    enterAndClear(m);
    place(m, d);
    const r = legality(m);
    if (r != .legal) return r;
    save(s);
    s.refreshCopies();
    return .legal;
}

/// The position loader's castling lines (load_position_text 0EF8:6AAB-6AF0) [read]: after
/// the build, each right the record does not give is stamped lost (FFFFh), and the four
/// copies are rewritten. The hash key is not rebuilt (docs/arch/23-position-setup.md,
/// suspected bug 2): the main key keeps the castling keys of the rights the build gave.
// UNVERIFIED: runs in the engine (`position fen` with a right the board would give) and is
// tested there (perft_test, the DEV-027 test); not compared with the original, whose loader
// (0EF8:69CC) no key sequence the emulator can send was found to reach; read from the listing.
pub fn withdrawRights(m: anytype, c: fen.Castling) void {
    const stamps = [4]struct { bool, u16 }{
        .{ c.white_short, 0xB426 }, .{ c.white_long, 0x3A30 },
        .{ c.black_short, 0xB428 }, .{ c.black_long, 0x3A32 },
    };
    for (stamps) |st| if (!st[0]) dgroup.memSetWord(m, st[1], 0xFFFF);
    dgroup.memCopy(m, 0xA5E6, 0xB426, 2);
    dgroup.memCopy(m, 0xA5E8, 0xB428, 2);
    dgroup.memCopy(m, 0xA6A4, 0x3A30, 2);
    dgroup.memCopy(m, 0xA6A6, 0x3A32, 2);
}

/// A FEN put into the engine as the original's own code can take it: Setup mode for the
/// board and the side to move (proved: every corpus2 scenario), with what the position
/// loader adds to the same build (0EF8:6A9A-6AF0) [read]: the FEN's en-passant square in
/// [90B8] before the build (it becomes ep_square_by_ply[0] and the record's square), and
/// the rights the FEN withholds stamped lost after it. A FEN whose rights and square are
/// those Setup mode gives (`unsupported` false for both) takes Setup mode's path exactly.
/// The halfmove clock and the move number have no counterpart in either path and are not
/// used (`unsupported` says which differ). Returns Setup mode's refusal, if any.
pub fn enterFen(s: anytype, d: *const fen.Description) setup.Legality {
    return enterFenFixes(pos.Fixes.original, s, d);
}

/// `enterFen` under `fixes` (DEV-027, `dev027_loader_key`).
pub fn enterFenFixes(comptime fixes: pos.Fixes, s: anytype, d: *const fen.Description) setup.Legality {
    const m = s.home();
    enterAndClear(m);
    place(m, d);
    const r = legality(m);
    if (r != .legal) return r;
    saveWithEp(s, d.en_passant orelse 0);
    if (!std.meta.eql(rightsFromBoard(&d.board), d.castling)) {
        withdrawRights(m, d.castling);
        if (fixes.dev027_loader_key) rekeyAfterWithdraw(s);
    }
    s.refreshCopies();
    return .legal;
}

/// DEV-027, corrected (`dev027_loader_key`). The position loader (0EF8:6AAB-6AD5) stamps a
/// right lost after the build, whose hash_from_scratch (38C0:6DA7) counted it as held, and
/// does not rebuild the key; a lost stamp XORs that right's key into the main key
/// everywhere else (4793:412E, make_move). Two stored copies of the key are then stale:
/// the main key DG:8CCC and the game record's key of ply 0 (5A7B:3A34, written by the
/// build from DG:8CCC; in the engine `EngineRoot.rec.keys[0]`, which the node reads). Corrected, both are the
/// key of the position as loaded, rights withdrawn: hash_from_scratch on the stamps as they
/// now stand. The pawn key has no castling term and is unchanged.
///
/// In the original neither stale copy is read: prepare_eval rebuilds DG:8CCC from the
/// stamps before every search (0000:9605) and every game move rebuilds it (38C0:0377);
/// with White to move the first search writes its key at game ply 0 (0000:960A); and both
/// repetition tests (2B9F:402A, leaf.isRepetition) read the record from the last
/// irreversible ply, which the build sets to 1 (DG:7464), never ply 0. So the correction
/// changes no search; `src/adapt_setup_test.zig` shows both.
fn rekeyAfterWithdraw(s: anytype) void {
    // On the domain's `Position`, its copies refreshed first and its changed bytes carried
    // to their homes after, as Stage A's load and store.
    const p = &s.node.dom.p;
    s.node.refreshAliases(&.{.p});
    var pb: PositionMap.Snapshot = undefined;
    PositionMap.snapshot(p, &pb);
    const keys = p.hashFromScratch();
    p.hash_key = keys.main;
    _ = PositionMap.storeChangedVia(p, s.home(), &pb);
    const m = s.home();
    const fm = s.recordHome();
    for (0..6) |k| fm.set(@intCast(engine_root.keys_offset + k), m.get(@intCast(0x8CCC + k)));
}
