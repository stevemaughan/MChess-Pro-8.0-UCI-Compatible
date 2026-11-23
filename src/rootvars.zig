//! The homes of the DGROUP variables that no unit's struct holds (Stage B step 8, stage 7;
//! docs/arch/60-engine-assembly.md section 10.7.15): `RootVars`, the root's own variables,
//! and `ProgramVars`, every other variable the engine reads or writes between and during
//! searches. Both are members of the engine's state (src/engine_state.zig `Members.rv`,
//! `Members.pg`), persistent for its life, so that no byte of live state is left in the
//! 64 KB image during play.
//!
//! Before this stage these variables lived in the image: the root's views (src/rootprep.zig
//! `PrepState`, src/rootsearch.zig `RootState`) kept copies of them that were written to the
//! image before every callee and read back after it, the game's and the time budget's
//! structs pointed at the image for them, and the routines that address the original's
//! variables (src/newgame.zig, src/gameslide.zig, Setup mode, the hash dialog, the book)
//! reached them there through `engine_root.EngineRoot.Home`. Now each view field is a pointer into
//! these structs (`rootprep.bindRoot`, `rootsearch.bindRoot`), and every other declaration
//! of the same bytes is a pointer too, bound through the layout's one home of each byte.
//!
//! Each field is a variable at the address `var_addresses` gives, held in memory as the
//! image holds it (integers little-endian, arrays of them), so that a view's narrower or
//! differently signed declaration of the same bytes is a pointer to them. A variable that
//! several structs declare with different extents is one field covering all of them (the
//! move handed to play_best_move, five bytes, of which main's view names four; the level-2
//! records, inside which main's view names two words). Two fields are byte arrays because
//! the original addresses them as memory: main's low page and the root's stack frames.

const std = @import("std");
const tbud = @import("timebudget.zig");
const dgroup = @import("dgroup.zig");

/// The field map of `S` (`RootVars` or `ProgramVars`) from its `dg`: one entry per field,
/// every field (both are values only).
pub fn mapOf(comptime S: type) [@typeInfo(S).@"struct".field_names.len]dgroup.Entry {
    return comptime blk: {
        @setEvalBranchQuota(100_000);
        const fs = @typeInfo(S).@"struct".field_names;
        var out: [fs.len]dgroup.Entry = undefined;
        for (fs, 0..) |f, i| {
            const F = @FieldType(S, f);
            out[i] = .{ .field = f, .first = 0, .count = dgroup.flatLen(F), .addr = @field(S.dg, f), .esize = dgroup.elemSize(dgroup.Flat(F)) };
        }
        break :blk out;
    };
}

/// Bytes of the original a value of type `T` covers (integers of whole bytes, arrays of
/// them, extern structs).
pub fn originalSize(comptime T: type) usize {
    return switch (@typeInfo(T)) {
        .int => |i| i.bits / 8,
        .array => |a| a.len * originalSize(a.child),
        .@"struct" => |s| if (s.layout == .@"extern") @sizeOf(T) else @compileError("rootvars: a non-extern struct"),
        else => @compileError("rootvars: unsupported field type " ++ @typeName(T)),
    };
}

/// Where DGROUP bytes `addr`..`addr + n` lie in the two structs: the struct (`.rv` or
/// `.pg`), the field and the offset in it; null if no field of either holds the first
/// byte. A compile error if the bytes run past the end of the field that holds the first.
pub const Place = struct { in: enum { rv, pg }, field: []const u8, off: usize };

pub fn place(comptime addr: u16, comptime n: usize) ?Place {
    @setEvalBranchQuota(1_000_000);
    inline for (.{ .{ RootVars, Place{ .in = .rv, .field = "", .off = 0 } }, .{ ProgramVars, Place{ .in = .pg, .field = "", .off = 0 } } }) |sp| {
        const S = sp[0];
        for (@typeInfo(S).@"struct".field_names) |f| {
            const base: usize = @field(S.dg, f);
            const len = originalSize(@FieldType(S, f));
            if (addr >= base and addr < base + len) {
                if (addr + n > base + len) @compileError(std.fmt.comptimePrint("rootvars: DG:{X:0>4} + {d} runs past {s}.{s}", .{ addr, n, @typeName(S), f }));
                var p = sp[1];
                p.field = f;
                p.off = addr - base;
                return p;
            }
        }
    }
    return null;
}

/// The `n` bytes at DGROUP address `addr` in `rv` or `pg` (`place`, resolved at compile
/// time; a compile error where neither holds them).
pub inline fn bytesAt(rv: *RootVars, pg: *ProgramVars, comptime addr: u16, comptime n: usize) *[n]u8 {
    const p = comptime place(addr, n) orelse @compileError(std.fmt.comptimePrint("rootvars: DG:{X:0>4} is in no field", .{addr}));
    const b: [*]u8 = switch (p.in) {
        .rv => @ptrCast(&@field(rv, p.field)),
        .pg => @ptrCast(&@field(pg, p.field)),
    };
    return b[p.off..][0..n];
}

/// Points every pointer field of `view` named in `layout` (name, address) whose bytes lie
/// in `rv` or `pg` at them; the fields whose bytes no field of either holds are left as
/// they are (a member of the node domain holds them: the view's `bindDomain`).
pub fn bindView(comptime V: type, comptime layout: anytype, view: *V, rv: *RootVars, pg: *ProgramVars) void {
    inline for (layout) |l| {
        const F = @FieldType(V, l[0]);
        const n = comptime originalSize(@typeInfo(F).pointer.child);
        if (comptime place(l[1], n) != null) @field(view, l[0]) = @ptrCast(@alignCast(bytesAt(rv, pg, l[1], n)));
    }
}

/// Every other DGROUP variable the engine reads or writes that no unit's member holds:
/// the settings and the program's memory, the tablebase signatures, the book's words,
/// Setup mode's boards and copies (src/setup.zig `SetupVars`, which works on a copy loaded
/// from these homes for each call), the variables prepare_eval writes that no evaluator of
/// the search reads (src/evaltables.zig `Tables`) and the ones it reads that nothing else
/// holds (`Inputs`), the game's own (`gamemove.GameVars`' pointers), and the bytes the
/// start-up, the settings and the turn write and no ported routine reads.
pub const ProgramVars = struct {
    // ---- the program's memory and settings --------------------------------------------
    /// DG:00E2: the memory on offer for the hash tables (KB, dword; hash_setup).
    hash_avail_kb: i32 = 0,
    /// DG:9352: the XMS tables are allocated (a word; hash_resize reads its low byte).
    xms_ready: u16 = 0,
    /// DG:239A: the number of tablebase signatures the start-up scan left; DG:A422: the
    /// signatures (at most 50h, 2B9F:C2A6).
    tb_signature_count: i16 = 0,
    tb_signatures: [0x50]u16 = @splat(0),
    // ---- the book ----------------------------------------------------------------------
    /// DG:2522, DG:2524: the plies of the book moves (per side).
    book_move_ply: [2]u16 = .{ 0, 0 },
    /// DG:2DC8: the C library's random seed (rand, 4793:89D8).
    rand_seed: u32 = 0,
    /// DG:7449: the opening name's number.
    book_name: u8 = 0,
    /// DG:70E4: 1: the book is not used (a set-up position).
    book_off: u8 = 0,
    // ---- Setup mode (`setup.SetupVars`) ------------------------------------------------
    /// DG:8C46..8CBA: the set-up board, squares 4 to 120 (its squares 0..3, DG:8C42..8C45,
    /// are held by the tail of `Position.check_by_ply`); main's copy of the root position,
    /// DG:8C57, is squares 21..98 (`PrepState.root_copy`).
    setup_board: [117]u8 = @splat(7),
    /// DG:90B8: the en-passant square of the set-up.
    setup_ep_square: u8 = 0,
    /// DG:776C..77CF: the saved set-up board, squares 0..99 (Setup mode writes squares
    /// 21..98). `SetupVars.saved_setup` declares 120 squares: square 100, DG:77D0, is
    /// `RootVars.best_check`; squares 101..109, DG:77D1..77D9, are `saved_setup_tail`; the
    /// rest, from DG:77DA, is `LeafVars.bk_diag`. The set-up routines' copy loads and stores
    /// every declared square at its home, and writes none past square 98.
    saved_setup: [100]u8 = @splat(0),
    saved_setup_tail: [9]u8 = @splat(0),
    /// DG:7520: the game (displayed) board.
    game_board: [120]u8 = @splat(0),
    /// DG:AE44, DG:B42A: copies of the side to move.
    side_ae44: u8 = 0,
    setup_side_saved: u8 = 0,
    /// DG:A5E6, DG:A5E8: copies of the O-O stamps; DG:A6A4, DG:A6A6: of the O-O-O stamps.
    oo_copy: [2]u16 = .{ 0, 0 },
    ooo_copy: [2]u16 = .{ 0, 0 },
    /// DG:A4F3: a byte Setup mode and New game clear. DG:2A8E: a word Setup mode clears.
    ba4f3: u8 = 0,
    w2a8e: u16 = 0,
    // ---- the game ----------------------------------------------------------------------
    /// DG:A6AE: the game ply at which the game ended (0: not ended).
    game_over_ply: u16 = 0,
    /// DG:9D92: the game ply at which the program resigned (0 none).
    resigned_ply: u16 = 0,
    /// DG:A414: the predicted reply (from, to) as play_best_move leaves it.
    predicted: u16 = 0,
    // ---- prepare_eval's (`evaltables.Tables`, `Inputs`) ---------------------------------
    /// DG:14D0, DG:14EC: piece value and promotion gain by code for the second balance.
    piece_value_2: [14]u16 = @splat(0),
    promotion_gain_2: [14]u16 = @splat(0),
    /// DG:153E: the style, 0 = custom; DG:2906: Aggression (dword); DG:2922: the custom
    /// style's piece values (dwords).
    style: u16 = 0,
    aggression: i32 = 0,
    custom_piece_values: [5]u32 = @splat(0),
    /// DG:7468: the base of Black's pawn square sum; DG:A5E2: of the pieces' square sum.
    base_black_pawns: i16 = 0,
    base_pieces: i16 = 0,
    /// DG:724C, DG:9D8B, DG:8CC4: Black's, White's and all passed pawns at the root.
    passed_count_black: u8 = 0,
    passed_count_white: u8 = 0,
    passed_count_both: u8 = 0,
    /// DG:A8E0: the highest rank code of a White passed pawn per file.
    passed_rank_by_file_white: [8]u8 = @splat(0),
    /// DG:A3FE, DG:8CE6: White's and Black's passed-pawn squares.
    passed_pawn_sq_white: [16]u8 = @splat(0),
    passed_pawn_sq_black: [16]u8 = @splat(0),
    /// DG:7692: 16 bytes from DG:03FA, divided.
    table_7692: [16]u8 = @splat(0),
    /// DG:A080: the mobility weight of piece codes 6..13.
    mobility_weights_rest: [8]i16 = @splat(0),
    /// DG:A360: 1 both sides have only bishop slot 2, 2 only slot 3.
    single_bishops_same_slot: u8 = 0,
    /// DG:A4F2: both Black castling stamps non-zero.
    black_castling_gone: u8 = 0,
    /// DG:A8D7: the opening.
    phase_opening: u8 = 0,
    /// DG:B522, DG:B5A8: White's and Black's centrality bytes, by square.
    centrality_white: [120]u8 = @splat(0),
    centrality_black: [120]u8 = @splat(0),
    /// DG:B622: bishop and knight against a bare king.
    kbn_vs_king: u8 = 0,
    /// DG:B628, DG:8BBC: Black's and White's king tucked in a corner.
    black_king_tucked: u8 = 0,
    white_king_tucked: u8 = 0,

    // ---- the turn's -----------------------------------------------------------------------
    /// DG:B620: the game ply - 2 when an analysis ends (0EF8:89CD); the ponder test reads it.
    wb620: u16 = 0,
    /// DG:776A: set by the ponder test, cleared by main's top.
    b776a: u8 = 0,
    /// DG:A4C8: the side to move as Setup mode leaves it.
    ba4c8: u8 = 0,

    // ---- written, and read by no ported routine -----------------------------------------
    /// Start-up, the settings, main's top, the turn and New game write these; no ported
    /// routine reads them (docs/arch/60-engine-assembly.md section 10.7.2). Each keeps the
    /// value written, so that the state as an image holds the original's bytes. DG:2605 is
    /// read once, by the settings' level check, and holds the executable's constant.
    b1b8c: u8 = 0,
    w1b8e: u16 = 0,
    w1b90: u16 = 0,
    w1df8: u16 = 0,
    w1e00: u16 = 0,
    w1e34: u16 = 0,
    b22d4: u8 = 0,
    w2500: u16 = 0,
    b2605: u8 = 0,
    w2512: u16 = 0,
    w2514: u16 = 0,
    b2a6a: u8 = 0,
    w2acc: u16 = 0,
    w2ace: u16 = 0,
    w2ad2: u16 = 0,
    b9350: u8 = 0,
    b9d86: u8 = 0,
    wa09a: u16 = 0,
    wa09c: u16 = 0,
    ba38a: u8 = 0,
    ba3f7: u8 = 0,
    ba40f: u8 = 0,
    ba67c: u8 = 0,
    waaf4: u16 = 0,
    wacf2: u16 = 0,
    bafc2: u8 = 0,
    wb4ae: u16 = 0,

    /// DGROUP address of each field.
    pub const dg = .{
        .hash_avail_kb = 0x00E2,
        .xms_ready = 0x9352,
        .tb_signature_count = 0x239A,
        .tb_signatures = 0xA422,
        .book_move_ply = 0x2522,
        .rand_seed = 0x2DC8,
        .book_name = 0x7449,
        .book_off = 0x70E4,
        .setup_board = 0x8C46,
        .setup_ep_square = 0x90B8,
        .game_board = 0x7520,
        .side_ae44 = 0xAE44,
        .setup_side_saved = 0xB42A,
        .oo_copy = 0xA5E6,
        .ooo_copy = 0xA6A4,
        .ba4f3 = 0xA4F3,
        .w2a8e = 0x2A8E,
        .game_over_ply = 0xA6AE,
        .resigned_ply = 0x9D92,
        .predicted = 0xA414,
        .piece_value_2 = 0x14D0,
        .promotion_gain_2 = 0x14EC,
        .style = 0x153E,
        .aggression = 0x2906,
        .custom_piece_values = 0x2922,
        .base_black_pawns = 0x7468,
        .base_pieces = 0xA5E2,
        .passed_count_black = 0x724C,
        .passed_count_white = 0x9D8B,
        .passed_count_both = 0x8CC4,
        .passed_rank_by_file_white = 0xA8E0,
        .passed_pawn_sq_white = 0xA3FE,
        .passed_pawn_sq_black = 0x8CE6,
        .table_7692 = 0x7692,
        .mobility_weights_rest = 0xA080,
        .single_bishops_same_slot = 0xA360,
        .black_castling_gone = 0xA4F2,
        .phase_opening = 0xA8D7,
        .centrality_white = 0xB522,
        .centrality_black = 0xB5A8,
        .kbn_vs_king = 0xB622,
        .black_king_tucked = 0xB628,
        .white_king_tucked = 0x8BBC,
        .saved_setup = 0x776C,
        .saved_setup_tail = 0x77D1,
        .wb620 = 0xB620,
        .b776a = 0x776A,
        .ba4c8 = 0xA4C8,
        .b1b8c = 0x1B8C,
        .w1b8e = 0x1B8E,
        .w1b90 = 0x1B90,
        .w1df8 = 0x1DF8,
        .w1e00 = 0x1E00,
        .w1e34 = 0x1E34,
        .b22d4 = 0x22D4,
        .w2500 = 0x2500,
        .b2605 = 0x2605,
        .w2512 = 0x2512,
        .w2514 = 0x2514,
        .b2a6a = 0x2A6A,
        .w2acc = 0x2ACC,
        .w2ace = 0x2ACE,
        .w2ad2 = 0x2AD2,
        .b9350 = 0x9350,
        .b9d86 = 0x9D86,
        .wa09a = 0xA09A,
        .wa09c = 0xA09C,
        .ba38a = 0xA38A,
        .ba3f7 = 0xA3F7,
        .ba40f = 0xA40F,
        .ba67c = 0xA67C,
        .waaf4 = 0xAAF4,
        .wacf2 = 0xACF2,
        .bafc2 = 0xAFC2,
        .wb4ae = 0xB4AE,
    };
};

/// The root's own variables: one field for each variable main's view (`PrepState`) or the
/// loop's view (`RootState`) declares and no other member holds, main's low page, the
/// irreversible-move flags, the root scores, the level-2 time-control records, and the
/// window of the stack where main and root_search keep the locals their callees write
/// through a pointer.
pub const RootVars = struct {
    // ---- main's low page and the root's stack ---------------------------------------
    /// DG:0000..0061 and DG:0064..00C9: main's low page but for the node's ply ceiling
    /// (DG:0062, `searchnode.State.ply_ceiling`). Holds the ticks to the next second of the
    /// displayed clocks (DG:0058, `TimeState.tick58`), the bytes per hash table (DG:005A, a
    /// dword), the loop limit (DG:0064, `RootState.loop_limit`) and the default ply ceiling
    /// (DG:0066, `RootState.default_ceiling`), and the flags DG:4A + b of the easy-move test
    /// (`rootprep` `lowByte`).
    low_page: [0x62]u8 = @splat(0),
    low_page_rest: [0x66]u8 = @splat(0),
    /// DG:D500..D62F: the window of the stack that holds main's frame (bp D62C) and
    /// root_search's (bp D5A2): the captured piece and its slot make_move returns
    /// ([bp-22h], [bp-30h] of main; [bp-16h], [bp-1Ah] of root_search), the legal-move word
    /// of the node calls ([bp-0Eh] of main, [bp-6] of root_search), the threat evaluators'
    /// counter ([bp-24h] of main), and the easy-move words main reads ([bp-6]..[bp-3]).
    /// Persistent, like the stack it stands for: a search finds what the last one left.
    frame: [0x130]u8 = @splat(0),
    /// DG:FFCA..FFFF: the top of the segment, where the easy-move test's flag DG:4A + b
    /// falls for b from -128 to -75 (`rootprep` 10A9); never written by the engine.
    stack_top: [0x36]u8 = @splat(0),

    // ---- settings and modes -----------------------------------------------------------
    /// DG:03FA: the threat-count bonus for 8 to 31 attacked pieces (its first 8 entries,
    /// DG:03EA, are the node's `standpat_bonus`).
    threat_count_bonus_rest: [24]i16 = @splat(0),
    /// DG:12C6: the hash size requested (KB, dword); DG:12CA: the size set (the total).
    hash_request: i32 = 0,
    hash_setting: i32 = 0,
    /// DG:1480: the single-move control.
    single_move: u16 = 0,
    /// DG:153C: a new game or a menu request.
    w153c: u16 = 0,
    /// DG:1B8B: the clock mode byte. DG:1B9C: the PV display's screen mode. DG:1BAC:
    /// analysis display mode, auto-play of book moves.
    b1b8b: u8 = 0,
    w1b9c: i16 = 0,
    analysis_mode: u8 = 0,
    /// DG:1DFE: Mate in N; DG:1E02: Fixed depth N.
    mate_in: u16 = 0,
    fixed_depth: u16 = 0,
    /// DG:22B4: the PV display's window; DG:22BA: display off.
    w22b4: u16 = 0,
    display_off: u16 = 0,
    /// DG:24F0, DG:24F6: the analysis hook's depth and switch.
    analysis_depth: i16 = 0,
    analysis_hook: u16 = 0,
    /// DG:2502: game-end flag; DG:2508: exclusion-list flag; DG:250A: entries in the
    /// excluded-move list; DG:250C: the [A00A] path's delay count.
    w2502: u16 = 0,
    exclusion_flag: u16 = 0,
    excluded_count: i16 = 0,
    w250c: i16 = 0,
    /// DG:260A: a display variable; DG:2660: the PV display line.
    w260a: u16 = 0,
    w2660: u16 = 0,
    /// DG:291E: Random Limit (style).
    random_limit: u16 = 0,
    /// DG:2A5E: the PV display column per side.
    pv_columns: [2]u16 = .{ 0, 0 },
    /// DG:348E + ply: the irreversible-move flags DG:3490 + game ply (`GameVars.
    /// irreversible`, 196h bytes) and the two bytes below them, which main reads for game
    /// plies 0 and 1 (the hash-table keep test, 0000:07B6-07C4).
    irreversible_area: [2 + 0x196]u8 = @splat(0),
    /// DG:38A0: the move handed to play_best_move (the book's, or the one played): from,
    /// to, flag, the captured piece and its slot (`GameVars.played`; main's view names the
    /// first four, `book_move`).
    played_move: [5]u8 = @splat(0),
    /// DG:70F2: the random term drawn (Random Limit's copy).
    random_value: u16 = 0,
    /// DG:7102: moves to go.
    mtg: i16 = 0,
    /// DG:717C: the side to move after a root move (the side the program does not play).
    opponent_side: u8 = 0,
    /// DG:7184: the last score at the start of this search; DG:7186, DG:77D0: the best
    /// move's captured piece and check flag.
    search_start_score: i16 = 0,
    best_captured: u8 = 0,
    best_check: u8 = 0,
    /// DG:7242: 6 bytes saved and restored with the best move (meaning not determined);
    /// DG:B4A8: their copy during a root fail-high re-search; DG:75C0: the best move then.
    state_7242: [6]u8 = @splat(0),
    saved_7242: [6]u8 = @splat(0),
    saved_best: [4]u8 = @splat(0),
    /// DG:724D: pre-scoring (stop + 10 parked).
    prescoring: u8 = 0,
    /// DG:7328: root in check / game status (`GameVars.status`).
    result_7328: u8 = 0,
    /// DG:73F8: the address of the move play_best_move plays (A36Ch).
    w73f8: u16 = 0,
    /// DG:73FA + 2·side: the move number of the side's next time control.
    next_control: [2]i16 = .{ 0, 0 },
    /// DG:73FE: castling or the phase changed.
    changed_73fe: u8 = 0,
    /// DG:7442: entries in the root list; DG:A518: legal root moves; DG:8CBC: the number of
    /// the root move being searched.
    root_move_count: u16 = 0,
    legal_count: i8 = 0,
    root_move_number: u8 = 0,
    /// DG:75B7: menu depth.
    menu_depth: i8 = 0,
    /// DG:77EC + 4·side: time left, ticks.
    time_left: [2]i32 = .{ 0, 0 },
    /// DG:8BAA.
    w8baa: u16 = 0,
    /// DG:8D06: the base time.
    base: i32 = 0,
    /// DG:8D0A + 2i: the root score of each root-list entry (`GameVars.reply_scores`: the
    /// score of each predicted reply), up to DG:8DD1.
    root_scores: [100]i16 = @splat(0),
    /// DG:8DDE: the side the program plays.
    computer_side: u8 = 0,
    /// DG:90AE: a display request.
    b90ae: u8 = 0,
    /// DG:9312; DG:933C, DG:934E: the reference score and the root score; DG:9351:
    /// "Planning" shown.
    w9312: u16 = 0,
    reference_score: i16 = 0,
    root_score: i16 = 0,
    planning_shown: u8 = 0,
    /// DG:9D8A: the repetition count of the position after the program's move, plus 1.
    b9d8a: u8 = 0,
    /// DG:A274: the level type.
    level: u8 = 0,
    /// DG:A356: the elapsed time at the first root move of this iteration; DG:A35C: the
    /// depth reached; DG:A362: the soft limit.
    iter_start_elapsed: i32 = 0,
    depth_reached: u8 = 0,
    soft: i32 = 0,
    /// DG:A36A: the game ply after the last move played; DG:A36C: the best move (from, to,
    /// flag, score byte): the move that is played.
    wa36a: i16 = 0,
    best_move: [4]u8 = @splat(0),
    /// DG:A38B: the analysis hook's switches.
    a38b: u8 = 0,
    /// DG:A3F5: a root fail-high re-search pending; DG:A3F6: the last move before the
    /// control; DG:A3FA: the reply list is valid (the computer has moved).
    fail_high_pending: u8 = 0,
    last_before_control: u8 = 0,
    wa3fa: u16 = 0,
    /// DG:A416: the predicted reply (from, to).
    predicted_reply: u16 = 0,
    /// DG:A4F4: correspondence: root moves searched in full.
    corr_moves: i16 = 0,
    /// DG:A5EE: the M-Chess book off; DG:A5F4: a display switch.
    wa5ee: u16 = 0,
    a5f4: u8 = 0,
    /// DG:A6A0, DG:A6A1: display, book and learning flags.
    a6a0: u8 = 0,
    a6a1: u8 = 0,
    /// DG:A84A: the move number.
    move_number: i16 = 0,
    /// DG:A8C6: the level's preset.
    preset: u8 = 0,
    /// DG:A8DA: the score of the last iteration that returned above its lower bound.
    last_score: i16 = 0,
    /// DG:A8E8: the clock at the start of thinking.
    start_clock: u32 = 0,
    /// DG:AB9E: a display countdown.
    bab9e: u8 = 0,
    /// DG:AE36: a root fail high at a later move.
    later_fail_high: u8 = 0,
    /// DG:AFC4: the tablebase threshold (the last score).
    tb_threshold: u16 = 0,
    /// DG:B42B: the PV length.
    pv_length: i8 = 0,
    /// DG:B4C2 + 14·side: the level-2 time-control records (`TimeState.tc`; main's view
    /// names each record's last counted move, DG:B4CE and B4DC).
    tc: [2]tbud.ControlRecord = .{ .{}, .{} },
    /// DG:B4DE: the game ply at the start of the search.
    search_ply: i16 = 0,
    /// DG:B4F6: the ponder bonus move.
    ponder_bonus_move: u16 = 0,
    /// DG:B59A: the fail-high limit.
    fail_high: i32 = 0,
    /// DG:B65C: pv[0] at the first root move of iteration 2.
    wb65c: u16 = 0,

    /// DGROUP address of each field.
    pub const dg = .{
        .low_page = 0x0000,
        .low_page_rest = 0x0064,
        .frame = 0xD500,
        .stack_top = 0xFFCA,
        .threat_count_bonus_rest = 0x03FA,
        .hash_request = 0x12C6,
        .hash_setting = 0x12CA,
        .single_move = 0x1480,
        .w153c = 0x153C,
        .b1b8b = 0x1B8B,
        .w1b9c = 0x1B9C,
        .analysis_mode = 0x1BAC,
        .mate_in = 0x1DFE,
        .fixed_depth = 0x1E02,
        .w22b4 = 0x22B4,
        .display_off = 0x22BA,
        .analysis_depth = 0x24F0,
        .analysis_hook = 0x24F6,
        .w2502 = 0x2502,
        .exclusion_flag = 0x2508,
        .excluded_count = 0x250A,
        .w250c = 0x250C,
        .w260a = 0x260A,
        .w2660 = 0x2660,
        .random_limit = 0x291E,
        .pv_columns = 0x2A5E,
        .irreversible_area = 0x348E,
        .played_move = 0x38A0,
        .random_value = 0x70F2,
        .mtg = 0x7102,
        .opponent_side = 0x717C,
        .search_start_score = 0x7184,
        .best_captured = 0x7186,
        .best_check = 0x77D0,
        .state_7242 = 0x7242,
        .saved_7242 = 0xB4A8,
        .saved_best = 0x75C0,
        .prescoring = 0x724D,
        .result_7328 = 0x7328,
        .w73f8 = 0x73F8,
        .next_control = 0x73FA,
        .changed_73fe = 0x73FE,
        .root_move_count = 0x7442,
        .legal_count = 0xA518,
        .root_move_number = 0x8CBC,
        .menu_depth = 0x75B7,
        .time_left = 0x77EC,
        .w8baa = 0x8BAA,
        .base = 0x8D06,
        .root_scores = 0x8D0A,
        .computer_side = 0x8DDE,
        .b90ae = 0x90AE,
        .w9312 = 0x9312,
        .reference_score = 0x933C,
        .root_score = 0x934E,
        .planning_shown = 0x9351,
        .b9d8a = 0x9D8A,
        .level = 0xA274,
        .iter_start_elapsed = 0xA356,
        .depth_reached = 0xA35C,
        .soft = 0xA362,
        .wa36a = 0xA36A,
        .best_move = 0xA36C,
        .a38b = 0xA38B,
        .fail_high_pending = 0xA3F5,
        .last_before_control = 0xA3F6,
        .wa3fa = 0xA3FA,
        .predicted_reply = 0xA416,
        .corr_moves = 0xA4F4,
        .wa5ee = 0xA5EE,
        .a5f4 = 0xA5F4,
        .a6a0 = 0xA6A0,
        .a6a1 = 0xA6A1,
        .move_number = 0xA84A,
        .preset = 0xA8C6,
        .last_score = 0xA8DA,
        .start_clock = 0xA8E8,
        .bab9e = 0xAB9E,
        .later_fail_high = 0xAE36,
        .tb_threshold = 0xAFC4,
        .pv_length = 0xB42B,
        .tc = 0xB4C2,
        .search_ply = 0xB4DE,
        .ponder_bonus_move = 0xB4F6,
        .fail_high = 0xB59A,
        .wb65c = 0xB65C,
    };
};
