//! Main before the iteration loop: from "it is the program's turn" (0000:0526, or 0000:055B
//! for a ponder search) to the first iteration (0000:146F), or to one of the ends that play
//! or stop without a search. This is where the search is set up: the start of the move's
//! clock and moves to go, the book, prepare_eval, the hash tables, the root moves and their
//! legality test and pre-scoring (the static evaluation of each root move, or a search of
//! the reply when it gives check), the tablebase choice at the root, the decision to play
//! without a search, the time budget, the first sort of the root list and the variables
//! the iteration loop starts from. Also the root's repetition count (2B9F:402A), a leaf
//! routine ported here for real.
//!
//! Specification: docs/arch/33-root-preparation.md, whose executable form is
//! tools/research/rootprep/rootprep.py (matched the original by record and replay, §6 of
//! that document). Test: src/rootprep_test.zig, which replays invocations recorded from the
//! original (tests/golden/rootprep/, tools/port/gen_rootprep_vectors.py).
//!
//! **The callees are an interface**, as in src/rootsearch.zig: everything main calls that
//! is not ported here goes through `env.call(site, callee, args)` (args are the original's
//! stack words; a callee's result is AX, or DX:AX). Values main reads outside DGROUP go
//! through `env.far(site, segvar, offset)` (a byte of the far segment whose selector is the
//! DGROUP word `segvar`: the game-record tables), `env.clock(site)` (the tick counter, read
//! through the far pointer DG:B4AE), and its writes outside DGROUP through
//! `env.farWrite(site, segvar, offset, value)`. Bytes a callee writes into main's frame
//! (make_move's captured piece) are read with `env.local(addr)`, `addr` being the
//! original's stack address given by `bp`. The C run-time calls (memcpy, the long
//! division), set_prescore_margins (0000:6BE4), set_search_margins (0000:6BF8) and
//! clear_move_marks (1E9D:54CE) are done here.
//!
//! **Reproduced, not corrected** (undecided entries of docs/DEVIATIONS.md, or new): the
//! 4/5 scaling in 16 bits (DEV-031); the White-to-move static pre-score adding the
//! threat-count bonus where the Black-to-move one subtracts it (0C63 against 0B0F); the
//! stale [bp-6]/[bp-4] read when there are no root moves (10A9); playing the stale best
//! move when every root move fails the legality test (0FEA). See the document, "Suspected
//! bugs".

const std = @import("std");
const pos = @import("position.zig");
const sn = @import("searchnode.zig");
const evm = @import("evalvars.zig");
const et = @import("evalthreats.zig");
const see = @import("see.zig");
const leaf = @import("leaf.zig");
const rvm = @import("rootvars.zig");

/// Number of root-list entries (the ply-1 move list at DG:3BC4, 400 bytes).
pub const max_root_moves = 100;

/// The move-mark table DG:781A that clear_move_marks (1E9D:54CE) clears: 0x137E bytes.
pub const marks_len = 0x137E;

/// The state main reads and writes before the loop, by DGROUP address. Fields that the
/// callees also read or write are here because main reads or writes them too.
///
/// **Every field is a pointer** to its variable's one home (Stage B step 7, stage 3c-1, and
/// step 8, stage 7): a variable or table whose byte a struct of the node domain holds, to
/// that byte of the struct (`bindDomain`); every other one, main's own variables and
/// tables, to its field of `rootvars.RootVars` or `rootvars.ProgramVars` (`bindRoot`), the
/// members that are their homes. Nothing is copied around main's callees: main and every
/// callee read and write each variable where the original does. A `PrepState` must be bound
/// by both before main runs. A multi-byte pointer to main's own variables is `align(1)`.
pub const PrepState = struct {
    // ---- low page ----------------------------------------------------------------------
    /// DG:0000–00C9: holds the loop limit DG:64, the default ply ceiling DG:66 and the
    /// flags DG:4A + b of the easy-move test (b a signed table byte), which can reach any
    /// byte here: DG:0000-0061 (`low_page`) and DG:0064-00C9 (`low_page_rest`). Its bytes
    /// DG:62-63 are the node's ply ceiling, read through `ply_ceiling` (`lowByte`).
    low_page: *[0x62]u8 = undefined,
    low_page_rest: *[0x66]u8 = undefined,
    /// DG:0062: the node's ply ceiling (`searchnode.State.ply_ceiling`), inside the low
    /// page; main never writes it.
    ply_ceiling: *i16 = undefined,
    /// DG:0154, DG:0168, DG:0172, DG:0186: four entries of the passed-pawn rank tables
    /// (`EvalVars.passer_rank_tables`) that set_prescore_margins / set_search_margins write.
    margin_154: *u16 = undefined,
    margin_168: *u16 = undefined,
    margin_172: *u16 = undefined,
    margin_186: *u16 = undefined,
    /// DG:03EA: the threat-count bonus by number of attacked pieces (word table, 32
    /// entries): the first 8 are the node's stand-pat bonus (`searchnode.State.
    /// standpat_bonus`), the other 24 at DG:03FA main's view. Read with `threatBonus`.
    threat_count_bonus: *[8]i16 = undefined,
    threat_count_bonus_rest: *align(1) [24]i16 = undefined,
    // ---- settings and modes ------------------------------------------------------------------
    /// DG:12C6: hash size requested (KB, dword); DG:12CA: the size set.
    hash_request: *align(1) i32 = undefined,
    hash_setting: *align(1) i32 = undefined,
    /// DG:1480: single-move control (timebudget).
    single_move: *align(1) u16 = undefined,
    /// DG:153C: a menu request that leaves main's search path (exit to 013B).
    w153c: *align(1) u16 = undefined,
    /// DG:1548: style flag (0 = Normal; the random term needs it 0).
    style_flag: *u16 = undefined,
    /// DG:154A: men on the board (signed byte).
    men: *i8 = undefined,
    /// DG:1B8B: clock mode byte.
    b1b8b: *u8 = undefined,
    /// DG:1BAC: analysis display mode.
    analysis_mode: *u8 = undefined,
    /// DG:1DFE: Mate in N; DG:1E02: Fixed depth N.
    mate_in: *align(1) u16 = undefined,
    fixed_depth: *align(1) u16 = undefined,
    /// DG:239C: tablebase settings (bit 3: use at the root).
    tb_settings: *u8 = undefined,
    /// DG:2502, DG:2508, DG:250C, DG:260A, DG:2660: game-end flag, exclusion-list flag,
    /// the [A00A] path's delay count, a display variable, the PV display line.
    w2502: *align(1) u16 = undefined,
    exclusion_flag: *align(1) u16 = undefined,
    w250c: *align(1) i16 = undefined,
    w260a: *align(1) u16 = undefined,
    w2660: *align(1) u16 = undefined,
    /// DG:291E: Random Limit (style); DG:70F2: its copy, the divisor.
    random_limit: *align(1) u16 = undefined,
    random_divisor: *align(1) u16 = undefined,
    /// DG:2A5E: PV display column per side.
    pv_columns: *align(1) [2]u16 = undefined,
    /// DG:348E + ply, DG:348F + ply: the irreversible-move flags of game plies ply - 2 and
    /// ply - 1 (DG:3490 + ply - 2), read for the hash-table keep test (0000:07B6-07C4) at
    /// game plies 0..405: 348E..3625, the two bytes below DG:3490 and the whole 196h-byte
    /// table (docs/arch/34-game-move-path.md, "How long a game can be").
    irreversible_area: *[2 + 0x196]u8 = undefined,
    // ---- game ------------------------------------------------------------------------------
    /// DG:3626: the move that undoes the computer's last move (from the game record);
    /// DG:3628: the same for the opponent.
    reverse_move: *u16 = undefined,
    reverse_move_opp: *u16 = undefined,
    /// DG:8BC0: mask applied to `reverse_move`.
    reverse_mask: *u16 = undefined,
    /// DG:3676: pondering.
    pondering: *u8 = undefined,
    /// DG:717C: the side to move after a root move; DG:8DDE: the computer's side; DG:9EEC:
    /// the side whose clock runs.
    opponent_side: *u8 = undefined,
    computer_side: *u8 = undefined,
    clock_side: *u8 = undefined,
    /// DG:9FC8: game ply; DG:9FBC: book-exit ply; DG:A36A; DG:B4DE: game ply at the start.
    game_ply: *i16 = undefined,
    book_exit_ply: *align(1) i16 = undefined,
    wa36a: *align(1) i16 = undefined,
    search_ply: *align(1) i16 = undefined,
    /// DG:A84A: move number.
    move_number: *align(1) i16 = undefined,
    /// DG:9FCF: analysis; DG:A00A: auto-play target ply; DG:A00D; DG:A00E: ponder miss.
    analysis: *u8 = undefined,
    wa00a: *align(1) i16 = undefined,
    ba00d: *u8 = undefined,
    wa00e: *align(1) u16 = undefined,
    /// DG:A3FA: the computer has moved; DG:8C30.
    wa3fa: *align(1) u16 = undefined,
    w8c30: *align(1) u16 = undefined,
    /// DG:73FE: castling or phase changed; DG:8BAA.
    changed_73fe: *u8 = undefined,
    w8baa: *align(1) u16 = undefined,
    /// DG:7328: root in check / game result (8 stalemate, 9 mate).
    result_7328: *u8 = undefined,
    /// DG:9EC9 and DG:8C07 (root in check), from the game record.
    b9ec9: *u8 = undefined,
    root_in_check: *u8 = undefined,
    /// DG:8C08: the move just made gives check; DG:9ECA: en-passant square at ply 2.
    gives_check: *u8 = undefined,
    ep_ply2: *u8 = undefined,
    // ---- level and time ------------------------------------------------------------------------
    /// DG:A274: level type; DG:A8C6: preset.
    level: *i8 = undefined,
    preset: *u8 = undefined,
    /// DG:7102: moves to go.
    mtg: *align(1) i16 = undefined,
    /// DG:73FA: next control per side; DG:B4CE, DG:B4DC: the last counted move of each
    /// side's level-2 record.
    next_control: *align(1) [2]i16 = undefined,
    tc_last_white: *align(1) i16 = undefined,
    tc_last_black: *align(1) i16 = undefined,
    /// DG:A8E8: clock at the start of thinking.
    start_clock: *align(1) u32 = undefined,
    /// DG:8D06, DG:9DB8: base, hard.
    base: *align(1) i32 = undefined,
    hard: *align(1) i32 = undefined,
    /// DG:A362: soft. It lies, as the depth reached, the two fail-high bytes and the
    /// computer-has-moved word do, inside a bishop activity table of `EvalVars` that the
    /// domain loads once a search and never stores: main's view.
    soft: *align(1) i32 = undefined,
    /// DG:A3F5, DG:AE36, DG:A3F6, DG:A22C, DG:A05C.
    fail_high_pending: *u8 = undefined,
    later_fail_high: *u8 = undefined,
    last_before_control: *u8 = undefined,
    clear_best: *u8 = undefined,
    ext_iteration: *u8 = undefined,
    /// DG:90AE: a display request.
    b90ae: *u8 = undefined,
    // ---- stop and keyboard ---------------------------------------------------------------------
    /// DG:A4FA: stop; DG:724D: pre-scoring (stop + 10 parked); DG:75B6: poll requests;
    /// DG:75B7: menu depth.
    stop: *u8 = undefined,
    prescoring: *u8 = undefined,
    poll_requests: *u8 = undefined,
    menu_depth: *i8 = undefined,
    // ---- position ------------------------------------------------------------------------------
    /// DG:9EF6: the search board.
    board: *[120]u8 = undefined,
    /// DG:8C57: copy of the root position (board squares 21..98).
    root_copy: *[0x4E]u8 = undefined,
    /// DG:A041, DG:A051: the king slots of the White and Black piece lists.
    white_king: *u8 = undefined,
    black_king: *u8 = undefined,
    /// DG:8FE4: the leaf attack map (non-zero where the side that just moved... is attacked).
    attack_map: *[120]u8 = undefined,
    /// DG:8CCC, DG:8CD2: the hash keys (main and pawn, 6 bytes each); DG:9DC4: the root
    /// key saved.
    hash_key: *u48 = undefined,
    pawn_hash_key: *u48 = undefined,
    root_key: *u48 = undefined,
    /// DG:7182, DG:90B6, DG:369A: the square sums, restored after each root move.
    w7182: *u16 = undefined,
    w90b6: *u16 = undefined,
    w369a: *u16 = undefined,
    /// DG:A35E, DG:A420: material balance and total; DG:A05A, DG:A35A: their root copies.
    material_balance: *u16 = undefined,
    material_total: *u16 = undefined,
    root_balance: *u16 = undefined,
    root_total: *u16 = undefined,
    /// DG:931A, DG:931B: piece counts; DG:A6C6: both non-zero.
    white_pieces: *u8 = undefined,
    black_pieces: *u8 = undefined,
    both_have_pieces: *u8 = undefined,
    /// DG:AE38, DG:AE3A: non-pawn material of White and Black.
    white_nonpawn: *i16 = undefined,
    black_nonpawn: *i16 = undefined,
    /// DG:A5F5: passed-threat bits (static_eval); DG:A8DE: static eval only.
    passed_threat: *u8 = undefined,
    static_only: *u8 = undefined,
    // ---- root list, scores, PV --------------------------------------------------------------------
    /// DG:3BC4: the root moves; DG:8D0A: their scores; DG:7442: entries; DG:A518: legal.
    root_moves: *[max_root_moves][4]u8 = undefined,
    root_scores: *[max_root_moves]i16 = undefined,
    root_move_count: *align(1) u16 = undefined,
    legal_count: *i8 = undefined,
    /// DG:A36C: best move; DG:7186, DG:77D0: its captured piece and check flag.
    best_move: *[4]u8 = undefined,
    best_captured: *u8 = undefined,
    best_check: *u8 = undefined,
    /// DG:38A0: the book move.
    book_move: *[4]u8 = undefined,
    /// DG:A038: the move with flags.
    current_move: *align(1) u16 = undefined,
    /// DG:93B0: the PV (37 words); DG:B42B: its length; DG:A35C: depth reached.
    pv: *[37]u16 = undefined,
    pv_length: *i8 = undefined,
    depth_reached: *i8 = undefined,
    /// DG:A416: predicted reply; DG:B4F6: the ponder bonus move; DG:B65C.
    predicted_reply: *align(1) u16 = undefined,
    ponder_bonus_move: *align(1) u16 = undefined,
    wb65c: *align(1) u16 = undefined,
    /// DG:3790: PV move to try first at ply p; DG:741E: cleared per ply.
    pv_follow: *[36]u16 = undefined,
    b741e: *[36]u8 = undefined,
    /// DG:A8DA, DG:934E, DG:933C, DG:7184: last score, root score, reference, start score.
    last_score: *align(1) i16 = undefined,
    root_score: *align(1) i16 = undefined,
    reference_score: *align(1) i16 = undefined,
    search_start_score: *align(1) i16 = undefined,
    /// DG:A418, DG:8DE8, DG:AFC4: the last score from White's view, Black's, and the TB
    /// threshold.
    score_white_view: *u16 = undefined,
    score_black_view: *u16 = undefined,
    tb_threshold: *align(1) u16 = undefined,
    /// DG:7466: the tablebase score.
    tb_score: *u16 = undefined,
    /// DG:9FD0: search over.
    search_over: *u8 = undefined,
    /// DG:744E, DG:A3F4: depth and iteration; DG:A272, DG:9356, DG:A5EC: ply limits.
    depth: *i8 = undefined,
    iteration: *u8 = undefined,
    ply_limit2: *u16 = undefined,
    ply_limit4: *u16 = undefined,
    ply_limit6: *u16 = undefined,
    /// DG:740A: node counter (dword); DG:9312.
    nodes: *u32 = undefined,
    w9312: *align(1) u16 = undefined,
    /// DG:9D8A, DG:A40E, DG:9351: cleared before pre-scoring (A40E set around a threat call).
    b9d8a: *u8 = undefined,
    ba40e: *u8 = undefined,
    planning_shown: *u8 = undefined,
    // ---- display ----------------------------------------------------------------------------------
    /// DG:9EB6, DG:A6A0: display and book flags; DG:A5EE, DG:A002: book switches; DG:73F8;
    /// DG:AB9E: a display countdown.
    b9eb6: *u8 = undefined,
    a6a0: *u8 = undefined,
    wa5ee: *align(1) u16 = undefined,
    wa002: *align(1) u16 = undefined,
    w73f8: *align(1) u16 = undefined,
    bab9e: *u8 = undefined,
};

/// The routines called through the interface, by the original's address.
pub const Callee = enum {
    screen_8536, // 38C0:8536
    reset_move_time_used, // 1E9D:7E8A
    moves_to_go, // 0000:8B7E
    display_8454, // 38C0:8454
    add_control_time, // 1E9D:6F48
    clocks_run, // 1E9D:6AE8
    poll, // 1E9D:7514
    delay, // 1E9D:562A
    play_best_move, // 38C0:01E0
    book_probe, // 4793:621E
    book_exit_display_1, // 38C0:D478
    book_exit_display_2, // 38C0:88C6
    prepare_eval, // 0000:9582
    hash_resize, // 0000:6C3A
    hash_clear, // 0000:88CC
    hash_seed_learning, // 0000:89D0
    gen_evasions, // 38C0:E260
    gen_all_moves, // 1E9D:3938
    square_sums, // 0000:678A
    hash_key, // 4793:3EA2
    make, // 1E9D:000C
    unmake, // 1E9D:0960
    tb_probe, // 2B9F:BB76
    attack_map_white, // 2B9F:40A8
    attack_map_black, // 2B9F:42DA
    repetition, // 2B9F:402A (repetitionCount below)
    has_legal_move, // 2B9F:458A
    node_white, // 0000:3AC6
    node_black, // 0000:5036
    pawn_eval_wtm, // 0EF8:89DC
    pawn_eval_btm, // 0EF8:8F82
    static_eval, // 2B9F:000E
    hanging_white, // 2B9F:5534
    hanging_black, // 2B9F:4BFE
    pieces_and_kings, // 0EF8:0006
    activity_white, // 1E9D:16E4
    activity_black, // 1E9D:1E30
    endgame_king_white, // 1E9D:3416
    endgame_king_black, // 1E9D:35FB
    count_attacked_wtm, // 1E9D:CE3E
    count_attacked_btm, // 1E9D:CC4E
    threats_white, // 0EF8:A026
    threats_black, // 0EF8:CD20
    rand, // 4793:89D8
    pv_screen_line, // 38C0:8898
    show_move, // 38C0:948A
    show_score, // 38C0:9BEA
    clear_excluded, // 0000:6F2E
    set_time_budget, // 0000:8C3E
    game_over_display, // 38C0:570A
    end_analysis, // 2B9F:6614
    display_7144, // 1E9D:7144
    display_72b4, // 1E9D:72B4
    positions_display, // 38C0:9E7C
    sort_root_moves, // 0000:668E
    display_a0b0, // 38C0:A0B0
};

/// Where main goes on.
pub const Exit = enum(u16) {
    /// 0000:146F: the iteration loop.
    iteration_loop = 0x146F,
    /// 0000:1618: the conclusion; the move [A36C] is played without (more) search.
    conclude = 0x1618,
    /// 0000:023C: the main loop head (book move played, game over, the [A00A] path).
    main_loop = 0x023C,
    /// 0000:013B: a menu request ([153C]).
    menu = 0x013B,
};

/// The two entries.
pub const Entry = enum(u16) { own = 0x0526, ponder = 0x055B };

inline fn w(x: anytype) u16 {
    return @bitCast(@as(i16, @intCast(x)));
}

inline fn r16(x: u32) i16 {
    return @bitCast(@as(u16, @truncate(x)));
}

/// 0CD9 / 0D04: score·4/5 as `shl ax,2; cwd; idiv 5`: the product is taken in 16 bits, so
/// it wraps for |si| > 8191 (DEV-031, reproduced).
pub fn fourFifths(si: i16) i16 {
    return fourFifthsFixes(pos.Fixes.original, si);
}

/// `fourFifths` under `fixes`. The original (0CD9-0CE4, 0D04-0D0F) shifts the score left
/// by 2 in AX and only then sign-extends it into DX:AX (`cwd`) for the 32-bit division,
/// so the product wraps in 16 bits: 19974 becomes 2872, not 15979 (DEV-031). The `cwd`
/// and `idiv` show that the signed quotient score·4/5 was meant; corrected
/// (`dev031_scaling_overflow`), the product is taken in 32 bits. The quotient, truncated
/// towards zero as `idiv` does, always fits 16 bits.
pub fn fourFifthsFixes(comptime fixes: pos.Fixes, si: i16) i16 {
    if (fixes.dev031_scaling_overflow) return @intCast(@divTrunc(@as(i32, si) * 4, 5));
    const p: i16 = @bitCast(@as(u16, @bitCast(si)) << 2); // shl: wraps
    return @divTrunc(p, 5);
}

/// Port of set_prescore_margins (0000:6BE4): DG:154 = DG:172 = 70, DG:168 = DG:186 = 100.
pub fn setPrescoreMargins(st: *PrepState) void {
    st.margin_154.* = 70;
    st.margin_172.* = 70;
    st.margin_168.* = 100;
    st.margin_186.* = 100;
}

/// Port of set_search_margins (0000:6BF8): DG:154 = DG:172 = 200, DG:168 = DG:186 = 720.
pub fn setSearchMargins(st: *PrepState) void {
    st.margin_154.* = 200;
    st.margin_172.* = 200;
    st.margin_168.* = 720;
    st.margin_186.* = 720;
}

/// The DGROUP address of each `PrepState` field but the tables (the layout its replay test
/// proves, src/rootprep_test.zig).
pub const layout = [_]struct { []const u8, u16 }{
    .{ "ply_ceiling", 0x0062 },        .{ "margin_154", 0x0154 },
    .{ "margin_168", 0x0168 },         .{ "threat_count_bonus_rest", 0x03FA },
    .{ "margin_172", 0x0172 },         .{ "margin_186", 0x0186 },
    .{ "threat_count_bonus", 0x03EA }, .{ "hash_request", 0x12C6 },
    .{ "hash_setting", 0x12CA },       .{ "single_move", 0x1480 },
    .{ "w153c", 0x153C },              .{ "style_flag", 0x1548 },
    .{ "men", 0x154A },                .{ "b1b8b", 0x1B8B },
    .{ "analysis_mode", 0x1BAC },      .{ "mate_in", 0x1DFE },
    .{ "fixed_depth", 0x1E02 },        .{ "tb_settings", 0x239C },
    .{ "w2502", 0x2502 },              .{ "exclusion_flag", 0x2508 },
    .{ "w250c", 0x250C },              .{ "w260a", 0x260A },
    .{ "w2660", 0x2660 },              .{ "random_limit", 0x291E },
    .{ "random_divisor", 0x70F2 },     .{ "pv_columns", 0x2A5E },
    .{ "reverse_move", 0x3626 },       .{ "reverse_move_opp", 0x3628 },
    .{ "reverse_mask", 0x8BC0 },       .{ "pondering", 0x3676 },
    .{ "opponent_side", 0x717C },      .{ "computer_side", 0x8DDE },
    .{ "clock_side", 0x9EEC },         .{ "game_ply", 0x9FC8 },
    .{ "book_exit_ply", 0x9FBC },      .{ "wa36a", 0xA36A },
    .{ "search_ply", 0xB4DE },         .{ "move_number", 0xA84A },
    .{ "analysis", 0x9FCF },           .{ "wa00a", 0xA00A },
    .{ "ba00d", 0xA00D },              .{ "wa00e", 0xA00E },
    .{ "wa3fa", 0xA3FA },              .{ "w8c30", 0x8C30 },
    .{ "changed_73fe", 0x73FE },       .{ "w8baa", 0x8BAA },
    .{ "result_7328", 0x7328 },        .{ "b9ec9", 0x9EC9 },
    .{ "root_in_check", 0x8C07 },      .{ "gives_check", 0x8C08 },
    .{ "ep_ply2", 0x9ECA },            .{ "level", 0xA274 },
    .{ "preset", 0xA8C6 },             .{ "mtg", 0x7102 },
    .{ "next_control", 0x73FA },       .{ "tc_last_white", 0xB4CE },
    .{ "tc_last_black", 0xB4DC },      .{ "start_clock", 0xA8E8 },
    .{ "base", 0x8D06 },               .{ "hard", 0x9DB8 },
    .{ "soft", 0xA362 },               .{ "fail_high_pending", 0xA3F5 },
    .{ "later_fail_high", 0xAE36 },    .{ "last_before_control", 0xA3F6 },
    .{ "clear_best", 0xA22C },         .{ "ext_iteration", 0xA05C },
    .{ "b90ae", 0x90AE },              .{ "stop", 0xA4FA },
    .{ "prescoring", 0x724D },         .{ "poll_requests", 0x75B6 },
    .{ "menu_depth", 0x75B7 },         .{ "white_king", 0xA041 },
    .{ "black_king", 0xA051 },         .{ "hash_key", 0x8CCC },
    .{ "pawn_hash_key", 0x8CD2 },      .{ "root_key", 0x9DC4 },
    .{ "w7182", 0x7182 },              .{ "w90b6", 0x90B6 },
    .{ "w369a", 0x369A },              .{ "material_balance", 0xA35E },
    .{ "material_total", 0xA420 },     .{ "root_balance", 0xA05A },
    .{ "root_total", 0xA35A },         .{ "white_pieces", 0x931A },
    .{ "black_pieces", 0x931B },       .{ "both_have_pieces", 0xA6C6 },
    .{ "white_nonpawn", 0xAE38 },      .{ "black_nonpawn", 0xAE3A },
    .{ "passed_threat", 0xA5F5 },      .{ "static_only", 0xA8DE },
    .{ "root_move_count", 0x7442 },    .{ "legal_count", 0xA518 },
    .{ "best_move", 0xA36C },          .{ "best_captured", 0x7186 },
    .{ "best_check", 0x77D0 },         .{ "book_move", 0x38A0 },
    .{ "current_move", 0xA038 },       .{ "pv_length", 0xB42B },
    .{ "depth_reached", 0xA35C },      .{ "predicted_reply", 0xA416 },
    .{ "ponder_bonus_move", 0xB4F6 },  .{ "wb65c", 0xB65C },
    .{ "b741e", 0x741E },              .{ "last_score", 0xA8DA },
    .{ "root_score", 0x934E },         .{ "reference_score", 0x933C },
    .{ "search_start_score", 0x7184 }, .{ "score_white_view", 0xA418 },
    .{ "score_black_view", 0x8DE8 },   .{ "tb_threshold", 0xAFC4 },
    .{ "tb_score", 0x7466 },           .{ "search_over", 0x9FD0 },
    .{ "depth", 0x744E },              .{ "iteration", 0xA3F4 },
    .{ "ply_limit2", 0xA272 },         .{ "ply_limit4", 0x9356 },
    .{ "ply_limit6", 0xA5EC },         .{ "nodes", 0x740A },
    .{ "w9312", 0x9312 },              .{ "b9d8a", 0x9D8A },
    .{ "ba40e", 0xA40E },              .{ "planning_shown", 0x9351 },
    .{ "b9eb6", 0x9EB6 },              .{ "a6a0", 0xA6A0 },
    .{ "wa5ee", 0xA5EE },              .{ "wa002", 0xA002 },
    .{ "w73f8", 0x73F8 },              .{ "bab9e", 0xAB9E },
};

/// The DGROUP address of each of `PrepState`'s tables.
pub const tables = [_]struct { []const u8, u16 }{
    .{ "low_page", 0x0000 },          .{ "low_page_rest", 0x0064 },
    .{ "irreversible_area", 0x348E }, .{ "root_copy", 0x8C57 },
    .{ "root_scores", 0x8D0A },       .{ "board", 0x9EF6 },
    .{ "attack_map", 0x8FE4 },        .{ "root_moves", 0x3BC4 },
    .{ "pv", 0x93B0 },                .{ "pv_follow", 0x3790 },
};

/// Points every field of `st` whose bytes no member of the node domain holds at its one
/// home (Stage B step 8, stage 7): main's own variables and tables, in `RootVars` (the
/// variables main's or the loop's view declares, the low page, the irreversible-move area,
/// the root scores) and `ProgramVars` (the root copy DG:8C57, squares 21..98 of the set-up
/// board), by address (`rootvars.bindView`). With `bindDomain` for the rest, every field is
/// a pointer to its byte's one home: main reads and writes each variable where the original
/// does, and nothing is copied around its callees.
pub fn bindRoot(st: *PrepState, rv: *rvm.RootVars, pg: *rvm.ProgramVars) void {
    rvm.bindView(PrepState, layout ++ tables, st, rv, pg);
}

/// Points `st`'s fields whose bytes the node domain's structs hold at those bytes (Stage B
/// step 7, stage 3c-1), by the rule stage 3b used for the loop's view (src/rootsearch.zig
/// `bindDomain`): every byte of the view that a struct of the domain holds and stores at
/// `exit` is reached in that struct, so that while main runs inside the domain no byte has
/// two homes. The node's `State` holds the ply ceiling (0062), the first 8 threat-count
/// bonuses (03EA), the tablebase setting and score (239C, 7466), the stop flag (A4FA), the
/// poll requests (75B6), the root material copies (A05A, A35A), both-have-pieces (A6C6),
/// the extensions (741E), the scores from each side's view (A418, 8DE8), the depth (744E),
/// the node count (740A), and the tables of the root moves (3BC4, the ply-1 move list), the
/// PV row of ply 1 (93B0) and the PV moves to follow (3790, the killers); `Position` the
/// board (9EF6), the men (154A), the quiet moves of plies 0 and 1 and the reversible-move
/// word of ply 1 (3626, 3628, 8BC0), past their rooms pondering (3676), the clock side
/// (9EEC) and 8C30, the game ply (9FC8), the check and en-passant bytes of plies 1 and 2
/// (8C07, 8C08, 9EC9, 9ECA), the kings (A041, A051), the keys (8CCC, 8CD2), the sums and
/// material (7182, A35E, A420, 931A, 931B, AE38, AE3A); `EvalVars` the four margins of
/// the passer rank tables (0154, 0168, 0172, 0186), the style flag (1548), the hard limit
/// (9DB8, in `ply_flag`), the pawn square sums (90B6, 369A), the passed-threat bits (A5F5)
/// and the draw flag (A8DE); `ThreatVars` the book-exit ply, analysis and search over
/// (9FBC, 9FCF, 9FD0, in `board_after`), the easy-move flag (A22C), A40E, the iteration
/// (A3F4) and the ply limits (A272, 9356, A5EC); `see.Scratch` A002, A00A, A00D, A00E,
/// the move being searched (A038) and the fail-low iteration (A05C), in `attackers`;
/// `LeafVars` the leaf map (8FE4), the root key (9DC4, `key_history[1]`) and 9EB6 (in
/// `key_history[41]`). The root copy (8C57), the root scores (8D0A), the irreversible-move
/// area (348E) and the rest of the low page are `RootVars`' and `ProgramVars`' (`bindRoot`).
pub fn bindDomain(st: *PrepState, state: *sn.State, p: *pos.Position, ev: *evm.EvalVars, tv: *et.ThreatVars, s: *see.Scratch, lv: *leaf.LeafVars) void {
    st.ply_ceiling = &state.ply_ceiling;
    st.threat_count_bonus = &state.standpat_bonus;
    st.tb_settings = @ptrCast(&state.tb_setting);
    st.tb_score = @ptrCast(&state.tb_score);
    st.stop = &state.stop;
    st.poll_requests = &state.poll_pending;
    st.root_balance = @ptrCast(&state.root_material_balance);
    st.root_total = @ptrCast(&state.root_material_total);
    st.both_have_pieces = &state.both_had_pieces;
    st.b741e = state.extension[0..36];
    st.score_white_view = @ptrCast(&state.prev_score_white);
    st.score_black_view = @ptrCast(&state.prev_score_black);
    st.depth = &state.horizon;
    st.nodes = &state.node_count;
    st.root_moves = @ptrCast(&state.move_list[1]);
    st.pv = &state.pv[1];
    st.pv_follow = state.killer[0..36];
    st.board = &p.board;
    st.men = @ptrCast(&p.men);
    st.reverse_move = &p.quiet_move_by_ply[0];
    st.reverse_move_opp = &p.quiet_move_by_ply[1];
    st.reverse_mask = &p.reversible_by_ply[1];
    st.pondering = @ptrCast(&p.quiet_move_by_ply[(0x3676 - 0x3626) / 2]);
    st.clock_side = &p.ep_square_by_ply[0x9EEC - 0x9EC8];
    st.w8c30 = @ptrCast(p.check_by_ply[0x8C30 - 0x8C06 ..][0..2]);
    st.game_ply = @ptrCast(&p.game_ply);
    st.b9ec9 = &p.ep_square_by_ply[1];
    st.ep_ply2 = &p.ep_square_by_ply[2];
    st.root_in_check = &p.check_by_ply[1];
    st.gives_check = &p.check_by_ply[2];
    st.white_king = &p.piece_list[7];
    st.black_king = &p.piece_list[23];
    st.hash_key = &p.hash_key;
    st.pawn_hash_key = &p.pawn_hash_key;
    st.w7182 = &p.piece_square_sum;
    st.material_balance = &p.material_balance;
    st.material_total = &p.total_material;
    st.white_pieces = &p.piece_count[0];
    st.black_pieces = &p.piece_count[1];
    st.white_nonpawn = @ptrCast(&p.piece_material[0]);
    st.black_nonpawn = @ptrCast(&p.piece_material[1]);
    st.margin_154 = &ev.passer_rank_tables[0][8];
    st.margin_168 = &ev.passer_rank_tables[1][8];
    st.margin_172 = &ev.passer_rank_tables[2][3];
    st.margin_186 = &ev.passer_rank_tables[3][3];
    st.style_flag = &ev.style_normal;
    st.hard = @ptrCast(&ev.ply_flag[0x9DB8 - 0x9D94]);
    st.w90b6 = &ev.pawn_square_sum[0];
    st.w369a = &ev.pawn_square_sum[1];
    st.passed_threat = &ev.passer_flags;
    st.static_only = &ev.draw_flag;
    st.book_exit_ply = @ptrCast(tv.board_after[0x9FBC - 0x9F6E ..][0..2]);
    st.analysis = &tv.board_after[0x9FCF - 0x9F6E];
    st.search_over = &tv.board_after[0x9FD0 - 0x9F6E];
    st.clear_best = &tv.black_rays_after[0xA22C - 0xA1DC];
    st.ba40e = &tv.mate_switch;
    st.iteration = @ptrCast(&tv.iteration);
    st.ply_limit2 = @ptrCast(&tv.ply_limit1);
    st.ply_limit4 = @ptrCast(&tv.ply_limit2);
    st.ply_limit6 = @ptrCast(&tv.ply_limit3);
    st.wa002 = @ptrCast(s.attackers[0xA002 - 0x9FEC ..][0..2]);
    st.wa00a = @ptrCast(s.attackers[0xA00A - 0x9FEC ..][0..2]);
    st.ba00d = &s.attackers[0xA00D - 0x9FEC];
    st.wa00e = @ptrCast(s.attackers[0xA00E - 0x9FEC ..][0..2]);
    st.current_move = @ptrCast(s.attackers[0xA038 - 0x9FEC ..][0..2]);
    st.ext_iteration = &s.attackers[0xA05C - 0x9FEC];
    st.attack_map = &lv.leaf_map;
    st.root_key = &lv.key_history[1];
    // DG:9EB6: byte 2 of `key_history[41]` (DG:9EB4, 6 bytes; a u48 is stored little-endian).
    st.b9eb6 = &@as(*[@sizeOf(u48)]u8, @ptrCast(&lv.key_history[41]))[2];
}

/// The threat-count bonus [3EA + 2c] (`threat_count_bonus`, `threat_count_bonus_rest`).
fn threatBonus(st: *const PrepState, c: u16) i16 {
    return if (c < 8) st.threat_count_bonus[c] else st.threat_count_bonus_rest[c - 8];
}

/// The bytes of the low page, DG:0000..00C9.
const low_page_len = 0xCA;

/// A byte of the low page: DG:62-63 is the node's ply ceiling (`ply_ceiling`).
fn lowByte(st: *const PrepState, a: u16) u8 {
    if (a == 0x62 or a == 0x63) return std.mem.asBytes(st.ply_ceiling)[a - 0x62];
    return if (a < 0x62) st.low_page[a] else st.low_page_rest[a - 0x64];
}

/// Port of clear_move_marks (1E9D:54CE): the 0x137E bytes of the move-mark table DG:781A
/// to 0 (`rep stosb`). The table is not `PrepState`'s (Stage B step 7): its one home is the
/// search's (`movegen.SearchVars.marks`), which the env gives (`env.marks()`).
pub fn clearMoveMarks(env: anytype) void {
    @memset(env.marks(), 0);
}

/// Port of the root repetition count (2B9F:402A–40A7). `history[p]` is the 6-byte key
/// the game record holds for game ply p (5A7B:3A34 + 6p); `key` is DG:8CCC..8CD1. Counts
/// the entries p = game_ply − 4, game_ply − 6, … that equal the key, (p − L + 2) >> 1 of
/// them with L = `last_irreversible` (DG:7464); none when game_ply − 4 < L (signed).
pub fn repetitionCount(history: []const [6]u8, game_ply: i16, last_irreversible: i16, key: [6]u8) u16 {
    const p0: i16 = game_ply -% 4;
    if (p0 < last_irreversible) return 0;
    var n: u16 = @as(u16, @bitCast(p0 -% last_irreversible +% 2)) >> 1;
    var count: u16 = 0;
    var p: i32 = p0;
    while (true) {
        if (std.mem.eql(u8, &history[@intCast(p)], &key)) count += 1;
        p -= 2;
        n -%= 1;
        if (n == 0) break;
    }
    return count;
}

inline fn L(bp: u16, off: u16) u16 {
    return bp -% off;
}

/// A word main writes in the low page above the ply ceiling (DG:64, DG:66).
fn setLowWord(st: *PrepState, addr: u16, v: u16) void {
    std.debug.assert(addr >= 0x64);
    std.mem.writeInt(u16, st.low_page_rest[addr - 0x64 ..][0..2], v, .little);
}

/// The game-record read of 086E / 08C5 / 1328 (segment [3052]): 0 if either flag byte at
/// base+2, base+3 is non-zero; else the byte at base << 8 | the sign-extended byte at
/// base+1. `sites` are the reading instructions in the order they run.
fn recordMove(env: anytype, sites: [4]u16, base: u16) u16 {
    if (env.far(sites[0], 0x3052, base +% 2) == 0 and env.far(sites[1], 0x3052, base +% 3) == 0) {
        const lo: u16 = env.far(sites[2], 0x3052, base +% 1);
        const hi: u16 = env.far(sites[3], 0x3052, base);
        return (hi << 8) | lo | (if (lo & 0x80 != 0) @as(u16, 0xFF00) else 0);
    }
    return 0;
}

fn instantLevel(st: *const PrepState) bool {
    if (st.level.* >= 3) return false;
    if (st.level.* == 0 and st.preset.* == 0) return true;
    return st.base.* == 0;
}

fn concludeNow(st: *PrepState, env: anytype, si: i16) Exit {
    // 0FB8
    st.last_score.* = si;
    st.root_score.* = si;
    st.search_over.* = 1;
    st.pv_length.* = 1;
    st.prescoring.* = 0;
    setSearchMargins(st); // 0FCF
    _ = env.call(0x0FD2, .end_analysis, &.{});
    if (st.pondering.* == 0) st.exclusion_flag.* = 0;
    return .conclude;
}

/// Port of main 0000:0526 (own search) or 0000:055B (ponder search) to 0000:146F, or to
/// an end without a search. `bp` is main's frame pointer (for the addresses of the locals
/// main passes to its callees). The original exactly: every class C fix off and the stale
/// frame words of DEV-044 read through `env.local`.
pub fn rootPrep(st: *PrepState, env: anytype, bp: u16, entry: Entry) Exit {
    return rootPrepFixes(pos.Fixes.original, .stale, st, env, bp, entry);
}

/// What 10A9 reads for the best and second pre-scores when the generator gave no root
/// move (DEV-044). The original never sets `[bp-6]` and `[bp-4]` on that path and reads
/// what main's frame holds from the previous search; `.stale` reads those bytes through
/// `env.local` (the replay's recorded bytes), `.zero` takes 0 for both, the owner's
/// correction of uninitialised reads. They decide only the easy-move flag [A22C] and the
/// halving of the time base, on a path where the game is over (no legal move).
pub const NoMoveScores = enum { stale, zero };

/// `rootPrep` under `fixes` (DEV-031, DEV-043) and with `no_move_scores` (DEV-044).
pub fn rootPrepFixes(comptime fixes: pos.Fixes, comptime no_move_scores: NoMoveScores, st: *PrepState, env: anytype, bp: u16, entry: Entry) Exit {
    if (entry == .own) {
        st.computer_side.* = 1 -% st.opponent_side.*; // 0526
        st.wa3fa.* = 0;
        st.wa00e.* = 0;
        st.w8c30.* = 0;
        if (st.w153c.* != 0) return .menu; // 053A
        if (st.analysis_mode.* == 0) _ = env.call(0x054B, .screen_8536, &.{});
        st.clock_side.* = st.computer_side.*; // 0550
        _ = env.call(0x0556, .reset_move_time_used, &.{});
    }
    // ---- 055B ----
    st.root_copy.* = st.board[0x15..][0..0x4E].*; // memcpy(8C57, 9F0B, 4Eh)
    st.start_clock.* = env.clock(0x056F);
    st.fail_high_pending.* = 0;
    st.later_fail_high.* = 0;
    st.last_before_control.* = 0;
    const side: i16 = @as(i8, @bitCast(st.computer_side.*));
    st.mtg.* = r16(env.call(0x058F, .moves_to_go, &.{w(side)}));
    if (st.b90ae.* != 0) {
        _ = env.call(0x059F, .display_8454, &.{});
        st.b90ae.* = 0;
    }
    if (!(st.level.* > 2 or (st.preset.* == 0 and st.level.* == 0))) {
        if (st.analysis.* == 0) {
            if (st.level.* == 2) {
                const last = if (side == 0) st.tc_last_white.* else st.tc_last_black.*;
                if (last +% 1 >= st.move_number.* and st.next_control[@intCast(side)] <= st.move_number.*) {
                    // 6F48 from 05FD: tests/golden/rootprep/tc1in1-typed.zst.
                    _ = env.call(0x05FD, .add_control_time, &.{w(side)});
                    st.mtg.* = r16(env.call(0x060C, .moves_to_go, &.{w(side)}));
                }
            } else {
                while (st.mtg.* <= 0) {
                    // 6F48 from 061D: tests/golden/rootprep/preset1-monitor61-m.zst.
                    _ = env.call(0x061D, .add_control_time, &.{w(side)});
                    st.mtg.* = r16(env.call(0x062C, .moves_to_go, &.{w(side)}));
                }
            }
        }
        if (st.mtg.* <= 1) st.last_before_control.* = 1; // 063C
    }
    // ---- 0648 ----
    if (st.wa00a.* == 0) {
        _ = env.call(0x064F, .clocks_run, &.{});
        if (st.b1b8b.* == 2) st.b1b8b.* = 1;
    }
    st.result_7328.* = 0;
    st.stop.* = 0;
    st.ba00d.* = 0;
    if (st.poll_requests.* != 0) _ = env.call(0x0672, .poll, &.{});
    const rec: u16 = @as(u16, @bitCast(side)) *% 0xCB +% @as(u16, @bitCast(st.move_number.*)); // 0677
    st.b9ec9.* = env.far(0x0687, 0x304E, rec +% 0x330E);
    st.root_in_check.* = env.far(0x0693, 0x3050, rec +% 0x0B54);
    if (st.wa00a.* != 0) {
        // UNVERIFIED: the [A00A] path (069B–06F7) never ran in the recordings.
        const ply = st.game_ply.*;
        if (st.wa00a.* <= ply) return .main_loop;
        const n: i16 = if (ply == 0 and st.w250c.* > 2) 300 else st.w250c.* *% 100;
        var k: i16 = 0;
        while (n > k) : (k += 1) {
            if (st.stop.* == 2) break;
            _ = env.call(0x06D3, .delay, &.{1});
            if (st.poll_requests.* != 0) _ = env.call(0x06E2, .poll, &.{});
        }
        _ = env.call(0x06EF, .play_best_move, &.{1});
        return .main_loop;
    }
    // ---- 06FA: the book ----
    if (st.pondering.* == 0 and st.analysis_mode.* == 0) {
        const r = env.call(0x070F, .book_probe, &.{ 1, w(@as(i8, @bitCast(st.clock_side.*))) });
        if (@as(u16, @truncate(r)) != 0) {
            st.best_move.* = st.book_move.*; // memcpy(A36C, 38A0, 4)
            st.best_check.* = 0;
            const to: i8 = @bitCast(st.book_move[1]);
            st.best_captured.* = @intFromBool(st.book_move[2] == 1 or st.board[@intCast(to)] != 0);
            st.pv_length.* = 0;
            st.predicted_reply.* = 0;
            _ = env.call(0x06EF, .play_best_move, &.{1});
            return .main_loop;
        }
    }
    // ---- 075E ----
    if (st.book_exit_ply.* == 0 and st.pondering.* == 0) st.book_exit_ply.* = st.game_ply.*;
    if (st.book_exit_ply.* == st.game_ply.* and st.a6a0.* & 1 != 0 and st.menu_depth.* < 2 and st.pondering.* == 0) {
        _ = env.call(0x0790, .book_exit_display_1, &.{});
        _ = env.call(0x0795, .book_exit_display_2, &.{});
    }
    _ = env.call(0x079C, .prepare_eval, &.{});
    // ---- 079F: the hash tables ----
    {
        const ply = st.game_ply.*;
        const keep = st.wa36a.* <= ply and st.changed_73fe.* == 0 and st.w8baa.* == 0 and
            st.irreversible_area[@intCast(ply)] != 0 and st.irreversible_area[@intCast(ply + 1)] != 0;
        if (!keep) {
            if (st.level.* < 3 and st.base.* < 0x5B and st.hash_setting.* > 0x140) {
                st.hash_request.* = 0x140;
            } else {
                st.hash_request.* = st.hash_setting.*;
            }
            if (@as(u16, @truncate(env.call(0x080C, .hash_resize, &.{}))) != 0)
                _ = env.call(0x0815, .hash_clear, &.{});
        }
    }
    _ = env.call(0x081A, .hash_seed_learning, &.{}); // 0818
    st.changed_73fe.* = 0;
    clearMoveMarks(env); // 0822
    const n: u16 = @truncate(if (st.root_in_check.* != 0)
        env.call(0x0835, .gen_evasions, &.{ w(side), 1 })
    else
        env.call(0x0843, .gen_all_moves, &.{ w(side), 1 }));
    st.root_move_count.* = n;
    st.legal_count.* = @bitCast(@as(u8, @truncate(n)));
    st.root_key.* = st.hash_key.*; // memcpy(9DC4, 8CCC, 6)

    var best: i16 = undefined;
    var second: i16 = undefined;
    if (st.root_move_count.* != 0) {
        const pre = prescore(fixes, st, env, bp, side);
        switch (pre) {
            .exit => |e| return e,
            .scores => |s| {
                best = s.best;
                second = s.second;
            },
        }
    } else switch (no_move_scores) {
        // [bp-6] and [bp-4] are not set on this path: 10A9 and 10EB read what main's frame
        // holds (from the previous search), DEV-044. `.stale` reproduces it.
        .stale => {
            best = @bitCast(@as(u16, env.local(L(bp, 6))) | @as(u16, env.local(L(bp, 5))) << 8);
            second = @bitCast(@as(u16, env.local(L(bp, 4))) | @as(u16, env.local(L(bp, 3))) << 8);
        },
        // Corrected: 0 for both, so the gap is 0, [A22C] = 0 and the base is not halved.
        .zero => {
            best = 0;
            second = 0;
        },
    }
    // ---- 1063 ----
    setSearchMargins(st);
    // UNVERIFIED: no stop was parked during pre-scoring in the recordings.
    if (@as(i8, @bitCast(st.prescoring.*)) > 10) st.stop.* = st.prescoring.* -% 10;
    st.search_over.* = 0;
    st.prescoring.* = 0;
    clearMoveMarks(env); // 107F
    if (st.pondering.* == 0 and st.exclusion_flag.* == 0) _ = env.call(0x1094, .clear_excluded, &.{});
    st.exclusion_flag.* = 0;
    if (st.poll_requests.* != 0) _ = env.call(0x10A4, .poll, &.{});
    // ---- 10A9: easy move and the budget ----
    const opp: u16 = @as(u16, @bitCast(@as(i16, @as(i8, @bitCast(st.opponent_side.*)))));
    const easy: u16 = opp *% 0xCB +% @as(u16, @bitCast(st.move_number.*)) +% 0x22EE;
    const b: i8 = @bitCast(env.far(0x10B9, 0x3056, easy));
    const gap: i16 = best -% second;
    const flag_addr: u16 = 0x4A +% @as(u16, @bitCast(@as(i16, b)));
    const flag = if (flag_addr < low_page_len) lowByte(st, flag_addr) else env.local(flag_addr);
    st.clear_best.* = @intFromBool(flag != 0 and gap > 300);
    _ = env.call(0x10E1, .set_time_budget, &.{});
    if (st.single_move.* == 0 and env.far(0x10FB, 0x3056, easy) != 0 and gap > 300) {
        st.base.* >>= 1;
    }
    if (st.clear_best.* != 0 or st.mtg.* <= 2) {
        st.soft.* = st.base.*;
        st.hard.* = st.base.*;
    } else if (st.mtg.* <= 4) {
        // Moves to go 3 or 4.
        st.soft.* = st.base.*;
        st.hard.* = @divTrunc(st.base.*, 2) +% st.base.*;
    } else {
        st.soft.* = @divTrunc(st.hard.* +% st.base.*, 2);
    }
    // ---- 1187 ----
    if (st.legal_count.* == 0) return gameOver(st, env);
    // ---- 1280 ----
    st.nodes.* = @bitCast(@as(i32, st.legal_count.*));
    st.w9312.* = 0;
    if (instantLevel(st)) {
        st.last_score.* = best;
        st.root_score.* = best;
    }
    if (st.pondering.* == 0) { // 12B9
        if (st.bab9e.* != 0) {
            st.bab9e.* -%= 1;
            _ = env.call(0x12CB, .display_7144, &.{});
            _ = env.call(0x12D0, .display_72b4, &.{});
        }
        _ = env.call(0x12D5, .positions_display, &.{});
        if (st.a6a0.* & 2 != 0) _ = env.call(0x12ED, .show_score, &.{ 0x1B, 0x3C, w(st.last_score.*), 2, 0 });
    }
    if (instantLevel(st)) { // 12F5
        st.pv_length.* = 1;
        st.search_over.* = 1;
        return .conclude;
    }
    // UNVERIFIED: no stop was pending here in the recordings.
    if (st.stop.* != 0) return .conclude; // 131E
    st.reverse_move_opp.* = recordMove(env, .{ 0x1340, 0x1348, 0x136C, 0x1371 }, oppRecord(st));
    _ = env.call(0x1388, .sort_root_moves, &.{ 0x3BC4, st.root_move_count.* }); // 137F
    @memset(st.pv_follow, 0); // 1390
    @memset(st.b741e, 0);
    st.depth.* = 1; // 13A3
    if (st.pondering.* != 0) {
        var di: usize = 2;
        while (@as(i16, st.pv_length.*) - 1 > @as(i16, @intCast(di))) : (di += 1) {
            const v = st.pv[di + 1];
            st.pv[di - 1] = v;
            st.pv_follow[di] = v & 0x7F7F;
        }
        if (st.depth_reached.* >= 4 and st.pv_length.* >= 3) {
            st.depth.* = st.depth_reached.* -% 2;
            st.pv_length.* -%= 2;
        } else {
            st.pv_length.* = 1;
            st.depth_reached.* = 1;
        }
    } else {
        st.pv_length.* = 1;
        st.depth_reached.* = 1;
    }
    if (st.depth.* > 1) st.wb65c.* = st.pv[0]; // 13F6
    if (st.analysis.* == 0) _ = env.call(0x140A, .display_a0b0, &.{});
    st.search_start_score.* = st.last_score.*; // 140F
    st.reference_score.* = st.last_score.*;
    st.root_score.* = st.last_score.*;
    st.ext_iteration.* = 0;
    st.search_ply.* = st.game_ply.*;
    setLowWord(st, 0x66, 35);
    setLowWord(st, 0x64, 35);
    if (st.level.* == 3) setLowWord(st, 0x64, st.fixed_depth.* +% 1);
    if (st.level.* == 4) {
        const ax: u16 = st.mate_in.* *% 2 +% 1;
        setLowWord(st, 0x66, ax);
        setLowWord(st, 0x64, ax -% 2);
        st.depth.* = @bitCast(@as(u8, @truncate(ax)) -% 3);
    }
    if (st.depth.* > 8 and st.pv_length.* < 3) st.depth.* = 8; // 145C
    return .iteration_loop;
}

fn oppRecord(st: *const PrepState) u16 {
    const o: u16 = @bitCast(@as(i16, @as(i8, @bitCast(st.opponent_side.*))));
    return 6 *% (o *% 0xCA +% @as(u16, @bitCast(st.move_number.*))) +% 0x1D0;
}

const PreResult = union(enum) {
    exit: Exit,
    scores: struct { best: i16, second: i16 },
};

/// Root pre-scoring, main 086E–1061: the game-record moves, the variables set before the
/// loop, and for each root move in list order its legality test and score, the best move
/// [A36C], and the end without a search.
fn prescore(comptime fixes: pos.Fixes, st: *PrepState, env: anytype, bp: u16, side: i16) PreResult {
    st.reverse_move.* = recordMove(env, .{ 0x0886, 0x088E, 0x08B2, 0x08B7 }, 6 *% (@as(u16, @bitCast(side)) *% 0xCB +% @as(u16, @bitCast(st.move_number.*))) +% 0x1CA);
    st.reverse_move_opp.* = recordMove(env, .{ 0x08D9, 0x08E1, 0x0906, 0x090B }, oppRecord(st));
    st.root_balance.* = st.material_balance.*; // 0919
    st.root_total.* = st.material_total.*;
    st.both_have_pieces.* = @intFromBool(st.white_pieces.* != 0 and st.black_pieces.* != 0);
    const ls: u16 = @bitCast(st.last_score.*);
    const ax: u16 = if (st.opponent_side.* != 0) ls else 0 -% ls; // 093F
    st.score_white_view.* = ax;
    st.score_black_view.* = 0 -% ax;
    st.tb_threshold.* = ls;
    const rep_move = st.reverse_mask.* & st.reverse_move.*; // [bp-44h]
    var best: i16 = -20000; // [bp-6]
    var second: i16 = -20000; // [bp-4]
    var best_bonus: i16 = -20000; // [bp-2]
    st.b9d8a.* = 0;
    const sv = .{ st.w7182.*, st.w90b6.*, st.w369a.* };
    st.stop.* = 0; // 098C
    st.depth.* = 0;
    st.iteration.* = 0;
    st.ply_limit6.* = 2;
    st.ply_limit4.* = 2;
    st.ply_limit2.* = 2;
    st.prescoring.* = 1;
    setPrescoreMargins(st); // 09AD
    var no_legal = true; // [bp-4Ch]
    var tb_win = false; // [bp-4Eh]
    st.clear_best.* = 0;
    st.ba40e.* = 0;
    st.planning_shown.* = 0;
    const keys = .{ st.hash_key.*, st.pawn_hash_key.* }; // memcpy([bp-3Ch], 8CCC, 12)
    st.ponder_bonus_move.* = 0;
    if (st.pondering.* != 0 and st.pv_length.* >= 3) st.ponder_bonus_move.* = st.pv[2] & 0x7F7F;
    var shown: u8 = 0; // [bp-4Ah]
    var i: usize = 0;
    while (@as(i16, @bitCast(st.root_move_count.*)) > @as(i16, @intCast(i))) : (i += 1) { // 0F3F
        const ptr: u16 = 0x3BC4 + 4 * @as(u16, @intCast(i)); // [bp-48h]
        const move = st.root_moves[i];
        const move_word = @as(u16, move[0]) | @as(u16, move[1]) << 8;
        var rep: u8 = 0; // [bp-1Eh]
        _ = env.call(0x0F51, .square_sums, &.{ptr});
        _ = env.call(0x0F57, .hash_key, &.{ptr});
        _ = env.call(0x0F6E, .make, &.{ L(bp, 0x30), L(bp, 0x22), 2, w(side), ptr });
        const o: i16 = @as(i8, @bitCast(st.opponent_side.*));
        const white = o == 0; // White to move after the root move
        var si: i16 = 0;
        var scored = false;
        var illegal = false;
        if (st.tb_settings.* & 8 != 0 and st.men.* < 6) { // 0F73
            if (@as(u16, @truncate(env.call(0x0F8E, .tb_probe, &.{ w(o), 0 }))) != 0) {
                si = 0 -% @as(i16, @bitCast(st.tb_score.*));
                if (si > 0) tb_win = true;
                scored = true;
            }
        }
        if (!scored) {
            // ---- 09FE: the evaluation path ----
            _ = env.call(if (white) 0x0B64 else 0x0A08, if (white) .attack_map_white else .attack_map_black, &.{});
            const king = if (white) st.black_king.* else st.white_king.*;
            if (st.attack_map[king] != 0) {
                si = -20500;
                st.legal_count.* -%= 1;
                illegal = true;
            } else {
                no_legal = false;
                rep = @truncate(env.call(if (white) 0x0B7D else 0x0A28, .repetition, &.{}));
                if (st.material_total.* == 0) {
                    si = 0;
                } else if (st.gives_check.* == 0 and @as(u16, @truncate(env.call(if (white) 0x0B9A else 0x0A42, .has_legal_move, &.{ if (white) 0 else 1, 2 }))) == 0) {
                    si = 0;
                } else if (st.gives_check.* != 0 or st.ep_ply2.* != 0) {
                    const r = env.call(if (white) 0x0BC3 else 0x0A6E, if (white) .node_white else .node_black, &.{ L(bp, 0x0E), 0x4E20, 0xB1E0, 2 });
                    si = 0 -% r16(r);
                } else {
                    si = staticScore(fixes, st, env, bp, white);
                }
            }
        }
        if (!illegal) {
            // ---- 0CD3 ----
            const cap = env.local(L(bp, 0x22));
            if (rep != 0) {
                si = fourFifthsFixes(fixes, si); // 0CD9 (DEV-031)
                if (@as(i8, @bitCast(rep)) >= 2) si = 0;
            } else if (move_word == rep_move and cap == 0 and si > 0) {
                si = fourFifthsFixes(fixes, si); // 0D04 (DEV-031)
            }
            if (best < si) { // 0D11
                second = best;
                best = si;
            } else if (second < si) {
                second = si;
            }
            if (st.ponder_bonus_move.* != 0 and move_word == st.ponder_bonus_move.* and si < 15000 and !no_legal) {
                si +%= 4000;
            }
            if (best_bonus < si) { // 0D4B
                best_bonus = si;
                st.best_move.* = move; // memcpy(A36C, ptr, 4)
                st.best_check.* = st.gives_check.*;
                st.best_captured.* = cap;
                if (st.b9eb6.* & 1 != 0 and (st.book_exit_ply.* != 0 or (st.wa5ee.* != 0 and st.wa002.* != 0)) and
                    st.pondering.* == 0 and st.menu_depth.* < 2)
                {
                    if (shown == 0) {
                        _ = env.call(0x0DA6, .pv_screen_line, &.{st.w2660.*});
                        shown += 1;
                    }
                    _ = env.call(0x0DD7, .show_move, &.{ 1, st.best_check.*, st.best_captured.*, st.w73f8.*, st.pv_columns[@intCast(side)] +% 0x3F, st.w2660.* });
                }
                st.current_move.* = move_word; // 0DDC
                if (cap != 0) st.current_move.* |= 0x80;
                st.pv[0] = st.current_move.*;
                if (st.best_check.* != 0) st.pv[0] = st.current_move.* | 0x8000;
            }
        }
        // ---- 0E02 ----
        _ = env.call(0x0E12, .unmake, &.{ L(bp, 0x30), L(bp, 0x22), w(side), ptr });
        st.w7182.* = sv[0];
        st.w90b6.* = sv[1];
        st.w369a.* = sv[2];
        st.hash_key.* = keys[0];
        st.pawn_hash_key.* = keys[1];
        // 0E3C: the sort key; -20500 for an illegal move, or DEV-067's -32768 (`rootListScore`).
        st.root_scores[i] = pos.rootListScore(fixes, !illegal, si);
        if (st.exclusion_flag.* != 0 and st.pondering.* == 0) {
            // UNVERIFIED: the exclusion list (segment [3054], 0E54–0F34) is not modelled.
            env.notModelled(0x0E54);
            return .{ .exit = .main_loop };
        }
        // UNVERIFIED: the test runs at every root move of every search; the branch has never
        // been taken and is probably unreachable (a mate in one pre-scores 19998, a tablebase
        // score at most 19998; docs/UNVERIFIED.md), so it cannot be compared.
        if (si > 0x4E1E) return .{ .exit = concludeNow(st, env, si) }; // 0FB2: an immediate mate
    }
    // ---- 0FEA ----
    if (no_legal or tb_win) {
        const si = best_bonus;
        if (st.a6a0.* & 2 != 0 and st.pondering.* == 0) {
            st.w260a.* = 300;
            _ = env.call(0x1016, .show_score, &.{ 0x1B, 0x3C, w(si), 2, 0 });
            st.w260a.* = 0x78;
        }
        if (st.analysis_mode.* == 0) return .{ .exit = concludeNow(st, env, si) };
        // UNVERIFIED: analysis mode after a no-search decision (1024–1061) waits for a key.
        env.notModelled(0x1024);
        return .{ .exit = .conclude };
    }
    return .{ .scores = .{ .best = best, .second = second } };
}

/// The first threat term of the White-to-move pre-score (0C5E-0C69): the threat result
/// `r` of eval_threats_white combined with the threat-count bonus [3EA + 2c]. The original
/// *adds* the bonus here (`add ax, [bx+3EA]` at 0C63), where its mirror with Black to move
/// (0B0F) and both second terms (0B3A, 0C8E) subtract it (`sub ax, [bx+3EA]`): one reversed
/// sign in four mirrored places (DEV-043). Corrected (`dev043_prescore_sign`), it
/// subtracts, as the mirror does. 16-bit wrap-around as in the original.
pub fn threatTerm(comptime fixes: pos.Fixes, r: i16, bonus: i16) i16 {
    return if (fixes.dev043_prescore_sign) r -% bonus else r +% bonus;
}

/// The static pre-score of a legal quiet root move (0A78–0CCF with Black to move after
/// it, 0BCA–0CCF with White), 16-bit arithmetic with wrap-around.
fn staticScore(comptime fixes: pos.Fixes, st: *PrepState, env: anytype, bp: u16, white: bool) i16 {
    var si: i16 = undefined;
    if (white) {
        const pe = r16(env.call(0x0BCA, .pawn_eval_wtm, &.{}));
        si = 0 -% r16(env.call(0x0BD6, .static_eval, &.{ 0, 0 }));
        if (st.passed_threat.* & 2 != 0) si +%= 200;
        // [A8DE] set: the pre-score is the static evaluation alone.
        if (st.static_only.* != 0) return si;
        _ = env.call(0x0BFB, .static_eval, &.{ 1, 0 });
        if (st.passed_threat.* & 2 != 0) si -%= 1400;
        si -%= r16(env.call(0x0C0E, .hanging_black, &.{}));
        si -%= r16(env.call(0x0C19, .pieces_and_kings, &.{ 0, 1 })) +% pe;
        si -%= r16(env.call(0x0C26, .activity_white, &.{}));
        si +%= r16(env.call(0x0C2D, .activity_black, &.{})) >> 1;
        if (st.black_nonpawn.* < 0xA5A) si -%= r16(env.call(0x0C3E, .endgame_king_white, &.{}));
        var c: u16 = @truncate(env.call(0x0C45, .count_attacked_wtm, &.{}));
        var r = r16(env.call(0x0C56, .threats_white, &.{ 0x64, c, L(bp, 0x24) }));
        si -%= threatTerm(fixes, r, threatBonus(st, c)) >> 1;
        c = @truncate(env.call(0x0C6B, .count_attacked_btm, &.{}));
        st.ba40e.* = 1;
        r = r16(env.call(0x0C81, .threats_black, &.{ 0x64, c, L(bp, 0x24) }));
        si -%= (r -% threatBonus(st, c)) >> 2;
        st.ba40e.* = 0;
    } else {
        const pe = r16(env.call(0x0A78, .pawn_eval_btm, &.{}));
        si = r16(env.call(0x0A84, .static_eval, &.{ 1, 0 }));
        if (st.passed_threat.* & 2 != 0) si +%= 200;
        if (st.static_only.* != 0) return si;
        _ = env.call(0x0AA7, .static_eval, &.{ 0, 0 });
        if (st.passed_threat.* & 2 != 0) si -%= 1400;
        si -%= r16(env.call(0x0ABA, .hanging_white, &.{}));
        si +%= r16(env.call(0x0AC5, .pieces_and_kings, &.{ 1, 1 })) +% pe;
        si -%= r16(env.call(0x0AD2, .activity_black, &.{}));
        si +%= r16(env.call(0x0AD9, .activity_white, &.{})) >> 1;
        if (st.white_nonpawn.* < 0xA5A) si +%= r16(env.call(0x0AEA, .endgame_king_black, &.{}));
        var c: u16 = @truncate(env.call(0x0AF1, .count_attacked_btm, &.{}));
        var r = r16(env.call(0x0B02, .threats_black, &.{ 0x64, c, L(bp, 0x24) }));
        si +%= (r -% threatBonus(st, c)) >> 1;
        c = @truncate(env.call(0x0B17, .count_attacked_wtm, &.{}));
        st.ba40e.* = 1;
        r = r16(env.call(0x0B2D, .threats_white, &.{ 0x64, c, L(bp, 0x24) }));
        si +%= (r -% threatBonus(st, c)) >> 2;
        st.ba40e.* = 0;
    }
    // ---- 0C9C / 0B48: the random term (Normal style, per-move preset 0 only) ----
    if (st.style_flag.* == 0 and st.preset.* == 0 and st.level.* == 0 and si > -19700 and si < 19700) {
        // UNVERIFIED: the random term never ran in the recordings (Random Limit 0).
        st.random_divisor.* = st.random_limit.*;
        if (st.random_limit.* != 0) {
            const q = r16(env.call(0x0CC7, .rand, &.{}));
            si +%= @rem(q, @as(i16, @bitCast(st.random_limit.*)));
        }
    }
    return si;
}

/// 1187–127C: no legal move. Game over: the result (mate or stalemate) into [A8DA],
/// [934E], [7328] and the game record ([3058]); when pondering, pondering is abandoned.
fn gameOver(st: *PrepState, env: anytype) Exit {
    if (st.pondering.* != 0) {
        // UNVERIFIED: no ponder search found no legal move in the recordings.
        st.pondering.* = 0;
        st.w2502.* = 1;
        st.opponent_side.* = 1 -% st.opponent_side.*;
        _ = env.call(0x11AC, .game_over_display, &.{});
        st.analysis.* = 0;
        _ = env.call(0x11B6, .end_analysis, &.{});
        if (st.computer_side.* != 0) st.move_number.* -%= 1;
        return .main_loop;
    }
    if (st.w2502.* == 0) {
        if (st.computer_side.* != 0) st.move_number.* -%= 1 else st.w2502.* = 1;
    }
    if (st.root_in_check.* != 0) {
        st.last_score.* = -19998;
        st.root_score.* = -19998;
        st.result_7328.* = 9;
    } else {
        st.last_score.* = 0;
        st.root_score.* = 0;
        st.result_7328.* = 8;
    }
    const mn2: u16 = 2 *% @as(u16, @bitCast(st.move_number.*));
    if (st.result_7328.* == 9) {
        if (st.opponent_side.* != 0) env.farWrite(0x1223, 0x3058, mn2 +% 0x261A, 0xB1E2) else env.farWrite(0x1238, 0x3058, mn2 +% 0x2486, 0x4E1E);
    } else if (st.opponent_side.* != 0) {
        env.farWrite(0x1255, 0x3058, mn2 +% 0x261A, 0);
        env.farWrite(0x125A, 0x3058, mn2 +% 0x2486, 0);
    } else {
        env.farWrite(0x1270, 0x3058, mn2 +% 0x2486, 0);
        env.farWrite(0x1275, 0x3058, mn2 +% 0x261C, 0);
    }
    return .main_loop;
}

test "fourFifths wraps in 16 bits (DEV-031): 19974 becomes 2872" {
    try std.testing.expectEqual(@as(i16, 2872), fourFifths(19974));
    try std.testing.expectEqual(@as(i16, 80), fourFifths(100));
    try std.testing.expectEqual(@as(i16, -80), fourFifths(-100));
    try std.testing.expectEqual(@as(i16, 6552), fourFifths(8191));
}

test "repetitionCount: counts equal keys two plies apart back to the last irreversible ply" {
    var h: [20][6]u8 = @splat(.{ 0, 0, 0, 0, 0, 0 });
    const k: [6]u8 = .{ 1, 2, 3, 4, 5, 6 };
    h[6] = k;
    h[4] = k;
    h[5] = k; // wrong parity: never compared
    try std.testing.expectEqual(@as(u16, 2), repetitionCount(&h, 10, 0, k));
    try std.testing.expectEqual(@as(u16, 1), repetitionCount(&h, 10, 5, k)); // p = 6 only
    try std.testing.expectEqual(@as(u16, 0), repetitionCount(&h, 10, 7, k)); // 6 < 7
    try std.testing.expectEqual(@as(u16, 0), repetitionCount(&h, 3, 0, k)); // p = -1 < 0
}
