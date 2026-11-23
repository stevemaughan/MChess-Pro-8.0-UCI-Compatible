//! The root: the iteration loop of main (0000:146F–16E7), root_search (0000:22C0) and
//! the root sort sort_root_moves (0000:668E). This is the logic that decides which move
//! is played: the order of the root moves and how it changes between iterations, the
//! window given to each root move, the null window from depth 2 and the re-search on a
//! fail high, the first-move fail low, the aspiration window and its re-search, what is
//! recorded as the best move ([A36C]), and when the loop ends.
//!
//! Specification: docs/arch/31-root-iteration-time.md §2, §3 and §4.4–4.5, whose
//! executable form is tools/research/rootmodel/rootloop.py (matched the original by
//! record and replay on 69 loops, 305 root_search calls and 270 sorts, §7.3). Test:
//! src/rootsearch_test.zig, which replays invocations recorded from the original
//! (tests/golden/rootsearch/).
//!
//! **The callees are an interface.** Everything these routines call that is not ported
//! here goes through `env.call(site, callee, args)`: the search nodes (3AC6, 5036),
//! root_move_search (2EC8, ported as `searchnode.Node(Ctx).searchPly2`), make and
//! unmake, the hash key, the square
//! sums, the repetition count, the tablebase probe, the keyboard poll, rand(), the
//! analysis hook, 8FE6, and the screen. The call site is passed so that a caller (or
//! the replay test) can tell the calls apart; arguments are the original's stack words
//! (signed words as two's complement). Values the original reads that an interrupt can
//! change between two of its own instructions (the clock, the poll counter [75B6], the
//! stop flag [A4FA] at three points) are read with `env.volatileRead(site)`. Locals of
//! the original that a callee writes through a pointer (the captured piece and the
//! capture flag that make_move returns) are read with `env.local(addr)`, `addr` being
//! the original's stack address, given by `bp`. The C run-time calls (stack check,
//! memcpy, memcmp, sprintf, the long division and multiplication) are done inline.
//!
//! There are no class C corrections in this unit (§"Suspected bugs": none found), so
//! it has no `Fixes` parameter.

const std = @import("std");
const dg = @import("original.zig").dgroup;
const tb = @import("timebudget.zig");
const sn = @import("searchnode.zig");
const pos = @import("position.zig");
const evm = @import("evalvars.zig");
const et = @import("evalthreats.zig");
const see = @import("see.zig");
const rvm = @import("rootvars.zig");

/// Number of root-list entries the original has room for: the list at DG:3BC4 is the
/// ply-1 move list (400 bytes), and the scores at DG:8D0A end where the displayed clock
/// at DG:8DD2 begins.
pub const max_root_moves = 100;

/// DG:1A80: the row of the move-mark table for each square (a word per square).
const mark_row: [120]u16 = blk: {
    const raw = dg(0x1A80, 240);
    var t: [120]u16 = undefined;
    for (0..120) |i| t[i] = std.mem.readInt(u16, raw[2 * i ..][0..2], .little);
    break :blk t;
};

/// DG:0E16: the square-colour table (non-zero on dark squares), by square.
const dark_square = dg(0x0E16, 120);

/// DG:1079 and DG:100B: the tens and units digits of the root-move number, for the
/// display.
const digit_tens = dg(0x1079, 120);
const digit_units = dg(0x100B, 120);

/// DG:123C, DG:123E: the aspiration margins, 200 below and 120 above.
const aspiration_below: i16 = @bitCast(std.mem.readInt(u16, &dg(0x123C, 2), .little));
const aspiration_above: i16 = @bitCast(std.mem.readInt(u16, &dg(0x123E, 2), .little));

/// Size of the move-mark table at DG:781A reached through `mark_row` (rows of 78 bytes,
/// up to row 4892 plus a square).
pub const marks_len = 4892 + 120;

/// The state the three routines read and write, by DGROUP address. Fields that the
/// callees also read or write are here because the routines read or write them too.
///
/// **Where each field lives** (Stage B step 7, and step 8, stage 7). Every field is a pointer
/// to its byte's one home: every variable the node domain's structs hold, in those structs
/// (`bindDomain`): the node's `State`, the `Position`, `EvalVars`, `ThreatVars` and
/// `see.Scratch`; the loop's own variables and the root scores in `rootvars.RootVars`
/// (`bindRoot`). Some of the domain's holders are over-long declarations of another
/// variable (`current_move` is bytes 76 and 77 of `see.Scratch.attackers`): the binding
/// follows the byte, whatever declaration holds it, so that the loop and the node read and
/// write one byte as the original does; src/engine_root_domain_test.zig checks every one
/// against the domain's layout.
pub const RootState = struct {
    // ---- the root list -----------------------------------------------------------
    /// DG:3BC4: the root moves, 4 bytes each: from, to, flag, score byte.
    root_moves: *[max_root_moves][4]u8 = undefined,
    /// DG:8D0A: the root score of each list entry; the sort key.
    root_scores: *[max_root_moves]i16 = undefined,
    /// DG:7442: entries in the root list.
    root_move_count: *align(1) u16 = undefined,
    /// DG:A518: legal root moves (signed byte compares).
    legal_count: *i8 = undefined,
    /// DG:8CBC: 1-based number of the root move being searched.
    root_move_number: *u8 = undefined,
    /// DG:A038: the move being searched, from | 0x80 if capture, to | 0x80 if check.
    current_move: *[2]u8 = undefined,
    // ---- best move and scores ------------------------------------------------------
    /// DG:A36C: the best move so far: **the move that is played**.
    best_move: *[4]u8 = undefined,
    /// DG:7186, DG:77D0: captured piece and gives-check flag of `best_move`.
    best_captured: *u8 = undefined,
    best_check: *u8 = undefined,
    /// DG:75C0, DG:B4A8: best move and DG:7242 saved during a root fail-high re-search.
    saved_best: *[4]u8 = undefined,
    saved_7242: *[6]u8 = undefined,
    /// DG:7242: 6 bytes saved and restored with the best move (meaning not determined).
    state_7242: *[6]u8 = undefined,
    /// DG:934E: the current root score.
    root_score: *align(1) i16 = undefined,
    /// DG:933C: the reference score for time decisions.
    reference_score: *align(1) i16 = undefined,
    /// DG:A8DA: the score of the last iteration that returned above its lower bound.
    last_score: *align(1) i16 = undefined,
    /// DG:7184: `last_score` at the start of this search.
    search_start_score: *align(1) i16 = undefined,
    /// DG:9FD0: search over (mate found).
    search_over: *u8 = undefined,
    // ---- PV ----------------------------------------------------------------------
    /// DG:93B0: the PV row of ply 1 (37 words: from | to << 8, bit 7 of from capture,
    /// bit 7 of to check), DG:93FA the row of ply 2 that the child search leaves.
    pv: *[37]u16 = undefined,
    child_pv: *[37]u16 = undefined,
    /// DG:B42B: PV length; DG:AAF8: PV length of the row at ply 2.
    pv_length: *i8 = undefined,
    child_pv_length: *i8 = undefined,
    /// DG:3790 + 2·p: PV move to try first at ply p.
    pv_follow: *[37]u16 = undefined,
    /// DG:B65C: pv[0] at the first root move of iteration 2.
    b65c: *align(1) u16 = undefined,
    // ---- depth and limits ------------------------------------------------------------
    /// DG:744E: the iteration depth (signed byte).
    depth: *i8 = undefined,
    /// DG:A3F4: the iteration number.
    iteration: *u8 = undefined,
    /// DG:A35C: depth at the end of root_search (+1 if a root move was finished).
    depth_reached: *u8 = undefined,
    /// DG:64, DG:66, DG:62: loop limit, default ply ceiling, ply ceiling of the nodes.
    loop_limit: *align(1) i16 = undefined,
    default_ceiling: *align(1) i16 = undefined,
    ply_ceiling: *i16 = undefined,
    /// DG:A272, DG:9356, DG:A5EC: ply limits depth+2, +4, +6.
    ply_limit2: *u16 = undefined,
    ply_limit4: *u16 = undefined,
    ply_limit6: *u16 = undefined,
    /// DG:1E08: mate mode (Mate in, Shortest mate).
    mate_mode: *u16 = undefined,
    /// DG:A274: level type.
    level: *u8 = undefined,
    /// DG:A4F4: correspondence: root moves searched in full.
    corr_moves: *align(1) i16 = undefined,
    // ---- time ----------------------------------------------------------------------
    /// DG:A8E8: clock at the start of thinking.
    start_clock: *align(1) u32 = undefined,
    /// DG:A356: elapsed at the first root move of this iteration; 0 for the others.
    iter_start_elapsed: *align(1) i32 = undefined,
    /// DG:8D06, DG:9DB8, DG:A362, DG:B59A: base, hard, soft, fail-high.
    base: *align(1) i32 = undefined,
    hard: *align(1) i32 = undefined,
    soft: *align(1) i32 = undefined,
    fail_high: *align(1) i32 = undefined,
    /// DG:7102: moves to go; DG:77EC + 4·side: time left; DG:A22C: easy-move flag.
    mtg: *align(1) i16 = undefined,
    time_left: *align(1) [2]i32 = undefined,
    clear_best: *u8 = undefined,
    /// DG:A05C: the iteration given the fail-low extension.
    ext_iteration: *u8 = undefined,
    /// DG:A3F5: root fail-high re-search pending; DG:AE36: one at a later move.
    fail_high_pending: *u8 = undefined,
    later_fail_high: *u8 = undefined,
    /// DG:A4FA: the stop flag.
    stop: *u8 = undefined,
    // ---- sides and modes ---------------------------------------------------------------
    /// DG:8DDE: the computer's side; DG:717C: the side to move after a root move.
    computer_side: *u8 = undefined,
    opponent_side: *u8 = undefined,
    /// DG:3676: pondering.
    pondering: *u8 = undefined,
    /// DG:8C08: the move just made gives check (written by make_move).
    gives_check: *u8 = undefined,
    /// DG:9EF6: the search board (read: is the target square occupied).
    board: *[120]u8 = undefined,
    /// DG:A03C, DG:A03D, DG:A04C, DG:A04D: the bishop slots of the piece lists.
    white_bishops: *[2]u8 = undefined,
    black_bishops: *[2]u8 = undefined,
    /// DG:154A: piece count; DG:239C: tablebase flags; DG:7466: tablebase score.
    piece_count: *i8 = undefined,
    tb_flags: *i16 = undefined,
    tb_score: *u16 = undefined,
    /// DG:8BC0 & DG:3626: a move scored as a draw at the root.
    draw_mask: *u16 = undefined,
    draw_move: *u16 = undefined,
    /// DG:7182, DG:90B6, DG:369A: saved over each root move and restored after it.
    w7182: *u16 = undefined,
    w90b6: *u16 = undefined,
    w369a: *u16 = undefined,
    /// DG:8CCC, DG:8CD2: the hash keys (main and pawn, 6 bytes each), restored after each
    /// root move.
    hash_key: *u48 = undefined,
    pawn_hash_key: *u48 = undefined,
    /// DG:250A: entries in the excluded-move list (in segment [3054]).
    excluded_count: *align(1) i16 = undefined,
    /// DG:1548, DG:291E, DG:70F2: random play off, its limit, the term drawn.
    random_off: *u16 = undefined,
    random_limit: *align(1) u16 = undefined,
    random_value: *align(1) u16 = undefined,
    // ---- display (read only to decide whether to call the screen) ----------------------
    /// DG:AB1A: thinking display; DG:22BA: display off; DG:9351: "Planning" shown;
    /// DG:A5F4; DG:73F8; DG:A6A0, DG:A6A1: display options; DG:75B7: menu depth.
    think_display: *u8 = undefined,
    display_off: *align(1) u16 = undefined,
    planning_shown: *u8 = undefined,
    a5f4: *u8 = undefined,
    w73f8: *align(1) u16 = undefined,
    a6a0: *u8 = undefined,
    a6a1: *u8 = undefined,
    menu_depth: *i8 = undefined,
    /// DG:24F6, DG:A38B, DG:24F0: the analysis hook's switches.
    analysis_hook: *align(1) u16 = undefined,
    a38b: *u8 = undefined,
    analysis_depth: *align(1) i16 = undefined,
    /// DG:2660, DG:1B9C, DG:22B4: PV display: move number, screen mode, window.
    w2660: *align(1) u16 = undefined,
    w1b9c: *align(1) i16 = undefined,
    w22b4: *align(1) u16 = undefined,
    /// DG:2A5E: PV display column per side.
    pv_columns: *align(1) [2]u16 = undefined,
    /// DG:3686: pointer to the PV display's copy of the root position (in root_search's
    /// frame).
    pv_display_ptr: *u16 = undefined,
};

/// The routines called through the interface, by the original's address.
pub const Callee = enum {
    square_sums, // 0000:678A update_square_sums
    hash_key, // 4793:3EA2 update_hash_key
    make, // 1E9D:000C make_move
    unmake, // 1E9D:0960 unmake_move
    repetition, // 2B9F:402A
    tb_probe, // 2B9F:BB76
    node_white, // 0000:3AC6
    node_black, // 0000:5036
    root_move_search, // 0000:2EC8: searchnode.Node(Ctx).searchPly2
    keep_fail_high, // 0000:8FE6: keepFailHigh below
    poll, // 1E9D:7514
    rand, // 4793:89D8
    analysis, // 1E9D:9B08
    planning_header, // 1E9D:7D58
    show_move, // 38C0:948A
    show_char, // 38C0:B156
    show_score, // 38C0:9BEA
    show_at, // 38C0:8066
    show_text, // 38C0:DDF6
    show_number, // 38C0:9764 (PV display)
    pv_screen_begin, // 38C0:D2DC
    pv_screen_window, // 38C0:D566
    pv_screen_line, // 38C0:8898
    pv_screen_flush, // 38C0:D5BE
    pv_screen_end, // 38C0:D306
    root_search, // 0000:22C0 (the loop's call; the port's own rootSearch)
    sort_root_moves, // 0000:668E (the loop's call; the port's own sortRootMoves)
};

inline fn w(x: anytype) u16 {
    return @bitCast(@as(i16, @intCast(x)));
}

// ---------------------------------------------------------------------------
// sort_root_moves (0000:668E)
// ---------------------------------------------------------------------------

/// Port of sort_root_moves (0000:668E): Shell sort of the first `n` root moves,
/// descending by their scores, each 4-byte move moving with its score. The gap starts at
/// 1 and becomes 3h+1 while h ≤ n/9 (toward zero); the passes use h, then 13, 4 and 1
/// (each only if smaller than the last). The shift test is a strict `<`, so equal keys
/// keep their order inside a pass.
pub fn sortRootMoves(moves: [][4]u8, scores: []i16, n: i16) void {
    const h0 = @divTrunc(n, 9);
    var h: i16 = 1;
    while (h0 >= h) h = h *% 3 +% 1;
    while (h > 0) {
        var j: i16 = h + 1;
        while (j <= n) : (j += 1) {
            const tmp = moves[@intCast(j - 1)];
            const key = scores[@intCast(j - 1)];
            var d = j;
            while (h < d) {
                const p: usize = @intCast(d - h - 1);
                if (scores[p] >= key) break;
                moves[@intCast(d - 1)] = moves[p];
                scores[@intCast(d - 1)] = scores[p];
                d -= h;
            }
            moves[@intCast(d - 1)] = tmp;
            scores[@intCast(d - 1)] = key;
        }
        if (h > 13) {
            h = 13;
        } else if (h > 4) {
            h = 4;
        } else if (h > 1) {
            h = 1;
        } else break;
    }
}

// ---------------------------------------------------------------------------
// root_stop_keep_failhigh_move (0000:8FE6)
// ---------------------------------------------------------------------------

/// Port of root_stop_keep_failhigh_move (0000:8FE6-901A), which root_search calls when it
/// sees the stop flag while a later root move's fail-high re-search is pending (§3.2 step
/// 6; `env.call(0x26E0, .keep_fail_high, ...)` below). The best move so far becomes the
/// first word of the PV: [73F8] points to [A36C] (its only write, 0000:012B, stores
/// A36Ch); W(A038) = that move with bit 7 of its from byte set if it captured ([7186]);
/// W(93B0) = W(A038), with bit 7 of the to byte set if it gave check ([77D0]). The routine
/// then shows the best move (0000:8F78, the screen), which the engine leaves out.
/// UNVERIFIED: runs in the engine (a timed search stopped by the time manager) and in its UCI
/// stop tests; not compared with the original: the stop must land during a later root
/// move's fail-high re-search, and no recording, live-clock ones included, has caught one.
pub fn keepFailHigh(st: *RootState) void {
    var from = st.best_move[0];
    if (st.best_captured.* != 0) from |= 0x80;
    st.current_move.* = .{ from, st.best_move[1] };
    var word: u16 = @as(u16, from) | @as(u16, st.best_move[1]) << 8;
    if (st.best_check.* != 0) word |= 0x8000;
    st.pv[0] = word;
}

// ---------------------------------------------------------------------------
// root_search (0000:22C0)
// ---------------------------------------------------------------------------

fn showScoreKind(i: i16, fh_pending: bool) u16 {
    return if (i != 0 and !fh_pending) 2 else 1;
}

/// The DGROUP address of each `RootState` field but the tables (the layout its replay test
/// proves, src/rootsearch_test.zig).
pub const layout = [_]struct { []const u8, u16 }{
    .{ "root_move_count", 0x7442 },   .{ "legal_count", 0xA518 },
    .{ "root_move_number", 0x8CBC },  .{ "current_move", 0xA038 },
    .{ "best_move", 0xA36C },         .{ "best_captured", 0x7186 },
    .{ "best_check", 0x77D0 },        .{ "saved_best", 0x75C0 },
    .{ "saved_7242", 0xB4A8 },        .{ "state_7242", 0x7242 },
    .{ "root_score", 0x934E },        .{ "reference_score", 0x933C },
    .{ "last_score", 0xA8DA },        .{ "search_start_score", 0x7184 },
    .{ "search_over", 0x9FD0 },       .{ "pv_length", 0xB42B },
    .{ "child_pv_length", 0xAAF8 },   .{ "b65c", 0xB65C },
    .{ "depth", 0x744E },             .{ "iteration", 0xA3F4 },
    .{ "depth_reached", 0xA35C },     .{ "loop_limit", 0x0064 },
    .{ "default_ceiling", 0x0066 },   .{ "ply_ceiling", 0x0062 },
    .{ "ply_limit2", 0xA272 },        .{ "ply_limit4", 0x9356 },
    .{ "ply_limit6", 0xA5EC },        .{ "mate_mode", 0x1E08 },
    .{ "level", 0xA274 },             .{ "corr_moves", 0xA4F4 },
    .{ "start_clock", 0xA8E8 },       .{ "iter_start_elapsed", 0xA356 },
    .{ "base", 0x8D06 },              .{ "hard", 0x9DB8 },
    .{ "soft", 0xA362 },              .{ "fail_high", 0xB59A },
    .{ "mtg", 0x7102 },               .{ "time_left", 0x77EC },
    .{ "clear_best", 0xA22C },        .{ "ext_iteration", 0xA05C },
    .{ "fail_high_pending", 0xA3F5 }, .{ "later_fail_high", 0xAE36 },
    .{ "stop", 0xA4FA },              .{ "computer_side", 0x8DDE },
    .{ "opponent_side", 0x717C },     .{ "pondering", 0x3676 },
    .{ "gives_check", 0x8C08 },       .{ "white_bishops", 0xA03C },
    .{ "black_bishops", 0xA04C },     .{ "piece_count", 0x154A },
    .{ "tb_flags", 0x239C },          .{ "tb_score", 0x7466 },
    .{ "draw_mask", 0x8BC0 },         .{ "draw_move", 0x3626 },
    .{ "w7182", 0x7182 },             .{ "w90b6", 0x90B6 },
    .{ "w369a", 0x369A },             .{ "hash_key", 0x8CCC },
    .{ "pawn_hash_key", 0x8CD2 },     .{ "excluded_count", 0x250A },
    .{ "random_off", 0x1548 },        .{ "random_limit", 0x291E },
    .{ "random_value", 0x70F2 },      .{ "think_display", 0xAB1A },
    .{ "display_off", 0x22BA },       .{ "planning_shown", 0x9351 },
    .{ "a5f4", 0xA5F4 },              .{ "w73f8", 0x73F8 },
    .{ "a6a0", 0xA6A0 },              .{ "a6a1", 0xA6A1 },
    .{ "menu_depth", 0x75B7 },        .{ "analysis_hook", 0x24F6 },
    .{ "a38b", 0xA38B },              .{ "analysis_depth", 0x24F0 },
    .{ "w2660", 0x2660 },             .{ "w1b9c", 0x1B9C },
    .{ "w22b4", 0x22B4 },             .{ "pv_columns", 0x2A5E },
    .{ "pv_display_ptr", 0x3686 },
};

/// The DGROUP address of each of `RootState`'s tables.
pub const tables = [_]struct { []const u8, u16 }{
    .{ "root_moves", 0x3BC4 }, .{ "root_scores", 0x8D0A }, .{ "pv", 0x93B0 },
    .{ "child_pv", 0x93FA },   .{ "pv_follow", 0x3790 },   .{ "board", 0x9EF6 },
};

/// Points every field of `st` whose bytes no member of the node domain holds at its one
/// home in `RootVars` (Stage B step 8, stage 7): the loop's own variables, the loop limit
/// and the default ply ceiling in main's low page, and the root scores, by address
/// (`rootvars.bindView`). With `bindDomain` for the rest, every field is a pointer to its
/// byte's one home, and nothing is copied around the loop's callees.
pub fn bindRoot(st: *RootState, rv: *rvm.RootVars, pg: *rvm.ProgramVars) void {
    rvm.bindView(RootState, layout ++ tables, st, rv, pg);
}

/// Points `st`'s fields whose bytes the node domain's structs hold at those bytes (Stage B
/// step 7, stage 3b): the loop and its callees then read and write each of these variables
/// in its one home, with no copy between the loop's view, the image and the domain while
/// the loop runs. The node's `State` holds the depth (744E), the ply ceiling (0062), the
/// mate mode (1E08), the tablebase setting and score (239C, 7466), the stop flag (A4FA),
/// the child's PV length and the thinking display (`pv_end`, AAF6 + 2 and + 36), and the
/// tables of the root moves (the ply-1 move list, 3BC4), the PV rows of plies 1 and 2
/// (93B0, 93FA) and the PV moves to follow (the killers, 3790); the `Position` the board
/// (9EF6), the bishop slots (A03C, A04C), the men (154A), the piece-square sum (7182), the
/// keys (8CCC, 8CD2), the per-ply check flag of ply 2 (8C08), reversible-move word of ply 1
/// (8BC0) and quiet move of ply 0 (3626), and, past the original's room of the quiet moves
/// (`room_quiet_move`), pondering (3676) and the PV display's pointer (3686); `EvalVars`
/// the pawn square sums (90B6, 369A), the style flag (1548) and, in the last four bytes of
/// `ply_flag`, the hard time limit (9DB8); `ThreatVars` the iteration (A3F4), the three ply
/// limits (A272, 9356, A5EC) and, inside `board_after` and `black_rays_after`, the search-
/// over flag (9FD0) and the easy-move flag (A22C); `see.Scratch` the move being searched
/// (A038, `attackers[76..78]`) and the fail-low iteration (A05C, `attackers[112]`). The root
/// scores (8D0A) are `RootVars`' (`bindRoot`).
pub fn bindDomain(st: *RootState, state: *sn.State, p: *pos.Position, ev: *evm.EvalVars, tv: *et.ThreatVars, s: *see.Scratch) void {
    st.root_moves = @ptrCast(&state.move_list[1]);
    st.pv = &state.pv[1];
    st.child_pv = &state.pv[2];
    st.pv_follow = state.killer[0..37];
    st.board = &p.board;
    st.depth = &state.horizon;
    st.ply_ceiling = &state.ply_ceiling;
    st.mate_mode = &state.mode_1e08;
    st.tb_flags = &state.tb_setting;
    st.tb_score = @ptrCast(&state.tb_score);
    st.stop = &state.stop;
    st.child_pv_length = @ptrCast(&state.pv_end[2]);
    st.think_display = &state.pv_end[0xAB1A - 0xAAF6];
    st.white_bishops = p.piece_list[2..4];
    st.black_bishops = p.piece_list[18..20];
    st.piece_count = @ptrCast(&p.men);
    st.w7182 = &p.piece_square_sum;
    st.hash_key = &p.hash_key;
    st.pawn_hash_key = &p.pawn_hash_key;
    st.gives_check = &p.check_by_ply[2];
    st.draw_mask = &p.reversible_by_ply[1];
    st.draw_move = &p.quiet_move_by_ply[0];
    st.pondering = @ptrCast(&p.quiet_move_by_ply[(0x3676 - 0x3626) / 2]);
    st.pv_display_ptr = &p.quiet_move_by_ply[(0x3686 - 0x3626) / 2];
    st.w90b6 = &ev.pawn_square_sum[0];
    st.w369a = &ev.pawn_square_sum[1];
    st.random_off = &ev.style_normal;
    st.hard = @ptrCast(&ev.ply_flag[0x9DB8 - 0x9D94]);
    st.iteration = @ptrCast(&tv.iteration);
    st.ply_limit2 = @ptrCast(&tv.ply_limit1);
    st.ply_limit4 = @ptrCast(&tv.ply_limit2);
    st.ply_limit6 = @ptrCast(&tv.ply_limit3);
    st.search_over = &tv.board_after[0x9FD0 - 0x9F6E];
    st.clear_best = &tv.black_rays_after[0xA22C - 0xA1DC];
    st.current_move = s.attackers[0xA038 - 0x9FEC ..][0..2];
    st.ext_iteration = &s.attackers[0xA05C - 0x9FEC];
}

/// The mark of root move `i` (a quiet move) to 3, at `mark_row[from] + to` of the move-mark
/// table DG:781A, which is not `RootState`'s (Stage B step 7): its one home is the search's
/// (`movegen.SearchVars.marks`), which the env gives (`env.marks()`).
fn markQuiet(st: *const RootState, env: anytype, i: usize) void {
    const m = st.root_moves[i];
    const row = mark_row[m[0]];
    env.marks()[@as(u16, row) +% m[1]] = 3;
}

/// Port of root_search (0000:22C0): one iteration over the root moves with the window
/// (lo, hi). Returns the best score (alpha if nothing raised it). `bp` is the original's
/// frame pointer, used only to name the locals a callee writes through a pointer.
pub fn rootSearch(st: *RootState, env: anytype, bp: u16, hi_in: i16, lo: i16) i16 {
    const L = struct {
        fn at(b: u16, off: u16) u16 {
            return b -% off;
        }
    }.at;
    var hi = hi_in;
    st.best_move.* = st.root_moves[0];
    const saved_words = .{ st.w7182.*, st.w90b6.*, st.w369a.* };
    var si = lo;
    const draw = st.draw_mask.* & st.draw_move.*;
    const keys = .{ st.hash_key.*, st.pawn_hash_key.* };
    var fh_pending = false;
    st.root_move_number.* = 0;
    var i: i16 = 0;
    var saved_si: i16 = 0;
    var saved_cap: u8 = 0;
    var saved_check: u8 = 0;
    const side = st.computer_side.*;
    const ptr_base: u16 = 0x3BC4;

    moves: while (true) {
        // ---- 238E: next root move ----
        if (st.legal_count.* <= i) break;
        const iu: usize = @intCast(i);
        const ptr: u16 = ptr_base + 4 * @as(u16, @intCast(i));
        st.root_move_number.* +%= 1;
        if (st.pondering.* == 0 and st.excluded_count.* > 0) {
            // UNVERIFIED: the excluded-move list ([250A] > 0, in segment [3054]) is not
            // modelled (docs/arch/31-root-iteration-time.md §3) and never ran.
            if (env.excluded(st.root_moves[iu])) {
                i += 1;
                continue;
            }
        }
        // ---- 23AC ----
        st.current_move.* = .{ st.root_moves[iu][0], st.root_moves[iu][1] };
        if (st.board[@as(u8, st.root_moves[iu][1])] != 0) st.current_move[0] |= 0x80;
        st.iter_start_elapsed.* = 0;
        if (env.volatileRead(0x23CE) != 0) _ = env.call(0x23D4, .poll, &.{});
        const now: u32 = env.volatileRead(0x23DD);
        const e: i32 = @bitCast(now -% st.start_clock.*);
        var stop = false;
        if (st.level.* == tb.level_correspondence) {
            // UNVERIFIED: correspondence pruning never ran (§7.3).
            if (st.corr_moves.* != 0 and i > st.corr_moves.* and lo < si and st.reference_score.* -% 0x30 < si) break;
        } else if (st.level.* < 3) {
            if (i == 0) {
                // Test B (2424-2476).
                if (st.iteration.* == 2) st.b65c.* = st.pv[0];
                if (st.iteration.* != st.ext_iteration.*) {
                    if (e < st.base.*) {
                        st.iter_start_elapsed.* = e;
                    } else if (st.pondering.* == 0) stop = true;
                }
            } else if (st.pondering.* == 0 and e >= st.base.*) {
                // Test C (247A-258C).
                const ref = st.reference_score.*;
                if (ref <= si or (i > 3 and ref -% 20 < si) or (i > 5 and ref -% 50 < si)) stop = true;
            }
        }
        if (stop) {
            st.stop.* = 1;
            break;
        }
        // ---- 249A: search this move (again, for a fail-high re-search) ----
        while (true) {
            _ = env.call(0x249F, .square_sums, &.{ptr});
            _ = env.call(0x24A5, .hash_key, &.{ptr});
            _ = env.call(0x24BC, .make, &.{ L(bp, 0x1A), L(bp, 0x16), 2, side, ptr });
            if (st.gives_check.* != 0) st.current_move[1] |= 0x80;
            const cap = env.local(L(bp, 0x16));
            if (!(st.pondering.* != 0 and st.think_display.* & 2 == 0) and st.display_off.* == 0) {
                if (st.think_display.* != 0 and st.planning_shown.* == 0 and st.a5f4.* == 0) {
                    _ = env.call(0x24FD, .planning_header, &.{});
                    _ = env.call(0x2516, .show_move, &.{ 1, st.best_check.*, st.best_captured.*, st.w73f8.*, 0x31, 0x1B });
                    st.planning_shown.* = 1;
                }
                if (st.planning_shown.* != 0) {
                    _ = env.call(0x253E, .show_move, &.{ 1, st.gives_check.*, w(@as(i8, @bitCast(cap))), ptr, 0x17, 0x1B });
                    const tens: u16 = if (i >= 9) w(@as(i8, @bitCast(digit_tens[iu])) + 0x30) else 0x20;
                    _ = env.call(0x2598, .show_char, &.{ 0x1B, 0x20, tens, 1 });
                    _ = env.call(0x25B2, .show_char, &.{ 0x1B, 0x21, w(@as(i8, @bitCast(digit_units[iu])) + 0x30), 1 });
                }
            }
            // ---- 25BA: score ----
            const r: i16 = @bitCast(@as(u16, @truncate(env.call(0x25BA, .repetition, &.{}))));
            var di: ?i16 = null;
            const move_word = @as(u16, st.root_moves[iu][0]) | @as(u16, st.root_moves[iu][1]) << 8;
            if (r >= 2) {
                di = 0;
            } else if (si >= 0 and (r != 0 or (move_word == draw and cap == 0))) {
                di = 0;
            }
            if (di == null and (st.root_moves[iu][2] | cap) != 0 and st.piece_count.* < 5 and st.tb_flags.* >= 11) {
                // UNVERIFIED: no tablebase probe hit at the root in the recordings (§7.3).
                const hit: u16 = @truncate(env.call(0x260A, .tb_probe, &.{ w(@as(i8, @bitCast(st.opponent_side.*))), 1 }));
                if (hit != 0) di = 0 -% @as(i16, @bitCast(st.tb_score.*));
            }
            var score: i16 = undefined;
            if (di) |d| {
                st.child_pv_length.* = 1;
                score = d;
            } else {
                var res: u16 = undefined;
                if (st.depth.* == 1 or st.mate_mode.* != 0) {
                    const black = st.opponent_side.* != 0;
                    res = @truncate(env.call(if (black) 0x2644 else 0x265B, if (black) .node_black else .node_white, &.{ L(bp, 6), w(0 -% si), w(0 -% hi), 2 }));
                } else {
                    res = @truncate(env.call(0x2670, .root_move_search, &.{ w(0 -% si), w(0 -% hi), w(@as(i8, @bitCast(st.opponent_side.*))) }));
                }
                score = 0 -% @as(i16, @bitCast(res));
            }
            // ---- 2677: unmake and restore ----
            _ = env.call(0x2687, .unmake, &.{ L(bp, 0x1A), L(bp, 0x16), side, ptr });
            st.hash_key.*, st.pawn_hash_key.* = keys;
            st.w7182.*, st.w90b6.*, st.w369a.* = saved_words;
            if (env.volatileRead(0x26C5) != 0) {
                if (!fh_pending or i == 0) return finish(st, si, i);
                // UNVERIFIED: the call of 8FE6 (`keepFailHigh`): runs in the engine on a time
                // stop and in its UCI stop tests; no recording of the original has caught a
                // stop during a later move's fail-high re-search, so it is not compared.
                _ = env.call(0x26E0, .keep_fail_high, &.{});
                return finish(st, si, i);
            }
            // ---- 26E6: promotion to a bishop ----
            if (st.root_moves[iu][2] == 3 and -4000 < score and score < 4000) {
                const dark = dark_square[st.root_moves[iu][1]];
                const a, const b = if (st.opponent_side.* != 0)
                    .{ st.white_bishops[0], st.white_bishops[1] }
                else
                    .{ st.black_bishops[1], st.black_bishops[0] };
                if ((a < 0x63 and dark == 0) or (b < 0x63 and dark != 0)) score -%= 300;
            }
            // ---- 274D ----
            if (score <= si) {
                st.root_scores[iu] = -20000 -% i;
                if (i == 0) {
                    firstMoveFailLow(st, env, si);
                    return finish(st, si, i);
                }
                if (fh_pending) {
                    // The fail-high re-search failed: restore the earlier best.
                    si = saved_si;
                    st.root_score.* = si;
                    st.best_move.* = st.saved_best.*;
                    st.best_captured.* = saved_cap;
                    st.best_check.* = saved_check;
                    st.state_7242.* = st.saved_7242.*;
                    if (!(st.pondering.* != 0 and st.think_display.* & 2 == 0)) {
                        if (st.planning_shown.* != 0 and st.display_off.* == 0)
                            _ = env.call(0x2E42, .show_move, &.{ 1, st.best_check.*, st.best_captured.*, st.w73f8.*, 0x31, 0x1B });
                        if (st.pondering.* == 0) _ = env.call(0x2C1F, .show_score, &.{ 0x1B, 0x3C, w(si), 1, 0 });
                    }
                    if (afterNewBest(st, si, hi, lo)) |nh| {
                        hi = nh;
                    } else return finish(st, si, i);
                    fh_pending = false;
                }
                break;
            }
            if (hi <= score) {
                // ---- 275C: fail high ----
                score = hi;
                if (fh_pending or st.mate_mode.* != 0) {
                    st.fail_high_pending.* = 0;
                    hi = 20000;
                } else {
                    st.fail_high_pending.* = 1;
                    st.stop.* = 0;
                    hi +%= 120;
                    if (i == 0) hi +%= 60 else st.later_fail_high.* = 1;
                    if (hi > 20000) hi = 20000;
                    st.saved_best.* = st.best_move.*;
                    saved_si = si;
                    saved_cap = st.best_captured.*;
                    saved_check = st.best_check.*;
                    st.saved_7242.* = st.state_7242.*;
                }
                if (!(st.pondering.* != 0 and st.think_display.* & 2 == 0)) {
                    if (st.planning_shown.* != 0 and st.display_off.* == 0)
                        _ = env.call(0x2803, .show_move, &.{ 1, st.gives_check.*, w(@as(i8, @bitCast(cap))), ptr, 0x31, 0x1B });
                    if (st.pondering.* == 0) _ = env.call(0x2835, .show_score, &.{ 0x1B, 0x3C, w(score), showScoreKind(i, fh_pending), 0 });
                }
                st.best_move.* = st.root_moves[iu];
                st.best_captured.* = cap;
                st.best_check.* = st.gives_check.*;
                if (cap == 0) markQuiet(st, env, iu);
                fh_pending = true;
                continue; // 287E: search the same move again
            }
            // ---- 2882: new best, si < score < hi ----
            if (env.local(L(bp, 0x16)) == 0) markQuiet(st, env, iu);
            st.best_move.* = st.root_moves[iu];
            st.best_captured.* = cap;
            st.best_check.* = st.gives_check.*;
            if (st.pondering.* == 0 and st.display_off.* == 0 and st.a6a1.* & 8 != 0) {
                // UNVERIFIED: the analysis-line display (28D4) is not modelled.
                env.notModelled(0x28D4);
            }
            if (-19500 < score and score < 19500 and score != 0 and st.random_off.* == 0) {
                const lim = st.random_limit.*;
                st.random_value.* = lim;
                if (lim != 0) {
                    // UNVERIFIED: the random term never ran ([291E] = 0 in every run).
                    const q: i16 = @bitCast(@as(u16, @truncate(env.call(0x295B, .rand, &.{}))));
                    const rem: i16 = @rem(q, @as(i16, @bitCast(lim)));
                    st.random_value.* = @bitCast(rem);
                    const ax = hi -% score;
                    if (ax <= rem) st.random_value.* = @bitCast(ax -% 1);
                    score +%= @as(i16, @bitCast(st.random_value.*));
                }
            }
            si = score;
            st.root_score.* = si;
            st.root_scores[iu] = si;
            const old = st.pv[0];
            const flag1a = env.local(L(bp, 0x1A));
            const ax: u16 = (((@as(u16, st.gives_check.*) << 8) | flag1a) & 0x8080) | move_word;
            st.pv[0] = ax;
            var same = ax == old;
            const n = st.child_pv_length.*;
            if (!(n <= 1 and same)) {
                if (st.pv_length.* <= n) {
                    same = false;
                } else if (same) {
                    // The "same line, longer" comparison.
                    const len: usize = @intCast(n - 1);
                    same = std.mem.eql(u16, st.pv[1..][0..len], st.child_pv[0..len]);
                }
                if (!same) {
                    st.pv_length.* = n;
                    const len: usize = @intCast(n - 1);
                    @memcpy(st.pv[1..][0..len], st.child_pv[0..len]);
                }
            }
            if (st.a6a0.* & 1 != 0 and st.pondering.* == 0 and st.menu_depth.* < 2) pvDisplay(st, env, bp);
            if (st.pondering.* != 0 and st.think_display.* & 2 != 0 and st.a6a1.* & 8 != 0 and st.display_off.* == 0) {
                // UNVERIFIED: the display while pondering (2B1D) is not modelled.
                env.notModelled(0x2B1D);
            }
            if (!(st.pondering.* != 0 and st.think_display.* & 2 == 0)) {
                if (st.planning_shown.* != 0 and st.display_off.* == 0)
                    _ = env.call(0x2BED, .show_move, &.{ 1, st.best_check.*, st.best_captured.*, st.w73f8.*, 0x31, 0x1B });
                if (st.pondering.* == 0) _ = env.call(0x2C1F, .show_score, &.{ 0x1B, 0x3C, w(si), showScoreKind(i, fh_pending), 0 });
            }
            if (afterNewBest(st, si, hi, lo)) |nh| {
                hi = nh;
            } else return finish(st, si, i);
            fh_pending = false;
            break;
        }
        i += 1;
        continue :moves;
    }
    return finish(st, si, i);
}

/// 2C27–2C88, after a new best: the null window for the remaining moves from depth 2,
/// the mate return and the lowering of the ply ceiling. Returns the new hi, or null for
/// the mate return ([9FD0] = 1, return si).
fn afterNewBest(st: *RootState, si: i16, hi_in: i16, lo: i16) ?i16 {
    st.root_score.* = si;
    st.fail_high_pending.* = 0;
    st.later_fail_high.* = 0;
    const d = st.depth.*;
    var hi = hi_in;
    if (d > 1 and si > -19700) hi = si +% 1;
    if (@as(i16, 19997) -% d <= si and lo < si) {
        // The mate return (2C5B).
        st.search_over.* = 1;
        return null;
    }
    if (si >= 19700 and lo < si) {
        // A score of 19700 or more lowers the ply ceiling.
        const ax = @as(i16, 20000) -% st.last_score.*;
        if (ax < st.ply_ceiling.*) st.ply_ceiling.* = ax;
    }
    return hi;
}

/// 2CA3–2DCE: the first root move failed low: extra time (timebudget.failLowExtension),
/// then main re-searches with a lower window.
fn firstMoveFailLow(st: *RootState, env: anytype, si: i16) void {
    st.root_score.* = si;
    if (st.mtg.* > 1) {
        const now: u32 = env.volatileRead(0x2CB5);
        const e: i32 = @bitCast(now -% st.start_clock.*);
        // On copies of the loop's variables (the extension writes them only when it
        // extends, and then all four limits are taken back).
        var v: tb.TimeState.Values = .{
            .computer_side = st.computer_side.* & 1,
            .mtg = st.mtg.*,
            .time_left = st.time_left.*,
            .base = st.base.*,
            .hard = st.hard.*,
            .soft = st.soft.*,
            .fail_high = st.fail_high.*,
            .clear_best = st.clear_best.*,
        };
        var ts: tb.TimeState = .{};
        ts.bindValues(&v);
        if (tb.failLowExtension(&ts, e, st.depth.*)) {
            st.base.* = v.base;
            st.hard.* = v.hard;
            st.soft.* = v.soft;
            st.fail_high.* = v.fail_high;
            st.ext_iteration.* = @bitCast(st.depth.*);
            st.stop.* = 0;
        }
    }
    st.fail_high_pending.* = 0;
}

/// 2A36–2AF0: the PV on the screen (interface calls only).
fn pvDisplay(st: *RootState, env: anytype, bp: u16) void {
    st.pv_display_ptr.* = bp -% 0x9E;
    // 2A47: memcpy of the root position (DG:8C57, 4Eh bytes) to [bp-89h], for the screen.
    _ = env.call(0x2A4F, .pv_screen_begin, &.{});
    if (st.menu_depth.* == 1 and st.w22b4.* == 8) _ = env.call(0x2A62, .pv_screen_window, &.{});
    _ = env.call(0x2A6B, .pv_screen_line, &.{st.w2660.*});
    var n: i16 = st.pv_length.*;
    if (n > 30) n = 30;
    if (n > 26 and st.w1b9c.* >= 2) n = 26;
    if (n > 24 and st.w1b9c.* >= 3) n = 24;
    const opp: i16 = @as(i8, @bitCast(st.opponent_side.*));
    var k: i16 = 1;
    while (k <= n) : (k += 1) {
        const num: u16 = w(@divTrunc(k - opp, 2)) +% st.w2660.*;
        const col = st.pv_columns[@intCast((opp + k) & 1)] +% 0x3F;
        _ = env.call(0x2AE0, .show_number, &.{ 0x93AE +% 2 * @as(u16, @bitCast(k)), col, num });
    }
    _ = env.call(0x2AEB, .pv_screen_flush, &.{});
    _ = env.call(0x2AF0, .pv_screen_end, &.{});
}

/// 2E58: [A35C] = depth, +1 if a root move was finished.
fn finish(st: *RootState, si: i16, i: i16) i16 {
    st.depth_reached.* = @as(u8, @bitCast(st.depth.*)) +% @intFromBool(i != 0);
    return si;
}

// ---------------------------------------------------------------------------
// The iteration loop (main 0000:146F–16E7)
// ---------------------------------------------------------------------------

/// Port of the iteration loop of main (0000:146F–16E7, exit at 160C): one root_search
/// per depth inside the aspiration window [A8DA] − 200 .. [A8DA] + 120, the re-search
/// below it on a fail low, the depth step (two at a time in mate mode or when winning),
/// the mate stop and the re-sort of the root list. root_search and the sort are called
/// through `env` (sites 15FA, 165D, 16E1). `bp` is main's frame pointer (the DEPTH
/// display's buffer).
pub fn iterationLoop(st: *RootState, env: anytype, bp: u16) void {
    while (true) {
        const d = st.depth.*; // 146F
        if (d >= st.loop_limit.*) {
            if (st.level.* != tb.level_infinite or d >= 35) return;
        }
        st.corr_moves.* = 0; // 148A
        if (st.level.* == tb.level_correspondence and d >= 9) {
            // UNVERIFIED: the correspondence limits never ran (§7.3).
            const n = st.legal_count.*;
            if (n > 25) {
                st.corr_moves.* = if (d == 9) 7 else 5;
            } else if (n >= 20) {
                st.corr_moves.* = @divTrunc(@as(i16, n) + 1, 2);
            }
        }
        st.ply_ceiling.* = st.default_ceiling.*; // 14CE
        if (st.mate_mode.* != 0 and @as(i16, d) + 3 < st.ply_ceiling.*) st.ply_ceiling.* = @as(i16, d) + 3;
        if (d >= st.ply_ceiling.*) st.ply_ceiling.* = st.default_ceiling.*;
        st.iteration.* = @bitCast(d); // 14FB
        st.ply_limit2.* = w(@as(i16, d) + 2);
        st.ply_limit4.* = w(@as(i16, d) + 4);
        st.ply_limit6.* = w(@as(i16, d) + 6);
        var k: i16 = 2;
        while (st.pv_length.* >= k) : (k += 1) {
            st.pv_follow[@intCast(k)] = st.pv[@intCast(k - 1)] & 0x7F7F;
        }
        if (st.planning_shown.* != 0 and (st.pondering.* == 0 or st.think_display.* & 2 != 0) and st.display_off.* == 0) {
            // 155E: sprintf("%2d", depth) into a buffer in main's frame, shown below.
            const buf = bp -% 0x2E;
            _ = env.call(0x156C, .show_at, &.{ 2, 7, 0x1B });
            _ = env.call(0x157D, .show_text, &.{ 1, 0xA, buf, 7, 0x1B });
            _ = env.call(0x1598, .show_move, &.{ 1, st.best_check.*, st.best_captured.*, st.w73f8.*, 0x17, 0x1B });
            _ = env.call(0x15A3, .show_at, &.{ 2, 0x20, 0x1B });
            _ = env.call(0x15B3, .show_text, &.{ 1, 0xA, 0x71, 0x20, 0x1B });
        }
        st.reference_score.* = @max(st.last_score.*, st.search_start_score.*); // 15B8
        var hi = aspiration_above +% st.last_score.*; // 15CA
        var lo = st.last_score.* -% aspiration_below;
        if (lo < -20000) lo = -20000;
        if (hi > 20000) hi = 20000;
        var r: i16 = @bitCast(@as(u16, @truncate(env.call(0x15FA, .root_search, &.{ w(hi), w(lo) }))));
        var store = false;
        if (r > lo) {
            store = true;
        } else if (env.volatileRead(0x1605) != 0) {
            return;
        } else {
            hi = lo +% 50;
            if (hi > 20000) hi = 20000;
            r = @bitCast(@as(u16, @truncate(env.call(0x165D, .root_search, &.{ w(hi), w(-20000) }))));
            store = r > -20000;
        }
        if (store) {
            st.last_score.* = r;
            st.root_score.* = r;
        }
        if (env.volatileRead(0x166E) != 0) return;
        if (st.analysis_hook.* != 0 and st.a38b.* & 0x10 != 0 and @as(i16, d) >= st.analysis_depth.*) {
            // UNVERIFIED: the analysis hook never ran (§7.3).
            _ = env.call(0x1691, .analysis, &.{ 0, 0 });
        }
        st.depth.* +%= 1; // 1699
        if (st.level.* == tb.level_shortest_mate or st.last_score.* > 19700) {
            // The odd-depth skip.
            if (st.depth.* & 1 != 0) st.depth.* +%= 1;
        }
        const d2: i16 = st.depth.*; // 16B7
        const sc = st.last_score.*;
        // The mate stop.
        if (!(@as(i16, 19997) -% d2 > sc)) return;
        if (!(d2 -% 19997 < sc)) return;
        _ = env.call(0x16E1, .sort_root_moves, &.{ 0x3BC4, st.root_move_count.* }); // 16D8
    }
}
