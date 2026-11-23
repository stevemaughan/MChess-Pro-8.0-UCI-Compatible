//! Tests of the generated field maps (src/dgroup_maps.zig, written by
//! tools/port/state_inventory.py):
//!
//! - at compile time, that every field of every struct with a generated map is either in
//!   the map or in `not_mapped`, each with its reason, and that every map binds to its
//!   struct (`dgroup.Map`: field names, element sizes, bounds);
//! - that the generated maps of `PrepState`, `RootState`, `TimeState` and `GameVars` place
//!   every element where the layouts their replay tests prove place it (the layouts
//!   src/engine_root.zig uses, and `gamemove.var_addresses`);
//! - that the search node's map equals its own address table (`searchnode.dg_fields`);
//! - where two units' views of one DGROUP address disagree in length or element size.
//!   Stage A copies each unit's own view (src/dgroup.zig), so these do not break the
//!   replays; each is a place Stage B, the merge into one struct of named fields, must
//!   resolve (docs/arch/60-engine-assembly.md sections 4 and 8; the same list is section
//!   2.1 of docs/arch/state-inventory.md).

const std = @import("std");
const dgroup = @import("dgroup.zig");
const maps = @import("dgroup_maps.zig");
const engine_root = @import("engine_root.zig");
const gamemove = @import("gamemove.zig");
const timebudget = @import("timebudget.zig");
const Entry = maps.Entry;

const Item = struct { file: []const u8, st: []const u8, e: Entry };

const all: []const Item = blk: {
    @setEvalBranchQuota(1_000_000);
    var items: []const Item = &.{};
    for (@typeInfo(maps).@"struct".decl_names) |file| {
        const F = @field(maps, file);
        if (@TypeOf(F) != type or @typeInfo(F) != .@"struct") continue;
        for (@typeInfo(F).@"struct".decl_names) |st| {
            const list = @field(F, st);
            const T = @TypeOf(list);
            if (@typeInfo(T) != .array or @typeInfo(T).array.child != Entry) continue;
            for (list) |e| items = items ++ &[_]Item{.{ .file = file, .st = st, .e = e }};
        }
    }
    break :blk items;
};

fn bytes(e: Entry) usize {
    return e.count * e.esize;
}

// ---------------------------------------------------------------------------
// Every field is mapped, or listed here with the reason it is not
// ---------------------------------------------------------------------------

/// The units whose structs have generated maps, by the name the maps give their file.
/// A new unit with a `DG:` comment makes the compile check below ask for its line here.
const units = .{
    .{ "book", @import("book.zig") },
    .{ "eval_state", @import("eval_state.zig") },
    .{ "evaltables", @import("evaltables.zig") },
    .{ "evalthreats", @import("evalthreats.zig") },
    .{ "evalvars", @import("evalvars.zig") },
    .{ "gamemove", gamemove },
    .{ "hashsize", @import("hashsize.zig") },
    .{ "leaf", @import("leaf.zig") },
    .{ "movegen", @import("movegen.zig") },
    .{ "position", @import("position.zig") },
    .{ "rootprep", @import("rootprep.zig") },
    .{ "rootsearch", @import("rootsearch.zig") },
    .{ "rootvars", @import("rootvars.zig") },
    .{ "searchnode", @import("searchnode.zig") },
    .{ "see", @import("see.zig") },
    .{ "setup", @import("setup.zig") },
    .{ "tablebase", @import("tablebase.zig") },
    .{ "timebudget", @import("timebudget.zig") },
};

/// Generated maps whose struct this test cannot name, with the reason.
const unreachable_structs = [_][3][]const u8{
    .{ "helpers", "Evasions", "a private struct of helpers.zig: the working set of gen_evasions (pointers, a count, square sets); its one mapped field `chk` is a local copy of the byte DG:8C06 + ply" },
    .{ "staticeval", "Fixes", "switches of class C fixes, not DGROUP state: the tool reads the DG address in a field's doc comment (DEV-053)" },
    .{ "uci_engine", "Options", "UCI options, not DGROUP state: the tool reads the DG address in a field's doc comment (Use Tablebases)" },
};

/// Fields of a mapped struct that have no map entry, with the reason. A name ending in
/// `*` stands for every field that starts with the rest.
const not_mapped = [_][4][]const u8{
    .{ "book", "BookPosition", "board", "a pointer to the search board DG:9EF6, not storage" },
    .{ "book", "BookPosition", "side", "the probe's argument, not a variable" },
    .{ "book", "Result", "early", "what the probe returns (4793:6238-625E), not a variable" },
    .{ "book", "Result", "found", "what the probe returns (a local, [bp-1Ch]), not a variable" },
    .{ "book", "Result", "display", "the book moves as the probe lists them, for the display; not a variable" },
    .{ "book", "Result", "chosen", "an optional move the probe returns; DG:38A0..38A2 hold it without the null, so dgroup.Map cannot move it (the caller writes the bytes)" },
    .{ "hashsize", "Setup", "mem", "a struct with its own map (`hashsize.Memory`)" },
    .{ "hashsize", "Setup", "tables", "a struct with its own map (`hashsize.Tables`)" },
    .{ "hashsize", "Setup", "block_kb", "the size of each XMS block allocated: the XMS driver's state, not DGROUP" },
    .{ "searchnode", "State", "_pad*", "padding between the byte ranges of `dg_fields` in the extern struct" },
    .{ "searchnode", "State", "p", "a pointer to the position the node reads and writes (`Position`, which has its own map), not storage" },
    .{ "searchnode", "State", "sv", "a pointer to the move marks and hint bytes the node writes (`movegen.SearchVars`, which has its own map), not storage" },
    .{ "searchnode", "State", "ev", "a pointer to the evaluation's flags and sums the node reads and writes (`evalvars.EvalVars`, which has its own map), not storage" },
    .{ "searchnode", "State", "lv", "a pointer to the leaf map and key history the node writes (`leaf.LeafVars`, which has its own map), not storage" },
    .{ "searchnode", "State", "tv", "a pointer to the ply limits and iteration the node reads and writes (`evalthreats.ThreatVars`, which has its own map), not storage" },
    .{ "rootprep", "PrepState", "low_page*", "a pointer to RootVars.low_page, low_page_rest (DG:0000, 0064) (`rootprep.bindRoot`, Stage B step 8, stage 7)" },
    .{ "rootprep", "PrepState", "irreversible_area", "a pointer to RootVars.irreversible_area (DG:348E) (`rootprep.bindRoot`, Stage B step 8, stage 7)" },
    .{ "rootprep", "PrepState", "board", "a pointer to Position.board (DG:9EF6) (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "attack_map", "a pointer to LeafVars.leaf_map (DG:8FE4) (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "root_moves", "a pointer to searchnode.State.move_list[1] (DG:3BC4) (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "pv", "a pointer to searchnode.State.pv[1] (DG:93B0) (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "pv_follow", "a pointer to searchnode.State.killer[0..36] (DG:3790) (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "ply_ceiling", "a pointer to searchnode.State.ply_ceiling (DG:0062) (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "margin_*", "a pointer to EvalVars.passer_rank_tables entries (DG:0154, 0168, 0172, 0186) (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "threat_count_bonus", "a pointer to searchnode.State.standpat_bonus, the first 8 words of DG:03EA (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "style_flag", "a pointer to EvalVars.style_normal (DG:1548) (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "men", "a pointer to Position.men (DG:154A) (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "tb_settings", "a pointer to the low byte of searchnode.State.tb_setting (DG:239C) (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "reverse_move*", "a pointer to Position.quiet_move_by_ply[0], [1] (DG:3626, 3628) (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "reverse_mask", "a pointer to Position.reversible_by_ply[1] (DG:8BC0) (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "pondering", "a pointer to Position.quiet_move_by_ply[40], which holds DG:3676 (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "clock_side", "a pointer to Position.ep_square_by_ply[36], which holds DG:9EEC (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "game_ply", "a pointer to Position.game_ply (DG:9FC8) (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "book_exit_ply", "a pointer to ThreatVars.board_after[78..80], which holds DG:9FBC (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "analysis", "a pointer to ThreatVars.board_after[97], which holds DG:9FCF (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "wa00a", "a pointer to see.Scratch.attackers[30..32], which holds DG:A00A (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "ba00d", "a pointer to see.Scratch.attackers[33], which holds DG:A00D (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "wa00e", "a pointer to see.Scratch.attackers[34..36], which holds DG:A00E (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "w8c30", "a pointer to Position.check_by_ply[42..44], which holds DG:8C30 (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "b9ec9", "a pointer to Position.ep_square_by_ply[1] (DG:9EC9) (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "root_in_check", "a pointer to Position.check_by_ply[1] (DG:8C07) (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "gives_check", "a pointer to Position.check_by_ply[2] (DG:8C08) (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "ep_ply2", "a pointer to Position.ep_square_by_ply[2] (DG:9ECA) (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "hard", "a pointer to EvalVars.ply_flag[36..40], which holds DG:9DB8 (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "clear_best", "a pointer to ThreatVars.black_rays_after[80], which holds DG:A22C (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "ext_iteration", "a pointer to see.Scratch.attackers[112], which holds DG:A05C (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "stop", "a pointer to searchnode.State.stop (DG:A4FA) (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "poll_requests", "a pointer to searchnode.State.poll_pending (DG:75B6) (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "white_king", "a pointer to Position.piece_list[7] (DG:A041) (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "black_king", "a pointer to Position.piece_list[23] (DG:A051) (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "hash_key", "a pointer to Position.hash_key (DG:8CCC) (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "pawn_hash_key", "a pointer to Position.pawn_hash_key (DG:8CD2) (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "root_key", "a pointer to LeafVars.key_history[1] (DG:9DC4) (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "w7182", "a pointer to Position.piece_square_sum (DG:7182) (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "w90b6", "a pointer to EvalVars.pawn_square_sum[0] (DG:90B6) (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "w369a", "a pointer to EvalVars.pawn_square_sum[1] (DG:369A) (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "material_balance", "a pointer to Position.material_balance (DG:A35E) (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "material_total", "a pointer to Position.total_material (DG:A420) (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "root_balance", "a pointer to searchnode.State.root_material_balance (DG:A05A) (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "root_total", "a pointer to searchnode.State.root_material_total (DG:A35A) (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "white_pieces", "a pointer to Position.piece_count[0] (DG:931A) (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "black_pieces", "a pointer to Position.piece_count[1] (DG:931B) (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "both_have_pieces", "a pointer to searchnode.State.both_had_pieces (DG:A6C6) (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "white_nonpawn", "a pointer to Position.piece_material[0] (DG:AE38) (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "black_nonpawn", "a pointer to Position.piece_material[1] (DG:AE3A) (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "passed_threat", "a pointer to EvalVars.passer_flags (DG:A5F5) (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "static_only", "a pointer to EvalVars.draw_flag (DG:A8DE) (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "current_move", "a pointer to see.Scratch.attackers[76..78], which holds DG:A038 (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "b741e", "a pointer to searchnode.State.extension[0..36] (DG:741E) (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "score_white_view", "a pointer to searchnode.State.prev_score_white (DG:A418) (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "score_black_view", "a pointer to searchnode.State.prev_score_black (DG:8DE8) (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "tb_score", "a pointer to searchnode.State.tb_score (DG:7466) (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "search_over", "a pointer to ThreatVars.board_after[98], which holds DG:9FD0 (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "depth", "a pointer to searchnode.State.horizon (DG:744E) (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "iteration", "a pointer to ThreatVars.iteration (DG:A3F4) (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "ply_limit*", "a pointer to ThreatVars.ply_limit1..3 (DG:A272, 9356, A5EC) (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "nodes", "a pointer to searchnode.State.node_count (DG:740A) (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "ba40e", "a pointer to ThreatVars.mate_switch (DG:A40E) (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "b9eb6", "a pointer to byte 2 of LeafVars.key_history[41], which holds DG:9EB6 (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "wa002", "a pointer to see.Scratch.attackers[22..24], which holds DG:A002 (`rootprep.bindDomain`, stage 3c-1)" },
    .{ "rootprep", "PrepState", "root_copy", "a pointer to ProgramVars.setup_board (DG:8C57) (`rootprep.bindRoot`, Stage B step 8, stage 7)" },
    .{ "rootprep", "PrepState", "root_scores", "a pointer to RootVars.root_scores (DG:8D0A) (`rootprep.bindRoot`, Stage B step 8, stage 7)" },
    .{ "rootsearch", "RootState", "root_moves", "a pointer to searchnode.State.move_list[1] (`rootsearch.bindDomain`, stage 3b)" },
    .{ "rootsearch", "RootState", "pv", "a pointer to searchnode.State.pv[1] (`rootsearch.bindDomain`, stage 3b)" },
    .{ "rootsearch", "RootState", "root_scores", "a pointer to RootVars.root_scores (DG:8D0A) (`rootsearch.bindRoot`, Stage B step 8, stage 7)" },
    .{ "rootsearch", "RootState", "child_pv", "a pointer to searchnode.State.pv[2] (`rootsearch.bindDomain`, stage 3b)" },
    .{ "rootsearch", "RootState", "pv_follow", "a pointer to searchnode.State.killer (`rootsearch.bindDomain`, stage 3b)" },
    .{ "rootsearch", "RootState", "board", "a pointer to Position.board (`rootsearch.bindDomain`, stage 3b)" },
    // Stage B step 7, stage 3b: the loop's variables the node domain holds, reached there.
    .{ "rootsearch", "RootState", "current_move", "a pointer to see.Scratch.attackers[76..78], which holds DG:A038 (`rootsearch.bindDomain`)" },
    .{ "rootsearch", "RootState", "search_over", "a pointer to ThreatVars.board_after[98], which holds DG:9FD0 (`rootsearch.bindDomain`)" },
    .{ "rootsearch", "RootState", "child_pv_length", "a pointer to searchnode.State.pv_end[2] (DG:AAF8, `rootsearch.bindDomain`)" },
    .{ "rootsearch", "RootState", "depth", "a pointer to searchnode.State.horizon (DG:744E, `rootsearch.bindDomain`)" },
    .{ "rootsearch", "RootState", "iteration", "a pointer to ThreatVars.iteration (DG:A3F4, `rootsearch.bindDomain`)" },
    .{ "rootsearch", "RootState", "ply_ceiling", "a pointer to searchnode.State.ply_ceiling (DG:0062, `rootsearch.bindDomain`)" },
    .{ "rootsearch", "RootState", "ply_limit*", "pointers to ThreatVars.ply_limit1..3 (DG:A272, 9356, A5EC, `rootsearch.bindDomain`)" },
    .{ "rootsearch", "RootState", "mate_mode", "a pointer to searchnode.State.mode_1e08 (DG:1E08, `rootsearch.bindDomain`)" },
    .{ "rootsearch", "RootState", "hard", "a pointer to EvalVars.ply_flag[36..40], which holds DG:9DB8 (`rootsearch.bindDomain`)" },
    .{ "rootsearch", "RootState", "clear_best", "a pointer to ThreatVars.black_rays_after[80], which holds DG:A22C (`rootsearch.bindDomain`)" },
    .{ "rootsearch", "RootState", "ext_iteration", "a pointer to see.Scratch.attackers[112], which holds DG:A05C (`rootsearch.bindDomain`)" },
    .{ "rootsearch", "RootState", "stop", "a pointer to searchnode.State.stop (DG:A4FA, `rootsearch.bindDomain`)" },
    .{ "rootsearch", "RootState", "pondering", "a pointer to Position.quiet_move_by_ply[40], which holds DG:3676 (`rootsearch.bindDomain`)" },
    .{ "rootsearch", "RootState", "gives_check", "a pointer to Position.check_by_ply[2] (DG:8C08, `rootsearch.bindDomain`)" },
    .{ "rootsearch", "RootState", "white_bishops", "a pointer to Position.piece_list[2..4] (DG:A03C, `rootsearch.bindDomain`)" },
    .{ "rootsearch", "RootState", "black_bishops", "a pointer to Position.piece_list[18..20] (DG:A04C, `rootsearch.bindDomain`)" },
    .{ "rootsearch", "RootState", "piece_count", "a pointer to Position.men (DG:154A, `rootsearch.bindDomain`)" },
    .{ "rootsearch", "RootState", "tb_flags", "a pointer to searchnode.State.tb_setting (DG:239C, `rootsearch.bindDomain`)" },
    .{ "rootsearch", "RootState", "tb_score", "a pointer to searchnode.State.tb_score (DG:7466, `rootsearch.bindDomain`)" },
    .{ "rootsearch", "RootState", "draw_mask", "a pointer to Position.reversible_by_ply[1] (DG:8BC0, `rootsearch.bindDomain`)" },
    .{ "rootsearch", "RootState", "draw_move", "a pointer to Position.quiet_move_by_ply[0] (DG:3626, `rootsearch.bindDomain`)" },
    .{ "rootsearch", "RootState", "w7182", "a pointer to Position.piece_square_sum (DG:7182, `rootsearch.bindDomain`)" },
    .{ "rootsearch", "RootState", "w90b6", "a pointer to EvalVars.pawn_square_sum[0] (DG:90B6, `rootsearch.bindDomain`)" },
    .{ "rootsearch", "RootState", "w369a", "a pointer to EvalVars.pawn_square_sum[1] (DG:369A, `rootsearch.bindDomain`)" },
    .{ "rootsearch", "RootState", "hash_key", "a pointer to Position.hash_key (DG:8CCC, `rootsearch.bindDomain`)" },
    .{ "rootsearch", "RootState", "pawn_hash_key", "a pointer to Position.pawn_hash_key (DG:8CD2, `rootsearch.bindDomain`)" },
    .{ "rootsearch", "RootState", "random_off", "a pointer to EvalVars.style_normal (DG:1548, `rootsearch.bindDomain`)" },
    .{ "rootsearch", "RootState", "think_display", "a pointer to searchnode.State.pv_end[36], which holds DG:AB1A (`rootsearch.bindDomain`)" },
    .{ "rootsearch", "RootState", "pv_display_ptr", "a pointer to Position.quiet_move_by_ply[48], which holds DG:3686 (`rootsearch.bindDomain`)" },
    .{ "leaf", "LeafVars", "past_board", "no longer read (DEV-018 skipped); its home is ThreatVars.board_after (Stage B step 5)" },
    .{ "evalvars", "EvalVars", "past_board", "no longer read but by activity_reference.zig (DEV-018 skipped); its home is ThreatVars.board_after (Stage B step 5)" },
    .{ "tablebase", "State", "signatures", "a slice: the material signatures at DG:A422 are given to the probe by its caller" },
    .{ "timebudget", "PonderInputs", "elapsed", "clock minus [A8E8], computed by the caller, not a variable" },
};

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

fn nameMatches(pattern: []const u8, name: []const u8) bool {
    if (pattern.len > 0 and pattern[pattern.len - 1] == '*') return std.mem.startsWith(u8, name, pattern[0 .. pattern.len - 1]);
    return eql(pattern, name);
}

fn listedNotMapped(comptime file: []const u8, comptime st: []const u8, comptime field: []const u8) bool {
    // GameVars' pointer fields (Stage B step 8, stage 2): each points at its variable's
    // one home, a member of the node domain or the image (`engine_state` `bindGameVars`,
    // `GameVars.bindImage`), and is not storage.
    if (eql(file, "gamemove") and eql(st, "GameVars") and gamemove.isPointerVar(field)) return true;
    // TimeState's likewise (stage 5: `engine_state` `bindTimeState`, `TimeState.bindImage`).
    if (eql(file, "timebudget") and eql(st, "TimeState") and timebudget.isPointerVar(field)) return true;
    for (not_mapped) |n| {
        if (eql(n[0], file) and eql(n[1], st) and nameMatches(n[2], field)) return true;
    }
    return false;
}

fn inMap(comptime list: anytype, comptime field: []const u8) bool {
    for (list) |e| {
        if (eql(e.field, field)) return true;
    }
    return false;
}

fn isUnreachable(comptime file: []const u8, comptime st: []const u8) bool {
    for (unreachable_structs) |u| {
        if (eql(u[0], file) and eql(u[1], st)) return true;
    }
    return false;
}

fn unitOf(comptime file: []const u8) ?type {
    inline for (units) |u| {
        if (comptime eql(u[0], file)) return u[1];
    }
    return null;
}

/// The number of structs the compile check below covers (to show it ran).
const structs_checked: usize = blk: {
    @setEvalBranchQuota(2_000_000);
    var n: usize = 0;
    for (@typeInfo(maps).@"struct".decl_names) |file| {
        const F = @field(maps, file);
        if (@TypeOf(F) != type or @typeInfo(F) != .@"struct") continue;
        for (@typeInfo(F).@"struct".decl_names) |st| {
            const list = @field(F, st);
            const L = @TypeOf(list);
            if (@typeInfo(L) != .array or @typeInfo(L).array.child != Entry) continue;
            if (isUnreachable(file, st)) continue;
            const M = unitOf(file) orelse @compileError("dgroup_test: maps." ++ file ++ " has no line in `units`");
            if (!@hasDecl(M, st)) @compileError("dgroup_test: " ++ file ++ ".zig has no public struct " ++ st ++ " (list it in `unreachable_structs`)");
            const T = @field(M, st);
            // Every field of the struct: in the map, or listed with a reason.
            for (@typeInfo(T).@"struct".field_names) |fname| {
                const mapped = inMap(list, fname);
                const listed = listedNotMapped(file, st, fname);
                if (!mapped and !listed) @compileError("dgroup maps: " ++ file ++ "." ++ st ++ "." ++ fname ++ " has no map entry and no line in `not_mapped`: re-run tools/port/state_inventory.py, or give the reason it is not DGROUP state");
                if (mapped and listed) @compileError("dgroup maps: " ++ file ++ "." ++ st ++ "." ++ fname ++ " is mapped and also listed in `not_mapped`");
            }
            // The map binds to the struct (field names, element sizes, bounds).
            _ = dgroup.Map(T, &list);
            n += 1;
        }
    }
    // Every line of `not_mapped` names a field that exists.
    for (not_mapped) |nm| {
        const M = unitOf(nm[0]) orelse @compileError("dgroup_test: not_mapped names an unknown unit " ++ nm[0]);
        const T = @field(M, nm[1]);
        var found = false;
        for (@typeInfo(T).@"struct".field_names) |fname| {
            if (nameMatches(nm[2], fname)) found = true;
        }
        if (!found) @compileError("dgroup_test: not_mapped names " ++ nm[0] ++ "." ++ nm[1] ++ "." ++ nm[2] ++ ", which does not exist");
    }
    break :blk n;
};

test "dgroup: every field of a mapped struct is in its map or listed as not DGROUP state (checked at compile time)" {
    // 26 since Stage B step 6 (eval_state.EvalState is evalvars.EvalVars); 25 since step 7,
    // stage 3c-2: evaltables.Tables is pointers (no generated map), its values' map is built
    // from `Tables.dg` (adapt_eval.TablesMap).
    try std.testing.expect(structs_checked >= 25);
}

// ---------------------------------------------------------------------------
// The root's maps equal the layouts the replay tests prove
// ---------------------------------------------------------------------------

/// Whether `list` places element `elem` of `field` (element size `esize`) at `addr`.
fn places(list: []const Entry, field: []const u8, elem: usize, addr: usize, esize: usize) bool {
    for (list) |e| {
        if (!eql(e.field, field) or e.esize != esize) continue;
        if (elem < e.first or elem >= e.first + e.count) continue;
        if (@as(usize, e.addr) + (elem - e.first) * esize == addr) return true;
    }
    return false;
}

/// Every element `a` places, `b` places at the same address with the same size, and the
/// other way round: the two maps cover the same bytes with the same elements.
fn sameLayout(name: []const u8, a: []const Entry, a_name: []const u8, b: []const Entry, b_name: []const u8) !void {
    var bad: usize = 0;
    for ([2][]const Entry{ a, b }, 0..) |x, side| {
        const y = if (side == 0) b else a;
        for (x) |e| {
            for (0..e.count) |i| {
                const addr = @as(usize, e.addr) + i * e.esize;
                if (places(y, e.field, e.first + i, addr, e.esize)) continue;
                bad += 1;
                if (bad <= 10) std.debug.print("{s}.{s}[{d}] at DG:{X:0>4} ({d} bytes) is in {s} but not in {s}\n", .{
                    name, e.field, e.first + i, addr, e.esize, if (side == 0) a_name else b_name, if (side == 0) b_name else a_name,
                });
                break;
            }
        }
    }
    if (bad != 0) return error.GeneratedMapDiffersFromProvedLayout;
}

test "dgroup: the generated maps of RootVars and ProgramVars equal their address tables (rootvars `dg`)" {
    // Stage B step 8, stage 7: the views' fields are all pointers (no map); their variables
    // are these two members', every field a value with an address in its `dg`.
    const rvm = @import("rootvars.zig");
    const rv_table = rvm.mapOf(rvm.RootVars);
    const pg_table = rvm.mapOf(rvm.ProgramVars);
    try sameLayout("rootvars.RootVars", &maps.rootvars.RootVars, "the generated map", &rv_table, "RootVars.dg");
    try sameLayout("rootvars.ProgramVars", &maps.rootvars.ProgramVars, "the generated map", &pg_table, "ProgramVars.dg");
    // Every field of a view that `bindRoot` binds lies inside one of their fields at the
    // address the view's layout (proved by its replay test) gives it: `rootvars.place`
    // checks that at compile time, so a place for each is enough here.
    @setEvalBranchQuota(1_000_000);
    var placed: usize = 0;
    inline for (@import("rootprep.zig").layout ++ @import("rootsearch.zig").layout) |l| {
        if (comptime rvm.place(l[1], 1) != null) placed += 1;
    }
    try std.testing.expectEqual(@as(usize, 64 + 48), placed);
}

test "dgroup: the generated map of timebudget.TimeState equals timebudget.var_addresses" {
    // The value fields (Stage B step 8, stage 5: the pointer fields are bound to their
    // homes, not stored, and the generated map leaves them out). The addresses are those
    // the replay test of rootprep and the time budget's own replay prove (the former
    // `engine_root.time_layout`).
    const T = timebudget.TimeState;
    const fields = @typeInfo(T).@"struct".field_names;
    comptime var n: usize = 0;
    inline for (fields) |f| {
        if (comptime !timebudget.isPointerVar(f)) n += 1;
    }
    var from_table: [n]Entry = undefined;
    var i: usize = 0;
    inline for (fields) |f| {
        if (comptime timebudget.isPointerVar(f)) continue;
        const F = @FieldType(T, f);
        from_table[i] = .{ .field = f, .first = 0, .count = dgroup.flatLen(F), .addr = @field(timebudget.var_addresses, f), .esize = dgroup.elemSize(dgroup.Flat(F)) };
        i += 1;
    }
    try sameLayout("timebudget.TimeState", &maps.timebudget.TimeState, "the generated map", &from_table, "timebudget.var_addresses");
    // Every field has an address, and the time budget's addresses are main's where both
    // declare a variable (PrepState's layout, proved by the rootprep replay).
    @setEvalBranchQuota(100_000);
    inline for (fields) |f| {
        const a: u16 = @field(timebudget.var_addresses, f);
        inline for (engine_root.prep_layout) |l| {
            if (comptime eql(l[0], f)) try std.testing.expectEqual(l[1], a);
        }
    }
}

test "dgroup: the generated map of gamemove.GameVars equals gamemove.var_addresses" {
    // The value fields (Stage B step 8, stage 2: the pointer fields are bound to their
    // homes, not stored, and the generated map leaves them out).
    const T = gamemove.GameVars;
    const fields = @typeInfo(T).@"struct".field_names;
    comptime var n: usize = 0;
    inline for (fields) |f| {
        if (comptime !gamemove.isPointerVar(f)) n += 1;
    }
    var from_table: [n]Entry = undefined;
    var i: usize = 0;
    inline for (fields) |f| {
        if (comptime gamemove.isPointerVar(f)) continue;
        const F = @FieldType(T, f);
        from_table[i] = .{ .field = f, .first = 0, .count = dgroup.flatLen(F), .addr = @field(gamemove.var_addresses, f), .esize = dgroup.elemSize(dgroup.Flat(F)) };
        i += 1;
    }
    try sameLayout("gamemove.GameVars", &maps.gamemove.GameVars, "the generated map", &from_table, "gamemove.var_addresses");
}

test "dgroup: the comparison of layouts catches a field moved by one byte" {
    const rvm = @import("rootvars.zig");
    const rv_table = rvm.mapOf(rvm.RootVars);
    var moved = maps.rootvars.RootVars;
    moved[3].addr += 1;
    try std.testing.expectError(error.GeneratedMapDiffersFromProvedLayout, sameLayout("check", &moved, "moved", &rv_table, "proved"));
}

// ---------------------------------------------------------------------------
// The search node's map, and the units' disagreements
// ---------------------------------------------------------------------------

/// Pairs of entries of different structs that start at one address with different
/// lengths or element sizes.
fn disagreements(out: ?*std.ArrayList([2]Item), gpa: std.mem.Allocator) !usize {
    var n: usize = 0;
    for (all, 0..) |a, i| {
        for (all[i + 1 ..]) |b| {
            if (a.e.addr != b.e.addr) continue;
            if (std.mem.eql(u8, a.file, b.file) and std.mem.eql(u8, a.st, b.st)) continue;
            if (bytes(a.e) == bytes(b.e) and a.e.esize == b.e.esize) continue;
            n += 1;
            if (out) |o| try o.append(gpa, .{ a, b });
        }
    }
    return n;
}

fn has(list: []const [2]Item, addr: u16, a_field: []const u8, b_field: []const u8) bool {
    for (list) |p| {
        if (p[0].e.addr != addr) continue;
        const f0 = p[0].e.field;
        const f1 = p[1].e.field;
        if ((std.mem.eql(u8, f0, a_field) and std.mem.eql(u8, f1, b_field)) or (std.mem.eql(u8, f0, b_field) and std.mem.eql(u8, f1, a_field))) return true;
    }
    return false;
}

test "dgroup: units whose views of one address disagree in length (printed; Stage B must resolve each)" {
    const gpa = std.testing.allocator;
    var list: std.ArrayList([2]Item) = .empty;
    defer list.deinit(gpa);
    const n = try disagreements(&list, gpa);
    std.debug.print("dgroup maps: {d} entries; {d} pairs of units disagree at one start address:\n", .{ all.len, n });
    for (list.items) |p| {
        std.debug.print("  DG:{X:0>4}  {s}.{s}.{s} {d} bytes (elements of {d})  vs  {s}.{s}.{s} {d} bytes (elements of {d})\n", .{
            p[0].e.addr, p[0].file, p[0].st,      p[0].e.field,  bytes(p[0].e), p[0].e.esize,
            p[1].file,   p[1].st,   p[1].e.field, bytes(p[1].e), p[1].e.esize,
        });
    }
    // The ones the plan names (docs/arch/60-engine-assembly.md section 1) must be found.
    // Resolved since: DG:3766 is 40 bytes in both (the node's read past H = 31, 2026-11-20).
    try std.testing.expect(!has(list.items, 0x3766, "table_3766", "qs_max_ply"));
    // DG:781A: one declaration, `SearchVars.marks` (the node's since step 3; the root's
    // `PrepState` and `RootState` reach the table through their env since step 7).
    try std.testing.expect(!has(list.items, 0x781A, "marks", "marks"));
    inline for (maps.searchnode.State) |e| try std.testing.expect(e.addr != 0x781A);
    // Resolved since: DG:7260 is 100 words in both (Stage B step 6, the tables at the original's length).
    try std.testing.expect(!has(list.items, 0x7260, "king_table", "king_white"));
    try std.testing.expect(has(list.items, 0x239C, "tb_setting", "mode")); // a word against a byte
}

test "dgroup: the search node's generated map equals its own address table (searchnode.dg_fields)" {
    const sn = @import("searchnode.zig");
    const map = maps.searchnode.State;
    for (sn.dg_fields) |f| {
        var found = false;
        for (map) |e| {
            if (std.mem.eql(u8, e.field, f.name)) {
                found = true;
                if (e.addr != f.addr or bytes(e) != f.len) {
                    std.debug.print("searchnode.State.{s}: map DG:{X:0>4} {d} bytes, dg_fields DG:{X:0>4} {d} bytes\n", .{ f.name, e.addr, bytes(e), f.addr, f.len });
                    return error.MapDisagreesWithTransfer;
                }
            }
        }
        if (!found) {
            std.debug.print("searchnode.State.{s} is in dg_fields but not in the map\n", .{f.name});
            return error.MapDisagreesWithTransfer;
        }
    }
}
