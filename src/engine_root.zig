//! Stage A, steps 11 to 13 (docs/arch/60-engine-assembly.md section 5), and Stage B: the
//! root of the search joined to the real routines, on the engine's members.
//!
//! `main` before the iteration loop (src/rootprep.zig, 0000:0526-146E) and the iteration
//! loop with root_search and the root sort (src/rootsearch.zig, 0000:146F-16E7,
//! 0000:22C0, 0000:668E) reach every routine they call through an `env`. This file is
//! the engine's `env` for both: each callee is bound to its ported routine on the node
//! domain's members (src/engine_state.zig), and the search node and the ply-2 node to the
//! domain. The root's own state (`PrepState`, `RootState`) is a view: in Stage A of the
//! image, written into it before each callee and reloaded after it; since Stage B step 8,
//! stage 7, of the members, every field a pointer to its variable's one home (the node
//! domain's structs, and `rootvars.RootVars` and `ProgramVars` for the root's own variables
//! and every other variable no unit's struct holds), so that nothing is copied.
//!
//! **No image** (Stage B step 8, stage 8). The engine holds no image of DGROUP and no far
//! segment: the members are decoded once from the executable's initialised data at
//! start-up (`init`, `startUp`) and are the state from then on; the far segment 5A7B is the
//! game record `rec` (`gamemove.GameRecord`), addressed by offset where main forms one
//! (`farByte`, `setFarWord`). The tests load the root from an oracle's image and compare it
//! with one through src/state_image.zig, the tests' codec, on the root's test image (`test_img`,
//! `test_far`: fields of the test build only). The pawn hash tables are the node's `PawnHash`;
//! the main hash tables (XMS in the original) are two `searchnode.HashTable`s.
//!
//! | Callee (rootprep / rootsearch)         | Original           | Bound to |
//! | -------------------------------------- | ------------------ | -------- |
//! | screen and display routines            | 38C0:*, 1E9D:7144.. | nothing (user interface) |
//! | reset_move_time_used, clocks_run, delay, poll, clear_excluded, hash_seed_learning | 1E9D:7E8A, 6AE8, 562A, 7514; 0000:6F2E, 89D0 | nothing (clock, keyboard, excluded-move list, learning: off) |
//! | moves_to_go, add_control_time, set_time_budget | 0000:8B7E, 1E9D:6F48, 0000:8C3E | src/timebudget.zig on `TimeState` |
//! | book_probe                             | 4793:621E          | src/book.zig `probe` on `book_files` (the engine' embedded book); without files, the gate and book-exit ply with the M-Chess book off (DG:A5EE). A drawn move that fails an independent legality test is a book miss (AGENTS.md section 9.3) |
//! | play_best_move (main 06EF, a book move) | 38C0:01E0          | gamemove.playBestMove(arg 1) on the move DG:38A0, on the domain's structs and the record |
//! | prepare_eval                           | 0000:9582          | src/evaltables.zig on the domain's structs (`prepareEvalDomain`); then the root key into the game record and the pawn hash cleared (0000:960A, 8B50) |
//! | hash_resize, hash_clear                | 0000:6C3A, 88CC    | src/hashsize.zig `resize`; `HashTable.clear` |
//! | gen_evasions, gen_all_moves            | 38C0:E260, 1E9D:3938 | the domain's generators (movegen, helpers; DEV-003 corrected) |
//! | square_sums, hash_key, make, unmake    | 0000:678A, 4793:3EA2, 1E9D:000C, 0960 | `Position` and `squaresums` on the domain's structs (DEV-001 as `fixes`) |
//! | tb_probe                               | 2B9F:BB76          | src/tablebase.zig (files from the caller; DEV-025 corrected) on the domain's `Position` |
//! | attack_map_white / _black              | 2B9F:40A8 / 42DA   | leaf.leafAttackMap(.white / .black) |
//! | repetition                             | 2B9F:402A          | rootprep.repetitionCount on the game record's keys |
//! | has_legal_move                         | 2B9F:458A          | gamemove.legalMoveExists |
//! | node_white / node_black                | 0000:3AC6 / 5036   | the node domain (src/engine_state.zig), which `search` enters once for main and the loop |
//! | root_move_search                       | 0000:2EC8          | `searchnode.Node(Ctx).searchPly2` in the node domain, which the loop is inside |
//! | keep_fail_high                         | 0000:8FE6          | rootsearch.keepFailHigh |
//! | pawn_eval_wtm / _btm                   | 0EF8:89DC / 8F82   | evalpawns.pawnEval on the domain (the evaluator itself, not the probe) |
//! | static_eval                            | 2B9F:000E          | the domain's static_eval (DEV-015 corrected) |
//! | hanging_black / hanging_white          | 2B9F:4BFE / 5534   | leaf.hangingPieces(.white / .black) through the node's binding |
//! | pieces_and_kings, activity_*, endgame_king_*, count_attacked_*, threats_* | 0EF8:0006, 1E9D:16E4/1E30, 3416/35FB, CE3E/CC4E, 0EF8:A026/CD20 | the node domain's bindings |
//! | rand                                   | 4793:89D8          | the C rand() on DG:2DC8 |
//! | root_search, sort_root_moves (from the loop) | 0000:22C0, 668E | rootsearch.rootSearch, sortRootMoves |
//!
//! A `Hook` (tests only) sees every call before and after it; the mixed-mode tests
//! (src/engine_root_test.zig) use it to compare each real callee's effects with the ones
//! the original recorded, and to answer from the recording the calls whose inputs the
//! recordings do not hold.
//!
//! Main before the loop, the iteration loop and the search below them run in the node
//! domain (Stage B step 7, stages 3b, 3c-1 and 3c-2: `search`): main's and the loop's views
//! point at the domain's structs for every variable they hold (`rootprep.bindDomain`,
//! `rootsearch.bindDomain`), and their callees run on them (`dispatchPrepDomain`,
//! `dispatchLoop`); prepare_eval's tables point at them too (`evaltables.bindDomain`).
//! Since Stage B step 8, stage 5, the last of main's callees that ran on the image (the
//! time budget, the book and its legality test, hash_resize, rand) run in the domain too:
//! the time budget on its member `Members.ts` (`timebudget.TimeState`, whose pointer fields
//! reach the members), the book on the domain's `Position`, the others at
//! each variable's home (`dgByte`, `home`). `PrepEnv.call` brackets no callee.
//!
//! Since Stage B step 8, stage 2, the game's variables (`gamemove.GameVars`, a member of
//! the domain) and the game record (`rec`) are persistent too, and play_best_move,
//! check_entered_move and play_entered_move run on them (`DomainGameCtx`). Since
//! stage 3 set_predicted_reply and every routine it calls run on them too: the ply-0
//! generators, make and take-back, prepare_eval and the evaluator terms
//! (`replyDispatch`), with no bracket.

const std = @import("std");
const builtin = @import("builtin");
const dgroup = @import("dgroup.zig");
const pos = @import("position.zig");
const sn = @import("searchnode.zig");
const rs = @import("rootsearch.zig");
const rp = @import("rootprep.zig");
const tbud = @import("timebudget.zig");
const hashsize = @import("hashsize.zig");
const book = @import("book.zig");
const tablebase = @import("tablebase.zig");
const leaf = @import("leaf.zig");
const gamemove = @import("gamemove.zig");
const legality = @import("legality.zig");
const mg = @import("movegen.zig");
const se = @import("staticeval.zig");
const PawnHash = @import("pawnhash.zig").PawnHash;
const ev = @import("evalvars.zig");
const squaresums = @import("squaresums.zig");
const evalpawns = @import("evalpawns.zig");
const activity = @import("activity.zig");
const setup = @import("setup.zig");
const est = @import("engine_state.zig");
const evaltables = @import("evaltables.zig");
const newgame = @import("newgame.zig");
const gameslide = @import("gameslide.zig");
const rvm = @import("rootvars.zig");
/// The tests' codec (test builds only: the engine build never reaches it).
const si = @import("state_image.zig");

const Image = dgroup.Image;
/// The far segment 5A7B as an image (the tests' far segment, `EngineRoot.test_far`).
pub const Far = [0x10000]u8;

/// What hash_resize reads and leaves, on a store by address (`dgroup.ImageMem`, or
/// `EngineRoot.Home`): DG:12C6 (size), B624 (XMS mask), 9316 (3/4 mode), A3F8 (present), 005A
/// (bytes per table), AB9C (conventional mask).
pub fn hashTablesAt(m: anytype) hashsize.Tables {
    return .{
        .size_kb = @bitCast(dgroup.memDword(m, 0x12C6)),
        .mask = dgroup.memDword(m, 0xB624),
        .mode = m.get(0x9316),
        .enabled = dgroup.memWord(m, 0xA3F8),
        .table_bytes = @bitCast(dgroup.memDword(m, 0x005A)),
        .conv_mask = dgroup.memWord(m, 0xAB9C),
    };
}

/// Port of hash_resize (0000:6C3A-6F2D, src/hashsize.zig `resize`) on a store by address:
/// the request DG:12C6, the memory DG:00E2, DG:AC28, DG:9352; writes what `hashTablesAt`
/// reads.
pub fn hashResizeAt(m: anytype) hashsize.Tables {
    const mem: hashsize.Memory = .{
        .avail_kb = @bitCast(dgroup.memDword(m, 0x00E2)),
        .conv = @bitCast(m.get(0xAC28)),
        .xms_ready = m.get(0x9352) != 0,
    };
    const old = hashTablesAt(m);
    const t = hashsize.resize(old.size_kb, mem, old);
    dgroup.memSetDword(m, 0x12C6, @bitCast(t.size_kb));
    dgroup.memSetDword(m, 0xB624, t.mask);
    m.set(0x9316, t.mode);
    dgroup.memSetWord(m, 0xA3F8, t.enabled);
    dgroup.memSetDword(m, 0x005A, @bitCast(t.table_bytes));
    dgroup.memSetWord(m, 0xAB9C, t.conv_mask);
    return t;
}

/// The Settings / Hash-tables dialog's effect on a store by address (38C0:4C91-4CC6;
/// src/hashsize.zig `menu`): a negative value is ignored; otherwise [12CA] = [12C6] = the
/// typed value, hash_resize, and with no tables left [12CA] = [12C6] = 0. Returns whether
/// the dialog then clears the tables (clear_hash_tables, 0000:88CC), which the caller does.
pub fn hashMenuAt(m: anytype, typed_kb: i32) bool {
    if (typed_kb < 0) return false;
    dgroup.memSetDword(m, 0x12CA, @bitCast(typed_kb));
    dgroup.memSetDword(m, 0x12C6, @bitCast(typed_kb));
    if (hashResizeAt(m).enabled != 0) return true;
    dgroup.memSetDword(m, 0x12CA, 0);
    dgroup.memSetDword(m, 0x12C6, 0);
    return false;
}

// ---------------------------------------------------------------------------
// The root's views
// ---------------------------------------------------------------------------

/// The DGROUP address of each `rootprep.PrepState` field but its tables (the layout its
/// replay test proves, src/rootprep_test.zig).
pub const prep_layout = rp.layout;

/// The DGROUP address of each `rootsearch.RootState` field but its tables (the layout its
/// replay test proves, src/rootsearch_test.zig).
pub const root_layout = rs.layout;

/// Whether a field of `layout` (a view's, its fields pointers) declares DGROUP byte `a`.
fn viewCovers(comptime V: type, comptime layout: anytype, a: usize) bool {
    inline for (layout) |l| {
        const n = comptime rvm.originalSize(@typeInfo(@FieldType(V, l[0])).pointer.child);
        if (a >= l[1] and a < @as(usize, l[1]) + n) return true;
    }
    return false;
}

/// Whether a field of main's or the loop's view, a variable or a table, declares DGROUP
/// byte `a`.
pub fn viewDeclares(a: usize) bool {
    return viewCovers(rp.PrepState, rp.layout ++ rp.tables, a) or viewCovers(rs.RootState, rs.layout ++ rs.tables, a);
}

/// `timebudget.TimeState`'s value fields on the image (Stage B step 8, stage 5: its
/// pointer fields are bound to their homes; `timebudget.var_addresses` gives every
/// field's address).
pub const TimeMap = est.TimeStateMap;

/// Whether a field of `timebudget.TimeState`, a value or a pointer, declares DGROUP byte `a`.
pub fn timeStateCovers(a: usize) bool {
    inline for (@typeInfo(@TypeOf(tbud.var_addresses)).@"struct".field_names) |n| {
        const lo: usize = @field(tbud.var_addresses, n);
        if (a >= lo and a < lo + comptime tbud.varBytes(n)) return true;
    }
    return false;
}

fn entriesFromAddresses(comptime T: type, comptime addresses: anytype) [@typeInfo(T).@"struct".field_names.len]dgroup.Entry {
    @setEvalBranchQuota(100_000);
    const fs = @typeInfo(T).@"struct".field_names;
    var out: [fs.len]dgroup.Entry = undefined;
    for (fs, 0..) |f, i| {
        const F = @FieldType(T, f);
        out[i] = .{ .field = f, .first = 0, .count = dgroup.flatLen(F), .addr = @field(addresses, f), .esize = dgroup.elemSize(dgroup.Flat(F)) };
    }
    return out;
}

const game_record_entries = entriesFromAddresses(gamemove.GameRecord, gamemove.record_offsets);
/// `gamemove.GameVars`' value fields on the image (its pointer fields are bound to their
/// homes); `gamemove.GameRecord` on `Far` (offsets in segment 5A7B).
pub const GameVarsMap = est.GameVarsMap;
pub const GameRecordMap = dgroup.Map(gamemove.GameRecord, &game_record_entries);

/// Whether a field of `gamemove.GameVars`, a value or a pointer, declares DGROUP byte `a`.
pub fn gameVarsCover(a: usize) bool {
    inline for (@typeInfo(@TypeOf(gamemove.var_addresses)).@"struct".field_names) |n| {
        const lo: usize = @field(gamemove.var_addresses, n);
        if (a >= lo and a < lo + comptime gamemove.varBytes(n)) return true;
    }
    return false;
}
pub const SetupVarsMap = dgroup.Map(setup.SetupVars, &dgroup.maps.setup.SetupVars);
/// DG:B4C2: the level-2 time-control records, 14 bytes per side.
const tc_addr: u16 = 0xB4C2;
const PositionMap = est.PositionMap;
/// prepare_eval's inputs (`evaltables.Inputs`), read at their homes.
const InputsMap = dgroup.Map(evaltables.Inputs, &dgroup.maps.evaltables.Inputs);

/// Whether some unit the engine runs holds DGROUP address `a` in a field (so that a
/// difference there can change what the engine does): the bytes the tests compare with an
/// oracle's image (src/state_image.zig). The lifted threat code, which reads the image
/// directly, is not counted: the engine runs the hand-written one.
pub fn mappedByAUnit(a: usize) bool {
    // prepare_eval's tables and the evaluation's state as Stage A maps them (test-only).
    const ae = @import("adapt_eval.zig");
    if (PositionMap.covers(a) or est.EvalVarsMap.covers(a) or est.ScratchMap.covers(a) or est.SearchVarsMap.covers(a)) return true;
    if (ae.TablesMap.covers(a) or InputsMap.covers(a) or ae.EvalStateMap.covers(a)) return true;
    if (est.LeafVarsMap.covers(a) or est.ThreatVarsMap.covers(a)) return true;
    if (viewCovers(rp.PrepState, rp.layout, a) or viewCovers(rs.RootState, rs.layout, a) or timeStateCovers(a) or gameVarsCover(a)) return true;
    if (a >= 0x3A34 and a < 0x3A34 + 400 * 35) return true; // the move lists
    inline for (sn.dg_fields) |f| {
        if (a >= f.addr and a < @as(usize, f.addr) + f.len) return true;
    }
    return false;
}

/// main's frame pointer in the original (every recorded run: rootprep and rootsearch
/// vectors), and root_search's (the loop's call, SP D5A4 at entry). The root's locals that
/// a callee writes through a pointer live at these addresses, where the original has them:
/// in `RootVars.frame` (Stage B step 8, stage 7), reached by address.
pub const main_bp: u16 = 0xD62C;
pub const root_search_bp: u16 = 0xD5A2;

/// DG:304E..306A and DG:B4B0: the far pointers of the game record and the clock.
pub const far_selectors = [_]u16{ 0x304E, 0x3050, 0x3052, 0x3054, 0x3056, 0x3058, 0x305A, 0x306A };
/// 5A7B:3A30: the tick counter (dword) the root reads through DG:B4AE.
pub const clock_offset: u16 = 0x3A30;
/// 5A7B:3A34 + 6 * game ply: the game record's keys.
pub const keys_offset: u16 = 0x3A34;
/// The game record's room for keys (`gamemove.key_room`, 1,992).
pub const max_game_keys = gamemove.key_room;
/// DG:3A34: the ply-0 move list (100 entries of 4 bytes), where set_predicted_reply and
/// check_entered_move keep the opponent's replies.
const list0: u16 = 0x3A34;

/// One event of a search, in the original's order, as the oracle's `--trace` lists them.
pub const Event = union(enum) {
    make: struct { ply: u8, from: u8, to: u8, flag: u8 },
    node: struct { side: sn.Side, ply: i16, alpha: i16, beta: i16 },
    /// An entry of root_move_search (0000:2EC8): the side to move, alpha, beta.
    ply2: struct { side: sn.Side, alpha: i16, beta: i16 },
};

/// Which routine a hook call is about.
pub const Which = union(enum) { prep: rp.Callee, loop: rs.Callee };

/// The test hook (src/engine_root_test.zig): `before` is called with the image as the
/// root left it before the call and returns whether the real routine is to be run;
/// `after` is called after it (or in its place) with the real result, and returns the
/// value the root is given.
pub const Hook = struct {
    ctx: *anyopaque,
    before: *const fn (ctx: *anyopaque, site: u16, which: Which, args: []const u16) bool,
    after: *const fn (ctx: *anyopaque, site: u16, which: Which, args: []const u16, real: ?u32) u32,
    far: ?*const fn (ctx: *anyopaque, site: u16, off: u16) ?u32 = null,
};

/// The UCI layer's view of a search (src/uci_report.zig), Stage A: it is told of the
/// root's calls and never changes what the search reads, but for two stops: the stop flag
/// (`stopRequested`, the key the original's keyboard poll 1E9D:7514 would find, and the
/// time control's stop inside an iteration) and the loop's depth limit (`iterationDone`
/// returning true: the time control's stop at the end of an iteration).
pub const Observer = struct {
    ctx: *anyopaque,
    /// Before each callee of the iteration loop and root_search but the loop's own calls
    /// of root_search and the sort, with the root's state as the root left it (and as the
    /// image holds it).
    call: *const fn (ctx: *anyopaque, site: u16, callee: rs.Callee, args: []const u16, st: *const rs.RootState) void,
    /// After the iteration loop's call of root_search (site 15FA or 165D) with the window
    /// (hi, lo) and its result. Returns true to end the search after this iteration: the
    /// loop's limit DG:64 is then lowered to the iteration's depth + 1, so that the loop
    /// ends at its top (0000:146F) exactly as the Fixed depth level of this depth ends.
    iterationDone: *const fn (ctx: *anyopaque, site: u16, hi: i16, lo: i16, r: i16, st: *const rs.RootState) bool,
    /// Whether the UCI layer asks the search to stop (`Signals.stop`, or the time control);
    /// read every 1024th node entry of the iteration loop (owner decision, 2026-11-19: not
    /// the keyboard poll). `nodes` is the node entries of this search so far;
    /// `request_test` is set where `Signals.stop` is read (every 1024th entry of the
    /// engine's count), `time_test` where the time control is consulted (every 1024th
    /// entry of this search, and the loop's first entry).
    stopRequested: *const fn (ctx: *anyopaque, nodes: u64, request_test: bool, time_test: bool) bool,
};

/// What one search did.
pub const Outcome = struct {
    exit: rp.Exit,
    /// DG:A36C after the search: the move main plays.
    best: [4]u8,
    nodes: u64,
    makes: u64,
};

/// The engine's state for searches, Stage A. `fixes` holds the class C switches (every one
/// off for the golden files, which record the original): each callee that reads one is
/// called through its `...Fixes` variant with them, the search node's through `NodeEnv`.
/// Room for the slots written since a clear, per main hash table (searchnode.HashTable):
/// up to this many the clear zeroes just those slots; past it, every slot below the highest
/// written. 65,536 indices, 256 KB a table.
pub const written_room = 1 << 16;

/// The counts of `EngineRoot.root_lists` (test builds): root generations compared, those in check
/// (gen_evasions), and differences found.
pub const RootListCheck = struct { checked: u32 = 0, in_check: u32 = 0, mismatches: u32 = 0 };

pub fn EngineRoot(comptime fixes: pos.Fixes) type {
    return struct {
        const Self = @This();
        pub const NodeEnv = est.NodeEnv(fixes);
        pub const Node = NodeEnv.Node;
        /// The class C switches this root runs with (src/legality.zig generates with them).
        pub const class_c_fixes: pos.Fixes = fixes;

        gpa: std.mem.Allocator,
        /// The tests' image of DGROUP and of the far segment 5A7B, which their codec loads
        /// the root from and stores it to (src/state_image.zig). Fields of the test build
        /// only: the engine holds no image (Stage B step 8, stage 8).
        test_img: if (builtin.is_test) *Image else void,
        test_far: if (builtin.is_test) *Far else void,
        node_state: *sn.State,
        pawn_hash: *PawnHash,
        tables: *[2]sn.HashTable,
        /// The game record (far segment 5A7B), persistent for the root's life (Stage B
        /// step 8, stage 2): the one home of the record; the node reads its keys in place
        /// (`node.game_keys`).
        rec: *gamemove.GameRecord,
        /// prepare_eval's inputs (`evaltables.Inputs`), read at their homes before each
        /// call (`prepareEvalDomain`) and kept between calls, as Stage A's work area kept
        /// them.
        eval_in: evaltables.Inputs = .{},
        node: NodeEnv,
        /// The search's events (makes, node entries, root_move_search entries) when
        /// `trace` is set (the tests); the line hash is kept in any case. The search below
        /// the root counts and hashes each make and node entry as it happens (`StopCtx`
        /// `applyMove`, `child`): nothing is kept per event unless `trace` is set.
        events: std.ArrayList(Event) = .empty,
        trace: bool = false,
        line: std.crypto.hash.sha2.Sha256 = .init(.{}),
        makes: u64 = 0,
        nodes: u64 = 0,
        /// The tick counter the root reads (held during a search, as the oracle holds it).
        ticks: u32 = 0,
        /// The tablebase files, if any (the shipped TB folder); none: every probe fails.
        tb_files: ?tablebase.Files = null,
        /// Tablebase probes of this search that accepted a byte (for reporting only).
        tb_hits: u32 = 0,
        /// The opening book's files, if bound (the engine's embedded PRBOOK folder). None:
        /// book_probe with the M-Chess book on fails, as before the book was joined.
        book_files: ?*const book.Files = null,
        /// This search's main played a book move (main 070F, play_best_move(1)).
        book_played: bool = false,
        /// The move the book drew in this search that failed the legality test (a book
        /// miss, AGENTS.md section 9.3), for reporting.
        book_illegal: ?pos.Move = null,
        /// The tests' hook (a field of the test build only).
        hook: if (builtin.is_test) ?Hook else void = if (builtin.is_test) null else {},
        /// Calls of each callee, for the tests' report of which bindings ran.
        prep_calls: [std.enums.values(rp.Callee).len]u64 = @splat(0),
        loop_calls: [std.enums.values(rs.Callee).len]u64 = @splat(0),
        failure: ?[]const u8 = null,
        msg: [300]u8 = undefined,
        /// Calls of set_predicted_reply (38C0:0D22) by play_best_move (normal play only).
        predict_calls: u64 = 0,
        /// Whether the turn routines slide the game record when it is due (owner decision
        /// 26: the engine plays on past move 201; `slideIfDue`). The tests that slide by
        /// hand, or show the original's own end at move 202, switch it off.
        slide_when_due: bool = true,
        /// Plies dropped from the start of the game record by slides, for reporting: the
        /// game ply DG:9FC8 plus this is the ply counted from the game's start.
        dropped_plies: u64 = 0,
        /// The UCI layer's observer, if any (reporting and the stop key); none in the
        /// golden tests.
        observer: ?Observer = null,
        /// Test builds only: the list-identity test of src/legality.zig (DEV-066). At each
        /// root generation (main 0000:0835 or 0843, ply 1) the rewrite's legality test
        /// generates on copies, its check byte and en-passant square read from the game
        /// record (`legality.rootRecord`, as `Engine.findLegal` and `PvCheck.load` read
        /// them), and its list must be the root's own, move for move: a difference is a
        /// failure of the search. Nothing the search reads is written.
        root_lists: if (builtin.is_test) RootListCheck else void = if (builtin.is_test) .{} else {},
        /// The deepest ply a node of this search was entered at (the root's moves are made
        /// at ply 2), for `seldepth`; kept for reporting only.
        max_ply: i16 = 0,
        /// `StopCtx`: node entries counted, whether the count reads the stop request (in
        /// the iteration loop only), and whether it has written the stop flag.
        node_tick: u32 = 0,
        stop_armed: bool = false,
        stop_fired: bool = false,
        /// Node entries of this search, counted where `node_tick` is (from `beginSearch`):
        /// the same count as `nodes`, but current at every entry.
        live_nodes: u64 = 0,
        /// `go nodes N`: the stop flag is written at the node entry that makes `live_nodes`
        /// N (in the iteration loop); 0: no limit.
        node_limit: u64 = 0,
        /// Why the stop flag was written (for reporting and the tests).
        stop_cause: StopCause = .none,
        /// Node entries since the iteration loop was entered (`iterate`).
        loop_entries: u64 = 0,
        /// Whether the routines that write many bytes between searches (start-up, New game,
        /// Setup mode) refresh the members' copies of bytes another member holds at their
        /// end (`refreshCopies`). Off only in the test that measures what they would leave
        /// stale.
        refresh_copies: bool = true,
        /// The times the last `search` stored the members to the tests' image (the codec's
        /// `exit`, counted in test builds only): 0 without a hook since Stage B step 8,
        /// stage 5.
        search_exits: u64 = 0,
        /// The tests' image brackets opened (`state_image.imageBegin`), and checkpoints
        /// taken or restored (`saveState`, `restoreState`), counted in test builds only: the
        /// test that the engine's commands make no image bracket reads them (Stage B step 8,
        /// stage 6).
        image_brackets: u64 = 0,
        checkpoints: u64 = 0,

        pub const StopCause = enum { none, request, node_limit };

        /// Allocates the node's state, the members, the game record and two main hash
        /// tables of `slots` 10-byte slots each (3,145,728 for the original's 30,720 KB
        /// tables), and decodes the members from the C start-up's image (`dgroup.initial`,
        /// `NodeEnv.decodeFrom`). In a test build also the tests' image and far segment,
        /// set to that image and to zeros.
        pub fn init(gpa: std.mem.Allocator, slots: usize) !*Self {
            const s = try gpa.create(Self);
            errdefer gpa.destroy(s);
            const img = if (builtin.is_test) blk: {
                const i = try gpa.create(Image);
                i.* = dgroup.initial;
                break :blk i;
            } else {};
            const far = if (builtin.is_test) blk: {
                const f = try gpa.create(Far);
                f.* = @splat(0);
                break :blk f;
            } else {};
            const st = try gpa.create(sn.State);
            st.* = .{};
            const ph = try gpa.create(PawnHash);
            ph.* = .{};
            const tables = try gpa.create([2]sn.HashTable);
            for (tables) |*t| {
                t.* = .{ .slots = try gpa.alloc([10]u8, slots), .written = try gpa.alloc(u32, written_room) };
                @memset(std.mem.sliceAsBytes(t.slots), 0);
                t.pristine = true;
            }
            const rec = try gpa.create(gamemove.GameRecord);
            rec.* = .{};
            s.* = .{
                .gpa = gpa,
                .test_img = img,
                .test_far = far,
                .node_state = st,
                .pawn_hash = ph,
                .tables = tables,
                .rec = rec,
                .node = .{ .st = st, .pawn_hash = ph, .tables = tables, .game_keys = rec.keys[0..], .gpa = gpa, .dom = undefined },
            };
            if (builtin.is_test) s.node.codec.img = img;
            s.node.dom = try est.Members.create(gpa);
            try s.node.bindGameVars();
            try s.node.bindTimeState();
            // The members from the C start-up's image, once (Stage B step 8, stage 8: the
            // members are the state for the root's life, and no image is kept).
            s.node.decodeFrom(&dgroup.initial);
            return s;
        }

        /// In a test build, that the members hold the state (a test that has stored them to
        /// its image, src/state_image.zig `imageBegin`, must load them again first).
        inline fn assertEntered(s: *const Self) void {
            if (builtin.is_test) std.debug.assert(s.node.codec.in_domain);
        }

        /// The C start-up's image (`dgroup.initial`) and a far segment of zeros into the
        /// members and the record (`startUp`): the one image the engine reads, decoded
        /// through the members' maps (`NodeEnv.decodeFrom`), and the record of a far
        /// segment of zeros, every field 0 (`GameRecord{}`: every field of the record is at
        /// an offset of `gamemove.record_offsets`, so `fromFar` of zeros sets each to 0). In
        /// a test build the tests' image is set to the same first (src/state_image.zig
        /// `startImage`).
        fn loadStart(s: *Self) void {
            if (builtin.is_test) si.startImage(s);
            s.node.decodeFrom(&dgroup.initial);
            s.rec.* = .{};
        }

        /// A far offset no field of the game record holds: no routine forms one (Stage B
        /// step 8, stage 7, measured over the whole suite), and since stage 8 there is no far
        /// image to fall back on.
        fn noFarHome(off: u16) noreturn {
            @branchHint(.cold);
            std.debug.panic("engine_root: far segment offset 5A7B:{X:0>4} has no home: no field of the game record holds it", .{off});
        }

        /// Byte `off` of the far segment 5A7B as main reads it: the game record's. Since
        /// Stage B step 8, stage 7, the record has a field at every offset main and the slide
        /// form (`GameRecord.before_moves`, `key_gap`); an offset no field holds panics
        /// (`noFarHome`).
        pub fn farByte(s: *const Self, off: u16) u8 {
            return s.rec.byteAt(off) orelse noFarHome(off);
        }

        /// Word `off` of the far segment written as main writes it (`farByte`'s homes).
        pub fn setFarWord(s: *Self, off: u16, v: u16) void {
            for (0..2) |k| {
                const o = off +% @as(u16, @intCast(k));
                const b: u8 = @truncate(v >> @intCast(8 * k));
                if (!s.rec.setByteAt(o, b)) noFarHome(o);
            }
        }

        /// The record's key of game ply `ply` (prepare_eval's root key, 0000:960A).
        fn setRecordKey(s: *Self, ply: usize, key: u48) void {
            if (ply >= max_game_keys) return s.fail("game ply {d} beyond the game record", .{ply});
            s.rec.keys[ply] = key;
        }

        /// repetition_count (2B9F:402A) on the record's keys.
        fn repetitionOnRecord(s: *Self, game_ply: i16, last: i16, key: u48) u16 {
            // rp.repetitionCount's loop on the u48 keys.
            const p0: i16 = game_ply -% 4;
            if (p0 < last) return 0;
            var n: u16 = @as(u16, @bitCast(p0 -% last +% 2)) >> 1;
            var count: u16 = 0;
            var at: i32 = p0;
            while (true) {
                if (s.rec.keys[@intCast(at)] == key) count += 1;
                at -= 2;
                n -%= 1;
                if (n == 0) break;
            }
            return count;
        }

        /// A checkpoint of the engine's state (Stage B step 8, stage 7): the members, the
        /// node's `State` and the game record, as values. Since this stage every variable the
        /// engine reads or writes has a member for its home, so this is the whole state; the
        /// image and the far segment are neither read nor written to take or restore it.
        pub const Checkpoint = struct {
            p: pos.Position = .{},
            ev: ev.EvalVars = .{},
            sv: mg.SearchVars = .{},
            s: @FieldType(est.Members, "s") = .{},
            lv: leaf.LeafVars = .{},
            tv: @FieldType(est.Members, "tv") = .{},
            gv: gamemove.GameVars = .{},
            ts: tbud.TimeState = .{},
            rv: rvm.RootVars = .{},
            pg: rvm.ProgramVars = .{},
            st: sn.State = .{},
            rec: gamemove.GameRecord = .{},
        };

        /// A checkpoint of the whole state (the engine's start-up checkpoint and `rebuild`'s
        /// one-move copy): every member's value, the node's `State` and the record
        /// (`NodeEnv.saveMembers`). Not an image bracket: the image is not touched.
        pub fn saveState(s: *Self, cp: *Checkpoint) void {
            s.assertEntered();
            s.node.saveMembers(cp);
            cp.rec = s.rec.*;
            if (builtin.is_test) s.checkpoints += 1;
        }

        /// The state of a checkpoint `saveState` took (`NodeEnv.restoreMembers`): every
        /// member's mapped fields, the node's `State` and the record, and the members'
        /// copies of bytes another member holds set from their homes, exactly what loading
        /// the checkpoint's image did before this stage (`enter`).
        pub fn restoreState(s: *Self, cp: *Checkpoint) void {
            s.assertEntered();
            s.node.restoreMembers(cp);
            s.rec.* = cp.rec;
            if (builtin.is_test) s.checkpoints += 1;
        }

        /// DGROUP by address in a checkpoint, as a store (`dgroup.ImageMem`'s interface):
        /// each byte at its home's copy (`NodeEnv.checkpointPtr`). The options write their
        /// variables in the start-up checkpoint through it.
        pub const CheckpointHome = struct {
            s: *Self,
            cp: *Checkpoint,
            pub fn get(h: CheckpointHome, a: u16) u8 {
                return h.s.node.checkpointPtr(h.cp, a).*;
            }
            pub fn set(h: CheckpointHome, a: u16, v: u8) void {
                h.s.node.checkpointPtr(h.cp, a).* = v;
            }
        };
        pub fn checkpointHome(s: *Self, cp: *Checkpoint) CheckpointHome {
            return .{ .s = s, .cp = cp };
        }

        pub fn deinit(s: *Self) void {
            const gpa = s.gpa;
            for (s.tables) |*t| {
                gpa.free(t.slots);
                gpa.free(t.written);
            }
            gpa.destroy(s.tables);
            gpa.destroy(s.pawn_hash);
            gpa.destroy(s.node_state);
            s.node.dom.destroy(gpa);
            if (builtin.is_test) {
                gpa.destroy(s.test_far);
                gpa.destroy(s.test_img);
            }
            gpa.destroy(s.rec);
            s.events.deinit(gpa);
            gpa.destroy(s);
        }

        fn fail(s: *Self, comptime fmt: []const u8, args: anytype) void {
            if (s.failure != null) return;
            s.failure = std.fmt.bufPrint(&s.msg, fmt, args) catch "failure";
        }

        // ---- counters, line hash and trace ------------------------------------------

        /// Start the counts and the line hash of a new search (the oracle starts them at
        /// the entry of prepare_eval).
        pub fn beginSearch(s: *Self) void {
            s.line = .init(.{});
            s.makes = 0;
            s.nodes = 0;
            s.max_ply = 0;
            s.live_nodes = 0;
            s.stop_cause = .none;
            s.tb_hits = 0;
            s.book_played = false;
            s.book_illegal = null;
            s.events.clearRetainingCapacity();
        }

        /// A make of the search (the root's own and every one below it): counted, fed to the
        /// line hash, and, when tracing, recorded, as it happens.
        inline fn countMake(s: *Self, ply: u8, from: u8, to: u8, flag: u8) void {
            s.makes += 1;
            s.line.update(&.{ ply, from, to, flag });
            if (s.trace) s.traceEvent(.{ .make = .{ .ply = ply, .from = from, .to = to, .flag = flag } });
        }

        /// A node entry (the node at the root's call, `node`, and every child below it,
        /// `StopCtx.child`): counted and the deepest ply kept, and, when tracing, recorded,
        /// as it happens, with nothing kept per event (no allocation in a search: AGENTS.md
        /// section 12, docs/ROBUSTNESS.md "Fault 3"). The readers of `nodes`, `makes` and
        /// `max_ply` (src/uci_report.zig `line`, `final`; src/engine.zig) run at the root,
        /// between root moves; during a subtree only `live_nodes` is read (`StopCtx.tick`).
        inline fn countNode(s: *Self, side: sn.Side, ply: i16, alpha: i16, beta: i16) void {
            s.nodes += 1;
            if (ply > s.max_ply) s.max_ply = ply;
            if (s.trace) s.traceEvent(.{ .node = .{ .side = side, .ply = ply, .alpha = alpha, .beta = beta } });
        }

        /// One event of the trace (the tests' `trace`; the engine never sets it).
        fn traceEvent(s: *Self, e: Event) void {
            @branchHint(.cold);
            s.events.append(s.gpa, e) catch @panic("engine_root: out of memory");
        }

        /// The hex digest of the line so far.
        pub fn lineHex(s: *const Self) [64]u8 {
            var h = s.line;
            var d: [32]u8 = undefined;
            h.final(&d);
            return std.fmt.bytesToHex(d, .lower);
        }

        // ---- DGROUP by address --------------------------------------------------------

        // DGROUP by address at the byte's home (engine_state `dgPtr`): the member that holds it.
        fn dgByte(s: *Self, a: u16) u8 {
            return s.node.dgPtr(a).*;
        }
        fn dgSet(s: *Self, a: u16, v: u8) void {
            s.node.dgPtr(a).* = v;
        }
        fn dgWord(s: *Self, a: u16) u16 {
            return @as(u16, s.dgByte(a)) | @as(u16, s.dgByte(a + 1)) << 8;
        }
        fn dgSetWord(s: *Self, a: u16, v: u16) void {
            s.dgSet(a, @truncate(v));
            s.dgSet(a + 1, @truncate(v >> 8));
        }
        fn dgDword(s: *Self, a: u16) u32 {
            return @as(u32, s.dgWord(a)) | @as(u32, s.dgWord(a + 2)) << 16;
        }
        fn dgSetDword(s: *Self, a: u16, v: u32) void {
            s.dgSetWord(a, @truncate(v));
            s.dgSetWord(a + 2, @truncate(v >> 16));
        }

        /// `n` bytes from DG:`a` at their homes.
        fn dgBytes(s: *Self, a: u16, comptime n: usize) [n]u8 {
            var out: [n]u8 = undefined;
            for (&out, 0..) |*x, k| x.* = s.dgByte(a + @as(u16, @intCast(k)));
            return out;
        }

        /// DGROUP by address at each byte's home, as a store (`dgroup.ImageMem`'s
        /// interface) for the routines that address the original's variables
        /// (src/newgame.zig, src/gameslide.zig, src/adapt_setup.zig, the hash dialog):
        /// `dgPtr`, the member that holds the byte (since Stage B step 8, stage 7, every
        /// byte the engine reads or writes has one; since stage 8 one that has none panics).
        pub const Home = struct {
            s: *Self,
            pub fn get(h: Home, a: u16) u8 {
                return h.s.node.dgPtr(a).*;
            }
            pub fn set(h: Home, a: u16, v: u8) void {
                h.s.node.dgPtr(a).* = v;
            }
        };
        pub fn home(s: *Self) Home {
            return .{ .s = s };
        }

        /// The far segment 5A7B by offset at the game record's home, as a store: each
        /// offset at its field of `rec` (`GameRecord.byteAt`, `setByteAt`; an offset no
        /// field holds panics, `farByte`).
        pub const RecordHome = struct {
            s: *Self,
            pub fn get(h: RecordHome, off: u16) u8 {
                return h.s.farByte(off);
            }
            pub fn set(h: RecordHome, off: u16, v: u8) void {
                if (!h.s.rec.setByteAt(off, v)) noFarHome(off);
            }
        };
        pub fn recordHome(s: *Self) RecordHome {
            return .{ .s = s };
        }
        fn sideOf(a: u16) pos.Side {
            return if (a & 1 == 0) .white else .black;
        }

        // ---- the loop's callees on the node domain's structs (stage 3b) ------------------
        //
        // While the iteration loop runs, the node domain holds the position and the
        // evaluation's sums (`iterate` entered it), so root_search's make and take-back, the
        // square sums, the key and the repetition count run on the domain's `Position` and
        // `EvalVars`, as the node's own `applyMove` and `unmake` do, and not on the image.
        // The captured piece and its slot are root_search's locals ([bp-16h], [bp-1Ah]), in
        // the root's frame (`RootVars.frame`), where `env.local` reads them.

        /// The move at `ptr` in the move lists DG:3A34 + 400 * ply (the root list is ply 1's),
        /// read in the node's `State`, where the lists live while the loop runs.
        fn domainMoveAt(s: *const Self, ptr: u16) pos.Move {
            const off = ptr -% list0;
            std.debug.assert(ptr >= list0 and off % 4 == 0 and off < 400 * est.move_list_room);
            return s.node_state.move_list[off / 400][(off % 400) / 4];
        }

        fn squareSumsDomain(s: *Self, ptr: u16) void {
            const mv = s.domainMoveAt(ptr);
            s.node.guardRoot(&.{ .p, .ev });
            squaresums.updateSquareSums(&s.node.dom.p, &s.node.dom.ev, mv);
        }

        fn hashKeyDomain(s: *Self, ptr: u16) void {
            const mv = s.domainMoveAt(ptr);
            s.node.guardRoot(&.{.p});
            s.node.dom.p.updateHashKey(mv, fixes);
        }

        fn makeDomain(s: *Self, slotp: u16, capp: u16, ply: u16, side: u16, ptr: u16) void {
            const mv = s.domainMoveAt(ptr);
            s.countMake(@truncate(ply), mv.from, mv.to, mv.flag);
            var u: pos.Undo = .{ .captured = s.dgByte(capp), .captured_slot = s.dgByte(slotp) };
            s.node.guardRoot(&.{.p});
            s.node.dom.p.makeMoveFixes(mv, sideOf(side), ply, &u, fixes);
            s.dgSet(capp, u.captured);
            s.dgSet(slotp, u.captured_slot);
        }

        fn unmakeDomain(s: *Self, slotp: u16, capp: u16, side: u16, ptr: u16) void {
            const mv = s.domainMoveAt(ptr);
            var u: pos.Undo = .{ .captured = s.dgByte(capp), .captured_slot = s.dgByte(slotp) };
            s.node.guardRoot(&.{.p});
            s.node.dom.p.unmakeMoveFixes(mv, sideOf(side), &u, fixes);
            s.dgSet(capp, u.captured);
            s.dgSet(slotp, u.captured_slot);
        }

        /// 2B9F:402A on the domain's key, game ply (DG:9FC8, `Position`) and last
        /// irreversible ply (DG:7464, `EvalVars`), and the game record.
        fn repetitionDomain(s: *Self) u16 {
            const d = s.node.dom;
            return s.repetitionOnRecord(@bitCast(d.p.game_ply), @bitCast(d.ev.last_irreversible_ply), d.p.hash_key);
        }

        /// The node's interface as the root gives it: the node's own (`NodeEnv`), with a
        /// count of node entries that, every 1024th entry while `stop_armed`, reads the
        /// observer's stop request and, once, writes the original's stop flag [A4FA] (the
        /// node state's `stop`) with 1, the value of the original's own time-out
        /// (2EC8:2F3E, `searchnode.timeTestD`). The node tests it after a move is searched
        /// and unmade (0000:41CB, 4DB0) and unwinds as the original does. Without an
        /// observer, or with no request, it changes nothing: every method is the node's.
        pub const StopCtx = struct {
            s: *Self,
            /// The class C fixes the search node reads (searchnode.zig `node_fixes`: DEV-035).
            pub const node_fixes: pos.Fixes = fixes;

            fn tick(w: *StopCtx) void {
                const s = w.s;
                s.node_tick +%= 1;
                s.live_nodes += 1;
                if (!s.stop_armed or s.stop_fired) return;
                if (s.node_limit != 0 and s.live_nodes >= s.node_limit) {
                    // `go nodes N`: tested at every node entry, so that the same N always
                    // stops at the same node.
                    s.node_state.stop = 1;
                    s.stop_fired = true;
                    s.stop_cause = .node_limit;
                    return;
                }
                // The request is read every 1024th entry of the engine's count (its phase
                // carries over from search to search), every 1024th of this search's (so
                // that a scripted clock stops a search at the same node every time), and at
                // the iteration loop's first node entry (the time control's test, so that a
                // clock already past its limit costs no more than main's preparation).
                s.loop_entries += 1;
                const time_test = s.live_nodes & 1023 == 0 or s.loop_entries == 1;
                const request_test = s.node_tick & 1023 == 0;
                if (!request_test and !time_test) return;
                const o = s.observer orelse return;
                if (!o.stopRequested(o.ctx, s.live_nodes, request_test, time_test)) return;
                s.node_state.stop = 1;
                s.stop_fired = true;
                s.stop_cause = .request;
            }

            /// NodeEnv.run with the count, on the members (the node domain, which the root
            /// never leaves). The root counts this node's entry itself (`node`).
            pub fn run(w: *StopCtx, side: sn.Side, legal: *i16, beta: i16, alpha: i16, ply: i16) i16 {
                const c = &w.s.node;
                c.nodes += 1;
                w.tick();
                return sn.Node(StopCtx).search(w, c.st, side, legal, beta, alpha, ply, 0);
            }

            /// NodeEnv.child with the count: the entry is counted into the root's counts
            /// (`countNode`) as it happens.
            pub fn child(w: *StopCtx, side: sn.Side, legal: *i16, beta: i16, alpha: i16, ply: i16) i16 {
                const c = &w.s.node;
                c.calls.getPtr(.child).* += 1;
                c.nodes += 1;
                w.s.countNode(side, ply, alpha, beta);
                w.tick();
                return sn.Node(StopCtx).search(w, c.st, side, legal, beta, alpha, ply, 0);
            }

            pub fn poll(w: *StopCtx) void {
                w.s.node.poll();
            }
            pub fn isRepetition(w: *StopCtx, ply: i16) bool {
                return w.s.node.isRepetition(ply);
            }
            pub fn attacks(w: *StopCtx, side: sn.Side, sq: u8) bool {
                return w.s.node.attacks(side, sq);
            }
            pub fn hashMovePlausible(w: *StopCtx, side: sn.Side, mv: *u16) bool {
                return w.s.node.hashMovePlausible(side, mv);
            }
            pub fn probe(w: *StopCtx, side: sn.Side, index: u32) void {
                w.s.node.probe(side, index);
            }
            pub fn store(w: *StopCtx, side: sn.Side, index: u32) void {
                w.s.node.store(side, index);
            }
            pub fn prefetchProbe(w: *StopCtx, side: sn.Side, index: u32) void {
                w.s.node.prefetchProbe(side, index);
            }
            pub fn generate(w: *StopCtx, gen: sn.Gen, side: sn.Side, ply: i16) u16 {
                return w.s.node.generate(gen, side, ply);
            }
            pub fn sortList(w: *StopCtx, ply: i16, count: u16) void {
                w.s.node.sortList(ply, count);
            }
            pub fn makeNull(w: *StopCtx, ply: i16) void {
                w.s.node.makeNull(ply);
            }
            /// NodeEnv.applyMove, the make counted and hashed into the root's line
            /// (`countMake`) as it happens, before the move is made, where the node's own
            /// count is.
            pub fn applyMove(w: *StopCtx, side: sn.Side, ply: i16, m: pos.Move, undo: *pos.Undo) void {
                w.s.countMake(@truncate(@as(u16, @bitCast(ply))), m.from, m.to, m.flag);
                w.s.node.applyMove(side, ply, m, undo);
            }
            pub fn unmake(w: *StopCtx, side: sn.Side, m: pos.Move, undo: *pos.Undo) void {
                w.s.node.unmake(side, m, undo);
            }
            pub fn pawnEval(w: *StopCtx, side: sn.Side) i16 {
                return w.s.node.pawnEval(side);
            }
            pub fn staticEval(w: *StopCtx, side: sn.Side, arg: i16) i16 {
                return w.s.node.staticEval(side, arg);
            }
            pub fn pieceEval(w: *StopCtx, side: sn.Side, ply: i16) i16 {
                return w.s.node.pieceEval(side, ply);
            }
            pub fn countAttacked(w: *StopCtx, side: sn.Side) u16 {
                return w.s.node.countAttacked(side);
            }
            pub fn threats(w: *StopCtx, side: sn.Side, ply: i16, count: u16, counter: *u8) i16 {
                return w.s.node.threats(side, ply, count, counter);
            }
            pub fn kingSafety(w: *StopCtx) i16 {
                return w.s.node.kingSafety();
            }
            pub fn endgameKing(w: *StopCtx, side: sn.Side) i16 {
                return w.s.node.endgameKing(side);
            }
            pub fn leafAttackMap(w: *StopCtx, side: sn.Side) void {
                w.s.node.leafAttackMap(side);
            }
            pub fn leafTermA(w: *StopCtx, side: sn.Side) i16 {
                return w.s.node.leafTermA(side);
            }
            pub fn leafTermB(w: *StopCtx, side: sn.Side) i16 {
                return w.s.node.leafTermB(side);
            }
            pub fn pawnEndingTerm(w: *StopCtx, side: sn.Side) i16 {
                return w.s.node.pawnEndingTerm(side);
            }
            pub fn tablebase(w: *StopCtx, side_arg: u16, ply: i16) bool {
                return w.s.node.tablebase(side_arg, ply);
            }
        };

        /// The search node at the root's call: `legalp` the address of the root's legal
        /// word.
        fn callNode(s: *Self, side: sn.Side, legalp: u16, beta: u16, alpha: u16, ply: u16) u32 {
            s.countNode(side, @bitCast(ply), @bitCast(alpha), @bitCast(beta));
            var legal: i16 = @bitCast(s.dgWord(legalp));
            var w: StopCtx = .{ .s = s };
            const r = w.run(side, &legal, @bitCast(beta), @bitCast(alpha), @bitCast(ply));
            s.dgSetWord(legalp, @bitCast(legal));
            return @as(u16, @bitCast(r));
        }

        /// root_move_search (0000:2EC8) with (beta, alpha, side) as root_search passes them.
        fn ply2(s: *Self, rst: *const rs.RootState, beta: u16, alpha: u16, side_w: u16) u32 {
            const side: sn.Side = @truncate(side_w);
            if (s.trace) s.traceEvent(.{ .ply2 = .{ .side = side, .alpha = @bitCast(alpha), .beta = @bitCast(beta) } });
            const clock: sn.Ply2Clock = .{
                .iter_start_elapsed = @bitCast(rst.iter_start_elapsed.*),
                .base_time = @bitCast(rst.base.*),
                .pondering = rst.pondering.*,
                .single_move = s.dgWord(0x1480),
            };
            var w: StopCtx = .{ .s = s };
            const r = sn.Node(StopCtx).searchPly2(&w, s.node_state, side, @bitCast(beta), @bitCast(alpha), clock, 0, 0);
            return @as(u16, @bitCast(r));
        }

        /// A routine of the time budget (src/timebudget.zig) on the member `Members.ts`
        /// (`timebudget.TimeState`), whose value fields are its own and whose pointer fields
        /// reach every other variable at its one home (the members that hold pondering, the
        /// clock side, the game ply, `hard`, the book-exit ply, analysis and `clear_best`;
        /// `RootVars` for the rest, since Stage B step 8, stage 7): main's callees in the
        /// search and the turn routines between searches.
        fn timeCall(s: *Self, comptime f: anytype, args: anytype) i16 {
            const r = @call(.auto, f, .{&s.node.dom.ts} ++ args);
            return if (@TypeOf(r) == i16) r else 0;
        }

        /// prepare_eval (0000:9582) with its caller's duties: the root key into the game
        /// record (0000:960A) and both pawn hash tables cleared (0000:8B50), on the domain's
        /// structs (`prepareEvalDomain`): from main before the loop and from
        /// set_predicted_reply between searches.
        fn prepareEval(s: *Self) void {
            s.prepareEvalDomain();
            const p = &s.node.dom.p;
            s.setRecordKey(p.game_ply, p.hash_key);
            s.pawn_hash.clear();
        }

        /// prepare_eval on the node domain's structs: the position is the domain's, the
        /// tables point at the bytes the domain's structs hold and, since Stage B step 8,
        /// stage 7, at `RootVars` and `ProgramVars` for the rest (`evaltables.bindDomain`),
        /// and the inputs are read at their homes (`Home`). Nothing is copied back: every
        /// byte written is in its one home.
        fn prepareEvalDomain(s: *Self) void {
            const d = s.node.dom;
            var t: evaltables.Tables = .{};
            evaltables.bindDomain(&t, s.node_state, &d.p, &d.ev, &d.s, &d.lv, &d.tv, &d.rv, &d.pg);
            // Stage B step 8, stage 7: the inputs are read at their homes.
            const in = &s.eval_in;
            var in_snap: InputsMap.Snapshot = undefined;
            InputsMap.loadSnapVia(in, s.home(), &in_snap);
            in.passed_mask_white = d.ev.passed_pawns[0];
            in.passed_mask_black = d.ev.passed_pawns[1];
            in.beyond_board = d.tv.board_after[0..78].*;
            s.node.guardRoot(&.{ .st, .p, .ev, .s, .lv, .tv });
            evaltables.prepareEvalFixes(&d.p, &t, in, fixes);
        }

        /// hash_resize (0000:6C3A) from main at each byte's home (Stage B step 8, stage 5):
        /// the mask, the mode, the presence and the conventional mask in the node's
        /// `State` with the domain entered, the request, the memory and the bytes per table
        /// in `RootVars` and `ProgramVars` (Stage B step 8, stage 7).
        fn hashResize(s: *Self) u16 {
            const t = hashResizeAt(s.home());
            if (hashsize.slots(t) > s.tables[0].slots.len) s.fail("hash tables of {d} slots needed, {d} allocated", .{ hashsize.slots(t), s.tables[0].slots.len });
            return t.enabled;
        }

        /// The Settings / Hash-tables dialog (38C0:4C36-4CE6; docs/arch/35-hash-sizing.md
        /// section 4.2) with `typed_kb` typed at the command loop: the request and the total
        /// ([12C6], [12CA]) become the typed value, hash_resize runs, and the main tables are
        /// cleared if it leaves tables; if not, both become 0. Returns whether it cleared.
        /// The UCI option `Hash` is this dialog (src/engine.zig `setHash`).
        /// Since Stage B step 8, stage 4, on each byte's home (`Home`: the node's `State`
        /// for the mask, the mode, the presence and the conventional mask; `RootVars` and
        /// `ProgramVars` for the request, the total and the memory, since stage 7).
        pub fn hashMenu(s: *Self, typed_kb: i32) bool {
            const cleared = hashMenuAt(s.home(), typed_kb);
            const need = hashsize.slots(hashTablesAt(s.home()));
            if (need > s.tables[0].slots.len) s.fail("hash tables of {d} slots needed, {d} allocated", .{ need, s.tables[0].slots.len });
            if (cleared) for (s.tables) |*t| t.clear();
            return cleared;
        }

        /// The slots of each main table the index reaches now (the size in use: DG:B624
        /// and DG:9316, as hash_resize left them); 0 with no tables. Those two and DG:A3F8,
        /// AB9C are the node's `State`'s, the size and the bytes per table `RootVars`' and
        /// `ProgramVars'` (Stage B step 8, stage 7).
        pub fn hashSlotsInUse(s: *const Self) u32 {
            return hashsize.slots(hashTablesAt(Home{ .s = @constCast(s) }));
        }

        /// book_probe (4793:621E) from main (in the search since Stage B step 8, stage 5),
        /// on the domain's `Position`, every other variable at its home (`dgByte`: the
        /// book-exit ply in the threat evaluators' tail, the key DG:935A in `GameVars`, the
        /// rest in `RootVars` and `ProgramVars`).
        fn bookProbe(s: *Self, mode: u16, side: u16) u16 {
            s.node.guardRoot(&.{.p});
            const p: *const pos.Position = &s.node.dom.p;
            var session: book.Session = .{
                .book_exit_ply = @bitCast(s.dgWord(0x9FBC)),
                .book_disabled = s.dgByte(0x70E4) != 0,
                .book_move_ply = .{ s.dgWord(0x2522), s.dgWord(0x2524) },
            };
            const ply = s.dgWord(0x9FC8);
            if (s.book_files) |files| return s.bookProbeFiles(files, p, mode, side, ply, &session);
            if (!book.gate(&session, ply)) return 0;
            if (s.dgWord(0xA5EE) == 0) {
                s.fail("book_probe with the M-Chess book on: not bound", .{});
                return 0;
            }
            // The M-Chess book off (key K): the key is computed, nothing is found.
            const key = book.bookKey(book.BookPosition.fromPosition(p, sideOf(side)));
            s.dgSetKey(0x935A, key);
            s.dgSet(0x7449, 0); // the name number: not found
            if (mode == 1 and session.book_exit_ply == 0) s.dgSetWord(0x9FBC, ply);
            if (mode == 3 and session.book_exit_ply == 0) s.dgSetWord(0x9FBC, ply);
            return 0;
        }

        /// Port of book_probe (4793:621E, src/book.zig `probe`) at each variable's home:
        /// the book's settings DG:A6A0 and DG:A5EE, the random seed DG:2DC8, the book-exit
        /// ply DG:9FBC, the plies of the book moves DG:2522/2524, the key DG:935A, the name
        /// number DG:7449 and, in mode 1, the move handed over at DG:38A0. Not ported: the
        /// display list (far 7816, 8FDA, DG:2A8E, 32A0) and the opening name, user interface.
        ///
        /// A move drawn in mode 1 that fails `bookMoveLegal` (the book holds five that pass
        /// the original's own check 4793:59FE) is a book miss: the draw and its rand()
        /// calls stand, the move is not handed over, and the exit ply is set as when no
        /// move is drawn (6D80), so main searches (AGENTS.md section 9.3, class B).
        fn bookProbeFiles(s: *Self, files: *const book.Files, p: *const pos.Position, mode: u16, side: u16, ply: u16, session: *book.Session) u16 {
            const m: book.Mode = @fromBackingInt(@intCast(@as(u8, @truncate(mode))));
            const settings = book.Settings.fromFlags(s.dgWord(0xA6A0), s.dgWord(0xA5EE));
            var r: book.Rand = .{ .seed = s.dgDword(0x2DC8) };
            const bp = book.BookPosition.fromPosition(p, sideOf(side));
            var res = book.probeFixes(fixes, session, files, bp, ply, m, settings, &r);
            if (res.early) return 0;
            s.dgSetKey(0x935A, res.key);
            s.dgSet(0x7449, res.name);
            if (res.chosen) |mv| {
                if (!s.bookMoveLegal(mv, sideOf(side))) {
                    s.book_illegal = mv;
                    res.chosen = null;
                    if (session.book_exit_ply == 0) session.book_exit_ply = @bitCast(ply); // 6D80
                } else {
                    s.dgSet(0x38A0, mv.from);
                    s.dgSet(0x38A1, mv.to);
                    s.dgSet(0x38A2, mv.flag);
                }
            }
            s.dgSetWord(0x9FBC, @bitCast(session.book_exit_ply));
            s.dgSetWord(0x2522, session.book_move_ply[0]);
            s.dgSetWord(0x2524, session.book_move_ply[1]);
            s.dgSetDword(0x2DC8, r.seed);
            return res.returnValue(m);
        }

        /// The six bytes of a key at `a`, little-endian, at their homes.
        fn dgSetKey(s: *Self, a: u16, key: u48) void {
            for (0..6) |k| s.dgSet(a + @as(u16, @intCast(k)), @truncate(key >> @intCast(8 * k)));
        }

        /// An independent legality test of a book move for `side` on the search position:
        /// the move is one of the original's generator (gen_all_moves 1E9D:3938, which
        /// generates castling only with the squares between empty and the rook home), it
        /// does not leave the mover's king attacked, and a castling move does not start in
        /// check or pass over an attacked square. Not a port: the original plays its book
        /// move with only the pseudo-legal check 4793:59FE (AGENTS.md section 9.3).
        ///
        /// With the domain entered (Stage B step 8, stage 5: main's book probe in the
        /// search, and a test's call) on copies of the domain's `Position`, `see.Scratch`,
        /// `SearchVars` and the node's ply-1 list, as the node's own generator runs on the
        /// structs (`engine_state` `generate`); nothing of the domain changes.
        ///
        /// The generator is the one the original uses there (src/legality.zig, DEV-066):
        /// gen_evasions when the root's check byte is set (DG:8C07, `check_by_ply[1]`, which
        /// main sets from the game record at 0000:0693, before its book probe at 070F),
        /// else gen_all_moves.
        pub fn bookMoveLegal(s: *Self, mv: pos.Move, side: pos.Side) bool {
            const d = s.node.dom;
            var p = d.p;
            var sc = d.s;
            var sv = d.sv;
            var list = s.node_state.move_list[1];
            const n = legality.generate(fixes, &p, &sc, &sv, &list, side, 1);
            if (n == 0xFFFF) return false;
            var found = false;
            for (list[0..@min(n, 100)]) |g| {
                if (g.from == mv.from and g.to == mv.to and g.flag == mv.flag) found = true;
            }
            if (!found) return false;
            return kingSafeAfter(d.p, mv, side);
        }

        /// The king tests of `bookMoveLegal` on position `p0` (a copy): a castling move
        /// does not start in check or pass over an attacked square, and the move does not
        /// leave the mover's king attacked.
        fn kingSafeAfter(p0: pos.Position, mv: pos.Move, side: pos.Side) bool {
            var p = p0;
            const mover: u8 = @backingInt(side);
            const king_step = p.board[mv.from] == 6 or p.board[mv.from] == 13;
            if (king_step and (mv.to == mv.from + 2 or mv.to + 2 == mv.from)) {
                if (gamemove.kingAttacked(&p, mover) != 0) return false;
                var q = p;
                var u: pos.Undo = .{};
                const mid: u8 = if (mv.to > mv.from) mv.from + 1 else mv.from - 1;
                q.makeMove(.{ .from = mv.from, .to = mid, .flag = 0, .score = 0 }, side, 1, &u);
                if (gamemove.kingAttacked(&q, mover) != 0) return false;
            }
            var u: pos.Undo = .{};
            p.makeMove(mv, side, 1, &u);
            return gamemove.kingAttacked(&p, mover) == 0;
        }

        /// main 06EF (a book move, or the [A00A] path): play_best_move(arg) on the move at
        /// DG:38A0 (src/gamemove.zig), as `playMove` runs it after a search: on the
        /// domain's structs and the game record (Stage B step 8, stage 2). The move DG:A36C
        /// is the root's own variable (`RootVars.best_move`).
        fn playBestMoveFromMain(s: *Self, arg: u16) void {
            s.assertEntered();
            const d = s.node.dom;
            var c: DomainGameCtx = .{ .s = s };
            s.node.guardRoot(&.{ .p, .ev });
            gamemove.playBestMove(&d.p, &d.gv, s.rec, arg, s.dgBytes(0xA36C, 3), &c);
            s.book_played = true;
        }

        /// tb_probe from main and from root_search (0000:260A), on the members (stage 3b): the
        /// probe reads the position the domain holds (its `Position`, where the root's move
        /// is made), the setting DG:239C and the score DG:7466 in the node's `State`, and
        /// writes the score there. What else it reads (DG:239A and the signatures at A422,
        /// the program's side 8DDE, the bound AFC4) it reads at their homes, `ProgramVars`
        /// and `RootVars` (Stage B step 8, stage 7).
        fn tbProbeDomain(s: *Self, side: u16, ply: u16) u16 {
            if (s.tb_files == null) return 0;
            const st = s.node_state;
            return s.tbProbeOn(&s.node.dom.p, @truncate(@as(u16, @bitCast(st.tb_setting))), &st.tb_score, side, ply);
        }

        /// The probe on position `p`, with the setting byte `mode` (DG:239C) and the score
        /// word `score` (DG:7466, read and written).
        fn tbProbeOn(s: *Self, p: *const pos.Position, mode: u8, score: *i16, side: u16, ply: u16) u16 {
            const files = s.tb_files.?;
            // DG:A422: the [239A] signatures the start-up scan left, at most 50h (the scan's
            // limit, 2B9F:C2A6): 6 with the shipped TB folder, 62 with the "cd" set. A
            // negative count is passed as it is (the probe then skips the test, BBD8).
            const count: i16 = @bitCast(s.dgWord(0x239A));
            var sig: [0x50]u16 = undefined;
            const n: usize = @intCast(std.math.clamp(count, 0, 0x50));
            for (sig[0..n], 0..) |*x, k| x.* = s.dgWord(@intCast(0xA422 + 2 * k));
            var st: tablebase.State = .{
                .signature_count = if (count < 0) count else @intCast(n),
                .signatures = sig[0..n],
                .mode = mode,
                .program_side = s.dgByte(0x8DDE),
                .score_bound = @bitCast(s.dgWord(0xAFC4)),
                .score = score.*,
            };
            const r = tablebase.probe(tablebase.Fixes.corrected, p, &st, files, @truncate(side), ply, 0);
            score.* = st.score;
            if (r) s.tb_hits += 1;
            return @intFromBool(r);
        }

        /// The C rand() (4793:89D8) on its seed DG:2DC8, at its home (`ProgramVars.rand_seed`
        /// since Stage B step 8, stage 7), from main and the loop.
        fn rand(s: *Self) u16 {
            var r: book.Rand = .{ .seed = s.dgDword(0x2DC8) };
            const v = r.next();
            s.dgSetDword(0x2DC8, r.seed);
            return v;
        }

        /// Main's callees on the node domain's structs (Stage B step 7, stage 3c-1): the
        /// generators, make and take-back, the square sums and the key, the leaf attack
        /// maps, the repetition count, has_legal_move, the tablebase probe and the terms of
        /// the static pre-score, each the routine the node's own binding runs
        /// (src/engine_state.zig), or the 3b root callee. Null for the callees
        /// `dispatchPrep` runs itself (the time budget, the book, hash_resize, rand,
        /// play_best_move, the nodes, the displays).
        fn dispatchPrepDomain(s: *Self, c: rp.Callee, a: []const u16) ?u32 {
            const cx = &s.node;
            const d = cx.dom;
            if (builtin.is_test and (c == .gen_evasions or c == .gen_all_moves) and a[1] == 1) {
                // The list-identity test (`root_lists`), on copies taken before the root's
                // generation, compared after it.
                var p = d.p;
                const r = legality.rootRecord(s, a[0]);
                p.ep_square_by_ply[1] = r.ep;
                p.check_by_ply[1] = r.check;
                var sc = d.s;
                var sv = d.sv;
                var list = s.node_state.move_list[1];
                const want = legality.generate(fixes, &p, &sc, &sv, &list, sideOf(a[0]), 1);
                const got: u16 = @truncate(if (c == .gen_evasions)
                    cx.generate(.evasions, @truncate(a[0]), @bitCast(a[1]))
                else
                    cx.generate(.all, @truncate(a[0]), @bitCast(a[1])));
                s.root_lists.checked += 1;
                if (c == .gen_evasions) s.root_lists.in_check += 1;
                const same = want == got and (got == mg.king_capture or for (list[0..@min(got, 100)], s.node_state.move_list[1][0..@min(got, 100)]) |x, y| {
                    if (!std.meta.eql(x, y)) break false;
                } else true);
                if (!same) {
                    s.root_lists.mismatches += 1;
                    s.fail("list-identity test (DEV-066): the legality test's root list ({d} moves) is not the root's ({s}, {d} moves)", .{ want, @tagName(c), got });
                }
                return got;
            }
            return switch (c) {
                .gen_evasions => cx.generate(.evasions, @truncate(a[0]), @bitCast(a[1])),
                .gen_all_moves => cx.generate(.all, @truncate(a[0]), @bitCast(a[1])),
                .square_sums => blk: {
                    s.squareSumsDomain(a[0]);
                    break :blk 0;
                },
                .hash_key => blk: {
                    s.hashKeyDomain(a[0]);
                    break :blk 0;
                },
                .make => blk: {
                    s.makeDomain(a[0], a[1], a[2], a[3], a[4]);
                    break :blk 0;
                },
                .unmake => blk: {
                    s.unmakeDomain(a[0], a[1], a[2], a[3]);
                    break :blk 0;
                },
                .tb_probe => s.tbProbeDomain(a[0], a[1]),
                .attack_map_white => blk: {
                    cx.leafAttackMap(sn.white);
                    break :blk 0;
                },
                .attack_map_black => blk: {
                    cx.leafAttackMap(sn.black);
                    break :blk 0;
                },
                .repetition => s.repetitionDomain(),
                .has_legal_move => blk: {
                    cx.guardRoot(&.{.p});
                    break :blk gamemove.legalMoveExists(&d.p, a[0], a[1]);
                },
                // The evaluator itself (0EF8:89DC / 8F82), not the pawn-hash probe.
                .pawn_eval_wtm => blk: {
                    cx.guardRoot(&.{ .p, .ev });
                    break :blk @as(u16, @bitCast(evalpawns.pawnEval(&d.p, &d.ev, .white)));
                },
                .pawn_eval_btm => blk: {
                    cx.guardRoot(&.{ .p, .ev });
                    break :blk @as(u16, @bitCast(evalpawns.pawnEval(&d.p, &d.ev, .black)));
                },
                .static_eval => @as(u16, @bitCast(cx.staticEval(@truncate(a[0]), @bitCast(a[1])))),
                // 2B9F:4BFE is the White node's leaf term, 5534 the Black node's.
                .hanging_black => @as(u16, @bitCast(cx.leafTermA(sn.white))),
                .hanging_white => @as(u16, @bitCast(cx.leafTermA(sn.black))),
                .pieces_and_kings => @as(u16, @bitCast(cx.pieceEval(@truncate(a[0]), @bitCast(a[1])))),
                .activity_white => blk: {
                    cx.guardRoot(&.{ .p, .ev });
                    break :blk @as(u16, @bitCast(activity.pieceActivityWhiteFixes(fixes, &d.p, &d.ev)));
                },
                .activity_black => blk: {
                    cx.guardRoot(&.{ .p, .ev });
                    break :blk @as(u16, @bitCast(activity.pieceActivityBlackFixes(fixes, &d.p, &d.ev)));
                },
                .endgame_king_white => @as(u16, @bitCast(cx.endgameKing(sn.white))),
                .endgame_king_black => @as(u16, @bitCast(cx.endgameKing(sn.black))),
                .count_attacked_wtm => cx.countAttacked(sn.white),
                .count_attacked_btm => cx.countAttacked(sn.black),
                .prepare_eval => blk: {
                    s.prepareEval();
                    break :blk 0;
                },
                .threats_white, .threats_black => blk: {
                    // The counter is a byte of main's frame ([bp-24h]), `RootVars.frame`.
                    var counter = s.dgByte(a[2]);
                    const r = cx.threats(if (c == .threats_white) sn.white else sn.black, @bitCast(a[0]), a[1], &counter);
                    s.dgSet(a[2], counter);
                    break :blk @as(u16, @bitCast(r));
                },
                else => null,
            };
        }

        /// The callees of main before the loop (rootprep.Callee), on the node domain's
        /// structs: `dispatchPrepDomain`'s, and the rest here. Since Stage B step 8, stage 8,
        /// there is no other binding (Stage A's, on the image, is gone from the engine).
        pub fn dispatchPrep(s: *Self, site: u16, c: rp.Callee, a: []const u16) u32 {
            _ = site;
            s.prep_calls[@backingInt(c)] += 1;
            if (s.dispatchPrepDomain(c, a)) |r| return r;
            return switch (c) {
                .screen_8536, .display_8454, .book_exit_display_1, .book_exit_display_2, .pv_screen_line, .show_move, .show_score, .game_over_display, .end_analysis, .display_7144, .display_72b4, .positions_display, .display_a0b0 => 0,
                .reset_move_time_used, .clocks_run, .poll, .delay, .clear_excluded, .hash_seed_learning => 0,
                .moves_to_go => @as(u16, @bitCast(s.timeCall(tbud.movesToGo, .{}))),
                .add_control_time => blk: {
                    _ = s.timeCall(tbud.addControlTime, .{@as(u1, @truncate(a[0]))});
                    break :blk 0;
                },
                .set_time_budget => blk: {
                    _ = s.timeCall(tbud.setTimeBudget, .{});
                    break :blk 0;
                },
                .play_best_move => blk: {
                    if (s.book_files == null) {
                        s.fail("play_best_move from main before the loop: not bound", .{});
                        break :blk 0;
                    }
                    s.playBestMoveFromMain(a[0]);
                    break :blk 0;
                },
                .book_probe => s.bookProbe(a[0], a[1]),
                .prepare_eval => blk: {
                    s.prepareEval();
                    break :blk 0;
                },
                .hash_resize => s.hashResize(),
                .hash_clear => blk: {
                    for (s.tables) |*t| t.clear();
                    break :blk 0;
                },
                .node_white => s.callNode(sn.white, a[0], a[1], a[2], a[3]),
                .node_black => s.callNode(sn.black, a[0], a[1], a[2], a[3]),
                .rand => s.rand(),
                // `dispatchPrepDomain`'s.
                .gen_evasions, .gen_all_moves, .square_sums, .hash_key, .make, .unmake, .tb_probe, .attack_map_white, .attack_map_black, .repetition, .has_legal_move, .pawn_eval_wtm, .pawn_eval_btm, .static_eval, .hanging_black, .hanging_white, .pieces_and_kings, .activity_white, .activity_black, .endgame_king_white, .endgame_king_black, .count_attacked_wtm, .count_attacked_btm, .threats_white, .threats_black => unreachable,
                .sort_root_moves => blk: {
                    s.fail("sort_root_moves from main: handled by the env", .{});
                    break :blk 0;
                },
            };
        }

        /// The callees of the iteration loop and root_search (rootsearch.Callee), but the
        /// loop's own calls of root_search and the sort, which the env makes. Called inside
        /// the node domain (`iterate`): the position's callees run on its structs.
        pub fn dispatchLoop(s: *Self, rst: *rs.RootState, site: u16, c: rs.Callee, a: []const u16) u32 {
            _ = site;
            s.assertEntered();
            s.loop_calls[@backingInt(c)] += 1;
            return switch (c) {
                .square_sums => blk: {
                    s.squareSumsDomain(a[0]);
                    break :blk 0;
                },
                .hash_key => blk: {
                    s.hashKeyDomain(a[0]);
                    break :blk 0;
                },
                .make => blk: {
                    s.makeDomain(a[0], a[1], a[2], a[3], a[4]);
                    break :blk 0;
                },
                .unmake => blk: {
                    s.unmakeDomain(a[0], a[1], a[2], a[3]);
                    break :blk 0;
                },
                .repetition => s.repetitionDomain(),
                .tb_probe => s.tbProbeDomain(a[0], a[1]),
                .node_white => s.callNode(sn.white, a[0], a[1], a[2], a[3]),
                .node_black => s.callNode(sn.black, a[0], a[1], a[2], a[3]),
                .root_move_search => s.ply2(rst, a[0], a[1], a[2]),
                .poll => 0,
                .rand => s.rand(),
                .analysis => 0,
                .planning_header, .show_move, .show_char, .show_score, .show_at, .show_text, .show_number, .pv_screen_begin, .pv_screen_window, .pv_screen_line, .pv_screen_flush, .pv_screen_end => 0,
                .keep_fail_high, .root_search, .sort_root_moves => blk: {
                    s.fail("{s}: handled by the env", .{@tagName(c)});
                    break :blk 0;
                },
            };
        }

        // ---- the two envs -------------------------------------------------------------

        pub const PrepEnv = struct {
            s: *Self,
            st: *rp.PrepState,

            /// Main runs inside the node domain (stage 3c-1). Since Stage B step 8, stage 5,
            /// every callee runs on the domain's structs and the homes of its variables, and
            /// none is bracketed; since stage 7 main's own variables are members too
            /// (`RootVars`, `ProgramVars`), and main's view points at them, so nothing is
            /// copied around a call. A hook (the tests) reads the tests' image as the original
            /// would have it at the call, and may write it: the members are stored to it around
            /// its calls and loaded again after (src/state_image.zig), as `LoopEnv.call` does;
            /// the callee itself runs between them on the members.
            pub fn call(e: *PrepEnv, site: u16, callee: rp.Callee, args: []const u16) u32 {
                const s = e.s;
                if (callee == .sort_root_moves) {
                    // 0000:668E on the root list (DG:3BC4, args[0]), the port's routine.
                    rs.sortRootMoves(e.st.root_moves[0..], e.st.root_scores[0..], @bitCast(args[1]));
                    return 0;
                }
                s.assertEntered();
                if (builtin.is_test) if (s.hook) |h| {
                    si.exit(&s.node);
                    const run = h.before(h.ctx, site, .{ .prep = callee }, args);
                    si.enter(&s.node);
                    const real: ?u32 = if (run) s.dispatchPrep(site, callee, args) else null;
                    si.exit(&s.node);
                    const r = h.after(h.ctx, site, .{ .prep = callee }, args, real);
                    si.enter(&s.node);
                    return r;
                };
                return s.dispatchPrep(site, callee, args);
            }
            pub fn far(e: *PrepEnv, site: u16, segvar: u16, off: u16) u8 {
                _ = segvar;
                if (builtin.is_test) if (e.s.hook) |h| if (h.far) |f| if (f(h.ctx, site, off)) |v| return @truncate(v);
                return e.s.farByte(off);
            }
            pub fn clock(e: *PrepEnv, site: u16) u32 {
                if (builtin.is_test) if (e.s.hook) |h| if (h.far) |f| if (f(h.ctx, site, clock_offset)) |v| return v;
                return e.s.ticks;
            }
            pub fn farWrite(e: *PrepEnv, site: u16, segvar: u16, off: u16, value: u16) void {
                _ = site;
                _ = segvar;
                e.s.setFarWord(off, value);
            }
            /// A byte of main's frame (or of the top of the segment), at its home
            /// (`RootVars.frame`, `stack_top`).
            pub fn local(e: *PrepEnv, addr: u16) u8 {
                return e.s.dgByte(addr);
            }
            /// The move-mark table DG:781A, which main clears (clear_move_marks): the
            /// search's (`SearchVars.marks`), its one home while main runs in the domain.
            pub fn marks(e: *PrepEnv) *[mg.marks_len]u8 {
                return &e.s.node.dom.sv.marks;
            }
            pub fn notModelled(e: *PrepEnv, site: u16) void {
                e.s.fail("main before the loop: branch {X:0>4} not modelled", .{site});
            }
        };

        pub const LoopEnv = struct {
            s: *Self,
            st: *rs.RootState,

            pub fn call(e: *LoopEnv, site: u16, callee: rs.Callee, args: []const u16) u32 {
                const s = e.s;
                switch (callee) {
                    // The loop's own calls: the port's routines on the same state.
                    .root_search => {
                        const r = rs.rootSearch(e.st, e, root_search_bp, @bitCast(args[0]), @bitCast(args[1]));
                        if (s.observer) |o| {
                            // The end of the search after this iteration: the loop limit
                            // DG:64 (written only by main before the loop, rootprep 0000:13F6
                            // ff., and read only at the loop's top) becomes this depth + 1,
                            // what main writes for Fixed depth of this depth. The loop then
                            // goes on as after any iteration (the depth step, the mate stop,
                            // the sort) and ends at 146F.
                            if (o.iterationDone(o.ctx, site, @bitCast(args[0]), @bitCast(args[1]), r, e.st))
                                e.st.loop_limit.* = @as(i16, e.st.depth.*) + 1;
                        }
                        return @as(u16, @bitCast(r));
                    },
                    .sort_root_moves => {
                        rs.sortRootMoves(e.st.root_moves[0..], e.st.root_scores[0..], @bitCast(args[1]));
                        return 0;
                    },
                    .keep_fail_high => {
                        rs.keepFailHigh(e.st);
                        return 0;
                    },
                    else => {},
                }
                if (s.observer) |o| o.call(o.ctx, site, callee, args, e.st);
                if (builtin.is_test) if (s.hook) |h| {
                    // A hook (the tests) reads the tests' image as the original would have it
                    // at the call, and may write it: the members are stored to it around each
                    // of its calls and loaded from it again after (src/state_image.zig).
                    si.exit(&s.node);
                    const run = h.before(h.ctx, site, .{ .loop = callee }, args);
                    si.enter(&s.node);
                    const real: ?u32 = if (run) s.dispatchLoop(e.st, site, callee, args) else null;
                    si.exit(&s.node);
                    const r = h.after(h.ctx, site, .{ .loop = callee }, args, real);
                    si.enter(&s.node);
                    return r;
                };
                return s.dispatchLoop(e.st, site, callee, args);
            }
            pub fn volatileRead(e: *LoopEnv, site: u16) u32 {
                return switch (site) {
                    // [75B6], the poll requests (not a RootState field): the node's `State`
                    // holds it while the loop runs.
                    0x23CE => e.s.node_state.poll_pending,
                    0x23DD, 0x2CB5 => blk: {
                        if (builtin.is_test) if (e.s.hook) |h| if (h.far) |f| if (f(h.ctx, site, clock_offset)) |v| break :blk v;
                        break :blk e.s.ticks;
                    },
                    else => e.st.stop.*,
                };
            }
            /// A byte of root_search's frame, at its home (`RootVars.frame`).
            pub fn local(e: *LoopEnv, addr: u16) u8 {
                return e.s.dgByte(addr);
            }
            /// The move-mark table DG:781A, which root_search marks: the search's
            /// (`SearchVars.marks`), its one home while the loop runs.
            pub fn marks(e: *LoopEnv) *[mg.marks_len]u8 {
                return &e.s.node.dom.sv.marks;
            }
            pub fn excluded(e: *LoopEnv, move: [4]u8) bool {
                _ = move;
                e.s.fail("the excluded-move list is not bound", .{});
                return false;
            }
            pub fn notModelled(e: *LoopEnv, site: u16) void {
                e.s.fail("root: branch {X:0>4} not modelled", .{site});
            }
        };

        /// Main before the loop, on the members: returns its exit (the tests; `search` runs
        /// it with the loop).
        pub fn prepare(s: *Self, entry: rp.Entry) rp.Exit {
            return s.prepareIn(entry);
        }

        /// Main before the loop on the members (Stage B step 7, stage 3c-1): main's view
        /// points at the domain's structs for every variable and table they hold
        /// (`rootprep.bindDomain`) and at `RootVars` and `ProgramVars` for the rest
        /// (`rootprep.bindRoot`, Stage B step 8, stage 7).
        fn prepareIn(s: *Self, entry: rp.Entry) rp.Exit {
            s.assertEntered();
            var st: rp.PrepState = .{};
            const d = s.node.dom;
            rp.bindRoot(&st, &d.rv, &d.pg);
            rp.bindDomain(&st, s.node_state, &d.p, &d.ev, &d.tv, &d.s, &d.lv);
            var e: PrepEnv = .{ .s = s, .st = &st };
            return rp.rootPrepFixes(fixes, .zero, &st, &e, main_bp, entry);
        }

        /// The iteration loop on the members (Stage B step 7, stage 3b): the loop's view
        /// points at the domain's structs for every variable they hold
        /// (`rootsearch.bindDomain`) and at `RootVars` and `ProgramVars` for the rest
        /// (`rootsearch.bindRoot`), its callees run on them, and its node and ply-2 calls
        /// copy nothing. A stopped loop returns through the same path.
        pub fn iterate(s: *Self) void {
            // The loop's view of its variables (a struct of pointers, as main's `PrepState`
            // in `prepareIn`), on the stack: nothing is allocated in a search.
            var view: rs.RootState = .{};
            const st = &view;
            var e: LoopEnv = .{ .s = s, .st = st };
            s.assertEntered();
            const d = s.node.dom;
            rs.bindRoot(st, &d.rv, &d.pg);
            rs.bindDomain(st, s.node_state, &d.p, &d.ev, &d.tv, &d.s);
            s.stop_armed = true;
            s.stop_fired = false;
            s.loop_entries = 0;
            rs.iterationLoop(st, &e, main_bp);
            s.stop_armed = false;
        }

        /// One search from the image at main 0000:0526 (`entry` .own): main before the
        /// loop, then the loop if main goes there. The counts start at prepare_eval, as
        /// the oracle's do; a search that ends before prepare_eval counts nothing.
        ///
        /// The search runs on the members (the node domain), whichever way main ends: a
        /// book move (main 06EF, play_best_move, runs on the domain's structs and main
        /// returns at once), a tablebase move or one legal move played without a search, a
        /// stop before the loop, a menu request, the game's end, or the loop's end. Every
        /// variable is at its home (`Home`, `RecordHome`: the conclusion and the game-move
        /// path, src/engine.zig, src/uci_report.zig, src/adapt_setup.zig, src/newgame.zig);
        /// the best move DG:A36C is the root's own variable (`RootVars.best_move`). A test
        /// that reads its image makes it current first (src/state_image.zig `toImage`).
        pub fn search(s: *Self, entry: rp.Entry) Outcome {
            s.assertEntered();
            // A write into the tests' image since the last load outside a bracket would be
            // lost: their image check reports it (Debug, ReleaseSafe test builds).
            if (builtin.is_test) si.checkImage(&s.node);
            s.beginSearch();
            const exits0 = if (builtin.is_test) s.node.codec.exits else 0;
            const x = s.prepareIn(entry);
            if (x == .iteration_loop and s.failure == null) s.iterate();
            // Stage B step 8, stage 5: no callee of main or of the loop stores the members
            // to the tests' image (counted in test builds; a hook's own stores count).
            if (builtin.is_test) s.search_exits = s.node.codec.exits - exits0;
            return .{ .exit = x, .best = s.dgBytes(0xA36C, 4), .nodes = s.nodes, .makes = s.makes };
        }

        /// From the return of play_best_move to main 0000:0526 of the next search, in
        /// auto-play (the oracle's golden files) [read: main 023C-04A8, the command loop's
        /// entry 38C0:174A-1974, its auto-play path 3FAA-3FFE and exit 517C, main
        /// 04AD-0525; traced with tools/research/newgame/trace.py]: [9FD0] = 0 (main
        /// 16EA, in the conclusion before play_best_move, for a search not pondering);
        /// main's [8BAA] = [153C] = [3676] = 0 and [9EEC] = [717C]; the control-time test;
        /// the command loop: [8BAA] = [A4FA] = 0, the move number + 1 when White is to move,
        /// the program takes the side to move ([8DDE] = [717C], [717C] the other side,
        /// [A8DA] = [A3FA] = [A6AE] = 0, its time left from its clock, [AB9E] = 2),
        /// [B4DE] = the game ply; main [B620] = [1B8A] = [776A] = 0. The game board DG:7520
        /// (the screen's) takes the search board's squares [traced by snapshot: its
        /// writer was not found]. At move number 202 the command loop ends the game instead
        /// (38C0:1974, `newgame.commandLoopEntry`): the program does not take the move and
        /// `failure` says so.
        /// Since Stage B step 8, stage 4, the turn routines (this one, `toOpponentMove`,
        /// the second half of `enterMove`, `autoPlay`, `togglePondering`, the command
        /// loop's entry and exit, main's top and the time state's calls) have no bracket:
        /// every variable at its home (`Home`, `RecordHome`), so that they run on the
        /// members with the domain entered and on the image inside a caller's bracket.
        pub fn nextTurnAutoPlay(s: *Self) void {
            s.slideIfDue();
            s.dgSet(0x9FD0, 0);
            if (!s.toCommandLoop()) {
                s.fail(game_over_text, .{});
                return;
            }
            s.programTakesMove();
            s.gameBoardFromSearch();
        }

        /// The game board DG:7520 takes the search board's squares 21..98 that are not
        /// border (DG:9EF6, `Position.board`).
        fn gameBoardFromSearch(s: *Self) void {
            for (21..99) |sq| {
                const v = s.dgByte(@intCast(0x9EF6 + sq));
                if (v != 7) s.dgSet(@intCast(0x7520 + sq), v);
            }
        }

        // ---- start-up, the turn, New game (src/newgame.zig) ------------------------------

        /// next_control_moves (1E9D:6E40) [read]: for each side, the first control after
        /// its move number (one more for White while Black's clock runs, one less again
        /// while pondering): the period's first move, plus whole periods.
        fn nextControlMovesTs(st: *tbud.TimeState) void {
            for (0..2) |k| {
                const side: u1 = @intCast(k);
                var m: i16 = st.move_number.*;
                if (st.clockSide() == 1) {
                    if (side == 0) m +%= 1;
                    if (st.isPondering()) m -%= 1;
                }
                const pl = tbud.periodLength(st, side);
                var next = pl.first;
                while (next <= m) next +%= pl.moves;
                st.next_control[side] = next;
            }
        }

        /// reset_clocks (1E9D:702E) as it ends at the untimed levels [traced, level 3]:
        /// both sides' time left 0 (7112-711B); the displayed clocks 0 and the ticks to
        /// the next second 18 (4793:34EA, 3553-3598). Its timed-level values are not
        /// ported: at start-up they are replaced by the level change.
        fn resetClocksTs(st: *tbud.TimeState) void {
            st.time_left.* = .{ 0, 0 };
            st.display = .{ .{ 0, 0, 0 }, .{ 0, 0, 0 } };
            st.tick58.* = .{ 18, 18 };
        }

        /// 38C0:3FC2-3FD8: the program's time left from its displayed clock
        /// (clock_to_ticks 1E9D:6AF4).
        fn programTimeLeftTs(st: *tbud.TimeState) void {
            const side = st.computerSide();
            st.time_left[side] = tbud.clockToTicks(st, side);
        }

        /// main 0000:0444-04A5 [read]: the time control of the program's side is renewed
        /// before the command loop when it is at most one move away, at level 0 with a
        /// preset, or at level 2 within the record ([B4CE + 14 side]); add_control_time
        /// does nothing at the untimed levels.
        fn controlTimeTest(s: *Self) void {
            // UNVERIFIED: recorded only at level 3, where add_control_time does nothing.
            if (s.dgWord(0xA00E) != 0 or s.dgWord(0x3698) != 0) return;
            const side: u1 = @truncate(s.dgByte(0x8DDE));
            const mn: i16 = @bitCast(s.dgWord(0xA84A));
            if (s.dgByte(0xA8C6) == 0 or s.dgByte(0xA274) != 0) {
                if (s.dgByte(0xA274) != 2) return;
                const last: i16 = @bitCast(s.dgWord(@intCast(0xB4CE + 14 * @as(u16, side))));
                if (last < mn) return;
            }
            const next: i16 = @bitCast(s.dgWord(@intCast(0x73FA + 2 * @as(u16, side))));
            if (next -% mn > 1) return;
            _ = s.timeCall(tbud.addControlTime, .{side});
        }

        /// The level change of the Levels menu: next_control_moves and reset_clocks
        /// (after 2B9F:B8FA level_changed, traced).
        fn levelChanged(s: *Self) void {
            _ = s.timeCall(nextControlMovesTs, .{});
            _ = s.timeCall(resetClocksTs, .{});
        }

        /// main 013B-023B (newgame.mainTop) with its time state: 01F5-0203 runs
        /// next_control_moves and reset_clocks with the move number one higher.
        fn mainTop(s: *Self) void {
            if (!newgame.mainTop(s.home())) return;
            s.dgSetWord(0xA84A, s.dgWord(0xA84A) +% 1);
            _ = s.timeCall(nextControlMovesTs, .{});
            _ = s.timeCall(resetClocksTs, .{});
            s.dgSetWord(0xA84A, s.dgWord(0xA84A) -% 1);
        }

        /// main 023C to the command loop, and the command loop's entry. False if the
        /// command loop ends the game at move number 202 (38C0:1974).
        fn toCommandLoop(s: *Self) bool {
            newgame.mainBeforeCommandLoop(s.home());
            s.controlTimeTest();
            return newgame.commandLoopEntry(s.home());
        }

        /// Between turns (after play_best_move, before the command loop), from game ply 300
        /// (`gameslide.due`): the oldest plies of the game record are dropped and every game
        /// ply and move number renumbered, as far as every absolute test of the original
        /// allows (`gameslide.maxSlide`: the game ply stays at 202 or more), so that the
        /// command loop never reaches its end at move number 202 (docs/arch/34-game-move-
        /// path.md, "Playing on past move 201: the slide"; DEV-F19). The node's copy of the
        /// record's keys is refreshed whole. Nothing changes in a game shorter than 300
        /// plies. Since Stage B step 8, stage 4, on the homes: DGROUP's variables at their
        /// members (`Home`) and the game record in place (`RecordHome`, through the far
        /// tables' offsets), with no bracket.
        pub fn slideIfDue(s: *Self) void {
            if (!s.slide_when_due or !gameslide.dueAt(s.home())) return;
            const d = gameslide.maxSlideAt(s.home());
            if (d == 0) return;
            // Cannot fail: maxSlide leaves at least gameslide.min_ply plies.
            gameslide.slideAt(s.home(), s.recordHome(), d) catch return;
            s.dropped_plies += d;
        }

        /// What `failure` says when the command loop has ended the game at move 202.
        pub const game_over_text = "the original ends the game at move 202 (38C0:1974: the game record holds move numbers 0..202)";

        /// 38C0:3FAA-517F: the program takes the side to move, and the command loop
        /// returns to main, which runs to 0526 (newgame.mainToSearch).
        fn programTakesMove(s: *Self) void {
            newgame.programTakesMove(s.home());
            _ = s.timeCall(programTimeLeftTs, .{});
            newgame.commandLoopExit(s.home());
            newgame.mainToSearch(s.home());
        }

        /// The program's start as far as it writes engine state (docs/arch/34-game-move-
        /// path.md, "Start-up"), then the menu choices of the repeatable state (book
        /// ignored, learning and book learning off, Fixed depth `depth`), leaving the
        /// program in its command loop with White to move, as the oracle's scenarios find
        /// it before their first key of play: the C start-up's image (`dgroup.initial`),
        /// main 0083, hash_setup, the start-up constants, new_game_position (0000:919A,
        /// from 0000:7728), the settings files (38C0:B976), the book key of the start
        /// position (4793:5816 from 0000:774F), main from 013B to the command loop, and
        /// the menus. The far segment 5A7B starts as zeros (only the game record is held
        /// by a unit). The main hash tables and the pawn hash start empty.
        ///
        /// Stage B step 8, stage 4: the C start-up's image and the far segment of zeros are
        /// loaded into the members once (since stage 8 `loadStart`: every member's mapped
        /// bytes, the copies of bytes another member holds included, decoded from the
        /// executable's initialised data, the one image the engine reads); then every
        /// routine runs on the members, DGROUP's variables at their homes (`Home`), the
        /// record in `rec`, and the copies are refreshed from their homes at the end
        /// (`refreshAliases`), as Stage A's bracket refreshed them.
        pub fn startUp(s: *Self, mc: newgame.Machine, settings: newgame.Settings, ub: newgame.UserBooks, depth: u16) void {
            s.loadStart();
            s.dropped_plies = 0;
            for (s.tables) |*t| t.clear();
            s.pawn_hash.clear();
            s.ticks = 0;
            s.failure = null;
            const m = s.home();
            m.set(0x9316, 3); // main 0083
            m.set(0x9350, 0);
            newgame.hashSetup(m, mc.xms_free_kb);
            newgame.startUpConstants(m, mc);
            newgame.newGameClears(m);
            s.newGame();
            newgame.loadSettings(m, settings, ub);
            s.bookKeyOfPosition(.white);
            // 4793:8CBA (from 0000:7763) [traced]: the key into the game record at ply 0.
            s.rec.book_keys[0] = s.node.dom.gv.book_key;
            s.mainTop();
            _ = s.toCommandLoop(); // move number 0 or 1: never the end
            newgame.repeatableState(m, depth);
            s.levelChanged();
            s.refreshCopies();
        }

        /// 4793:5816, the book key of the search position for `side`, into DG:935A
        /// (`GameVars.book_key`), on the domain's `Position`.
        fn bookKeyOfPosition(s: *Self, side: pos.Side) void {
            const d = s.node.dom;
            s.node.refreshAliases(&.{.p});
            d.gv.book_key = book.bookKey(book.BookPosition.fromPosition(&d.p, side));
        }

        /// Runs `f(&Position, &SetupVars, args...)` (a routine of src/setup.zig: the
        /// build, New game's position) on the domain's `Position` and on the set-up
        /// variables, exactly as the routine ran on structs loaded from the image and
        /// stored back (Stage A): the `Position`'s copies of bytes another member holds
        /// are first refreshed from their homes; `SetupVars` (no member: its bytes are
        /// declared also by the game variables, the root's views and the members, Stage B
        /// step 8, stage 4) is loaded from each byte's home (`Home`) and its changed bytes
        /// stored back there; then the `Position`'s changed bytes, last as before, so that
        /// a byte both change keeps the position's value and a write through the
        /// position's over-long declarations reaches the byte's holder.
        pub fn onPositionAndSetup(s: *Self, comptime f: anytype, args: anytype) void {
            s.assertEntered();
            const d = s.node.dom;
            s.node.refreshAliases(&.{.p});
            var pb: PositionMap.Snapshot = undefined;
            PositionMap.snapshot(&d.p, &pb);
            var sv: setup.SetupVars = .{};
            var svb: SetupVarsMap.Snapshot = undefined;
            SetupVarsMap.loadSnapVia(&sv, s.home(), &svb);
            @call(.auto, f, .{ &d.p, &sv } ++ args);
            _ = SetupVarsMap.storeChangedVia(&sv, s.home(), &svb);
            _ = PositionMap.storeChangedVia(&d.p, s.home(), &pb);
        }

        /// Ctrl-A in the command loop (38C0:3F1C, newgame.autoPlayKey): auto-play, the
        /// program takes the side to move, and main runs to 0526, where `search` starts.
        /// False at move 202 or later (the original then refuses).
        pub fn autoPlay(s: *Self) bool {
            if (!newgame.autoPlayKey(s.home())) return false;
            s.programTakesMove();
            return true;
        }

        /// The New game command (Ctrl-N, confirmed; 38C0:3BB4-3C37) from the command loop,
        /// to main 0000:0526 [read; proved against the oracle after a game of normal play,
        /// src/newgame_test.zig]: srand(the BIOS tick count) (new_game_reseed 4793:322E;
        /// the engine keeps the seed, a platform input); [8C2E] = [ACF2] = 0 (38C0:155C);
        /// the speed calibration again (1E9D:54DE, DG:7258 = m.speed); [A00D] = [A6AE] =
        /// 0; new_game_keep_settings (38C0:169E): 0000:919A with the
        /// learning flags DG:A6A0 and DG:AC29 kept, [A84A] = 1; then [A84A] = 0, the last
        /// played ply DG:A36A kept (0 with the book off); [153C] = [2500] = 1; the
        /// the return to main (04AD) and main to 0526. Not ported: the
        /// displays and 0EF8:745E (no engine state written before 0526 [traced]).
        pub fn newGameCommand(s: *Self, mc: newgame.Machine) void {
            s.assertEntered();
            s.dgSetWord(0x3698, 0); // the command loop, 38C0:1C1B [traced]
            s.dgSetWord(0x7258, mc.speed); // 1E9D:54DE: the speed calibration is run again
            s.dgSetWord(0x8C2E, 0);
            s.dgSetWord(0xACF2, 0);
            s.dgSet(0xA00D, 0);
            s.dgSetWord(0xA6AE, 0);
            const kept_ply: u16 = if (s.dgByte(0x70E4) != 0) 0 else s.dgWord(0xA36A);
            const learn = s.dgWord(0xA6A0);
            const ac29 = s.dgByte(0xAC29);
            newgame.newGameClears(s.home());
            s.newGame();
            s.dgSetWord(0xA6A0, learn);
            s.dgSet(0xAC29, ac29);
            s.dgSetWord(0xA84A, 0); // 169E sets 1, 3BF3 0
            s.dgSetWord(0xA36A, kept_ply);
            s.dgSetWord(0x153C, 1);
            s.dgSetWord(0x2500, 1);
            newgame.mainToSearch(s.home());
            s.refreshCopies();
        }

        /// main from 0526 after the New game command ([153C] set): 0526-0537, back to 013B,
        /// and on to the command loop ([read]; with the book off, 01C6's book_probe is not
        /// called).
        pub fn mainAfterNewGame(s: *Self) void {
            // UNVERIFIED: read only; the original asks for the CD-ROM after New game in the
            // emulator, so the search that follows could not be recorded.
            s.dgSet(0x8DDE, 1 -% s.dgByte(0x717C));
            s.dgSetWord(0xA3FA, 0);
            s.dgSetWord(0xA00E, 0);
            s.dgSetWord(0x8C30, 0);
            s.mainTop();
            _ = s.toCommandLoop(); // a new game: never the end
        }

        /// New game as far as it is ported (0000:919A): the search position
        /// (`setup.newGame`) and the game variables (`gamemove.newGameVars`). Its clears of
        /// 919C-9250 are `newgame.newGameClears`, which the callers (`startUp`,
        /// `newGameCommand`) run first. Since Stage B step 8, stage 4, on the domain's
        /// `Position` and `GameVars` and on the record `rec`, the set-up
        /// variables through their homes (`onPositionAndSetup`), in the order the stores
        /// had: the record and the game variables as written, then the set-up variables,
        /// then the position.
        pub fn newGame(s: *Self) void {
            s.onPositionAndSetup(newGameOn, .{s});
        }

        fn newGameOn(p: *pos.Position, sv: *setup.SetupVars, s: *Self) void {
            setup.newGame(p, sv);
            gamemove.newGameVars(p, &s.node.dom.gv, s.rec, s.dgWord(0xA512));
        }

        /// The members' copies of bytes another member holds, each set from its home
        /// (`NodeEnv.refreshAliases`): what Stage A's bracket gave them.
        pub fn refreshCopies(s: *Self) void {
            if (s.refresh_copies) s.node.refreshAliases(&NodeEnv.all_members);
        }

        // ---- after the search: the conclusion and the program's move ----------------

        fn gameMake(p: *pos.Position, buf: *[5]u8, side: u8, ply: u16) void {
            var u: pos.Undo = .{ .captured = buf[3], .captured_slot = buf[4] };
            p.makeMove(.{ .from = buf[0], .to = buf[1], .flag = buf[2], .score = 0 }, sideOf(side), ply, &u);
            buf[3] = u.captured;
            buf[4] = u.captured_slot;
        }
        fn gameUnmake(p: *pos.Position, move: [5]u8, side: u8) void {
            var u: pos.Undo = .{ .captured = move[3], .captured_slot = move[4] };
            p.unmakeMove(.{ .from = move[0], .to = move[1], .flag = move[2], .score = 0 }, sideOf(side), &u);
        }

        /// The game-move callees of play_best_move, check_entered_move and
        /// play_entered_move (src/gamemove.zig `Ctx`) on the node domain's structs, the
        /// game variables (`Members.gv`) and the game record (`rec`), Stage B step 8,
        /// stage 2: make and take-back, the square sums, the keys and the legality tests
        /// on the domain's `Position` and `EvalVars`, the book on the domain. Since stage
        /// 3 the move generators at ply 0 (into the list DG:3A34, the node's
        /// `State.move_list[0]`) and set_predicted_reply with every routine it calls
        /// (`replyDispatch`) run on the domain too, with no bracket. Other DGROUP
        /// variables are read and written at their homes (`dgByte`).
        const DomainGameCtx = struct {
            s: *Self,

            fn dom(c: *DomainGameCtx) *est.Members {
                return c.s.node.dom;
            }
            pub fn notation(c: *DomainGameCtx, from: u8, to: u8, moving: u8) u8 {
                _ = c;
                _ = from;
                _ = to;
                _ = moving;
                return 0; // 38C0:D5E2, the notation bits: user interface
            }
            pub fn squareSums(c: *DomainGameCtx, move: [3]u8) void {
                const d = c.dom();
                squaresums.updateSquareSums(&d.p, &d.ev, .{ .from = move[0], .to = move[1], .flag = move[2], .score = 0 });
            }
            pub fn makeMove(c: *DomainGameCtx, buf: *[5]u8, side: u8, ply: u16) void {
                gameMake(&c.dom().p, buf, side, ply);
            }
            pub fn unmakeMove(c: *DomainGameCtx, move: [5]u8, side: u8) void {
                gameUnmake(&c.dom().p, move, side);
            }
            pub fn bookKey(c: *DomainGameCtx, side: u8) void {
                const d = c.dom();
                d.gv.book_key = book.bookKey(book.BookPosition.fromPosition(&d.p, sideOf(side)));
            }
            pub fn hashFromScratch(c: *DomainGameCtx) void {
                const p = &c.dom().p;
                const k = p.hashFromScratch();
                p.hash_key = k.main;
                p.pawn_hash_key = k.pawn;
            }
            pub fn legalMoveExists(c: *DomainGameCtx, side: u8) u16 {
                return gamemove.legalMoveExists(&c.dom().p, side, 0);
            }
            /// set_predicted_reply (38C0:0D22; its argument is not read) on the domain: the
            /// search position, the game variables and the ply-0 list DG:3A34 (the node's
            /// `State.move_list[0]`), its callees through `replyCall`.
            pub fn predictReply(c: *DomainGameCtx, arg: u16) void {
                _ = arg;
                const s = c.s;
                s.assertEntered();
                s.predict_calls += 1;
                const d = c.dom();
                gamemove.setPredictedReplyFixes(fixes, &d.p, &d.gv, s.node_state.move_list[0][0..100], c);
            }
            /// 38C0:E260 (in check) or gen_all_moves 1E9D:3938 for `side` at ply 0, into
            /// the list DG:3A34 (`State.move_list[0]`), as the node generates; the count.
            pub fn genMoves(c: *DomainGameCtx, side: u8, in_check: bool) u16 {
                return c.s.node.generate(if (in_check) .evasions else .all, @truncate(side), 0);
            }
            /// The routines set_predicted_reply calls (`gamemove.ReplyCallee`).
            pub fn replyCall(c: *DomainGameCtx, callee: gamemove.ReplyCallee, a: u16, b: u16) u16 {
                return c.s.replyDispatch(callee, a, b);
            }
            pub fn bookProbe(c: *DomainGameCtx, mode: u16, side: u8) void {
                const s = c.s;
                const d = c.dom();
                const gv = &d.gv;
                const session: book.Session = .{
                    .book_exit_ply = @bitCast(gv.book_exit_ply.*),
                    .book_disabled = gv.b70e4.* != 0,
                };
                if (s.book_files) |files| {
                    // Modes 2 and 3 (after a game move, a new game): no draw, no move.
                    var sess: book.Session = .{
                        .book_exit_ply = @bitCast(gv.book_exit_ply.*),
                        .book_disabled = gv.b70e4.* != 0,
                        .book_move_ply = .{ s.dgWord(0x2522), s.dgWord(0x2524) },
                    };
                    const settings = book.Settings.fromFlags(s.dgWord(0xA6A0), s.dgWord(0xA5EE));
                    var r: book.Rand = .{ .seed = s.dgDword(0x2DC8) };
                    const res = book.probeFixes(fixes, &sess, files, book.BookPosition.fromPosition(&d.p, sideOf(side)), d.p.game_ply, @fromBackingInt(@intCast(@as(u8, @truncate(mode)))), settings, &r);
                    if (res.early) return;
                    gv.book_key = res.key;
                    s.dgSet(0x7449, res.name);
                    gv.book_exit_ply.* = @bitCast(sess.book_exit_ply);
                    return;
                }
                if (!book.gate(&session, d.p.game_ply)) return;
                if (s.dgWord(0xA5EE) == 0) return s.fail("book_probe with the M-Chess book on: not bound", .{});
                gv.book_key = book.bookKey(book.BookPosition.fromPosition(&d.p, sideOf(side)));
                s.dgSet(0x7449, 0);
                if ((mode == 1 or mode == 3) and gv.book_exit_ply.* == 0) gv.book_exit_ply.* = d.p.game_ply;
            }
            pub fn resetMoveTime(c: *DomainGameCtx) void {
                _ = c; // 1E9D:7E8A: the clock
            }
            pub fn kingAttacked(c: *DomainGameCtx, side: u8) u16 {
                return gamemove.kingAttacked(&c.dom().p, side);
            }
            pub fn gameBoard(c: *DomainGameCtx, square: u8) u8 {
                return c.s.dgByte(0x7520 + @as(u16, square));
            }
            pub fn ported(c: *DomainGameCtx, site: u16, ax: u16) void {
                _ = c;
                _ = site;
                _ = ax;
            }
            pub fn ui(c: *DomainGameCtx, site: u16) void {
                _ = c;
                _ = site;
            }
        };

        /// What main does from the end of the iteration loop to the program's move, for
        /// a search that is not pondering and not stopped (docs/arch/31-root-iteration-
        /// time.md section 6, steps 1 to 4, and the conclusion 160C-1618), then
        /// play_best_move(0) (38C0:01E0, src/gamemove.zig). Not ported (and so left out):
        /// the clock charge (16EF-1756, 4.6), the displays, the 50-move message, and
        /// what main does from 023C to the next 0526 (the ponder start, the turn).
        /// On the domain's structs, the game variables and the game record (Stage B step
        /// 8, stage 2); main's variables by address at their homes.
        pub fn playMove(s: *Self) void {
            s.assertEntered();
            // 160C-1618: the conclusion.
            if (s.dgByte(0xA4FA) == 0) s.dgSet(0x9FD0, 1);
            s.dgSet(0x724D, 0);
            s.dgSetWord(0x0062, 35);
            // 1767: the predicted reply and the PV length.
            const pv_len: i8 = @bitCast(s.dgByte(0xB42B));
            s.dgSetWord(0xA416, if (pv_len >= 2) s.dgWord(0x93B2) & 0x7F7F else 0);
            if (s.dgByte(0xAE36) != 0) s.dgSet(0xB42B, 1);
            s.dgSet(0xAB9E, 0);
            s.dgSetWord(0x9312, 0);
            s.dgSetDword(0x740A, 0);
            // 38C0:01E0(0) on the move at [73F8] (= DG:A36C, the root's own: the image).
            const d = s.node.dom;
            var c: DomainGameCtx = .{ .s = s };
            s.node.guardRoot(&.{ .p, .ev });
            gamemove.playBestMove(&d.p, &d.gv, s.rec, 0, s.dgBytes(0xA36C, 3), &c);
        }

        // ---- normal play: set_predicted_reply's callees, the opponent's move ----------

        /// set_predicted_reply's static_eval calls push one argument (38C0:0E3D, 0E61,
        /// 0F31, 0F56); static_eval's second argument [bp+8] (ply - [9356], read only by
        /// the passed-pawn loops) is then the word above it, set_predicted_reply's saved
        /// SI (38C0:0D27), which is play_best_move's SI at its call 38C0:04AF: 8CD2h, left
        /// by the three movsw from DG:8CCC at 38C0:0390-0395 [read].
        const reply_static_eval_arg2: u16 = 0x8CD2;

        /// The routines set_predicted_reply calls (gamemove.ReplyCallee) on the domain's
        /// structs (Stage B step 8, stage 3), each the routine main's binding runs inside
        /// the domain (`dispatchPrepDomain`): prepare_eval on the domain (`prepareEval`),
        /// the square sums and the key of reply `a` in the ply-0 list (`State.move_list[0]`),
        /// the evaluator terms through the domain's `NodeEnv`, and the sort of the list with
        /// the scores DG:8D0A (`GameVars.reply_scores`, whose home is the image).
        fn replyDispatch(s: *Self, c: gamemove.ReplyCallee, a: u16, b: u16) u16 {
            const cx = &s.node;
            const d = cx.dom;
            s.assertEntered();
            switch (c) {
                // prepare_eval (0000:9582), with its key into the game record and its
                // clear of the pawn hash (0000:B9D0 calls 8B50).
                .prepare_eval => s.prepareEval(),
                // set_prescore_margins (0000:6BE4) / set_search_margins (0000:6BF8).
                .prescore_margins => s.setMargins(70, 100),
                .search_margins => s.setMargins(200, 720),
                .square_sums => s.squareSumsDomain(list0 + 4 * a),
                .update_key => s.hashKeyDomain(list0 + 4 * a),
                .leaf_attack_map_white => cx.leafAttackMap(sn.white),
                .leaf_attack_map_black => cx.leafAttackMap(sn.black),
                // The evaluator itself (0EF8:89DC / 8F82), not the pawn-hash probe.
                .pawn_eval_wtm => {
                    cx.guardRoot(&.{ .p, .ev });
                    return @bitCast(evalpawns.pawnEval(&d.p, &d.ev, .white));
                },
                .pawn_eval_btm => {
                    cx.guardRoot(&.{ .p, .ev });
                    return @bitCast(evalpawns.pawnEval(&d.p, &d.ev, .black));
                },
                .static_eval => return @bitCast(cx.staticEval(@truncate(a), @bitCast(reply_static_eval_arg2))),
                // 2B9F:5534 is the Black node's leaf term, 4BFE the White node's.
                .hanging_white => return @bitCast(cx.leafTermA(sn.black)),
                .hanging_black => return @bitCast(cx.leafTermA(sn.white)),
                .pieces_and_kings => return @bitCast(cx.pieceEval(@truncate(a), @bitCast(b))),
                .activity_white => {
                    cx.guardRoot(&.{ .p, .ev });
                    return @bitCast(activity.pieceActivityWhiteFixes(fixes, &d.p, &d.ev));
                },
                .activity_black => {
                    cx.guardRoot(&.{ .p, .ev });
                    return @bitCast(activity.pieceActivityBlackFixes(fixes, &d.p, &d.ev));
                },
                .endgame_king_white => return @bitCast(cx.endgameKing(sn.white)),
                .endgame_king_black => return @bitCast(cx.endgameKing(sn.black)),
                .count_attacked_wtm => return cx.countAttacked(sn.white),
                .count_attacked_btm => return cx.countAttacked(sn.black),
                // (100, n, &[bp-0Dh]): the flag byte is set at the routine's entry and
                // not read by set_predicted_reply.
                .threats_white, .threats_black => {
                    var flag: u8 = 0;
                    return @bitCast(cx.threats(if (c == .threats_white) sn.white else sn.black, @bitCast(a), b, &flag));
                },
                // sort_root_moves (0000:668E)(DG:3A34, n): the list and the scores DG:8D0A.
                .sort_root_moves => {
                    const moves: *[100][4]u8 = @ptrCast(s.node_state.move_list[0][0..100]);
                    var scores: [100]i16 = undefined;
                    for (&scores, d.gv.reply_scores) |*x, w| x.* = @bitCast(w);
                    rs.sortRootMoves(moves[0..], scores[0..], @bitCast(a));
                    for (d.gv.reply_scores, scores) |*w, x| w.* = @bitCast(x);
                },
            }
            return 0;
        }

        /// set_prescore_margins / set_search_margins: DG:0154, 0172 (near) and 0168, 0186
        /// (far), at their homes.
        fn setMargins(s: *Self, near: u16, far_: u16) void {
            s.dgSetWord(0x0154, near);
            s.dgSetWord(0x0172, near);
            s.dgSetWord(0x0168, far_);
            s.dgSetWord(0x0186, far_);
        }

        /// main 0000:02CC-0350 [read]: the ponder test after the program's move. With a
        /// valid reply list ([A3FA]) and a predicted reply ([8FDE]), not stopped by a
        /// ponder miss (stop 3), status < 4 and not replaying, analysing or resigning
        /// ([A00A], [1BAC], [24F2], [B620]), the predicted move is copied to the entered
        /// move DG:9360 (memcpy, 3 bytes) and [776A] = 1 (0318-0328); pondering then
        /// starts unless the level forbids it (level 0 without a preset) or pondering is
        /// switched off ([3674], the key `!`), when [3676] = 0 (0350) and main goes on to
        /// the command loop as without a prediction. Returns false if pondering would
        /// start (not supported: the engine plays with pondering off).
        fn ponderTest(s: *Self) bool {
            if (s.dgWord(0xA3FA) == 0 or s.dgByte(0x8FDE) == 0 or s.dgByte(0xA4FA) == 3) return true;
            if (@as(i8, @bitCast(s.dgByte(0x7328))) >= 4 or s.dgWord(0xA00A) != 0 or s.dgByte(0x1BAC) != 0 or s.dgByte(0x24F2) != 0 or s.dgWord(0xB620) != 0) return true;
            dgroup.memCopy(s.home(), 0x9360, 0x8FDE, 3);
            s.dgSet(0x776A, 1);
            if ((s.dgByte(0xA8C6) != 0 or s.dgByte(0xA274) != 0) and s.dgByte(0x3674) == 0) return false;
            s.dgSet(0x3676, 0);
            return true;
        }

        /// The key `!` in the command loop (1E9D:8B83) [traced]: pondering on or off,
        /// DG:3674 = 1 - DG:3674 (`Position`'s, through its tail). The oracle's normal
        /// play types it once, after the level (`"ponder": "off"`).
        pub fn togglePondering(s: *Self) void {
            s.dgSet(0x3674, if (s.dgByte(0x3674) != 0) 0 else 1);
        }

        /// From the return of play_best_move to the command loop's wait for the
        /// opponent's move, in normal play with pondering off [read: main 16EA, 023C-04A7,
        /// 38C0:174A-1974; traced with tools/research/newgame/trace.py on np-open-black-d4,
        /// docs/arch/34-game-move-path.md "Normal play: the turn"]: [9FD0] = 0, main's
        /// ponder test (`ponderTest`), [8BAA] = [153C] = [3676] = 0, [9EEC] = [717C], the
        /// control-time test, the command loop's entry. False if pondering would start
        /// (`failure` says so), or if the command loop ends the game at move number 202
        /// (38C0:1974; no failure: the program has played its move, and no move can follow).
        pub fn toOpponentMove(s: *Self) bool {
            s.slideIfDue();
            s.dgSet(0x9FD0, 0);
            if (!s.ponderTest()) {
                s.fail("main 0000:0349: pondering would start (only pondering off is supported)", .{});
                return false;
            }
            return s.toCommandLoop();
        }

        /// The opponent's move typed at the command loop, to main 0000:0526 of the
        /// program's next search [read: 38C0:4E78-4F95, 4F98-517F; main 04AD-0525;
        /// traced]: from and to into DG:9360/9361; check_entered_move (38C0:5864); a
        /// promotion's piece (`promo` 'n', 'b', 'r' give the flag 2, 3, 4; anything else
        /// keeps 5, the queen; 4F30-4F68); play_entered_move (38C0:554E); [A416] = [A00E]
        /// = 0 (4FB3-4FB8); if the move gave check, the program's legal evasions are
        /// counted into [A518] at ply 1, status 9 if none (4FC4-504E); the game board
        /// DG:7520 takes the move (show_move 38C0:CE66); check_new_control(1)
        /// (1E9D:6EB2, 50C9); then, the move being the other side's ([AE44] = [717C],
        /// 50D8), [AB9E] = 2 (516C), the move number + 1 after Black's move (5178),
        /// [B4DE] = the game ply (517F); main [B620] = [1B8A] = [776A] = 0. Returns false
        /// if the original refuses the move (check_entered_move 0: it then waits for
        /// another) or the path is not the one ported (monitor mode).
        pub fn enterMove(s: *Self, from: u8, to: u8, promo: u8) bool {
            if (!s.enterMoveDomain(from, to, promo)) return false;
            // Since Stage B step 8, stage 4, with no bracket: each variable at its home.
            s.gameBoardFromSearch();
            if (s.dgWord(0xA28A) == 0 and s.dgWord(0xA00A) == 0) _ = s.timeCall(tbud.checkNewControl, .{@as(i16, 1)});
            if (s.dgWord(0xA28A) != 0 or s.dgByte(0xAE44) != s.dgByte(0x717C)) {
                s.fail("38C0:50E1: the entered move's side is not the opponent's (monitor mode): not ported", .{});
                return false;
            }
            if (s.dgByte(0x9FCF) == 0) s.dgSet(0xAB9E, 2);
            if (s.dgByte(0x717C) == 1) s.dgSetWord(0xA84A, s.dgWord(0xA84A) +% 1);
            s.dgSetWord(0xB4DE, s.dgWord(0x9FC8));
            newgame.mainToSearch(s.home());
            return true;
        }

        /// `enterMove` from the entered move to the return of play_entered_move, on the
        /// domain's structs, the game variables and the game record (Stage B step 8, stage
        /// 2): from and to into DG:9360/9361 (`GameVars.entered`), check_entered_move, the
        /// promotion's piece, play_entered_move; since stage 3 also [A416] = [A00E] = 0
        /// and the evasion count after a check (`countEvasions`). False if
        /// check_entered_move refuses it.
        fn enterMoveDomain(s: *Self, from: u8, to: u8, promo: u8) bool {
            s.assertEntered();
            const d = s.node.dom;
            d.gv.entered[0] = from;
            d.gv.entered[1] = to;
            var c: DomainGameCtx = .{ .s = s };
            s.node.guardRoot(&.{ .p, .ev });
            if (gamemove.checkEnteredMove(&d.p, &d.gv, s.rec, &s.node_state.move_list[0], &c) == 0) return false;
            if (d.gv.entered[2] == 5) {
                d.gv.entered[2] = switch (promo) {
                    'n' => 2,
                    'b' => 3,
                    'r' => 4,
                    else => 5,
                };
            }
            _ = gamemove.playEnteredMove(&d.p, &d.gv, s.rec, &c);
            // 4FB3-4FB8, then 4FC4: the move gave check (DG:8C07, `Position.check_by_ply[1]`).
            s.dgSetWord(0xA416, 0);
            s.dgSetWord(0xA00E, 0);
            if (s.dgByte(0x8C07) != 0) s.countEvasions();
            return true;
        }

        /// 38C0:4FCE-504E: after an entered move that gives check, the program's legal
        /// moves: gen_evasions([8DDE], 1) into the list DG:3BC4, [A518] = their number,
        /// each made at ply 2, the program's king tested (2B9F:4B32) and unmade; none
        /// legal: status [7328] = 9. On the domain (Stage B step 8, stage 3): the evasion
        /// generator as the node's, into `State.move_list[1]`, make and take-back on the
        /// domain's `Position`; the counts at their homes.
        fn countEvasions(s: *Self) void {
            const cx = &s.node;
            s.assertEntered();
            const p = &cx.dom.p;
            const side = s.dgByte(0x8DDE);
            const n = cx.generate(.evasions, @truncate(side), 1);
            s.dgSet(0xA518, @truncate(n));
            for (s.node_state.move_list[1][0..n]) |mv| {
                var u: pos.Undo = .{};
                cx.guardRoot(&.{.p});
                p.makeMove(mv, sideOf(side), 2, &u);
                if (gamemove.kingAttacked(p, side) != 0) s.dgSet(0xA518, s.dgByte(0xA518) -% 1);
                p.unmakeMove(mv, sideOf(side), &u);
            }
            if (s.dgByte(0xA518) == 0) s.dgSet(0x7328, 9);
        }

        /// One turn of normal play with pondering off, from the return of play_best_move
        /// to main 0526 of the program's next search: `toOpponentMove`, then the
        /// opponent's move (`enterMove`).
        pub fn nextTurnNormal(s: *Self, from: u8, to: u8, promo: u8) bool {
            if (!s.toOpponentMove()) return false;
            return s.enterMove(from, to, promo);
        }
    };
}
