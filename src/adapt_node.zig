//! Stage A, steps 9 and 10 (docs/arch/60-engine-assembly.md section 5): the search node
//! (src/searchnode.zig, 0000:3AC6 / 0000:5036) with every routine it calls bound to the
//! ported routine, on the shared DGROUP image (src/dgroup.zig), and the main hash tables
//! in ordinary memory.
//!
//! `Ctx(threats)` is the node's `Ctx`. The node keeps its own variables in
//! `searchnode.State`, whose fields are byte ranges of DGROUP (`searchnode.dg_fields`;
//! `State` is an extern struct with the original's little-endian words, so each range is a
//! plain copy), reads and writes the position in a `Position` (`State.p`, here `Work.np`),
//! the move marks and hint bytes in a `SearchVars` (`State.sv`, here `Work.nsv`), and the
//! evaluation's flags and sums in an `EvalVars` and an `EvalState` (`State.ev`, `State.es`,
//! here `Work.nev`, `Work.nes`), the leaf map and key history in a `LeafVars` (`State.lv`,
//! `Work.nlv`), the ply limits and the iteration in a `ThreatVars` (`State.tv`, `Work.ntv`). The image is the one store: before each callee the node's
//! `State` and the bytes of those structs it changed are copied into the image, the callee
//! runs on the image through its adapter (src/adapt_*.zig), and the image is copied back.
//! Between callees only the node writes, so the copy is exact, aliases included. The child
//! node is the same `Node(Ctx).search` on the same `State`.
//!
//! | `Ctx` method        | Original                 | Bound to                                                     |
//! | ------------------- | ------------------------ | ------------------------------------------------------------ |
//! | `poll`              | 1E9D:7514                | not bound: platform (DEV-F04/F05); counted, the test fails if reached |
//! | `isRepetition`      | 0000:1B88                | `leaf.isRepetition`, game keys of far segment 5A7B:3A34      |
//! | `attacks`           | 0000:1C76 / 1DE6         | `helpers.attacksSquareNoPawns` (adapt_movegen)               |
//! | `hashMovePlausible` | 0000:1F56 / 211E         | `helpers.hashMovePlausible` (adapt_movegen)                  |
//! | `probe`, `store`    | XMS copy 0000:6A91       | `searchnode.HashTable`, one per side to move                 |
//! | `prefetchProbe`     | none                     | `HashTable.prefetch`                                         |
//! | `generate`          | 3938, E260, 579A, 25A0, 9528, 4954 | adapt_movegen `generateFixes` (DEV-003 corrected; DEV-004, 005, 007, 008 as `fixes`), `genEvasions` |
//! | `sortList`          | 0000:65BC                | `sort.sortMoves` (adapt_movegen)                             |
//! | `makeNull`          | 1E9D:16BE                | `leaf.makeNull`                                              |
//! | `child`             | 0000:5036 / 3AC6         | `Node(Ctx).search`, `stale_move_to` 0 (DEV-030)               |
//! | `applyMove`         | 0000:678A, 4793:3EA2, 1E9D:000C | `Position.applyMove` (DEV-001 as `fixes`)              |
//! | `unmake`            | 1E9D:0960                | `Position.unmakeMove` (adapt_position)                       |
//! | `pawnEval`          | 0000:18E8 / 19D4         | `PawnHash.probe` (adapt_eval)                                |
//! | `staticEval`        | 2B9F:000E                | adapt_staticeval `staticEvalFixes` (callees bound; DEV-015 corrected; DEV-023 as `fixes`) |
//! | `pieceEval`         | 0EF8:0006                | `evalpieces.evalPiecesAndKingsFixes` (adapt_eval; DEV-017 as `fixes`) |
//! | `countAttacked`     | 1E9D:CE3E / CC4E         | `helpers.countAttackedFixes` (adapt_movegen; DEV-024 as `fixes`) |
//! | `threats`           | 0EF8:A026 / CD20         | lifted `threats.zig` on the image, or hand-written `evalthreats` with `pinexchange` (`Threats`; DEV-020, 022, 023 as `fixes`, hand-written only) |
//! | `kingSafety`        | 0000:2E72                | `activity.mobilityTermFixes` (adapt_eval; DEV-019 as `fixes`) |
//! | `endgameKing`       | 1E9D:3416 / 35FB         | `leaf.endgameKing`                                           |
//! | `leafAttackMap`     | 2B9F:40A8 / 42DA         | `leaf.leafAttackMap`                                         |
//! | `leafTermA`         | 2B9F:4BFE / 5534         | `leaf.hangingPiecesFixes` (masks DG:A6C2, 9D8C; DEV-040 as `fixes`) |
//! | `leafTermB`         | 2B9F:450E / 454C         | `leaf.kingRingMap`                                           |
//! | `pawnEndingTerm`    | 1E9D:1E30 / 16E4         | **crossed**: White node `pieceActivityBlack`, Black node `pieceActivityWhite` |
//! | `tablebase`         | 2B9F:BB76                | not bound: the node calls it only with DG:239C >= 11, never in the repeatable state (0Ah); panics if reached |
//!
//! The exchange work areas (DG:9FEC, A060, 70E5, B4E6), which overlap the piece lists, are
//! the image's bytes for every routine that uses them (SEE, the pin-aware exchange, the
//! hanging-piece term), so none of them starts from a fresh scratch (OPEN_QUESTIONS 3).
//!
//! Stray bytes: the engine passes the corrected values (DEV-003 and DEV-015
//! `Fixes.corrected`, `stale_move_to` 0, DEV-030), as the golden files are recorded from
//! the corrected original; DEV-001 is the caller's choice (`fixes`), off for the golden
//! files. The class C fixes of `fixes` (pos.Fixes) reach every callee that reads one;
//! `pos.Fixes.original` is the original.
//!
//! Slow on purpose (Stage A): every callee copies its structs in and out of the image.
//!
//! Since Stage B step 8, stage 8, test-only: the engine runs the node on its members
//! (src/engine_state.zig), and its build never reaches this file (the `comptime` block
//! below fails the build if it does). It stays for its own tests, the reference the node
//! domain was proved against.

const std = @import("std");
const builtin = @import("builtin");

comptime {
    if (!builtin.is_test) @compileError("src/adapt_node.zig is a Stage A adapter, test-only since Stage B step 8, stage 8: the engine build must not reach it");
}
const sn = @import("searchnode.zig");
const pos = @import("position.zig");
const ev = @import("evalvars.zig");
const see_mod = @import("see.zig");
const mg = @import("movegen.zig");
const se = @import("staticeval.zig");
const leaf = @import("leaf.zig");
const et = @import("evalthreats.zig");
const pinexchange = @import("pinexchange.zig");
const PawnHash = @import("pawnhash.zig").PawnHash;
const dgroup = @import("dgroup.zig");
const adapt_position = @import("adapt_position.zig");
const adapt_movegen = @import("adapt_movegen.zig");
const adapt_eval = @import("adapt_eval.zig");
const adapt_staticeval = @import("adapt_staticeval.zig");
const adapt_threats = @import("adapt_threats.zig");

const Image = dgroup.Image;

pub const LeafVarsMap = dgroup.Map(leaf.LeafVars, &dgroup.maps.leaf.LeafVars);
pub const ThreatVarsMap = dgroup.Map(et.ThreatVars, &dgroup.maps.evalthreats.ThreatVars);
const PositionMap = adapt_position.PositionMap;
const EvalVarsMap = adapt_position.EvalVarsMap;
const ScratchMap = adapt_movegen.ScratchMap;
const SearchVarsMap = adapt_movegen.SearchVarsMap;
const EvalStateMap = adapt_eval.EvalStateMap;
const EvalState = @import("eval_state.zig").EvalState;

/// Which threat evaluators the node calls.
pub const Threats = enum {
    /// The machine-lifted 0EF8:A026 / CD20 (src/threats.zig) on the image itself: every
    /// byte they read is the original's.
    lifted,
    /// The hand-written src/evalthreats.zig, with see.zig and the hand-written
    /// pin-aware exchange (src/pinexchange.zig) as its far routines.
    hand,
};

/// The default: the hand-written evaluators (readable, faster, and the subtree tests pass
/// with both; src/adapt_node_test.zig).
pub const default_threats: Threats = .hand;

fn toSide(s: sn.Side) pos.Side {
    return if (s == sn.white) .white else .black;
}

/// Copy the node's `State` into the image (every mapped range).
pub fn stateToImage(st: *const sn.State, img: *Image) void {
    const bytes = std.mem.asBytes(st);
    inline for (sn.dg_fields) |f| {
        const off = @offsetOf(sn.State, f.name);
        @memcpy(img[f.addr..][0..f.len], bytes[off..][0..f.len]);
    }
}

/// Copy the image into the node's `State` (every mapped range).
pub fn imageToState(img: *const Image, st: *sn.State) void {
    const bytes = std.mem.asBytes(st);
    inline for (sn.dg_fields) |f| {
        const off = @offsetOf(sn.State, f.name);
        @memcpy(bytes[off..][0..f.len], img[f.addr..][0..f.len]);
    }
}

/// One make by the search or one node entry, as the oracle records them (`--subtree`):
/// the node domain's (src/engine_state.zig), so that a test records both in one list.
pub const Event = @import("engine_state.zig").Event;

/// Working storage of the adapters, allocated once by the caller (about 60 KB).
pub const Work = struct {
    gen: adapt_movegen.GenStateBuf = .{},
    eval: adapt_eval.Buf = .{},
    p: pos.Position = .{},
    pb: PositionMap.Snapshot = undefined,
    v: ev.EvalVars = .{},
    vb: EvalVarsMap.Snapshot = undefined,
    lv: leaf.LeafVars = .{},
    lb: LeafVarsMap.Snapshot = undefined,
    s: see_mod.Scratch = .{},
    sb: ScratchMap.Snapshot = undefined,
    t: et.ThreatVars = .{},
    /// The node's own `Position` (`State.p` while `Ctx.run` runs) and its snapshot.
    np: pos.Position = .{},
    npb: PositionMap.Snapshot = undefined,
    /// The node's own `SearchVars` (`State.sv` while `Ctx.run` runs) and its snapshot.
    nsv: mg.SearchVars = .{},
    nsvb: SearchVarsMap.Snapshot = undefined,
    /// The node's own `EvalVars` and `EvalState` (`State.ev`, `State.es` while `Ctx.run`
    /// runs) and their snapshots.
    nev: ev.EvalVars = .{},
    nevb: EvalVarsMap.Snapshot = undefined,
    /// The node's own `LeafVars` and `ThreatVars` (`State.lv`, `State.tv` while `Ctx.run`
    /// runs) and their snapshots.
    nlv: leaf.LeafVars = .{},
    nlvb: LeafVarsMap.Snapshot = undefined,
    ntv: et.ThreatVars = .{},
    ntvb: ThreatVarsMap.Snapshot = undefined,
};

/// The node's interface methods, for the call counts (`Ctx.calls`): the node domain's.
pub const Method = @import("engine_state.zig").Method;

pub fn Ctx(comptime threats_impl: Threats, comptime fixes: pos.Fixes) type {
    return CtxPos(threats_impl, fixes, PositionMap);
}

/// `Ctx` with the node's `Position` (`Work.np`) synchronised with the image through
/// `NodePositionMap` (`PositionMap`, or a map broken on purpose in a test).
pub fn CtxPos(comptime threats_impl: Threats, comptime fixes: pos.Fixes, comptime NodePositionMap: type) type {
    return CtxMaps(threats_impl, fixes, NodePositionMap, SearchVarsMap, EvalVarsMap, LeafVarsMap, ThreatVarsMap);
}

/// `CtxPos` with the node's `SearchVars`, `EvalVars`, `EvalState`, `LeafVars` and
/// `ThreatVars` (`Work.nsv`, `nev`, `nes`, `nlv`, `ntv`) synchronised through the maps given
/// (the generated ones, or one broken on purpose in a test).
pub fn CtxMaps(comptime threats_impl: Threats, comptime fixes: pos.Fixes, comptime NodePositionMap: type, comptime NodeSearchVarsMap: type, comptime NodeEvalVarsMap: type, comptime NodeLeafVarsMap: type, comptime NodeThreatVarsMap: type) type {
    // The lifted threat evaluators run the original's instructions on the image and
    // cannot take the corrections of DEV-020, 021, 022, 023, 041, 052 and 058.
    if (threats_impl == .lifted and (fixes.dev020_threat_table_index or fixes.dev021_knight_escape_order or
        fixes.dev022_captured_pieces or fixes.dev023_pinned_bishop or fixes.dev041_threat_mirror or fixes.dev052_line_tables or
        fixes.dev058_lifted_knight_entry))
        @compileError("adapt_node: the lifted threat evaluators cannot be corrected (DEV-020, 021, 022, 023, 041, 052, 058); use .hand");
    return struct {
        const Self = @This();
        pub const Node = sn.Node(Self);
        /// The class C fixes the search node itself reads (searchnode.zig `node_fixes`:
        /// DEV-035).
        pub const node_fixes: pos.Fixes = fixes;

        img: *Image,
        st: *sn.State,
        work: *Work,
        pawn_hash: *PawnHash,
        /// The main hash tables: [0] White to move (XMS handle DG:744C), [1] Black (DG:7240).
        tables: *[2]sn.HashTable,
        /// The game record's keys, 5A7B:3A34 + 6 * game ply (read by isRepetition).
        game_keys: []const u48,
        /// Every make and node entry below the first node, if the caller wants them.
        events: ?*std.ArrayList(Event) = null,
        gpa: std.mem.Allocator = std.heap.page_allocator,
        /// Node entries (the first included) and makes.
        nodes: u64 = 0,
        makes: u64 = 0,
        /// Calls of routines that are not bound (the keyboard poll).
        polls: u64 = 0,
        /// Calls of each interface method, for the test's report.
        calls: std.EnumArray(Method, u64) = .initFill(0),
        /// Inside `run`: the node's `Position` (`work.np`) and `SearchVars` (`work.nsv`)
        /// are synchronised around each callee. Outside it (the root's own calls of a binding) no node is running.
        node_running: bool = false,

        /// Run the node `side` at `ply` from the image's state: the entry of 0000:3AC6
        /// (White) or 0000:5036 (Black) with [bp+6] `beta`, [bp+8] `alpha`, and `legal`
        /// the parent's word. Leaves the node's state in the image.
        pub fn run(c: *Self, side: sn.Side, legal: *i16, beta: i16, alpha: i16, ply: i16) i16 {
            imageToState(c.img, c.st);
            c.st.p = &c.work.np;
            c.st.sv = &c.work.nsv;
            c.st.ev = &c.work.nev;
            c.st.lv = &c.work.nlv;
            c.st.tv = &c.work.ntv;
            NodePositionMap.loadSnap(&c.work.np, c.img, &c.work.npb);
            NodeSearchVarsMap.loadSnap(&c.work.nsv, c.img, &c.work.nsvb);
            NodeEvalVarsMap.loadSnap(&c.work.nev, c.img, &c.work.nevb);
            NodeLeafVarsMap.loadSnap(&c.work.nlv, c.img, &c.work.nlvb);
            NodeThreatVarsMap.loadSnap(&c.work.ntv, c.img, &c.work.ntvb);
            c.node_running = true;
            c.nodes += 1;
            const r = Node.search(c, c.st, side, legal, beta, alpha, ply, 0);
            c.node_running = false;
            stateToImage(c.st, c.img);
            _ = NodePositionMap.storeChanged(&c.work.np, c.img, &c.work.npb);
            _ = NodeSearchVarsMap.storeChanged(&c.work.nsv, c.img, &c.work.nsvb);
            _ = NodeEvalVarsMap.storeChanged(&c.work.nev, c.img, &c.work.nevb);
            _ = NodeLeafVarsMap.storeChanged(&c.work.nlv, c.img, &c.work.nlvb);
            _ = NodeThreatVarsMap.storeChanged(&c.work.ntv, c.img, &c.work.ntvb);
            c.event(.{ .ret = .{ .side = side, .ply = ply, .ax = r } });
            return r;
        }

        fn event(c: *Self, e: Event) void {
            if (c.events) |list| list.append(c.gpa, e) catch @panic("adapt_node: out of memory for events");
        }

        inline fn begin(c: *Self) void {
            stateToImage(c.st, c.img);
            if (c.node_running) {
                _ = NodePositionMap.storeChanged(&c.work.np, c.img, &c.work.npb);
                _ = NodeSearchVarsMap.storeChanged(&c.work.nsv, c.img, &c.work.nsvb);
                _ = NodeEvalVarsMap.storeChanged(&c.work.nev, c.img, &c.work.nevb);
                _ = NodeLeafVarsMap.storeChanged(&c.work.nlv, c.img, &c.work.nlvb);
                _ = NodeThreatVarsMap.storeChanged(&c.work.ntv, c.img, &c.work.ntvb);
            }
        }
        inline fn end(c: *Self) void {
            imageToState(c.img, c.st);
            if (c.node_running) {
                NodePositionMap.loadSnap(&c.work.np, c.img, &c.work.npb);
                NodeSearchVarsMap.loadSnap(&c.work.nsv, c.img, &c.work.nsvb);
                NodeEvalVarsMap.loadSnap(&c.work.nev, c.img, &c.work.nevb);
                NodeLeafVarsMap.loadSnap(&c.work.nlv, c.img, &c.work.nlvb);
                NodeThreatVarsMap.loadSnap(&c.work.ntv, c.img, &c.work.ntvb);
            }
        }

        fn loadPos(c: *Self) void {
            PositionMap.loadSnap(&c.work.p, c.img, &c.work.pb);
        }
        fn storePos(c: *Self) void {
            _ = PositionMap.storeChanged(&c.work.p, c.img, &c.work.pb);
        }
        fn loadLeaf(c: *Self) void {
            LeafVarsMap.loadSnap(&c.work.lv, c.img, &c.work.lb);
        }
        fn storeLeaf(c: *Self) void {
            _ = LeafVarsMap.storeChanged(&c.work.lv, c.img, &c.work.lb);
        }

        // ---- the interface (searchnode.zig, `Node`) ----------------------------------

        /// 1E9D:7514: not bound (the UCI layer will set the stop flag here).
        pub fn poll(c: *Self) void {
            c.calls.getPtr(.poll).* += 1;
            c.polls += 1;
        }

        pub fn isRepetition(c: *Self, ply: i16) bool {
            c.calls.getPtr(.isRepetition).* += 1;
            c.begin();
            c.loadPos();
            c.loadLeaf();
            var e: EvalState = undefined;
            EvalStateMap.load(&e, c.img);
            const r = leaf.isRepetition(&c.work.p, &c.work.lv, &e, c.game_keys, ply);
            c.end();
            return r;
        }

        pub fn attacks(c: *Self, side: sn.Side, sq: u8) bool {
            c.calls.getPtr(.attacks).* += 1;
            c.begin();
            const r = adapt_movegen.attacksSquareNoPawns(c.img, toSide(side), sq) != 0;
            c.end();
            return r;
        }

        pub fn hashMovePlausible(c: *Self, side: sn.Side, mv: *u16) bool {
            c.calls.getPtr(.hashMovePlausible).* += 1;
            c.begin();
            var m: pos.Move = .{ .from = @truncate(mv.*), .to = @truncate(mv.* >> 8), .flag = 0, .score = 0 };
            const r = adapt_movegen.hashMovePlausible(c.img, toSide(side), &m) != 0;
            mv.* = @as(u16, m.from) | @as(u16, m.to) << 8;
            c.end();
            return r;
        }

        pub fn probe(c: *Self, side: sn.Side, index: u32) void {
            c.calls.getPtr(.probe).* += 1;
            c.tables[side].probe(index, &c.st.hash_entry);
        }

        pub fn store(c: *Self, side: sn.Side, index: u32) void {
            c.calls.getPtr(.store).* += 1;
            c.tables[side].store(index, &c.st.hash_entry);
        }

        pub fn prefetchProbe(c: *Self, side: sn.Side, index: u32) void {
            c.calls.getPtr(.prefetchProbe).* += 1;
            c.tables[side].prefetch(index);
        }

        pub fn generate(c: *Self, gen: sn.Gen, side: sn.Side, ply: i16) u16 {
            c.calls.getPtr(.generate).* += 1;
            c.begin();
            const s = toSide(side);
            const p: usize = @intCast(ply);
            const r = switch (gen) {
                .all => adapt_movegen.generateFixes(&c.work.gen, c.img, mg.Fixes.corrected, fixes, .all_moves, s, p, .{}),
                .evasions => adapt_movegen.genEvasions(&c.work.gen, c.img, s, p),
                .q1 => adapt_movegen.generateFixes(&c.work.gen, c.img, mg.Fixes.corrected, fixes, .tactical, s, p, .{}),
                .q2 => adapt_movegen.generateFixes(&c.work.gen, c.img, mg.Fixes.corrected, fixes, .tactical_no_losers, s, p, .{}),
                .q3 => adapt_movegen.generateFixes(&c.work.gen, c.img, mg.Fixes.corrected, fixes, .quiescence, s, p, .{}),
                .q4 => adapt_movegen.generateFixes(&c.work.gen, c.img, mg.Fixes.corrected, fixes, .captures, s, p, .{}),
            };
            c.end();
            return r;
        }

        pub fn sortList(c: *Self, ply: i16, count: u16) void {
            c.calls.getPtr(.sortList).* += 1;
            c.begin();
            adapt_movegen.sortList(c.img, @intCast(ply), @bitCast(count));
            c.end();
        }

        pub fn makeNull(c: *Self, ply: i16) void {
            c.calls.getPtr(.makeNull).* += 1;
            c.begin();
            c.loadPos();
            leaf.makeNull(&c.work.p, @bitCast(ply));
            c.storePos();
            c.end();
        }

        pub fn child(c: *Self, side: sn.Side, legal: *i16, beta: i16, alpha: i16, ply: i16) i16 {
            c.calls.getPtr(.child).* += 1;
            c.nodes += 1;
            c.event(.{ .node = .{ .side = side, .ply = ply, .alpha = alpha, .beta = beta } });
            const r = Node.search(c, c.st, side, legal, beta, alpha, ply, 0);
            c.event(.{ .ret = .{ .side = side, .ply = ply, .ax = r } });
            return r;
        }

        pub fn applyMove(c: *Self, side: sn.Side, ply: i16, m: pos.Move, undo: *pos.Undo) void {
            c.calls.getPtr(.applyMove).* += 1;
            c.makes += 1;
            c.event(.{ .make = .{ .ply = @truncate(@as(u16, @bitCast(ply))), .from = m.from, .to = m.to, .flag = m.flag } });
            c.begin();
            c.loadPos();
            EvalVarsMap.loadSnap(&c.work.v, c.img, &c.work.vb);
            c.work.p.applyMove(&c.work.v, m, toSide(side), @intCast(ply), undo, fixes);
            _ = EvalVarsMap.storeChanged(&c.work.v, c.img, &c.work.vb);
            c.storePos();
            c.end();
        }

        pub fn unmake(c: *Self, side: sn.Side, m: pos.Move, undo: *pos.Undo) void {
            c.calls.getPtr(.unmake).* += 1;
            c.begin();
            // The take-back of `applyMove` under the same fixes (DEV-050).
            adapt_position.unmakeMoveFixes(c.img, m, toSide(side), undo, fixes);
            c.end();
        }

        pub fn pawnEval(c: *Self, side: sn.Side) i16 {
            c.calls.getPtr(.pawnEval).* += 1;
            c.begin();
            const r = adapt_eval.pawnHashProbe(&c.work.eval, c.img, c.pawn_hash, toSide(side));
            c.end();
            return r;
        }

        pub fn staticEval(c: *Self, side: sn.Side, arg: i16) i16 {
            c.calls.getPtr(.staticEval).* += 1;
            c.begin();
            const r = adapt_staticeval.staticEvalFixes(fixes, &c.work.eval, c.img, c.pawn_hash, side, @bitCast(arg), se.Fixes.corrected, .{ .{}, .{} }, null);
            c.end();
            return r;
        }

        pub fn pieceEval(c: *Self, side: sn.Side, ply: i16) i16 {
            c.calls.getPtr(.pieceEval).* += 1;
            c.begin();
            const r = adapt_eval.evalPiecesAndKingsFixes(fixes, &c.work.eval, c.img, side, @bitCast(ply));
            c.end();
            return r;
        }

        pub fn countAttacked(c: *Self, side: sn.Side) u16 {
            c.calls.getPtr(.countAttacked).* += 1;
            c.begin();
            const r = adapt_movegen.countAttackedFixes(fixes, c.img, toSide(side));
            c.end();
            return r;
        }

        pub fn threats(c: *Self, side: sn.Side, ply: i16, count: u16, counter: *u8) i16 {
            c.calls.getPtr(.threats).* += 1;
            c.begin();
            const r = switch (threats_impl) {
                .lifted => adapt_threats.threats(c.img, toSide(side), ply, count, counter),
                .hand => c.handThreats(side, ply, count, counter),
            };
            c.end();
            return r;
        }

        /// The far routines of the hand-written evaluators: both read the evaluator's
        /// `Position` (with its lifted pieces) and the shared work areas.
        const HandCallees = struct {
            p: *const pos.Position,
            s: *see_mod.Scratch,
            pub fn see(h: HandCallees, side: pos.Side, square: u8, value: u16) u16 {
                return see_mod.seeFixes(fixes, h.p, h.s, side, square, value);
            }
            pub fn att(h: HandCallees, side: pos.Side, square: u8, value: u16) u16 {
                return pinexchange.exchangeFixes(fixes, h.p, h.s, side, square, value);
            }
        };

        fn handThreats(c: *Self, side: sn.Side, ply: i16, count: u16, counter: *u8) i16 {
            const w = c.work;
            c.loadPos();
            EvalVarsMap.loadSnap(&w.v, c.img, &w.vb);
            ScratchMap.loadSnap(&w.s, c.img, &w.sb);
            ThreatVarsMap.load(&w.t, c.img);
            // The routine overwrites its own argument slot [bp+6]; the node never reads it.
            var ply_slot: u16 = @bitCast(ply);
            const cal: HandCallees = .{ .p = &w.p, .s = &w.s };
            const r = switch (side) {
                sn.white => et.evalThreatsFixes(fixes, .white, &w.p, &w.v, &w.t, &w.s, cal, &ply_slot, count, counter),
                else => et.evalThreatsFixes(fixes, .black, &w.p, &w.v, &w.t, &w.s, cal, &ply_slot, count, counter),
            };
            // The work areas first: DG:9FEC + 116 covers the piece lists (A03A) in the
            // scratch's declaration; only changed bytes are written.
            _ = ScratchMap.storeChanged(&w.s, c.img, &w.sb);
            _ = EvalVarsMap.storeChanged(&w.v, c.img, &w.vb);
            c.storePos();
            return r;
        }

        pub fn kingSafety(c: *Self) i16 {
            c.calls.getPtr(.kingSafety).* += 1;
            c.begin();
            const r = adapt_eval.mobilityTermFixes(fixes, &c.work.eval, c.img);
            c.end();
            return r;
        }

        pub fn endgameKing(c: *Self, side: sn.Side) i16 {
            c.calls.getPtr(.endgameKing).* += 1;
            c.begin();
            c.loadPos();
            c.loadLeaf();
            EvalVarsMap.loadSnap(&c.work.v, c.img, &c.work.vb);
            const r = switch (side) {
                sn.white => leaf.endgameKing(&c.work.p, &c.work.lv, &c.work.v, .white),
                else => leaf.endgameKing(&c.work.p, &c.work.lv, &c.work.v, .black),
            };
            c.storeLeaf();
            _ = EvalVarsMap.storeChanged(&c.work.v, c.img, &c.work.vb);
            c.end();
            return r;
        }

        pub fn leafAttackMap(c: *Self, side: sn.Side) void {
            c.calls.getPtr(.leafAttackMap).* += 1;
            c.begin();
            c.loadPos();
            c.loadLeaf();
            switch (side) {
                sn.white => leaf.leafAttackMap(&c.work.p, &c.work.lv, .white),
                else => leaf.leafAttackMap(&c.work.p, &c.work.lv, .black),
            }
            c.storeLeaf();
            c.end();
        }

        pub fn leafTermA(c: *Self, side: sn.Side) i16 {
            c.calls.getPtr(.leafTermA).* += 1;
            c.begin();
            const w = c.work;
            c.loadPos();
            c.loadLeaf();
            ScratchMap.loadSnap(&w.s, c.img, &w.sb);
            // The passed-pawn masks DG:A6C2 (White) and DG:9D8C (Black).
            const passed: [2]u8 = .{ c.img[0xA6C2], c.img[0x9D8C] };
            const r = switch (side) {
                sn.white => leaf.hangingPiecesFixes(fixes, &w.p, &w.lv, &w.s, .white, passed),
                else => leaf.hangingPiecesFixes(fixes, &w.p, &w.lv, &w.s, .black, passed),
            };
            _ = ScratchMap.storeChanged(&w.s, c.img, &w.sb);
            c.storeLeaf();
            c.end();
            return r;
        }

        pub fn leafTermB(c: *Self, side: sn.Side) i16 {
            c.calls.getPtr(.leafTermB).* += 1;
            c.begin();
            c.loadPos();
            c.loadLeaf();
            const r = switch (side) {
                sn.white => leaf.kingRingMap(&c.work.p, &c.work.lv, .white),
                else => leaf.kingRingMap(&c.work.p, &c.work.lv, .black),
            };
            c.storeLeaf();
            c.end();
            return r;
        }

        /// The White node calls 1E9D:1E30 (piece_activity_black), the Black node 16E4
        /// (piece_activity_white): crossed, as the original (30- mirror table).
        pub fn pawnEndingTerm(c: *Self, side: sn.Side) i16 {
            c.calls.getPtr(.pawnEndingTerm).* += 1;
            c.begin();
            const r = switch (side) {
                sn.white => adapt_eval.pieceActivityBlackFixes(fixes, &c.work.eval, c.img),
                else => adapt_eval.pieceActivityWhiteFixes(fixes, &c.work.eval, c.img),
            };
            c.end();
            return r;
        }

        /// 2B9F:BB76: the node calls it only when DG:239C >= 11, which no setting of the
        /// repeatable state gives (0Ah). Not bound yet.
        pub fn tablebase(c: *Self, side_arg: u16, ply: i16) bool {
            c.calls.getPtr(.tablebase).* += 1;
            _ = side_arg;
            _ = ply;
            @panic("adapt_node: the tablebase probe 2B9F:BB76 is not bound (DG:239C >= 11)");
        }
    };
}
