//! Stage B, step 1 (docs/arch/60-engine-assembly.md section 10): the node domain.
//!
//! The node domain is the search below the root: every node (0000:3AC6 / 5036), the ply-2
//! node (root_move_search, 0000:2EC8), and every routine they call (`searchnode.zig`'s
//! `Ctx`). Inside it, each unit struct the node and its callees take is one persistent
//! instance (`Members`): the node's `searchnode.State` and the units' `Position`, `EvalVars`,
//! `SearchVars`, `see.Scratch`, `LeafVars` and `ThreatVars` (`EvalState` is `EvalVars` since
//! Stage B step 6). The routines run
//! on those instances directly; the move lists are the node's `State.move_list`, passed to
//! the generators and the sort in place. Stage 2 of step 8 added the game's variables
//! (`GameVars`) and stage 5 the time budget's (`timebudget.TimeState`) to the members, and
//! stage 7 the root's own variables and every other variable no unit's struct holds
//! (`rootvars.RootVars`, `ProgramVars`), so that every byte of live state has a member for
//! its home.
//!
//! **No image** (Stage B step 8, stage 8). The members are the engine's state for its life:
//! they are decoded once, at start-up, from the executable's initialised data
//! (`decodeFrom` on `dgroup.initial`, src/engine_root.zig `EngineRoot.init` and `startUp`), and
//! every routine runs on them; the engine holds no image of DGROUP. Every method runs on the
//! members: there is no call outside the domain, and no Stage A binding behind it. The tests
//! load the members from an oracle's image and compare them with one through their codec,
//! src/state_image.zig, whose state lives in fields of the test build only (`codec`,
//! `Members.img_snap`; `void` in the engine).
//!
//! **Who holds a byte.** Where two of these structs declare the same DGROUP byte, the one
//! whose declaration is that variable's own holds it; a table declared longer than the
//! original's room does not hold the variable it runs into. The rule (`Layout.build`):
//!
//! 1. The node's `State` declares exactly the original's room for each of its variables
//!    (`searchnode.dg_fields`). Where it declares a byte it holds it, and another struct
//!    holds it only through a declaration starting at or after `State`'s: the same
//!    variable, or a part of a group `State` declares as one array (`Position.pawn_hash_key`
//!    at DG:8CD2 is part of `State.keys` at 8CCC).
//! 2. Elsewhere the declaration with the latest start address holds the byte; contiguous
//!    pieces of one field count as one declaration.
//!
//! **One holder per byte.** Since Stage B step 6 no DGROUP byte is held by two of these
//! structs; `Members.create` fails (`error.TwoHolders`) if one is. Nothing is copied between
//! the structs before or
//! after a call otherwise: a struct's bytes past the original's room (an over-long table) are
//! loaded with the rest and not refreshed; the reads that can reach such a byte whose holder
//! changes in the search go through an accessor in the reading unit (`evalthreats` `boardAt`,
//! the game ply at DG:9FC8), and every other one is out of reach of any index the reader
//! forms or reaches a variable no routine of the domain writes (docs/arch/60-engine-assembly.md,
//! the step 5 note).
//!
//! That was so while the domain was entered at every node call of the root. Since Stage B
//! step 7 it is entered once a search (since step 8 once for the engine's life), and main
//! writes two such variables inside it: the
//! root's game ply (DG:A000, `LeafVars`, written by prepare_eval) and the root's material
//! balance (DG:A05A, the node's `State`, written by main at 0000:0919). Both lie inside
//! `see.Scratch.attackers`, which `boardAt` reads when the original's x-ray walk from a
//! captured piece's entry runs past the board (only with DEV-022 off). `threats` copies
//! the two words from their holders into `Scratch` before each call
//! (`refreshRootAliases`), so the walk reads what the original's one copy holds.
//!
//! **The alias-write detector** (on in Debug and ReleaseSafe): a unit that writes a byte
//! its struct covers but does not hold writes through a declaration longer than the
//! original's room. Stage A carried such a write to the image; the domain does not. The
//! detector saves those bytes before each callee and compares them before the next callee
//! (or a checkpoint, a refresh of the copies, or the tests' store to an image), and panics
//! on a difference.
//!
//! **A byte no member holds** has no home: `dgPtr` and `checkpointPtr` panic naming it (in
//! every build mode), and `bindGameVars` / `bindTimeState` fail (`error.UnheldHome`). Since
//! stage 7 no routine forms such an address (the whole suite, the games through UCI).

const std = @import("std");
const builtin = @import("builtin");
const sn = @import("searchnode.zig");
const pos = @import("position.zig");
const evm = @import("evalvars.zig");
const see_mod = @import("see.zig");
const mg = @import("movegen.zig");
const h = @import("helpers.zig");
const sort_mod = @import("sort.zig");
const se = @import("staticeval.zig");
const leaf = @import("leaf.zig");
const et = @import("evalthreats.zig");
const evalpieces = @import("evalpieces.zig");
const activity = @import("activity.zig");
const pinexchange = @import("pinexchange.zig");
const PawnHash = @import("pawnhash.zig").PawnHash;
const dgroup = @import("dgroup.zig");
const gamemove = @import("gamemove.zig");
const tbud = @import("timebudget.zig");
const rvm = @import("rootvars.zig");
/// The tests' codec (test builds only: the engine build never reaches it).
const si = @import("state_image.zig");

const Image = dgroup.Image;

/// Each member's field map (src/dgroup_maps.zig, generated): the members' addresses, which
/// the holding rule (`Layout`) and the start-up decode (`decodeFrom`) read. The Stage A
/// adapters name the same types (src/adapt_position.zig, src/adapt_movegen.zig,
/// src/adapt_node.zig: `dgroup.Map` of the same arguments is the same type).
pub const PositionMap = dgroup.Map(pos.Position, &dgroup.maps.position.Position);
pub const EvalVarsMap = dgroup.Map(evm.EvalVars, &dgroup.maps.evalvars.EvalVars);
pub const SearchVarsMap = dgroup.Map(mg.SearchVars, &dgroup.maps.movegen.SearchVars);
pub const ScratchMap = dgroup.Map(see_mod.Scratch, &dgroup.maps.see.Scratch);
pub const LeafVarsMap = dgroup.Map(leaf.LeafVars, &dgroup.maps.leaf.LeafVars);
pub const ThreatVarsMap = dgroup.Map(et.ThreatVars, &dgroup.maps.evalthreats.ThreatVars);

/// One make by the search or one node entry, as the oracle records them (`--subtree`).
pub const Event = union(enum) {
    make: struct { ply: u8, from: u8, to: u8, flag: u8 },
    node: struct { side: sn.Side, ply: i16, alpha: i16, beta: i16 },
    /// A node's return (its `ret 8`), with AX.
    ret: struct { side: sn.Side, ply: i16, ax: i16 },
};

/// The node's interface methods, for the call counts (`NodeEnv.calls`).
pub const Method = enum { poll, isRepetition, attacks, hashMovePlausible, probe, store, prefetchProbe, generate, sortList, makeNull, child, applyMove, unmake, pawnEval, staticEval, pieceEval, countAttacked, threats, kingSafety, endgameKing, leafAttackMap, leafTermA, leafTermB, pawnEndingTerm, tablebase };

/// The node's `State` from an image (every mapped range, `searchnode.dg_fields`).
pub fn imageToState(img: *const Image, st: *sn.State) void {
    const bytes = std.mem.asBytes(st);
    inline for (sn.dg_fields) |f| {
        const off = @offsetOf(sn.State, f.name);
        @memcpy(bytes[off..][0..f.len], img[f.addr..][0..f.len]);
    }
}

/// A byte no member holds was asked for: no routine forms such an address (Stage B step 8,
/// stage 7, measured over the whole suite), and since stage 8 there is no image to fall back
/// on.
fn noHome(addr: u16) noreturn {
    @branchHint(.cold);
    std.debug.panic("engine_state: DG:{X:0>4} has no home: no member holds it", .{addr});
}

/// The domain's structs, by index. `gv` (Stage B step 8, stage 2) is the game's variables,
/// `gamemove.GameVars`: its value fields, the variables no other struct declares, are its
/// own; its pointer fields are bound to their homes (`bindGameVars`). `ts` (stage 5) is the
/// time budget's state, `timebudget.TimeState`, in the same way (`bindTimeState`). `rv` and
/// `pg` (stage 7) are the homes of every other variable the engine reads or writes: the
/// root's own (`rootvars.RootVars`) and the rest (`rootvars.ProgramVars`); with them no
/// byte of live state has its home in the image (since stage 8 there is none).
pub const Member = enum(u4) { st, p, ev, sv, s, lv, tv, gv, ts, rv, pg };
pub const n_members = 11;

/// `gamemove.GameVars`' value fields on the image (the generated map leaves its pointer
/// fields out).
pub const GameVarsMap = dgroup.Map(gamemove.GameVars, &dgroup.maps.gamemove.GameVars);
/// `timebudget.TimeState`'s value fields on the image (likewise).
pub const TimeStateMap = dgroup.Map(tbud.TimeState, &dgroup.maps.timebudget.TimeState);
/// `rootvars.RootVars` and `rootvars.ProgramVars` on the image (every field).
pub const RootVarsMap = dgroup.Map(rvm.RootVars, &dgroup.maps.rootvars.RootVars);
pub const ProgramVarsMap = dgroup.Map(rvm.ProgramVars, &dgroup.maps.rootvars.ProgramVars);

/// The original's room for move lists: plies 0 to 34 (DG:3A34 + 400 * ply up to DG:70E4;
/// DEV-002).
pub const move_list_room = 35;

/// Where `see.Scratch.attackers` (DG:9FEC) covers the root's game ply (DG:A000, whose home
/// is `LeafVars.root_game_ply`) and the root's material balance (DG:A05A, whose home is the
/// node's `State.root_material_balance`).
pub const root_ply_in_attackers = 0xA000 - 0x9FEC;
pub const root_balance_in_attackers = 0xA05A - 0x9FEC;

/// The two words above, from their holders into `Scratch`: the copies there are what
/// `evalthreats`' `boardAt` returns when the original's x-ray walk from a captured piece's
/// entry runs past the board as far as DG:A000 or DG:A05A (DEV-022 off). The original has
/// one copy of each; `enter` made the two equal while the domain was entered at every node
/// call of the root, and since it is entered once a search (Stage B step 7) main writes the
/// holders inside it.
pub fn refreshRootAliases(s: *see_mod.Scratch, lv: *const leaf.LeafVars, st: *const sn.State) void {
    s.attackers[root_ply_in_attackers..][0..2].* = @bitCast(lv.root_game_ply);
    s.attackers[root_balance_in_attackers..][0..2].* = @bitCast(st.root_material_balance);
}

/// Deliberate faults, for the tests that show each kind is caught (engine_state_test.zig).
pub const Break = enum {
    none,
    /// `threats` does not refresh `Scratch`'s copies of the root's game ply and material
    /// balance (`refreshRootAliases`).
    stale_root_aliases,
    /// The threat evaluators write `ThreatVars.black_rays_after` at index 88 (DG:A234,
    /// `LeafVars.wk_diag`): a write through an over-long declaration.
    alias_write,
    /// `decodeFrom` loads the node's `Position` with its main key (DG:8CCC) mapped one byte off.
    position_off_by_one,
    /// `decodeFrom` loads the node's `SearchVars` with the move marks (DG:781A) mapped one byte
    /// off.
    search_vars_off_by_one,
    /// `decodeFrom` loads the domain's `EvalVars` with the pawn square sums (DG:90B6, 369A)
    /// mapped one byte off.
    eval_vars_off_by_one,
    /// `decodeFrom` loads the domain's `ThreatVars` with the first ply limit (DG:A272) mapped
    /// one byte off.
    threat_vars_off_by_one,
};

/// `PositionMap` with the main key (DG:8CCC) one byte off (the `position_off_by_one`
/// fault).
pub const PositionMapOffByOne = dgroup.Map(pos.Position, &position_off_by_one_entries);
const position_off_by_one_entries = blk: {
    var a = dgroup.maps.position.Position;
    for (&a) |*e| {
        if (std.mem.eql(u8, e.field, "hash_key")) e.addr += 1;
    }
    const final = a;
    break :blk final;
};

/// The order in which the holders of a byte are tried for its canonical holder: the
/// structs the node writes directly first.
pub const canon_order = [n_members]Member{ .st, .p, .sv, .ev, .s, .lv, .tv, .gv, .ts, .rv, .pg };

/// `SearchVarsMap` with the move marks (DG:781A) one byte off (the `search_vars_off_by_one`
/// fault).
pub const SearchVarsMapOffByOne = dgroup.Map(mg.SearchVars, &search_vars_off_by_one_entries);
const search_vars_off_by_one_entries = blk: {
    var a = dgroup.maps.movegen.SearchVars;
    for (&a) |*e| {
        if (std.mem.eql(u8, e.field, "marks")) e.addr += 1;
    }
    const final = a;
    break :blk final;
};

/// `EvalVarsMap` with the pawn square sums (DG:90B6, 369A) one byte off (the `eval_vars_off_by_one`
/// fault).
pub const EvalVarsMapOffByOne = dgroup.Map(evm.EvalVars, &eval_vars_off_by_one_entries);
const eval_vars_off_by_one_entries = blk: {
    var a = dgroup.maps.evalvars.EvalVars;
    for (&a) |*e| {
        if (std.mem.eql(u8, e.field, "pawn_square_sum")) e.addr += 1;
    }
    const final = a;
    break :blk final;
};

/// `ThreatVarsMap` with the first ply limit (DG:A272) one byte off (the
/// `threat_vars_off_by_one` fault).
pub const ThreatVarsMapOffByOne = dgroup.Map(et.ThreatVars, &threat_vars_off_by_one_entries);
const threat_vars_off_by_one_entries = blk: {
    var a = dgroup.maps.evalthreats.ThreatVars;
    for (&a) |*e| {
        if (std.mem.eql(u8, e.field, "ply_limit1")) e.addr += 1;
    }
    const final = a;
    break :blk final;
};

/// One run of bytes: `len` bytes at `a` in one struct (or address) and `b` in the other.
pub const Run = struct { a: u32, b: u32, len: u32 };

const space = 0x10000;

/// For every DGROUP byte and every member: the memory offset of the byte in the member
/// where it holds it (`off`), where it covers it at all (`cov`, through its latest-starting
/// declaration there), and the canonical holder (`canon`, -1 for none).
pub const Layout = struct {
    off: []i32,
    cov: []i32,
    canon: []i8,

    const Rec = struct { lo: u32, hi: u32, merged_lo: u32, base: u32, first: u32, esize: u32, stride: u32, field: []const u8 };

    fn records(comptime T: type, comptime entries: []const dgroup.Entry, out: *std.ArrayList(Rec), gpa: std.mem.Allocator) !void {
        inline for (entries) |e| {
            try out.append(gpa, .{
                .lo = e.addr,
                .hi = @intCast(@as(usize, e.addr) + dgroup.entryBytes(e)),
                .merged_lo = e.addr,
                .base = @offsetOf(T, e.field),
                .first = e.first,
                .esize = e.esize,
                .stride = @sizeOf(dgroup.Flat(@FieldType(T, e.field))),
                .field = e.field,
            });
        }
        // Contiguous pieces of one field are one declaration.
        const items = out.items;
        var i: usize = 1;
        while (i < items.len) : (i += 1) {
            const a = items[i - 1];
            const b = &items[i];
            if (std.mem.eql(u8, a.field, b.field) and b.lo == a.hi and b.first * b.esize == a.first * a.esize + (a.hi - a.lo)) b.merged_lo = a.merged_lo;
        }
    }

    pub fn build(gpa: std.mem.Allocator, wrong_holder: bool) !Layout {
        var recs: [n_members]std.ArrayList(Rec) = @splat(.empty);
        defer for (&recs) |*r| r.deinit(gpa);
        try records(sn.State, &dgroup.maps.searchnode.State, &recs[0], gpa);
        try records(pos.Position, &dgroup.maps.position.Position, &recs[1], gpa);
        try records(evm.EvalVars, &dgroup.maps.evalvars.EvalVars, &recs[2], gpa);
        try records(mg.SearchVars, &dgroup.maps.movegen.SearchVars, &recs[3], gpa);
        try records(see_mod.Scratch, &dgroup.maps.see.Scratch, &recs[4], gpa);
        try records(leaf.LeafVars, &dgroup.maps.leaf.LeafVars, &recs[5], gpa);
        try records(et.ThreatVars, &dgroup.maps.evalthreats.ThreatVars, &recs[6], gpa);
        try records(gamemove.GameVars, &dgroup.maps.gamemove.GameVars, &recs[7], gpa);
        try records(tbud.TimeState, &dgroup.maps.timebudget.TimeState, &recs[8], gpa);
        try records(rvm.RootVars, &dgroup.maps.rootvars.RootVars, &recs[9], gpa);
        try records(rvm.ProgramVars, &dgroup.maps.rootvars.ProgramVars, &recs[10], gpa);

        // Rule 1: where `State` declares a byte, the start of its declaration.
        const st_start = try gpa.alloc(i32, space);
        defer gpa.free(st_start);
        @memset(st_start, -1);
        for (recs[0].items) |r| for (r.lo..r.hi) |a| {
            st_start[a] = @intCast(r.merged_lo);
        };
        // Rule 2: elsewhere, the latest declared start among the other structs.
        const var_start = try gpa.alloc(i32, space);
        defer gpa.free(var_start);
        @memset(var_start, -1);
        for (recs[1..]) |rl| for (rl.items) |r| for (r.lo..r.hi) |a| {
            var_start[a] = @max(var_start[a], @as(i32, @intCast(r.merged_lo)));
        };

        const off = try gpa.alloc(i32, n_members * space);
        errdefer gpa.free(off);
        @memset(off, -1);
        const cov = try gpa.alloc(i32, n_members * space);
        errdefer gpa.free(cov);
        @memset(cov, -1);
        const cov_lo = try gpa.alloc(i32, space);
        defer gpa.free(cov_lo);
        for (recs, 0..) |rl, m| {
            @memset(cov_lo, -1);
            for (rl.items) |r| for (r.lo..r.hi) |a| {
                if (@as(i32, @intCast(r.merged_lo)) <= cov_lo[a]) continue;
                cov_lo[a] = @intCast(r.merged_lo);
                const rel: u32 = @intCast(a - r.lo);
                cov[m * space + a] = @intCast(r.base + (r.first + rel / r.esize) * r.stride + rel % r.esize);
            };
            for (0..space) |a| {
                if (cov_lo[a] < 0) continue;
                const holds = if (m == 0) true else if (st_start[a] >= 0) cov_lo[a] >= st_start[a] else cov_lo[a] == var_start[a];
                if (holds) off[m * space + a] = cov[m * space + a];
            }
        }

        const canon = try gpa.alloc(i8, space);
        errdefer gpa.free(canon);
        for (canon, 0..) |*k, a| {
            k.* = -1;
            for (0..n_members) |i| {
                // `wrong_holder` (a deliberate fault) tries the holders in the reverse order.
                const m: usize = @backingInt(canon_order[if (wrong_holder) n_members - 1 - i else i]);
                if (off[m * space + a] >= 0) {
                    k.* = @intCast(m);
                    break;
                }
            }
        }
        return .{ .off = off, .cov = cov, .canon = canon };
    }

    pub fn deinit(l: *Layout, gpa: std.mem.Allocator) void {
        gpa.free(l.off);
        gpa.free(l.cov);
        gpa.free(l.canon);
    }

    pub fn offOf(l: *const Layout, m: usize) []const i32 {
        return l.off[m * space ..][0..space];
    }
    pub fn covOf(l: *const Layout, m: usize) []const i32 {
        return l.cov[m * space ..][0..space];
    }
};

/// Whether no DGROUP byte is held by two members (Stage B step 6: no exception).
pub fn checkOneHolder(l: *const Layout) bool {
    for (0..space) |a| {
        var n: usize = 0;
        for (0..n_members) |m| {
            if (l.offOf(m)[a] >= 0) n += 1;
        }
        if (n > 1) return false;
    }
    return true;
}

/// The alias-write detector's tables: for each member, the bytes it covers but does not
/// hold (memory offset `a`, DG address `b`).
pub const Aliases = struct {
    alias: [n_members][]Run = @splat(&.{}),
    alias_bytes: [n_members]usize = @splat(0),

    pub fn build(al: *Aliases, gpa: std.mem.Allocator, l: *const Layout) !void {
        for (0..n_members) |m| {
            var list: std.ArrayList(Run) = .empty;
            errdefer list.deinit(gpa);
            for (0..space) |a| {
                const cv = l.covOf(m)[a];
                if (cv < 0 or l.offOf(m)[a] >= 0) continue;
                if (list.items.len > 0) {
                    const last = &list.items[list.items.len - 1];
                    if (last.a + last.len == cv and last.b + last.len == a) {
                        last.len += 1;
                        continue;
                    }
                }
                try list.append(gpa, .{ .a = @intCast(cv), .b = @intCast(a), .len = 1 });
            }
            al.alias[m] = try list.toOwnedSlice(gpa);
            for (al.alias[m]) |r| al.alias_bytes[m] += r.len;
        }
    }

    pub fn deinit(al: *Aliases, gpa: std.mem.Allocator) void {
        for (al.alias) |r| gpa.free(r);
    }
};

/// The domain's persistent structs (the node's `State` is the caller's), the homes of every
/// byte, and the alias-write detector's tables and saved bytes (and in a test build the
/// tests' codec snapshots).
pub const Members = struct {
    p: pos.Position = .{},
    ev: evm.EvalVars = .{},
    sv: mg.SearchVars = .{},
    s: see_mod.Scratch = .{},
    lv: leaf.LeafVars = .{},
    tv: et.ThreatVars = .{},
    /// The game's variables (Stage B step 8, stage 2); its pointer fields are bound by
    /// `bindGameVars`.
    gv: gamemove.GameVars = .{},
    /// The time budget's state (Stage B step 8, stage 5); its pointer fields are bound by
    /// `bindTimeState`.
    ts: tbud.TimeState = .{},
    /// The root's own variables and every other variable no unit's struct holds (Stage B
    /// step 8, stage 7).
    rv: rvm.RootVars = .{},
    pg: rvm.ProgramVars = .{},
    al: Aliases = .{},
    alias_saved: [n_members][alias_room]u8 = undefined,
    pending: u16 = 0,
    /// The tests' codec (src/state_image.zig `Snapshots`): the members' encodings as the
    /// last load from an image left them, and the image check's tables. A field of the test
    /// build only (`void` in the engine).
    img_snap: if (builtin.is_test) si.Snapshots else void = if (builtin.is_test) .{} else {},
    /// For every DGROUP byte: the member that holds it (-1: none; the byte has no home)
    /// and its offset in that member's memory (`Layout`'s canonical holder).
    home_m: []i8 = &.{},
    home_off: []i32 = &.{},
    /// For each member with a map: its snapshot's bytes at addresses it covers but does
    /// not hold (`copySlotsOf`), for `refreshAliases`.
    copy_slots: [n_members][]CopySlot = @splat(&.{}),
    /// For each member with a map: its snapshot's bytes that are not the byte of the
    /// address's home (`patchSlotsOf`): the copies above, and the bytes of a declaration of
    /// the member's own that another of its declarations holds (`Position.ep_square_by_ply`
    /// past its room over the board's first squares). A load from an image (`decodeFrom`)
    /// decodes every one of them from its one byte at the address; a checkpoint restored
    /// takes them from the
    /// home's byte in the checkpoint (`restoreMembers`).
    patch_slots: [n_members][]CopySlot = @splat(&.{}),

    const alias_room = 4096;

    /// Allocates a domain, checks that no byte has two holders (`error.TwoHolders`), and builds the alias-write detector's tables (once per engine,
    /// at start-up).
    pub fn create(gpa: std.mem.Allocator) !*Members {
        const d = try gpa.create(Members);
        errdefer gpa.destroy(d);
        d.* = .{};
        var l = try Layout.build(gpa, false);
        defer l.deinit(gpa);
        if (!checkOneHolder(&l)) return error.TwoHolders;
        try d.al.build(gpa, &l);
        errdefer d.al.deinit(gpa);
        for (d.al.alias_bytes) |n| if (n > alias_room) return error.AliasRoom;
        if (builtin.is_test) d.img_snap.held = try heldRuns(gpa, &l);
        errdefer if (builtin.is_test) gpa.free(d.img_snap.held);
        d.home_m = try gpa.alloc(i8, space);
        errdefer gpa.free(d.home_m);
        d.home_off = try gpa.alloc(i32, space);
        errdefer gpa.free(d.home_off);
        for (0..space) |a| {
            d.home_m[a] = l.canon[a];
            d.home_off[a] = if (l.canon[a] >= 0) l.offOf(@intCast(l.canon[a]))[a] else -1;
        }
        inline for (copy_members) |m| d.copy_slots[@backingInt(m)] = try copySlotsOf(MemberMap(m), gpa, &l, @backingInt(m));
        inline for (copy_members) |m| d.patch_slots[@backingInt(m)] = try patchSlotsOf(MemberMap(m), gpa, d, @backingInt(m));
        return d;
    }

    pub fn destroy(d: *Members, gpa: std.mem.Allocator) void {
        d.al.deinit(gpa);
        if (builtin.is_test) gpa.free(d.img_snap.held);
        gpa.free(d.home_m);
        gpa.free(d.home_off);
        for (d.copy_slots) |x| gpa.free(x);
        for (d.patch_slots) |x| gpa.free(x);
        gpa.destroy(d);
    }
};

/// The members with a field map (the node's `State` holds every byte it declares).
pub const copy_members = [_]Member{ .p, .ev, .sv, .s, .lv, .tv, .gv, .ts, .rv, .pg };

/// The field map of member `m`.
pub fn MemberMap(comptime m: Member) type {
    return switch (m) {
        .p => PositionMap,
        .ev => EvalVarsMap,
        .sv => SearchVarsMap,
        .s => ScratchMap,
        .lv => LeafVarsMap,
        .tv => ThreatVarsMap,
        .gv => GameVarsMap,
        .ts => TimeStateMap,
        .rv => RootVarsMap,
        .pg => ProgramVarsMap,
        .st => @compileError("the node's State has no copies"),
    };
}

/// A byte of a member's snapshot (`slot`, in its map's order) at a DGROUP address the
/// member covers but does not hold (`addr`): a copy of a byte whose home is elsewhere.
pub const CopySlot = struct { slot: u32, addr: u16 };

fn copySlotsOf(comptime M: type, gpa: std.mem.Allocator, l: *const Layout, m: usize) ![]CopySlot {
    var list: std.ArrayList(CopySlot) = .empty;
    errdefer list.deinit(gpa);
    var o: u32 = 0;
    inline for (M.map) |e| {
        const n = dgroup.entryBytes(e);
        for (0..n) |k| {
            const a: usize = e.addr + k;
            if (l.offOf(m)[a] < 0) try list.append(gpa, .{ .slot = @intCast(o + k), .addr = @intCast(a) });
        }
        o += @intCast(n);
    }
    return list.toOwnedSlice(gpa);
}

/// The slots of member `m`'s map (`M`) whose byte is not the home's: the address's home is
/// another member, or another byte of this member's memory (two declarations of its own).
fn patchSlotsOf(comptime M: type, gpa: std.mem.Allocator, d: *const Members, m: usize) ![]CopySlot {
    const T = M.Struct;
    var list: std.ArrayList(CopySlot) = .empty;
    errdefer list.deinit(gpa);
    var o: u32 = 0;
    inline for (M.map) |e| {
        const n = dgroup.entryBytes(e);
        const base = @offsetOf(T, e.field);
        const stride = @sizeOf(dgroup.Flat(@FieldType(T, e.field)));
        for (0..n) |k| {
            const a: usize = e.addr + k;
            const own: i32 = @intCast(base + (e.first + k / e.esize) * stride + k % e.esize);
            if (d.home_m[a] != @as(i8, @intCast(m)) or d.home_off[a] != own) try list.append(gpa, .{ .slot = @intCast(o + k), .addr = @intCast(a) });
        }
        o += @intCast(n);
    }
    return list.toOwnedSlice(gpa);
}

/// The tests' image check (src/state_image.zig `checkImage`) is on in the test builds where
/// safety checks are (Debug, ReleaseSafe). The engine has no image to check.
pub const image_check = builtin.is_test and std.debug.runtime_safety;

/// The DGROUP bytes some member holds, as runs of one holder (`a` its index, `b` the
/// first address, `len`).
pub fn heldRuns(gpa: std.mem.Allocator, l: *const Layout) ![]Run {
    var list: std.ArrayList(Run) = .empty;
    errdefer list.deinit(gpa);
    for (0..space) |a| {
        const k = l.canon[a];
        if (k < 0) continue;
        const m: u32 = @intCast(k);
        if (list.items.len > 0) {
            const last = &list.items[list.items.len - 1];
            if (last.a == m and last.b + last.len == a) {
                last.len += 1;
                continue;
            }
        }
        try list.append(gpa, .{ .a = m, .b = @intCast(a), .len = 1 });
    }
    return list.toOwnedSlice(gpa);
}

/// The node's interface on the domain, with the class C fixes `fixes`; the alias-write
/// detector is on where safety checks are (Debug, ReleaseSafe).
pub fn NodeEnv(comptime fixes: pos.Fixes) type {
    return NodeEnvWith(fixes, .none, std.debug.runtime_safety);
}

/// `NodeEnv` with a deliberate fault `brk` and the detector `detect` chosen (tests).
pub fn NodeEnvWith(comptime fixes: pos.Fixes, comptime brk: Break, comptime detect: bool) type {
    return struct {
        const Self = @This();
        pub const Node = sn.Node(Self);
        /// The class C fixes the search node itself reads (searchnode.zig `node_fixes`).
        pub const node_fixes: pos.Fixes = fixes;
        /// Whether the alias-write detector runs (for the tests' codec, which checks it
        /// before a store).
        pub const alias_detect = detect;

        st: *sn.State,
        pawn_hash: *PawnHash,
        tables: *[2]sn.HashTable,
        game_keys: []const u48,
        /// The tests' record of the node's makes, entries and returns (a field of the test
        /// build only: the engine's root counts them as they happen, engine_root `StopCtx`,
        /// and keeps no list).
        events: if (builtin.is_test) ?*std.ArrayList(Event) else void = if (builtin.is_test) null else {},
        gpa: std.mem.Allocator = std.heap.page_allocator,
        nodes: u64 = 0,
        makes: u64 = 0,
        polls: u64 = 0,
        calls: std.EnumArray(Method, u64) = .initFill(0),
        dom: *Members,
        /// The detector panics on an alias write unless this is false (tests): then it
        /// counts them, and keeps the first address.
        alias_panic: bool = true,
        alias_writes: u64 = 0,
        alias_first: u16 = 0,
        /// The tests' codec (src/state_image.zig `CtxCodec`: the image this `NodeEnv` is loaded
        /// from and stored to, whether it is entered, the image check's settings and counts).
        /// A field of the test build only (`void` in the engine).
        codec: if (builtin.is_test) si.CtxCodec else void = if (builtin.is_test) .{} else {},

        /// In a test build, that the members hold the state (a test that has stored them to
        /// its image, `state_image.exit`, must load them again before calling a routine).
        inline fn assertEntered(c: *const Self) void {
            if (builtin.is_test) std.debug.assert(c.codec.in_domain);
        }

        fn bytes(c: *Self, m: Member) [*]u8 {
            const d = c.dom;
            return switch (m) {
                .st => std.mem.asBytes(c.st),
                .p => std.mem.asBytes(&d.p),
                .ev => std.mem.asBytes(&d.ev),
                .sv => std.mem.asBytes(&d.sv),
                .s => std.mem.asBytes(&d.s),
                .lv => std.mem.asBytes(&d.lv),
                .tv => std.mem.asBytes(&d.tv),
                .gv => std.mem.asBytes(&d.gv),
                .ts => std.mem.asBytes(&d.ts),
                .rv => std.mem.asBytes(&d.rv),
                .pg => std.mem.asBytes(&d.pg),
            };
        }

        /// The home of DGROUP byte `addr`: the byte of the member that holds it. Since Stage
        /// B step 8, stage 7, every variable the engine reads or writes has a member for its
        /// home; since stage 8 there is no image behind them, and a byte no member holds
        /// panics (`noHome`), in every build mode.
        pub fn dgPtr(c: *Self, addr: u16) *u8 {
            c.assertEntered();
            const d = c.dom;
            const m = d.home_m[addr];
            if (m < 0) noHome(addr);
            return &c.bytes(@fromBackingInt(@intCast(m)))[@intCast(d.home_off[addr])];
        }

        /// Points every pointer field of the domain's `GameVars` at its variable's one home
        /// (`dgPtr`): the byte of the member that holds it. Each field's bytes must lie in
        /// one home, contiguous (`error.SplitHome`), and have one (`error.UnheldHome`).
        /// Once, at creation: the members do not move.
        pub fn bindGameVars(c: *Self) !void {
            const d = c.dom;
            inline for (@typeInfo(gamemove.GameVars).@"struct".field_names) |name| {
                if (comptime gamemove.isPointerVar(name)) {
                    const a: u16 = @field(gamemove.var_addresses, name);
                    const n = comptime gamemove.varBytes(name);
                    const first = try c.homeOf(a);
                    for (1..n) |k| if (try c.homeOf(a + @as(u16, @intCast(k))) != first + k) return error.SplitHome;
                    @field(d.gv, name) = @ptrCast(@as([*]u8, @ptrFromInt(first))[0..n]);
                }
            }
        }

        /// The same for the domain's `TimeState` (Stage B step 8, stage 5): every pointer
        /// field at its variable's one home, each field's bytes contiguous in one home.
        pub fn bindTimeState(c: *Self) !void {
            const d = c.dom;
            inline for (@typeInfo(tbud.TimeState).@"struct".field_names) |name| {
                if (comptime tbud.isPointerVar(name)) {
                    const a: u16 = @field(tbud.var_addresses, name);
                    const n = comptime tbud.varBytes(name);
                    const first = try c.homeOf(a);
                    for (1..n) |k| if (try c.homeOf(a + @as(u16, @intCast(k))) != first + k) return error.SplitHome;
                    @field(d.ts, name) = @ptrCast(@as([*]u8, @ptrFromInt(first))[0..n]);
                }
            }
        }

        fn homeOf(c: *Self, addr: u16) error{UnheldHome}!usize {
            const d = c.dom;
            const m = d.home_m[addr];
            if (m < 0) return error.UnheldHome;
            return @intFromPtr(&c.bytes(@fromBackingInt(@intCast(m)))[@intCast(d.home_off[addr])]);
        }

        /// Before a callee: the alias-write detector's check of the last callee and its
        /// save of the bytes this one's structs cover but do not hold.
        inline fn guard(c: *Self, comptime ms: []const Member) void {
            if (detect) {
                c.checkAliases();
                c.saveAliases(ms);
            }
        }

        /// `guard` for a callee of the root that runs on the domain's structs while the
        /// iteration loop is inside the domain (Stage B step 7, stage 3b: root_search's make
        /// and take-back, the square sums and the key, src/engine_root.zig).
        pub inline fn guardRoot(c: *Self, comptime ms: []const Member) void {
            c.guard(ms);
        }

        fn saveAliases(c: *Self, comptime ms: []const Member) void {
            const d = c.dom;
            inline for (ms) |m| {
                const i = @backingInt(m);
                const src = c.bytes(m);
                var o: usize = 0;
                for (d.al.alias[i]) |r| {
                    @memcpy(d.alias_saved[i][o..][0..r.len], src[r.a..][0..r.len]);
                    o += r.len;
                }
                d.pending |= @as(u16, 1) << i;
            }
        }

        /// The detector's check of the last callee (also run by the tests' codec before
        /// it stores the members to an image).
        pub fn checkAliases(c: *Self) void {
            const d = c.dom;
            if (d.pending == 0) return;
            inline for (0..n_members) |i| {
                if (d.pending & (@as(u16, 1) << i) != 0) {
                    const src = c.bytes(@fromBackingInt(@intCast(i)));
                    var o: usize = 0;
                    for (d.al.alias[i]) |r| {
                        if (!std.mem.eql(u8, src[r.a..][0..r.len], d.alias_saved[i][o..][0..r.len])) {
                            for (0..r.len) |k| if (src[r.a + k] != d.alias_saved[i][o + k]) c.aliasWrite(@fromBackingInt(@intCast(i)), @intCast(r.b + k));
                            // Not carried: the bytes go back to what the struct held, so that a
                            // store to an image (the tests' codec), which writes each struct's
                            // changed bytes, does not write them.
                            @memcpy(src[r.a..][0..r.len], d.alias_saved[i][o..][0..r.len]);
                        }
                        o += r.len;
                    }
                }
            }
            d.pending = 0;
        }

        fn aliasWrite(c: *Self, m: Member, addr: u16) void {
            if (c.alias_panic) std.debug.panic("engine_state: {s} wrote DG:{X:0>4}, a byte it covers but does not hold (a write through an over-long declaration)", .{ @tagName(m), addr });
            if (c.alias_writes == 0) c.alias_first = addr;
            c.alias_writes += 1;
        }

        /// The copies members `ms` keep of bytes they cover but do not hold (an over-long
        /// declaration's tail: `Aliases`), set from each byte's home (`dgPtr`), as a load
        /// from an image (`decodeFrom`) sets them from an image in which every byte holds
        /// its home's value. Stage B step 8, stage 4: the routines between searches that
        /// write many bytes (start-up, New game, Setup mode) refresh the copies once at
        /// their end, so that the members are left exactly as the bracket of Stage A, which
        /// stored them to the image and loaded them again, left them.
        ///
        /// Exactly that load for those bytes and nothing else: the member's mapped fields
        /// are encoded (`snapshot`), the copies' bytes replaced by their homes'
        /// (`Members.copy_slots`), and decoded back (`loadFromSnapshot`). In a test build the
        /// tests' codec snapshot takes the same bytes, so that its store does not write a
        /// refreshed copy over its home, and still writes every byte the member holds and
        /// has changed.
        pub fn refreshAliases(c: *Self, comptime ms: []const Member) void {
            c.assertEntered();
            if (detect) c.checkAliases();
            const d = c.dom;
            inline for (ms) |m| {
                if (comptime m != .st) {
                    const M = MemberMap(m);
                    const sp = c.member(m);
                    var cur: M.Snapshot = undefined;
                    M.snapshot(sp, &cur);
                    for (d.copy_slots[@backingInt(m)]) |x| {
                        const v = c.dgPtr(x.addr).*;
                        cur[x.slot] = v;
                        if (builtin.is_test) c.memberSnapshot(m)[x.slot] = v;
                    }
                    M.loadFromSnapshot(sp, &cur);
                }
            }
        }

        /// A checkpoint of the members (Stage B step 8, stage 7): `cp` has a field of each
        /// member's type named as the member (`copy_members`) and `st`, the node's `State`.
        /// Their values are copied; the alias-write detector's pending check is run first.
        pub fn saveMembers(c: *Self, cp: anytype) void {
            c.assertEntered();
            if (detect) c.checkAliases();
            inline for (copy_members) |m| @field(cp, @tagName(m)) = c.member(m).*;
            cp.st = c.st.*;
        }

        /// The members set from a checkpoint `saveMembers` took, exactly as a load from an
        /// image (`decodeFrom`) sets them from the image of the checkpoint (in which every
        /// address holds its home's byte): each member's mapped fields decoded from the
        /// checkpoint's encoding of them, every slot whose byte is not the home's
        /// (`Members.patch_slots`: the copies of bytes another member holds, and a
        /// declaration of the member's own that another of its declarations holds) taken
        /// from the home's byte in the checkpoint (`checkpointPtr`); the member's other
        /// fields, the pointers among them, are left as they are. The node's `State` is
        /// copied range by range (`searchnode.dg_fields`, as `imageToState` copies it). In a
        /// test build the tests' codec snapshots describe the test image, which is not
        /// touched; those slots are set in them to the homes' bytes, as `refreshAliases`
        /// sets the copies', so that the codec's store writes a copy or a second declaration
        /// over its home only if a routine has changed it since (an alias write) and the
        /// image after it is what a restore from an image and a store gave.
        pub fn restoreMembers(c: *Self, cp: anytype) void {
            c.assertEntered();
            if (detect) c.checkAliases();
            const d = c.dom;
            inline for (copy_members) |m| {
                const M = MemberMap(m);
                var tmp: M.Snapshot = undefined;
                M.snapshot(&@field(cp, @tagName(m)), &tmp);
                for (d.patch_slots[@backingInt(m)]) |x| {
                    tmp[x.slot] = c.checkpointPtr(cp, x.addr).*;
                    if (builtin.is_test) c.memberSnapshot(m)[x.slot] = tmp[x.slot];
                }
                M.loadFromSnapshot(c.member(m), &tmp);
            }
            const src = std.mem.asBytes(&cp.st);
            const dst = std.mem.asBytes(c.st);
            inline for (sn.dg_fields) |f| {
                const off = @offsetOf(sn.State, f.name);
                @memcpy(dst[off..][0..f.len], src[off..][0..f.len]);
            }
            d.pending = 0;
        }

        /// DGROUP byte `addr` in a checkpoint `cp` (`saveMembers`): the byte of the member's
        /// copy that holds it (`dgPtr`'s home in the checkpoint). A byte no member holds
        /// panics, as in `dgPtr`.
        pub fn checkpointPtr(c: *Self, cp: anytype, addr: u16) *u8 {
            const d = c.dom;
            const m = d.home_m[addr];
            if (m < 0) noHome(addr);
            const off: usize = @intCast(d.home_off[addr]);
            return switch (@as(Member, @fromBackingInt(@intCast(m)))) {
                .st => &std.mem.asBytes(&cp.st)[off],
                inline else => |k| &std.mem.asBytes(&@field(cp, @tagName(k)))[off],
            };
        }

        fn member(c: *Self, comptime m: Member) *MemberMap(m).Struct {
            const d = c.dom;
            return switch (m) {
                .p => &d.p,
                .ev => &d.ev,
                .sv => &d.sv,
                .s => &d.s,
                .lv => &d.lv,
                .tv => &d.tv,
                .gv => &d.gv,
                .ts => &d.ts,
                .rv => &d.rv,
                .pg => &d.pg,
                .st => unreachable,
            };
        }

        /// The tests' codec snapshot of member `m` (test builds only).
        fn memberSnapshot(c: *Self, comptime m: Member) *MemberMap(m).Snapshot {
            const sp = &c.dom.img_snap;
            return switch (m) {
                .p => &sp.pb,
                .ev => &sp.evb,
                .sv => &sp.svb,
                .s => &sp.sb,
                .lv => &sp.lvb,
                .tv => &sp.tvb,
                .gv => &sp.gvb,
                .ts => &sp.tsb,
                .rv => &sp.rvb,
                .pg => &sp.pgb,
                .st => unreachable,
            };
        }

        pub const all_members = [_]Member{ .st, .p, .ev, .sv, .s, .lv, .tv, .gv, .ts, .rv, .pg };

        /// A copy of `refreshAliases` that is not its home's value: the member and the
        /// address. For the tests that measure which copies a routine leaves stale.
        pub const Stale = struct { m: Member, addr: u16 };

        /// Every copy that `refreshAliases` would change now (its field's encoding at the
        /// copy's byte differs from what decoding the home's byte gives), into `out` (as
        /// many as fit); returns how many. With the domain entered; changes nothing.
        pub fn staleAliases(c: *Self, gpa: std.mem.Allocator, out: []Stale) !usize {
            c.assertEntered();
            const d = c.dom;
            var n: usize = 0;
            inline for (copy_members) |m| {
                const M = MemberMap(m);
                const cur = try gpa.create(M.Snapshot);
                defer gpa.destroy(cur);
                const alt = try gpa.create(M.Snapshot);
                defer gpa.destroy(alt);
                const tmp = try gpa.create(M.Struct);
                defer gpa.destroy(tmp);
                M.snapshot(c.member(m), cur);
                alt.* = cur.*;
                for (d.copy_slots[@backingInt(m)]) |x| alt[x.slot] = c.dgPtr(x.addr).*;
                tmp.* = c.member(m).*;
                M.loadFromSnapshot(tmp, alt);
                M.snapshot(tmp, alt);
                for (d.copy_slots[@backingInt(m)]) |x| {
                    if (alt[x.slot] != cur[x.slot]) {
                        if (n < out.len) out[n] = .{ .m = m, .addr = x.addr };
                        n += 1;
                    }
                }
            }
            return n;
        }

        /// Every member and the node's `State` decoded from the DGROUP image `img`, through
        /// each member's map, the copies of bytes another member holds included: the C
        /// start-up's image at start-up (`dgroup.initial`, src/engine_root.zig `EngineRoot.init`,
        /// `startUp`), the one image the engine reads; and in the tests the codec's load
        /// (src/state_image.zig `enter`), which also takes the snapshots its store compares
        /// with. The node's `State` points at the members.
        pub fn decodeFrom(c: *Self, img: *const Image) void {
            if (detect) c.checkAliases();
            const d = c.dom;
            imageToState(img, c.st);
            c.st.p = &d.p;
            c.st.sv = &d.sv;
            c.st.ev = &d.ev;
            c.st.lv = &d.lv;
            c.st.tv = &d.tv;
            c.loadOne(.p, if (brk == .position_off_by_one) PositionMapOffByOne else PositionMap, img);
            c.loadOne(.ev, if (brk == .eval_vars_off_by_one) EvalVarsMapOffByOne else EvalVarsMap, img);
            c.loadOne(.sv, if (brk == .search_vars_off_by_one) SearchVarsMapOffByOne else SearchVarsMap, img);
            c.loadOne(.s, ScratchMap, img);
            c.loadOne(.lv, LeafVarsMap, img);
            c.loadOne(.tv, if (brk == .threat_vars_off_by_one) ThreatVarsMapOffByOne else ThreatVarsMap, img);
            c.loadOne(.gv, GameVarsMap, img);
            c.loadOne(.ts, TimeStateMap, img);
            c.loadOne(.rv, RootVarsMap, img);
            c.loadOne(.pg, ProgramVarsMap, img);
            if (image_check) @memcpy(&d.img_snap.loaded, img);
            d.pending = 0;
            if (builtin.is_test) c.codec.in_domain = true;
        }

        /// Member `m` decoded from `img` through map `M` (`m`'s map, or one broken on
        /// purpose); in a test build its encoding kept as the codec's snapshot.
        inline fn loadOne(c: *Self, comptime m: Member, comptime M: type, img: *const Image) void {
            M.load(c.member(m), img);
            if (builtin.is_test) M.snapshot(c.member(m), c.memberSnapshot(m));
        }
        fn toSide(s: sn.Side) pos.Side {
            return if (s == sn.white) .white else .black;
        }

        fn count(c: *Self, comptime m: Method) void {
            c.assertEntered();
            c.calls.getPtr(m).* += 1;
        }

        /// Run the node `side` at `ply` from the test image's state (the node tests, as
        /// adapt_node `Ctx.run`): the members loaded from it, the search, the members stored
        /// back (src/state_image.zig).
        pub fn run(c: *Self, side: sn.Side, legal: *i16, beta: i16, alpha: i16, ply: i16) i16 {
            si.enter(c);
            c.nodes += 1;
            const r = Node.search(c, c.st, side, legal, beta, alpha, ply, 0);
            si.exit(c);
            c.event(.{ .ret = .{ .side = side, .ply = ply, .ax = r } });
            return r;
        }

        inline fn event(c: *Self, e: Event) void {
            if (builtin.is_test) if (c.events) |list| list.append(c.gpa, e) catch @panic("engine_state: out of memory for events");
        }

        // ---- the interface (searchnode.zig, `Node`) ----------------------------------

        /// 1E9D:7514: not bound (the UCI layer sets the stop flag at the root's count).
        pub fn poll(c: *Self) void {
            c.count(.poll);
            c.polls += 1;
        }

        pub fn isRepetition(c: *Self, ply: i16) bool {
            c.count(.isRepetition);
            c.guard(&.{ .p, .lv, .ev });
            return leaf.isRepetition(&c.dom.p, &c.dom.lv, &c.dom.ev, c.game_keys, ply);
        }

        pub fn attacks(c: *Self, side: sn.Side, sq: u8) bool {
            c.count(.attacks);
            c.guard(&.{.p});
            return switch (side) {
                sn.white => h.attacksSquareNoPawns(&c.dom.p, .white, sq),
                else => h.attacksSquareNoPawns(&c.dom.p, .black, sq),
            } != 0;
        }

        pub fn hashMovePlausible(c: *Self, side: sn.Side, mv: *u16) bool {
            c.count(.hashMovePlausible);
            c.guard(&.{.p});
            var m: pos.Move = .{ .from = @truncate(mv.*), .to = @truncate(mv.* >> 8), .flag = 0, .score = 0 };
            const r = switch (side) {
                sn.white => h.hashMovePlausible(&c.dom.p, .white, &m),
                else => h.hashMovePlausible(&c.dom.p, .black, &m),
            } != 0;
            mv.* = @as(u16, m.from) | @as(u16, m.to) << 8;
            return r;
        }

        pub fn probe(c: *Self, side: sn.Side, index: u32) void {
            c.count(.probe);
            c.tables[side].probe(index, &c.st.hash_entry);
        }

        pub fn store(c: *Self, side: sn.Side, index: u32) void {
            c.count(.store);
            c.tables[side].store(index, &c.st.hash_entry);
        }

        pub fn prefetchProbe(c: *Self, side: sn.Side, index: u32) void {
            c.tables[side].prefetch(index);
        }

        pub fn generate(c: *Self, gen: sn.Gen, side: sn.Side, ply: i16) u16 {
            c.count(.generate);
            const d = c.dom;
            const s = toSide(side);
            const p: usize = @intCast(ply);
            // A list past the original's room would lie over the variables after DG:70E4
            // (DEV-002); the node's ceiling (DG:0062, 35) keeps it out of reach.
            std.debug.assert(p < move_list_room);
            const list: *mg.MoveList = &c.st.move_list[p];
            if (gen == .evasions) {
                c.guard(&.{ .p, .sv });
                const r = h.genEvasions(&d.p, &d.sv, list, s, p);
                return r;
            }
            c.guard(&.{ .p, .s, .sv });
            // DEV-003 corrected as in Stage A (the move's own mark).
            const cf = mg.Fixes.corrected;
            const r = switch (gen) {
                .all => mg.genAllMovesFixes(cf, fixes, &d.p, &d.s, &d.sv, list, s, p, .{}),
                .q1 => mg.genTacticalMovesFixes(fixes, &d.p, &d.s, &d.sv, d.ev.black_king_by_passer, list, s, p),
                .q2 => mg.genTacticalMovesNoLosersFixes(fixes, &d.p, &d.s, &d.sv, list, s, p),
                .q3 => mg.genQuiescenceMovesFixes(fixes, &d.p, &d.s, &d.sv, list, s, p),
                .q4 => mg.genCapturesFixes(fixes, &d.p, &d.s, &d.sv, list, s, p),
                .evasions => unreachable,
            };
            return r;
        }

        pub fn sortList(c: *Self, ply: i16, n: u16) void {
            c.count(.sortList);
            sort_mod.sortMoves(&c.st.move_list[@intCast(ply)], @bitCast(n));
        }

        pub fn makeNull(c: *Self, ply: i16) void {
            c.count(.makeNull);
            c.guard(&.{.p});
            leaf.makeNull(&c.dom.p, @bitCast(ply));
        }

        pub fn child(c: *Self, side: sn.Side, legal: *i16, beta: i16, alpha: i16, ply: i16) i16 {
            c.count(.child);
            c.nodes += 1;
            c.event(.{ .node = .{ .side = side, .ply = ply, .alpha = alpha, .beta = beta } });
            const r = Node.search(c, c.st, side, legal, beta, alpha, ply, 0);
            c.event(.{ .ret = .{ .side = side, .ply = ply, .ax = r } });
            return r;
        }

        pub fn applyMove(c: *Self, side: sn.Side, ply: i16, m: pos.Move, undo: *pos.Undo) void {
            c.makes += 1;
            c.event(.{ .make = .{ .ply = @truncate(@as(u16, @bitCast(ply))), .from = m.from, .to = m.to, .flag = m.flag } });
            c.count(.applyMove);
            c.guard(&.{ .p, .ev });
            c.dom.p.applyMove(&c.dom.ev, m, toSide(side), @intCast(ply), undo, fixes);
        }

        pub fn unmake(c: *Self, side: sn.Side, m: pos.Move, undo: *pos.Undo) void {
            c.count(.unmake);
            c.guard(&.{.p});
            // The take-back of `applyMove` under the same fixes (DEV-050).
            c.dom.p.unmakeMoveFixes(m, toSide(side), undo, fixes);
        }

        pub fn pawnEval(c: *Self, side: sn.Side) i16 {
            c.count(.pawnEval);
            c.guard(&.{ .p, .ev });
            const r = switch (side) {
                sn.white => c.pawn_hash.probe(&c.dom.p, &c.dom.ev, .white),
                else => c.pawn_hash.probe(&c.dom.p, &c.dom.ev, .black),
            };
            return r;
        }

        /// static_eval's callees on the domain's own position and work areas, so that they
        /// see the pawn static_eval has lifted, as in the original. 4793:41B6 / 4CEC are the
        /// hand-written `pinexchange` under every `Fixes` (Stage A keeps the lifted routine
        /// with DEV-023 off; both are verified against the original).
        pub const StaticEvalCallees = struct {
            p: *pos.Position,
            s: *see_mod.Scratch,
            fn g(ctx: *anyopaque) *StaticEvalCallees {
                return @ptrCast(@alignCast(ctx));
            }
            pub fn seeWhite(ctx: *anyopaque, sq: u16, v: u16) u16 {
                const b = g(ctx);
                return see_mod.seeFixes(fixes, b.p, b.s, .white, @truncate(sq), v);
            }
            pub fn seeBlack(ctx: *anyopaque, sq: u16, v: u16) u16 {
                const b = g(ctx);
                return see_mod.seeFixes(fixes, b.p, b.s, .black, @truncate(sq), v);
            }
            pub fn att4CEC(ctx: *anyopaque, sq: u16, v: u16) u16 {
                const b = g(ctx);
                return pinexchange.exchangeFixes(fixes, b.p, b.s, .black, @truncate(sq), v);
            }
            pub fn att41B6(ctx: *anyopaque, sq: u16, v: u16) u16 {
                const b = g(ctx);
                return pinexchange.exchangeFixes(fixes, b.p, b.s, .white, @truncate(sq), v);
            }
            pub fn att4A76(ctx: *anyopaque, sq: u16) u16 {
                return h.attacksSquare(g(ctx).p, .white, sq);
            }
            pub fn att4AD4(ctx: *anyopaque, sq: u16) u16 {
                return h.attacksSquare(g(ctx).p, .black, sq);
            }
            pub fn callees(b: *StaticEvalCallees) se.Callees {
                return .{ .see_white = seeWhite, .see_black = seeBlack, .r4793_4CEC = att4CEC, .r4793_41B6 = att41B6, .r2B9F_4A76 = att4A76, .r2B9F_4AD4 = att4AD4, .ctx = b };
            }
        };

        /// static_eval's own fixes: DEV-015 corrected, as in Stage A, and DEV-053 from
        /// `fixes` (as adapt_staticeval `staticEvalFixes` passes it).
        pub const static_eval_fixes: se.Fixes = blk: {
            var f = se.Fixes.corrected;
            f.dev053_line_tables_other = f.dev053_line_tables_other or fixes.dev053_line_tables_other;
            f.dev054_unstoppable_passer_mirror = f.dev054_unstoppable_passer_mirror or fixes.dev054_unstoppable_passer_mirror;
            f.dev055_passer_block_extra_test = f.dev055_passer_block_extra_test or fixes.dev055_passer_block_extra_test;
            f.dev062_king_test_rank = f.dev062_king_test_rank or fixes.dev062_king_test_rank;
            break :blk f;
        };

        pub fn staticEval(c: *Self, side: sn.Side, arg: i16) i16 {
            c.count(.staticEval);
            const d = c.dom;
            c.guard(&.{ .p, .ev, .s });
            var b: StaticEvalCallees = .{ .p = &d.p, .s = &d.s };
            const iface = b.callees();
            const r = se.staticEval(&d.p, &d.ev, c.pawn_hash, &iface, side, @bitCast(arg), static_eval_fixes, .{ .{}, .{} });
            return r;
        }

        pub fn pieceEval(c: *Self, side: sn.Side, ply: i16) i16 {
            c.count(.pieceEval);
            c.guard(&.{ .p, .ev });
            return evalpieces.evalPiecesAndKingsFixes(fixes, &c.dom.p, &c.dom.ev, side, @bitCast(ply));
        }

        pub fn countAttacked(c: *Self, side: sn.Side) u16 {
            c.count(.countAttacked);
            c.guard(&.{.p});
            return switch (side) {
                sn.white => h.countAttackedFixes(fixes, &c.dom.p, .white),
                else => h.countAttackedFixes(fixes, &c.dom.p, .black),
            };
        }

        /// The far routines of the hand-written threat evaluators.
        const ThreatCallees = struct {
            p: *const pos.Position,
            s: *see_mod.Scratch,
            pub fn see(hc: ThreatCallees, side: pos.Side, square: u8, value: u16) u16 {
                return see_mod.seeFixes(fixes, hc.p, hc.s, side, square, value);
            }
            pub fn att(hc: ThreatCallees, side: pos.Side, square: u8, value: u16) u16 {
                return pinexchange.exchangeFixes(fixes, hc.p, hc.s, side, square, value);
            }
        };

        pub fn threats(c: *Self, side: sn.Side, ply: i16, n: u16, counter: *u8) i16 {
            c.count(.threats);
            const d = c.dom;
            // With DEV-022 corrected the x-ray walk starts from a piece on the board and
            // ends on it; uncorrected, it can run past the board into `Scratch`.
            if (comptime !fixes.dev022_captured_pieces) {
                if (detect) c.checkAliases();
                if (brk != .stale_root_aliases) refreshRootAliases(&d.s, &d.lv, c.st);
            }
            c.guard(&.{ .p, .ev, .s, .tv });
            // The routine overwrites its own argument slot [bp+6]; the node never reads it.
            var ply_slot: u16 = @bitCast(ply);
            const cal: ThreatCallees = .{ .p = &d.p, .s = &d.s };
            const r = switch (side) {
                sn.white => et.evalThreatsFixes(fixes, .white, &d.p, &d.ev, &d.tv, &d.s, cal, &ply_slot, n, counter),
                else => et.evalThreatsFixes(fixes, .black, &d.p, &d.ev, &d.tv, &d.s, cal, &ply_slot, n, counter),
            };
            if (brk == .alias_write) d.tv.black_rays_after[88] +%= 1;
            return r;
        }

        pub fn kingSafety(c: *Self) i16 {
            c.count(.kingSafety);
            c.guard(&.{ .p, .ev });
            return activity.mobilityTermFixes(fixes, &c.dom.p, &c.dom.ev);
        }

        pub fn endgameKing(c: *Self, side: sn.Side) i16 {
            c.count(.endgameKing);
            c.guard(&.{ .p, .lv, .ev });
            const r = switch (side) {
                sn.white => leaf.endgameKing(&c.dom.p, &c.dom.lv, &c.dom.ev, .white),
                else => leaf.endgameKing(&c.dom.p, &c.dom.lv, &c.dom.ev, .black),
            };
            return r;
        }

        pub fn leafAttackMap(c: *Self, side: sn.Side) void {
            c.count(.leafAttackMap);
            c.guard(&.{ .p, .lv });
            switch (side) {
                sn.white => leaf.leafAttackMap(&c.dom.p, &c.dom.lv, .white),
                else => leaf.leafAttackMap(&c.dom.p, &c.dom.lv, .black),
            }
        }

        pub fn leafTermA(c: *Self, side: sn.Side) i16 {
            c.count(.leafTermA);
            const d = c.dom;
            c.guard(&.{ .p, .lv, .s });
            // The passed-pawn masks DG:A6C2 (White) and DG:9D8C (Black), whose home is
            // `EvalVars` (step 4).
            const passed: [2]u8 = d.ev.passed_pawns;
            const r = switch (side) {
                sn.white => leaf.hangingPiecesFixes(fixes, &d.p, &d.lv, &d.s, .white, passed),
                else => leaf.hangingPiecesFixes(fixes, &d.p, &d.lv, &d.s, .black, passed),
            };
            return r;
        }

        pub fn leafTermB(c: *Self, side: sn.Side) i16 {
            c.count(.leafTermB);
            c.guard(&.{ .p, .lv });
            const r = switch (side) {
                sn.white => leaf.kingRingMap(&c.dom.p, &c.dom.lv, .white),
                else => leaf.kingRingMap(&c.dom.p, &c.dom.lv, .black),
            };
            return r;
        }

        /// The White node calls 1E9D:1E30 (piece_activity_black), the Black node 16E4
        /// (piece_activity_white): crossed, as the original (30- mirror table).
        pub fn pawnEndingTerm(c: *Self, side: sn.Side) i16 {
            c.count(.pawnEndingTerm);
            c.guard(&.{ .p, .ev });
            return switch (side) {
                sn.white => activity.pieceActivityBlackFixes(fixes, &c.dom.p, &c.dom.ev),
                else => activity.pieceActivityWhiteFixes(fixes, &c.dom.p, &c.dom.ev),
            };
        }

        /// 2B9F:BB76: the node calls it only when DG:239C >= 11, which no setting of the
        /// repeatable state gives (0Ah). Not bound, as in Stage A.
        pub fn tablebase(c: *Self, side_arg: u16, ply: i16) bool {
            _ = c;
            _ = side_arg;
            _ = ply;
            @panic("engine_state: the tablebase probe 2B9F:BB76 is not bound (DG:239C >= 11)");
        }
    };
}
