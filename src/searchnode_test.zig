//! Replay test of src/searchnode.zig against nodes recorded from the running original
//! (tests/golden/searchnode/*.zst, made by tools/port/gen_searchnode_vectors.py, whose
//! docstring defines the format).
//!
//! Each recorded node is replayed on its own. The state starts empty; every byte the
//! original node read is supplied at the point the recording gives (at entry, or as the
//! effect of the call just made). Every call the Zig node makes through the interface
//! is checked against the recording (same routine, same arguments, in the same order),
//! and at each call the bytes the node itself wrote since the previous call are compared.
//! The recorded result is returned and the routine's effects applied. At the return the
//! value, the parent's legal word and the last writes are compared, and then the whole
//! State against the expected image, so that a write the original did not make is
//! caught too. The first difference is reported with the node's index and arguments.

const std = @import("std");
const sn = @import("searchnode.zig");
const State = sn.State;
const pos = @import("position.zig");
const mg = @import("movegen.zig");
const evm = @import("evalvars.zig");
const EvalState = @import("eval_state.zig").EvalState;
const leaf = @import("leaf.zig");
const et = @import("evalthreats.zig");
const dgroup = @import("dgroup.zig");

/// The node's state, its position and its `SearchVars`, side by side: the replay's address
/// map gives each DGROUP address the offset of its byte in here (`State`'s fields by
/// `dg_fields`, the position's variables by `sn.position_rooms` through `Position`'s
/// generated field map, the marks and hints by `sn.search_rooms` through `SearchVars`').
const Both = struct {
    st: State = .{},
    p: pos.Position = .{},
    sv: mg.SearchVars = .{},
    ev: evm.EvalVars = .{},
    lv: leaf.LeafVars = .{},
    tv: et.ThreatVars = .{},

    /// All zeros, the node's `State.p`, `sv`, `ev`, `lv` and `tv` pointing at these.
    fn reset(b: *Both) void {
        @memset(std.mem.asBytes(b), 0);
        b.st.p = &b.p;
        b.st.sv = &b.sv;
        b.st.ev = &b.ev;
        b.st.lv = &b.lv;
        b.st.tv = &b.tv;
    }
};
const Move = sn.Move;
const Undo = sn.Undo;
const Side = sn.Side;

const files = [_][]const u8{ "start.zst", "incheck.zst", "fifty.zst", "minor.zst", "knightpawns.zst", "game.zst", "stops.zst", "nullmove.zst", "nulldrawwhite.zst", "nulldrawblack.zst" };

// ---------------------------------------------------------------------------
// Address map
// ---------------------------------------------------------------------------

const Map = [65536]i32;

/// The offset in `T` of DGROUP byte `a` through the latest-starting entry of its generated
/// field map `entries` (src/dgroup_maps.zig) covering it (an over-long per-ply array does
/// not own the next variable's byte), or -1.
fn mapOffset(comptime T: type, comptime entries: []const dgroup.Entry, a: usize) i32 {
    var lo: i32 = -1;
    var off: i32 = -1;
    inline for (entries) |e| {
        const n = dgroup.entryBytes(e);
        if (a >= e.addr and a < @as(usize, e.addr) + n and @as(i32, e.addr) > lo) {
            const rel = a - e.addr;
            const stride = @sizeOf(dgroup.Flat(@FieldType(T, e.field)));
            lo = e.addr;
            off = @intCast(@offsetOf(T, e.field) + (e.first + rel / e.esize) * stride + rel % e.esize);
        }
    }
    return off;
}

fn positionOffset(a: usize) i32 {
    return mapOffset(pos.Position, &dgroup.maps.position.Position, a);
}

fn searchVarsOffset(a: usize) i32 {
    return mapOffset(mg.SearchVars, &dgroup.maps.movegen.SearchVars, a);
}

fn evalVarsOffset(a: usize) i32 {
    return mapOffset(evm.EvalVars, &dgroup.maps.evalvars.EvalVars, a);
}

fn evalStateOffset(a: usize) i32 {
    return mapOffset(evm.EvalVars, &dgroup.maps.evalvars.EvalVars, a);
}

fn leafVarsOffset(a: usize) i32 {
    return mapOffset(leaf.LeafVars, &dgroup.maps.leaf.LeafVars, a);
}

fn threatVarsOffset(a: usize) i32 {
    return mapOffset(et.ThreatVars, &dgroup.maps.evalthreats.ThreatVars, a);
}

fn buildMap(map: *Map) void {
    @memset(map, -1);
    inline for (sn.dg_fields) |f| {
        const off: i32 = @intCast(@offsetOf(Both, "st") + @offsetOf(State, f.name));
        for (0..f.len) |i| map[f.addr + i] = off + @as(i32, @intCast(i));
    }
    // The position's variables, in the rooms the node's `State` declared for them.
    for (sn.position_rooms) |r| for (0..r.len) |i| {
        const a = r.addr + i;
        const o = positionOffset(a);
        std.debug.assert(o >= 0 and map[a] < 0);
        map[a] = @as(i32, @intCast(@offsetOf(Both, "p"))) + o;
    };
    // The marks and the hint bytes, in the original's rooms.
    for (sn.search_rooms) |r| for (0..r.len) |i| {
        const a = r.addr + i;
        const o = searchVarsOffset(a);
        std.debug.assert(o >= 0 and map[a] < 0);
        map[a] = @as(i32, @intCast(@offsetOf(Both, "sv"))) + o;
    };
    // The evaluation's flags and sums, in the rooms the node's `State` declared.
    for (sn.eval_vars_rooms) |r| for (0..r.len) |i| {
        const a = r.addr + i;
        const o = evalVarsOffset(a);
        std.debug.assert(o >= 0 and map[a] < 0);
        map[a] = @as(i32, @intCast(@offsetOf(Both, "ev"))) + o;
    };
    for (sn.eval_state_rooms) |r| for (0..r.len) |i| {
        const a = r.addr + i;
        const o = evalStateOffset(a);
        std.debug.assert(o >= 0 and map[a] < 0);
        map[a] = @as(i32, @intCast(@offsetOf(Both, "ev"))) + o;
    };
    // The leaf map, the key history, the ply limits and the iteration.
    for (sn.leaf_vars_rooms) |r| for (0..r.len) |i| {
        const a = r.addr + i;
        const o = leafVarsOffset(a);
        std.debug.assert(o >= 0 and map[a] < 0);
        map[a] = @as(i32, @intCast(@offsetOf(Both, "lv"))) + o;
    };
    for (sn.threat_vars_rooms) |r| for (0..r.len) |i| {
        const a = r.addr + i;
        const o = threatVarsOffset(a);
        std.debug.assert(o >= 0 and map[a] < 0);
        map[a] = @as(i32, @intCast(@offsetOf(Both, "tv"))) + o;
    };
}

fn fieldOfOffset(off: usize) struct { []const u8, usize } {
    const so = @offsetOf(Both, "st");
    const po = @offsetOf(Both, "p");
    inline for (.{ .{ "ev", evm.EvalVars, "EvalVars." }, .{ "lv", leaf.LeafVars, "LeafVars." }, .{ "tv", et.ThreatVars, "ThreatVars." } }) |m| {
        const mo = @offsetOf(Both, m[0]);
        if (off >= mo and off < mo + @sizeOf(m[1])) {
            inline for (@typeInfo(m[1]).@"struct".field_names) |name| {
                const o = mo + @offsetOf(m[1], name);
                if (off >= o and off < o + @sizeOf(@FieldType(m[1], name))) return .{ m[2] ++ name, off - o };
            }
            return .{ m[2] ++ "(padding)", off - mo };
        }
    }
    const vo = @offsetOf(Both, "sv");
    if (off >= vo and off < vo + @sizeOf(mg.SearchVars)) {
        inline for (@typeInfo(mg.SearchVars).@"struct".field_names) |name| {
            const o = vo + @offsetOf(mg.SearchVars, name);
            if (off >= o and off < o + @sizeOf(@FieldType(mg.SearchVars, name))) return .{ "SearchVars." ++ name, off - o };
        }
        return .{ "SearchVars (padding)", off - vo };
    }
    if (off >= po and off < po + @sizeOf(pos.Position)) {
        inline for (@typeInfo(pos.Position).@"struct".field_names) |name| {
            const o = po + @offsetOf(pos.Position, name);
            if (off >= o and off < o + @sizeOf(@FieldType(pos.Position, name))) return .{ "Position." ++ name, off - o };
        }
        return .{ "Position (padding)", off - po };
    }
    inline for (sn.dg_fields) |f| {
        const o = so + @offsetOf(State, f.name);
        if (off >= o and off < o + @sizeOf(@FieldType(State, f.name))) return .{ f.name, off - o };
    }
    return .{ "(padding)", off };
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

fn readVectors(gpa: std.mem.Allocator, name: []const u8) ![]u8 {
    return readVectorsIn(gpa, "searchnode", name);
}

fn readVectorsIn(gpa: std.mem.Allocator, unit: []const u8, name: []const u8) ![]u8 {
    var path_buf: [256]u8 = undefined;
    const dir = @import("build_options").golden_dir;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/{s}/{s}", .{ dir, unit, name });
    const compressed = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, gpa, .limited(64 << 20));
    defer gpa.free(compressed);
    var in: std.Io.Reader = .fixed(compressed);
    const window = try gpa.alloc(u8, std.compress.zstd.default_window_len + std.compress.zstd.block_size_max);
    defer gpa.free(window);
    var zd = std.compress.zstd.Decompress.init(&in, window, .{});
    return zd.reader.allocRemaining(gpa, .limited(512 << 20));
}

const Cursor = struct {
    d: []const u8,
    i: usize = 0,

    fn byte(c: *Cursor) u8 {
        const v = c.d[c.i];
        c.i += 1;
        return v;
    }
    fn u16_(c: *Cursor) u16 {
        const v = std.mem.readInt(u16, c.d[c.i..][0..2], .little);
        c.i += 2;
        return v;
    }
    fn u32_(c: *Cursor) u32 {
        const v = std.mem.readInt(u32, c.d[c.i..][0..4], .little);
        c.i += 4;
        return v;
    }
    /// A list (u16 n, n x (u16 addr, u8 value)); returns its bytes.
    fn list(c: *Cursor) []const u8 {
        const n = c.u16_();
        const s = c.d[c.i .. c.i + 3 * @as(usize, n)];
        c.i += 3 * @as(usize, n);
        return s;
    }
};

const Call = struct {
    id: u8,
    args: [8]u16 = undefined,
    nargs: u8,
    ax: u16,
    outs: [2]struct { id: u8, v: u16 } = undefined,
    nouts: u8,
    writes: []const u8,
    inject: []const u8,
};

const max_calls = 4096;

const Replay = struct {
    st: *State,
    exp: *State,
    sb: *Both,
    eb: *Both,
    map: *const Map,
    calls: []Call,
    ncalls: usize = 0,
    k: usize = 0,
    failed: bool = false,
    msg: [400]u8 = undefined,
    msg_len: usize = 0,

    fn fail(r: *Replay, comptime fmt: []const u8, args: anytype) void {
        if (r.failed) return;
        r.failed = true;
        const s = std.fmt.bufPrint(&r.msg, fmt, args) catch r.msg[0..];
        r.msg_len = s.len;
    }

    fn byteOf(r: *Replay, s: *Both, addr: u16) ?*u8 {
        const off = r.map[addr];
        if (off < 0) {
            r.fail("address DG:{X:0>4} is not in State or the node's Position", .{addr});
            return null;
        }
        return &std.mem.asBytes(s)[@intCast(off)];
    }

    /// The replay on `sb`, its expected image `eb`, both reset.
    fn init(sb: *Both, eb: *Both, map: *const Map, calls: []Call) Replay {
        sb.reset();
        eb.reset();
        // The expected state's pointer is the replayed one's, so that the whole-struct
        // comparison compares the variables and not two addresses.
        eb.st.p = &sb.p;
        eb.st.sv = &sb.sv;
        eb.st.ev = &sb.ev;
        eb.st.lv = &sb.lv;
        eb.st.tv = &sb.tv;
        return .{ .st = &sb.st, .exp = &eb.st, .sb = sb, .eb = eb, .map = map, .calls = calls, .ncalls = calls.len };
    }

    /// At the return: the node's state and its position against the expected image,
    /// so that a write the original did not make is caught.
    fn compareAll(r: *Replay) void {
        const a = std.mem.asBytes(r.sb);
        const b = std.mem.asBytes(r.eb);
        if (std.mem.indexOfDiff(u8, a, b)) |off| {
            const fo = fieldOfOffset(off);
            r.fail("State differs at {s}[{d}]: Zig {X:0>2}, original {X:0>2} (a write the original did not make)", .{ fo[0], fo[1], a[off], b[off] });
        }
    }

    fn apply(r: *Replay, list: []const u8, to_st: bool) void {
        var i: usize = 0;
        while (i < list.len) : (i += 3) {
            const a = std.mem.readInt(u16, list[i..][0..2], .little);
            if (to_st) {
                if (r.byteOf(r.sb, a)) |p| p.* = list[i + 2];
            }
            if (r.byteOf(r.eb, a)) |p| p.* = list[i + 2];
        }
    }

    fn checkWrites(r: *Replay, list: []const u8, where: []const u8) void {
        var i: usize = 0;
        while (i < list.len) : (i += 3) {
            const a = std.mem.readInt(u16, list[i..][0..2], .little);
            const p = r.byteOf(r.sb, a) orelse return;
            if (p.* != list[i + 2]) {
                const fo = fieldOfOffset(@intCast(r.map[a]));
                r.fail("{s}: node wrote DG:{X:0>4} ({s}[{d}]) = {X:0>2}, original {X:0>2}", .{ where, a, fo[0], fo[1], p.*, list[i + 2] });
                return;
            }
        }
        r.apply(list, false);
    }

    /// The next recorded call: must be routine `id` with arguments `args`.
    fn call(r: *Replay, id: u8, args: []const u16) ?*const Call {
        if (r.failed) return null;
        if (r.k >= r.ncalls) {
            r.fail("extra call: routine {d} args {any} after {d} recorded calls", .{ id, args, r.ncalls });
            return null;
        }
        const c = &r.calls[r.k];
        r.k += 1;
        if (c.id != id or c.nargs != args.len or !std.mem.eql(u16, c.args[0..c.nargs], args)) {
            r.fail("call {d}: Zig routine {d} args {any}, original routine {d} args {any}", .{ r.k - 1, id, args, c.id, c.args[0..c.nargs] });
            return null;
        }
        var buf: [32]u8 = undefined;
        r.checkWrites(c.writes, std.fmt.bufPrint(&buf, "at call {d}", .{r.k - 1}) catch "at call");
        if (r.failed) return null;
        r.apply(c.inject, true);
        return c;
    }

    fn out(c: *const Call, id: u8) u16 {
        for (c.outs[0..c.nouts]) |o| if (o.id == id) return o.v;
        unreachable;
    }

    // ---- the interface -------------------------------------------------------------

    pub fn poll(r: *Replay) void {
        _ = r.call(0, &.{});
    }
    pub fn isRepetition(r: *Replay, ply: i16) bool {
        const c = r.call(1, &.{@bitCast(ply)}) orelse return false;
        return c.ax != 0;
    }
    pub fn attacks(r: *Replay, side: Side, sq: u8) bool {
        _ = side;
        const c = r.call(2, &.{sq}) orelse return false;
        return c.ax != 0;
    }
    pub fn hashMovePlausible(r: *Replay, side: Side, mv: *u16) bool {
        _ = side;
        const c = r.call(3, &.{mv.*}) orelse return true;
        mv.* = out(c, 4);
        return c.ax != 0;
    }
    pub fn probe(r: *Replay, side: Side, index: u32) void {
        _ = side;
        _ = r.call(4, &.{ @truncate(index), @truncate(index >> 16) });
    }
    pub fn store(r: *Replay, side: Side, index: u32) void {
        _ = side;
        _ = r.call(5, &.{ @truncate(index), @truncate(index >> 16) });
    }
    pub fn generate(r: *Replay, gen: sn.Gen, side: Side, ply: i16) u16 {
        const c = r.call(@backingInt(gen), &.{ side, @bitCast(ply) }) orelse return 0;
        return c.ax;
    }
    pub fn sortList(r: *Replay, ply: i16, count: u16) void {
        _ = r.call(12, &.{ @bitCast(ply), count });
    }
    pub fn makeNull(r: *Replay, ply: i16) void {
        _ = r.call(13, &.{@bitCast(ply)});
    }
    pub fn child(r: *Replay, side: Side, legal: *i16, beta: i16, alpha: i16, ply: i16) i16 {
        _ = side;
        const c = r.call(14, &.{ @bitCast(beta), @bitCast(alpha), @bitCast(ply) }) orelse return 0;
        legal.* = @bitCast(out(c, 0));
        return @bitCast(c.ax);
    }
    fn mw(m: Move) u16 {
        return @as(u16, m.from) | @as(u16, m.to) << 8;
    }
    /// The recording has the three calls the node made as three records (0000:678A,
    /// 4793:3EA2, 1E9D:000C): each must come next, in that order, with its arguments,
    /// and the node's writes are checked at each, as when the node made them apart.
    pub fn applyMove(r: *Replay, side: Side, ply: i16, m: Move, undo: *Undo) void {
        _ = r.call(15, &.{ mw(m), m.flag });
        _ = r.call(16, &.{ mw(m), m.flag });
        const c = r.call(17, &.{ @bitCast(ply), side, mw(m), m.flag }) orelse return;
        undo.captured_slot = @truncate(out(c, 1));
        undo.captured = @truncate(out(c, 2));
    }
    /// No call of the original: nothing to check, nothing to do.
    pub fn prefetchProbe(r: *Replay, side: Side, index: u32) void {
        _ = r;
        _ = side;
        _ = index;
    }
    pub fn unmake(r: *Replay, side: Side, m: Move, undo: *Undo) void {
        const c = r.call(18, &.{ side, mw(m), m.flag, undo.captured, undo.captured_slot }) orelse return;
        undo.captured_slot = @truncate(out(c, 1));
        undo.captured = @truncate(out(c, 2));
    }
    fn val(r: *Replay, id: u8, args: []const u16) i16 {
        const c = r.call(id, args) orelse return 0;
        return @bitCast(c.ax);
    }
    pub fn pawnEval(r: *Replay, side: Side) i16 {
        _ = side;
        return r.val(19, &.{});
    }
    pub fn staticEval(r: *Replay, side: Side, arg: i16) i16 {
        return r.val(20, &.{ side, @bitCast(arg) });
    }
    pub fn pieceEval(r: *Replay, side: Side, ply: i16) i16 {
        return r.val(21, &.{ side, @bitCast(ply) });
    }
    pub fn countAttacked(r: *Replay, side: Side) u16 {
        _ = side;
        return @bitCast(r.val(22, &.{}));
    }
    pub fn threats(r: *Replay, side: Side, ply: i16, count: u16, counter: *u8) i16 {
        _ = side;
        const c = r.call(23, &.{ @bitCast(ply), count, counter.* }) orelse return 0;
        counter.* = @truncate(out(c, 3));
        return @bitCast(c.ax);
    }
    pub fn kingSafety(r: *Replay) i16 {
        return r.val(24, &.{});
    }
    pub fn endgameKing(r: *Replay, side: Side) i16 {
        _ = side;
        return r.val(25, &.{});
    }
    pub fn leafAttackMap(r: *Replay, side: Side) void {
        _ = side;
        _ = r.call(26, &.{});
    }
    pub fn leafTermA(r: *Replay, side: Side) i16 {
        _ = side;
        return r.val(27, &.{});
    }
    pub fn leafTermB(r: *Replay, side: Side) i16 {
        _ = side;
        return r.val(28, &.{});
    }
    pub fn pawnEndingTerm(r: *Replay, side: Side) i16 {
        _ = side;
        return r.val(29, &.{});
    }
    pub fn tablebase(r: *Replay, side_arg: u16, ply: i16) bool {
        const c = r.call(30, &.{ side_arg, @bitCast(ply) }) orelse return false;
        return c.ax != 0;
    }
};

const N = sn.Node(Replay);

const Result = struct { nodes: usize = 0, white: usize = 0, black: usize = 0, failed: usize = 0, calls: usize = 0 };

fn replayFile(gpa: std.mem.Allocator, name: []const u8, map: *const Map, sb: *Both, eb: *Both, calls: []Call) !Result {
    const data = try readVectors(gpa, name);
    defer gpa.free(data);
    var c: Cursor = .{ .d = data };
    if (!std.mem.eql(u8, data[0..4], "MCSN")) return error.BadMagic;
    c.i = 4;
    if (c.u16_() != 1) return error.BadVersion;
    const count = c.u32_();
    var res: Result = .{};
    var shown: usize = 0;
    for (0..count) |ni| {
        const side: Side = @intCast(c.byte());
        const beta: i16 = @bitCast(c.u16_());
        const alpha: i16 = @bitCast(c.u16_());
        const ply: i16 = @bitCast(c.u16_());
        var legal: i16 = @bitCast(c.u16_());
        const stale = c.byte();
        const entry = c.list();
        const ncalls = c.u16_();
        if (ncalls > calls.len) return error.TooManyCalls;
        for (0..ncalls) |k| {
            var x: Call = .{ .id = c.byte(), .nargs = c.byte(), .ax = 0, .nouts = 0, .writes = &.{}, .inject = &.{} };
            for (0..x.nargs) |j| x.args[j] = c.u16_();
            x.ax = c.u16_();
            x.nouts = c.byte();
            for (0..x.nouts) |j| {
                x.outs[j].id = c.byte();
                x.outs[j].v = c.u16_();
            }
            x.writes = c.list();
            x.inject = c.list();
            calls[k] = x;
        }
        const ret: i16 = @bitCast(c.u16_());
        const legal_out: i16 = @bitCast(c.u16_());
        const final = c.list();

        var r: Replay = .init(sb, eb, map, calls[0..ncalls]);
        const st = r.st;
        r.apply(entry, true);
        const v = N.search(&r, st, side, &legal, beta, alpha, ply, stale);
        if (!r.failed and r.k != ncalls) r.fail("the node made {d} of {d} recorded calls", .{ r.k, ncalls });
        if (!r.failed and v != ret) r.fail("return value {d}, original {d}", .{ v, ret });
        if (!r.failed and legal != legal_out) r.fail("parent's legal word {d}, original {d}", .{ legal, legal_out });
        if (!r.failed) r.checkWrites(final, "at return");
        if (!r.failed) r.compareAll();
        res.nodes += 1;
        res.calls += ncalls;
        if (side == 0) res.white += 1 else res.black += 1;
        if (r.failed) {
            res.failed += 1;
            if (shown < 5) {
                shown += 1;
                std.debug.print("searchnode {s} node {d} ({s}, ply {d}, beta {d}, alpha {d}): {s}\n", .{ name, ni, if (side == 0) "White" else "Black", ply, beta, alpha, r.msg[0..r.msg_len] });
            }
        }
    }
    if (c.i != data.len) return error.TrailingData;
    return res;
}

test "search node: replay of recorded nodes" {
    const gpa = std.testing.allocator;
    const map = try gpa.create(Map);
    defer gpa.destroy(map);
    buildMap(map);
    const sb = try gpa.create(Both);
    defer gpa.destroy(sb);
    const eb = try gpa.create(Both);
    defer gpa.destroy(eb);
    const calls = try gpa.alloc(Call, max_calls);
    defer gpa.free(calls);
    var total: Result = .{};
    for (files) |f| {
        const r = replayFile(gpa, f, map, sb, eb, calls) catch |e| switch (e) {
            error.FileNotFound => continue,
            else => return e,
        };
        std.debug.print("searchnode {s}: {d} nodes ({d} White, {d} Black), {d} calls, {d} failed\n", .{ f, r.nodes, r.white, r.black, r.calls, r.failed });
        total.nodes += r.nodes;
        total.white += r.white;
        total.black += r.black;
        total.calls += r.calls;
        total.failed += r.failed;
    }
    std.debug.print("searchnode total: {d} nodes ({d} White, {d} Black), {d} calls, {d} failed\n", .{ total.nodes, total.white, total.black, total.calls, total.failed });
    try std.testing.expect(total.nodes > 0);
    try std.testing.expectEqual(@as(usize, 0), total.failed);
}

// ---------------------------------------------------------------------------
// The ply-2 node, root_move_search (0000:2EC8)
// ---------------------------------------------------------------------------

/// tests/golden/rootmove/*.zst, made by tools/port/gen_rootmove_vectors.py (format in its
/// docstring: the node's, with the ply-2 head). Every invocation of 2EC8 the runs made.
const ply2_files = [_][]const u8{ "fixed5.zst", "timed2s.zst", "incheck.zst", "pawnend6.zst", "fried.zst", "timedfried.zst", "ponder.zst", "fifty.zst", "qgd4.zst", "pawnless.zst", "rookminor9.zst" };

fn readCalls(c: *Cursor, calls: []Call) void {
    for (calls) |*x| {
        x.* = .{ .id = c.byte(), .nargs = c.byte(), .ax = 0, .nouts = 0, .writes = &.{}, .inject = &.{} };
        for (0..x.nargs) |j| x.args[j] = c.u16_();
        x.ax = c.u16_();
        x.nouts = c.byte();
        for (0..x.nouts) |j| {
            x.outs[j].id = c.byte();
            x.outs[j].v = c.u16_();
        }
        x.writes = c.list();
        x.inject = c.list();
    }
}

/// The entry reads, with the four bytes of test D's inputs taken out into the clock
/// argument (they are not `State` fields).
fn applyPly2Entry(r: *Replay, entry: []const u8) sn.Ply2Clock {
    var cb: [12]u8 = @splat(0); // A356 dword, 8D06 dword, 3676 byte, 1480 word
    var i: usize = 0;
    while (i < entry.len) : (i += 3) {
        const a = std.mem.readInt(u16, entry[i..][0..2], .little);
        const v = entry[i + 2];
        switch (a) {
            0xA356...0xA359 => cb[a - 0xA356] = v,
            0x8D06...0x8D09 => cb[4 + a - 0x8D06] = v,
            0x3676 => cb[8] = v,
            0x1480...0x1481 => cb[10 + a - 0x1480] = v,
            else => r.apply(entry[i..][0..3], true),
        }
    }
    return .{
        .iter_start_elapsed = std.mem.readInt(u32, cb[0..4], .little),
        .base_time = std.mem.readInt(u32, cb[4..8], .little),
        .pondering = cb[8],
        .single_move = std.mem.readInt(u16, cb[10..12], .little),
    };
}

fn replayPly2File(gpa: std.mem.Allocator, name: []const u8, map: *const Map, sb: *Both, eb: *Both, calls: []Call) !Result {
    const data = try readVectorsIn(gpa, "rootmove", name);
    defer gpa.free(data);
    var c: Cursor = .{ .d = data };
    if (!std.mem.eql(u8, data[0..4], "MCRM")) return error.BadMagic;
    c.i = 4;
    if (c.u16_() != 1) return error.BadVersion;
    const count = c.u32_();
    var res: Result = .{};
    var shown: usize = 0;
    for (0..count) |ni| {
        const side: Side = @intCast(c.byte());
        const beta: i16 = @bitCast(c.u16_());
        const alpha: i16 = @bitCast(c.u16_());
        const stale_to = c.byte();
        const stale_slot = c.byte();
        const entry = c.list();
        const ncalls = c.u16_();
        if (ncalls > calls.len) return error.TooManyCalls;
        readCalls(&c, calls[0..ncalls]);
        const ret: i16 = @bitCast(c.u16_());
        const final = c.list();

        var r: Replay = .init(sb, eb, map, calls[0..ncalls]);
        const st = r.st;
        const clock = applyPly2Entry(&r, entry);
        const v = N.searchPly2(&r, st, side, beta, alpha, clock, stale_to, stale_slot);
        if (!r.failed and r.k != ncalls) r.fail("the node made {d} of {d} recorded calls", .{ r.k, ncalls });
        if (!r.failed and v != ret) r.fail("return value {d}, original {d}", .{ v, ret });
        if (!r.failed) r.checkWrites(final, "at return");
        if (!r.failed) r.compareAll();
        res.nodes += 1;
        res.calls += ncalls;
        if (side == 0) res.white += 1 else res.black += 1;
        if (r.failed) {
            res.failed += 1;
            if (shown < 5) {
                shown += 1;
                std.debug.print("rootmove {s} invocation {d} ({s}, beta {d}, alpha {d}): {s}\n", .{ name, ni, if (side == 0) "White" else "Black", beta, alpha, r.msg[0..r.msg_len] });
            }
        }
    }
    if (c.i != data.len) return error.TrailingData;
    return res;
}

test "root_move_search (2EC8): replay of recorded invocations" {
    const gpa = std.testing.allocator;
    const map = try gpa.create(Map);
    defer gpa.destroy(map);
    buildMap(map);
    const sb = try gpa.create(Both);
    defer gpa.destroy(sb);
    const eb = try gpa.create(Both);
    defer gpa.destroy(eb);
    const calls = try gpa.alloc(Call, max_calls);
    defer gpa.free(calls);
    var total: Result = .{};
    for (ply2_files) |f| {
        const r = replayPly2File(gpa, f, map, sb, eb, calls) catch |e| switch (e) {
            error.FileNotFound => continue,
            else => return e,
        };
        std.debug.print("rootmove {s}: {d} invocations ({d} White, {d} Black), {d} calls, {d} failed\n", .{ f, r.nodes, r.white, r.black, r.calls, r.failed });
        total.nodes += r.nodes;
        total.white += r.white;
        total.black += r.black;
        total.calls += r.calls;
        total.failed += r.failed;
    }
    std.debug.print("rootmove total: {d} invocations ({d} White, {d} Black), {d} calls, {d} failed\n", .{ total.nodes, total.white, total.black, total.calls, total.failed });
    try std.testing.expect(total.nodes > 0);
    try std.testing.expectEqual(@as(usize, 0), total.failed);
}

/// Replays one hand-made invocation of 2EC8: no hash hit, no null move (iteration 1),
/// one legal move that does not raise alpha, so the hash move word is never written and
/// its high byte, [bp-2Fh], is what goes into the entry stored (3A21).
fn ply2StaleRun(stale_to: u8) !u8 {
    const gpa = std.testing.allocator;
    const map = try gpa.create(Map);
    defer gpa.destroy(map);
    buildMap(map);
    const sb = try gpa.create(Both);
    defer gpa.destroy(sb);
    const eb = try gpa.create(Both);
    defer gpa.destroy(eb);
    var no_calls: [0]Call = .{};
    var r: Replay = .init(sb, eb, map, &no_calls);
    const st = r.st;
    st.* = .{ .p = &sb.p, .sv = &sb.sv, .ev = &sb.ev, .lv = &sb.lv, .tv = &sb.tv };
    st.hash_enabled = 1;
    st.hash_mask = 0xFF;
    st.horizon = 4;
    st.tv.iteration = 1;
    st.move_list[2][0] = .{ .from = 0x23, .to = 0x2B, .flag = 0, .score = 0 };
    const mw: u16 = 0x2B23;
    var calls = [_]Call{
        .{ .id = 4, .nargs = 2, .args = .{ 0, 0, 0, 0, 0, 0, 0, 0 }, .ax = 0, .nouts = 0, .writes = &.{}, .inject = &.{} },
        .{ .id = 6, .nargs = 2, .args = .{ 1, 2, 0, 0, 0, 0, 0, 0 }, .ax = 1, .nouts = 0, .writes = &.{}, .inject = &.{} },
        .{ .id = 15, .nargs = 2, .args = .{ mw, 0, 0, 0, 0, 0, 0, 0 }, .ax = 0, .nouts = 0, .writes = &.{}, .inject = &.{} },
        .{ .id = 16, .nargs = 2, .args = .{ mw, 0, 0, 0, 0, 0, 0, 0 }, .ax = 0, .nouts = 0, .writes = &.{}, .inject = &.{} },
        .{ .id = 17, .nargs = 4, .args = .{ 3, 1, mw, 0, 0, 0, 0, 0 }, .ax = 0, .outs = .{ .{ .id = 1, .v = 0 }, .{ .id = 2, .v = 0 } }, .nouts = 2, .writes = &.{}, .inject = &.{} },
        // child: beta = -alpha = 50, alpha = -beta = -50, ply 3; returns 100 (v = -100 <= alpha)
        .{ .id = 14, .nargs = 3, .args = .{ 50, @bitCast(@as(i16, -50)), 3, 0, 0, 0, 0, 0 }, .ax = 100, .outs = .{ .{ .id = 0, .v = 3 }, undefined }, .nouts = 1, .writes = &.{}, .inject = &.{} },
        .{ .id = 18, .nargs = 5, .args = .{ 1, mw, 0, 0, 0, 0, 0, 0 }, .ax = 0, .outs = .{ .{ .id = 1, .v = 0 }, .{ .id = 2, .v = 0 } }, .nouts = 2, .writes = &.{}, .inject = &.{} },
        .{ .id = 5, .nargs = 2, .args = .{ 0, 0, 0, 0, 0, 0, 0, 0 }, .ax = 0, .nouts = 0, .writes = &.{}, .inject = &.{} },
    };
    r.calls = &calls;
    r.ncalls = calls.len;
    const v = N.searchPly2(&r, st, 1, 50, -50, .{}, stale_to, 0);
    if (r.failed) {
        std.debug.print("{s}\n", .{r.msg[0..r.msg_len]});
        return error.ReplayFailed;
    }
    try std.testing.expectEqual(calls.len, r.k);
    try std.testing.expectEqual(@as(i16, -50), v); // upper bound: stored and returned as alpha
    try std.testing.expectEqual(@as(u8, 0x80 | 2), st.hash_entry[8]);
    try std.testing.expectEqual(@as(u8, 0), st.hash_entry[6]); // no move: from = 0
    return st.hash_entry[7];
}

test "root_move_search: DEV-034, the stale high byte of the hash move reaches the entry" {
    // The original: whatever the stack held at [bp-2Fh] (here 5Ah) is stored as the
    // to-square of "no move". The correction (the engine passes 0): 0 is stored. No
    // reader looks at it, since the from byte is 0.
    try std.testing.expectEqual(@as(u8, 0x5A), try ply2StaleRun(0x5A));
    try std.testing.expectEqual(@as(u8, 0), try ply2StaleRun(0));
}

// ---------------------------------------------------------------------------
// The direct-indexed hash table
// ---------------------------------------------------------------------------

test "hash index: the recorded probe indices" {
    // Keys and the run's mask 003FFFFFh with [9316] = 1, against the index the
    // original passed to the XMS copy (offset / 10), from the recorded probes
    // (tests/golden/searchnode, first probes of start.zst; see the vector tool).
    const gpa = std.testing.allocator;
    const data = readVectors(gpa, "start.zst") catch |e| switch (e) {
        error.FileNotFound => return error.SkipZigTest,
        else => return e,
    };
    defer gpa.free(data);
    // Walk the nodes; for each probe, rebuild the keys from the node's reads and check
    // hashIndex against the recorded index.
    var c: Cursor = .{ .d = data, .i = 6 };
    const count = c.u32_();
    var checked: usize = 0;
    for (0..count) |_| {
        _ = c.byte();
        c.i += 8;
        _ = c.byte();
        var keys: [12]u8 = @splat(0);
        var mask: [4]u8 = @splat(0);
        var mode: u8 = 0;
        var have: u32 = 0;
        const note = struct {
            fn f(l: []const u8, k: *[12]u8, m: *[4]u8, md: *u8, h: *u32) void {
                var i: usize = 0;
                while (i < l.len) : (i += 3) {
                    const a = std.mem.readInt(u16, l[i..][0..2], .little);
                    if (a >= 0x8CCC and a < 0x8CD8) {
                        k[a - 0x8CCC] = l[i + 2];
                        h.* |= @as(u32, 1) << @intCast(a - 0x8CCC);
                    } else if (a >= 0xB624 and a < 0xB628) {
                        m[a - 0xB624] = l[i + 2];
                        h.* |= @as(u32, 1) << @intCast(12 + a - 0xB624);
                    } else if (a == 0x9316) {
                        md.* = l[i + 2];
                        h.* |= 1 << 16;
                    }
                }
            }
        }.f;
        note(c.list(), &keys, &mask, &mode, &have);
        const ncalls = c.u16_();
        for (0..ncalls) |_| {
            const id = c.byte();
            const nargs = c.byte();
            var args: [8]u16 = undefined;
            for (0..nargs) |j| args[j] = c.u16_();
            _ = c.u16_();
            const nouts = c.byte();
            c.i += 3 * @as(usize, nouts);
            note(c.list(), &keys, &mask, &mode, &have);
            if (id == 4 and (have & 0x1F03C) == 0x1F03C) {
                const want = @as(u32, args[0]) | @as(u32, args[1]) << 16;
                try std.testing.expectEqual(want, sn.hashIndex(&keys, std.mem.readInt(u32, &mask, .little), mode));
                // The node's form since Stage B step 2: the main key as Position holds it.
                try std.testing.expectEqual(want, sn.hashIndexOfKey(std.mem.readInt(u48, keys[0..6], .little), std.mem.readInt(u32, &mask, .little), mode));
                checked += 1;
            }
            note(c.list(), &keys, &mask, &mode, &have);
        }
        c.i += 4;
        _ = c.list();
    }
    std.debug.print("searchnode hash index: {d} recorded probes checked\n", .{checked});
    try std.testing.expect(checked > 0);
}

// ---------------------------------------------------------------------------
// Benchmarks (src/bench.zig): -Dbench=true -Dtest-filter="bench: searchnode"
// ---------------------------------------------------------------------------

const bench = @import("bench.zig");

/// A recorded call reduced to what the node needs back: the result, the outputs and the
/// bytes to write into the state (as State offsets). Nothing is checked.
const FastCall = struct { ax: u16, outs: [2]u16, inject: []const [2]u16 };

const FastNode = struct {
    side: Side,
    beta: i16,
    alpha: i16,
    ply: i16,
    legal: i16,
    stale: u8,
    entry: []const [2]u16,
    calls: []const FastCall,
    /// Every State byte the original wrote or the recording supplied: zeroed after the
    /// node, so each node starts from the zero state the replay test gives it.
    dirty: []const u16,
};

const FastReplay = struct {
    st: *State,
    calls: []const FastCall,
    k: usize = 0,

    fn next(r: *FastReplay) *const FastCall {
        const c = &r.calls[r.k];
        r.k += 1;
        const b = std.mem.asBytes(r.st);
        for (c.inject) |e| b[e[0]] = @truncate(e[1]);
        return c;
    }
    pub fn poll(r: *FastReplay) void {
        _ = r.next();
    }
    pub fn isRepetition(r: *FastReplay, ply: i16) bool {
        _ = ply;
        return r.next().ax != 0;
    }
    pub fn attacks(r: *FastReplay, side: Side, sq: u8) bool {
        _ = side;
        _ = sq;
        return r.next().ax != 0;
    }
    pub fn hashMovePlausible(r: *FastReplay, side: Side, mv: *u16) bool {
        _ = side;
        const c = r.next();
        mv.* = c.outs[0];
        return c.ax != 0;
    }
    pub fn probe(r: *FastReplay, side: Side, index: u32) void {
        _ = side;
        _ = index;
        _ = r.next();
    }
    pub fn store(r: *FastReplay, side: Side, index: u32) void {
        _ = side;
        _ = index;
        _ = r.next();
    }
    pub fn generate(r: *FastReplay, gen: sn.Gen, side: Side, ply: i16) u16 {
        _ = gen;
        _ = side;
        _ = ply;
        return r.next().ax;
    }
    pub fn sortList(r: *FastReplay, ply: i16, count: u16) void {
        _ = ply;
        _ = count;
        _ = r.next();
    }
    pub fn makeNull(r: *FastReplay, ply: i16) void {
        _ = ply;
        _ = r.next();
    }
    pub fn child(r: *FastReplay, side: Side, legal: *i16, beta: i16, alpha: i16, ply: i16) i16 {
        _ = side;
        _ = beta;
        _ = alpha;
        _ = ply;
        const c = r.next();
        legal.* = @bitCast(c.outs[0]);
        return @bitCast(c.ax);
    }
    pub fn applyMove(r: *FastReplay, side: Side, ply: i16, m: Move, undo: *Undo) void {
        _ = side;
        _ = ply;
        _ = m;
        _ = r.next(); // 0000:678A
        _ = r.next(); // 4793:3EA2
        const c = r.next(); // 1E9D:000C
        undo.captured_slot = @truncate(c.outs[0]);
        undo.captured = @truncate(c.outs[1]);
    }
    pub fn prefetchProbe(r: *FastReplay, side: Side, index: u32) void {
        _ = r;
        _ = side;
        _ = index;
    }
    pub fn unmake(r: *FastReplay, side: Side, m: Move, undo: *Undo) void {
        _ = side;
        _ = m;
        const c = r.next();
        undo.captured_slot = @truncate(c.outs[0]);
        undo.captured = @truncate(c.outs[1]);
    }
    fn val(r: *FastReplay) i16 {
        return @bitCast(r.next().ax);
    }
    pub fn pawnEval(r: *FastReplay, side: Side) i16 {
        _ = side;
        return r.val();
    }
    pub fn staticEval(r: *FastReplay, side: Side, arg: i16) i16 {
        _ = side;
        _ = arg;
        return r.val();
    }
    pub fn pieceEval(r: *FastReplay, side: Side, ply: i16) i16 {
        _ = side;
        _ = ply;
        return r.val();
    }
    pub fn countAttacked(r: *FastReplay, side: Side) u16 {
        _ = side;
        return @bitCast(r.val());
    }
    pub fn threats(r: *FastReplay, side: Side, ply: i16, count: u16, counter: *u8) i16 {
        _ = side;
        _ = ply;
        _ = count;
        const c = r.next();
        counter.* = @truncate(c.outs[0]);
        return @bitCast(c.ax);
    }
    pub fn kingSafety(r: *FastReplay) i16 {
        return r.val();
    }
    pub fn endgameKing(r: *FastReplay, side: Side) i16 {
        _ = side;
        return r.val();
    }
    pub fn leafAttackMap(r: *FastReplay, side: Side) void {
        _ = side;
        _ = r.next();
    }
    pub fn leafTermA(r: *FastReplay, side: Side) i16 {
        _ = side;
        return r.val();
    }
    pub fn leafTermB(r: *FastReplay, side: Side) i16 {
        _ = side;
        return r.val();
    }
    pub fn pawnEndingTerm(r: *FastReplay, side: Side) i16 {
        _ = side;
        return r.val();
    }
    pub fn tablebase(r: *FastReplay, side_arg: u16, ply: i16) bool {
        _ = side_arg;
        _ = ply;
        return r.next().ax != 0;
    }
};

/// Decodes every node of the vector files into `FastNode`s (arena-allocated).
fn loadFast(arena: std.mem.Allocator, map: *const Map) ![]FastNode {
    var nodes: std.ArrayList(FastNode) = .empty;
    for (files) |name| {
        const data = readVectors(arena, name) catch |e| switch (e) {
            error.FileNotFound => continue,
            else => return e,
        };
        var c: Cursor = .{ .d = data, .i = 6 };
        const count = c.u32_();
        for (0..count) |_| {
            var n: FastNode = undefined;
            n.side = @intCast(c.byte());
            n.beta = @bitCast(c.u16_());
            n.alpha = @bitCast(c.u16_());
            n.ply = @bitCast(c.u16_());
            n.legal = @bitCast(c.u16_());
            n.stale = c.byte();
            n.entry = try toOffsets(arena, map, c.list());
            var dirty: std.ArrayList(u16) = .empty;
            for (n.entry) |e| try dirty.append(arena, e[0]);
            const ncalls = c.u16_();
            const calls = try arena.alloc(FastCall, ncalls);
            for (calls) |*x| {
                const id = c.byte();
                const nargs = c.byte();
                c.i += 2 * @as(usize, nargs);
                x.ax = c.u16_();
                const nouts = c.byte();
                x.outs = .{ 0, 0 };
                var outs: [2]struct { id: u8, v: u16 } = undefined;
                for (0..nouts) |j| outs[j] = .{ .id = c.byte(), .v = c.u16_() };
                // Order the outputs as FastReplay reads them.
                const want: [2]u8 = switch (id) {
                    3 => .{ 4, 0xFF },
                    14 => .{ 0, 0xFF },
                    17, 18 => .{ 1, 2 },
                    23 => .{ 3, 0xFF },
                    else => .{ 0xFF, 0xFF },
                };
                for (want, 0..) |w, j| {
                    for (outs[0..nouts]) |o| if (o.id == w) {
                        x.outs[j] = o.v;
                    };
                }
                for (try toOffsets(arena, map, c.list())) |e| try dirty.append(arena, e[0]);
                x.inject = try toOffsets(arena, map, c.list());
                for (x.inject) |e| try dirty.append(arena, e[0]);
            }
            n.calls = calls;
            c.i += 4;
            for (try toOffsets(arena, map, c.list())) |e| try dirty.append(arena, e[0]);
            n.dirty = dirty.items;
            try nodes.append(arena, n);
        }
    }
    return nodes.items;
}

fn toOffsets(arena: std.mem.Allocator, map: *const Map, list: []const u8) ![]const [2]u16 {
    const out = try arena.alloc([2]u16, list.len / 3);
    for (out, 0..) |*o, k| {
        const a = std.mem.readInt(u16, list[3 * k ..][0..2], .little);
        o.* = .{ @intCast(map[a]), list[3 * k + 2] };
    }
    return out;
}

test "bench: searchnode: one node over the recorded calls" {
    if (!bench.enabled) return;
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const map = try arena.create(Map);
    buildMap(map);
    const nodes = try loadFast(arena, map);
    const both = try arena.create(Both);
    const passes = 25;
    both.reset();
    const st = &both.st;
    const b = std.mem.asBytes(both);
    // Overhead: the entry bytes and the reset, as for every node below.
    var over: bench.Best = .{};
    for (0..passes) |_| {
        const t0 = bench.now();
        for (nodes) |n| {
            for (n.entry) |e| b[e[0]] = @truncate(e[1]);
            bench.keep(st);
            for (n.dirty) |o| b[o] = 0;
        }
        over.pass(t0);
    }
    var best: bench.Best = .{};
    var sum: i32 = 0;
    for (0..passes) |_| {
        const t0 = bench.now();
        for (nodes) |n| {
            for (n.entry) |e| b[e[0]] = @truncate(e[1]);
            var r: FastReplay = .{ .st = st, .calls = n.calls };
            var legal = n.legal;
            sum +%= sn.Node(FastReplay).search(&r, st, n.side, &legal, n.beta, n.alpha, n.ply, n.stale);
            bench.keep(st);
            for (n.dirty) |o| b[o] = 0;
        }
        best.pass(t0);
    }
    bench.keep(sum);
    best.report("searchnode: node (own work + fast replay of its calls)", nodes.len, passes, over.ns);
}

test "bench: searchnode: hash index, probe and store" {
    if (!bench.enabled) return;
    const n_slots = 3 << 20; // the run's mask 3FFFFFh with [9316] = 1
    const slots = try std.heap.page_allocator.alloc([10]u8, n_slots);
    defer std.heap.page_allocator.free(slots);
    @memset(slots, @splat(0));
    var t: sn.HashTable = .{ .slots = slots };
    const calls = 1 << 20;
    const keys = try std.heap.page_allocator.alloc([12]u8, calls);
    defer std.heap.page_allocator.free(keys);
    var rng = std.Random.DefaultPrng.init(0x5EED);
    for (keys) |*k| rng.random().bytes(k);
    const passes = 5;
    var over: bench.Best = .{};
    var best: bench.Best = .{};
    var e: [10]u8 = @splat(0);
    for (0..passes) |_| {
        const t0 = bench.now();
        for (keys) |*k| {
            const i = sn.hashIndex(k, 0x003FFFFF, 1);
            e[0] +%= @truncate(i);
            bench.keep(&e);
        }
        over.pass(t0);
    }
    for (0..passes) |_| {
        const t0 = bench.now();
        for (keys) |*k| {
            const i = sn.hashIndex(k, 0x003FFFFF, 1);
            t.probe(i, &e);
            e[8] |= 0x40;
            t.store(i, &e);
            bench.keep(&e);
        }
        best.pass(t0);
    }
    best.report("searchnode: hash probe + store, random slots of a 30 MB table", calls, passes, over.ns);
}

test "tagged hash table: the same probes as the plain table, clears included" {
    // Two million random operations on small tables (so slots are reused across
    // clears). The tagged table starts three clears before its count wraps, with every
    // slot holding garbage tagged with the count after the wrap: those slots must read
    // as zeros before the wrap (another count) and after it (the memory clear). Every
    // probe must return the same ten bytes, and after the run every slot must read the
    // same.
    const gpa = std.testing.allocator;
    const n = 1024;
    const plain_slots = try gpa.alloc([10]u8, n);
    defer gpa.free(plain_slots);
    @memset(plain_slots, @splat(0));
    const tagged_slots = try gpa.alignedAlloc(sn.TaggedSlot, .fromByteUnits(64), n);
    defer gpa.free(tagged_slots);
    @memset(std.mem.sliceAsBytes(tagged_slots), 0);
    var plain: sn.HashTable = .{ .slots = plain_slots };
    var tagged: sn.TaggedHashTable = .{ .slots = tagged_slots, .clears = std.math.maxInt(u32) - 2 };
    @memset(std.mem.sliceAsBytes(tagged_slots), 0xA5);
    for (tagged_slots) |*s| s.clears = 0;
    var rng = std.Random.DefaultPrng.init(0x88CC);
    const r = rng.random();
    var clears: usize = 0;
    for (0..2_000_000) |_| {
        const i = r.uintLessThan(u32, n);
        switch (r.uintLessThan(u32, 1000)) {
            0...1 => {
                plain.clear();
                tagged.clear();
                clears += 1;
            },
            2...499 => {
                var e: [10]u8 = undefined;
                r.bytes(&e);
                plain.store(i, &e);
                tagged.store(i, &e);
            },
            else => {
                var a: [10]u8 = undefined;
                var b: [10]u8 = undefined;
                plain.probe(i, &a);
                tagged.prefetch(i);
                tagged.probe(i, &b);
                try std.testing.expectEqualSlices(u8, &a, &b);
            },
        }
    }
    try std.testing.expect(clears > 3); // the count wrapped
    for (0..n) |i| {
        var a: [10]u8 = undefined;
        var b: [10]u8 = undefined;
        plain.probe(@intCast(i), &a);
        tagged.probe(@intCast(i), &b);
        try std.testing.expectEqualSlices(u8, &a, &b);
    }
}

test "bench: searchnode: hash clear and probe, plain and tagged tables" {
    if (!bench.enabled) return;
    const pa = std.heap.page_allocator;
    const n_slots = 3 << 20;
    const plain_slots = try pa.alloc([10]u8, n_slots);
    defer pa.free(plain_slots);
    @memset(plain_slots, @splat(0));
    const tagged_slots = try pa.alignedAlloc(sn.TaggedSlot, .fromByteUnits(64), n_slots);
    defer pa.free(tagged_slots);
    @memset(std.mem.sliceAsBytes(tagged_slots), 0);
    var plain: sn.HashTable = .{ .slots = plain_slots };
    var tagged: sn.TaggedHashTable = .{ .slots = tagged_slots };
    const passes = 7;
    {
        var b1: bench.Best = .{};
        var b2: bench.Best = .{};
        for (0..passes) |_| {
            var t0 = bench.now();
            plain.clear();
            bench.keep(plain.slots.ptr);
            b1.pass(t0);
            t0 = bench.now();
            tagged.clear();
            bench.keep(&tagged);
            b2.pass(t0);
        }
        b1.report("searchnode: clear one table of 3M slots (30 MB), plain", 1, passes, 0);
        b2.report("searchnode: clear one table of 3M slots, tagged", 1, passes, 0);
    }
    // Probe and store at random slots, each index depending on the previous probe, as
    // in a search, where the next key is not known before the last node is done. The
    // tables are first filled under the current clear count, so that every probe of
    // either table reads its result from memory.
    const calls = 1 << 20;
    const keys = try pa.alloc(u32, calls);
    defer pa.free(keys);
    var rng = std.Random.DefaultPrng.init(0x5EED);
    for (0..n_slots) |i| {
        var e: [10]u8 = undefined;
        rng.random().bytes(&e);
        plain.store(@intCast(i), &e);
        tagged.store(@intCast(i), &e);
    }
    for (keys) |*k| k.* = rng.random().int(u32);
    var b1: bench.Best = .{};
    var b2: bench.Best = .{};
    var over: bench.Best = .{};
    for (0..passes) |_| {
        var e: [10]u8 = @splat(0);
        var t0 = bench.now();
        for (keys) |k| {
            const i = (k ^ e[0]) % n_slots;
            e[1] +%= @truncate(i);
            bench.keep(&e);
        }
        over.pass(t0);
        t0 = bench.now();
        for (keys) |k| {
            const i = (k ^ e[0]) % n_slots;
            plain.probe(i, &e);
            e[8] |= 0x40;
            plain.store(i, &e);
        }
        b1.pass(t0);
        bench.keep(&e);
        t0 = bench.now();
        for (keys) |k| {
            const i = (k ^ e[0]) % n_slots;
            tagged.probe(i, &e);
            e[8] |= 0x40;
            tagged.store(i, &e);
        }
        b2.pass(t0);
        bench.keep(&e);
    }
    b1.report("searchnode: dependent probe + store, plain 10-byte slots", calls, passes, over.ns);
    b2.report("searchnode: dependent probe + store, tagged 16-byte slots", calls, passes, over.ns);
}

test "hash table: entry layout, store and probe" {
    var slots: [16][10]u8 = @splat(@splat(0));
    var t: sn.HashTable = .{ .slots = &slots };
    // An entry as the node builds it (B22 step 90): score -5, key words 1234h, 5678h,
    // move e2e4 (from 35h, to 4Bh... any bytes), lower bound at depth 3, key byte FDh
    // with extension 1.
    const e: [10]u8 = .{ 0xFB, 0xFF, 0x34, 0x12, 0x78, 0x56, 0x23, 0x37, 0xC3, 0xFD };
    t.store(5, &e);
    var o: [10]u8 = undefined;
    t.prefetch(5);
    t.probe(5, &o);
    try std.testing.expectEqualSlices(u8, &e, &o);
    try std.testing.expectEqual(@as(u8, 0xC0), o[8] & 0xC0);
    try std.testing.expectEqual(@as(u8, 3), o[8] & 0x3F);
    try std.testing.expectEqual(@as(u8, 1), o[9] & 3);
    t.probe(4, &o);
    try std.testing.expectEqual(@as(u8, 0), o[8] & 0xC0); // empty slot
    // The index with the run's mask: below 3 * 2^20 slots.
    var keys: [12]u8 = @splat(0xFF);
    try std.testing.expectEqual(@as(u32, (0x3FFFFF + 0x1FFFFF) >> 1), sn.hashIndex(&keys, 0x003FFFFF, 1));
    keys = @splat(0);
    keys[2] = 0x10;
    try std.testing.expectEqual(@as(u32, 0x10), sn.hashIndex(&keys, 0x003FFFFF, 0));
}

// ---------------------------------------------------------------------------
// The binding of the node's position (Stage B step 2), broken on purpose
// ---------------------------------------------------------------------------

/// `buildMap` with the position variable or search variable `name` (an entry of
/// `sn.position_rooms` or `sn.search_rooms`) mapped one byte off: each of its addresses to
/// the byte after the right one.
fn buildMapShifted(map: *Map, name: []const u8) void {
    buildMap(map);
    for (sn.position_rooms ++ sn.search_rooms ++ sn.eval_vars_rooms ++ sn.eval_state_rooms ++ sn.leaf_vars_rooms ++ sn.threat_vars_rooms) |r| if (std.mem.eql(u8, r.name, name)) {
        for (0..r.len) |i| map[r.addr + i] += 1;
    };
}

test "search node and root_move_search: a position variable mapped one byte off fails the replays" {
    const gpa = std.testing.allocator;
    const map = try gpa.create(Map);
    defer gpa.destroy(map);
    const sb = try gpa.create(Both);
    defer gpa.destroy(sb);
    const eb = try gpa.create(Both);
    defer gpa.destroy(eb);
    const calls = try gpa.alloc(Call, max_calls);
    defer gpa.free(calls);
    for ([_][]const u8{ "keys", "piece_list", "in_check" }) |name| {
        buildMapShifted(map, name);
        const a = try replayFile(gpa, "start.zst", map, sb, eb, calls);
        const b = try replayPly2File(gpa, "fixed5.zst", map, sb, eb, calls);
        std.debug.print("{s} one byte off: {d} of {d} nodes and {d} of {d} ply-2 invocations fail\n", .{ name, a.failed, a.nodes, b.failed, b.nodes });
        // In-check one byte off changes no recorded invocation of fixed5's ply-2 node
        // (measured); the node's replay catches it.
        try std.testing.expect(a.failed > 0 and (b.failed > 0 or std.mem.eql(u8, name, "in_check")));
    }
}

test "search node and root_move_search: a move mark or a hint byte mapped one byte off, or left out, fails the replays" {
    const gpa = std.testing.allocator;
    const map = try gpa.create(Map);
    defer gpa.destroy(map);
    const sb = try gpa.create(Both);
    defer gpa.destroy(sb);
    const eb = try gpa.create(Both);
    defer gpa.destroy(eb);
    const calls = try gpa.alloc(Call, max_calls);
    defer gpa.free(calls);
    var caught: [sn.search_rooms.len]usize = @splat(0);
    for (sn.search_rooms, 0..) |r, k| {
        for ([_]bool{ false, true }) |left_out| {
            buildMapShifted(map, r.name);
            // Left out: the room's addresses map nowhere, so any recorded read or write of
            // them fails (a byte off is invisible where every recorded value is 0).
            if (left_out) for (0..r.len) |i| {
                map[r.addr + i] = -1;
            };
            var a: Result = .{};
            for (files) |f| {
                const x = try replayFile(gpa, f, map, sb, eb, calls);
                a.nodes += x.nodes;
                a.failed += x.failed;
            }
            const b = try replayPly2File(gpa, "fixed5.zst", map, sb, eb, calls);
            std.debug.print("{s} {s}: {d} of {d} nodes and {d} of {d} ply-2 invocations fail\n", .{ r.name, if (left_out) "left out" else "one byte off", a.failed, a.nodes, b.failed, b.nodes });
            caught[k] += a.failed + b.failed;
        }
    }
    for (sn.search_rooms, caught) |r, n| {
        // The node writes DG:39AE only on the `[1E08]` path, which never runs (UNVERIFIED in
        // searchnode.zig): no recorded node reads or writes it, so no replay can see it.
        if (!std.mem.eql(u8, r.name, "king_rule")) try std.testing.expect(n > 0);
    }
}

test "search node and root_move_search: an evaluation flag or sum mapped one byte off, or left out, fails the replays" {
    const gpa = std.testing.allocator;
    const map = try gpa.create(Map);
    defer gpa.destroy(map);
    const sb = try gpa.create(Both);
    defer gpa.destroy(sb);
    const eb = try gpa.create(Both);
    defer gpa.destroy(eb);
    const calls = try gpa.alloc(Call, max_calls);
    defer gpa.free(calls);
    const rooms = sn.eval_vars_rooms ++ sn.eval_state_rooms;
    var caught: [rooms.len]usize = @splat(0);
    for (rooms, 0..) |r, k| {
        for ([_]bool{ false, true }) |left_out| {
            buildMapShifted(map, r.name);
            if (left_out) for (0..r.len) |i| {
                map[r.addr + i] = -1;
            };
            var a: Result = .{};
            for (files) |f| {
                const x = try replayFile(gpa, f, map, sb, eb, calls);
                a.nodes += x.nodes;
                a.failed += x.failed;
            }
            const b = try replayPly2File(gpa, "fixed5.zst", map, sb, eb, calls);
            std.debug.print("{s} {s}: {d} of {d} nodes and {d} of {d} ply-2 invocations fail\n", .{ r.name, if (left_out) "left out" else "one byte off", a.failed, a.nodes, b.failed, b.nodes });
            caught[k] += a.failed + b.failed;
        }
    }
    for (rooms, caught) |r, n| {
        // The node writes DG:39AE only on the `[1E08]` path, which never runs (UNVERIFIED in
        // searchnode.zig): no recorded node reads or writes it, so no replay can see it.
        if (!std.mem.eql(u8, r.name, "black_king_by_passer")) try std.testing.expect(n > 0);
    }
}

test "search node and root_move_search: a leaf or threat variable mapped one byte off, or left out, fails the replays" {
    const gpa = std.testing.allocator;
    const map = try gpa.create(Map);
    defer gpa.destroy(map);
    const sb = try gpa.create(Both);
    defer gpa.destroy(sb);
    const eb = try gpa.create(Both);
    defer gpa.destroy(eb);
    const calls = try gpa.alloc(Call, max_calls);
    defer gpa.free(calls);
    const rooms = sn.leaf_vars_rooms ++ sn.threat_vars_rooms ++ [_]sn.DgField{sn.eval_state_rooms[2]};
    var caught: [rooms.len]usize = @splat(0);
    for (rooms, 0..) |r, k| {
        for ([_]bool{ false, true }) |left_out| {
            buildMapShifted(map, r.name);
            if (left_out) for (0..r.len) |i| {
                map[r.addr + i] = -1;
            };
            var a: Result = .{};
            for (files) |f| {
                const x = try replayFile(gpa, f, map, sb, eb, calls);
                a.nodes += x.nodes;
                a.failed += x.failed;
            }
            const b = try replayPly2File(gpa, "fixed5.zst", map, sb, eb, calls);
            std.debug.print("{s} {s}: {d} of {d} nodes and {d} of {d} ply-2 invocations fail\n", .{ r.name, if (left_out) "left out" else "one byte off", a.failed, a.nodes, b.failed, b.nodes });
            caught[k] += a.failed + b.failed;
        }
    }
    for (caught) |n| try std.testing.expect(n > 0);
}

test "hash table: the clear that zeroes only what was written leaves the same bytes as a full clear (random stores, probes and clears, the tables kept between searches, the list's overflow)" {
    const gpa = std.testing.allocator;
    const n_slots = 1 << 14;
    var prng = std.Random.DefaultPrng.init(0x5EED_C1EA);
    const rnd = prng.random();
    for ([_]usize{ 0, 1, 7, 64, 1 << 12 }) |room| {
        const ref = try gpa.alloc([10]u8, n_slots);
        defer gpa.free(ref);
        const mem = try gpa.alloc([10]u8, n_slots);
        defer gpa.free(mem);
        const written = try gpa.alloc(u32, room);
        defer gpa.free(written);
        // Unknown content at first: the first clear must be a full one.
        for (ref, mem) |*a, *b| {
            rnd.bytes(a);
            b.* = a.*;
        }
        var t: sn.HashTable = .{ .slots = mem, .written = written };
        var clears: usize = 0;
        var overflows: usize = 0;
        for (0..200_000) |_| {
            const op = rnd.uintLessThan(u32, 1000);
            // The size in use varies, as with `Hash`: indices below a random bound.
            const bound: u32 = if (rnd.boolean()) 1 << 14 else @as(u32, 1) << rnd.uintLessThan(u5, 15);
            const i = rnd.uintLessThan(u32, bound);
            if (op < 3) {
                // clear_hash_tables; between clears the table is kept, as main keeps it.
                if (t.overflow) overflows += 1;
                t.clear();
                @memset(std.mem.sliceAsBytes(ref), 0);
                clears += 1;
                try std.testing.expectEqualSlices(u8, std.mem.sliceAsBytes(ref), std.mem.sliceAsBytes(mem));
            } else if (op < 450) {
                var e: [10]u8 = undefined;
                rnd.bytes(&e);
                if (op < 20) t.put(i, e) else t.store(i, &e);
                ref[i] = e;
            } else {
                var got: [10]u8 = undefined;
                t.probe(i, &got);
                try std.testing.expectEqualSlices(u8, &ref[i], &got);
            }
        }
        t.clear();
        @memset(std.mem.sliceAsBytes(ref), 0);
        try std.testing.expectEqualSlices(u8, std.mem.sliceAsBytes(ref), std.mem.sliceAsBytes(mem));
        try std.testing.expect(clears > 100);
        if (room < 64) try std.testing.expect(overflows > 0);
    }
}
