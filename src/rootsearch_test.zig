//! Replay test of src/rootsearch.zig against invocations recorded from the running
//! original (tests/golden/rootsearch/*.zst, made by tools/port/gen_rootsearch_vectors.py,
//! whose docstring defines the format).
//!
//! Each recorded invocation of the iteration loop, root_search or the root sort gives
//! the DGROUP image at its entry, every direct call it made in order (site, target,
//! stack words, the image just before and just after the call, AX and DX), the values
//! read that an interrupt can change, and the final image and AX. The port runs on the
//! entry state. At every call it makes through the interface, the test checks the site,
//! the callee and the arguments against the next recorded call, compares every field
//! of the port's state with the image the original had just before that call, and then
//! takes the callee's effects from the recording (the state is reloaded from the image
//! after the call; the call's AX and DX are returned). The C run-time calls the original
//! makes (stack check, memcpy, memcmp, sprintf, long division and multiplication) are
//! done inline by the port and skipped in the recording. At the return the final image
//! and the return value are compared. Bytes the timer interrupt wrote are left out of
//! the comparison of their stretch, as in tools/research/rootmodel/replay.py.
//!
//! The view is bound as the engine binds it (Stage B step 7, stage 3b): its tables and the
//! variables the node domain holds point at a port `State`, `Position`, `EvalVars`,
//! `ThreatVars` and `see.Scratch` (`rootsearch.bindDomain`), loaded from the recorded image
//! through their generated maps at the start and after every call, and read through the
//! view's pointers wherever the view's fields are compared. Since Stage B step 8, stage 7,
//! every other field points at a port `RootVars` (`rootsearch.bindRoot`), loaded in the same
//! way.

const std = @import("std");
const rs = @import("rootsearch.zig");
const RootState = rs.RootState;
const Callee = rs.Callee;

/// The fields of RootState and their DGROUP addresses.
const layout = [_]struct { []const u8, u16 }{
    .{ "root_move_count", 0x7442 },
    .{ "legal_count", 0xA518 },
    .{ "root_move_number", 0x8CBC },
    .{ "current_move", 0xA038 },
    .{ "best_move", 0xA36C },
    .{ "best_captured", 0x7186 },
    .{ "best_check", 0x77D0 },
    .{ "saved_best", 0x75C0 },
    .{ "saved_7242", 0xB4A8 },
    .{ "state_7242", 0x7242 },
    .{ "root_score", 0x934E },
    .{ "reference_score", 0x933C },
    .{ "last_score", 0xA8DA },
    .{ "search_start_score", 0x7184 },
    .{ "search_over", 0x9FD0 },
    .{ "pv_length", 0xB42B },
    .{ "child_pv_length", 0xAAF8 },
    .{ "b65c", 0xB65C },
    .{ "depth", 0x744E },
    .{ "iteration", 0xA3F4 },
    .{ "depth_reached", 0xA35C },
    .{ "loop_limit", 0x0064 },
    .{ "default_ceiling", 0x0066 },
    .{ "ply_ceiling", 0x0062 },
    .{ "ply_limit2", 0xA272 },
    .{ "ply_limit4", 0x9356 },
    .{ "ply_limit6", 0xA5EC },
    .{ "mate_mode", 0x1E08 },
    .{ "level", 0xA274 },
    .{ "corr_moves", 0xA4F4 },
    .{ "start_clock", 0xA8E8 },
    .{ "iter_start_elapsed", 0xA356 },
    .{ "base", 0x8D06 },
    .{ "hard", 0x9DB8 },
    .{ "soft", 0xA362 },
    .{ "fail_high", 0xB59A },
    .{ "mtg", 0x7102 },
    .{ "time_left", 0x77EC },
    .{ "clear_best", 0xA22C },
    .{ "ext_iteration", 0xA05C },
    .{ "fail_high_pending", 0xA3F5 },
    .{ "later_fail_high", 0xAE36 },
    .{ "stop", 0xA4FA },
    .{ "computer_side", 0x8DDE },
    .{ "opponent_side", 0x717C },
    .{ "pondering", 0x3676 },
    .{ "gives_check", 0x8C08 },
    .{ "white_bishops", 0xA03C },
    .{ "black_bishops", 0xA04C },
    .{ "piece_count", 0x154A },
    .{ "tb_flags", 0x239C },
    .{ "tb_score", 0x7466 },
    .{ "draw_mask", 0x8BC0 },
    .{ "draw_move", 0x3626 },
    .{ "w7182", 0x7182 },
    .{ "w90b6", 0x90B6 },
    .{ "w369a", 0x369A },
    .{ "hash_key", 0x8CCC },
    .{ "pawn_hash_key", 0x8CD2 },
    .{ "excluded_count", 0x250A },
    .{ "random_off", 0x1548 },
    .{ "random_limit", 0x291E },
    .{ "random_value", 0x70F2 },
    .{ "think_display", 0xAB1A },
    .{ "display_off", 0x22BA },
    .{ "planning_shown", 0x9351 },
    .{ "a5f4", 0xA5F4 },
    .{ "w73f8", 0x73F8 },
    .{ "a6a0", 0xA6A0 },
    .{ "a6a1", 0xA6A1 },
    .{ "menu_depth", 0x75B7 },
    .{ "analysis_hook", 0x24F6 },
    .{ "a38b", 0xA38B },
    .{ "analysis_depth", 0x24F0 },
    .{ "w2660", 0x2660 },
    .{ "w1b9c", 0x1B9C },
    .{ "w22b4", 0x22B4 },
    .{ "pv_columns", 0x2A5E },
    .{ "pv_display_ptr", 0x3686 },
};

/// The tables of RootState and their DGROUP addresses (pointers: `rootsearch.bindRoot` and
/// `bindDomain`).
const tables = [_]struct { []const u8, u16 }{
    .{ "root_moves", 0x3BC4 },
    .{ "root_scores", 0x8D0A },
    .{ "pv", 0x93B0 },
    .{ "child_pv", 0x93FA },
    .{ "pv_follow", 0x3790 },
    .{ "board", 0x9EF6 },
};

comptime {
    // every field of RootState is in the layout or the tables
    @setEvalBranchQuota(100000);
    const fs = @typeInfo(RootState).@"struct".field_names;
    if (fs.len != layout.len + tables.len) @compileError("layout does not list every RootState field");
    for (fs) |f| {
        var found = false;
        for (layout) |l| {
            if (std.mem.eql(u8, l[0], f)) found = true;
        }
        for (tables) |l| {
            if (std.mem.eql(u8, l[0], f)) found = true;
        }
        if (!found) @compileError("field not in layout: " ++ f);
    }
    // The layout is the one `rootsearch.bindRoot` binds by.
    for (layout, rs.layout) |a, b| {
        if (!std.mem.eql(u8, a[0], b[0]) or a[1] != b[1]) @compileError("rootsearch.layout differs from the test's: " ++ a[0]);
    }
}

/// The type a field holds: the field's own, or what it points at (Stage B step 7: a
/// table, or a variable the node domain's structs hold).
fn Held(comptime F: type) type {
    return switch (@typeInfo(F)) {
        .pointer => |p| p.child,
        else => F,
    };
}

fn isPointer(comptime F: type) bool {
    return @typeInfo(F) == .pointer;
}

fn byteSize(comptime T: type) usize {
    return switch (@typeInfo(T)) {
        .int => |i| i.bits / 8,
        .array => |a| a.len * byteSize(a.child),
        else => @compileError("unsupported field type"),
    };
}

fn readT(comptime T: type, img: []const u8, addr: usize) T {
    switch (@typeInfo(T)) {
        .int => return std.mem.readInt(T, img[addr..][0..comptime byteSize(T)], .little),
        .array => |a| {
            var v: T = undefined;
            for (&v, 0..) |*x, k| x.* = readT(a.child, img, addr + k * byteSize(a.child));
            return v;
        },
        else => unreachable,
    }
}

fn writeT(comptime T: type, img: []u8, addr: usize, v: T) void {
    switch (@typeInfo(T)) {
        .int => std.mem.writeInt(T, img[addr..][0..comptime byteSize(T)], v, .little),
        .array => |a| for (v, 0..) |x, k| writeT(a.child, img, addr + k * byteSize(a.child), x),
        else => unreachable,
    }
}

fn store(st: *const RootState, img: []u8) void {
    inline for (layout ++ tables) |l| {
        const F = @FieldType(RootState, l[0]);
        const v = if (comptime isPointer(F)) @field(st, l[0]).* else @field(st, l[0]);
        writeT(Held(F), img, l[1], v);
    }
}

/// Compare the port's fields, the ones it points at among them, with the reference image,
/// skipping noise bytes. Returns a description of the first difference, or null.
fn compareState(st: *const RootState, ref: []const u8, noise: *const std.StaticBitSet(0x10000), scratch: []u8, buf: []u8) ?[]const u8 {
    @memcpy(scratch, ref);
    store(st, scratch);
    inline for (layout ++ tables) |l| {
        const n = byteSize(Held(@FieldType(RootState, l[0])));
        for (0..n) |k| {
            const a = l[1] + k;
            if (scratch[a] != ref[a] and !noise.isSet(a))
                return std.fmt.bufPrint(buf, "field {s} (DG:{X:0>4}), byte {d}: port {d}, original {d}", .{ l[0], l[1], k, scratch[a], ref[a] }) catch "field differs";
        }
    }
    return null;
}

// ---------------------------------------------------------------------------
// The node domain's structs the loop's view points at (Stage B step 7, stage 3b)
// ---------------------------------------------------------------------------

const dgroup = @import("dgroup.zig");
const sn = @import("searchnode.zig");
const pos = @import("position.zig");
const evm = @import("evalvars.zig");
const et = @import("evalthreats.zig");
const see = @import("see.zig");

const StateMap = dgroup.Map(sn.State, &dgroup.maps.searchnode.State);
const PositionMap = dgroup.Map(pos.Position, &dgroup.maps.position.Position);
const EvalVarsMap = dgroup.Map(evm.EvalVars, &dgroup.maps.evalvars.EvalVars);
const ThreatVarsMap = dgroup.Map(et.ThreatVars, &dgroup.maps.evalthreats.ThreatVars);
const ScratchMap = dgroup.Map(see.Scratch, &dgroup.maps.see.Scratch);
const rvm = @import("rootvars.zig");
const RootVarsMap = dgroup.Map(rvm.RootVars, &dgroup.maps.rootvars.RootVars);
const ProgramVarsMap = dgroup.Map(rvm.ProgramVars, &dgroup.maps.rootvars.ProgramVars);

/// The port's `State`, `Position`, `EvalVars`, `ThreatVars` and `see.Scratch`, which
/// `rootsearch.bindDomain` points the view at, as the engine points it at the domain's, and
/// its `RootVars` (with `ProgramVars`), which `rootsearch.bindRoot` points the rest at.
/// Loaded from the recorded image through their generated maps (every byte at its own
/// address), so that a field pointed at the wrong byte reads another variable's value.
const Members = struct {
    st: sn.State = .{},
    p: pos.Position = .{},
    ev: evm.EvalVars = .{},
    tv: et.ThreatVars = .{},
    s: see.Scratch = .{},
    rv: rvm.RootVars = .{},
    pg: rvm.ProgramVars = .{},

    fn load(m: *Members, img: []const u8) void {
        const i: *const [0x10000]u8 = img[0..0x10000];
        StateMap.load(&m.st, i);
        PositionMap.load(&m.p, i);
        EvalVarsMap.load(&m.ev, i);
        ThreatVarsMap.load(&m.tv, i);
        ScratchMap.load(&m.s, i);
        RootVarsMap.load(&m.rv, i);
        ProgramVarsMap.load(&m.pg, i);
    }

    fn bind(m: *Members, st: *RootState) void {
        rs.bindRoot(st, &m.rv, &m.pg);
        rs.bindDomain(st, &m.st, &m.p, &m.ev, &m.tv, &m.s);
    }
};

// ---------------------------------------------------------------------------
// Reading the file
// ---------------------------------------------------------------------------

/// The move-mark table DG:781A, which root_search marks through the env (`env.marks()`).
const marks_addr = 0x781A;
const marks_len = @import("movegen.zig").marks_len;

const Cursor = struct {
    d: []const u8,
    i: usize = 0,
    fn u8_(c: *Cursor) u8 {
        const v = c.d[c.i];
        c.i += 1;
        return v;
    }
    fn int(c: *Cursor, comptime T: type) T {
        const v = std.mem.readInt(T, c.d[c.i..][0..@sizeOf(T)], .little);
        c.i += @sizeOf(T);
        return v;
    }
    fn varint(c: *Cursor) usize {
        var n: usize = 0;
        var shift: std.math.Log2Int(usize) = 0;
        while (true) {
            const b = c.u8_();
            n |= @as(usize, b & 0x7F) << shift;
            if (b & 0x80 == 0) return n;
            shift += 7;
        }
    }
    /// Apply a change list to img (or skip it when img is null).
    fn changes(c: *Cursor, img: ?[]u8) void {
        const n = c.varint();
        var prev: isize = -1;
        for (0..n) |_| {
            const a: usize = @intCast(prev + 1 + @as(isize, @intCast(c.varint())));
            const v = c.u8_();
            if (img) |m| m[a] = v;
            prev = @intCast(a);
        }
    }
};

const Call = struct {
    site: u16,
    seg: u16,
    off: u16,
    words: [8]u16,
    before: usize, // file offset of the change list
    after: usize,
    ax: u16,
    dx: u16,
    isr: usize, // file offset of the ISR list (u16 k, k x u16)
};

fn calleeOf(seg: u16, off: u16) ?Callee {
    const t = (@as(u32, seg) << 16) | off;
    return switch (t) {
        0x0000_678A => .square_sums,
        0x4793_3EA2 => .hash_key,
        0x1E9D_000C => .make,
        0x1E9D_0960 => .unmake,
        0x2B9F_402A => .repetition,
        0x2B9F_BB76 => .tb_probe,
        0x0000_3AC6 => .node_white,
        0x0000_5036 => .node_black,
        0x0000_2EC8 => .root_move_search,
        0x0000_8FE6 => .keep_fail_high,
        0x1E9D_7514 => .poll,
        0x4793_89D8 => .rand,
        0x1E9D_9B08 => .analysis,
        0x1E9D_7D58 => .planning_header,
        0x38C0_948A => .show_move,
        0x38C0_B156 => .show_char,
        0x38C0_9BEA => .show_score,
        0x38C0_8066 => .show_at,
        0x38C0_DDF6 => .show_text,
        0x38C0_9764 => .show_number,
        0x38C0_D2DC => .pv_screen_begin,
        0x38C0_D566 => .pv_screen_window,
        0x38C0_8898 => .pv_screen_line,
        0x38C0_D5BE => .pv_screen_flush,
        0x38C0_D306 => .pv_screen_end,
        0x0000_22C0 => .root_search,
        0x0000_668E => .sort_root_moves,
        else => null, // the C run-time: done inline by the port
    };
}

/// The interface, answered from one recorded invocation.
const Replay = struct {
    raw: []const u8,
    calls: []const Call,
    vol_sites: []const u16,
    vol_values: []const u32,
    k: usize = 0,
    v: usize = 0,
    cur: []u8,
    scratch: []u8,
    noise: *std.StaticBitSet(0x10000),
    st: *RootState,
    failure: ?[]const u8 = null,
    msg: [400]u8 = undefined,
    checked: usize = 0,
    /// The port's move marks (`env.marks()`), compared with the original's like
    /// RootState's fields.
    marks_buf: [marks_len]u8 = undefined,
    /// The structs `rootsearch.bindDomain` and `bindRoot` point the view at.
    m: *Members,

    pub fn marks(r: *Replay) *[marks_len]u8 {
        return &r.marks_buf;
    }

    fn compareMarks(r: *Replay, where: []const u8) bool {
        for (0..marks_len) |k| {
            const a = marks_addr + k;
            if (r.marks_buf[k] != r.cur[a] and !r.noise.isSet(a)) {
                r.fail("{s}: move mark {d} (DG:{X:0>4}): port {d}, original {d}", .{ where, k, a, r.marks_buf[k], r.cur[a] });
                return false;
            }
        }
        return true;
    }

    fn fail(r: *Replay, comptime fmt: []const u8, args: anytype) void {
        if (r.failure != null) return;
        r.failure = std.fmt.bufPrint(&r.msg, fmt, args) catch "failure";
    }

    fn noiseOf(r: *Replay, k: usize) void {
        var c: Cursor = .{ .d = r.raw, .i = r.calls[k].isr };
        const n = c.int(u16);
        for (0..n) |_| r.noise.set(c.int(u16));
    }

    /// Skip run-time calls up to the next interface call; apply their effects to cur.
    fn skipRuntime(r: *Replay) void {
        while (r.k < r.calls.len and calleeOf(r.calls[r.k].seg, r.calls[r.k].off) == null) {
            r.noiseOf(r.k);
            var c: Cursor = .{ .d = r.raw, .i = r.calls[r.k].before };
            c.changes(r.cur);
            c.changes(r.cur);
            r.k += 1;
        }
    }

    pub fn call(r: *Replay, site: u16, callee: Callee, args: []const u16) u32 {
        if (r.failure != null) return 0;
        r.skipRuntime();
        if (r.k >= r.calls.len) {
            r.fail("port calls {s} at {X:0>4}, the original made no more calls", .{ @tagName(callee), site });
            return 0;
        }
        const c = r.calls[r.k];
        const want = calleeOf(c.seg, c.off).?;
        if (c.site != site or want != callee) {
            r.fail("call {d}: port {s} at {X:0>4}, original {s} at {X:0>4}", .{ r.k, @tagName(callee), site, @tagName(want), c.site });
            return 0;
        }
        for (args, 0..) |a, j| {
            if (a != c.words[j]) {
                r.fail("call {d} ({s} at {X:0>4}): argument {d}: port {X:0>4}, original {X:0>4}", .{ r.k, @tagName(callee), site, j, a, c.words[j] });
                return 0;
            }
        }
        r.noiseOf(r.k);
        var cur: Cursor = .{ .d = r.raw, .i = c.before };
        cur.changes(r.cur);
        var buf: [200]u8 = undefined;
        if (compareState(r.st, r.cur, r.noise, r.scratch, &buf)) |d| {
            r.fail("before call {d} ({s} at {X:0>4}): {s}", .{ r.k, @tagName(callee), site, d });
            return 0;
        }
        if (!r.compareMarks("before a call")) return 0;
        r.noise.* = .empty;
        cur.changes(r.cur);
        r.m.load(r.cur);
        r.marks_buf = r.cur[marks_addr..][0..marks_len].*;
        r.k += 1;
        r.checked += 1;
        return @as(u32, c.dx) << 16 | c.ax;
    }

    pub fn volatileRead(r: *Replay, site: u16) u32 {
        if (r.failure != null) return 1; // ends the routines quickly after a failure
        while (r.v < r.vol_sites.len) {
            const s = r.vol_sites[r.v];
            r.v += 1;
            if (s == site) return r.vol_values[r.v - 1];
        }
        r.fail("volatile read at {X:0>4} not recorded", .{site});
        return 1;
    }

    pub fn local(r: *Replay, addr: u16) u8 {
        return r.cur[addr];
    }

    pub fn excluded(r: *Replay, move: [4]u8) bool {
        _ = move;
        r.fail("the excluded-move list is not modelled", .{});
        return false;
    }

    pub fn notModelled(r: *Replay, site: u16) void {
        r.fail("branch {X:0>4} not modelled", .{site});
    }

    /// At the routine's return: the remaining run-time calls, the final image.
    fn finish(r: *Replay, final_off: usize, isr_off: usize) void {
        if (r.failure != null) return;
        r.skipRuntime();
        if (r.k != r.calls.len) {
            const c = r.calls[r.k];
            r.fail("port returned after {d} calls, the original made {d} (next {X:0>4}:{X:0>4} at {X:0>4})", .{ r.k, r.calls.len, c.seg, c.off, c.site });
            return;
        }
        var ic: Cursor = .{ .d = r.raw, .i = isr_off };
        const n = ic.int(u16);
        for (0..n) |_| r.noise.set(ic.int(u16));
        var c: Cursor = .{ .d = r.raw, .i = final_off };
        c.changes(r.cur);
        var buf: [200]u8 = undefined;
        if (compareState(r.st, r.cur, r.noise, r.scratch, &buf)) |d| r.fail("at the return: {s}", .{d});
        _ = r.compareMarks("at the return");
    }
};

fn readVectors(gpa: std.mem.Allocator, name: []const u8) ![]u8 {
    var path_buf: [256]u8 = undefined;
    const dir = @import("build_options").golden_dir;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/rootsearch/{s}", .{ dir, name });
    const compressed = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, gpa, .limited(64 << 20));
    defer gpa.free(compressed);
    var in: std.Io.Reader = .fixed(compressed);
    const window = try gpa.alloc(u8, std.compress.zstd.default_window_len + std.compress.zstd.block_size_max);
    defer gpa.free(window);
    var zd = std.compress.zstd.Decompress.init(&in, window, .{});
    return zd.reader.allocRemaining(gpa, .limited(512 << 20));
}

const Totals = struct { loops: u32 = 0, roots: u32 = 0, sorts: u32 = 0, calls: usize = 0, failures: u32 = 0 };

fn replayFile(gpa: std.mem.Allocator, name: []const u8, tot: *Totals) !void {
    const raw = try readVectors(gpa, name);
    defer gpa.free(raw);
    try std.testing.expectEqualSlices(u8, "MCRT", raw[0..4]);
    try std.testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, raw[4..6], .little));
    const cur = try gpa.alloc(u8, 0x10000);
    defer gpa.free(cur);
    @memset(cur, 0);
    const scratch = try gpa.alloc(u8, 0x10000);
    defer gpa.free(scratch);
    const noise = try gpa.create(std.StaticBitSet(0x10000));
    defer gpa.destroy(noise);
    const st = try gpa.create(RootState);
    defer gpa.destroy(st);
    const members = try gpa.create(Members);
    defer gpa.destroy(members);
    var calls: std.ArrayList(Call) = .empty;
    defer calls.deinit(gpa);
    var vs: std.ArrayList(u16) = .empty;
    defer vs.deinit(gpa);
    var vv: std.ArrayList(u32) = .empty;
    defer vv.deinit(gpa);
    var c: Cursor = .{ .d = raw, .i = 6 };
    var n: [3]u32 = .{ 0, 0, 0 };
    var index: u32 = 0;
    while (true) : (index += 1) {
        const kind = c.u8_();
        if (kind == 0) {
            const want = [3]u32{ c.int(u32), c.int(u32), c.int(u32) };
            try std.testing.expectEqual(want, n);
            break;
        }
        const sp = c.int(u16);
        const bp = c.int(u16);
        const a0 = c.int(u16);
        const a1 = c.int(u16);
        c.changes(cur);
        // pre-scan the calls, the volatile reads and the final image
        calls.clearRetainingCapacity();
        vs.clearRetainingCapacity();
        vv.clearRetainingCapacity();
        const ncalls = c.int(u16);
        for (0..ncalls) |_| {
            var call: Call = undefined;
            call.site = c.int(u16);
            call.seg = c.int(u16);
            call.off = c.int(u16);
            for (&call.words) |*x| x.* = c.int(u16);
            call.before = c.i;
            c.changes(null);
            call.after = c.i;
            c.changes(null);
            call.ax = c.int(u16);
            call.dx = c.int(u16);
            call.isr = c.i;
            const k = c.int(u16);
            c.i += 2 * @as(usize, k);
            try calls.append(gpa, call);
        }
        const exit_isr = c.i;
        const kx = c.int(u16);
        c.i += 2 * @as(usize, kx);
        const nv = c.int(u16);
        for (0..nv) |_| {
            try vs.append(gpa, c.int(u16));
            try vv.append(gpa, c.int(u32));
        }
        const final_off = c.i;
        c.changes(null);
        const ax = c.int(u16);

        st.* = .{};
        members.* = .{};
        members.load(cur);
        members.bind(st);
        noise.* = .empty;
        var r: Replay = .{ .raw = raw, .calls = calls.items, .vol_sites = vs.items, .vol_values = vv.items, .cur = cur, .scratch = scratch, .noise = noise, .st = st, .m = members };
        r.marks_buf = cur[marks_addr..][0..marks_len].*;
        var result: ?u16 = null;
        switch (kind) {
            1 => rs.iterationLoop(st, &r, bp),
            2 => result = @bitCast(rs.rootSearch(st, &r, sp -% 2, @bitCast(a0), @bitCast(a1))),
            3 => {
                if (a0 != 0x3BC4) r.fail("sort of a list at {X:0>4}", .{a0});
                rs.sortRootMoves(st.root_moves[0..], st.root_scores[0..], @bitCast(a1));
            },
            else => return error.BadKind,
        }
        r.finish(final_off, exit_isr);
        if (r.failure == null) {
            if (result) |res| {
                if (res != ax) r.fail("return value: port {d}, original {d}", .{ @as(i16, @bitCast(res)), @as(i16, @bitCast(ax)) });
            }
        }
        if (r.failure) |f| {
            if (tot.failures < 10) std.debug.print("rootsearch {s} invocation {d} ({s}, args {X:0>4} {X:0>4}, depth {d}): {s}\n", .{ name, index, switch (kind) {
                1 => "iteration_loop",
                2 => "root_search",
                else => "sort_root_moves",
            }, a0, a1, @as(i8, @bitCast(cur[0x744E])), f });
            tot.failures += 1;
        }
        tot.calls += r.checked;
        n[kind - 1] += 1;
        // cur already holds the final image when the replay ran to the end; otherwise
        // rebuild it from the recording
        if (r.failure != null) {
            var k = r.k;
            while (k < calls.items.len) : (k += 1) {
                var cc: Cursor = .{ .d = raw, .i = calls.items[k].before };
                cc.changes(cur);
                cc.changes(cur);
            }
            var cf: Cursor = .{ .d = raw, .i = final_off };
            cf.changes(cur);
        }
    }
    tot.loops += n[0];
    tot.roots += n[1];
    tot.sorts += n[2];
}

test "root: every recorded iteration loop, root_search and root sort of the original" {
    const gpa = std.testing.allocator;
    var tot: Totals = .{};
    const files = [_][]const u8{ "fixed.zst", "timed.zst", "timed2.zst" };
    for (files) |f| try replayFile(gpa, f, &tot);
    std.debug.print("rootsearch: iteration_loop {d}, root_search {d}, sort_root_moves {d} invocations replayed; {d} interface calls checked; {d} mismatches\n", .{ tot.loops, tot.roots, tot.sorts, tot.calls, tot.failures });
    try std.testing.expectEqual(@as(u32, 0), tot.failures);
}

test "sort_root_moves: descending, equal keys keep their order within a pass" {
    var moves = [_][4]u8{ .{ 1, 0, 0, 0 }, .{ 2, 0, 0, 0 }, .{ 3, 0, 0, 0 }, .{ 4, 0, 0, 0 } };
    var scores = [_]i16{ 5, 9, 5, 7 };
    rs.sortRootMoves(&moves, &scores, 4);
    try std.testing.expectEqualSlices(i16, &.{ 9, 7, 5, 5 }, &scores);
    try std.testing.expectEqual(@as(u8, 2), moves[0][0]);
    try std.testing.expectEqual(@as(u8, 4), moves[1][0]);
    try std.testing.expectEqual(@as(u8, 1), moves[2][0]);
    try std.testing.expectEqual(@as(u8, 3), moves[3][0]);
}

test "root_stop_keep_failhigh_move (8FE6): the best move as the PV's first word, with its flags" {
    // From the listing (0000:8FE6-901A); it never ran in the recordings. [A36C] = e2e4
    // (from 35h, to 4Bh... as bytes 23h, 33h here), captured and check flags each way.
    var st: RootState = .{};
    // The PV and the move being searched are the domain's (`bindDomain`), the best move
    // `RootVars`' (`bindRoot`).
    const m = try std.testing.allocator.create(Members);
    defer std.testing.allocator.destroy(m);
    m.* = .{};
    m.bind(&st);
    st.best_move.* = .{ 0x23, 0x33, 0, 0x50 };
    rs.keepFailHigh(&st);
    try std.testing.expectEqual(@as(u16, 0x3323), st.pv[0]);
    try std.testing.expectEqualSlices(u8, &.{ 0x23, 0x33 }, st.current_move);
    st.best_captured.* = 9; // a piece code: only "non-zero" matters
    rs.keepFailHigh(&st);
    try std.testing.expectEqual(@as(u16, 0x33A3), st.pv[0]);
    try std.testing.expectEqualSlices(u8, &.{ 0xA3, 0x33 }, st.current_move);
    st.best_check.* = 1;
    rs.keepFailHigh(&st);
    try std.testing.expectEqual(@as(u16, 0xB3A3), st.pv[0]);
    // [A038]'s to byte does not get the check bit (9002-9012 set it in AX only).
    try std.testing.expectEqualSlices(u8, &.{ 0xA3, 0x33 }, st.current_move);
    // pv[1..] and the best move are untouched.
    try std.testing.expectEqual(@as(u16, 0), st.pv[1]);
    try std.testing.expectEqualSlices(u8, &.{ 0x23, 0x33, 0, 0x50 }, st.best_move);
}
