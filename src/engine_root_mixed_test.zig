//! Mixed mode for main before the iteration loop (docs/arch/60-engine-assembly.md §5 step
//! 11): every invocation recorded in tests/golden/rootprep/ (format: src/rootprep_test.zig,
//! tools/port/gen_rootprep_vectors.py) is run through the engine's env (src/engine_root.zig)
//! with the real callees, and each callee's effect on DGROUP and its result are compared
//! with the ones the original recorded at that call. The image is then set to the
//! recorded one, so that every call starts from the original's state.
//!
//! Answered from the recording instead of run: the search nodes (their inputs include the
//! main hash tables, which the recordings do not hold), the repetition count (it reads the
//! game record's keys, likewise), and play_best_move. The far reads (the game record, the
//! clock) are answered from the recording. A difference is counted per callee, at a byte
//! some unit holds (`engine_root.mappedByAUnit`) or not; the bytes of main's stack frame
//! are left out.

const std = @import("std");
const si = @import("state_image.zig");
const ert = @import("engine_root.zig");
const rp = @import("rootprep.zig");
const rs = @import("rootsearch.zig");
const pos = @import("position.zig");
const tablebase = @import("tablebase.zig");
const rpt = @import("rootprep_test.zig");

const R = ert.EngineRoot(pos.Fixes.original);

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

const Call = struct { site: u16, seg: u16, off: u16, before: usize, after: usize, ax: u16, dx: u16 };
const Far = struct { site: u16, value: u32 };

fn inlineCall(seg: u16, off: u16) bool {
    const t = (@as(u32, seg) << 16) | off;
    return switch (t) {
        // done by the port (the C run-time, 6BE4, 6BF8, 54CE) or by the env itself (the sort)
        0x4793_87D4, 0x4793_8AF0, 0x0000_6BE4, 0x0000_6BF8, 0x1E9D_54CE, 0x0000_668E => true,
        else => false,
    };
}

/// The callees whose AX is a result the port uses.
fn returnsValue(c: rp.Callee) bool {
    return switch (c) {
        .moves_to_go, .book_probe, .hash_resize, .gen_evasions, .gen_all_moves, .tb_probe, .repetition, .has_legal_move, .pawn_eval_wtm, .pawn_eval_btm, .static_eval, .hanging_white, .hanging_black, .pieces_and_kings, .activity_white, .activity_black, .endgame_king_white, .endgame_king_black, .count_attacked_wtm, .count_attacked_btm, .threats_white, .threats_black, .rand, .node_white, .node_black => true,
        else => false,
    };
}

const n_callees = std.enums.values(rp.Callee).len;

const Stats = struct {
    run: [n_callees]u32 = @splat(0),
    answered: [n_callees]u32 = @splat(0),
    ax_differs: [n_callees]u32 = @splat(0),
    held_differs: [n_callees]u32 = @splat(0),
    other_differs: [n_callees]u32 = @splat(0),
    first_held: [n_callees]?u16 = @splat(null),
    invocations: u32 = 0,
    aborted: u32 = 0,
};

const Mixed = struct {
    s: *R,
    raw: []const u8,
    calls: []const Call,
    fars: []const Far,
    k: usize = 0,
    f: usize = 0,
    pre: *[0x10000]u8,
    want: *[0x10000]u8,
    stack_lo: u16,
    stack_hi: u16,
    stats: *Stats,
    broken: ?[]const u8 = null,
    msg: [200]u8 = undefined,

    fn self(ctx: *anyopaque) *Mixed {
        return @ptrCast(@alignCast(ctx));
    }
    fn apply(m: *Mixed, off: usize, img: []u8) void {
        var c: Cursor = .{ .d = m.raw, .i = off };
        c.changes(img);
    }
    fn skipInline(m: *Mixed) void {
        while (m.k < m.calls.len and inlineCall(m.calls[m.k].seg, m.calls[m.k].off)) {
            m.apply(m.calls[m.k].before, m.s.test_img);
            m.apply(m.calls[m.k].after, m.s.test_img);
            m.k += 1;
        }
    }
    fn before(ctx: *anyopaque, site: u16, which: ert.Which, args: []const u16) bool {
        _ = args;
        const m = self(ctx);
        const c = which.prep;
        if (m.broken != null) return false;
        m.skipInline();
        if (m.k >= m.calls.len or m.calls[m.k].site != site) {
            m.broken = std.fmt.bufPrint(&m.msg, "call at {X:0>4} ({s}) not the next recorded", .{ site, @tagName(c) }) catch "out of step";
            return false;
        }
        m.apply(m.calls[m.k].before, m.s.test_img);
        @memcpy(m.pre, m.s.test_img);
        return switch (c) {
            .node_white, .node_black, .repetition, .play_best_move => false,
            else => true,
        };
    }
    fn after(ctx: *anyopaque, site: u16, which: ert.Which, args: []const u16, real: ?u32) u32 {
        _ = site;
        _ = args;
        const m = self(ctx);
        const c = which.prep;
        if (m.broken != null) return 0;
        const call = m.calls[m.k];
        m.k += 1;
        @memcpy(m.want, m.pre);
        m.apply(call.after, m.want);
        const i = @backingInt(c);
        if (real) |r| {
            m.stats.run[i] += 1;
            if (returnsValue(c) and @as(u16, @truncate(r)) != call.ax) m.stats.ax_differs[i] += 1;
            var held = false;
            var other = false;
            for (m.s.test_img, m.want, 0..) |g, w, a| {
                if (g == w or (a >= m.stack_lo and a < m.stack_hi)) continue;
                if (ert.mappedByAUnit(a)) {
                    held = true;
                    if (m.stats.first_held[i] == null) m.stats.first_held[i] = @intCast(a);
                } else other = true;
            }
            if (held) m.stats.held_differs[i] += 1;
            if (other) m.stats.other_differs[i] += 1;
        } else m.stats.answered[i] += 1;
        @memcpy(m.s.test_img, m.want);
        return @as(u32, call.dx) << 16 | call.ax;
    }
    fn far(ctx: *anyopaque, site: u16, off: u16) ?u32 {
        _ = off;
        const m = self(ctx);
        if (m.f >= m.fars.len or m.fars[m.f].site != site) {
            if (m.broken == null) m.broken = std.fmt.bufPrint(&m.msg, "far access at {X:0>4} not the next recorded", .{site}) catch "out of step";
            return 0;
        }
        m.f += 1;
        return m.fars[m.f - 1].value;
    }
};

const TbFiles = struct {
    const names = [_][]const u8{ "KPK.TBW", "KPK.TBB", "KQK.TBW", "KQK.TBB", "KRK.TBW", "KRK.TBB" };
    data: [names.len]?[]u8 = @splat(null),
    fn lookup(ctx: ?*const anyopaque, loc: tablebase.Location, name: []const u8) ?[]const u8 {
        const t: *const TbFiles = @ptrCast(@alignCast(ctx.?));
        if (loc != .program_tb) return null;
        for (names, 0..) |n, i| if (std.ascii.eqlIgnoreCase(n, name)) return t.data[i];
        return null;
    }
};

fn readVectors(gpa: std.mem.Allocator, name: []const u8) ![]u8 {
    var path_buf: [256]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/rootprep/{s}", .{ @import("build_options").golden_dir, name });
    const compressed = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, gpa, .limited(64 << 20));
    defer gpa.free(compressed);
    var in: std.Io.Reader = .fixed(compressed);
    const window = try gpa.alloc(u8, std.compress.zstd.default_window_len + std.compress.zstd.block_size_max);
    defer gpa.free(window);
    var zd = std.compress.zstd.Decompress.init(&in, window, .{});
    return zd.reader.allocRemaining(gpa, .limited(512 << 20));
}

test "join-root: main before the loop with the real callees, each compared with the original's call (rootprep vectors)" {
    const gpa = std.testing.allocator;
    const s = try R.init(gpa, 1 << 16);
    defer s.deinit();
    // The test drives the image itself, call by call: the members are stored to it for the
    // test (the codec's bracket), and loaded from it and stored back around each invocation
    // (`state_image.prepare`), as before step 8.
    si.imageBegin(s);
    defer si.imageEnd(s);
    var tbf: TbFiles = .{};
    defer for (&tbf.data) |*d| if (d.*) |x| gpa.free(x);
    for (TbFiles.names, 0..) |n, i| {
        var buf: [256]u8 = undefined;
        const path = try std.fmt.bufPrint(&buf, "{s}/../../reference/original/M80/TB/{s}", .{ @import("build_options").golden_dir, n });
        tbf.data[i] = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, gpa, .limited(1 << 20));
    }
    s.tb_files = .{ .ctx = &tbf, .lookupFn = TbFiles.lookup };
    const pre = try gpa.create([0x10000]u8);
    defer gpa.destroy(pre);
    const want = try gpa.create([0x10000]u8);
    defer gpa.destroy(want);
    var stats: Stats = .{};
    var calls: std.ArrayList(Call) = .empty;
    defer calls.deinit(gpa);
    var fars: std.ArrayList(Far) = .empty;
    defer fars.deinit(gpa);
    for (rpt.files) |name| {
        const raw = try readVectors(gpa, name);
        defer gpa.free(raw);
        @memset(s.test_img, 0);
        var c: Cursor = .{ .d = raw, .i = 6 };
        while (true) {
            const kind = c.u8_();
            if (kind == 0) break;
            if (kind == 2) {
                c.i += 2 + 2 + 6;
                const k = c.int(u16);
                c.i += 6 * @as(usize, k) + 2;
                continue;
            }
            const entry = c.int(u16);
            _ = c.int(u16); // exit
            const sp = c.int(u16);
            const bp = c.int(u16);
            c.changes(s.test_img);
            calls.clearRetainingCapacity();
            fars.clearRetainingCapacity();
            const ncalls = c.int(u16);
            for (0..ncalls) |_| {
                var call: Call = undefined;
                call.site = c.int(u16);
                call.seg = c.int(u16);
                call.off = c.int(u16);
                c.i += 16;
                call.before = c.i;
                c.changes(null);
                call.after = c.i;
                c.changes(null);
                call.ax = c.int(u16);
                call.dx = c.int(u16);
                try calls.append(gpa, call);
            }
            const nf = c.int(u16);
            for (0..nf) |_| {
                const site = c.int(u16);
                c.i += 4;
                try fars.append(gpa, .{ .site = site, .value = c.int(u32) });
            }
            const final_off = c.i;
            c.changes(null);
            stats.invocations += 1;
            if (bp == ert.main_bp) {
                var m: Mixed = .{ .s = s, .raw = raw, .calls = calls.items, .fars = fars.items, .pre = pre, .want = want, .stack_lo = sp -% 0x300, .stack_hi = bp +% 2, .stats = &stats };
                s.hook = .{ .ctx = &m, .before = Mixed.before, .after = Mixed.after, .far = Mixed.far };
                s.failure = null;
                for (s.tables) |*t| t.clear();
                _ = si.prepare(s, @as(rp.Entry, @fromBackingInt(@intCast(entry))));
                s.hook = null;
                if (m.broken) |b| {
                    stats.aborted += 1;
                    if (stats.aborted <= 5) std.debug.print("join-root mixed: {s}: invocation stopped: {s}\n", .{ name, b });
                }
            } else stats.aborted += 1;
            // The next invocation's entry changes are relative to the original's final
            // image: rebuild it from the recording, whatever the run did.
            rebuild(raw, calls.items, final_off, s.test_img);
        }
    }
    std.debug.print("join-root mixed: {d} invocations of main before the loop, {d} not run to the end\n", .{ stats.invocations, stats.aborted });
    var bad: u32 = 0;
    for (std.enums.values(rp.Callee)) |cal| {
        const i = @backingInt(cal);
        if (stats.run[i] == 0 and stats.answered[i] == 0) continue;
        std.debug.print("join-root mixed: {s}: {d} run, {d} answered from the recording; AX differs {d}; a unit's byte differs {d}", .{ @tagName(cal), stats.run[i], stats.answered[i], stats.ax_differs[i], stats.held_differs[i] });
        if (stats.first_held[i]) |a| std.debug.print(" (first DG:{X:0>4})", .{a});
        std.debug.print("; other bytes differ {d}\n", .{stats.other_differs[i]});
        // The result of every real callee is the original's but book_probe's with the
        // M-Chess book on (book.zst: the book is not bound, the probe fails the search).
        if (stats.ax_differs[i] != 0 and cal != .book_probe) bad += 1;
        // Bytes a unit holds that a callee writes and its binding does not: only these
        // (clock, display and the tablebase probe's file name and counts, and the book).
        // add_control_time (from 05FD and 061D: tc1in1-typed.zst, preset1-monitor61-m.zst)
        // redraws the side's clock through 4793:34EA, which sets the displayed time DG:8DD2,
        // the ticks to its next second DG:58 + side (12h) and DG:AB1C + side (5Bh); the port
        // leaves the display out (src/timebudget.zig, `addControlTime`).
        const allowed = switch (cal) {
            .screen_8536, .reset_move_time_used, .book_probe, .book_exit_display_2, .hash_clear, .tb_probe, .show_score, .add_control_time => true,
            else => false,
        };
        if (stats.held_differs[i] != 0 and !allowed) bad += 1;
    }
    try std.testing.expectEqual(@as(u32, 0), stats.aborted);
    try std.testing.expectEqual(@as(u32, 0), bad);
    try std.testing.expectEqual(@as(u32, 5), stats.ax_differs[@backingInt(rp.Callee.book_probe)]);
}

/// The original's image at the end of an invocation: every call's changes and the final
/// ones applied in order on top of what the run left (the changes are absolute values, so
/// every byte the recording names ends as the original left it).
fn rebuild(raw: []const u8, calls: []const Call, final_off: usize, img: []u8) void {
    for (calls) |call| {
        var c: Cursor = .{ .d = raw, .i = call.before };
        c.changes(img);
        c.changes(img);
    }
    var f: Cursor = .{ .d = raw, .i = final_off };
    f.changes(img);
}
