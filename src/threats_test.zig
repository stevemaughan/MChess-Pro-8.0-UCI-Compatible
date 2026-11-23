//! Differential tests of src/attackers.zig (4793:41B6, 4793:4CEC) and src/threats.zig
//! (0EF8:A026, 0EF8:CD20) against calls recorded from the running original
//! (tests/golden/evalthreats/*.zst, made by tools/port/gen_evalthreats_vectors.py, whose
//! docstring defines the format).
//!
//! Each attacker call is run on the recorded DGROUP image and registers; AX, the
//! registers the routine preserves (BX, CX, DX, SI, DI) and every byte of DGROUP after the
//! call are compared with the original's. Each threat call runs the whole chain in Zig
//! (the attacker routines here, the exchange evaluators in src/see.zig); its far calls
//! (target, site, square, value and AX after) are compared in order, then the checkpoints
//! where the vectors hold them (SI, DI, the nine frame words and the flag byte at every
//! label passed), then AX and every byte of DGROUP. Not compared, as in the model's
//! harness: the 2 KB below the caller's SP and the bytes the interrupts write.

const std = @import("std");
const lifted = @import("lifted_machine.zig");
const threats = @import("threats.zig");
const attackers = @import("attackers.zig");
const pos = @import("position.zig");
const see = @import("see.zig");
const dg = @import("original.zig").dgroup;

const Machine = lifted.Machine;
const Image = [0x10000]u8;

/// tools/research/evalthreats/check.py INTERRUPT_BYTES.
const irq_bytes = [_]u16{ 0x0058, 0x0059, 0x2A68, 0x2A69, 0xAB1C, 0xAB1D, 0x75B6, 0x3682, 0x8DDC, 0x9EB2, 0x367C, 0x8DD6, 0x8DD4 };
const slack = 0x800;

const Cursor = struct {
    d: []const u8,
    i: usize = 0,

    fn byte(c: *Cursor) u8 {
        const v = c.d[c.i];
        c.i += 1;
        return v;
    }
    fn word(c: *Cursor) u16 {
        const v = std.mem.readInt(u16, c.d[c.i..][0..2], .little);
        c.i += 2;
        return v;
    }
    fn take(c: *Cursor, n: usize) []const u8 {
        const v = c.d[c.i..][0..n];
        c.i += n;
        return v;
    }
    fn varint(c: *Cursor) usize {
        var n: usize = 0;
        var shift: std.math.Log2Int(usize) = 0;
        while (true) {
            const b = c.byte();
            n |= @as(usize, b & 0x7F) << shift;
            if (b & 0x80 == 0) return n;
            shift += 7;
        }
    }
    fn skipDelta(c: *Cursor) void {
        for (0..c.varint()) |_| {
            _ = c.varint();
            _ = c.byte();
        }
    }
    fn delta(c: *Cursor, img: *Image) void {
        const n = c.varint();
        var prev: isize = -1;
        for (0..n) |_| {
            const off: usize = @intCast(prev + 1 + @as(isize, @intCast(c.varint())));
            img[off] ^= c.byte();
            prev = @intCast(off);
        }
    }
};

fn readVectors(gpa: std.mem.Allocator, name: []const u8) ![]u8 {
    var path_buf: [256]u8 = undefined;
    const dir = @import("build_options").golden_dir;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/evalthreats/{s}", .{ dir, name });
    const compressed = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, gpa, .limited(64 << 20));
    defer gpa.free(compressed);
    var in: std.Io.Reader = .fixed(compressed);
    const window = try gpa.alloc(u8, std.compress.zstd.default_window_len + std.compress.zstd.block_size_max);
    defer gpa.free(window);
    var zd = std.compress.zstd.Decompress.init(&in, window, .{});
    return zd.reader.allocRemaining(gpa, .limited(512 << 20));
}

const names = [_][]const u8{ "", "attackers_41B6", "attackers_4CEC", "eval_threats_white A026", "eval_threats_black CD20" };
const far_names = [_][]const u8{ "SEE_W 2B9F:C32A", "SEE_B 2B9F:CAC2", "ATT 4793:41B6", "ATT 4793:4CEC" };

const Counts = struct {
    by_tag: [5]usize = @splat(0),
    far_calls: usize = 0,
    marks: usize = 0,
    calls_with_marks: usize = 0,
    /// Attacker calls replayed again through `attackersOnPosition`.
    on_position: usize = 0,
};

fn fail(name: []const u8, index: usize, tag: u8, regs: [8]u16, comptime fmt: []const u8, args: anytype) error{MismatchWithOriginal} {
    std.debug.print("\n{s}: record {d} ({s}) differs; entry SP {X:0>4}, args [sp+4..] ", .{ name, index, names[tag], regs[7] });
    std.debug.print(fmt ++ "\n", args);
    return error.MismatchWithOriginal;
}

/// The first byte of DGROUP that differs outside the bytes not compared.
fn compareImage(got: *const Image, want: *const Image, caller_sp: u16) ?usize {
    const lo: u16 = caller_sp -% slack;
    for (0..0x10000) |i| {
        if (got[i] == want[i]) continue;
        const a: u16 = @intCast(i);
        if (lo <= caller_sp) {
            if (a >= lo and a < caller_sp) continue;
        } else if (a >= lo or a < caller_sp) continue;
        if (std.mem.indexOfScalar(u16, &irq_bytes, a) != null) continue;
        return i;
    }
    return null;
}

const Hits = std.StaticBitSet(0x10000);

fn replay(gpa: std.mem.Allocator, name: []const u8, which: enum { attackers, all }, hits: ?*Hits) !Counts {
    const data = try readVectors(gpa, name);
    defer gpa.free(data);
    var c: Cursor = .{ .d = data };
    try std.testing.expectEqualSlices(u8, "MCET", c.take(4));
    try std.testing.expectEqual(@as(u16, 1), c.word());
    const img = try gpa.create(Image);
    defer gpa.destroy(img);
    const work = try gpa.create(Image);
    defer gpa.destroy(work);
    const want = try gpa.create(Image);
    defer gpa.destroy(want);
    const untraced = try gpa.create(Image);
    defer gpa.destroy(untraced);
    const trace = try gpa.create(lifted.Trace);
    defer gpa.destroy(trace);
    const aimg = try gpa.create(lifted.AttackerImage);
    defer gpa.destroy(aimg);
    aimg.init();
    img.* = @splat(0);
    var n: Counts = .{};
    var index: usize = 0;
    while (true) : (index += 1) {
        const tag = c.byte();
        if (tag == 0) break;
        c.delta(img);
        var regs: [8]u16 = undefined;
        for (&regs) |*r| r.* = c.word();
        work.* = img.*;
        var m: Machine = .{ .mem = work, .ax = regs[0], .bx = regs[1], .cx = regs[2], .dx = regs[3], .si = regs[4], .di = regs[5], .bp = regs[6], .sp = regs[7] };
        switch (tag) {
            1, 2 => {
                const ax = c.word();
                want.* = img.*;
                c.delta(want);
                if (tag == 1) attackers.run41B6(&m, attackers.entry_41b6) else attackers.run4CEC(&m, attackers.entry_4cec);
                if (m.ax != ax) return fail(name, index, tag, regs, "AX: want {X:0>4}, got {X:0>4}", .{ ax, m.ax });
                const kept = [5]u16{ m.bx, m.cx, m.dx, m.si, m.di };
                if (!std.mem.eql(u16, &kept, regs[1..6])) return fail(name, index, tag, regs, "BX CX DX SI DI not preserved: {any}", .{kept});
                if (compareImage(work, want, regs[7] +% 4)) |off|
                    return fail(name, index, tag, regs, "DG:{X:0>4}: want {X:0>2}, got {X:0>2}", .{ off, want[off], work[off] });
                // the same call through `attackersOnPosition`: the position and the work areas
                // taken from the image, everything else from the executable
                if (which == .attackers) {
                    var p: pos.Position = .{};
                    @memcpy(&p.board, img[0x9EF6..][0..120]);
                    @memcpy(&p.piece_list, img[0xA03A..][0..32]);
                    @memcpy(&p.pawn_attacks[0], img[0xA51C..][0..120]);
                    @memcpy(&p.pawn_attacks[1], img[0x37DA..][0..120]);
                    @memcpy(&p.king_rays[0], img[0xA09E..][0..120]);
                    @memcpy(&p.king_rays[1], img[0xA164..][0..120]);
                    var s: see.Scratch = .{};
                    @memcpy(&s.attackers, img[0x9FEC..][0..116]);
                    @memcpy(&s.defenders, img[0xA060..][0..32]);
                    @memcpy(&s.gain, img[0x70E5..][0..11]);
                    @memcpy(&s.net, img[0xB4E6..][0..11]);
                    const sq = std.mem.readInt(u16, img[regs[7] +% 4 ..][0..2], .little);
                    const v = std.mem.readInt(u16, img[regs[7] +% 6 ..][0..2], .little);
                    const got = lifted.attackersOnPosition(aimg, &p, &s, if (tag == 1) .white else .black, @truncate(sq), v);
                    if (got != ax) return fail(name, index, tag, regs, "attackersOnPosition({d}, {d}): AX want {X:0>4}, got {X:0>4}", .{ sq, v, ax, got });
                    const areas = [_]struct { a: u16, b: []const u8 }{ .{ .a = 0x9FEC, .b = &s.attackers }, .{ .a = 0xA060, .b = &s.defenders }, .{ .a = 0x70E5, .b = &s.gain }, .{ .a = 0xB4E6, .b = &s.net } };
                    for (areas) |r| for (r.b, 0..) |byte, k| if (byte != want[r.a + k])
                        return fail(name, index, tag, regs, "attackersOnPosition({d}, {d}): DG:{X:0>4}: want {X:0>2}, got {X:0>2}", .{ sq, v, r.a + k, want[r.a + k], byte });
                    n.on_position += 1;
                }
                n.by_tag[tag] += 1;
            },
            3, 4 => {
                const flagp = c.word();
                const ncalls = c.varint();
                const calls = c.take(ncalls * 9);
                const ax = c.word();
                want.* = img.*;
                c.delta(want);
                const has_marks = c.byte() != 0;
                var nmarks: usize = 0;
                var marks: []const u8 = &.{};
                if (has_marks) {
                    nmarks = c.varint();
                    marks = c.take(nmarks * 25);
                }
                if (which == .attackers) continue;
                trace.* = .{ .record_marks = has_marks, .flagp = flagp, .hits = hits };
                m.trace = trace;
                if (tag == 3) threats.runA026(&m, threats.entry_a026) else threats.runCD20(&m, threats.entry_cd20);
                // far calls, in order
                for (0..@min(ncalls, trace.ncalls)) |k| {
                    const e = calls[k * 9 ..][0..9];
                    const w: lifted.CallRecord = .{ .target = @fromBackingInt(@intCast(e[0])), .site = std.mem.readInt(u16, e[1..3], .little), .sq = std.mem.readInt(u16, e[3..5], .little), .v = std.mem.readInt(u16, e[5..7], .little), .ax = std.mem.readInt(u16, e[7..9], .little) };
                    const g = trace.calls[k];
                    if (w.target != g.target or w.site != g.site or w.sq != g.sq or w.v != g.v)
                        return fail(name, index, tag, regs, "far call {d}: want {s}({d}, {d}) at {X:0>4}, got {s}({d}, {d}) at {X:0>4}", .{ k, far_names[@backingInt(w.target)], w.sq, w.v, w.site, far_names[@backingInt(g.target)], g.sq, g.v, g.site });
                    if (w.ax != g.ax)
                        return fail(name, index, tag, regs, "far call {d} {s}({d}, {d}) at {X:0>4}: AX want {X:0>4}, got {X:0>4}", .{ k, far_names[@backingInt(w.target)], w.sq, w.v, w.site, w.ax, g.ax });
                }
                if (ncalls != trace.ncalls) return fail(name, index, tag, regs, "far calls: want {d}, got {d}", .{ ncalls, trace.ncalls });
                // checkpoints
                if (has_marks) {
                    for (0..@min(nmarks, trace.nmarks, trace.marks.len)) |k| {
                        const e = marks[k * 25 ..][0..25];
                        const g = trace.marks[k];
                        var wf: [12]u16 = undefined;
                        for (&wf, 0..) |*x, j| x.* = std.mem.readInt(u16, e[2 * j ..][0..2], .little);
                        const flag = e[24];
                        if (wf[0] != g.label) return fail(name, index, tag, regs, "path: checkpoint {d}: want label {X:0>4}, got {X:0>4}", .{ k, wf[0], g.label });
                        var gf: [12]u16 = undefined;
                        gf[0] = g.label;
                        gf[1] = g.si;
                        gf[2] = g.di;
                        @memcpy(gf[3..], &g.frame);
                        const fields = [_][]const u8{ "label", "SI", "DI", "[bp-2]", "[bp-4]", "[bp-6]", "[bp-8]", "[bp-0Ah]", "[bp-0Ch]", "[bp-0Eh]", "[bp-10h]", "[bp-12h]" };
                        for (1..12) |j| if (wf[j] != gf[j])
                            return fail(name, index, tag, regs, "checkpoint {d} at {X:0>4}: {s} want {X:0>4}, got {X:0>4}", .{ k, g.label, fields[j], wf[j], gf[j] });
                        if (flag != g.flag) return fail(name, index, tag, regs, "checkpoint {d} at {X:0>4}: flag byte want {d}, got {d}", .{ k, g.label, flag, g.flag });
                    }
                    if (nmarks != trace.nmarks) return fail(name, index, tag, regs, "checkpoints: want {d}, got {d}", .{ nmarks, trace.nmarks });
                    n.marks += nmarks;
                    n.calls_with_marks += 1;
                }
                if (m.ax != ax) return fail(name, index, tag, regs, "AX: want {d}, got {d}", .{ @as(i16, @bitCast(ax)), @as(i16, @bitCast(m.ax)) });
                if (compareImage(work, want, regs[7])) |off|
                    return fail(name, index, tag, regs, "DG:{X:0>4}: want {X:0>2}, got {X:0>2}", .{ off, want[off], work[off] });
                // the same call with no trace attached, as the engine makes it: the same AX,
                // registers and every byte of DGROUP, the stack included
                untraced.* = img.*;
                var u: Machine = .{ .mem = untraced, .ax = regs[0], .bx = regs[1], .cx = regs[2], .dx = regs[3], .si = regs[4], .di = regs[5], .bp = regs[6], .sp = regs[7] };
                if (tag == 3) threats.runA026(&u, threats.entry_a026) else threats.runCD20(&u, threats.entry_cd20);
                const ru = [8]u16{ u.ax, u.bx, u.cx, u.dx, u.si, u.di, u.bp, u.sp };
                const rt = [8]u16{ m.ax, m.bx, m.cx, m.dx, m.si, m.di, m.bp, m.sp };
                if (!std.mem.eql(u16, &ru, &rt)) return fail(name, index, tag, regs, "untraced: registers {any}, traced {any}", .{ ru, rt });
                if (!std.mem.eql(u8, untraced, work)) {
                    const off = std.mem.indexOfDiff(u8, untraced, work).?;
                    return fail(name, index, tag, regs, "untraced: DG:{X:0>4} {X:0>2}, traced {X:0>2}", .{ off, untraced[off], work[off] });
                }
                n.far_calls += ncalls;
                n.by_tag[tag] += 1;
            },
            else => return error.BadVectorFile,
        }
    }
    return n;
}

const files = [_][]const u8{ "A.zst", "B.zst", "C.zst", "D.zst", "E.zst" };

test "attacker routines 4793:41B6 and 4CEC equal the original on every recorded call" {
    const gpa = std.testing.allocator;
    var total: Counts = .{};
    for (files) |f| {
        const n = try replay(gpa, f, .attackers, null);
        std.debug.print("evalthreats vectors {s}: attackers 41B6 {d}, 4CEC {d} calls replayed, all equal ({d} again through attackersOnPosition)\n", .{ f, n.by_tag[1], n.by_tag[2], n.on_position });
        for (1..3) |t| total.by_tag[t] += n.by_tag[t];
    }
    std.debug.print("evalthreats vectors total: attackers 41B6 {d}, 4CEC {d}\n", .{ total.by_tag[1], total.by_tag[2] });
    try std.testing.expect(total.by_tag[1] > 0 and total.by_tag[2] > 0);
}

test "threat evaluators 0EF8:A026 and CD20 equal the original on every recorded call" {
    const gpa = std.testing.allocator;
    var total: Counts = .{};
    const hits = try gpa.create(Hits);
    defer gpa.destroy(hits);
    hits.* = .empty;
    for (files) |f| {
        const n = try replay(gpa, f, .all, hits);
        std.debug.print("evalthreats vectors {s}: A026 {d}, CD20 {d} calls ({d} far calls, {d} checkpoints in {d} calls), 41B6 {d}, 4CEC {d}; all equal\n", .{ f, n.by_tag[3], n.by_tag[4], n.far_calls, n.marks, n.calls_with_marks, n.by_tag[1], n.by_tag[2] });
        for (0..5) |t| total.by_tag[t] += n.by_tag[t];
        total.far_calls += n.far_calls;
        total.marks += n.marks;
    }
    std.debug.print("evalthreats vectors total: A026 {d}, CD20 {d} ({d} far calls, {d} checkpoints)\n", .{ total.by_tag[3], total.by_tag[4], total.far_calls, total.marks });
    var reached: [2]usize = .{ 0, 0 };
    for (threats.labels_a026) |l| reached[0] += @intFromBool(hits.isSet(l));
    for (threats.labels_cd20) |l| reached[1] += @intFromBool(hits.isSet(l));
    std.debug.print("  labels reached: A026 {d} of {d}, CD20 {d} of {d}\n", .{ reached[0], threats.labels_a026.len, reached[1], threats.labels_cd20.len });
    try std.testing.expect(total.by_tag[3] > 0 and total.by_tag[4] > 0);
}

/// A conditional jump read from the flags, as the 8086 does.
fn flagCond(m: *const Machine, c: Machine.Cond) bool {
    return switch (c) {
        .e => m.zf,
        .ne => !m.zf,
        .l => m.sf != m.of,
        .ge => m.sf == m.of,
        .le => m.zf or m.sf != m.of,
        .g => !m.zf and m.sf == m.of,
        .b => m.cf,
        .ae => !m.cf,
        .be => m.cf or m.zf,
        .a => !m.cf and !m.zf,
        .s => m.sf,
        .ns => !m.sf,
    };
}

fn checkConds(comptime T: type, m: *Machine, a: T, b: T) !void {
    inline for (comptime std.enums.values(Machine.Cond)) |c| {
        m.cmp(T, a, b);
        try std.testing.expectEqual(flagCond(m, c), Machine.subCond(T, a, b, c));
        _ = m.sub(T, a, b);
        try std.testing.expectEqual(flagCond(m, c), Machine.subCond(T, a, b, c));
        inline for (.{ "test", "and", "or", "xor" }) |op| {
            const r: T = if (comptime std.mem.eql(u8, op, "test")) a & b else @field(Machine, op)(m, T, a, b);
            if (comptime std.mem.eql(u8, op, "test")) m.@"test"(T, a, b);
            try std.testing.expectEqual(flagCond(m, c), Machine.logicCond(T, r, c));
        }
    }
}

const reference = @import("threats_reference.zig");

/// Two images equal, compared 64 bytes at a time.
fn sameImage(a: *const Image, b: *const Image) bool {
    const V = @Vector(64, u8);
    var i: usize = 0;
    while (i < a.len) : (i += 64) {
        const x: V = a[i..][0..64].*;
        const y: V = b[i..][0..64].*;
        if (@reduce(.Or, x != y)) return false;
    }
    return true;
}

/// Changes a recorded entry image into a nearby input the recordings do not hold: a few
/// inner board squares, piece-list entries and pawn-attack counts, and the call's
/// arguments. The border, the king ray maps and every pointer are left alone, so the
/// routines' scans still end.
fn mutate(rng: std.Random, img: *Image, tag: u8, sp: u16) void {
    const codes = [_]u8{ 0, 0, 0, 1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13 };
    const inner = struct {
        fn sq(r: std.Random) u16 {
            return 21 + 10 * @as(u16, r.uintLessThan(u8, 8)) + r.uintLessThan(u8, 8);
        }
    };
    for (0..rng.uintLessThan(usize, 7)) |_| img[0x9EF6 + inner.sq(rng)] = codes[rng.uintLessThan(usize, codes.len)];
    if (rng.uintLessThan(u8, 4) == 0) {
        const s = inner.sq(rng);
        img[0xA03A + rng.uintLessThan(u16, 32)] = @truncate(if (rng.boolean()) s else s + 0x63);
    }
    if (rng.uintLessThan(u8, 3) == 0) for (0..rng.uintLessThan(usize, 4)) |_| {
        img[(if (rng.boolean()) @as(u16, 0xA51C) else 0x37DA) + inner.sq(rng)] = rng.uintLessThan(u8, 3);
    };
    const values = [_]u16{ 1, 3, 9, 15, 27, 0, 0x30, 0xFF, 0x80 };
    switch (tag) {
        1, 2 => {
            if (rng.boolean()) std.mem.writeInt(u16, img[sp +% 4 ..][0..2], inner.sq(rng), .little);
            if (rng.boolean()) std.mem.writeInt(u16, img[sp +% 6 ..][0..2], values[rng.uintLessThan(usize, values.len)], .little);
        },
        else => {
            const plies = [_]u16{ 0, 1, 2, 3, 4, 5, 6, 8, 12, 100 };
            if (rng.boolean()) std.mem.writeInt(u16, img[sp +% 4 ..][0..2], plies[rng.uintLessThan(usize, plies.len)], .little);
            if (rng.boolean()) std.mem.writeInt(u16, img[sp +% 6 ..][0..2], rng.uintLessThan(u16, 5), .little);
        },
    }
}

test "the lifted routines equal their pre-speed-pass reference on mutated recorded inputs" {
    // src/threats_reference.zig holds the routines as generated before the speed pass. Each
    // recorded call is run again on many changed copies of its entry image, by both, with no
    // trace (the engine's path); AX, every register and every byte of DGROUP, the stack
    // included, must be equal. The reference threat routines' far calls reach the current
    // attacker routines, which the first half of the test compares on their own.
    const gpa = std.testing.allocator;
    const per_call: usize = if (@import("builtin").mode == .debug) 1 else 40;
    var rng_state = std.Random.DefaultPrng.init(0x41B6_4CEC_A026_CD20);
    const rng = rng_state.random();
    const img = try gpa.create(Image);
    defer gpa.destroy(img);
    const got = try gpa.create(Image);
    defer gpa.destroy(got);
    const ref = try gpa.create(Image);
    defer gpa.destroy(ref);
    const trace = try gpa.create(lifted.Trace);
    defer gpa.destroy(trace);
    const hits = try gpa.create(Hits);
    defer gpa.destroy(hits);
    hits.* = .empty;
    var compared: [5]usize = @splat(0);
    for (files) |name| {
        const data = try readVectors(gpa, name);
        defer gpa.free(data);
        var c: Cursor = .{ .d = data[6..] };
        img.* = @splat(0);
        while (true) {
            const tag = c.byte();
            if (tag == 0) break;
            c.delta(img);
            var regs: [8]u16 = undefined;
            for (&regs) |*r| r.* = c.word();
            switch (tag) {
                1, 2 => {
                    _ = c.word();
                    c.skipDelta();
                },
                3, 4 => {
                    _ = c.word();
                    _ = c.take(c.varint() * 9);
                    _ = c.word();
                    c.skipDelta();
                    if (c.byte() != 0) _ = c.take(c.varint() * 25);
                },
                else => return error.BadVectorFile,
            }
            for (0..per_call) |k| {
                @memcpy(got, img);
                if (k > 0) mutate(rng, got, tag, regs[7]);
                @memcpy(ref, got);
                var mg: Machine = .{ .mem = got, .ax = regs[0], .bx = regs[1], .cx = regs[2], .dx = regs[3], .si = regs[4], .di = regs[5], .bp = regs[6], .sp = regs[7] };
                // every other run notes the labels it passes (coverage); the rest run untraced
                trace.* = .{ .hits = hits };
                if (k % 2 == 1) mg.trace = trace;
                var mr: Machine = .{ .mem = ref, .ax = regs[0], .bx = regs[1], .cx = regs[2], .dx = regs[3], .si = regs[4], .di = regs[5], .bp = regs[6], .sp = regs[7] };
                switch (tag) {
                    1 => {
                        attackers.run41B6(&mg, attackers.entry_41b6);
                        reference.run41B6(&mr, reference.entry_41b6);
                    },
                    2 => {
                        attackers.run4CEC(&mg, attackers.entry_4cec);
                        reference.run4CEC(&mr, reference.entry_4cec);
                    },
                    3 => {
                        threats.runA026(&mg, threats.entry_a026);
                        reference.runA026(&mr, reference.entry_a026);
                    },
                    else => {
                        threats.runCD20(&mg, threats.entry_cd20);
                        reference.runCD20(&mr, reference.entry_cd20);
                    },
                }
                const rg = [8]u16{ mg.ax, mg.bx, mg.cx, mg.dx, mg.si, mg.di, mg.bp, mg.sp };
                const rr = [8]u16{ mr.ax, mr.bx, mr.cx, mr.dx, mr.si, mr.di, mr.bp, mr.sp };
                if (!std.mem.eql(u16, &rg, &rr)) {
                    std.debug.print("\n{s} ({s}), mutation {d}: registers {any}, reference {any}\n", .{ name, names[tag], k, rg, rr });
                    return error.MismatchWithReference;
                }
                if (!sameImage(got, ref)) {
                    const off = std.mem.indexOfDiff(u8, got, ref).?;
                    std.debug.print("\n{s} ({s}), mutation {d}: DG:{X:0>4} {X:0>2}, reference {X:0>2}\n", .{ name, names[tag], k, off, got[off], ref[off] });
                    return error.MismatchWithReference;
                }
                compared[tag] += 1;
            }
        }
    }
    var reached: [2]usize = .{ 0, 0 };
    for (threats.labels_a026) |l| reached[0] += @intFromBool(hits.isSet(l));
    for (threats.labels_cd20) |l| reached[1] += @intFromBool(hits.isSet(l));
    std.debug.print("lifted vs reference: 41B6 {d}, 4CEC {d}, A026 {d}, CD20 {d} calls, all equal; labels reached: A026 {d} of {d}, CD20 {d} of {d}\n", .{ compared[1], compared[2], compared[3], compared[4], reached[0], threats.labels_a026.len, reached[1], threats.labels_cd20.len });
}

test "the fused compare-and-jump conditions equal the jumps read from the flags" {
    var mem: Image = undefined;
    var m: Machine = .{ .mem = &mem };
    for (0..256) |a| for (0..256) |b| try checkConds(u8, &m, @intCast(a), @intCast(b));
    var rng = std.Random.DefaultPrng.init(0x5EED_A026);
    const edge = [_]u16{ 0, 1, 0x7F, 0x80, 0xFF, 0x100, 0x7FFE, 0x7FFF, 0x8000, 0x8001, 0xFFFE, 0xFFFF };
    for (edge) |a| for (edge) |b| try checkConds(u16, &m, a, b);
    for (0..200_000) |_| try checkConds(u16, &m, rng.random().int(u16), rng.random().int(u16));
}

test "the constant tables the lifted code reads (DG:0378-03FF, the result tables and what follows) are the executable's" {
    // docs/arch/54-evaluation-threats.md 7.1: the result table at DG:0388 is indexed without
    // a bound; the bytes past it are constant data, and the replay images hold the same.
    const gpa = std.testing.allocator;
    const data = try readVectors(gpa, files[0]);
    defer gpa.free(data);
    var c: Cursor = .{ .d = data[6..] };
    _ = c.byte();
    const img = try gpa.create(Image);
    defer gpa.destroy(img);
    img.* = @splat(0);
    c.delta(img);
    const exe = dg(0x0378, 0x88);
    try std.testing.expectEqualSlices(u8, &exe, img[0x0378..0x0400]);
}

// ---------------------------------------------------------------------------
// Benchmarks (src/bench.zig): -Dbench=true -Dtest-filter="bench: evalthreats"
// ---------------------------------------------------------------------------

const bench = @import("bench.zig");

/// One recorded call, decoded for timing: the registers at entry, the input delta from
/// the previous record's image, and the bytes the call changes (put back after it).
const BenchCall = struct { tag: u8, regs: [8]u16, d0: u32, d1: u32, u0: u32, u1: u32 };
const Patch = struct { off: u16, b: u8 };
const SeeCall = struct { call: u32, side: u8, sq: u16, v: u16 };

const BenchFile = struct {
    calls: std.ArrayList(BenchCall) = .empty,
    /// Input deltas (XOR) and undo lists (the byte before the call).
    delta: std.ArrayList(Patch) = .empty,
    undo: std.ArrayList(Patch) = .empty,
    /// The exchange-evaluator far calls the threat calls make.
    see_calls: std.ArrayList(SeeCall) = .empty,

    fn deinit(f: *BenchFile, gpa: std.mem.Allocator) void {
        f.calls.deinit(gpa);
        f.delta.deinit(gpa);
        f.undo.deinit(gpa);
        f.see_calls.deinit(gpa);
    }
};

fn runCall(m: *Machine, tag: u8) void {
    switch (tag) {
        1 => attackers.run41B6(m, attackers.entry_41b6),
        2 => attackers.run4CEC(m, attackers.entry_4cec),
        3 => threats.runA026(m, threats.entry_a026),
        else => threats.runCD20(m, threats.entry_cd20),
    }
}

fn loadBench(gpa: std.mem.Allocator, name: []const u8, img: *Image, work: *Image, scratch: *Image) !BenchFile {
    const data = try readVectors(gpa, name);
    defer gpa.free(data);
    var c: Cursor = .{ .d = data[6..] };
    var f: BenchFile = .{};
    img.* = @splat(0);
    while (true) {
        const tag = c.byte();
        if (tag == 0) break;
        const d0: u32 = @intCast(f.delta.items.len);
        {
            const n = c.varint();
            var prev: isize = -1;
            for (0..n) |_| {
                const off: usize = @intCast(prev + 1 + @as(isize, @intCast(c.varint())));
                const x = c.byte();
                img[off] ^= x;
                try f.delta.append(gpa, .{ .off = @intCast(off), .b = x });
                prev = @intCast(off);
            }
        }
        var regs: [8]u16 = undefined;
        for (&regs) |*r| r.* = c.word();
        var call: BenchCall = .{ .tag = tag, .regs = regs, .d0 = d0, .d1 = @intCast(f.delta.items.len), .u0 = 0, .u1 = 0 };
        var ncalls: usize = 0;
        var calls: []const u8 = &.{};
        switch (tag) {
            1, 2 => {
                _ = c.word();
                scratch.* = img.*;
                c.delta(scratch);
            },
            3, 4 => {
                _ = c.word();
                ncalls = c.varint();
                calls = c.take(ncalls * 9);
                _ = c.word();
                scratch.* = img.*;
                c.delta(scratch);
                if (c.byte() != 0) _ = c.take(c.varint() * 25);
            },
            else => return error.BadVectorFile,
        }
        for (0..ncalls) |k| {
            const e = calls[k * 9 ..][0..9];
            if (e[0] <= 1) try f.see_calls.append(gpa, .{ .call = @intCast(f.calls.items.len), .side = e[0], .sq = std.mem.readInt(u16, e[3..5], .little), .v = std.mem.readInt(u16, e[5..7], .little) });
        }
        // the bytes the call changes
        work.* = img.*;
        var m: Machine = .{ .mem = work, .ax = regs[0], .bx = regs[1], .cx = regs[2], .dx = regs[3], .si = regs[4], .di = regs[5], .bp = regs[6], .sp = regs[7] };
        runCall(&m, tag);
        call.u0 = @intCast(f.undo.items.len);
        for (0..0x10000) |i| if (work[i] != img[i]) try f.undo.append(gpa, .{ .off = @intCast(i), .b = img[i] });
        call.u1 = @intCast(f.undo.items.len);
        try f.calls.append(gpa, call);
    }
    return f;
}

/// One pass over a file: every record's input delta is applied; the calls with tag
/// `tag` are run (when `run`) and their changes put back.
fn benchPass(f: *const BenchFile, img: *Image, tag: u8, comptime run: bool) usize {
    img.* = @splat(0);
    var n: usize = 0;
    for (f.calls.items) |call| {
        for (f.delta.items[call.d0..call.d1]) |p| img[p.off] ^= p.b;
        if (call.tag != tag) continue;
        if (run) {
            const r = call.regs;
            var m: Machine = .{ .mem = img, .ax = r[0], .bx = r[1], .cx = r[2], .dx = r[3], .si = r[4], .di = r[5], .bp = r[6], .sp = r[7] };
            runCall(&m, tag);
            bench.keep(m.ax);
        }
        for (f.undo.items[call.u0..call.u1]) |p| img[p.off] = p.b;
        n += 1;
    }
    return n;
}

test "bench: evalthreats: the four lifted routines on every recorded call" {
    if (!bench.enabled) return;
    const gpa = std.testing.allocator;
    const img = try gpa.create(Image);
    defer gpa.destroy(img);
    const work = try gpa.create(Image);
    defer gpa.destroy(work);
    const scratch = try gpa.create(Image);
    defer gpa.destroy(scratch);
    var bf: [files.len]BenchFile = undefined;
    for (files, 0..) |name, i| bf[i] = try loadBench(gpa, name, img, work, scratch);
    defer for (&bf) |*f| f.deinit(gpa);
    const passes = 40;
    const labels = [_][]const u8{ "", "evalthreats: 4793:41B6 attackers (White)", "evalthreats: 4793:4CEC attackers (Black)", "evalthreats: 0EF8:A026 eval_threats_white, far calls included", "evalthreats: 0EF8:CD20 eval_threats_black, far calls included" };
    for (1..5) |t| {
        const tag: u8 = @intCast(t);
        var best: bench.Best = .{};
        var over: bench.Best = .{};
        var calls: usize = 0;
        for (0..passes) |_| {
            var t0 = bench.now();
            calls = 0;
            for (&bf) |*f| calls += benchPass(f, img, tag, false);
            over.pass(t0);
            t0 = bench.now();
            for (&bf) |*f| _ = benchPass(f, img, tag, true);
            best.pass(t0);
        }
        best.report(labels[t], calls, passes, over.ns);
    }
    // The exchange evaluators through `seeOnImage`, as the threat routines call them, on
    // the image before the threat call: an estimate of what the far calls cost.
    var best: bench.Best = .{};
    var n: usize = 0;
    for (0..passes) |_| {
        n = 0;
        var total: i96 = 0;
        for (&bf) |*f| {
            img.* = @splat(0);
            var k: usize = 0;
            for (f.calls.items, 0..) |call, ci| {
                for (f.delta.items[call.d0..call.d1]) |p| img[p.off] ^= p.b;
                const k0 = k;
                while (k < f.see_calls.items.len and f.see_calls.items[k].call == ci) k += 1;
                if (k == k0) continue;
                work.* = img.*;
                const t0 = bench.now();
                for (f.see_calls.items[k0..k]) |s| bench.keep(lifted.seeOnImage(work, if (s.side == 0) .white else .black, s.sq, s.v));
                total += bench.now() - t0;
                n += k - k0;
            }
        }
        if (total < best.ns) best.ns = total;
    }
    best.report("evalthreats: seeOnImage per far call (estimate, clock read per group)", n, passes, 0);

    // The hand-written exchange evaluator alone (src/see.zig `see`) on the same calls, the
    // positions built beforehand: a yardstick for what a hand rewrite of the attacker
    // routines, the same algorithm with pin tests, might cost.
    const SeeIn = struct { p: pos.Position, s: see.Scratch, side: pos.Side, sq: u8, v: u16 };
    var ins: std.ArrayList(SeeIn) = .empty;
    defer ins.deinit(gpa);
    for (&bf) |*f| {
        img.* = @splat(0);
        var k: usize = 0;
        for (f.calls.items, 0..) |call, ci| {
            for (f.delta.items[call.d0..call.d1]) |p| img[p.off] ^= p.b;
            while (k < f.see_calls.items.len and f.see_calls.items[k].call == ci) : (k += 1) {
                const sc = f.see_calls.items[k];
                var e: SeeIn = .{ .p = .{}, .s = .{}, .side = if (sc.side == 0) .white else .black, .sq = @truncate(sc.sq), .v = sc.v };
                @memcpy(&e.p.board, img[0x9EF6..][0..120]);
                @memcpy(&e.p.piece_list, img[0xA03A..][0..32]);
                @memcpy(&e.p.pawn_attacks[0], img[0xA51C..][0..120]);
                @memcpy(&e.p.pawn_attacks[1], img[0x37DA..][0..120]);
                @memcpy(&e.p.king_rays[0], img[0xA09E..][0..120]);
                @memcpy(&e.p.king_rays[1], img[0xA164..][0..120]);
                try ins.append(gpa, e);
            }
        }
    }
    var best_see: bench.Best = .{};
    var over_see: bench.Best = .{};
    for (0..passes) |_| {
        var t0 = bench.now();
        for (ins.items) |*e| {
            var s = e.s;
            bench.keep(&s);
        }
        over_see.pass(t0);
        t0 = bench.now();
        for (ins.items) |*e| {
            var s = e.s;
            bench.keep(see.see(&e.p, &s, e.side, e.sq, e.v));
        }
        best_see.pass(t0);
    }
    best_see.report("evalthreats: see.see alone on the same calls (yardstick)", ins.items.len, passes, over_see.ns);

    // The attacker routines through `attackersOnPosition` (as static_eval will call them),
    // on the recorded attacker calls.
    ins.clearRetainingCapacity();
    for (&bf) |*f| {
        img.* = @splat(0);
        for (f.calls.items) |call| {
            for (f.delta.items[call.d0..call.d1]) |p| img[p.off] ^= p.b;
            if (call.tag > 2) continue;
            const sp = call.regs[7];
            var e: SeeIn = .{ .p = .{}, .s = .{}, .side = if (call.tag == 1) .white else .black, .sq = img[sp +% 4], .v = std.mem.readInt(u16, img[sp +% 6 ..][0..2], .little) };
            @memcpy(&e.p.board, img[0x9EF6..][0..120]);
            @memcpy(&e.p.piece_list, img[0xA03A..][0..32]);
            @memcpy(&e.p.pawn_attacks[0], img[0xA51C..][0..120]);
            @memcpy(&e.p.pawn_attacks[1], img[0x37DA..][0..120]);
            @memcpy(&e.p.king_rays[0], img[0xA09E..][0..120]);
            @memcpy(&e.p.king_rays[1], img[0xA164..][0..120]);
            @memcpy(&e.s.attackers, img[0x9FEC..][0..116]);
            @memcpy(&e.s.defenders, img[0xA060..][0..32]);
            @memcpy(&e.s.gain, img[0x70E5..][0..11]);
            @memcpy(&e.s.net, img[0xB4E6..][0..11]);
            try ins.append(gpa, e);
        }
    }
    const aimg = try gpa.create(lifted.AttackerImage);
    defer gpa.destroy(aimg);
    aimg.init();
    // each call's input is first copied to one place, as the engine's position would be
    // in cache; the copy is timed in the overhead loop
    const hot = try gpa.create(SeeIn);
    defer gpa.destroy(hot);
    var best_aop: bench.Best = .{};
    var over_aop: bench.Best = .{};
    for (0..passes) |_| {
        var t0 = bench.now();
        for (ins.items) |*e| {
            hot.* = e.*;
            bench.keep(hot);
        }
        over_aop.pass(t0);
        t0 = bench.now();
        for (ins.items) |*e| {
            hot.* = e.*;
            bench.keep(lifted.attackersOnPosition(aimg, &hot.p, &hot.s, hot.side, hot.sq, hot.v));
        }
        best_aop.pass(t0);
    }
    best_aop.report("evalthreats: attackersOnPosition (41B6/4CEC with the copies in and out)", ins.items.len, passes, over_aop.ns);
}
