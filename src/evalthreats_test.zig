//! Tests of src/evalthreats.zig, the hand-written threat evaluators 0EF8:A026 and
//! 0EF8:CD20.
//!
//! 1. Replay: every threat call recorded from the original (tests/golden/evalthreats/,
//!    format in tools/port/gen_evalthreats_vectors.py) is run on the state read from its
//!    entry image; the result, the far calls (target, square, value and AX, in order)
//!    and every byte of DGROUP the original leaves behind are compared, outside the
//!    2 KB below the caller's SP and the interrupt bytes (as src/threats_test.zig).
//! 2. Differential: each recorded call is run again on many changed copies of its entry
//!    image (src/threats_test.zig `mutate`, a constant seed) by this port and by the
//!    machine-lifted routines of src/threats.zig, comparing the same things over the
//!    whole of DGROUP but the stack below the caller's SP. Besides those changes
//!    (`mutateMore`) the king and the enemy queen and rooks are put near each other,
//!    rooks and bishops are pinned on the king's rays, and the depth limits and material
//!    tests are varied, to reach the blocks the recordings do not. The kings' list
//!    entries are never made a captured piece's: a captured king is not a state the
//!    program reaches.
//!
//! 3. A benchmark against the lifted routines ("bench: evalthreats-hand").
//!
//! The far routines are bound to the same implementations in both: the exchange
//! evaluators to src/see.zig, the attacker routines to src/attackers.zig on a DGROUP
//! image.

const std = @import("std");
const builtin = @import("builtin");
const pos = @import("position.zig");
const seemod = @import("see.zig");
const lifted = @import("lifted_machine.zig");
const threats = @import("threats.zig");
const attackers = @import("attackers.zig");
const et = @import("evalthreats.zig");
const EvalVars = @import("evalvars.zig").EvalVars;

const Position = pos.Position;
const Side = pos.Side;
const Image = [0x10000]u8;
const Machine = lifted.Machine;

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

const files = [_][]const u8{ "A.zst", "B.zst", "C.zst", "D.zst", "E.zst" };

fn rw(img: *const Image, a: u16) u16 {
    return @as(u16, img[a]) | @as(u16, img[a +% 1]) << 8;
}

// ---------------------------------------------------------------------------
// The state of a call, read from and written back to a DGROUP image
// ---------------------------------------------------------------------------

const State = struct {
    p: Position = .{},
    v: EvalVars = .{},
    t: et.ThreatVars = .{},
    s: seemod.Scratch = .{},
    ply: u16 = 0,
    m: u16 = 0,
    flagp: u16 = 0,
    flag: u8 = 0,

    fn load(st: *State, img: *const Image, sp: u16) void {
        const p = &st.p;
        @memcpy(&p.board, img[0x9EF6..][0..120]);
        @memcpy(&p.piece_list, img[0xA03A..][0..32]);
        @memcpy(&p.pawn_attacks[0], img[0xA51C..][0..120]);
        @memcpy(&p.pawn_attacks[1], img[0x37DA..][0..120]);
        @memcpy(&p.king_rays[0], img[0xA09E..][0..120]);
        @memcpy(&p.king_rays[1], img[0xA164..][0..120]);
        @memcpy(&p.pawns_per_file[0], img[0xA8C8..][0..10]);
        @memcpy(&p.pawns_per_file[1], img[0x9EA8..][0..10]);
        p.piece_material = .{ rw(img, 0xAE38), rw(img, 0xAE3A) };
        p.piece_material_sum = rw(img, 0x378E);
        p.piece_count = .{ img[0x931A], img[0x931B] };
        p.king_file = .{ img[0xA22E], img[0xA22F] };
        st.v.weak_pawns = img[0x8EB6];
        st.v.passer_flags = img[0xA5F5];
        const t = &st.t;
        t.ply_limit1 = @bitCast(rw(img, 0xA272));
        t.ply_limit2 = @bitCast(rw(img, 0x9356));
        t.ply_limit3 = @bitCast(rw(img, 0xA5EC));
        t.mate_switch = img[0xA40E];
        t.iteration = @bitCast(img[0xA3F4]);
        t.promoted_queen_slot = .{ img[0xA38E], img[0xA38F] };
        @memcpy(&t.white_rays_after, img[0xA116..][0..78]);
        @memcpy(&t.black_rays_after, img[0xA1DC..][0..136]);
        @memcpy(&t.board_after, img[0x9F6E..][0..126]);
        @memcpy(&st.s.attackers, img[0x9FEC..][0..116]);
        @memcpy(&st.s.defenders, img[0xA060..][0..32]);
        @memcpy(&st.s.gain, img[0x70E5..][0..11]);
        @memcpy(&st.s.net, img[0xB4E6..][0..11]);
        st.ply = rw(img, sp +% 4);
        st.m = rw(img, sp +% 6);
        st.flagp = rw(img, sp +% 8);
        st.flag = img[st.flagp];
    }

    /// Writes back what the routine may change.
    fn store(st: *const State, img: *Image, sp: u16) void {
        @memcpy(img[0x9FEC..][0..116], &st.s.attackers);
        @memcpy(img[0xA060..][0..32], &st.s.defenders);
        @memcpy(img[0x70E5..][0..11], &st.s.gain);
        @memcpy(img[0xB4E6..][0..11], &st.s.net);
        @memcpy(img[0x9EF6..][0..120], &st.p.board);
        @memcpy(img[0xA03A..][0..32], &st.p.piece_list);
        img[0x8EB6] = st.v.weak_pawns;
        img[st.flagp] = st.flag;
        const ply = st.ply;
        img[sp +% 4] = @truncate(ply);
        img[sp +% 5] = @truncate(ply >> 8);
    }
};

/// One far call as recorded: target as lifted_machine.Far numbers it.
const Call = struct { target: u8, sq: u16, v: u16, ax: u16 };

const CallLog = struct {
    calls: [512]Call = undefined,
    n: usize = 0,
    fn add(l: *CallLog, c: Call) void {
        if (l.n < l.calls.len) l.calls[l.n] = c;
        l.n += 1;
    }
};

/// The far routines on the state: see.zig's exchange evaluators on the position, and
/// the lifted attacker routines on a DGROUP image holding what they read.
const Callees = struct {
    st: *State,
    img: *lifted.AttackerImage,
    log: ?*CallLog,

    pub fn see(c: Callees, side: Side, square: u8, value: u16) u16 {
        const r = seemod.see(&c.st.p, &c.st.s, side, square, value);
        if (c.log) |l| l.add(.{ .target = @backingInt(side), .sq = square, .v = value, .ax = r });
        return r;
    }

    pub fn att(c: Callees, side: Side, square: u8, value: u16) u16 {
        const mem = &c.img.mem;
        const st = c.st;
        // the exchange work area DG:9FEC holds the piece lists (DG:A03A): it goes first
        @memcpy(mem[0x9FEC..][0..116], &st.s.attackers);
        @memcpy(mem[0xA060..][0..32], &st.s.defenders);
        @memcpy(mem[0x70E5..][0..11], &st.s.gain);
        @memcpy(mem[0xB4E6..][0..11], &st.s.net);
        @memcpy(mem[0x9EF6..][0..120], &st.p.board);
        @memcpy(mem[0xA03A..][0..32], &st.p.piece_list);
        @memcpy(mem[0xA51C..][0..120], &st.p.pawn_attacks[0]);
        @memcpy(mem[0x37DA..][0..120], &st.p.pawn_attacks[1]);
        @memcpy(mem[0xA09E..][0..120], &st.p.king_rays[0]);
        @memcpy(mem[0xA164..][0..120], &st.p.king_rays[1]);
        var m: Machine = .{ .mem = mem, .sp = 0xFFF0 };
        m.push(value);
        m.push(square);
        m.push(0x0EF8);
        m.push(0);
        switch (side) {
            .white => attackers.run41B6(&m, attackers.entry_41b6),
            .black => attackers.run4CEC(&m, attackers.entry_4cec),
        }
        @memcpy(&st.s.attackers, mem[0x9FEC..][0..116]);
        @memcpy(&st.s.defenders, mem[0xA060..][0..32]);
        @memcpy(&st.s.gain, mem[0x70E5..][0..11]);
        @memcpy(&st.s.net, mem[0xB4E6..][0..11]);
        if (c.log) |l| l.add(.{ .target = 2 + @as(u8, @backingInt(side)), .sq = square, .v = value, .ax = m.ax });
        return m.ax;
    }
};

/// Runs the hand-written routine `tag` (3 A026, 4 CD20) on the image's state and writes
/// what it changes back into the image. Returns AX.
fn runPort(st: *State, img: *Image, sp: u16, tag: u8, aimg: *lifted.AttackerImage, log: ?*CallLog) u16 {
    st.load(img, sp);
    const c: Callees = .{ .st = st, .img = aimg, .log = log };
    const r = if (tag == 3)
        et.evalThreatsWhite(&st.p, &st.v, &st.t, &st.s, c, &st.ply, st.m, &st.flag)
    else
        et.evalThreatsBlack(&st.p, &st.v, &st.t, &st.s, c, &st.ply, st.m, &st.flag);
    st.store(img, sp);
    return @bitCast(r);
}

/// The first byte of DGROUP that differs outside the bytes not compared.
fn compareImage(got: *const Image, want: *const Image, caller_sp: u16, skip_irq: bool) ?usize {
    const lo: u16 = caller_sp -% slack;
    for (0..0x10000) |i| {
        if (got[i] == want[i]) continue;
        const a: u16 = @intCast(i);
        if (lo <= caller_sp) {
            if (a >= lo and a < caller_sp) continue;
        } else if (a >= lo or a < caller_sp) continue;
        if (skip_irq and std.mem.indexOfScalar(u16, &irq_bytes, a) != null) continue;
        return i;
    }
    return null;
}

const names = [_][]const u8{ "", "", "", "A026", "CD20" };
const far_names = [_][]const u8{ "SEE_W C32A", "SEE_B CAC2", "ATT 41B6", "ATT 4CEC" };

fn replayFile(gpa: std.mem.Allocator, name: []const u8, counts: *[5]usize, ncalls: *usize) !void {
    const data = try readVectors(gpa, name);
    defer gpa.free(data);
    var c: Cursor = .{ .d = data };
    try std.testing.expectEqualSlices(u8, "MCET", c.take(4));
    _ = c.word();
    const img = try gpa.create(Image);
    defer gpa.destroy(img);
    const work = try gpa.create(Image);
    defer gpa.destroy(work);
    const want = try gpa.create(Image);
    defer gpa.destroy(want);
    const aimg = try gpa.create(lifted.AttackerImage);
    defer gpa.destroy(aimg);
    aimg.init();
    const st = try gpa.create(State);
    defer gpa.destroy(st);
    var log: CallLog = .{};
    img.* = @splat(0);
    var index: usize = 0;
    while (true) : (index += 1) {
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
                const flagp = c.word();
                const n = c.varint();
                const calls = c.take(n * 9);
                const ax = c.word();
                want.* = img.*;
                c.delta(want);
                if (c.byte() != 0) _ = c.take(c.varint() * 25);
                work.* = img.*;
                st.* = .{};
                log.n = 0;
                const got = runPort(st, work, regs[7], tag, aimg, &log);
                try std.testing.expectEqual(flagp, st.flagp);
                for (0..@min(n, log.n)) |k| {
                    const e = calls[k * 9 ..][0..9];
                    const w: Call = .{ .target = e[0], .sq = std.mem.readInt(u16, e[3..5], .little), .v = std.mem.readInt(u16, e[5..7], .little), .ax = std.mem.readInt(u16, e[7..9], .little) };
                    const g = log.calls[k];
                    if (w.target != g.target or w.sq != g.sq or w.v != g.v or w.ax != g.ax) {
                        std.debug.print("\n{s} record {d} ({s}): far call {d}: want {s}({d}, {d}) = {X:0>4} at {X:0>4}, got {s}({d}, {d}) = {X:0>4}\n", .{ name, index, names[tag], k, far_names[w.target], w.sq, w.v, w.ax, std.mem.readInt(u16, e[1..3], .little), far_names[g.target], g.sq, g.v, g.ax });
                        return error.MismatchWithOriginal;
                    }
                }
                if (n != log.n) {
                    std.debug.print("\n{s} record {d} ({s}): far calls: want {d}, got {d}\n", .{ name, index, names[tag], n, log.n });
                    return error.MismatchWithOriginal;
                }
                if (got != ax) {
                    std.debug.print("\n{s} record {d} ({s}): AX want {d}, got {d}\n", .{ name, index, names[tag], @as(i16, @bitCast(ax)), @as(i16, @bitCast(got)) });
                    return error.MismatchWithOriginal;
                }
                if (compareImage(work, want, regs[7], true)) |off| {
                    std.debug.print("\n{s} record {d} ({s}): DG:{X:0>4} want {X:0>2}, got {X:0>2}\n", .{ name, index, names[tag], off, want[off], work[off] });
                    return error.MismatchWithOriginal;
                }
                counts[tag] += 1;
                ncalls.* += n;
            },
            else => return error.BadVectorFile,
        }
    }
}

test "evalthreats: the hand-written A026 and CD20 equal the original on every recorded call" {
    const gpa = std.testing.allocator;
    var counts: [5]usize = @splat(0);
    var ncalls: usize = 0;
    for (files) |f| try replayFile(gpa, f, &counts, &ncalls);
    std.debug.print("evalthreats (hand-written): A026 {d}, CD20 {d} recorded calls ({d} far calls) equal\n", .{ counts[3], counts[4], ncalls });
    try std.testing.expect(counts[3] > 0 and counts[4] > 0);
}

// ---------------------------------------------------------------------------
// The class C fixes DEV-020 and DEV-022 (AGENTS.md §9.2)
// ---------------------------------------------------------------------------

const fix020: pos.Fixes = .{ .dev001_ep_hash_square = false, .dev020_threat_table_index = true };
const fix022: pos.Fixes = .{ .dev001_ep_hash_square = false, .dev022_captured_pieces = true };

/// `runPort` with the fixes given.
fn runFixes(comptime fixes: pos.Fixes, st: *State, img: *Image, sp: u16, tag: u8, aimg: *lifted.AttackerImage, log: ?*CallLog) u16 {
    st.load(img, sp);
    const c: Callees = .{ .st = st, .img = aimg, .log = log };
    const r = if (tag == 3)
        et.evalThreatsFixes(fixes, .white, &st.p, &st.v, &st.t, &st.s, c, &st.ply, st.m, &st.flag)
    else
        et.evalThreatsFixes(fixes, .black, &st.p, &st.v, &st.t, &st.s, c, &st.ply, st.m, &st.flag);
    st.store(img, sp);
    return @bitCast(r);
}

/// The enemy's knight, bishop, rook and queen slots of the routine `tag` (3 A026, 4 CD20).
fn foeSlots(tag: u8) u16 {
    return if (tag == 3) 0xA04A else 0xA03A;
}

/// An enemy knight, bishop, rook or queen is captured (its entry is above 62h).
fn capturedFoe(img: *const Image, tag: u8) bool {
    for (0..7) |i| if (img[foeSlots(tag) + i] > 0x62) return true;
    return false;
}

const Outcome = struct { ax: u16, flag: u8, n: usize, calls: [512]Call };

fn outcome(comptime fixes: pos.Fixes, st: *State, input: *const Image, work: *Image, sp: u16, tag: u8, aimg: *lifted.AttackerImage, log: *CallLog) Outcome {
    work.* = input.*;
    st.* = .{};
    log.n = 0;
    const ax = runFixes(fixes, st, work, sp, tag, aimg, log);
    return .{ .ax = ax, .flag = st.flag, .n = log.n, .calls = log.calls };
}

fn sameCalls(a: *const Outcome, b: *const Outcome) bool {
    if (a.n != b.n) return false;
    for (0..@min(a.n, a.calls.len)) |i| {
        const x = a.calls[i];
        const y = b.calls[i];
        if (x.target != y.target or x.sq != y.sq or x.v != y.v or x.ax != y.ax) return false;
    }
    return true;
}

test "evalthreats: DEV-020 and DEV-022 corrected, against the original on every recorded call" {
    const gpa = std.testing.allocator;
    const img = try gpa.create(Image);
    defer gpa.destroy(img);
    const work = try gpa.create(Image);
    defer gpa.destroy(work);
    const moved = try gpa.create(Image);
    defer gpa.destroy(moved);
    const aimg = try gpa.create(lifted.AttackerImage);
    defer gpa.destroy(aimg);
    aimg.init();
    const st = try gpa.create(State);
    defer gpa.destroy(st);
    const out = try gpa.alloc(Outcome, 4);
    defer gpa.free(out);
    var log: CallLog = .{};
    var total: usize = 0;
    var with_captured: usize = 0;
    var changed020: usize = 0;
    var changed022: usize = 0;
    var first020: ?struct { name: []const u8, index: usize, tag: u8, orig: i16, fixed: i16 } = null;
    var first022: ?struct { name: []const u8, index: usize, tag: u8, orig: i16, fixed: i16, flag0: u8, flag1: u8 } = null;
    for (files) |name| {
        const data = try readVectors(gpa, name);
        defer gpa.free(data);
        var c: Cursor = .{ .d = data[6..] };
        img.* = @splat(0);
        var index: usize = 0;
        while (true) : (index += 1) {
            const tag = c.byte();
            if (tag == 0) break;
            c.delta(img);
            var regs: [8]u16 = undefined;
            for (&regs) |*r| r.* = c.word();
            switch (tag) {
                1, 2 => {
                    _ = c.word();
                    c.skipDelta();
                    continue;
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
            const sp = regs[7];
            total += 1;
            out[0] = outcome(pos.Fixes.original, st, img, work, sp, tag, aimg, &log);
            out[1] = outcome(fix020, st, img, work, sp, tag, aimg, &log);
            out[2] = outcome(fix022, st, img, work, sp, tag, aimg, &log);
            // DEV-020 changes the result word of the tail only: the flag byte and every
            // far call stay the original's.
            try std.testing.expectEqual(out[0].flag, out[1].flag);
            try std.testing.expect(sameCalls(&out[0], &out[1]));
            if (out[1].ax != out[0].ax) {
                changed020 += 1;
                if (first020 == null) first020 = .{ .name = name, .index = index, .tag = tag, .orig = @bitCast(out[0].ax), .fixed = @bitCast(out[1].ax) };
            }
            const captured = capturedFoe(img, tag);
            with_captured += @intFromBool(captured);
            // DEV-022 changes nothing in a call without a captured enemy piece.
            const differs = out[2].ax != out[0].ax or out[2].flag != out[0].flag;
            if (!captured) {
                try std.testing.expect(!differs and sameCalls(&out[0], &out[2]));
                continue;
            }
            if (differs) {
                changed022 += 1;
                if (first022 == null) first022 = .{ .name = name, .index = index, .tag = tag, .orig = @bitCast(out[0].ax), .fixed = @bitCast(out[2].ax), .flag0 = out[0].flag, .flag1 = out[2].flag };
            }
            // Corrected, the result no longer depends on where a captured piece was
            // taken: every captured entry moved to the first and to the last value a
            // captured piece can have (78h = a1 + 63h, C5h = h8 + 63h) gives the same.
            for ([_]u8{ 0x78, 0xC5 }) |entry| {
                moved.* = img.*;
                for (0..7) |i| {
                    if (moved[foeSlots(tag) + i] > 0x62) moved[foeSlots(tag) + i] = entry;
                }
                out[3] = outcome(fix022, st, moved, work, sp, tag, aimg, &log);
                if (out[3].ax != out[2].ax or out[3].flag != out[2].flag) {
                    std.debug.print("\n{s} record {d} ({s}): DEV-022 corrected depends on a captured entry: {d}/{d} against {d}/{d} with {X:0>2}\n", .{ name, index, names[tag], @as(i16, @bitCast(out[2].ax)), out[2].flag, @as(i16, @bitCast(out[3].ax)), out[3].flag, entry });
                    return error.CapturedEntryRead;
                }
            }
        }
    }
    std.debug.print("evalthreats fixes: {d} recorded calls, {d} with a captured enemy piece; DEV-020 changes {d}, DEV-022 changes {d}\n", .{ total, with_captured, changed020, changed022 });
    if (first020) |f| std.debug.print("  DEV-020 first: {s} record {d} ({s}): original {d}, corrected {d}\n", .{ f.name, f.index, names[f.tag], f.orig, f.fixed });
    if (first022) |f| std.debug.print("  DEV-022 first: {s} record {d} ({s}): original {d} flag {d}, corrected {d} flag {d}\n", .{ f.name, f.index, names[f.tag], f.orig, f.flag0, f.fixed, f.flag1 });
    // The committed recordings (12,623 threat calls): two read past T2 (n - m = 29 in
    // both), seven change with the captured pieces skipped.
    try std.testing.expectEqual(@as(usize, 2), changed020);
    try std.testing.expectEqual(@as(usize, 7), changed022);
    // B.zst record 4913, CD20: n - m = 29 reads DG:03C2 (900); corrected, three threats
    // in T2 (500).
    try std.testing.expectEqual(@as(i16, 900), first020.?.orig);
    try std.testing.expectEqual(@as(i16, 500), first020.?.fixed);
    // C.zst record 1763, CD20: a prefilter on a captured piece's entry leads to an
    // attacker call that finds a threat (24, one threat in T1); corrected, none.
    try std.testing.expectEqual(@as(i16, 24), first022.?.orig);
    try std.testing.expectEqual(@as(i16, 0), first022.?.fixed);
}

// ---------------------------------------------------------------------------
// Differential test against the lifted routines
// ---------------------------------------------------------------------------

/// src/threats_test.zig `mutate`, for the threat calls: a few inner board squares,
/// piece-list entries and pawn-attack counts, and the call's arguments.
fn mutate(rng: std.Random, img: *Image, sp: u16) void {
    const codes = [_]u8{ 0, 0, 0, 1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13 };
    const inner = struct {
        fn sq(r: std.Random) u16 {
            return 21 + 10 * @as(u16, r.uintLessThan(u8, 8)) + r.uintLessThan(u8, 8);
        }
    };
    for (0..rng.uintLessThan(usize, 7)) |_| img[0x9EF6 + inner.sq(rng)] = codes[rng.uintLessThan(usize, codes.len)];
    if (rng.uintLessThan(u8, 4) == 0) {
        const s = inner.sq(rng);
        // not the kings (slots 7, 23): a captured king is not a state the program reaches
        const slot = rng.uintLessThan(u16, 30);
        img[0xA03A + slot + @as(u16, if (slot >= 7) 1 else 0) + @as(u16, if (slot >= 22) 1 else 0)] = @truncate(if (rng.boolean()) s else s + 0x63);
    }
    if (rng.uintLessThan(u8, 3) == 0) for (0..rng.uintLessThan(usize, 4)) |_| {
        img[(if (rng.boolean()) @as(u16, 0xA51C) else 0x37DA) + inner.sq(rng)] = rng.uintLessThan(u8, 3);
    };
    const plies = [_]u16{ 0, 1, 2, 3, 4, 5, 6, 8, 12, 100 };
    if (rng.boolean()) std.mem.writeInt(u16, img[sp +% 4 ..][0..2], plies[rng.uintLessThan(usize, plies.len)], .little);
    if (rng.boolean()) std.mem.writeInt(u16, img[sp +% 6 ..][0..2], rng.uintLessThan(u16, 5), .little);
}

/// Further changes aimed at the branches the recordings reach rarely: the king and the
/// enemy queen moved near each other, enemy rooks on the first two ranks, the depth
/// limits and the material tests.
fn mutateMore(rng: std.Random, img: *Image, tag: u8) void {
    const white = tag == 3;
    const own: u16 = if (white) 0xA03A else 0xA04A;
    const foe: u16 = if (white) 0xA04A else 0xA03A;
    const own_code: u8 = if (white) 0 else 7;
    const foe_code: u8 = if (white) 7 else 0;
    const mirror = struct {
        fn f(w: bool, s: u16) u16 {
            return if (w) s else 110 - 10 * (s / 10) + s % 10;
        }
    }.f;
    const inner = struct {
        fn sq(r: std.Random, lo_rank: u16, hi_rank: u16) u16 {
            return 21 + 10 * (lo_rank + r.uintLessThan(u16, hi_rank - lo_rank + 1)) + r.uintLessThan(u16, 8);
        }
    };
    const board: u16 = 0x9EF6;
    // move a piece of `slot` (list `list`) with code `code` to `to`, if `to` is empty
    const move = struct {
        fn f(m: *Image, list: u16, slot: u16, code: u8, to: u16) void {
            if (m[0x9EF6 + to] != 0) return;
            const from: u16 = m[list + slot];
            if (from <= 0x62 and m[0x9EF6 + from] == code) m[0x9EF6 + from] = 0;
            m[list + slot] = @intCast(to);
            m[0x9EF6 + to] = code;
        }
    }.f;
    // put a piece of `slot` with `code` on `to`, whatever is there
    const force = struct {
        fn f(m: *Image, list: u16, slot: u16, code: u8, to: u16) void {
            const from = m[list + slot];
            if (from <= 0x62 and m[0x9EF6 + @as(u16, from)] == code) m[0x9EF6 + @as(u16, from)] = 0;
            m[list + slot] = @intCast(to);
            m[0x9EF6 + to] = code;
        }
    }.f;
    switch (rng.uintLessThan(u8, 12)) {
        0 => { // own king to the first three ranks
            move(img, own, 7, 6 + own_code, mirror(white, inner.sq(rng, 0, 2)));
        },
        1 => { // enemy queen near the own king's side of the board
            move(img, foe, 6, 5 + foe_code, mirror(white, inner.sq(rng, 0, 3)));
        },
        2 => { // an enemy rook to the first or second rank
            move(img, foe, 4 + rng.uintLessThan(u16, 2), 4 + foe_code, mirror(white, inner.sq(rng, 0, 1)));
        },
        3 => { // own pieces near their king
            move(img, own, rng.uintLessThan(u16, 7), @intCast(2 + own_code + rng.uintLessThan(u8, 4)), mirror(white, inner.sq(rng, 0, 2)));
        },
        4 => { // the depth limits
            const lims = [_]u16{ 0x9356, 0xA272, 0xA5EC };
            std.mem.writeInt(u16, img[lims[rng.uintLessThan(usize, 3)]..][0..2], rng.uintLessThan(u16, 10), .little);
            img[0xA3F4] = rng.uintLessThan(u8, 5);
            img[0xA40E] = @intFromBool(rng.uintLessThan(u8, 4) == 0);
        },
        5 => { // the material tests
            const vals = [_]u16{ 1100, 2000, 3800, 3801, 500, 6200, 7000 };
            const addrs = [_]u16{ 0xAE38, 0xAE3A, 0x378E };
            std.mem.writeInt(u16, img[addrs[rng.uintLessThan(usize, 3)]..][0..2], vals[rng.uintLessThan(usize, vals.len)], .little);
            img[0x931A + rng.uintLessThan(u16, 2)] = rng.uintLessThan(u8, 3);
            img[0x8EB6] = rng.int(u8);
            img[0xA5F5] = rng.int(u8);
        },
        6 => { // a pawn of either side near the kings
            img[board + inner.sq(rng, 0, 7)] = if (rng.boolean()) 1 else 8;
        },
        8, 9 => { // the king on a2 or h2 (b2, g2) with the enemy queen and rooks near
            const corner = [_]u16{ 0x1F, 0x26, 0x20, 0x25 };
            const k = mirror(white, corner[rng.uintLessThan(usize, corner.len)]);
            force(img, own, 7, 6 + own_code, k);
            const beside = mirror(white, if (k == mirror(white, 0x1F) or k == mirror(white, 0x20)) @as(u16, 0x20) else 0x25);
            if (beside != k) img[board + beside] = switch (rng.uintLessThan(u8, 3)) {
                0 => 0,
                1 => 1 + own_code,
                else => 2 + own_code,
            };
            const third = mirror(white, if (k == mirror(white, 0x1F) or k == mirror(white, 0x20)) @as(u16, 0x29) else 0x30);
            if (rng.boolean()) img[board + third] = if (rng.boolean()) 1 + own_code else 0;
            force(img, foe, 6, 5 + foe_code, mirror(white, inner.sq(rng, 0, 3)));
            if (rng.boolean()) force(img, foe, 4 + rng.uintLessThan(u16, 2), 4 + foe_code, mirror(white, inner.sq(rng, 0, 1)));
            // clear a square or two on the first two ranks
            for (0..rng.uintLessThan(usize, 3)) |_| {
                const x = mirror(white, inner.sq(rng, 0, 1));
                if (img[board + x] != 6 + own_code) img[board + x] = 0;
            }
        },
        10 => { // an own rook or bishop on a king ray, an enemy slider behind it
            const k: u16 = img[own + 7];
            if (k > 0x62) return;
            const diag = rng.boolean();
            const steps = if (diag) [_]i16{ 9, 11, -9, -11 } else [_]i16{ 1, 10, -1, -10 };
            const d = steps[rng.uintLessThan(usize, 4)];
            const r: u16 = @intCast(@as(i16, @intCast(k)) + d);
            const b: u16 = @intCast(@as(i16, @intCast(r)) + d);
            if (img[board + r] == 7 or img[board + b] == 7) return;
            const rook = rng.boolean();
            const slot: u16 = if (rook) 4 + rng.uintLessThan(u16, 2) else 2 + rng.uintLessThan(u16, 2);
            force(img, own, slot, (if (rook) @as(u8, 4) else 3) + own_code, r);
            // the enemy piece behind: for a rook on a diagonal a bishop or the queen, for
            // a bishop on a line a rook or the queen
            const queen = rng.uintLessThan(u8, 3) == 0;
            const fslot: u16 = if (queen) 6 else if (rook) 2 + rng.uintLessThan(u16, 2) else 4 + rng.uintLessThan(u16, 2);
            const fcode: u8 = @as(u8, if (queen) 5 else if (rook) 3 else 4) + foe_code;
            force(img, foe, fslot, fcode, b);
            // the own king's ray map at the piece: the direction code of d
            const codes = [_]i16{ 9, 11, -9, -11, 1, 10, -1, -10 };
            const code: u8 = @intCast(1 + (std.mem.indexOfScalar(i16, &codes, d) orelse return));
            img[(if (white) @as(u16, 0xA09E) else 0xA164) + r] = code + if (white) @as(u8, 0) else 8;
            if (rng.boolean()) img[(if (white) @as(u16, 0x37DA) else 0xA51C) + r] = 1;
            if (rng.boolean()) img[if (white) @as(u16, 0x931A) else 0x931B] = rng.uintLessThan(u8, 3);
            const lims = [_]u16{ 0x9356, 0xA272, 0xA5EC };
            std.mem.writeInt(u16, img[lims[rng.uintLessThan(usize, 3)]..][0..2], rng.uintLessThan(u16, 10), .little);
        },
        else => { // promoted queen slots
            img[0xA38E + rng.uintLessThan(u16, 2)] = if (rng.boolean()) 0 else 8 + rng.uintLessThan(u8, 8);
        },
    }
}

test "evalthreats: DEV-020 and DEV-022 corrected, on generated calls" {
    // The recorded calls changed as the differential test changes them (`mutate`,
    // `mutateMore`; a constant seed). DEV-020 changes the result only; DEV-022 changes
    // nothing without a captured enemy piece, and with one the corrected result does not
    // depend on the captured entries' values.
    const gpa = std.testing.allocator;
    const per_call: usize = if (builtin.mode == .debug) 1 else 12;
    var rng_state = std.Random.DefaultPrng.init(0xDE20_DE22);
    const rng = rng_state.random();
    const img = try gpa.create(Image);
    defer gpa.destroy(img);
    const ref = try gpa.create(Image);
    defer gpa.destroy(ref);
    const work = try gpa.create(Image);
    defer gpa.destroy(work);
    const moved = try gpa.create(Image);
    defer gpa.destroy(moved);
    const aimg = try gpa.create(lifted.AttackerImage);
    defer gpa.destroy(aimg);
    aimg.init();
    const st = try gpa.create(State);
    defer gpa.destroy(st);
    const out = try gpa.alloc(Outcome, 4);
    defer gpa.free(out);
    var log: CallLog = .{};
    var total: usize = 0;
    var with_captured: usize = 0;
    var changed: [2]usize = .{ 0, 0 };
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
                    continue;
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
            const sp = regs[7];
            for (0..per_call) |k| {
                ref.* = img.*;
                mutate(rng, ref, sp);
                if (k % 2 == 0) mutateMore(rng, ref, tag);
                total += 1;
                out[0] = outcome(pos.Fixes.original, st, ref, work, sp, tag, aimg, &log);
                out[1] = outcome(fix020, st, ref, work, sp, tag, aimg, &log);
                out[2] = outcome(fix022, st, ref, work, sp, tag, aimg, &log);
                try std.testing.expectEqual(out[0].flag, out[1].flag);
                try std.testing.expect(sameCalls(&out[0], &out[1]));
                changed[0] += @intFromBool(out[1].ax != out[0].ax);
                const differs = out[2].ax != out[0].ax or out[2].flag != out[0].flag;
                if (!capturedFoe(ref, tag)) {
                    try std.testing.expect(!differs and sameCalls(&out[0], &out[2]));
                    continue;
                }
                with_captured += 1;
                changed[1] += @intFromBool(differs);
                for ([_]u8{ 0x78, 0xC5 }) |entry| {
                    moved.* = ref.*;
                    for (0..7) |i| {
                        if (moved[foeSlots(tag) + i] > 0x62) moved[foeSlots(tag) + i] = entry;
                    }
                    out[3] = outcome(fix022, st, moved, work, sp, tag, aimg, &log);
                    if (out[3].ax != out[2].ax or out[3].flag != out[2].flag) {
                        std.debug.print("\n{s} ({s}) mutation {d}: DEV-022 corrected depends on a captured entry\n", .{ name, names[tag], k });
                        return error.CapturedEntryRead;
                    }
                }
            }
        }
    }
    std.debug.print("evalthreats fixes, generated: {d} calls, {d} with a captured enemy piece; DEV-020 changes {d}, DEV-022 changes {d}\n", .{ total, with_captured, changed[0], changed[1] });
}

/// The colour mirror of a call's state: ranks reversed, colours swapped, each side's
/// lists, pawn attacks, king-ray maps (direction codes mirrored), pawns per file,
/// material, piece counts, king files and promoted-queen slots exchanged. A captured
/// piece's entry (its square + 63h) is mirrored as such.
fn mirrorState(src: *const State, dst: *State) void {
    const M = struct {
        fn sq(s: usize) usize {
            return (11 - s / 10) * 10 + s % 10;
        }
        fn code(c: u8) u8 {
            return if (c >= 1 and c <= 6) c + 7 else if (c >= 8 and c <= 13) c - 7 else c;
        }
        fn entry(e: u8) u8 {
            if (e >= 21 and e <= 0x62) return @intCast(sq(e));
            if (e >= 0x78 and e <= 0xC5) return @intCast(sq(e - 0x63) + 0x63);
            return e;
        }
        // direction code k (1..8: 9 11 -9 -11 1 10 -1 -10) -> the code of the mirrored step
        const ray = [9]u8{ 0, 4, 3, 2, 1, 5, 8, 7, 6 };
    };
    dst.* = src.*;
    const s = &src.p;
    const d = &dst.p;
    for (0..120) |i| d.board[M.sq(i)] = M.code(s.board[i]);
    for (0..16) |i| {
        d.piece_list[i] = M.entry(s.piece_list[16 + i]);
        d.piece_list[16 + i] = M.entry(s.piece_list[i]);
    }
    for (0..2) |c| for (0..120) |i| {
        d.pawn_attacks[1 - c][M.sq(i)] = s.pawn_attacks[c][i];
        const r = s.king_rays[c][i];
        d.king_rays[1 - c][M.sq(i)] = if (r == 0) 0 else if (c == 0) M.ray[r] + 8 else M.ray[r - 8];
    };
    d.pawns_per_file = .{ s.pawns_per_file[1], s.pawns_per_file[0] };
    d.piece_material = .{ s.piece_material[1], s.piece_material[0] };
    d.piece_count = .{ s.piece_count[1], s.piece_count[0] };
    d.king_file = .{ s.king_file[1], s.king_file[0] };
    dst.t.promoted_queen_slot = .{ src.t.promoted_queen_slot[1], src.t.promoted_queen_slot[0] };
}

/// `see.see` and `pinexchange.exchangeFixes` on the state.
fn MirrorCallees(comptime fixes: pos.Fixes) type {
    return struct {
        st: *State,
        pub fn see(c: @This(), side: Side, square: u8, value: u16) u16 {
            return seemod.see(&c.st.p, &c.st.s, side, square, value);
        }
        pub fn att(c: @This(), side: Side, square: u8, value: u16) u16 {
            return @import("pinexchange.zig").exchangeFixes(fixes, &c.st.p, &c.st.s, side, square, value);
        }
    };
}

const Result = struct { ax: i16, flag: u8 };

/// The far routines of Black's routine answered by White's on the mirrored position:
/// `see(.white, s, v)` is `see(.black, mirror(s), v)` there, and `att` likewise. With
/// them the two colours' far calls are mirrors by construction, so a mirrored test sees
/// the threat evaluators' own differences only, not those of the exchange routines
/// (src/see.zig, src/pinexchange.zig), which on generated states (a piece list that
/// disagrees with the board, a pawn on the last rank) are not always mirrors.
fn SymCallees(comptime fixes: pos.Fixes) type {
    return struct {
        st: *State,
        tmp: *State,
        fn mirrorSquare(s: u8) u8 {
            return @intCast((11 - @as(u16, s) / 10) * 10 + s % 10);
        }
        pub fn see(c: @This(), side: Side, square: u8, value: u16) u16 {
            mirrorState(c.st, c.tmp);
            return seemod.see(&c.tmp.p, &c.tmp.s, side.other(), mirrorSquare(square), value);
        }
        pub fn att(c: @This(), side: Side, square: u8, value: u16) u16 {
            mirrorState(c.st, c.tmp);
            return @import("pinexchange.zig").exchangeFixes(fixes, &c.tmp.p, &c.tmp.s, side.other(), mirrorSquare(square), value);
        }
    };
}

/// One routine on `st`; with `sym`, Black's far calls answered as `SymCallees` says.
fn runProbe(comptime fixes: pos.Fixes, comptime probe: et.Probe, comptime side: Side, st: *State, sym: ?*State) Result {
    if (side == .black) if (sym) |tmp| {
        const c: SymCallees(fixes) = .{ .st = st, .tmp = tmp };
        const r = et.evalThreatsProbe(fixes, probe, side, &st.p, &st.v, &st.t, &st.s, c, &st.ply, st.m, &st.flag);
        return .{ .ax = r, .flag = st.flag };
    };
    const c: MirrorCallees(fixes) = .{ .st = st };
    const r = et.evalThreatsProbe(fixes, probe, side, &st.p, &st.v, &st.t, &st.s, c, &st.ply, st.m, &st.flag);
    return .{ .ax = r, .flag = st.flag };
}

/// The routine of `tag` (3 A026, 4 CD20) on `base`, and the other routine on its mirror.
/// `r[0]` is White's routine's result and `r[1]` Black's, whichever of them ran on the
/// mirror; both are in White's view, so they agree when `r[1] = -r[0]` with one flag.
fn mirrorPair(comptime fixes: pos.Fixes, comptime probe: et.Probe, base: *const State, tag: u8, a: *State, b: *State, sym: ?*State) [2]Result {
    a.* = base.*;
    mirrorState(base, b);
    if (tag == 3) return .{ runProbe(fixes, probe, .white, a, sym), runProbe(fixes, probe, .black, b, sym) };
    return .{ runProbe(fixes, probe, .white, b, sym), runProbe(fixes, probe, .black, a, sym) };
}

fn agree(r: [2]Result) bool {
    return r[1].ax == -%r[0].ax and r[1].flag == r[0].flag;
}

/// The state Black's routine ran on in `mirrorPair`.
fn blackState(base: *const State, tag: u8, b: *State) *const State {
    if (tag == 4) return base;
    mirrorState(base, b);
    return b;
}

/// DEV-020, 022 and 023 corrected (the fixes of decision 27 that touch the threat
/// evaluators and the attacker routines), then DEV-041 as well.
const fix3: pos.Fixes = .{ .dev001_ep_hash_square = false, .dev020_threat_table_index = true, .dev022_captured_pieces = true, .dev023_pinned_bishop = true };
const fix4: pos.Fixes = blk: {
    var f = fix3;
    f.dev041_threat_mirror = true;
    break :blk f;
};
const fix041: pos.Fixes = .{ .dev001_ep_hash_square = false, .dev041_threat_mirror = true };
/// Those four and DEV-021 (owner decision 30), then DEV-052 as well: every fix that
/// touches the threat evaluators and the attacker routines.
const fix5: pos.Fixes = blk: {
    var f = fix4;
    f.dev021_knight_escape_order = true;
    break :blk f;
};
const fix6: pos.Fixes = blk: {
    var f = fix5;
    f.dev052_line_tables = true;
    break :blk f;
};
/// Every fix but DEV-021, and every fix but DEV-041: each is needed for the mirror.
const fix6_no021: pos.Fixes = blk: {
    var f = fix6;
    f.dev021_knight_escape_order = false;
    break :blk f;
};
const fix6_no041: pos.Fixes = blk: {
    var f = fix6;
    f.dev041_threat_mirror = false;
    break :blk f;
};
const fix6_no052 = fix5;
const fix021: pos.Fixes = .{ .dev001_ep_hash_square = false, .dev021_knight_escape_order = true };
const fix052: pos.Fixes = .{ .dev001_ep_hash_square = false, .dev052_line_tables = true };

/// One routine on `st` with `fixes` and the other with `fixes2`, compared (result and flag).
fn changes(comptime f1: pos.Fixes, comptime f2: pos.Fixes, comptime side: Side, base: *const State, a: *State) bool {
    a.* = base.*;
    const x = runProbe(f1, .{}, side, a, null);
    a.* = base.*;
    const y = runProbe(f2, .{}, side, a, null);
    return x.ax != y.ax or x.flag != y.flag;
}

/// For DEV-021 and DEV-052, the first call (with the board and the lists in agreement)
/// where the switch, added to the other fixes, changes a routine's result and makes it the
/// mirror of the other's.
const SwitchExample = struct {
    found: bool = false,
    where: []const u8 = "",
    index: usize = 0,
    /// White's routine and Black's on the mirror, before (`fix_before`) and after.
    before: [2]Result = undefined,
    after: [2]Result = undefined,
    board: [120]u8 = undefined,
    black_to_examine: bool = false,
};

fn noteSwitch(x: *SwitchExample, where: []const u8, index: usize, base: *const State, tag: u8, before: [2]Result, after: [2]Result) void {
    if (x.found or agree(before) or !agree(after)) return;
    if (!consistent(base)) return;
    x.* = .{ .found = true, .where = where, .index = index, .before = before, .after = after, .board = base.p.board, .black_to_examine = tag == 4 };
}

fn printBoard(board: *const [120]u8) void {
    const ch = " PNBRQK#pnbrqk";
    std.debug.print("    placement ", .{});
    var rr: usize = 9;
    while (rr >= 2) : (rr -= 1) {
        var empty: u8 = 0;
        for (1..9) |f| {
            const c = board[rr * 10 + f];
            if (c == 0) {
                empty += 1;
                continue;
            }
            if (empty != 0) std.debug.print("{d}", .{empty});
            empty = 0;
            std.debug.print("{c}", .{if (c < ch.len) ch[c] else '?'});
        }
        if (empty != 0) std.debug.print("{d}", .{empty});
        if (rr > 2) std.debug.print("/", .{});
    }
    std.debug.print("\n", .{});
}

fn printSwitch(name: []const u8, x: *const SwitchExample) void {
    if (!x.found) {
        std.debug.print("  {s}: no call found\n", .{name});
        return;
    }
    std.debug.print("  {s}: {s} {d} ({s} routine's state): before: A026 {d} (flag {d}), CD20 {d} (flag {d}); after: A026 {d} (flag {d}), CD20 {d} (flag {d})\n", .{ name, x.where, x.index, if (x.black_to_examine) "CD20" else "A026", x.before[0].ax, x.before[0].flag, x.before[1].ax, x.before[1].flag, x.after[0].ax, x.after[0].flag, x.after[1].ax, x.after[1].flag });
    printBoard(&x.board);
}

const sites = std.enums.values(et.Site041);

/// For each place of DEV-041, the first call where correcting that place alone changes
/// Black's result and makes it the mirror of White's.
const Example = struct {
    found: bool = false,
    where: []const u8 = "",
    index: usize = 0,
    /// Black's routine (DEV-020, 022, 023 corrected), White's on the mirror, and Black's
    /// with the one place of DEV-041 corrected.
    black: Result = undefined,
    white: Result = undefined,
    corrected: Result = undefined,
    board: [120]u8 = undefined,
    king: u8 = 0,
    queen: u8 = 0,
};

/// The board and the piece lists agree: every live entry holds its slot's piece, every
/// piece on the board has an entry, and no pawn stands on the first or last rank. (The
/// generated states need not; an example is taken only from one that does.)
fn consistent(st: *const State) bool {
    const kinds = [16]u8{ 2, 2, 3, 3, 4, 4, 5, 6, 1, 1, 1, 1, 1, 1, 1, 1 };
    var listed: [120]bool = @splat(false);
    for (0..32) |i| {
        const e = st.p.piece_list[i];
        if (e > 0x62) continue;
        if (e < 21 or st.p.board[e] != kinds[i % 16] + @as(u8, if (i < 16) 0 else 7)) return false;
        listed[e] = true;
    }
    for (21..99) |s| {
        const c = st.p.board[s];
        if (c == 0 or c == 7) continue;
        if (!listed[s]) return false;
        if ((c == 1 or c == 8) and (s < 31 or s > 88)) return false;
    }
    return true;
}

fn noteExamples(examples: *[sites.len]Example, where: []const u8, index: usize, base: *const State, tag: u8, r3: [2]Result, a: *State, b: *State) void {
    const black = blackState(base, tag, b);
    if (!consistent(black)) return;
    const copy = black.*;
    inline for (sites, 0..) |site, k| {
        if (!examples[k].found) {
            a.* = copy;
            const r = runProbe(fix4, .{ .dev041_only = site }, .black, a, null);
            if ((r.ax != r3[1].ax or r.flag != r3[1].flag) and r.ax == -%r3[0].ax and r.flag == r3[0].flag) {
                examples[k] = .{ .found = true, .where = where, .index = index, .black = r3[1], .white = r3[0], .corrected = r, .board = copy.p.board, .king = copy.p.piece_list[23], .queen = copy.p.piece_list[6] };
            }
        }
    }
}

fn printExamples(examples: *const [sites.len]Example) void {
    const ch = " PNBRQK#pnbrqk";
    for (examples, 0..) |x, k| {
        if (!x.found) {
            std.debug.print("  DEV-041 {s}: no call found\n", .{@tagName(sites[k])});
            continue;
        }
        std.debug.print("  DEV-041 {s}: {s} {d}: CD20 {d} (flag {d}), A026 on the mirror {d} (flag {d}), CD20 corrected {d} (flag {d}); Black king {d}, White queen {d}\n", .{ @tagName(sites[k]), x.where, x.index, x.black.ax, x.black.flag, x.white.ax, x.white.flag, x.corrected.ax, x.corrected.flag, x.king, x.queen });
        std.debug.print("    placement ", .{});
        var rr: usize = 9;
        while (rr >= 2) : (rr -= 1) {
            var empty: u8 = 0;
            for (1..9) |f| {
                const c = x.board[rr * 10 + f];
                if (c == 0) {
                    empty += 1;
                    continue;
                }
                if (empty != 0) std.debug.print("{d}", .{empty});
                empty = 0;
                std.debug.print("{c}", .{if (c < ch.len) ch[c] else '?'});
            }
            if (empty != 0) std.debug.print("{d}", .{empty});
            if (rr > 2) std.debug.print("/", .{});
        }
        std.debug.print("\n", .{});
        var r: usize = 9;
        while (r >= 2) : (r -= 1) {
            std.debug.print("    ", .{});
            for (1..9) |f| {
                const c = x.board[r * 10 + f];
                std.debug.print("{c}", .{if (c == 0) '.' else if (c < ch.len) ch[c] else '?'});
            }
            std.debug.print("\n", .{});
        }
    }
}

test "evalthreats: A026 and CD20 agree on mirrored recorded calls (DEV-022, DEV-041)" {
    // spec 54 section 6: each routine derived from the other on the mirrored state gives
    // the negated result and the same flag, except where a captured piece's entry is used
    // as a square (DEV-022) or where CD20 is not A026's mirror (DEV-041, DEV-021), and
    // where the line tables' pseudo-lines are not symmetric (spec 7.4, DEV-052). With
    // every fix on, no recorded call differs.
    const gpa = std.testing.allocator;
    const img = try gpa.create(Image);
    defer gpa.destroy(img);
    const base = try gpa.create(State);
    defer gpa.destroy(base);
    const a = try gpa.create(State);
    defer gpa.destroy(a);
    const b = try gpa.create(State);
    defer gpa.destroy(b);
    var total: usize = 0;
    // original, DEV-022 alone, DEV-020/022/023, those and DEV-041, and DEV-021, and
    // DEV-052 (every fix)
    var differ: [6]usize = @splat(0);
    var changed041: usize = 0;
    var changed041_after3: usize = 0;
    // the calls DEV-021 and DEV-052 change, alone and after the other fixes
    var changed021: [2]usize = @splat(0);
    var changed052: [2]usize = @splat(0);
    var ex021: SwitchExample = .{};
    var ex052: SwitchExample = .{};
    var examples: [sites.len]Example = @splat(.{});
    var b3629: ?[3]Result = null;
    for (files) |name| {
        const data = try readVectors(gpa, name);
        defer gpa.free(data);
        var c: Cursor = .{ .d = data[6..] };
        img.* = @splat(0);
        var index: usize = 0;
        while (true) : (index += 1) {
            const tag = c.byte();
            if (tag == 0) break;
            c.delta(img);
            var regs: [8]u16 = undefined;
            for (&regs) |*r| r.* = c.word();
            switch (tag) {
                1, 2 => {
                    _ = c.word();
                    c.skipDelta();
                    continue;
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
            base.* = .{};
            base.load(img, regs[7]);
            total += 1;
            const r0 = mirrorPair(pos.Fixes.original, .{}, base, tag, a, b, null);
            const r3 = mirrorPair(fix3, .{}, base, tag, a, b, null);
            const r4 = mirrorPair(fix4, .{}, base, tag, a, b, null);
            const r5 = mirrorPair(fix5, .{}, base, tag, a, b, null);
            const r6 = mirrorPair(fix6, .{}, base, tag, a, b, null);
            differ[0] += @intFromBool(!agree(r0));
            differ[1] += @intFromBool(!agree(mirrorPair(fix022, .{}, base, tag, a, b, null)));
            differ[2] += @intFromBool(!agree(r3));
            differ[3] += @intFromBool(!agree(r4));
            differ[4] += @intFromBool(!agree(r5));
            if (!agree(r6)) {
                differ[5] += 1;
                std.debug.print("  {s} record {d} ({s}): White {d} (flag {d}), Black {d} (flag {d}), every fix on\n", .{ name, index, names[tag], r6[0].ax, r6[0].flag, r6[1].ax, r6[1].flag });
            }
            if (agree(r4) and !agree(r5)) {
                std.debug.print("  {s} record {d} ({s}): DEV-021 breaks the mirror\n", .{ name, index, names[tag] });
                return error.MirrorBroken;
            }
            if (agree(r5) and !agree(r6)) {
                std.debug.print("  {s} record {d} ({s}): DEV-052 breaks the mirror\n", .{ name, index, names[tag] });
                return error.MirrorBroken;
            }
            const side_rec: Side = if (tag == 3) .white else .black;
            // DEV-021 reads Black's routine only
            if (tag == 4) {
                changed021[0] += @intFromBool(changes(pos.Fixes.original, fix021, .black, base, a));
                changed021[1] += @intFromBool(changes(fix4, fix5, .black, base, a));
            } else {
                try std.testing.expect(r4[0].ax == r5[0].ax and r4[0].flag == r5[0].flag);
            }
            switch (side_rec) {
                inline else => |sd| {
                    changed052[0] += @intFromBool(changes(pos.Fixes.original, fix052, sd, base, a));
                    changed052[1] += @intFromBool(changes(fix5, fix6, sd, base, a));
                },
            }
            noteSwitch(&ex021, name, index, base, tag, r4, r5);
            noteSwitch(&ex052, name, index, base, tag, r5, r6);
            if (!agree(r4) and agree(r3)) {
                std.debug.print("  {s} record {d} ({s}): DEV-041 breaks the mirror\n", .{ name, index, names[tag] });
                return error.MirrorBroken;
            }
            // the calls of Black's routine the switch changes, alone and after the others
            if (tag == 4) {
                a.* = base.*;
                const o = runProbe(pos.Fixes.original, .{}, .black, a, null);
                a.* = base.*;
                const f = runProbe(fix041, .{}, .black, a, null);
                changed041 += @intFromBool(o.ax != f.ax or o.flag != f.flag);
                changed041_after3 += @intFromBool(r3[1].ax != r4[1].ax or r3[1].flag != r4[1].flag);
                if (std.mem.eql(u8, name, "B.zst") and index == 3629) b3629 = .{ r3[1], r3[0], r4[1] };
            } else {
                // White's routine is never changed by DEV-041
                try std.testing.expect(r3[0].ax == r4[0].ax and r3[0].flag == r4[0].flag);
            }
            if (r3[1].ax != r4[1].ax or r3[1].flag != r4[1].flag) noteExamples(&examples, name, index, base, tag, r3, a, b);
        }
    }
    std.debug.print("evalthreats mirrored: {d} recorded calls; differ from the mirror: original {d}, DEV-022 alone {d}, DEV-020/022/023 {d}, and DEV-041 {d}, and DEV-021 {d}, and DEV-052 {d}; DEV-041 changes {d} CD20 calls ({d} after the other fixes); DEV-021 changes {d} CD20 calls ({d} after the others); DEV-052 changes {d} calls ({d} after the others)\n", .{ total, differ[0], differ[1], differ[2], differ[3], differ[4], differ[5], changed041, changed041_after3, changed021[0], changed021[1], changed052[0], changed052[1] });
    printExamples(&examples);
    printSwitch("DEV-021", &ex021);
    printSwitch("DEV-052", &ex052);
    // Of the 13 in the original, 8 go with DEV-022 corrected. Of the 5 left, B.zst
    // records 2478 (A026) and 3629 (CD20), one position in both colours, go with DEV-041
    // (D720 / D760). The other three (A.zst 5191, B.zst 3115, D.zst 3895; 24 or 40) come
    // from the line tables' pseudo-lines (a8-g7 taken as a rank at -4, its mirror a1-g2
    // at +16 not; spec 7.4) and go with DEV-052. DEV-021 changes no recorded call.
    try std.testing.expectEqual(@as(usize, 13), differ[0]);
    try std.testing.expectEqual(@as(usize, 5), differ[1]);
    try std.testing.expectEqual(@as(usize, 5), differ[2]);
    try std.testing.expectEqual(@as(usize, 3), differ[3]);
    try std.testing.expectEqual(@as(usize, 3), differ[4]);
    try std.testing.expectEqual(@as(usize, 0), differ[5]);
    try std.testing.expectEqual(@as(usize, 1), changed041);
    try std.testing.expectEqual(@as(usize, 1), changed041_after3);
    // B.zst record 3629: CD20 600, A026 on the mirror -860; corrected, CD20 860.
    const x = b3629.?;
    try std.testing.expectEqual(@as(i16, 600), x[0].ax);
    try std.testing.expectEqual(@as(i16, -860), x[1].ax);
    try std.testing.expectEqual(@as(i16, 860), x[2].ax);
    try std.testing.expect(examples[@backingInt(et.Site041.queen_above)].found);
}

test "evalthreats: A026 and CD20 agree on mirrored generated calls (DEV-041)" {
    // The recorded calls changed as the differential tests change them (`mutate`,
    // `mutateMore`; a constant seed), each run by its routine and mirrored by the other.
    // With DEV-020, 022, 023, 041, 021 and 052 corrected and the far calls mirrored
    // (`SymCallees`), no call differs from its mirror; without any one of DEV-041, 021
    // and 052, some do.
    const gpa = std.testing.allocator;
    const per_call: usize = if (builtin.mode == .debug) 2 else 80;
    var rng_state = std.Random.DefaultPrng.init(0xDE41_A026_CD20);
    const rng = rng_state.random();
    const img = try gpa.create(Image);
    defer gpa.destroy(img);
    const ref = try gpa.create(Image);
    defer gpa.destroy(ref);
    const base = try gpa.create(State);
    defer gpa.destroy(base);
    const a = try gpa.create(State);
    defer gpa.destroy(a);
    const b = try gpa.create(State);
    defer gpa.destroy(b);
    const tmp = try gpa.create(State);
    defer gpa.destroy(tmp);
    var total: usize = 0;
    // original, DEV-020/022/023, and DEV-041, and DEV-021 and DEV-052 (every fix); then
    // with the far calls mirrored: every fix but DEV-041, but DEV-021, but DEV-052, and
    // every fix
    var differ: [8]usize = @splat(0);
    var changed041: usize = 0;
    var changed021: usize = 0;
    var changed052: usize = 0;
    var ex021: SwitchExample = .{};
    var ex052: SwitchExample = .{};
    var examples: [sites.len]Example = @splat(.{});
    for (files) |name| {
        const data = try readVectors(gpa, name);
        defer gpa.free(data);
        var c: Cursor = .{ .d = data[6..] };
        img.* = @splat(0);
        var index: usize = 0;
        while (true) : (index += 1) {
            const tag = c.byte();
            if (tag == 0) break;
            c.delta(img);
            var regs: [8]u16 = undefined;
            for (&regs) |*r| r.* = c.word();
            switch (tag) {
                1, 2 => {
                    _ = c.word();
                    c.skipDelta();
                    continue;
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
            const sp = regs[7];
            for (0..per_call) |k| {
                ref.* = img.*;
                mutate(rng, ref, sp);
                if (k % 2 == 0) mutateMore(rng, ref, tag);
                if (k % 8 == 1) mutateRookPin(rng, ref, tag);
                base.* = .{};
                base.load(ref, sp);
                total += 1;
                const r0 = mirrorPair(pos.Fixes.original, .{}, base, tag, a, b, null);
                const r3 = mirrorPair(fix3, .{}, base, tag, a, b, null);
                const r4 = mirrorPair(fix4, .{}, base, tag, a, b, null);
                const r5 = mirrorPair(fix6, .{}, base, tag, a, b, null);
                // the threat evaluators alone: Black's far calls answered by White's on
                // the mirror (`SymCallees`)
                const s5 = mirrorPair(fix5, .{}, base, tag, a, b, tmp);
                const s6 = mirrorPair(fix6, .{}, base, tag, a, b, tmp);
                differ[0] += @intFromBool(!agree(r0));
                differ[1] += @intFromBool(!agree(r3));
                differ[2] += @intFromBool(!agree(r4));
                differ[3] += @intFromBool(!agree(r5));
                differ[4] += @intFromBool(!agree(mirrorPair(fix6_no041, .{}, base, tag, a, b, tmp)));
                differ[5] += @intFromBool(!agree(mirrorPair(fix6_no021, .{}, base, tag, a, b, tmp)));
                differ[6] += @intFromBool(!agree(s5));
                if (!agree(s6)) {
                    differ[7] += 1;
                    if (differ[7] <= 10) std.debug.print("  {s} record {d} ({s}) mutation {d}: White {d} (flag {d}), Black {d} (flag {d}), every fix on, far calls mirrored\n", .{ name, index, names[tag], k, s6[0].ax, s6[0].flag, s6[1].ax, s6[1].flag });
                }
                if (r3[1].ax != r4[1].ax or r3[1].flag != r4[1].flag) {
                    changed041 += 1;
                    noteExamples(&examples, name, index, base, tag, r3, a, b);
                }
                // DEV-021 after the other fixes: Black's routine only
                const s4 = mirrorPair(fix4, .{}, base, tag, a, b, tmp);
                if (s4[1].ax != s5[1].ax or s4[1].flag != s5[1].flag) changed021 += 1;
                if (s4[0].ax != s5[0].ax or s4[0].flag != s5[0].flag) return error.Dev021ChangedWhite;
                if (s5[0].ax != s6[0].ax or s5[0].flag != s6[0].flag or s5[1].ax != s6[1].ax or s5[1].flag != s6[1].flag) changed052 += 1;
                noteSwitch(&ex021, name, index, base, tag, s4, s5);
                noteSwitch(&ex052, name, index, base, tag, s5, s6);
            }
        }
    }
    std.debug.print("evalthreats mirrored, generated: {d} calls; differ from the mirror: original {d}, DEV-020/022/023 {d}, and DEV-041 {d}, and DEV-021 and DEV-052 {d}; with the far calls mirrored too: every fix but DEV-041 {d}, but DEV-021 {d}, but DEV-052 {d}, every fix {d}; DEV-041 changes Black's result in {d}; with the far calls mirrored DEV-021 changes {d} and DEV-052 {d} (after the other fixes)\n", .{ total, differ[0], differ[1], differ[2], differ[3], differ[4], differ[5], differ[6], differ[7], changed041, changed021, changed052 });
    printExamples(&examples);
    printSwitch("DEV-021", &ex021);
    printSwitch("DEV-052", &ex052);
    try std.testing.expectEqual(@as(usize, 0), differ[7]);
    // each of DEV-041, DEV-021 and DEV-052 is needed
    try std.testing.expect(differ[4] > 0);
    try std.testing.expect(differ[5] > 0);
    try std.testing.expect(differ[6] > 0);
    if (builtin.mode != .debug) {
        try std.testing.expect(total >= 1_000_000);
        // a generated state with the board and lists in agreement, for each place but
        // the corners (whose positions are in the test below)
        try std.testing.expect(examples[@backingInt(et.Site041.queen_above)].found);
    }
}

/// A rook of the side examined pinned to its king on a diagonal by the enemy queen, with
/// an enemy bishop on each side of it on the other diagonal, one or two squares away
/// (the bishop test of B4F8 / E250, DEV-041). The king's ray map and the enemy pawn
/// attacks on the rook are set to match.
fn mutateRookPin(rng: std.Random, img: *Image, tag: u8) void {
    const white = tag == 3;
    const own: u16 = if (white) 0xA03A else 0xA04A;
    const foe: u16 = if (white) 0xA04A else 0xA03A;
    const oc: u8 = if (white) 0 else 7;
    const fc: u8 = if (white) 7 else 0;
    const k: i16 = img[own + 7];
    if (k > 0x62) return;
    const steps = [_]i16{ 9, 11, -9, -11 };
    const d = steps[rng.uintLessThan(usize, 4)];
    const r = k + d;
    const q = r + d;
    const other: i16 = if (d == 9 or d == -9) 11 else 9;
    const n1: i16 = 1 + @as(i16, rng.uintLessThan(u8, 2));
    const n2: i16 = 1 + @as(i16, rng.uintLessThan(u8, 2));
    const b1 = r + other * n1;
    const b2 = r - other * n2;
    for ([_]i16{ r, q, b1, b2, r + other, r - other }) |s| {
        if (s < 21 or s > 98 or img[0x9EF6 + @as(u16, @intCast(s))] == 7 or s == k) return;
    }
    const board: u16 = 0x9EF6;
    const put = struct {
        fn f(m: *Image, list: u16, slot: u16, code: u8, to: i16) void {
            const from = m[list + slot];
            if (from <= 0x62 and m[0x9EF6 + @as(u16, from)] == code) m[0x9EF6 + @as(u16, from)] = 0;
            m[list + slot] = @intCast(to);
            m[0x9EF6 + @as(u16, @intCast(to))] = code;
        }
    }.f;
    put(img, own, 4 + rng.uintLessThan(u16, 2), 4 + oc, r);
    put(img, foe, 6, 5 + fc, q);
    img[board + @as(u16, @intCast(r + other))] = 0;
    img[board + @as(u16, @intCast(r - other))] = 0;
    put(img, foe, 2, 3 + fc, b1);
    img[board + @as(u16, @intCast(b2))] = 3 + fc;
    const codes = [_]i16{ 9, 11, -9, -11, 1, 10, -1, -10 };
    const code: u8 = @intCast(1 + (std.mem.indexOfScalar(i16, &codes, d) orelse return));
    img[(if (white) @as(u16, 0xA09E) else 0xA164) + @as(u16, @intCast(r))] = code + if (white) @as(u8, 0) else 8;
    img[(if (white) @as(u16, 0x37DA) else 0xA51C) + @as(u16, @intCast(r))] = 0;
}

fn sameImage(a: *const Image, b: *const Image, sp: u16) ?usize {
    const V = @Vector(64, u8);
    var i: usize = 0;
    while (i < a.len) : (i += 64) {
        const x: V = a[i..][0..64].*;
        const y: V = b[i..][0..64].*;
        if (@reduce(.Or, x != y)) {
            if (compareImage(a, b, sp, false)) |off| return off;
            return null;
        }
    }
    return null;
}

const Hits = std.StaticBitSet(0x10000);

/// On a mismatch: the lifted routine's path (labels) on the same input, its far calls
/// and the port's.
fn showPath(input: *const Image, regs: [8]u16, tag: u8, trace: *lifted.Trace, log: *const CallLog) error{MismatchWithLifted} {
    var copy = input.*;
    var m: Machine = .{ .mem = &copy, .ax = regs[0], .bx = regs[1], .cx = regs[2], .dx = regs[3], .si = regs[4], .di = regs[5], .bp = regs[6], .sp = regs[7] };
    trace.* = .{ .record_marks = true, .flagp = rw(input, regs[7] +% 8) };
    m.trace = trace;
    if (tag == 3) threats.runA026(&m, threats.entry_a026) else threats.runCD20(&m, threats.entry_cd20);
    std.debug.print("lifted path:", .{});
    for (trace.marks[0..@min(trace.nmarks, trace.marks.len)]) |mk| std.debug.print(" {X:0>4}", .{mk.label});
    std.debug.print("\nlifted calls:", .{});
    for (trace.calls[0..@min(trace.ncalls, trace.calls.len)]) |c| std.debug.print(" {s}({d},{d})={X:0>4}@{X:0>4}", .{ far_names[@backingInt(c.target)], c.sq, c.v, c.ax, c.site });
    std.debug.print("\nport calls:", .{});
    for (log.calls[0..@min(log.n, log.calls.len)]) |c| std.debug.print(" {s}({d},{d})={X:0>4}", .{ far_names[c.target], c.sq, c.v, c.ax });
    std.debug.print("\nking W {d} B {d}, queens W {d} B {d}, ply {d} lim {d} {d} {d}\n", .{ input[0xA041], input[0xA051], input[0xA040], input[0xA050], rw(input, regs[7] +% 4), rw(input, 0xA272), rw(input, 0x9356), rw(input, 0xA5EC) });
    return error.MismatchWithLifted;
}

test "evalthreats: the hand-written A026 and CD20 equal the lifted routines on generated calls" {
    const gpa = std.testing.allocator;
    const per_call: usize = if (builtin.mode == .debug) 4 else 90;
    var rng_state = std.Random.DefaultPrng.init(0xA026_CD20_7E57);
    const rng = rng_state.random();
    const img = try gpa.create(Image);
    defer gpa.destroy(img);
    const got = try gpa.create(Image);
    defer gpa.destroy(got);
    const ref = try gpa.create(Image);
    defer gpa.destroy(ref);
    const input = try gpa.create(Image);
    defer gpa.destroy(input);
    const aimg = try gpa.create(lifted.AttackerImage);
    defer gpa.destroy(aimg);
    aimg.init();
    const st = try gpa.create(State);
    defer gpa.destroy(st);
    const trace = try gpa.create(lifted.Trace);
    defer gpa.destroy(trace);
    const hits = try gpa.create(Hits);
    defer gpa.destroy(hits);
    hits.* = .empty;
    var log: CallLog = .{};
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
                    continue;
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
            const sp = regs[7];
            for (0..per_call) |k| {
                @memcpy(ref, img);
                if (k > 0) mutate(rng, ref, sp);
                if (k > 0 and k % 2 == 0) mutateMore(rng, ref, tag);
                @memcpy(input, ref);
                @memcpy(got, ref);
                var mr: Machine = .{ .mem = ref, .ax = regs[0], .bx = regs[1], .cx = regs[2], .dx = regs[3], .si = regs[4], .di = regs[5], .bp = regs[6], .sp = sp };
                trace.* = .{ .hits = hits };
                mr.trace = trace;
                if (tag == 3) threats.runA026(&mr, threats.entry_a026) else threats.runCD20(&mr, threats.entry_cd20);
                st.* = .{};
                log.n = 0;
                const ax = runPort(st, got, sp, tag, aimg, &log);
                const where = .{ name, names[tag], k };
                for (0..@min(trace.ncalls, log.n)) |i| {
                    const w = trace.calls[i];
                    const g = log.calls[i];
                    if (@backingInt(w.target) != g.target or w.sq != g.sq or w.v != g.v or w.ax != g.ax) {
                        std.debug.print("\n{s} ({s}) mutation {d}: far call {d}: lifted {s}({d}, {d}) = {X:0>4} at {X:0>4}, port {s}({d}, {d}) = {X:0>4}\n", where ++ .{ i, far_names[@backingInt(w.target)], w.sq, w.v, w.ax, w.site, far_names[g.target], g.sq, g.v, g.ax });
                        return showPath(input, regs, tag, trace, &log);
                    }
                }
                if (trace.ncalls != log.n) {
                    std.debug.print("\n{s} ({s}) mutation {d}: far calls: lifted {d}, port {d}\n", where ++ .{ trace.ncalls, log.n });
                    return showPath(input, regs, tag, trace, &log);
                }
                if (ax != mr.ax) {
                    std.debug.print("\n{s} ({s}) mutation {d}: AX lifted {d}, port {d}\n", where ++ .{ @as(i16, @bitCast(mr.ax)), @as(i16, @bitCast(ax)) });
                    return showPath(input, regs, tag, trace, &log);
                }
                if (sameImage(got, ref, sp)) |off| {
                    std.debug.print("\n{s} ({s}) mutation {d}: DG:{X:0>4} lifted {X:0>2}, port {X:0>2}\n", where ++ .{ off, ref[off], got[off] });
                    return showPath(input, regs, tag, trace, &log);
                }
                compared[tag] += 1;
            }
        }
    }
    var reached: [2]usize = .{ 0, 0 };
    for (threats.labels_a026) |l| reached[0] += @intFromBool(hits.isSet(l));
    for (threats.labels_cd20) |l| reached[1] += @intFromBool(hits.isSet(l));
    std.debug.print("  labels not reached, A026:", .{});
    for (threats.labels_a026) |l| if (!hits.isSet(l)) std.debug.print(" {X:0>4}", .{l});
    std.debug.print("\n  CD20:", .{});
    for (threats.labels_cd20) |l| if (!hits.isSet(l)) std.debug.print(" {X:0>4}", .{l});
    std.debug.print("\n", .{});
    std.debug.print("evalthreats (hand-written) vs lifted: A026 {d}, CD20 {d} generated calls equal; labels reached: A026 {d} of {d}, CD20 {d} of {d}\n", .{ compared[3], compared[4], reached[0], threats.labels_a026.len, reached[1], threats.labels_cd20.len });
}

// ---------------------------------------------------------------------------
// Benchmarks (src/bench.zig): -Dbench=true -Dtest-filter="bench: evalthreats-hand"
// ---------------------------------------------------------------------------

const bench = @import("bench.zig");

const Patch = struct { off: u16, b: u8 };
/// One record: its input delta (XOR) and, for a threat call, the bytes the lifted
/// routine changes (undo list) and its recorded far-call answers.
const BenchRec = struct { tag: u8, regs: [8]u16, d0: u32, d1: u32, u0: u32 = 0, u1: u32 = 0, a0: u32 = 0, a1: u32 = 0 };

const BenchData = struct {
    recs: std.ArrayList(BenchRec) = .empty,
    delta: std.ArrayList(Patch) = .empty,
    undo: std.ArrayList(Patch) = .empty,
    answers: std.ArrayList(u16) = .empty,

    fn deinit(b: *BenchData, gpa: std.mem.Allocator) void {
        b.recs.deinit(gpa);
        b.delta.deinit(gpa);
        b.undo.deinit(gpa);
        b.answers.deinit(gpa);
    }
};

fn loadBenchData(gpa: std.mem.Allocator, b: *BenchData, name: []const u8, img: *Image, work: *Image) !void {
    const data = try readVectors(gpa, name);
    defer gpa.free(data);
    var c: Cursor = .{ .d = data[6..] };
    img.* = @splat(0);
    const r0 = b.recs.items.len;
    while (true) {
        const tag = c.byte();
        if (tag == 0) break;
        var rec: BenchRec = .{ .tag = tag, .regs = undefined, .d0 = @intCast(b.delta.items.len), .d1 = 0 };
        {
            const n = c.varint();
            var prev: isize = -1;
            for (0..n) |_| {
                const off: usize = @intCast(prev + 1 + @as(isize, @intCast(c.varint())));
                const x = c.byte();
                img[off] ^= x;
                try b.delta.append(gpa, .{ .off = @intCast(off), .b = x });
                prev = @intCast(off);
            }
        }
        rec.d1 = @intCast(b.delta.items.len);
        for (&rec.regs) |*r| r.* = c.word();
        switch (tag) {
            1, 2 => {
                _ = c.word();
                c.skipDelta();
            },
            3, 4 => {
                _ = c.word();
                const n = c.varint();
                const calls = c.take(n * 9);
                _ = c.word();
                c.skipDelta();
                if (c.byte() != 0) _ = c.take(c.varint() * 25);
                rec.a0 = @intCast(b.answers.items.len);
                for (0..n) |k| try b.answers.append(gpa, std.mem.readInt(u16, calls[k * 9 + 7 ..][0..2], .little));
                rec.a1 = @intCast(b.answers.items.len);
                work.* = img.*;
                var m: Machine = .{ .mem = work, .ax = rec.regs[0], .bx = rec.regs[1], .cx = rec.regs[2], .dx = rec.regs[3], .si = rec.regs[4], .di = rec.regs[5], .bp = rec.regs[6], .sp = rec.regs[7] };
                if (tag == 3) threats.runA026(&m, threats.entry_a026) else threats.runCD20(&m, threats.entry_cd20);
                rec.u0 = @intCast(b.undo.items.len);
                for (0..0x10000) |i| if (work[i] != img[i]) try b.undo.append(gpa, .{ .off = @intCast(i), .b = img[i] });
                rec.u1 = @intCast(b.undo.items.len);
            },
            else => return error.BadVectorFile,
        }
        try b.recs.append(gpa, rec);
    }
    // a file starts from an empty image: mark its first record
    b.recs.items[r0].tag |= 0x80;
}

/// The far calls answered from the recording: the evaluator's own cost.
const RecordedCallees = struct {
    answers: []const u16,
    i: *usize,
    pub fn see(c: RecordedCallees, side: Side, square: u8, value: u16) u16 {
        _ = .{ side, square, value };
        const r = c.answers[c.i.*];
        c.i.* += 1;
        return r;
    }
    pub fn att(c: RecordedCallees, side: Side, square: u8, value: u16) u16 {
        _ = .{ side, square, value };
        const r = c.answers[c.i.*];
        c.i.* += 1;
        return r;
    }
};

/// The far routines as the engine will bind them: both hand-written, on the position.
const DirectCallees = struct {
    st: *State,
    pub fn see(c: DirectCallees, side: Side, square: u8, value: u16) u16 {
        return seemod.see(&c.st.p, &c.st.s, side, square, value);
    }
    pub fn att(c: DirectCallees, side: Side, square: u8, value: u16) u16 {
        return @import("pinexchange.zig").exchange(&c.st.p, &c.st.s, side, square, value);
    }
};

const BenchMode = enum { overhead, lifted, port, port_direct, port_recorded, port_direct_fixed, port_direct_fixed6 };

/// DEV-020, DEV-022 and DEV-041 corrected, and DEV-023 in the attacker routine: what the engine
/// runs with the fixes on.
const bench_fixes: pos.Fixes = .{ .dev001_ep_hash_square = false, .dev020_threat_table_index = true, .dev022_captured_pieces = true, .dev023_pinned_bishop = true, .dev041_threat_mirror = true };

/// `DirectCallees` with DEV-023 corrected.
const DirectCalleesFixed = struct {
    st: *State,
    pub fn see(c: DirectCalleesFixed, side: Side, square: u8, value: u16) u16 {
        return seemod.see(&c.st.p, &c.st.s, side, square, value);
    }
    pub fn att(c: DirectCalleesFixed, side: Side, square: u8, value: u16) u16 {
        return @import("pinexchange.zig").exchangeFixes(bench_fixes, &c.st.p, &c.st.s, side, square, value);
    }
};

/// `bench_fixes` with DEV-021 and DEV-052 corrected as well.
const bench_fixes6: pos.Fixes = blk: {
    var f = bench_fixes;
    f.dev021_knight_escape_order = true;
    f.dev052_line_tables = true;
    break :blk f;
};

fn benchPass(b: *const BenchData, img: *Image, st: *State, aimg: *lifted.AttackerImage, want: u8, comptime mode: BenchMode) usize {
    var n: usize = 0;
    for (b.recs.items) |rec| {
        if (rec.tag & 0x80 != 0) img.* = @splat(0);
        for (b.delta.items[rec.d0..rec.d1]) |p| img[p.off] ^= p.b;
        const tag = rec.tag & 0x7F;
        if (tag != want) continue;
        n += 1;
        const sp = rec.regs[7];
        switch (mode) {
            .overhead => {
                st.load(img, sp);
                bench.keep(st);
            },
            .lifted => {
                const r = rec.regs;
                var m: Machine = .{ .mem = img, .ax = r[0], .bx = r[1], .cx = r[2], .dx = r[3], .si = r[4], .di = r[5], .bp = r[6], .sp = r[7] };
                if (tag == 3) threats.runA026(&m, threats.entry_a026) else threats.runCD20(&m, threats.entry_cd20);
                bench.keep(m.ax);
                for (b.undo.items[rec.u0..rec.u1]) |p| img[p.off] = p.b;
            },
            .port => {
                st.load(img, sp);
                const c: Callees = .{ .st = st, .img = aimg, .log = null };
                const r = if (tag == 3)
                    et.evalThreatsWhite(&st.p, &st.v, &st.t, &st.s, c, &st.ply, st.m, &st.flag)
                else
                    et.evalThreatsBlack(&st.p, &st.v, &st.t, &st.s, c, &st.ply, st.m, &st.flag);
                bench.keep(r);
            },
            .port_direct => {
                st.load(img, sp);
                const c: DirectCallees = .{ .st = st };
                const r = if (tag == 3)
                    et.evalThreatsWhite(&st.p, &st.v, &st.t, &st.s, c, &st.ply, st.m, &st.flag)
                else
                    et.evalThreatsBlack(&st.p, &st.v, &st.t, &st.s, c, &st.ply, st.m, &st.flag);
                bench.keep(r);
            },
            .port_direct_fixed => {
                st.load(img, sp);
                const c: DirectCalleesFixed = .{ .st = st };
                const r = if (tag == 3)
                    et.evalThreatsFixes(bench_fixes, .white, &st.p, &st.v, &st.t, &st.s, c, &st.ply, st.m, &st.flag)
                else
                    et.evalThreatsFixes(bench_fixes, .black, &st.p, &st.v, &st.t, &st.s, c, &st.ply, st.m, &st.flag);
                bench.keep(r);
            },
            .port_direct_fixed6 => {
                st.load(img, sp);
                const c: DirectCalleesFixed = .{ .st = st };
                const r = if (tag == 3)
                    et.evalThreatsFixes(bench_fixes6, .white, &st.p, &st.v, &st.t, &st.s, c, &st.ply, st.m, &st.flag)
                else
                    et.evalThreatsFixes(bench_fixes6, .black, &st.p, &st.v, &st.t, &st.s, c, &st.ply, st.m, &st.flag);
                bench.keep(r);
            },
            .port_recorded => {
                st.load(img, sp);
                var i: usize = 0;
                const c: RecordedCallees = .{ .answers = b.answers.items[rec.a0..rec.a1], .i = &i };
                const r = if (tag == 3)
                    et.evalThreatsWhite(&st.p, &st.v, &st.t, &st.s, c, &st.ply, st.m, &st.flag)
                else
                    et.evalThreatsBlack(&st.p, &st.v, &st.t, &st.s, c, &st.ply, st.m, &st.flag);
                bench.keep(r);
            },
        }
    }
    return n;
}

test "bench: evalthreats-hand: hand-written A026 and CD20 against the lifted routines" {
    if (!bench.enabled) return;
    const gpa = std.testing.allocator;
    const img = try gpa.create(Image);
    defer gpa.destroy(img);
    const work = try gpa.create(Image);
    defer gpa.destroy(work);
    const st = try gpa.create(State);
    defer gpa.destroy(st);
    st.* = .{};
    const aimg = try gpa.create(lifted.AttackerImage);
    defer gpa.destroy(aimg);
    aimg.init();
    var b: BenchData = .{};
    defer b.deinit(gpa);
    for (files) |f| try loadBenchData(gpa, &b, f, img, work);
    const passes = 30;
    for ([_]u8{ 3, 4 }) |tag| {
        var over: bench.Best = .{};
        var best: [6]bench.Best = .{ .{}, .{}, .{}, .{}, .{}, .{} };
        var n: usize = 0;
        for (0..passes) |_| {
            var t0 = bench.now();
            n = benchPass(&b, img, st, aimg, tag, .overhead);
            over.pass(t0);
            t0 = bench.now();
            _ = benchPass(&b, img, st, aimg, tag, .lifted);
            best[0].pass(t0);
            t0 = bench.now();
            _ = benchPass(&b, img, st, aimg, tag, .port);
            best[1].pass(t0);
            t0 = bench.now();
            _ = benchPass(&b, img, st, aimg, tag, .port_recorded);
            best[2].pass(t0);
            t0 = bench.now();
            _ = benchPass(&b, img, st, aimg, tag, .port_direct);
            best[3].pass(t0);
            t0 = bench.now();
            _ = benchPass(&b, img, st, aimg, tag, .port_direct_fixed);
            best[4].pass(t0);
            t0 = bench.now();
            _ = benchPass(&b, img, st, aimg, tag, .port_direct_fixed6);
            best[5].pass(t0);
        }
        // the lifted pass has no state load; its overhead is the delta replay alone,
        // measured as the overhead pass less the loads, which the port passes include
        var replay: bench.Best = .{};
        for (0..passes) |_| {
            const t0 = bench.now();
            _ = benchPass(&b, img, st, aimg, 0, .overhead);
            replay.pass(t0);
        }
        const w = if (tag == 3) "A026" else "CD20";
        var label: [96]u8 = undefined;
        best[0].report(std.fmt.bufPrint(&label, "evalthreats-hand: {s} lifted, far calls included", .{w}) catch unreachable, n, passes, replay.ns);
        best[1].report(std.fmt.bufPrint(&label, "evalthreats-hand: {s} hand-written, far calls included", .{w}) catch unreachable, n, passes, over.ns);
        best[2].report(std.fmt.bufPrint(&label, "evalthreats-hand: {s} hand-written, far calls answered from the recording", .{w}) catch unreachable, n, passes, over.ns);
        best[3].report(std.fmt.bufPrint(&label, "evalthreats-hand: {s} hand-written, see.see and pinexchange.exchange", .{w}) catch unreachable, n, passes, over.ns);
        best[4].report(std.fmt.bufPrint(&label, "evalthreats-hand: {s} the same, DEV-020, 022, 023 and 041 corrected", .{w}) catch unreachable, n, passes, over.ns);
        best[5].report(std.fmt.bufPrint(&label, "evalthreats-hand: {s} the same, and DEV-021 and 052 corrected", .{w}) catch unreachable, n, passes, over.ns);
    }
}

// ---------------------------------------------------------------------------
// DEV-041: one position for each place corrected
// ---------------------------------------------------------------------------

/// A State built from a FEN by the original's own set-up (src/setup.zig), with depth
/// limits 4, 6, 8, iteration 3 and m = 0.
fn stateFromFen(text: []const u8, ply: u16, st: *State) !void {
    const d = try @import("fen.zig").parse(text);
    st.* = .{};
    var sv: @import("setup.zig").SetupVars = .{};
    @import("setup.zig").buildFromDescription(&st.p, &sv, &d);
    st.t = .{ .ply_limit1 = 4, .ply_limit2 = 6, .ply_limit3 = 8, .iteration = 3 };
    st.ply = ply;
    st.m = 0;
}

test "evalthreats: DEV-041, a position for each place corrected" {
    const gpa = std.testing.allocator;
    const base = try gpa.create(State);
    defer gpa.destroy(base);
    const a = try gpa.create(State);
    defer gpa.destroy(a);
    const b = try gpa.create(State);
    defer gpa.destroy(b);
    const Case = struct { fen: []const u8, ply: u16, site: et.Site041, cd20: i16, a026: i16, corrected: i16 };
    const cases = [_]Case{
        // D117: Black king a7, White queen d5 on the a8-h1 diagonal through b7, a8 held
        // by the knight b6. CD20 tests the corner a8 only for a queen on a6.
        .{ .fen = "8/k5pp/1N6/3Q4/8/8/5PPP/6K1 b - - 0 1", .ply = 2, .site = .corner_a7, .cd20 = 0, .a026 = -5000, .corrected = 5000 },
        // D32D: the same on the h-side: king h7, queen e5, h8 held by the knight g6.
        .{ .fen = "8/pp5k/6N1/4Q3/8/8/PPP5/1K6 b - - 0 1", .ply = 2, .site = .corner_h7, .cd20 = 0, .a026 = -5000, .corrected = 5000 },
        // E250: the rook d7 pinned to the king e8 by the queen c6; White bishops on c8
        // (next to the rook) and f5 (two away) on the other diagonal. CD20 walks to c8
        // first, the mirror to f5.
        .{ .fen = "2B1k3/pp1r2pp/2Q5/5B2/8/8/PPP5/1K6 b - - 0 1", .ply = 7, .site = .rook_other_diagonal, .cd20 = 584, .a026 = -284, .corrected = 284 },
    };
    inline for (cases) |cs| {
        try stateFromFen(cs.fen, cs.ply, base);
        const r3 = mirrorPair(fix3, .{}, base, 4, a, b, null);
        a.* = base.*;
        const one = runProbe(fix4, .{ .dev041_only = cs.site }, .black, a, null);
        a.* = base.*;
        const all = runProbe(fix4, .{}, .black, a, null);
        std.debug.print("  DEV-041 {s}: {s}: CD20 {d} (flag {d}), A026 on the mirror {d} (flag {d}), CD20 corrected {d} (flag {d})\n", .{ @tagName(cs.site), cs.fen, r3[1].ax, r3[1].flag, r3[0].ax, r3[0].flag, one.ax, one.flag });
        try std.testing.expect(!agree(r3));
        try std.testing.expect(agree(.{ r3[0], one }));
        try std.testing.expect(agree(.{ r3[0], all }));
        try std.testing.expectEqual(cs.cd20, r3[1].ax);
        try std.testing.expectEqual(cs.a026, r3[0].ax);
        try std.testing.expectEqual(cs.corrected, one.ax);
    }
}

// ---------------------------------------------------------------------------
// DEV-021 and DEV-052: a position for each
// ---------------------------------------------------------------------------

test "evalthreats: DEV-021 and DEV-052, a position for each" {
    const gpa = std.testing.allocator;
    const base = try gpa.create(State);
    defer gpa.destroy(base);
    const a = try gpa.create(State);
    defer gpa.destroy(a);
    const b = try gpa.create(State);
    defer gpa.destroy(b);
    // DEV-021: the Black knight e5, attacked by the pawn d4, has the pawn c6 (attacked by
    // the bishop a4) and the bishop g6 (attacked by the rook g1) as its first pair of
    // squares, +8 and +12. CD20 visits c6 first and pays for the pawn before the bishop
    // ends the search; the mirror of A026's order visits g6 first and stops there.
    {
        try stateFromFen("k7/8/2p3b1/4n3/B2P4/8/8/6RK b - - 0 1", 2, base);
        const before = mirrorPair(fix4, .{}, base, 4, a, b, null);
        const after = mirrorPair(fix5, .{}, base, 4, a, b, null);
        a.* = base.*;
        const orig = runProbe(pos.Fixes.original, .{}, .black, a, null);
        a.* = base.*;
        const alone = runProbe(fix021, .{}, .black, a, null);
        std.debug.print("  DEV-021: CD20 original {d} (flag {d}), corrected alone {d} (flag {d}); after DEV-020/022/023/041: CD20 {d} (flag {d}), A026 on the mirror {d} (flag {d}), CD20 corrected {d} (flag {d})\n", .{ orig.ax, orig.flag, alone.ax, alone.flag, before[1].ax, before[1].flag, before[0].ax, before[0].flag, after[1].ax, after[1].flag });
        try std.testing.expect(!agree(before));
        try std.testing.expect(agree(after));
        try std.testing.expect(orig.ax != alone.ax or orig.flag != alone.flag);
        // the pawn's L02 -200 and the flag (with the flag above 1, L04 is not added)
        try std.testing.expectEqual(Result{ .ax = 1050, .flag = 4 }, orig);
        try std.testing.expectEqual(Result{ .ax = -850, .flag = 3 }, before[0]);
        try std.testing.expectEqual(Result{ .ax = 850, .flag = 3 }, alone);
    }
    // DEV-052: the White rook g7 and the Black rook a8 differ by -4, which the orthogonal
    // table takes for a rank (a pseudo-line across the border column), so A026 calls the
    // attacker routine on g7, which finds the rook g8's attack down the file (a file
    // attack that test does not look for); in the mirror (a1, g2: +16) CD20 makes no call.
    {
        try stateFromFen("r5r1/6R1/8/2k5/8/8/8/1K6 w - - 0 1", 2, base);
        const before = mirrorPair(fix5, .{}, base, 3, a, b, null);
        const after = mirrorPair(fix6, .{}, base, 3, a, b, null);
        a.* = base.*;
        const orig = runProbe(pos.Fixes.original, .{}, .white, a, null);
        a.* = base.*;
        const alone = runProbe(fix052, .{}, .white, a, null);
        std.debug.print("  DEV-052: A026 original {d} (flag {d}), corrected alone {d} (flag {d}); after the other fixes: A026 {d} (flag {d}), CD20 on the mirror {d} (flag {d}), A026 corrected {d} (flag {d})\n", .{ orig.ax, orig.flag, alone.ax, alone.flag, before[0].ax, before[0].flag, before[1].ax, before[1].flag, after[0].ax, after[0].flag });
        try std.testing.expect(!agree(before));
        try std.testing.expect(agree(after));
        try std.testing.expect(orig.ax != alone.ax or orig.flag != alone.flag);
        try std.testing.expectEqual(Result{ .ax = -574, .flag = 3 }, orig);
        try std.testing.expectEqual(Result{ .ax = 0, .flag = 1 }, before[1]);
        try std.testing.expectEqual(Result{ .ax = 0, .flag = 1 }, alone);
    }
}
