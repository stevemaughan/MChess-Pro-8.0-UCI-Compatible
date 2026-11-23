//! Differential tests of src/helpers.zig against calls of the original recorded in games
//! and on made-up positions (tests/golden/helpers/*.zst, made by
//! tools/port/gen_helpers_vectors.py, whose docstring defines the format).

const std = @import("std");
const pos = @import("position.zig");
const mg = @import("movegen.zig");
const h = @import("helpers.zig");
const dg = @import("original.zig").dgroup;

const max_ply_lists = 35;

/// The state of one recorded call, as the port holds it.
const State = struct {
    p: pos.Position = .{},
    v: mg.SearchVars = .{},
    lists: [max_ply_lists]mg.MoveList = @splat(@splat(.{ .from = 0, .to = 0, .flag = 0 })),
};

/// The image's regions, in the recorder's order (IMAGE_REGIONS).
const Region = struct { name: []const u8, dg: u16, len: usize };
const regions = [_]Region{
    .{ .name = "board", .dg = 0x9EF6, .len = 120 },
    .{ .name = "piece lists", .dg = 0xA03A, .len = 32 },
    .{ .name = "White pawn attacks", .dg = 0xA51C, .len = 120 },
    .{ .name = "Black pawn attacks", .dg = 0x37DA, .len = 120 },
    .{ .name = "White king rays", .dg = 0xA09E, .len = 120 },
    .{ .name = "Black king rays", .dg = 0xA164, .len = 120 },
    .{ .name = "ep squares", .dg = 0x9EC8, .len = max_ply_lists },
    .{ .name = "check values", .dg = 0x8C06, .len = max_ply_lists },
    .{ .name = "marks", .dg = 0x781A, .len = mg.marks_len },
    .{ .name = "move lists", .dg = 0x3A34, .len = 400 * max_ply_lists },
};
const image_size = blk: {
    var n: usize = 0;
    for (regions) |r| n += r.len;
    break :blk n;
};
const Image = [image_size]u8;

/// Constant data the routines read, as the recorder writes it in the header.
const const_ranges = [_]struct { u16, u16 }{
    .{ 0x0470, 0x42 },            .{ 0x04B2, 0x04C0 + 8 * 14 - 0x04B2 }, .{ 0x0A68 - 255, 375 },
    .{ 0x0B66 - 255, 375 },       .{ 0x0C64 - 255, 375 },                .{ 0x0CFF - 255, 375 },
    .{ 0x1508, 16 },              .{ 0x1A52, 14 },                       .{ 0x1A80, 240 },
    .{ 0x28CC, 0x28F8 - 0x28CC },
};

fn transfer(comptime to_image: bool, st: *State, img: *Image) void {
    var o: usize = 0;
    const T = struct {
        fn bytes(comptime ti: bool, im: *Image, off: *usize, part: []u8) void {
            if (ti) @memcpy(im[off.*..][0..part.len], part) else @memcpy(part, im[off.*..][0..part.len]);
            off.* += part.len;
        }
    };
    const p = &st.p;
    T.bytes(to_image, img, &o, &p.board);
    T.bytes(to_image, img, &o, &p.piece_list);
    T.bytes(to_image, img, &o, &p.pawn_attacks[0]);
    T.bytes(to_image, img, &o, &p.pawn_attacks[1]);
    T.bytes(to_image, img, &o, &p.king_rays[0]);
    T.bytes(to_image, img, &o, &p.king_rays[1]);
    T.bytes(to_image, img, &o, p.ep_square_by_ply[0..max_ply_lists]);
    T.bytes(to_image, img, &o, p.check_by_ply[0..max_ply_lists]);
    T.bytes(to_image, img, &o, &st.v.marks);
    T.bytes(to_image, img, &o, std.mem.sliceAsBytes(&st.lists));
    std.debug.assert(o == image_size);
}

fn describe(buf: []u8, off: usize) []const u8 {
    var o: usize = 0;
    for (regions) |r| {
        if (off < o + r.len) {
            const i = off - o;
            if (r.dg == 0x3A34) return std.fmt.bufPrint(buf, "move list of ply {d}, entry {d}, byte {d} (DG:{X:0>4})", .{ i / 400, i % 400 / 4, i % 4, r.dg + i }) catch r.name;
            return std.fmt.bufPrint(buf, "{s}[{d}] (DG:{X:0>4})", .{ r.name, i, r.dg + i }) catch r.name;
        }
        o += r.len;
    }
    return "?";
}

const Cursor = struct {
    d: []const u8,
    i: usize = 0,

    fn byte(c: *Cursor) u8 {
        const v = c.d[c.i];
        c.i += 1;
        return v;
    }
    fn int(c: *Cursor, comptime T: type) T {
        const n = @sizeOf(T);
        const v = std.mem.readInt(T, c.d[c.i..][0..n], .little);
        c.i += n;
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
    fn apply(c: *Cursor, img: *Image) void {
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
    const path = try std.fmt.bufPrint(&path_buf, "{s}/helpers/{s}", .{ dir, name });
    const compressed = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, gpa, .limited(64 << 20));
    defer gpa.free(compressed);
    var in: std.Io.Reader = .fixed(compressed);
    const window = try gpa.alloc(u8, std.compress.zstd.default_window_len + std.compress.zstd.block_size_max);
    defer gpa.free(window);
    var zd = std.compress.zstd.Decompress.init(&in, window, .{});
    return zd.reader.allocRemaining(gpa, .limited(512 << 20));
}

const ntags = 9;
const names = [ntags + 1][]const u8{
    "",                                          "white_attacks_square_no_pawns (0000:1C76)", "black_attacks_square_no_pawns (0000:1DE6)",
    "hash_move_plausible_white (0000:1F56)",     "hash_move_plausible_black (0000:211E)",     "count_attacked, White to move (1E9D:CE3E)",
    "count_attacked, Black to move (1E9D:CC4E)", "gen_evasions (38C0:E260)",                  "white_attacks_square (2B9F:4A76)",
    "black_attacks_square (2B9F:4AD4)",
};

const Counts = struct {
    replayed: [ntags + 1]usize = @splat(0),
    skipped: [ntags + 1]usize = @splat(0),
    /// Per tag: results 0, results non-zero (for E260: FFFFh returns, empty lists), and
    /// for E260 the promotions and en-passant moves in the returned lists.
    zero: [ntags + 1]usize = @splat(0),
    nonzero: [ntags + 1]usize = @splat(0),
    promotions: usize = 0,
    en_passant: usize = 0,
    /// DEV-024: recorded counter calls whose result the correction changes, and those
    /// where the corrected count differs from `meantCount`.
    dev024_changed: usize = 0,
    dev024_first_captured: usize = 0,
    dev024_not_meant: usize = 0,
    /// DEV-053: recorded counter calls whose result DEV-053 alone changes (against the
    /// original), and DEV-053 with DEV-024 (against DEV-024 alone); with both on, those
    /// that differ from `meantCount`, and those that differ from the colour mirror's count
    /// (with DEV-024 alone, for comparison).
    dev053_alone_changed: usize = 0,
    dev053_changed: usize = 0,
    dev053_not_meant: usize = 0,
    dev053_mirror_differs: usize = 0,
    dev024_mirror_differs: usize = 0,
};

/// The arguments of one recorded call.
const Call = struct {
    tag: u8,
    sq: u16 = 0,
    move: pos.Move = .{ .from = 0, .to = 0, .flag = 0 },
    side: pos.Side = .white,
    ply: usize = 0,
};

/// Runs routine `call.tag` on the state; null if it is not ported yet.
fn run(st: *State, call: *Call) ?u16 {
    const p = &st.p;
    return switch (call.tag) {
        1 => h.attacksSquareNoPawns(p, .white, call.sq),
        2 => h.attacksSquareNoPawns(p, .black, call.sq),
        3 => h.hashMovePlausible(p, .white, &call.move),
        4 => h.hashMovePlausible(p, .black, &call.move),
        5 => h.countAttacked(p, .white),
        6 => h.countAttacked(p, .black),
        7 => h.genEvasions(p, &st.v, &st.lists[call.ply], call.side, call.ply),
        8 => h.attacksSquare(p, .white, call.sq),
        9 => h.attacksSquare(p, .black, call.sq),
        else => null,
    };
}

fn replay(gpa: std.mem.Allocator, name: []const u8) !Counts {
    const data = try readVectors(gpa, name);
    defer gpa.free(data);
    var c: Cursor = .{ .d = data };
    try std.testing.expectEqualSlices(u8, "MCHV", c.take(4));
    try std.testing.expectEqual(@as(u16, 1), c.int(u16));
    try std.testing.expectEqual(@as(u16, image_size), c.int(u16));
    try std.testing.expectEqual(@as(u16, const_ranges.len), c.int(u16));
    inline for (const_ranges) |r| {
        try std.testing.expectEqual(r[0], c.int(u16));
        try std.testing.expectEqual(r[1], c.int(u16));
        try std.testing.expectEqualSlices(u8, &dg(r[0], r[1]), c.take(r[1]));
    }

    var truth: Image = c.take(image_size)[0..image_size].*;
    const st = try gpa.create(State);
    defer gpa.destroy(st);
    const got = try gpa.create(Image);
    defer gpa.destroy(got);
    var counts: Counts = .{};
    var index: usize = 0;
    while (true) {
        const tag = c.byte();
        var call: Call = .{ .tag = tag };
        switch (tag) {
            0 => {
                for (1..ntags + 1) |t| try std.testing.expectEqual(counts.replayed[t] + counts.skipped[t], c.int(u32));
                return counts;
            },
            0xFE => {
                @memcpy(&truth, c.take(image_size));
                continue;
            },
            1, 2, 8, 9 => call.sq = c.int(u16),
            3, 4 => {
                call.move.from = c.byte();
                call.move.to = c.byte();
            },
            5, 6 => {},
            7 => {
                call.side = if (c.byte() == 0) .white else .black;
                call.ply = c.byte();
            },
            else => return error.BadRecordTag,
        }
        const move_before = call.move;
        c.apply(&truth);
        const ax = c.int(u16);
        st.* = .{};
        transfer(false, st, &truth);
        if (tag == 5 or tag == 6) {
            const side: pos.Side = if (tag == 5) .white else .black;
            const fixed = switch (side) {
                .white => h.countAttackedFixes(fixed_024, &st.p, .white),
                .black => h.countAttackedFixes(fixed_024, &st.p, .black),
            };
            if (fixed != ax) {
                counts.dev024_changed += 1;
                if (st.p.piece_list[@as(usize, if (side == .white) 2 else 18)] >= 120) counts.dev024_first_captured += 1;
            }
            if (fixed != meantCount(&st.p, side)) counts.dev024_not_meant += 1;
            const alone = countSide(fixed_053, &st.p, side);
            const both = countSide(fixed_024_053, &st.p, side);
            if (alone != ax) counts.dev053_alone_changed += 1;
            if (both != fixed) counts.dev053_changed += 1;
            if (both != meantCount(&st.p, side)) counts.dev053_not_meant += 1;
            var m: pos.Position = .{};
            mirrorCounterState(&st.p, &m);
            if (both != countSide(fixed_024_053, &m, side.other())) counts.dev053_mirror_differs += 1;
            if (fixed != countSide(fixed_024, &m, side.other())) counts.dev024_mirror_differs += 1;
        }
        const result = run(st, &call);
        c.apply(&truth);
        const from_after: ?u8 = if (tag == 3 or tag == 4) c.byte() else null;
        if (result) |got_ax| {
            transfer(true, st, got);
            const move_ok = from_after == null or call.move.from == from_after.?;
            if (got_ax != ax or !move_ok or !std.mem.eql(u8, &truth, got)) {
                var buf: [96]u8 = undefined;
                std.debug.print("\n{s}: call {d} differs: {s}", .{ name, index, names[tag] });
                switch (tag) {
                    1, 2, 8, 9 => std.debug.print("(sq {d})", .{call.sq}),
                    3, 4 => std.debug.print("(move from {d} to {d})", .{ move_before.from, move_before.to }),
                    7 => std.debug.print("(side {d}, ply {d})", .{ @backingInt(call.side), call.ply }),
                    else => std.debug.print("()", .{}),
                }
                std.debug.print(": AX want {X:0>4}, got {X:0>4}\n", .{ ax, got_ax });
                if (!move_ok) std.debug.print("  the move's from byte: want {d}, got {d}\n", .{ from_after.?, call.move.from });
                for (truth, got, 0..) |want, have, off| {
                    if (want != have) {
                        std.debug.print("  first differing byte: {s}: want {X:0>2}, got {X:0>2}\n", .{ describe(&buf, off), want, have });
                        break;
                    }
                }
                return error.MismatchWithOriginal;
            }
            counts.replayed[tag] += 1;
            if (tag == 7) {
                if (ax == h.king_capture) counts.nonzero[tag] += 1 else if (ax == 0) counts.zero[tag] += 1;
                if (ax != h.king_capture) for (st.lists[call.ply][0..ax]) |m| switch (m.flag) {
                    pos.flag_en_passant => counts.en_passant += 1,
                    2...5 => counts.promotions += 1,
                    else => {},
                };
            } else if (ax == 0) counts.zero[tag] += 1 else counts.nonzero[tag] += 1;
        } else {
            counts.skipped[tag] += 1;
        }
        index += 1;
    }
}

const runs = [_][]const u8{ "A.zst", "E.zst", "probe.zst" };

// ---------------------------------------------------------------------------
// Benchmark
// ---------------------------------------------------------------------------

const bench = @import("bench.zig");

/// The inputs of one recorded call: every field a helper reads; the marks sparse.
const BenchInput = struct {
    board: [120]u8,
    piece_list: [32]u8,
    pawn_attacks: [2][120]u8,
    king_rays: [2][120]u8,
    ep: u8,
    chk: u8,
    call: Call,
    marks_from: u32,
    marks_to: u32,
};

const MarkByte = struct { at: u16, v: u8 };

/// Every `bench_stride`-th recorded call of a routine is kept, at most `bench_cap`, so the
/// inputs stay in the cache and sample the whole game.
const bench_cap = 6_000;
const bench_stride = 4;

const BenchData = struct {
    calls: [ntags + 1]std.ArrayList(BenchInput) = @splat(.empty),
    seen: [ntags + 1]usize = @splat(0),
    marks: std.ArrayList(MarkByte) = .empty,

    fn deinit(d: *BenchData, gpa: std.mem.Allocator) void {
        for (&d.calls) |*l| l.deinit(gpa);
        d.marks.deinit(gpa);
    }
};

fn collect(gpa: std.mem.Allocator, name: []const u8, d: *BenchData) !void {
    const data = try readVectors(gpa, name);
    defer gpa.free(data);
    var c: Cursor = .{ .d = data };
    _ = c.take(4 + 6);
    inline for (const_ranges) |r| _ = c.take(4 + r[1]);
    var truth: Image = c.take(image_size)[0..image_size].*;
    const st = try gpa.create(State);
    defer gpa.destroy(st);
    while (true) {
        const tag = c.byte();
        var call: Call = .{ .tag = tag };
        switch (tag) {
            0 => return,
            0xFE => {
                @memcpy(&truth, c.take(image_size));
                continue;
            },
            1, 2, 8, 9 => call.sq = c.int(u16),
            3, 4 => {
                call.move.from = c.byte();
                call.move.to = c.byte();
            },
            5, 6 => {},
            7 => {
                call.side = if (c.byte() == 0) .white else .black;
                call.ply = c.byte();
            },
            else => return error.BadRecordTag,
        }
        c.apply(&truth);
        _ = c.int(u16);
        d.seen[tag] += 1;
        if (d.seen[tag] % bench_stride != 0 or d.calls[tag].items.len >= bench_cap) {
            c.apply(&truth);
            if (tag == 3 or tag == 4) _ = c.byte();
            continue;
        }
        st.* = .{};
        transfer(false, st, &truth);
        const from: u32 = @intCast(d.marks.items.len);
        if (tag == 7) {
            for (st.v.marks, 0..) |m, i| if (m != 0) try d.marks.append(gpa, .{ .at = @intCast(i), .v = m });
        }
        try d.calls[tag].append(gpa, .{
            .board = st.p.board,
            .piece_list = st.p.piece_list,
            .pawn_attacks = st.p.pawn_attacks,
            .king_rays = st.p.king_rays,
            .ep = st.p.ep_square_by_ply[call.ply],
            .chk = st.p.check_by_ply[call.ply],
            .call = call,
            .marks_from = from,
            .marks_to = @intCast(d.marks.items.len),
        });
        c.apply(&truth);
        if (tag == 3 or tag == 4) _ = c.byte();
    }
}

fn loadInput(st: *State, in: *const BenchInput, marks: []const MarkByte) void {
    st.p.board = in.board;
    st.p.piece_list = in.piece_list;
    st.p.pawn_attacks = in.pawn_attacks;
    st.p.king_rays = in.king_rays;
    st.p.ep_square_by_ply[in.call.ply] = in.ep;
    st.p.check_by_ply[in.call.ply] = in.chk;
    for (marks[in.marks_from..in.marks_to]) |m| st.v.marks[m.at] = m.v;
}

fn clearMarks(st: *State, in: *const BenchInput, marks: []const MarkByte) void {
    for (marks[in.marks_from..in.marks_to]) |m| st.v.marks[m.at] = 0;
}

test "bench: helpers: the search helpers over the recorded calls" {
    if (!bench.enabled) return;
    const gpa = std.heap.page_allocator;
    var d: BenchData = .{};
    defer d.deinit(gpa);
    // The game runs only: the probe's made-up positions are mostly not in check.
    for (runs[0..2]) |name| try collect(gpa, name, &d);
    const st = try gpa.create(State);
    defer gpa.destroy(st);
    st.* = .{};
    const passes = 40;
    for (1..ntags + 1) |tag| {
        const calls = d.calls[tag].items;
        var best: bench.Best = .{};
        var over: bench.Best = .{};
        for (0..passes) |_| {
            var t0 = bench.now();
            for (calls) |*in| {
                loadInput(st, in, d.marks.items);
                var call = in.call;
                bench.keep(&st.p);
                bench.keep(&call);
                clearMarks(st, in, d.marks.items);
            }
            over.pass(t0);
            t0 = bench.now();
            var sum: u32 = 0;
            for (calls) |*in| {
                loadInput(st, in, d.marks.items);
                var call = in.call;
                sum +%= run(st, &call).?;
                clearMarks(st, in, d.marks.items);
            }
            best.pass(t0);
            bench.keep(sum);
        }
        best.report(names[tag], calls.len, passes, over.ns);
    }
    // The counters as the engine runs them: DEV-024 alone, and DEV-024 with DEV-053.
    inline for (.{ fixed_024, fixed_024_053 }, .{ "count_attacked, both sides, DEV-024", "count_attacked, both sides, DEV-024 and DEV-053" }) |fx, label| {
        var cb: bench.Best = .{};
        var co: bench.Best = .{};
        var n: usize = 0;
        for (0..passes) |_| {
            var t0 = bench.now();
            for ([2]usize{ 5, 6 }) |tag| {
                for (d.calls[tag].items) |*in| {
                    loadInput(st, in, d.marks.items);
                    bench.keep(&st.p);
                }
            }
            co.pass(t0);
            t0 = bench.now();
            var sum: u32 = 0;
            n = 0;
            for ([2]usize{ 5, 6 }) |tag| {
                for (d.calls[tag].items) |*in| {
                    loadInput(st, in, d.marks.items);
                    sum +%= if (tag == 5) h.countAttackedFixes(fx, &st.p, .white) else h.countAttackedFixes(fx, &st.p, .black);
                    n += 1;
                }
            }
            cb.pass(t0);
            bench.keep(sum);
        }
        cb.report(label, n, passes, co.ns);
    }
    // gen_evasions as it was before the speed pass (src/helpers_reference.zig), timed the
    // same way, for comparison in the same run.
    const calls = d.calls[7].items;
    var best: bench.Best = .{};
    var over: bench.Best = .{};
    for (0..passes) |_| {
        var t0 = bench.now();
        for (calls) |*in| {
            loadInput(st, in, d.marks.items);
            bench.keep(&st.p);
            clearMarks(st, in, d.marks.items);
        }
        over.pass(t0);
        t0 = bench.now();
        var sum: u32 = 0;
        for (calls) |*in| {
            loadInput(st, in, d.marks.items);
            sum +%= ref.genEvasions(&st.p, &st.v, &st.lists[in.call.ply], in.call.side, in.call.ply);
            clearMarks(st, in, d.marks.items);
        }
        best.pass(t0);
        bench.keep(sum);
    }
    best.report("gen_evasions (38C0:E260), reference: before the speed pass", calls.len, passes, over.ns);
}

test "search helpers: replay every recorded call of the original" {
    const gpa = std.testing.allocator;
    var total: Counts = .{};
    for (runs) |file| {
        const n = try replay(gpa, file);
        for (1..ntags + 1) |t| {
            total.replayed[t] += n.replayed[t];
            total.skipped[t] += n.skipped[t];
            total.zero[t] += n.zero[t];
            total.nonzero[t] += n.nonzero[t];
        }
        total.promotions += n.promotions;
        total.en_passant += n.en_passant;
        total.dev024_changed += n.dev024_changed;
        total.dev024_first_captured += n.dev024_first_captured;
        total.dev024_not_meant += n.dev024_not_meant;
        total.dev053_alone_changed += n.dev053_alone_changed;
        total.dev053_changed += n.dev053_changed;
        total.dev053_not_meant += n.dev053_not_meant;
        total.dev053_mirror_differs += n.dev053_mirror_differs;
        total.dev024_mirror_differs += n.dev024_mirror_differs;
    }
    std.debug.print("DEV-024: the correction changes {d} of {d} recorded counter calls ({d} with the first bishop captured); the corrected count equals the plain count in all but {d}\n", .{ total.dev024_changed, total.replayed[5] + total.replayed[6], total.dev024_first_captured, total.dev024_not_meant });
    try std.testing.expectEqual(@as(usize, 0), total.dev024_not_meant);
    std.debug.print("DEV-053: alone it changes {d} recorded counter calls; with DEV-024 on, {d} more than DEV-024 alone; with both, {d} differ from the plain count and {d} from the colour mirror's count ({d} with DEV-024 alone)\n", .{ total.dev053_alone_changed, total.dev053_changed, total.dev053_not_meant, total.dev053_mirror_differs, total.dev024_mirror_differs });
    try std.testing.expectEqual(@as(usize, 0), total.dev053_not_meant);
    try std.testing.expectEqual(@as(usize, 0), total.dev053_mirror_differs);
    std.debug.print("helpers vectors ({d} files), calls replayed, all equal to the original:\n", .{runs.len});
    for (1..ntags + 1) |t| {
        std.debug.print("  {s}: {d}", .{ names[t], total.replayed[t] });
        if (t == 7) {
            std.debug.print(" ({d} empty lists, {d} FFFFh; {d} promotions, {d} en passant generated)", .{ total.zero[t], total.nonzero[t], total.promotions, total.en_passant });
        } else std.debug.print(" ({d} returned 0, {d} non-zero)", .{ total.zero[t], total.nonzero[t] });
        if (total.skipped[t] != 0) std.debug.print(" (+{d} not ported, skipped)", .{total.skipped[t]});
        std.debug.print("\n", .{});
    }
}

// ---------------------------------------------------------------------------
// The faster routines against the reference (src/helpers_reference.zig)
// ---------------------------------------------------------------------------

const ref = @import("helpers_reference.zig");
const setup = @import("setup.zig");
const fen = @import("fen.zig");
const see_mod = @import("see.zig");

/// Start positions of the random games: the start, open middlegames with castling and
/// en passant about, pawns about to promote, bare kings with sliders.
const diff_fens = [_][]const u8{
    "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1",
    "r1bqkb1r/pppp1ppp/2n2n2/4p3/2B1P3/5N2/PPPP1PPP/RNBQK2R w KQkq - 4 4",
    "r3k2r/p1ppqpb1/bn2pnp1/3PN3/1p2P3/2N2Q1p/PPPBBPPP/R3K2R w KQkq - 0 1",
    "8/2p5/3p4/KP5r/1R3p1k/8/4P1P1/8 w - - 0 1",
    "r3k2r/Pppp1ppp/1b3nbN/nP6/BBP1P3/q4N2/Pp1P2PP/R2Q1RK1 w kq - 0 1",
    "4k3/1P4P1/8/8/8/8/1p4p1/4K3 w - - 0 1",
    "3q3k/8/8/8/8/8/8/R2QK2R b - - 0 1",
    "r1b1k2r/ppppqppp/2n2n2/2b1p3/2B1P3/2NP1N2/PPP2PPP/R1BQK2R b KQkq - 0 6",
};

const DiffState = struct {
    p: pos.Position = .{},
    v: mg.SearchVars = .{},
    s: see_mod.Scratch = .{},
    list: mg.MoveList = @splat(.{ .from = 0, .to = 0, .flag = 0 }),
};

/// A random square of the board (21..98, not on the border files).
fn boardSquare(r: std.Random) u8 {
    return 21 + 10 * r.uintLessThan(u8, 8) + r.uintLessThan(u8, 8);
}

/// gen_evasions of both versions on copies of `p`, from the same list contents; the
/// returns, the lists and the positions after must be equal. Returns 1 (a case run).
fn compareEvasions(p: *const pos.Position, v: *const mg.SearchVars, side: pos.Side, ply: usize, r: std.Random) !usize {
    var a = p.*;
    var b = p.*;
    var la: mg.MoveList = undefined;
    r.bytes(std.mem.asBytes(&la));
    var lb = la;
    const ra = ref.genEvasions(&a, v, &la, side, ply);
    const rb = h.genEvasions(&b, v, &lb, side, ply);
    if (ra != rb or !std.mem.eql(u8, std.mem.asBytes(&la), std.mem.asBytes(&lb)) or
        !std.mem.eql(u8, std.mem.asBytes(&a), std.mem.asBytes(&b)))
    {
        std.debug.print("\ngen_evasions differs: side {d}, ply {d}, check {X:0>2}: reference {X:0>4}, new {X:0>4}\n", .{ @backingInt(side), ply, p.check_by_ply[ply], ra, rb });
        return error.DiffersFromReference;
    }
    return 1;
}

/// The other routines of the file on a random square, move and both sides.
fn compareOthers(p: *const pos.Position, r: std.Random) !void {
    const sq = boardSquare(r);
    inline for (.{ pos.Side.white, pos.Side.black }) |side| {
        try std.testing.expectEqual(ref.attacksSquareNoPawns(p, side, sq), h.attacksSquareNoPawns(p, side, sq));
        try std.testing.expectEqual(ref.attacksSquare(p, side, sq), h.attacksSquare(p, side, sq));
        try std.testing.expectEqual(ref.countAttacked(p, side), h.countAttacked(p, side));
        var ma: pos.Move = .{ .from = boardSquare(r), .to = boardSquare(r), .flag = 0 };
        var mb = ma;
        try std.testing.expectEqual(ref.hashMovePlausible(p, side, &ma), h.hashMovePlausible(p, side, &mb));
        try std.testing.expectEqual(ma, mb);
    }
}

/// The variants of one node: the check value as made; a random line code; a random
/// checker square; and the king ray maps and the board disturbed (squares holding the
/// check's code added on board squares, as a border square there would index the mark
/// table beyond its end, in the original too; an extra slider or knight put on
/// an empty square that no piece list knows; a piece taken off the board but left in
/// its list).
fn compareNode(st: *DiffState, side: pos.Side, ply: usize, r: std.Random) !usize {
    var n: usize = 0;
    const p = &st.p;
    const made = p.check_by_ply[ply];
    // Not in check (0) every square off the king's rays is "on the line": lists that can
    // pass 100 entries, which the search never asks for. Such nodes get a random code.
    if (made & 0x7F != 0) n += try compareEvasions(p, &st.v, side, ply, r);
    var q = p.*;
    const hi: u8 = if (r.boolean()) 0x80 else 0;
    q.check_by_ply[ply] = (1 + r.uintLessThan(u8, 20)) | hi;
    n += try compareEvasions(&q, &st.v, side, ply, r);
    q.check_by_ply[ply] = boardSquare(r) | hi;
    n += try compareEvasions(&q, &st.v, side, ply, r);
    // Disturbed.
    q = p.*;
    const chk: u8 = if (made & 0x7F != 0 and made & 0x7F < 0x15) made else (1 + r.uintLessThan(u8, 16)) | hi;
    q.check_by_ply[ply] = chk;
    for (0..r.uintLessThan(usize, 5)) |_| q.king_rays[r.uintLessThan(usize, 2)][boardSquare(r)] = chk & 0x7F;
    for (0..r.uintLessThan(usize, 3)) |_| {
        const s = boardSquare(r);
        if (q.board[s] == pos.empty) {
            const codes = [_]u8{ 2, 3, 4, 5, 9, 10, 11, 12 };
            q.board[s] = codes[r.uintLessThan(usize, codes.len)];
        } else if (q.board[s] != pos.white_king and q.board[s] != pos.black_king) {
            q.board[s] = pos.empty;
        }
    }
    n += try compareEvasions(&q, &st.v, side, ply, r);
    try compareOthers(&q, r);
    try compareOthers(p, r);
    return n;
}

test "search helpers: the faster routines equal the reference on random games" {
    const gpa = std.testing.allocator;
    const st = try gpa.create(DiffState);
    defer gpa.destroy(st);
    var prng: std.Random.DefaultPrng = .init(0x4D43_4845_5641_5321);
    const r = prng.random();
    const target: usize = 1_000_000;
    var cases: usize = 0;
    var nodes: usize = 0;
    var in_check: usize = 0;
    var game: usize = 0;
    while (cases < target) : (game += 1) {
        st.* = .{};
        // Marks: random, so that the scores vary (gen_all_moves uses some up).
        for (&st.v.marks) |*m| m.* = if (r.uintLessThan(u8, 8) == 0) r.uintLessThan(u8, 4) else 0;
        var sv: setup.SetupVars = .{};
        const d = try fen.parse(diff_fens[game % diff_fens.len]);
        setup.buildFromDescription(&st.p, &sv, &d);
        var side = d.side_to_move;
        var ply: usize = 1;
        while (ply < 60) : (ply += 1) {
            // A king taken (possible with only pawns left, when no ray map is kept and
            // gen_all_moves does not see the capture): the game ends.
            if (st.p.piece_list[7] >= 120 or st.p.piece_list[23] >= 120) break;
            if (st.p.check_by_ply[ply] & 0x7F != 0) in_check += 1;
            cases += try compareNode(st, side, ply, r);
            nodes += 1;
            const count = mg.genAllMoves(.original, &st.p, &st.s, &st.v, &st.list, side, ply, .{});
            if (count == mg.king_capture or count == 0) break;
            const m = st.list[r.uintLessThan(usize, count)];
            var undo: pos.Undo = .{};
            st.p.makeMove(m, side, ply + 1, &undo);
            side = side.other();
        }
    }
    std.debug.print("helpers: the faster routines equal the reference on {d} gen_evasions calls ({d} nodes of {d} random games, {d} in check)\n", .{ cases, nodes, game, in_check });
}

// ---------------------------------------------------------------------------
// DEV-024: the attacked-piece counter's second bishop
// ---------------------------------------------------------------------------

const fixed_024: pos.Fixes = blk: {
    var f = pos.Fixes.original;
    f.dev024_attacked_counter = true;
    break :blk f;
};
const fixed_053: pos.Fixes = blk: {
    var f = pos.Fixes.original;
    f.dev053_line_tables_other = true;
    break :blk f;
};
const fixed_024_053: pos.Fixes = blk: {
    var f = fixed_024;
    f.dev053_line_tables_other = true;
    break :blk f;
};

fn countSide(comptime fixes: pos.Fixes, p: *const pos.Position, side: pos.Side) u16 {
    return switch (side) {
        .white => h.countAttackedFixes(fixes, p, .white),
        .black => h.countAttackedFixes(fixes, p, .black),
    };
}

fn mirrorSquare(s: usize) usize {
    return (11 - s / 10) * 10 + s % 10;
}

fn swapCode(b: u8) u8 {
    return if (b >= 1 and b <= 6) b + 7 else if (b >= 8 and b <= 13) b - 7 else b;
}

/// The colour mirror of what the counters read: ranks reversed, colours exchanged; each
/// side's piece list and pawn-attack counts are the other side's. A captured entry (120
/// or more) stays one.
fn mirrorCounterState(p: *const pos.Position, m: *pos.Position) void {
    m.* = p.*;
    for (0..120) |s| {
        const t = mirrorSquare(s);
        m.board[t] = swapCode(p.board[s]);
        for (0..2) |c| m.pawn_attacks[1 - c][t] = p.pawn_attacks[c][s];
    }
    for (0..2) |c| {
        for (0..16) |i| {
            const e = p.piece_list[16 * c + i];
            m.piece_list[16 * (1 - c) + i] = if (e < 120) @intCast(mirrorSquare(e)) else e;
        }
    }
}

/// The count as the counter's own description states it, written independently of the
/// port: the opponent's queen counts if a pawn, knight, bishop or rook of `side` attacks
/// it; each rook if a pawn, knight or bishop does; each knight and bishop if a pawn does.
/// A piece of `side` attacks only from its list slot and only if on the board (entry
/// below 120); a slider needs a clear line to the target.
fn meantCount(p: *const pos.Position, side: pos.Side) u16 {
    const a: usize = if (side == .white) 0 else 16;
    const v: usize = 16 - a;
    const counts = &p.pawn_attacks[if (side == .white) 0 else 1];
    const l = &p.piece_list;
    const bishop: u8 = if (side == .white) pos.white_bishop else pos.black_bishop;
    const rook: u8 = if (side == .white) pos.white_rook else pos.black_rook;
    const T = struct {
        fn slider(q: *const pos.Position, t: u8, slots: [2]u8, code: u8, steps: [4]i32) bool {
            for (steps) |st| {
                var s: i32 = @as(i32, t) + st;
                while (q.board[@intCast(s)] == pos.empty) s += st;
                if (q.board[@intCast(s)] != code) continue;
                for (slots) |e| if (e < 120 and @as(i32, e) == s) return true;
            }
            return false;
        }
        fn knight(t: u8, slots: [2]u8) bool {
            for (slots) |e| {
                if (e >= 120) continue;
                const d = @as(i32, t) - @as(i32, e);
                for ([8]i32{ 8, 12, 19, 21, -8, -12, -19, -21 }) |k| if (d == k) return true;
            }
            return false;
        }
    };
    const knights = [2]u8{ l[a], l[a + 1] };
    const bishops = [2]u8{ l[a + 2], l[a + 3] };
    const rooks = [2]u8{ l[a + 4], l[a + 5] };
    const diag = [4]i32{ 9, 11, -9, -11 };
    const line = [4]i32{ 1, 10, -1, -10 };
    var n: u16 = 0;
    const q = l[v + 6];
    if (q < 120 and (counts[q] != 0 or T.knight(q, knights) or T.slider(p, q, bishops, bishop, diag) or
        T.slider(p, q, rooks, rook, line))) n += 1;
    for ([2]usize{ v + 4, v + 5 }) |s| {
        const r = l[s];
        if (r < 120 and (counts[r] != 0 or T.knight(r, knights) or T.slider(p, r, bishops, bishop, diag))) n += 1;
    }
    for (l[v..][0..4]) |e| {
        if (e < 120 and counts[e] != 0) n += 1;
    }
    return n;
}

/// A position from a FEN, with the side's bishop slots 2 and 3 holding the entries
/// `first` and `second` (the order the counter tries them in; an entry of 120 or more is
/// a bishop captured on entry - 63h). Only the counter's inputs are made consistent.
fn bishopsInOrder(fen_text: []const u8, side: pos.Side, first: u8, second: u8) !pos.Position {
    var p: pos.Position = .{};
    var sv: setup.SetupVars = .{};
    const d = try fen.parse(fen_text);
    setup.buildFromDescription(&p, &sv, &d);
    const a: usize = if (side == .white) 0 else 16;
    p.piece_list[a + 2] = first;
    p.piece_list[a + 3] = second;
    return p;
}

fn countBoth(p: *const pos.Position, comptime side: pos.Side) [2]u16 {
    return .{ h.countAttacked(p, side), h.countAttackedFixes(fixed_024, p, side) };
}

test "DEV-024: the counter tries the second bishop when the first one's diagonal leads nowhere" {
    // The form recorded in game A: Black to move (CC4E), White's queen on a4 attacked by
    // Black's bishop on d7 (slot 3). The bishop on f8 (slot 2) is on no diagonal through
    // a4, but a4 - f8 = -45 is a multiple of 9 and the direction table, which is
    // arithmetic and does not know the board's edge, gives +9 (DG:0B66 - 45): the walk
    // meets the border at once (a4 + 9), and the original never tries the bishop on d7.
    const black_case = "4kb2/3b4/8/8/Q7/8/8/4K3 b - - 0 1";
    var p = try bishopsInOrder(black_case, .black, 96, 84);
    try std.testing.expectEqual([2]u16{ 0, 1 }, countBoth(&p, .black));
    try std.testing.expectEqual(@as(u16, 1), meantCount(&p, .black));
    p = try bishopsInOrder(black_case, .black, 84, 96);
    try std.testing.expectEqual([2]u16{ 1, 1 }, countBoth(&p, .black));

    const f3: u8 = 46;
    // White to move, Black's queen on d5 attacked by White's bishop on f3. White's other
    // bishop was captured on b3: its entry is 42 + 63h = 141, and the direction table at
    // d5 - 141 = -77 gives +11 (DG:0B66 - 77), so the original walks e6, f7 to g8, meets
    // Black's king, and never tries the bishop on f3 (CE94 -> CEA8 -> CEBB).
    const w = "6k1/8/8/3q4/8/5B2/8/6K1 w - - 0 1";
    p = try bishopsInOrder(w, .white, 42 + 0x63, f3);
    try std.testing.expectEqual([2]u16{ 0, 1 }, countBoth(&p, .white));
    try std.testing.expectEqual(@as(u16, 1), meantCount(&p, .white));
    // The same with the slots exchanged: the original finds the attack itself.
    p = try bishopsInOrder(w, .white, f3, 42 + 0x63);
    try std.testing.expectEqual([2]u16{ 1, 1 }, countBoth(&p, .white));
    // The captured bishop's old square on c1 instead: 64 - (23 + 63h) = -58 is no
    // diagonal, so both versions go on to the bishop on f3.
    p = try bishopsInOrder(w, .white, 23 + 0x63, f3);
    try std.testing.expectEqual([2]u16{ 1, 1 }, countBoth(&p, .white));

    // Both bishops on the board (a second light-squared bishop, after a promotion): the
    // one on a2 has a diagonal to d5 blocked by the pawn on c4.
    const a2: u8 = 31;
    p = try bishopsInOrder("6k1/8/8/3q4/2p5/5B2/B7/6K1 w - - 0 1", .white, a2, f3);
    try std.testing.expectEqual([2]u16{ 0, 1 }, countBoth(&p, .white));
    try std.testing.expectEqual(@as(u16, 1), meantCount(&p, .white));
    // A rook as the target (CF50..CF83): Black's rook on d5 instead of the queen.
    p = try bishopsInOrder("6k1/8/8/3r4/2p5/5B2/B7/6K1 w - - 0 1", .white, a2, f3);
    try std.testing.expectEqual([2]u16{ 0, 1 }, countBoth(&p, .white));

    // Black to move, the mirror (CC4E): White's queen on d4, Black's bishops on a7
    // (blocked by the pawn on c5) and f6.
    const a7: u8 = 81;
    const f6: u8 = 76;
    p = try bishopsInOrder("6k1/b7/5b2/2P5/3Q4/8/8/6K1 b - - 0 1", .black, a7, f6);
    try std.testing.expectEqual([2]u16{ 0, 1 }, countBoth(&p, .black));
    try std.testing.expectEqual(@as(u16, 1), meantCount(&p, .black));
    p = try bishopsInOrder("6k1/b7/5b2/2P5/3Q4/8/8/6K1 b - - 0 1", .black, f6, a7);
    try std.testing.expectEqual([2]u16{ 1, 1 }, countBoth(&p, .black));
}

// ---------------------------------------------------------------------------
// DEV-053: the line tables' pseudo-lines in the other readers
// ---------------------------------------------------------------------------

const se = @import("staticeval.zig");

/// DG:0B66 + d and DG:0C64 + d for d = -255..119 (index d + 255), as the readers index them.
const diag_table: [375]i8 = @bitCast(dg(0x0B66 - 255, 375));
const orth_table: [375]i8 = @bitCast(dg(0x0C64 - 255, 375));
/// DG:0E16: 1 on dark squares (gen_tactical_moves' bishop hint test, 1E9D:5A9F / 5EDB).
const dark_square = dg(0x0E16, 120);

fn onBoard(s: i32) bool {
    return s >= 21 and s <= 98 and @mod(s, 10) >= 1 and @mod(s, 10) <= 8;
}

fn tableAt(t: *const [375]i8, d: i32) i32 {
    return t[@intCast(d + 255)];
}

test "DEV-053: the rule, the tables' pseudo-lines, and the readers that walk to the target" {
    // The two copies of the rule agree on every target, entry and step.
    for (0..120) |t| {
        for (0..256) |e| {
            var st: i32 = -11;
            while (st <= 11) : (st += 1) {
                const ti: i32 = @intCast(t);
                const ei: i32 = @intCast(e);
                try std.testing.expectEqual(h.realLineStep(ti, ei, st), se.realLineStep(ti, ei, st));
            }
        }
    }
    var pseudo: usize = 0;
    var walks: usize = 0;
    var from: i32 = 21;
    while (from <= 98) : (from += 1) {
        if (!onBoard(from)) continue;
        var to: i32 = 21;
        while (to <= 98) : (to += 1) {
            if (!onBoard(to) or to == from) continue;
            const d = from - to;
            const o = tableAt(&orth_table, d);
            const g = tableAt(&diag_table, d);
            // The queen's fallback (0000:2065 / 220C, 4793:5B89 / 5D26) takes the diagonal
            // only when the orthogonal table gives 0: no difference has both, so a
            // pseudo-rank never hides a real diagonal.
            try std.testing.expect(o == 0 or g == 0);
            inline for (.{ o, g }) |st| {
                if (st != 0) {
                    // The step leads from `from` towards `to`: the walk of the hash-move test
                    // (0000:2008-2016) and the book's move check (4793:5B2F-5B3F, 5D4D) on an
                    // empty board. It reaches `to` on a real line; on a pseudo-line it meets
                    // the border first, which both treat as "no move", as they treat step 0.
                    var s = from + st;
                    while (s != to and onBoard(s)) s += st;
                    const real = h.realLineStep(from, to, st) != 0;
                    try std.testing.expectEqual(real, s == to);
                    walks += 1;
                    if (!real) {
                        pseudo += 1;
                        // A pseudo-diagonal joins a dark and a light square, so the bishop
                        // hint of gen_tactical_moves (1E9D:5AAF / 5EEB, read at 5AE9), which
                        // is used only for a hint of the bishop's colour, never meets one.
                        if (st == g and g != 0) try std.testing.expect(dark_square[@intCast(from)] != dark_square[@intCast(to)]);
                    }
                }
            }
            // DG:0E16 is the colour of the square.
            const same_colour = @mod(@divTrunc(from, 10) + @mod(from, 10), 2) == @mod(@divTrunc(to, 10) + @mod(to, 10), 2);
            try std.testing.expectEqual(same_colour, dark_square[@intCast(from)] == dark_square[@intCast(to)]);
        }
    }
    std.debug.print("DEV-053: {d} ordered pairs of board squares on a pseudo-line of the line tables (of {d} with a step); each walk meets the border before the target\n", .{ pseudo, walks });
    try std.testing.expectEqual(@as(usize, 350), pseudo);
}

fn countAll(p: *const pos.Position, comptime side: pos.Side) [4]u16 {
    return .{ h.countAttacked(p, side), h.countAttackedFixes(fixed_053, p, side), h.countAttackedFixes(fixed_024, p, side), h.countAttackedFixes(fixed_024_053, p, side) };
}

test "DEV-053: the counter, a position for each form, and the colour mirror" {
    // DEV-053 alone, Black to move (CC4E): White's queen on a4; Black's bishop on f8 (slot
    // 2) is on a pseudo-diagonal to it (a4 - f8 = -45, +9 by DG:0B66 - 45; the walk meets the
    // border at once), so the original never tries the bishop on d7 (slot 3). Corrected,
    // f8 has no line and d7 is tried. Values: original, DEV-053, DEV-024, both.
    var p = try bishopsInOrder("4kb2/3b4/8/8/Q7/8/8/4K3 b - - 0 1", .black, 96, 84);
    try std.testing.expectEqual([4]u16{ 0, 1, 1, 1 }, countAll(&p, .black));
    // The mirror, White to move: f1 (slot 2) gives no step at all (a5 - f1 = 35).
    var m = try bishopsInOrder("4k3/8/8/q7/8/8/3B4/4KB2 w - - 0 1", .white, 26, 34);
    try std.testing.expectEqual([4]u16{ 1, 1, 1, 1 }, countAll(&m, .white));
    var mm: pos.Position = .{};
    mirrorCounterState(&p, &mm);
    try std.testing.expectEqual(countAll(&m, .white), countAll(&mm, .white));

    // With DEV-024 on, White to move (CE3E): Black's queen on g2; White's bishop on a7
    // (slot 2) is on a pseudo-diagonal to it (g2 - a7 = -44, +11 by DG:0B66 - 44). The walk
    // goes g2 to h3 and meets a third White bishop (a promotion, in no bishop slot), and the
    // queen counts as attacked. The mirror never looks along h6-g7 (g7 - a2 = 56 gives no
    // step), and there it does not count. Corrected, both give 0, as `meantCount`, which
    // counts only the slots' pieces. (The original also counts it; DEV-053 alone does not:
    // the bishop on c1, slot 3, has no diagonal to g2.)
    p = try bishopsInOrder("8/B7/8/8/8/7B/6q1/1KB4k w - - 0 1", .white, 81, 23);
    try std.testing.expectEqual([4]u16{ 1, 0, 1, 0 }, countAll(&p, .white));
    try std.testing.expectEqual(@as(u16, 0), meantCount(&p, .white));
    m = try bishopsInOrder("1kb4K/6Q1/7b/8/8/8/b7/8 b - - 0 1", .black, 31, 93);
    try std.testing.expectEqual([4]u16{ 0, 0, 0, 0 }, countAll(&m, .black));
    mirrorCounterState(&p, &mm);
    try std.testing.expectEqual(countAll(&m, .black), countAll(&mm, .black));
}

test "DEV-053: with DEV-024 and DEV-053 on, no generated counter call differs from its colour mirror" {
    const gpa = std.testing.allocator;
    const st = try gpa.create(DiffState);
    defer gpa.destroy(st);
    var prng: std.Random.DefaultPrng = .init(0x4D43_4845_5353_3533);
    const r = prng.random();
    const target: usize = 400_000;
    var cases: usize = 0;
    var differs_024: usize = 0;
    var differs_both: usize = 0;
    var changed: usize = 0;
    var game: usize = 0;
    while (cases < target) : (game += 1) {
        st.* = .{};
        var sv: setup.SetupVars = .{};
        const d = try fen.parse(diff_fens[game % diff_fens.len]);
        setup.buildFromDescription(&st.p, &sv, &d);
        var side = d.side_to_move;
        var ply: usize = 1;
        while (ply < 60) : (ply += 1) {
            if (st.p.piece_list[7] >= 120 or st.p.piece_list[23] >= 120) break;
            // The position as made, and disturbed: an extra bishop, rook or queen of
            // either colour (a promotion: on the board, in no slot) on an empty square,
            // and a bishop or rook slot made a captured entry (its square + 63h).
            var q = st.p;
            for (0..r.uintLessThan(usize, 4)) |_| {
                const s = boardSquare(r);
                if (q.board[s] == pos.empty) {
                    const codes = [_]u8{ 3, 4, 5, 10, 11, 12 };
                    q.board[s] = codes[r.uintLessThan(usize, codes.len)];
                }
            }
            if (r.boolean()) {
                const slot = 16 * r.uintLessThan(usize, 2) + 2 + r.uintLessThan(usize, 4);
                if (q.piece_list[slot] < 120) {
                    q.board[q.piece_list[slot]] = pos.empty;
                    q.piece_list[slot] += 0x63;
                }
            }
            inline for (.{ pos.Side.white, pos.Side.black }) |s| {
                for ([2]*const pos.Position{ &st.p, &q }) |x| {
                    var m: pos.Position = .{};
                    mirrorCounterState(x, &m);
                    const a = h.countAttackedFixes(fixed_024, x, s);
                    const b = h.countAttackedFixes(fixed_024_053, x, s);
                    if (a != b) changed += 1;
                    if (a != h.countAttackedFixes(fixed_024, &m, comptime s.other())) differs_024 += 1;
                    if (b != h.countAttackedFixes(fixed_024_053, &m, comptime s.other())) {
                        if (differs_both == 0) std.debug.print("\nDEV-053: generated call differs from its mirror: game {d}, ply {d}\n", .{ game, ply });
                        differs_both += 1;
                    }
                    cases += 1;
                }
            }
            const count = mg.genAllMoves(.original, &st.p, &st.s, &st.v, &st.list, side, ply, .{});
            if (count == mg.king_capture or count == 0) break;
            const mv = st.list[r.uintLessThan(usize, count)];
            var undo: pos.Undo = .{};
            st.p.makeMove(mv, side, ply + 1, &undo);
            side = side.other();
        }
    }
    std.debug.print("DEV-053: {d} generated counter calls ({d} games, half disturbed): DEV-053 changes {d} against DEV-024 alone; differ from the colour mirror: {d} with DEV-024 alone, {d} with DEV-024 and DEV-053\n", .{ cases, game, changed, differs_024, differs_both });
    try std.testing.expectEqual(@as(usize, 0), differs_both);
}
