//! Differential tests of src/see.zig and src/sort.zig against calls recorded from the
//! running original (tests/golden/movegen/*.zst, made by
//! tools/port/gen_movegen_vectors.py, whose docstring defines the format).

const std = @import("std");
const pos = @import("position.zig");
const see_mod = @import("see.zig");
const sortMoves = @import("sort.zig").sortMoves;
const dg = @import("original.zig").dgroup;

/// The SEE image: what the routines read and write, in the recorder's order.
const Region = struct { name: []const u8, dg: u16, len: usize };
const regions = [_]Region{
    .{ .name = "board", .dg = 0x9EF6, .len = 120 },
    .{ .name = "piece lists", .dg = 0xA03A, .len = 32 },
    .{ .name = "White pawn attacks", .dg = 0xA51C, .len = 120 },
    .{ .name = "Black pawn attacks", .dg = 0x37DA, .len = 120 },
    .{ .name = "White king rays", .dg = 0xA09E, .len = 120 },
    .{ .name = "Black king rays", .dg = 0xA164, .len = 120 },
    .{ .name = "attacker list", .dg = 0x9FEC, .len = 116 },
    .{ .name = "defender list", .dg = 0xA060, .len = 32 },
    .{ .name = "gains g", .dg = 0x70E5, .len = 11 },
    .{ .name = "net values h", .dg = 0xB4E6, .len = 10 },
};
const image_size = blk: {
    var n: usize = 0;
    for (regions) |r| n += r.len;
    break :blk n;
};
const Image = [image_size]u8;

fn transfer(comptime to_image: bool, p: *pos.Position, s: *see_mod.Scratch, img: *Image) void {
    const parts = [_][]u8{
        &p.board,           &p.piece_list,
        &p.pawn_attacks[0], &p.pawn_attacks[1],
        &p.king_rays[0],    &p.king_rays[1],
        &s.attackers,       &s.defenders,
        &s.gain,            s.net[0..10],
    };
    var o: usize = 0;
    for (parts) |part| {
        if (to_image) @memcpy(img[o..][0..part.len], part) else @memcpy(part, img[o..][0..part.len]);
        o += part.len;
    }
    std.debug.assert(o == image_size);
}

fn describe(buf: []u8, off: usize) []const u8 {
    var o: usize = 0;
    for (regions) |r| {
        if (off < o + r.len) return std.fmt.bufPrint(buf, "{s}[{d}] (DG:{X:0>4})", .{ r.name, off - o, r.dg + off - o }) catch r.name;
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
    const path = try std.fmt.bufPrint(&path_buf, "{s}/movegen/{s}", .{ dir, name });
    const compressed = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, gpa, .limited(64 << 20));
    defer gpa.free(compressed);
    var in: std.Io.Reader = .fixed(compressed);
    const window = try gpa.alloc(u8, std.compress.zstd.default_window_len + std.compress.zstd.block_size_max);
    defer gpa.free(window);
    var zd = std.compress.zstd.Decompress.init(&in, window, .{});
    return zd.reader.allocRemaining(gpa, .limited(512 << 20));
}

const Counts = struct { white: usize = 0, black: usize = 0, sorts: usize = 0 };

fn replay(gpa: std.mem.Allocator, name: []const u8) !Counts {
    return replaySampled(gpa, name, null);
}

/// The replay, which also hands each call's inputs to `sampler` when one is given (the
/// benchmarks and the differential tests use it to collect real inputs).
fn replaySampled(gpa: std.mem.Allocator, name: []const u8, sampler: ?*Sampler) !Counts {
    const data = try readVectors(gpa, name);
    defer gpa.free(data);
    var c: Cursor = .{ .d = data };
    try std.testing.expectEqualSlices(u8, "MCSV", c.take(4));
    try std.testing.expectEqual(@as(u16, 1), c.int(u16));
    try std.testing.expectEqual(@as(u16, image_size), c.int(u16));
    // The tables the SEE reads out of range, as they were in the running original,
    // equal what the port reads from the executable.
    try std.testing.expectEqualSlices(u8, c.take(333), &dg(0x0A68 - 234, 333));
    try std.testing.expectEqualSlices(u8, c.take(333), &dg(0x0CFF - 234, 333));
    try std.testing.expectEqualSlices(u8, c.take(14), &dg(0x1A71, 14));

    var truth: Image = c.take(image_size)[0..image_size].*;
    var p: pos.Position = .{};
    var s: see_mod.Scratch = .{};
    var got: Image = undefined;
    var counts: Counts = .{};
    var index: usize = 0;
    var list: [256]pos.Move = undefined;
    while (true) : (index += 1) {
        const tag = c.byte();
        switch (tag) {
            0 => {
                try std.testing.expectEqual(counts.white, c.int(u32));
                try std.testing.expectEqual(counts.black, c.int(u32));
                try std.testing.expectEqual(counts.sorts, c.int(u32));
                return counts;
            },
            1, 2 => {
                c.apply(&truth);
                transfer(false, &p, &s, &truth);
                const sq = c.byte();
                const v = c.int(u16);
                const ax = c.int(u16);
                const side: pos.Side = if (tag == 1) .white else .black;
                if (sampler) |sm| sm.addSee(&p, &s, side, sq, v);
                const got_ax = see_mod.see(&p, &s, side, sq, v);
                c.apply(&truth);
                transfer(true, &p, &s, &got);
                // When collecting inputs (the next call's state comes from the recording,
                // not from this result), a mismatch is left to the replay test.
                if (sampler == null and (got_ax != ax or !std.mem.eql(u8, &truth, &got))) {
                    var buf: [64]u8 = undefined;
                    std.debug.print("\n{s}: call {d} differs: {s}(sq {d}, v {d}): AX want {X:0>4}, got {X:0>4}\n", .{ name, index, if (tag == 1) "see_capture_by_white" else "see_capture_by_black", sq, v, ax, got_ax });
                    for (truth, got, 0..) |want, have, off| {
                        if (want != have) {
                            std.debug.print("  first differing byte: {s}: want {X:0>2}, got {X:0>2}\n", .{ describe(&buf, off), want, have });
                            break;
                        }
                    }
                    return error.MismatchWithOriginal;
                }
                if (tag == 1) counts.white += 1 else counts.black += 1;
            },
            3 => {
                const n: i16 = @bitCast(c.int(u16));
                counts.sorts += 1;
                if (n <= 0) {
                    sortMoves(list[0..0], n);
                    continue;
                }
                const count: usize = @intCast(n);
                const before = c.take(4 * count);
                const perm = c.take(count);
                @memcpy(std.mem.sliceAsBytes(list[0..count]), before);
                if (sampler) |sm| sm.addSort(list[0..count]);
                sortMoves(list[0..count], n);
                for (0..count) |i| {
                    const want = before[4 * @as(usize, perm[i]) ..][0..4];
                    if (!std.mem.eql(u8, want, std.mem.asBytes(&list[i]))) {
                        std.debug.print("\n{s}: call {d} differs: sort_moves(n {d}): entry {d} want {any}, got {any}\n", .{ name, index, n, i, want, std.mem.asBytes(&list[i]) });
                        return error.MismatchWithOriginal;
                    }
                }
            },
            else => return error.BadRecordTag,
        }
    }
}

const runs = [_][]const u8{ "A.zst", "C.zst", "D.zst" };

test "see and sort_moves: replay every recorded call of the original" {
    const gpa = std.testing.allocator;
    var total: Counts = .{};
    for (runs) |name| {
        const n = try replay(gpa, name);
        std.debug.print("movegen vectors {s}: see_capture_by_white {d}, see_capture_by_black {d}, sort_moves {d} calls replayed, all equal\n", .{ name, n.white, n.black, n.sorts });
        total.white += n.white;
        total.black += n.black;
        total.sorts += n.sorts;
    }
    std.debug.print("movegen vectors total: see_capture_by_white {d}, see_capture_by_black {d}, sort_moves {d}\n", .{ total.white, total.black, total.sorts });
}

// ---------------------------------------------------------------------------
// Real inputs collected from the recordings: for the benchmarks and the
// differential tests against src/see_reference.zig
// ---------------------------------------------------------------------------

/// One SEE call: its position is `positions[pi]`, shared by consecutive calls on the
/// same position, as in a search.
const SeeCall = struct { pi: u32, s: see_mod.Scratch, side: pos.Side, sq: u8, v: u16 };
const SortCall = struct { list: [256]pos.Move, n: u16 };

/// Keeps SEE calls in runs of 32 consecutive calls, one run in every `stride`, and
/// every `stride`-th sort, up to `cap` of each.
const Sampler = struct {
    stride: usize,
    cap: usize,
    seen: [3]usize = .{ 0, 0, 0 },
    see: [2]std.ArrayList(SeeCall) = .{ .empty, .empty },
    positions: std.ArrayList(pos.Position) = .empty,
    sorts: std.ArrayList(SortCall) = .empty,
    gpa: std.mem.Allocator,

    fn sameForSee(a: *const pos.Position, b: *const pos.Position) bool {
        return std.mem.eql(u8, &a.board, &b.board) and std.mem.eql(u8, &a.piece_list, &b.piece_list) and
            std.mem.eql(u8, std.mem.asBytes(&a.pawn_attacks), std.mem.asBytes(&b.pawn_attacks)) and
            std.mem.eql(u8, std.mem.asBytes(&a.king_rays), std.mem.asBytes(&b.king_rays));
    }

    fn addSee(sm: *Sampler, p: *const pos.Position, s: *const see_mod.Scratch, side: pos.Side, sq: u8, v: u16) void {
        const r = @backingInt(side);
        const n = sm.seen[0] + sm.seen[1];
        defer sm.seen[r] += 1;
        if ((n / 32) % sm.stride != 0 or sm.see[r].items.len >= sm.cap) return;
        const ps = sm.positions.items;
        if (ps.len == 0 or !sameForSee(&ps[ps.len - 1], p)) sm.positions.append(sm.gpa, p.*) catch @panic("out of memory");
        const pi: u32 = @intCast(sm.positions.items.len - 1);
        sm.see[r].append(sm.gpa, .{ .pi = pi, .s = s.*, .side = side, .sq = sq, .v = v }) catch @panic("out of memory");
    }

    fn addSort(sm: *Sampler, list: []const pos.Move) void {
        defer sm.seen[2] += 1;
        if (sm.seen[2] % sm.stride != 0 or sm.sorts.items.len >= sm.cap) return;
        var c: SortCall = .{ .list = undefined, .n = @intCast(list.len) };
        @memcpy(c.list[0..list.len], list);
        sm.sorts.append(sm.gpa, c) catch @panic("out of memory");
    }

    fn deinit(sm: *Sampler) void {
        for (&sm.see) |*l| l.deinit(sm.gpa);
        sm.positions.deinit(sm.gpa);
        sm.sorts.deinit(sm.gpa);
    }

    fn collect(gpa: std.mem.Allocator, stride: usize, cap: usize) !Sampler {
        var sm: Sampler = .{ .stride = stride, .cap = cap, .gpa = gpa };
        errdefer sm.deinit();
        for (runs) |name| _ = try replaySampled(gpa, name, &sm);
        return sm;
    }
};

const bench = @import("bench.zig");

/// How many calls ahead the SEE benchmark loads a call's state; the sample's length
/// is a multiple of twice this.
const ahead = 8;

/// Copies the fields the SEE reads.
inline fn loadSeeState(w: *pos.Position, p: *const pos.Position) void {
    w.board = p.board;
    w.piece_list = p.piece_list;
    w.pawn_attacks = p.pawn_attacks;
    w.king_rays = p.king_rays;
}

test "bench: see: see_capture_by_white, see_capture_by_black, sort_moves on recorded inputs" {
    if (!bench.enabled) return;
    const gpa = std.testing.allocator;
    var sm = try Sampler.collect(gpa, 19, 2048);
    defer sm.deinit();
    const passes = 21;
    const reps = 32;
    // In a search the position is in the first-level cache. Here the sample's positions
    // are not, so the loop copies what the SEE reads into a small ring of working
    // positions `ahead` calls before it is used; the loop with the copies alone is timed
    // and taken off. Each pass times the routine as it is and the reference
    // (src/see_reference.zig, src/sort_reference.zig) one after the other.
    const ps = sm.positions.items;
    const ring = try gpa.alloc(pos.Position, 2 * ahead);
    defer gpa.free(ring);
    for (ring) |*w| w.* = .{};
    std.debug.print("see sample: {d} calls on {d} positions\n", .{ sm.see[0].items.len + sm.see[1].items.len, ps.len });
    inline for (sm.see, .{ "see see_capture_by_white", "see see_capture_by_black" }) |l, label| {
        var copy_best: bench.Best = .{};
        var now_best: bench.Best = .{};
        var was_best: bench.Best = .{};
        var fixed_best: bench.Best = .{};
        for (0..passes) |_| {
            var t0 = bench.now();
            for (0..reps) |_| for (l.items, 0..) |*c, i| {
                loadSeeState(&ring[(i + ahead) % (2 * ahead)], &ps[l.items[(i + ahead) % l.items.len].pi]);
                bench.keep(c.sq);
                bench.keep(&ring[i % (2 * ahead)]);
            };
            copy_best.pass(t0);
            inline for (.{ see_mod, see_ref, SeeFixed058 }, .{ &now_best, &was_best, &fixed_best }) |M, best| {
                var scratch: M.Scratch = .{};
                for (l.items[0..ahead], 0..) |*c, i| loadSeeState(&ring[i], &ps[c.pi]);
                t0 = bench.now();
                for (0..reps) |_| for (l.items, 0..) |*c, i| {
                    loadSeeState(&ring[(i + ahead) % (2 * ahead)], &ps[l.items[(i + ahead) % l.items.len].pi]);
                    const r = @call(.never_inline, M.see, .{ &ring[i % (2 * ahead)], &scratch, c.side, c.sq, c.v });
                    bench.keep(r);
                };
                best.pass(t0);
            }
        }
        now_best.report(label, reps * l.items.len, passes, copy_best.ns);
        was_best.report(label ++ " (before)", reps * l.items.len, passes, copy_best.ns);
        fixed_best.report(label ++ " (DEV-058 corrected)", reps * l.items.len, passes, copy_best.ns);
    }
    const sorts = sm.sorts.items;
    var work: [256]pos.Move = undefined;
    var total: usize = 0;
    for (sorts) |c| total += c.n;
    var copy_best: bench.Best = .{};
    var now_best: bench.Best = .{};
    var was_best: bench.Best = .{};
    for (0..passes) |_| {
        var t0 = bench.now();
        for (0..reps) |_| for (sorts) |*c| {
            @memcpy(work[0..c.n], c.list[0..c.n]);
            bench.keep(&work);
        };
        copy_best.pass(t0);
        inline for (.{ sortMoves, sort_ref.sortMoves }, .{ &now_best, &was_best }) |f, best| {
            t0 = bench.now();
            for (0..reps) |_| for (sorts) |*c| {
                @memcpy(work[0..c.n], c.list[0..c.n]);
                @call(.never_inline, f, .{ work[0..c.n], @as(i16, @intCast(c.n)) });
                bench.keep(&work);
            };
            best.pass(t0);
        }
    }
    now_best.report("see sort_moves", reps * sorts.len, passes, copy_best.ns);
    was_best.report("see sort_moves (before)", reps * sorts.len, passes, copy_best.ns);
    std.debug.print("sort_moves sample: {d} lists, mean length {d:.1}\n", .{ sorts.len, @as(f64, @floatFromInt(total)) / @as(f64, @floatFromInt(sorts.len)) });
}

// ---------------------------------------------------------------------------
// Differential tests against src/see_reference.zig and src/sort_reference.zig (the
// routines as they were before the speed pass), on inputs beyond the recorded ones
// ---------------------------------------------------------------------------

const see_ref = @import("see_reference.zig");
const sort_ref = @import("sort_reference.zig");
const RandomWalk = @import("position_test.zig").RandomWalk;
const full_diff = @import("position_test.zig").full_diff;
const diff_count = @import("position_test.zig").diff_count;

/// One SEE call through the new routine and the reference, from the same work areas.
fn diffSee(p: *const pos.Position, s_in: *const see_mod.Scratch, side: pos.Side, sq: u8, v: u16) !void {
    var a = s_in.*;
    var b: see_ref.Scratch = .{ .attackers = s_in.attackers, .defenders = s_in.defenders, .gain = s_in.gain, .net = s_in.net };
    const ra = see_mod.see(p, &a, side, sq, v);
    const rb = see_ref.see(p, &b, side, sq, v);
    if (ra != rb or !std.mem.eql(u8, &a.attackers, &b.attackers) or !std.mem.eql(u8, &a.defenders, &b.defenders) or
        !std.mem.eql(u8, &a.gain, &b.gain) or !std.mem.eql(u8, &a.net, &b.net))
    {
        std.debug.print("see differs: side {t} sq {d} v {d}: {X:0>4} want {X:0>4}\n", .{ side, sq, v, ra, rb });
        return error.DiffersFromReference;
    }
}

/// DG:0A68 + d for d = -255..119, as the SEE reads it for a knight's list entry.
const knight_reach = dg(0x0A68 - 255, 375);

/// Does the knight entry `e` make the SEE index the king ray map at `e` for target
/// `sq`? It reaches when the table byte is non-zero, and an entry of 78h or more (a
/// captured knight, an empty set-up slot, FFh) then indexes beyond the map: a trap in
/// safe builds in both versions, and a read of other variables in the original.
fn knightIndexesOffMap(p: *const pos.Position, sq: usize) bool {
    for ([_]u8{ 0, 1, 16, 17 }) |slot| {
        const e = p.piece_list[slot];
        if (e >= 120 and knight_reach[sq + 255 - e] != 0) return true;
    }
    return false;
}

/// Every board square, both sides, the callers' three capturer values and one random
/// value, from work areas of random bytes. Squares where a knight entry would index
/// the king ray map beyond its end (`knightIndexesOffMap`) are left out.
fn diffSeeAllSquares(p: *const pos.Position, r: std.Random) !usize {
    var s: see_mod.Scratch = undefined;
    r.bytes(std.mem.asBytes(&s));
    var n: usize = 0;
    for (21..99) |sq| {
        if (sq % 10 == 0 or sq % 10 == 9 or knightIndexesOffMap(p, sq)) continue;
        for ([2]pos.Side{ .white, .black }) |side| {
            for ([_]u16{ 9, 15, 27, r.int(u16) }) |v| {
                try diffSee(p, &s, side, @intCast(sq), v);
                n += 1;
            }
        }
    }
    return n;
}

test "see: equals the reference on random walks, every square, both sides" {
    var w = RandomWalk.init(0x5EED_0101);
    var rng: std.Random.DefaultPrng = .init(0x5EED_0102);
    var n: usize = 0;
    var states: usize = 0;
    while (n < 2 * diff_count) : (states += 1) {
        n += try diffSeeAllSquares(&w.p, rng.random());
        w.step();
    }
    std.debug.print("see: {d} calls on {d} random-walk states equal the reference\n", .{ n, states });
}

test "see: equals the reference on recorded states, as recorded and on every square" {
    const gpa = std.testing.allocator;
    var sm = try Sampler.collect(gpa, if (full_diff) 3 else 30, 40_000);
    defer sm.deinit();
    var rng: std.Random.DefaultPrng = .init(0x5EED_0103);
    var n: usize = 0;
    for (sm.see) |l| for (l.items) |*c| {
        try diffSee(&sm.positions.items[c.pi], &c.s, c.side, c.sq, c.v);
        n += 1;
    };
    for (sm.positions.items, 0..) |*p, i| {
        if (i % 8 == 0) n += try diffSeeAllSquares(p, rng.random());
    }
    std.debug.print("see: {d} calls on recorded states equal the reference\n", .{n});
}

test "sort_moves: equals the reference on random lists with many equal scores" {
    var rng: std.Random.DefaultPrng = .init(0x5EED_0104);
    const r = rng.random();
    var a: [256]pos.Move = undefined;
    var b: [256]pos.Move = undefined;
    for (0..diff_count) |i| {
        // Lengths up to the generators' 100 (and some beyond), counts of 0 and below.
        const len: usize = if (i % 64 == 0) r.uintLessThan(usize, 257) else r.uintLessThan(usize, 101);
        const n: i16 = if (i % 50 == 0) -r.intRangeAtMost(i16, 0, 300) else @intCast(len);
        // Few distinct scores, so that ties are common; sometimes the full byte range.
        const distinct: u8 = if (i % 3 == 0) 255 else 1 + r.uintLessThan(u8, 8);
        for (a[0..len], 0..) |*m, k| m.* = .{ .from = @truncate(k), .to = r.int(u8), .flag = r.int(u8), .score = r.uintLessThan(u8, distinct) -% 4 };
        @memcpy(b[0..len], a[0..len]);
        sortMoves(a[0..len], n);
        sort_ref.sortMoves(b[0..len], n);
        try std.testing.expectEqualSlices(u8, std.mem.sliceAsBytes(b[0..len]), std.mem.sliceAsBytes(a[0..len]));
    }
}

test "sort_moves: equals the reference on recorded lists" {
    const gpa = std.testing.allocator;
    var sm = try Sampler.collect(gpa, 1, 200_000);
    defer sm.deinit();
    for (sm.sorts.items) |*c| {
        var a = c.list;
        var b = c.list;
        sortMoves(a[0..c.n], @intCast(c.n));
        sort_ref.sortMoves(b[0..c.n], @intCast(c.n));
        try std.testing.expectEqualSlices(u8, std.mem.sliceAsBytes(b[0..c.n]), std.mem.sliceAsBytes(a[0..c.n]));
    }
}

/// `see` with DEV-058 corrected, for the benchmark.
const SeeFixed058 = struct {
    pub const Scratch = see_mod.Scratch;
    const fixes: pos.Fixes = .{ .dev001_ep_hash_square = false, .dev058_lifted_knight_entry = true };
    pub fn see(p: *const pos.Position, s: *Scratch, side: pos.Side, sq: u8, v: u16) u16 {
        return see_mod.seeFixes(fixes, p, s, side, sq, v);
    }
};

test "see DEV-058: a knight lifted with entry 0 takes part in an exchange on a1, corrected not" {
    // White Nb3 takes Black's Na1, defended by Nc2, as gen_tactical_moves calls it: the
    // moving knight's list entry 0 for the call (`seeEntry`). DG:0A68 + 21 is a knight
    // step, so the original counts the knight a second time.
    const fen = @import("fen.zig");
    const setup = @import("setup.zig");
    const d = try fen.parse("4k3/8/8/8/8/1N6/2n5/n6K w - - 0 1");
    var p: pos.Position = .{};
    var v: setup.SetupVars = .{};
    setup.buildFromDescription(&p, &v, &d);
    try std.testing.expectEqual(@as(u8, 42), p.piece_list[0]);
    p.piece_list[0] = 0;
    var s1: see_mod.Scratch = .{};
    var s2: see_mod.Scratch = .{};
    const original: i16 = @bitCast(see_mod.see(&p, &s1, .white, 21, 9));
    const corrected: i16 = @bitCast(see_mod.seeFixes(SeeFixed058.fixes, &p, &s2, .white, 21, 9));
    std.debug.print("see DEV-058: Nb3xa1 (entry 0), defended by Nc2: original {d}, corrected {d}\n", .{ original, corrected });
    try std.testing.expect(original != corrected);
    // gen_all_moves' lift, entry FFh, reaches no square of the first rank: on a1 the
    // corrected value is the original's with FFh.
    p.piece_list[0] = 0xFF;
    var s3: see_mod.Scratch = .{};
    try std.testing.expectEqual(corrected, @as(i16, @bitCast(see_mod.see(&p, &s3, .white, 21, 9))));
}
