//! Differential tests of src/movegen.zig against calls of the five move generators
//! recorded from the running original (tests/golden/movegen/gen_*.zst, made by
//! tools/port/gen_movegen_gen_vectors.py, whose docstring defines the format), and the
//! DEV-003 test.

const std = @import("std");
const pos = @import("position.zig");
const see_mod = @import("see.zig");
const mg = @import("movegen.zig");
const dg = @import("original.zig").dgroup;

const max_ply_lists = 35;

/// The state of one recorded call, as the port holds it.
const State = struct {
    p: pos.Position = .{},
    s: see_mod.Scratch = .{},
    v: mg.SearchVars = .{},
    /// DG:39AE, the tactical generator's king rule (its home is `EvalVars`; the generator
    /// takes its value).
    king_rule: u8 = 0,
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
    .{ .name = "SEE attackers", .dg = 0x9FEC, .len = 116 },
    .{ .name = "SEE defenders", .dg = 0xA060, .len = 32 },
    .{ .name = "SEE gains", .dg = 0x70E5, .len = 11 },
    .{ .name = "SEE net", .dg = 0xB4E6, .len = 10 },
    .{ .name = "ep squares", .dg = 0x9EC8, .len = 46 },
    .{ .name = "O-O stamps", .dg = 0xB426, .len = 4 },
    .{ .name = "O-O-O stamps", .dg = 0x3A30, .len = 4 },
    .{ .name = "piece material", .dg = 0xAE38, .len = 4 },
    .{ .name = "bishop hint", .dg = 0x725C, .len = 1 },
    .{ .name = "rook hint", .dg = 0xA8D8, .len = 2 },
    .{ .name = "queen hint", .dg = 0xA846, .len = 2 },
    .{ .name = "check flag", .dg = 0x73F2, .len = 1 },
    .{ .name = "king rule", .dg = 0x39AE, .len = 1 },
    .{ .name = "marks", .dg = 0x781A, .len = mg.marks_len },
    .{ .name = "unscored list", .dg = 0xB106, .len = 400 },
    .{ .name = "move lists", .dg = 0x3A34, .len = 400 * max_ply_lists },
};
const image_size = blk: {
    var n: usize = 0;
    for (regions) |r| n += r.len;
    break :blk n;
};
const Image = [image_size]u8;

/// Constant data the generators read, as the recorder writes it in the header.
const const_ranges = [_]struct { u16, u16 }{
    .{ 0x0470, 0x42 }, .{ 0x0A68 - 255, 375 }, .{ 0x0B66 - 255, 375 },             .{ 0x0CFF - 255, 375 },
    .{ 0x0E16, 256 },  .{ 0x1508, 16 },        .{ 0x1A44, 0x1A80 + 240 - 0x1A44 }, .{ 0x28CC, 0x28F6 - 0x28CC },
};

/// Copies between the image and the state; `to_image` chooses the direction.
fn transfer(comptime to_image: bool, st: *State, img: *Image) void {
    var o: usize = 0;
    const T = struct {
        fn bytes(comptime ti: bool, im: *Image, off: *usize, part: []u8) void {
            if (ti) @memcpy(im[off.*..][0..part.len], part) else @memcpy(part, im[off.*..][0..part.len]);
            off.* += part.len;
        }
        fn word(comptime ti: bool, im: *Image, off: *usize, w: *u16) void {
            const b = im[off.*..][0..2];
            if (ti) std.mem.writeInt(u16, b, w.*, .little) else w.* = std.mem.readInt(u16, b, .little);
            off.* += 2;
        }
    };
    const p = &st.p;
    T.bytes(to_image, img, &o, &p.board);
    T.bytes(to_image, img, &o, &p.piece_list);
    T.bytes(to_image, img, &o, &p.pawn_attacks[0]);
    T.bytes(to_image, img, &o, &p.pawn_attacks[1]);
    T.bytes(to_image, img, &o, &p.king_rays[0]);
    T.bytes(to_image, img, &o, &p.king_rays[1]);
    T.bytes(to_image, img, &o, &st.s.attackers);
    T.bytes(to_image, img, &o, &st.s.defenders);
    T.bytes(to_image, img, &o, &st.s.gain);
    T.bytes(to_image, img, &o, st.s.net[0..10]);
    T.bytes(to_image, img, &o, p.ep_square_by_ply[0..46]);
    T.word(to_image, img, &o, &p.oo_lost_at[0]);
    T.word(to_image, img, &o, &p.oo_lost_at[1]);
    T.word(to_image, img, &o, &p.ooo_lost_at[0]);
    T.word(to_image, img, &o, &p.ooo_lost_at[1]);
    T.word(to_image, img, &o, &p.piece_material[0]);
    T.word(to_image, img, &o, &p.piece_material[1]);
    T.bytes(to_image, img, &o, std.mem.asBytes(&st.v.bishop_hint));
    T.word(to_image, img, &o, &st.v.rook_hint);
    T.word(to_image, img, &o, &st.v.queen_hint);
    T.bytes(to_image, img, &o, std.mem.asBytes(&st.v.check_flag));
    T.bytes(to_image, img, &o, std.mem.asBytes(&st.king_rule));
    T.bytes(to_image, img, &o, &st.v.marks);
    T.bytes(to_image, img, &o, std.mem.sliceAsBytes(&st.v.unscored));
    T.bytes(to_image, img, &o, std.mem.sliceAsBytes(&st.lists));
    std.debug.assert(o == image_size);
}

fn describe(buf: []u8, off: usize) []const u8 {
    var o: usize = 0;
    for (regions) |r| {
        if (off < o + r.len) {
            const i = off - o;
            if (r.dg == 0x3A34) return std.fmt.bufPrint(buf, "move list of ply {d}, entry {d}, byte {d} (DG:{X:0>4})", .{ i / 400, i % 400 / 4, i % 4, r.dg + i }) catch r.name;
            if (r.dg == 0xB106) return std.fmt.bufPrint(buf, "unscored list entry {d}, byte {d} (DG:{X:0>4})", .{ i / 4, i % 4, r.dg + i }) catch r.name;
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
    const path = try std.fmt.bufPrint(&path_buf, "{s}/movegen/{s}", .{ dir, name });
    const compressed = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, gpa, .limited(64 << 20));
    defer gpa.free(compressed);
    var in: std.Io.Reader = .fixed(compressed);
    const window = try gpa.alloc(u8, std.compress.zstd.default_window_len + std.compress.zstd.block_size_max);
    defer gpa.free(window);
    var zd = std.compress.zstd.Decompress.init(&in, window, .{});
    return zd.reader.allocRemaining(gpa, .limited(512 << 20));
}

const names = [_][]const u8{ "", "gen_all_moves", "gen_tactical_moves", "gen_tactical_moves_no_losers", "gen_quiescence_moves", "gen_captures" };

/// Calls replayed per tag 1..5, and calls of a generator not yet ported (skipped: their
/// recorded effect is applied without running anything).
const Counts = struct {
    replayed: [6]usize = @splat(0),
    skipped: [6]usize = @splat(0),
    /// Per tag, over the replayed calls: FFFFh returns, empty lists, and the moves of
    /// each kind in the returned lists (castling, en passant, promotion).
    features: [6][5]usize = @splat(@splat(0)),

    fn count(c: *Counts, tag: u8, ax: u16, list: []const pos.Move) void {
        const f = &c.features[tag];
        if (ax == mg.king_capture) {
            f[0] += 1;
            return;
        }
        if (ax == 0) f[1] += 1;
        for (list[0..ax]) |m| switch (m.flag) {
            pos.flag_castle => f[2] += 1,
            pos.flag_en_passant => f[3] += 1,
            2...5 => f[4] += 1,
            else => {},
        };
    }
};

/// Runs generator `tag` on the state; null if it is not ported yet.
fn runGenerator(st: *State, tag: u8, side: pos.Side, ply: usize, stray: mg.StrayBytes) ?u16 {
    const list = &st.lists[ply];
    return switch (tag) {
        1 => mg.genAllMoves(.original, &st.p, &st.s, &st.v, list, side, ply, stray),
        2 => mg.genTacticalMoves(&st.p, &st.s, &st.v, st.king_rule, list, side, ply),
        3 => mg.genTacticalMovesNoLosers(&st.p, &st.s, &st.v, list, side, ply),
        4 => mg.genQuiescenceMoves(&st.p, &st.s, &st.v, list, side, ply),
        5 => mg.genCaptures(&st.p, &st.s, &st.v, list, side, ply),
        else => null,
    };
}

fn replay(gpa: std.mem.Allocator, name: []const u8) !Counts {
    const data = try readVectors(gpa, name);
    defer gpa.free(data);
    var c: Cursor = .{ .d = data };
    try std.testing.expectEqualSlices(u8, "MCGV", c.take(4));
    try std.testing.expectEqual(@as(u16, 1), c.int(u16));
    try std.testing.expectEqual(@as(u16, image_size), c.int(u16));
    try std.testing.expectEqual(@as(u16, const_ranges.len), c.int(u16));
    // The constant data, as it was in the running original, equals what the port reads
    // from the executable.
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
        switch (tag) {
            0 => {
                for (1..6) |t| try std.testing.expectEqual(counts.replayed[t] + counts.skipped[t], c.int(u32));
                return counts;
            },
            9 => {
                // A keyframe: the whole image before the next call, which the next
                // call's change list is taken against.
                @memcpy(&truth, c.take(image_size));
                continue;
            },
            1...5 => {},
            else => return error.BadRecordTag,
        }
        const side_byte = c.byte();
        const ply: usize = c.byte();
        var stray: mg.StrayBytes = .{};
        if (tag == 1) {
            const b = c.take(4);
            stray = .{ .white_pawn_capture = b[0], .white_king_capture = b[1], .black_pawn_capture = b[2], .black_king_capture = b[3] };
        }
        c.apply(&truth);
        const ax = c.int(u16);
        st.* = .{};
        transfer(false, st, &truth);
        const side: pos.Side = if (side_byte == 0) .white else .black;
        const result = runGenerator(st, tag, side, ply, stray);
        c.apply(&truth);
        if (result) |got_ax| {
            transfer(true, st, got);
            if (got_ax != ax or !std.mem.eql(u8, &truth, got)) {
                var buf: [96]u8 = undefined;
                std.debug.print("\n{s}: call {d} differs: {s}(side {d}, ply {d}): AX want {X:0>4}, got {X:0>4}\n", .{ name, index, names[tag], side_byte, ply, ax, got_ax });
                for (truth, got, 0..) |want, have, off| {
                    if (want != have) {
                        std.debug.print("  first differing byte: {s}: want {X:0>2}, got {X:0>2}\n", .{ describe(&buf, off), want, have });
                        break;
                    }
                }
                return error.MismatchWithOriginal;
            }
            counts.replayed[tag] += 1;
            counts.count(tag, ax, &st.lists[ply]);
        } else {
            counts.skipped[tag] += 1;
        }
        index += 1;
    }
}

const runs = [_][]const u8{ "gen_A.zst", "gen_C.zst", "gen_D.zst", "gen_E.zst", "gen_G.zst", "gen_A5.zst" };

test "move generators: replay every recorded call of the original" {
    const gpa = std.testing.allocator;
    var total: Counts = .{};
    for (runs) |name| {
        const n = try replay(gpa, name);
        std.debug.print("movegen vectors {s}:", .{name});
        for (1..6) |t| {
            std.debug.print(" {s} {d}", .{ names[t], n.replayed[t] });
            if (n.skipped[t] != 0) std.debug.print(" (+{d} not ported, skipped)", .{n.skipped[t]});
            std.debug.print(",", .{});
            total.replayed[t] += n.replayed[t];
            total.skipped[t] += n.skipped[t];
            for (0..5) |k| total.features[t][k] += n.features[t][k];
        }
        std.debug.print(" calls replayed, all equal\n", .{});
    }
    std.debug.print("movegen vectors total:", .{});
    for (1..6) |t| std.debug.print(" {s} {d},", .{ names[t], total.replayed[t] });
    std.debug.print("\n", .{});
    for (1..6) |t| {
        const f = total.features[t];
        std.debug.print("  {s}: {d} FFFFh returns, {d} empty lists; moves: {d} castling, {d} en passant, {d} promotions\n", .{ names[t], f[0], f[1], f[2], f[3], f[4] });
    }
}

// ---------------------------------------------------------------------------
// Benchmark
// ---------------------------------------------------------------------------

const bench = @import("bench.zig");

/// The inputs of one recorded call: every field a generator reads. The marks are kept
/// sparse (their non-zero bytes, in `BenchData.marks`).
const BenchInput = struct {
    board: [120]u8,
    piece_list: [32]u8,
    pawn_attacks: [2][120]u8,
    king_rays: [2][120]u8,
    oo: [2]u16,
    ooo: [2]u16,
    piece_material: [2]u16,
    ep: u8,
    ply: u8,
    side: pos.Side,
    stray: mg.StrayBytes,
    bishop_hint: u8,
    rook_hint: u16,
    queen_hint: u16,
    check_flag: u8,
    king_rule: u8,
    marks_from: u32,
    marks_to: u32,
};

const MarkByte = struct { at: u16, v: u8 };

const BenchData = struct {
    calls: [6]std.ArrayList(BenchInput) = @splat(.empty),
    seen: [6]usize = @splat(0),
    marks: std.ArrayList(MarkByte) = .empty,

    fn deinit(d: *BenchData, gpa: std.mem.Allocator) void {
        for (&d.calls) |*l| l.deinit(gpa);
        d.marks.deinit(gpa);
    }
};

/// Every `bench_stride`-th recorded call of a generator is kept, at most `bench_cap`, so
/// the inputs stay in the cache and sample every run.
const bench_cap = 6_000;
const bench_stride = 6;

/// Reads the recorded calls of `name` into `d` (inputs only).
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
        switch (tag) {
            0 => return,
            9 => {
                @memcpy(&truth, c.take(image_size));
                continue;
            },
            else => {},
        }
        const side_byte = c.byte();
        const ply: usize = c.byte();
        var stray: mg.StrayBytes = .{};
        if (tag == 1) {
            const b = c.take(4);
            stray = .{ .white_pawn_capture = b[0], .white_king_capture = b[1], .black_pawn_capture = b[2], .black_king_capture = b[3] };
        }
        c.apply(&truth);
        _ = c.int(u16);
        d.seen[tag] += 1;
        if (d.seen[tag] % bench_stride == 0 and d.calls[tag].items.len < bench_cap) {
            st.* = .{};
            transfer(false, st, &truth);
            const from: u32 = @intCast(d.marks.items.len);
            for (st.v.marks, 0..) |m, i| if (m != 0) try d.marks.append(gpa, .{ .at = @intCast(i), .v = m });
            try d.calls[tag].append(gpa, .{
                .board = st.p.board,
                .piece_list = st.p.piece_list,
                .pawn_attacks = st.p.pawn_attacks,
                .king_rays = st.p.king_rays,
                .oo = st.p.oo_lost_at,
                .ooo = st.p.ooo_lost_at,
                .piece_material = st.p.piece_material,
                .ep = st.p.ep_square_by_ply[ply],
                .ply = @intCast(ply),
                .side = if (side_byte == 0) .white else .black,
                .stray = stray,
                .bishop_hint = st.v.bishop_hint,
                .rook_hint = st.v.rook_hint,
                .queen_hint = st.v.queen_hint,
                .check_flag = st.v.check_flag,
                .king_rule = st.king_rule,
                .marks_from = from,
                .marks_to = @intCast(d.marks.items.len),
            });
        }
        c.apply(&truth);
    }
}

/// The working state: the inputs copied in, the marks set from their sparse form and
/// cleared after the call.
fn loadInput(st: *State, in: *const BenchInput, marks: []const MarkByte) void {
    st.p.board = in.board;
    st.p.piece_list = in.piece_list;
    st.p.pawn_attacks = in.pawn_attacks;
    st.p.king_rays = in.king_rays;
    st.p.oo_lost_at = in.oo;
    st.p.ooo_lost_at = in.ooo;
    st.p.piece_material = in.piece_material;
    st.p.ep_square_by_ply[in.ply] = in.ep;
    st.v.bishop_hint = in.bishop_hint;
    st.v.rook_hint = in.rook_hint;
    st.v.queen_hint = in.queen_hint;
    st.v.check_flag = in.check_flag;
    st.king_rule = in.king_rule;
    for (marks[in.marks_from..in.marks_to]) |m| st.v.marks[m.at] = m.v;
}

fn clearMarks(st: *State, in: *const BenchInput, marks: []const MarkByte) void {
    for (marks[in.marks_from..in.marks_to]) |m| st.v.marks[m.at] = 0;
}

test "bench: movegen: the five generators over the recorded calls" {
    if (!bench.enabled) return;
    const gpa = std.heap.page_allocator;
    var d: BenchData = .{};
    defer d.deinit(gpa);
    for (runs) |name| try collect(gpa, name, &d);
    const st = try gpa.create(State);
    defer gpa.destroy(st);
    st.* = .{};
    const passes = 40;
    for (1..6) |tag| {
        const calls = d.calls[tag].items;
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
                sum +%= runGenerator(st, @intCast(tag), in.side, in.ply, in.stray).?;
                clearMarks(st, in, d.marks.items);
            }
            best.pass(t0);
            bench.keep(sum);
        }
        best.report(names[tag], calls.len, passes, over.ns);
    }
}

test "bench: movegen: the five generators with DEV-003 and every pos.Fixes fix on" {
    if (!bench.enabled) return;
    const gpa = std.heap.page_allocator;
    var d: BenchData = .{};
    defer d.deinit(gpa);
    for (runs) |name| try collect(gpa, name, &d);
    const st = try gpa.create(State);
    defer gpa.destroy(st);
    st.* = .{};
    const passes = 40;
    for (1..6) |tag| {
        const calls = d.calls[tag].items;
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
                sum +%= runFixed(pos.Fixes.corrected, st, @intCast(tag), in.side, in.ply);
                clearMarks(st, in, d.marks.items);
            }
            best.pass(t0);
            bench.keep(sum);
        }
        best.report(names[tag], calls.len, passes, over.ns);
    }
}

// ---------------------------------------------------------------------------
// DEV-003
// ---------------------------------------------------------------------------

/// An empty board inside its border, no pieces in the lists (every entry 0, a border
/// square, which the generators skip).
fn emptyPosition() pos.Position {
    var p: pos.Position = .{};
    @memset(&p.board, pos.border);
    for (2..10) |r| @memset(p.board[10 * r + 1 ..][0..8], pos.empty);
    return p;
}

test "DEV-003: gen_all_moves scores pawn captures with a stray byte; corrected: the mark" {
    // White pawn e4 (55) can take a Black knight on d5 (64) and a Black pawn on f5 (66);
    // the push to e5 is free.
    var p = emptyPosition();
    p.board[55] = pos.white_pawn;
    p.board[64] = pos.black_knight;
    p.board[66] = pos.black_pawn;
    p.piece_list[8] = 55; // White's first pawn slot
    const vars = try std.testing.allocator.create(mg.SearchVars);
    defer std.testing.allocator.destroy(vars);
    vars.* = .{};
    var s: see_mod.Scratch = .{};
    var list: mg.MoveList = @splat(.{ .from = 0, .to = 0, .flag = 0 });

    // Original: victim value (knight 7, pawn 2) + the stray byte 79h. The knight
    // capture's score wraps to -128 and it sorts last.
    const stray: mg.StrayBytes = .{ .white_pawn_capture = 0x79 };
    var q = p;
    try std.testing.expectEqual(@as(u16, 3), mg.genAllMoves(.original, &q, &s, vars, &list, .white, 0, stray));
    try std.testing.expectEqual(pos.Move{ .from = 55, .to = 66, .flag = 0, .score = 0x7B }, list[0]);
    try std.testing.expectEqual(pos.Move{ .from = 55, .to = 64, .flag = 0, .score = 0x80 }, list[1]);
    try std.testing.expectEqual(@as(u8, 65), list[2].to);

    // Corrected: victim value + the move's mark (0 here): the knight capture first.
    q = p;
    try std.testing.expectEqual(@as(u16, 3), mg.genAllMoves(.corrected, &q, &s, vars, &list, .white, 0, stray));
    try std.testing.expectEqual(pos.Move{ .from = 55, .to = 64, .flag = 0, .score = 7 }, list[0]);
    try std.testing.expectEqual(pos.Move{ .from = 55, .to = 66, .flag = 0, .score = 2 }, list[1]);

    // With a mark on e4xf5 the corrected score adds it, and the mark is not used up.
    vars.marks[mg.markIndex(55, 66)] = 10;
    q = p;
    try std.testing.expectEqual(@as(u16, 3), mg.genAllMoves(.corrected, &q, &s, vars, &list, .white, 0, stray));
    try std.testing.expectEqual(pos.Move{ .from = 55, .to = 66, .flag = 0, .score = 12 }, list[0]);
    try std.testing.expectEqual(pos.Move{ .from = 55, .to = 64, .flag = 0, .score = 7 }, list[1]);
    try std.testing.expectEqual(@as(u8, 10), vars.marks[mg.markIndex(55, 66)]);
    // The original ignores the mark.
    q = p;
    _ = mg.genAllMoves(.original, &q, &s, vars, &list, .white, 0, stray);
    try std.testing.expectEqual(pos.Move{ .from = 55, .to = 66, .flag = 0, .score = 0x7B }, list[0]);
}

// ---------------------------------------------------------------------------
// The class C fixes of owner decision 27 that touch the generators (pos.Fixes):
// DEV-004, DEV-005, DEV-007, DEV-008
// ---------------------------------------------------------------------------

const Fix = enum { dev004, dev005, dev007, dev008 };
const all_fixes = [_]Fix{ .dev004, .dev005, .dev007, .dev008 };

/// `pos.Fixes.original` with the one switch `f` on.
fn fixesOf(comptime f: Fix) pos.Fixes {
    var x = pos.Fixes.original;
    switch (f) {
        .dev004 => x.dev004_promotion_capture_score = true,
        .dev005 => x.dev005_bishop_check_score = true,
        .dev007 => x.dev007_black_pawn_push = true,
        .dev008 => x.dev008_castling_mark = true,
    }
    return x;
}

/// The generators (tags as in the vectors) that read the switch of `f`.
fn touches(f: Fix, tag: u8) bool {
    return switch (f) {
        .dev004 => tag == 5,
        .dev005 => tag == 3 or tag == 4,
        .dev007, .dev008 => tag == 1,
    };
}

/// Generator `tag` through its `...Fixes` variant, with DEV-003 corrected, as the engine
/// runs it.
fn runFixed(comptime pf: pos.Fixes, st: *State, tag: u8, side: pos.Side, ply: usize) u16 {
    const list = &st.lists[ply];
    return switch (tag) {
        1 => mg.genAllMovesFixes(.corrected, pf, &st.p, &st.s, &st.v, list, side, ply, .{}),
        2 => mg.genTacticalMovesFixes(pf, &st.p, &st.s, &st.v, st.king_rule, list, side, ply),
        3 => mg.genTacticalMovesNoLosersFixes(pf, &st.p, &st.s, &st.v, list, side, ply),
        4 => mg.genQuiescenceMovesFixes(pf, &st.p, &st.s, &st.v, list, side, ply),
        5 => mg.genCapturesFixes(pf, &st.p, &st.s, &st.v, list, side, ply),
        else => unreachable,
    };
}

/// A score byte that no scored move of gen_all_moves takes with DEV-003 corrected. It is
/// written into every entry of the unscored buffer (DG:B106) before a comparison, so that
/// a move of the unscored group is recognised by its score byte.
const unscored_sentinel: u8 = 0xEE;

/// Whether a move whose score byte differs between the original (`m0`) and the fix
/// (`m1`) is a move the fix is meant to change, given the value it is meant to have:
/// White's (Black's, the sibling generators') 28h for DEV-004; White's 2 for DEV-005;
/// for DEV-007 a Black push the original scored 1, now in the unscored group as White's
/// mirror puts it; for DEV-008 a castling move, now its own mark + 3.
fn expectedChange(f: Fix, before: *const State, m0: pos.Move, m1: pos.Move) bool {
    const b = &before.p.board;
    return switch (f) {
        .dev004 => m0.flag == 5 and b[m0.from] == pos.white_pawn and (m0.score == 9 or m0.score == 11) and m1.score == 0x28,
        .dev005 => b[m0.from] == pos.black_bishop and m0.score == 1 and m1.score == 2,
        .dev007 => b[m0.from] == pos.black_pawn and m0.flag == pos.flag_normal and
            (@as(i32, m0.from) - m0.to == 10 or @as(i32, m0.from) - m0.to == 20) and m0.score == 1 and m1.score == unscored_sentinel,
        .dev008 => m0.flag == pos.flag_castle and m1.score == before.v.marks[mg.markIndex(m1.from, m1.to)] +% 3,
    };
}

const FixStats = struct {
    /// Calls of a generator that reads the switch.
    calls: usize = 0,
    /// Calls whose list or state differs with the switch on.
    changed_calls: usize = 0,
    /// Moves whose score byte differs.
    changed_moves: usize = 0,
};

const Work = struct { st0: State, st1: State, img0: Image, img1: Image };

/// Offsets in the image of the move lists and of the unscored buffer (DG:B106).
const list_region: usize = image_size - 400 * max_ply_lists;
const unscored_region: usize = list_region - 400;

/// Runs generator `tag` on `before` without and with the switch of `f` (DEV-003
/// corrected in both) and checks that the fix changes nothing but what it is meant to:
/// the same AX; every byte of state outside the ply's list the same (the unscored buffer
/// excepted for DEV-007, whose demoted pushes go there); the bytes beyond the count the
/// same; the same moves (from, to, flag), each once; and every score byte that differs
/// is one `expectedChange` allows. The two results are left in `w`.
fn compareFix(comptime f: Fix, before: *const State, tag: u8, side: pos.Side, ply: usize, w: *Work, stats: *FixStats) !void {
    w.st0 = before.*;
    if (tag == 1) for (&w.st0.v.unscored) |*m| {
        m.score = unscored_sentinel;
    };
    w.st1 = w.st0;
    const ax0 = runFixed(pos.Fixes.original, &w.st0, tag, side, ply);
    const ax1 = runFixed(comptime fixesOf(f), &w.st1, tag, side, ply);
    try std.testing.expectEqual(ax0, ax1);
    stats.calls += 1;
    transfer(true, &w.st0, &w.img0);
    transfer(true, &w.st1, &w.img1);
    if (std.mem.eql(u8, &w.img0, &w.img1)) return;
    stats.changed_calls += 1;
    const lo = list_region + 400 * ply;
    for (w.img0, w.img1, 0..) |a, b, off| {
        if (a == b) continue;
        const in_list = off >= lo and off < lo + 400;
        const in_unscored = f == .dev007 and off >= unscored_region and off < list_region;
        if (!in_list and !in_unscored) {
            var buf: [96]u8 = undefined;
            std.debug.print("\n{s}: {s} changed {s}: {X:0>2} -> {X:0>2}\n", .{ @tagName(f), names[tag], describe(&buf, off), a, b });
            return error.FixChangedState;
        }
    }
    if (ax0 == mg.king_capture) return; // lists left part-written: the state outside them is checked
    try std.testing.expectEqualSlices(u8, w.img0[lo + 4 * ax0 .. lo + 400], w.img1[lo + 4 * ax1 .. lo + 400]);
    const l0 = w.st0.lists[ply][0..ax0];
    const l1 = w.st1.lists[ply][0..ax1];
    var used: [mg.list_len]bool = @splat(false);
    for (l0) |m0| {
        const j = for (l1, 0..) |m1, k| {
            if (!used[k] and m1.from == m0.from and m1.to == m0.to and m1.flag == m0.flag) break k;
        } else return error.FixChangedMoves;
        used[j] = true;
        if (l1[j].score == m0.score) continue;
        if (!expectedChange(f, before, m0, l1[j])) {
            std.debug.print("\n{s}: {s}: move {X:0>2}-{X:0>2} flag {d}: score {X:0>2} -> {X:0>2}\n", .{ @tagName(f), names[tag], m0.from, m0.to, m0.flag, m0.score, l1[j].score });
            return error.FixChangedOtherScore;
        }
        stats.changed_moves += 1;
    }
}

/// Every recorded call of `name`, through `compareFix` for each fix that reads it.
fn fixReplay(gpa: std.mem.Allocator, name: []const u8, stats: *[all_fixes.len]FixStats, w: *Work, before: *State) !void {
    const data = try readVectors(gpa, name);
    defer gpa.free(data);
    var c: Cursor = .{ .d = data };
    _ = c.take(4 + 6);
    inline for (const_ranges) |r| _ = c.take(4 + r[1]);
    const truth = try gpa.create(Image);
    defer gpa.destroy(truth);
    truth.* = c.take(image_size)[0..image_size].*;
    while (true) {
        const tag = c.byte();
        switch (tag) {
            0 => return,
            9 => {
                @memcpy(truth, c.take(image_size));
                continue;
            },
            else => {},
        }
        const side_byte = c.byte();
        const ply: usize = c.byte();
        if (tag == 1) _ = c.take(4);
        c.apply(truth);
        _ = c.int(u16);
        before.* = .{};
        transfer(false, before, truth);
        const side: pos.Side = if (side_byte == 0) .white else .black;
        inline for (all_fixes, 0..) |f, k| {
            if (touches(f, tag)) try compareFix(f, before, tag, side, ply, w, &stats[k]);
        }
        c.apply(truth);
    }
}

test "DEV-004, 005, 007, 008: each fix changes only its own moves' scores in the recorded calls" {
    const gpa = std.testing.allocator;
    const w = try gpa.create(Work);
    defer gpa.destroy(w);
    const before = try gpa.create(State);
    defer gpa.destroy(before);
    var stats: [all_fixes.len]FixStats = @splat(.{});
    for (runs) |name| try fixReplay(gpa, name, &stats, w, before);
    for (all_fixes, stats) |f, s| {
        std.debug.print("movegen {s}: {d} of {d} recorded calls changed, {d} moves rescored\n", .{ @tagName(f), s.changed_calls, s.calls, s.changed_moves });
    }
}

fn emptyState(gpa: std.mem.Allocator) !*State {
    const st = try gpa.create(State);
    st.* = .{};
    st.p = emptyPosition();
    return st;
}

/// Puts `code` on `sq` and in piece-list entry `entry`.
fn place(st: *State, entry: usize, sq: u8, code: u8) void {
    st.p.board[sq] = code;
    st.p.piece_list[entry] = sq;
}

fn mv(from: u8, to: u8, flag: u8, score: u8) pos.Move {
    return .{ .from = from, .to = to, .flag = flag, .score = score };
}

test "DEV-004: gen_captures scores White's queen promotion by capture 9 or 11; corrected 28h, Black's value" {
    const gpa = std.testing.allocator;
    const w = try gpa.create(Work);
    defer gpa.destroy(w);
    // White pawn g7 can take a rook on f8 (step 9) or a knight on h8 (step 11); g8 is
    // blocked, so there is no promotion by push.
    const st = try emptyState(gpa);
    defer gpa.destroy(st);
    place(st, 8, 87, pos.white_pawn);
    st.p.board[96] = pos.black_rook;
    st.p.board[97] = pos.black_bishop;
    st.p.board[98] = pos.black_knight;
    var stats: FixStats = .{};
    try compareFix(.dev004, st, 5, .white, 0, w, &stats);
    try std.testing.expectEqual(@as(usize, 1), stats.changed_calls);
    try std.testing.expectEqual(@as(usize, 2), stats.changed_moves);
    try std.testing.expectEqualSlices(pos.Move, &.{ mv(87, 96, 5, 9), mv(87, 96, 2, 0x23), mv(87, 98, 5, 11), mv(87, 98, 2, 0x23) }, w.st0.lists[0][0..4]);
    try std.testing.expectEqualSlices(pos.Move, &.{ mv(87, 96, 5, 0x28), mv(87, 96, 2, 0x23), mv(87, 98, 5, 0x28), mv(87, 98, 2, 0x23) }, w.st1.lists[0][0..4]);

    // Black's mirror (pawn g2 taking on h1 and f1) scores 28h with or without the fix.
    const bl = try emptyState(gpa);
    defer gpa.destroy(bl);
    place(bl, 24, 37, pos.black_pawn);
    bl.p.board[26] = pos.white_knight;
    bl.p.board[27] = pos.white_bishop;
    bl.p.board[28] = pos.white_rook;
    stats = .{};
    try compareFix(.dev004, bl, 5, .black, 0, w, &stats);
    try std.testing.expectEqual(@as(usize, 0), stats.changed_calls);
    try std.testing.expectEqualSlices(pos.Move, &.{ mv(37, 28, 5, 0x28), mv(37, 28, 2, 0x23), mv(37, 26, 5, 0x28), mv(37, 26, 2, 0x23) }, w.st0.lists[0][0..4]);
}

/// A direction code of the diagonal kind (1..4, or 9..12 when `black`) whose step is
/// `step` or its negation.
fn diagonalCode(black: bool, step: i8) u8 {
    const dir_step: [17]i8 = @bitCast(dg(0x0490, 17));
    const first: u8 = if (black) 9 else 1;
    for (first..first + 4) |c| {
        if (dir_step[c] == step or dir_step[c] == -step) return @intCast(c);
    }
    unreachable;
}

/// Black bishop a2 with the White king on h1, whose a8-h1 diagonal (map code on g2..a8)
/// the bishop reaches on d5; or the mirror, White bishop a7 with the Black king on h8,
/// reaching the a1-h8 diagonal on d4. Both kings in their lists.
fn bishopCheckState(gpa: std.mem.Allocator, black: bool) !*State {
    const st = try emptyState(gpa);
    place(st, 7, 28, pos.white_king);
    place(st, 23, 98, pos.black_king);
    st.p.oo_lost_at = .{ 1, 1 };
    st.p.ooo_lost_at = .{ 1, 1 };
    if (black) {
        place(st, 18, 31, pos.black_bishop);
        const code = diagonalCode(false, 9);
        var s: usize = 37;
        while (s <= 91) : (s += 9) st.p.king_rays[0][s] = code;
    } else {
        place(st, 2, 81, pos.white_bishop);
        const code = diagonalCode(true, 11);
        var s: usize = 87;
        while (s >= 21) : (s -= 11) st.p.king_rays[1][s] = code;
    }
    return st;
}

test "DEV-005: the quiet bishop check scores 1 for Black, 2 for White; corrected 2 for both (0EF8:9528, 1E9D:25A0)" {
    const gpa = std.testing.allocator;
    const w = try gpa.create(Work);
    defer gpa.destroy(w);
    const bl = try bishopCheckState(gpa, true);
    defer gpa.destroy(bl);
    const wh = try bishopCheckState(gpa, false);
    defer gpa.destroy(wh);
    for ([_]u8{ 4, 3 }) |tag| {
        var stats: FixStats = .{};
        try compareFix(.dev005, bl, tag, .black, 0, w, &stats);
        try std.testing.expectEqual(@as(usize, 1), stats.changed_moves);
        try std.testing.expectEqualSlices(pos.Move, &.{mv(31, 64, 0, 1)}, w.st0.lists[0][0..1]);
        try std.testing.expectEqualSlices(pos.Move, &.{mv(31, 64, 0, 2)}, w.st1.lists[0][0..1]);
        // White's mirror: 2 with or without the fix.
        stats = .{};
        try compareFix(.dev005, wh, tag, .white, 0, w, &stats);
        try std.testing.expectEqual(@as(usize, 0), stats.changed_calls);
        try std.testing.expectEqualSlices(pos.Move, &.{mv(81, 54, 0, 2)}, w.st0.lists[0][0..1]);
    }
}

test "DEV-007: Black's pawn push scores 1 for an undefended attack on to-11; corrected: White's mirror" {
    const gpa = std.testing.allocator;
    const w = try gpa.create(Work);
    defer gpa.destroy(w);
    const S = unscored_sentinel;
    // Black pawn e7; a White knight on d5 (e6 - 11); e6 not defended by a Black pawn.
    const bl = try emptyState(gpa);
    defer gpa.destroy(bl);
    place(bl, 24, 85, pos.black_pawn);
    bl.p.board[64] = pos.white_knight;
    var stats: FixStats = .{};
    try compareFix(.dev007, bl, 1, .black, 0, w, &stats);
    try std.testing.expectEqual(@as(usize, 1), stats.changed_moves);
    try std.testing.expectEqualSlices(pos.Move, &.{ mv(85, 75, 0, 1), mv(85, 65, 0, S) }, w.st0.lists[0][0..2]);
    try std.testing.expectEqualSlices(pos.Move, &.{ mv(85, 75, 0, S), mv(85, 65, 0, S) }, w.st1.lists[0][0..2]);
    // The demoted push is written to the unscored buffer, as White's would be.
    try std.testing.expectEqual(@as(u8, 75), w.st1.v.unscored[0].to);
    try std.testing.expectEqual(@as(u8, 65), w.st0.v.unscored[0].to);

    // White's mirror (pawn e2, Black knight on d4 = e3 + 9, e3 not defended): unscored.
    const wh = try emptyState(gpa);
    defer gpa.destroy(wh);
    place(wh, 8, 35, pos.white_pawn);
    wh.p.board[54] = pos.black_knight;
    stats = .{};
    try compareFix(.dev007, wh, 1, .white, 0, w, &stats);
    try std.testing.expectEqual(@as(usize, 0), stats.changed_calls);
    try std.testing.expectEqualSlices(pos.Move, &.{ mv(35, 45, 0, S), mv(35, 55, 0, S) }, w.st0.lists[0][0..2]);

    // Defended (a Black pawn attacks e6), or the knight on f5 (e6 - 9): the original
    // already agrees with the mirror.
    bl.p.pawn_attacks[1][75] = 1;
    stats = .{};
    try compareFix(.dev007, bl, 1, .black, 0, w, &stats);
    try std.testing.expectEqual(@as(usize, 0), stats.changed_calls);
    try std.testing.expectEqual(mv(85, 75, 0, 1), w.st0.lists[0][0]);
    bl.p.pawn_attacks[1][75] = 0;
    bl.p.board[64] = pos.empty;
    bl.p.board[66] = pos.white_knight;
    stats = .{};
    try compareFix(.dev007, bl, 1, .black, 0, w, &stats);
    try std.testing.expectEqual(@as(usize, 0), stats.changed_calls);
    try std.testing.expectEqual(mv(85, 75, 0, S), w.st0.lists[0][0]);
}

test "DEV-008: castling is scored with the mark of e1-d2 (Black: f8-f1); corrected: its own mark" {
    const gpa = std.testing.allocator;
    const w = try gpa.create(Work);
    defer gpa.destroy(w);
    // White king e1, rook h1; O-O allowed; O-O-O not. e1-g1 a killer (mark 3), e1-d2 a
    // best move (mark 2).
    const wh = try emptyState(gpa);
    defer gpa.destroy(wh);
    place(wh, 7, 25, pos.white_king);
    place(wh, 4, 28, pos.white_rook);
    wh.p.oo_lost_at = .{ 0, 1 };
    wh.p.ooo_lost_at = .{ 1, 1 };
    wh.v.marks[mg.markIndex(25, 27)] = 3;
    wh.v.marks[mg.markIndex(25, 34)] = 2;
    var stats: FixStats = .{};
    try compareFix(.dev008, wh, 1, .white, 0, w, &stats);
    try std.testing.expectEqual(@as(usize, 1), stats.changed_moves);
    // The original reads e1-d2's mark after the king's step there used it up (2 -> 1).
    try std.testing.expectEqualSlices(pos.Move, &.{ mv(25, 27, pos.flag_castle, 4), mv(25, 34, 0, 2) }, w.st0.lists[0][0..2]);
    try std.testing.expectEqualSlices(pos.Move, &.{ mv(25, 27, pos.flag_castle, 6), mv(25, 34, 0, 2) }, w.st1.lists[0][0..2]);
    // The marks are left the same: d2's decremented, the castling's untouched.
    for ([_]*const State{ &w.st0, &w.st1 }) |s| {
        try std.testing.expectEqual(@as(u8, 1), s.v.marks[mg.markIndex(25, 34)]);
        try std.testing.expectEqual(@as(u8, 3), s.v.marks[mg.markIndex(25, 27)]);
    }

    // Black king e8, rook h8: e8 + 9 is off the board, and the byte read is the mark of
    // f8-f1 (here 2); the corrected score is e8-g8's own mark (3) + 3.
    try std.testing.expectEqual(mg.markIndex(96, 26), mg.markIndex(95, 95 + 9));
    const bl = try emptyState(gpa);
    defer gpa.destroy(bl);
    place(bl, 23, 95, pos.black_king);
    place(bl, 20, 98, pos.black_rook);
    bl.p.oo_lost_at = .{ 1, 0 };
    bl.p.ooo_lost_at = .{ 1, 1 };
    bl.v.marks[mg.markIndex(95, 97)] = 3;
    bl.v.marks[mg.markIndex(96, 26)] = 2;
    stats = .{};
    try compareFix(.dev008, bl, 1, .black, 0, w, &stats);
    try std.testing.expectEqual(@as(usize, 1), stats.changed_moves);
    try std.testing.expectEqual(mv(95, 97, pos.flag_castle, 5), w.st0.lists[0][0]);
    try std.testing.expectEqual(mv(95, 97, pos.flag_castle, 6), w.st1.lists[0][0]);
}
