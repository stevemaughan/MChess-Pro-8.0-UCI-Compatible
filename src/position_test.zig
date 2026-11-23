//! Differential tests of src/position.zig against calls recorded from the running
//! original (tests/golden/position/*.zst, made by tools/port/gen_position_vectors.py,
//! whose docstring defines the format), and the DEV-001 test.
//!
//! Each recorded call gives the modelled state at the routine's entry and at its
//! return, as the original had it. The test loads the entry state, makes the same call
//! on the Zig position, and compares every field of the result with the original's,
//! together with the bytes the routine reports through its pointers. The class C
//! fixes are off (`Fixes.original`).

const std = @import("std");
const pos = @import("position.zig");
const Position = pos.Position;

// ---------------------------------------------------------------------------
// The state image: model.FIELDS in order, each as it lies in DGROUP
// ---------------------------------------------------------------------------

const Field = struct { name: []const u8, dg: u16, kind: u8, count: u16 };

/// tools/research/position/model.py FIELDS, in order.
const fields = [_]Field{
    .{ .name = "board", .dg = 0x9EF6, .kind = 'b', .count = 120 },
    .{ .name = "wlist", .dg = 0xA03A, .kind = 'b', .count = 16 },
    .{ .name = "blist", .dg = 0xA04A, .kind = 'b', .count = 16 },
    .{ .name = "slot", .dg = 0xA28C, .kind = 'b', .count = 120 },
    .{ .name = "watt", .dg = 0xA51C, .kind = 'b', .count = 120 },
    .{ .name = "batt", .dg = 0x37DA, .kind = 'b', .count = 120 },
    .{ .name = "wmap", .dg = 0xA09E, .kind = 'b', .count = 120 },
    .{ .name = "bmap", .dg = 0xA164, .kind = 'b', .count = 120 },
    .{ .name = "wpf", .dg = 0xA8C8, .kind = 'b', .count = 10 },
    .{ .name = "bpf", .dg = 0x9EA8, .kind = 'b', .count = 10 },
    .{ .name = "wmat", .dg = 0x8DE4, .kind = 'w', .count = 1 },
    .{ .name = "bmat", .dg = 0x8DE6, .kind = 'w', .count = 1 },
    .{ .name = "wpiece_mat", .dg = 0xAE38, .kind = 'w', .count = 1 },
    .{ .name = "bpiece_mat", .dg = 0xAE3A, .kind = 'w', .count = 1 },
    .{ .name = "piece_mat", .dg = 0x378E, .kind = 'w', .count = 1 },
    .{ .name = "total_mat", .dg = 0xA420, .kind = 'w', .count = 1 },
    .{ .name = "mat_bal", .dg = 0xA35E, .kind = 'w', .count = 1 },
    .{ .name = "piece_bal", .dg = 0xA8D2, .kind = 'w', .count = 1 },
    .{ .name = "mat_bal2", .dg = 0xA4C6, .kind = 'w', .count = 1 },
    .{ .name = "qcap_bias", .dg = 0x7182, .kind = 'w', .count = 1 },
    .{ .name = "men", .dg = 0x154A, .kind = 'b', .count = 1 },
    .{ .name = "wpieces", .dg = 0x931A, .kind = 'b', .count = 1 },
    .{ .name = "bpieces", .dg = 0x931B, .kind = 'b', .count = 1 },
    .{ .name = "pawns", .dg = 0x90AA, .kind = 'b', .count = 1 },
    .{ .name = "wpawns", .dg = 0xAB1E, .kind = 'b', .count = 1 },
    .{ .name = "bpawns", .dg = 0x741A, .kind = 'b', .count = 1 },
    .{ .name = "wdark", .dg = 0xB520, .kind = 'b', .count = 1 },
    .{ .name = "bdark", .dg = 0xA354, .kind = 'b', .count = 1 },
    .{ .name = "wk_file", .dg = 0xA22E, .kind = 'b', .count = 1 },
    .{ .name = "bk_file", .dg = 0xA22F, .kind = 'b', .count = 1 },
    .{ .name = "wk_rank", .dg = 0x70F0, .kind = 'b', .count = 1 },
    .{ .name = "bk_rank", .dg = 0x70F1, .kind = 'b', .count = 1 },
    .{ .name = "lost_w_oo", .dg = 0xB426, .kind = 'w', .count = 1 },
    .{ .name = "lost_w_ooo", .dg = 0x3A30, .kind = 'w', .count = 1 },
    .{ .name = "lost_b_oo", .dg = 0xB428, .kind = 'w', .count = 1 },
    .{ .name = "lost_b_ooo", .dg = 0x3A32, .kind = 'w', .count = 1 },
    .{ .name = "game_ply", .dg = 0x9FC8, .kind = 'w', .count = 1 },
    .{ .name = "hash", .dg = 0x8CCC, .kind = 'b', .count = 6 },
    .{ .name = "pawn_hash", .dg = 0x8CD2, .kind = 'b', .count = 6 },
    .{ .name = "ep_sq", .dg = 0x9EC8, .kind = 'b', .count = 46 },
    .{ .name = "check", .dg = 0x8C06, .kind = 'b', .count = 64 },
    .{ .name = "rev", .dg = 0x8BBE, .kind = 'w', .count = 36 },
    .{ .name = "quiet", .dg = 0x3626, .kind = 'w', .count = 40 },
};

fn fieldSize(f: Field) usize {
    return f.count * @as(usize, if (f.kind == 'w') 2 else 1);
}

const state_size = blk: {
    var n: usize = 0;
    for (fields) |f| n += fieldSize(f);
    break :blk n;
};

const Image = [state_size]u8;

/// Moves the Zig position to or from a state image, field by field in `fields`
/// order. One list serves both directions so the two cannot disagree.
fn transfer(comptime to_image: bool, p: *Position, img: *Image) void {
    var o: usize = 0;
    const T = struct {
        fn bytes(io: *usize, im: *Image, s: []u8) void {
            if (to_image) @memcpy(im[io.*..][0..s.len], s) else @memcpy(s, im[io.*..][0..s.len]);
            io.* += s.len;
        }
        fn words(io: *usize, im: *Image, s: []u16) void {
            for (s) |*w| {
                const b = im[io.*..][0..2];
                if (to_image) std.mem.writeInt(u16, b, w.*, .little) else w.* = std.mem.readInt(u16, b, .little);
                io.* += 2;
            }
        }
        fn key(io: *usize, im: *Image, k: *u48) void {
            const b = im[io.*..][0..6];
            if (to_image) std.mem.writeInt(u48, b, k.*, .little) else k.* = std.mem.readInt(u48, b, .little);
            io.* += 6;
        }
    };
    T.bytes(&o, img, &p.board);
    T.bytes(&o, img, p.piece_list[0..16]);
    T.bytes(&o, img, p.piece_list[16..32]);
    T.bytes(&o, img, &p.square_slot);
    T.bytes(&o, img, &p.pawn_attacks[0]);
    T.bytes(&o, img, &p.pawn_attacks[1]);
    T.bytes(&o, img, &p.king_rays[0]);
    T.bytes(&o, img, &p.king_rays[1]);
    T.bytes(&o, img, &p.pawns_per_file[0]);
    T.bytes(&o, img, &p.pawns_per_file[1]);
    T.words(&o, img, p.material[0..1]);
    T.words(&o, img, p.material[1..2]);
    T.words(&o, img, p.piece_material[0..1]);
    T.words(&o, img, p.piece_material[1..2]);
    T.words(&o, img, (&p.piece_material_sum)[0..1]);
    T.words(&o, img, (&p.total_material)[0..1]);
    T.words(&o, img, (&p.material_balance)[0..1]);
    T.words(&o, img, (&p.piece_balance)[0..1]);
    T.words(&o, img, (&p.material_balance_2)[0..1]);
    T.words(&o, img, (&p.piece_square_sum)[0..1]);
    T.bytes(&o, img, (&p.men)[0..1]);
    T.bytes(&o, img, p.piece_count[0..1]);
    T.bytes(&o, img, p.piece_count[1..2]);
    T.bytes(&o, img, (&p.pawn_count)[0..1]);
    T.bytes(&o, img, p.side_pawn_count[0..1]);
    T.bytes(&o, img, p.side_pawn_count[1..2]);
    T.bytes(&o, img, p.pawns_on_dark[0..1]);
    T.bytes(&o, img, p.pawns_on_dark[1..2]);
    T.bytes(&o, img, p.king_file[0..1]);
    T.bytes(&o, img, p.king_file[1..2]);
    T.bytes(&o, img, p.king_rank[0..1]);
    T.bytes(&o, img, p.king_rank[1..2]);
    T.words(&o, img, p.oo_lost_at[0..1]);
    T.words(&o, img, p.ooo_lost_at[0..1]);
    T.words(&o, img, p.oo_lost_at[1..2]);
    T.words(&o, img, p.ooo_lost_at[1..2]);
    T.words(&o, img, (&p.game_ply)[0..1]);
    T.key(&o, img, &p.hash_key);
    T.key(&o, img, &p.pawn_hash_key);
    T.bytes(&o, img, p.ep_square_by_ply[0..46]);
    T.bytes(&o, img, p.check_by_ply[0..64]);
    T.words(&o, img, p.reversible_by_ply[0..36]);
    T.words(&o, img, p.quiet_move_by_ply[0..40]);
    std.debug.assert(o == state_size);
}

fn toImage(p: *const Position, img: *Image) void {
    var copy = p.*;
    transfer(true, &copy, img);
}

fn fromImage(p: *Position, img: *const Image) void {
    var copy = img.*;
    transfer(false, p, &copy);
}

/// Name and element of the field holding state-image offset `off`.
fn describe(buf: []u8, off: usize) []const u8 {
    var o: usize = 0;
    for (fields) |f| {
        const n = fieldSize(f);
        if (off < o + n) {
            const unit: usize = if (f.kind == 'w') 2 else 1;
            const i = (off - o) / unit;
            return std.fmt.bufPrint(buf, "{s}[{d}] (DG:{X:0>4})", .{ f.name, i, f.dg + i * unit }) catch f.name;
        }
        o += n;
    }
    return "?";
}

// ---------------------------------------------------------------------------
// Reading a vector file
// ---------------------------------------------------------------------------

fn readVectors(gpa: std.mem.Allocator, name: []const u8) ![]u8 {
    var path_buf: [256]u8 = undefined;
    const dir = @import("build_options").golden_dir;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/position/{s}", .{ dir, name });
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
    fn int(c: *Cursor, comptime T: type) T {
        const n = @sizeOf(T);
        const v = std.mem.readInt(T, c.d[c.i..][0..n], .little);
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
    /// Apply a change list to `img`; returns whether it changed anything.
    fn apply(c: *Cursor, img: *Image) bool {
        const n = c.varint();
        var prev: isize = -1;
        for (0..n) |_| {
            const off: usize = @intCast(prev + 1 + @as(isize, @intCast(c.varint())));
            img[off] ^= c.byte();
            prev = @intCast(off);
        }
        return n != 0;
    }
};

const Counts = struct { make: usize = 0, unmake: usize = 0, hash: usize = 0 };

const Routine = enum(u8) { make = 1, unmake = 2, hash = 3 };

/// Replays every call in one vector file. Returns the counts replayed, or fails at
/// the first call whose result differs from the original's, after printing the call
/// and the first differing field.
fn replay(gpa: std.mem.Allocator, name: []const u8) !Counts {
    return replaySampled(gpa, name, null);
}

/// The replay, which also hands the state before each call to `sampler` when one is
/// given (the benchmarks and the differential tests use it to collect real states).
fn replaySampled(gpa: std.mem.Allocator, name: []const u8, sampler: ?*Sampler) !Counts {
    const data = try readVectors(gpa, name);
    defer gpa.free(data);
    var c: Cursor = .{ .d = data };

    // Header and field table: the writer's layout must be ours.
    try std.testing.expectEqualSlices(u8, "MCPV", data[0..4]);
    c.i = 4;
    try std.testing.expectEqual(@as(u16, 1), c.int(u16));
    try std.testing.expectEqual(@as(u16, state_size), c.int(u16));
    try std.testing.expectEqual(@as(u16, fields.len), c.int(u16));
    var so: u16 = 0;
    for (fields) |f| {
        try std.testing.expectEqual(so, c.int(u16));
        try std.testing.expectEqual(f.dg, c.int(u16));
        try std.testing.expectEqual(f.kind, c.byte());
        try std.testing.expectEqual(@as(u8, @intCast(f.count)), c.byte());
        so += @intCast(fieldSize(f));
    }

    var truth: Image = data[c.i..][0..state_size].*;
    c.i += state_size;
    var p: Position = .{};
    fromImage(&p, &truth);
    var got: Image = undefined;
    var counts: Counts = .{};
    var index: usize = 0;

    while (true) {
        const tag = c.byte();
        if (tag == 0) {
            try std.testing.expectEqual(counts.make, c.int(u32));
            try std.testing.expectEqual(counts.unmake, c.int(u32));
            try std.testing.expectEqual(counts.hash, c.int(u32));
            break;
        }
        if (tag == 4) {
            // Checkpoint: the whole state after the previous call.
            toImage(&p, &got);
            try std.testing.expectEqualSlices(u8, data[c.i..][0..state_size], &got);
            c.i += state_size;
            continue;
        }
        const routine = std.enums.fromInt(Routine, tag) orelse return error.BadRecordTag;
        // Changes made between calls by code outside the three routines.
        if (c.apply(&truth)) fromImage(&p, &truth);

        var out_ok = true;
        var undo: pos.Undo = .{};
        const from = c.byte();
        const to = c.byte();
        const flag = c.byte();
        const move: pos.Move = .{ .from = from, .to = to, .flag = flag };
        const before = if (sampler != null) p else undefined;
        var side: u8 = 0;
        var ply: u16 = 0;
        var cap: u8 = 0;
        var slot_in: u8 = 0;
        var slot_out: u8 = 0;
        switch (routine) {
            .make => {
                side = c.byte();
                ply = c.int(u16);
                cap = c.byte();
                const written = c.byte() != 0;
                slot_out = c.byte();
                // 0A5h is never a slot, so it shows whether make_move wrote the byte.
                undo = .{ .captured = 0xA5, .captured_slot = 0xA5 };
                p.makeMove(move, @fromBackingInt(@intCast(side)), ply, &undo);
                out_ok = undo.captured == cap and undo.captured_slot == (if (written) slot_out else 0xA5);
                counts.make += 1;
            },
            .unmake => {
                side = c.byte();
                cap = c.byte();
                slot_in = c.byte();
                slot_out = c.byte();
                undo = .{ .captured = cap, .captured_slot = slot_in };
                p.unmakeMove(move, @fromBackingInt(@intCast(side)), &undo);
                out_ok = undo.captured == cap and undo.captured_slot == slot_out;
                counts.unmake += 1;
            },
            .hash => {
                p.updateHashKey(move, .original);
                counts.hash += 1;
            },
        }
        if (sampler) |sm| sm.add(routine, &before, move, side, ply, cap, slot_in);
        _ = c.apply(&truth);
        toImage(&p, &got);
        if (!out_ok or !std.mem.eql(u8, &truth, &got)) {
            var buf: [64]u8 = undefined;
            std.debug.print("\n{s}: call {d} differs: {t} from {d} to {d} flag {d} side {d} ply {d} cap {d} slot_in {X:0>2}\n", .{ name, index, routine, from, to, flag, side, ply, cap, slot_in });
            if (!out_ok) std.debug.print("  output bytes: got captured {d}, captured_slot {X:0>2}; want captured {d}, slot {X:0>2}\n", .{ undo.captured, undo.captured_slot, cap, slot_out });
            for (truth, got, 0..) |want, have, off| {
                if (want != have) {
                    std.debug.print("  first differing field: {s}: want {X:0>2}, got {X:0>2}\n", .{ describe(&buf, off), want, have });
                    break;
                }
            }
            return error.MismatchWithOriginal;
        }
        index += 1;
    }
    return counts;
}

/// The recorded runs: runs A, C, D and E of docs/arch/20-position-make-unmake.md
/// ("Evidence"), recorded with the same keys; docs/PORT_STATUS.md gives the commands.
const runs = [_][]const u8{ "A.zst", "C.zst", "D.zst", "E.zst" };

test "position: replay every recorded call of the original" {
    const gpa = std.testing.allocator;
    var total: Counts = .{};
    for (runs) |name| {
        const n = try replay(gpa, name);
        std.debug.print("position vectors {s}: make_move {d}, unmake_move {d}, update_hash_key {d} calls replayed, all equal\n", .{ name, n.make, n.unmake, n.hash });
        total.make += n.make;
        total.unmake += n.unmake;
        total.hash += n.hash;
    }
    std.debug.print("position vectors total: make_move {d}, unmake_move {d}, update_hash_key {d}\n", .{ total.make, total.unmake, total.hash });
}

test "position: the hash random table equals the model's" {
    // tests/golden/position/hash_random.bin is model.generate_random_table(), which
    // equals the table in the running original's memory (checked by the recorder at
    // the first update_hash_key of every run).
    const gpa = std.testing.allocator;
    const want = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, @import("build_options").golden_dir ++ "/position/hash_random.bin", gpa, .limited(1 << 16));
    defer gpa.free(want);
    try std.testing.expectEqualSlices(u8, want, &pos.random_table);
}

// ---------------------------------------------------------------------------
// DEV-001 (docs/DEVIATIONS.md), as tools/research/position/test_dev001.py
// ---------------------------------------------------------------------------

fn sq(name: []const u8) u8 {
    return 21 + (name[0] - 'a') + 10 * (name[1] - '1');
}

const Placed = struct { []const u8, u8 };

fn setUp(pieces: []const Placed) Position {
    var p: Position = .{};
    for (pieces) |pc| p.board[sq(pc[0])] = pc[1];
    const k = p.hashFromScratch();
    p.hash_key = k.main;
    p.pawn_hash_key = k.pawn;
    return p;
}

/// After update_hash_key, do the keys equal those of the resulting position?
fn keysCorrectAfter(before: []const Placed, move: pos.Move, after: []const Placed, fix: bool) bool {
    var p = setUp(before);
    p.updateHashKeyWith(move, fix);
    const want = setUp(after);
    return p.hash_key == want.hash_key and p.pawn_hash_key == want.pawn_hash_key;
}

test "DEV-001: en-passant hash key, original wrong, corrected right, ordinary capture unaffected" {
    const WK = pos.white_king;
    const BK = pos.black_king;
    const WP = pos.white_pawn;
    const BP = pos.black_pawn;
    // White e5xd6 en passant.
    {
        const before = [_]Placed{ .{ "e1", WK }, .{ "e8", BK }, .{ "e5", WP }, .{ "d5", BP } };
        const after = [_]Placed{ .{ "e1", WK }, .{ "e8", BK }, .{ "d6", WP } };
        const mv: pos.Move = .{ .from = sq("e5"), .to = sq("d6"), .flag = pos.flag_en_passant };
        try std.testing.expect(!keysCorrectAfter(&before, mv, &after, false));
        try std.testing.expect(keysCorrectAfter(&before, mv, &after, true));
    }
    // Black e4xd3 en passant.
    {
        const before = [_]Placed{ .{ "e1", WK }, .{ "e8", BK }, .{ "e4", BP }, .{ "d4", WP } };
        const after = [_]Placed{ .{ "e1", WK }, .{ "e8", BK }, .{ "d3", BP } };
        const mv: pos.Move = .{ .from = sq("e4"), .to = sq("d3"), .flag = pos.flag_en_passant };
        try std.testing.expect(!keysCorrectAfter(&before, mv, &after, false));
        try std.testing.expect(keysCorrectAfter(&before, mv, &after, true));
    }
    // White e5xd6, an ordinary capture: both versions right.
    {
        const before = [_]Placed{ .{ "e1", WK }, .{ "e8", BK }, .{ "e5", WP }, .{ "d6", BP } };
        const after = [_]Placed{ .{ "e1", WK }, .{ "e8", BK }, .{ "d6", WP } };
        const mv: pos.Move = .{ .from = sq("e5"), .to = sq("d6"), .flag = pos.flag_normal };
        try std.testing.expect(keysCorrectAfter(&before, mv, &after, false));
        try std.testing.expect(keysCorrectAfter(&before, mv, &after, true));
    }
}

// ---------------------------------------------------------------------------
// Real states collected from the recordings: for the benchmarks and the
// differential tests against src/position_reference.zig
// ---------------------------------------------------------------------------

/// One recorded call with the state the routine was given.
const Sample = struct {
    p: Position,
    move: pos.Move,
    side: pos.Side,
    ply: u16,
    /// unmake_move's inputs: the two bytes make_move left.
    undo: pos.Undo,
};

/// Keeps every `stride`-th call of each routine, up to `cap` of each.
const Sampler = struct {
    stride: usize,
    cap: usize,
    seen: [3]usize = .{ 0, 0, 0 },
    lists: [3]std.ArrayList(Sample) = .{ .empty, .empty, .empty },
    gpa: std.mem.Allocator,

    fn add(sm: *Sampler, routine: Routine, p: *const Position, move: pos.Move, side: u8, ply: u16, cap: u8, slot_in: u8) void {
        const r = @backingInt(routine) - 1;
        defer sm.seen[r] += 1;
        if (sm.seen[r] % sm.stride != 0 or sm.lists[r].items.len >= sm.cap) return;
        sm.lists[r].append(sm.gpa, .{
            .p = p.*,
            .move = move,
            .side = @fromBackingInt(@intCast(side)),
            .ply = ply,
            .undo = .{ .captured = cap, .captured_slot = slot_in },
        }) catch @panic("out of memory");
    }

    fn deinit(sm: *Sampler) void {
        for (&sm.lists) |*l| l.deinit(sm.gpa);
    }

    fn collect(gpa: std.mem.Allocator, stride: usize, cap: usize) !Sampler {
        var sm: Sampler = .{ .stride = stride, .cap = cap, .gpa = gpa };
        errdefer sm.deinit();
        for (runs) |name| _ = try replaySampled(gpa, name, &sm);
        return sm;
    }
};

const bench = @import("bench.zig");

test "bench: position: make_move, unmake_move, update_hash_key on recorded states" {
    if (!bench.enabled) return;
    const gpa = std.testing.allocator;
    var sm = try Sampler.collect(gpa, 97, 1024);
    defer sm.deinit();
    const passes = 21;
    const reps = 64;
    // The same states in the reference module's type, for timing it alongside.
    var refs: [3][]ref.Position = undefined;
    for (&refs, sm.lists) |*r, l| {
        r.* = try gpa.alloc(ref.Position, l.items.len);
        for (r.*, l.items) |*rp, *c| rp.* = toRef(&c.p);
    }
    defer for (refs) |r| gpa.free(r);
    const T = Timings(Position, pos);
    const R = Timings(ref.Position, ref);
    // Each pass times the routines as they are and the reference, one after the other,
    // so that both see the same machine; the best pass of each is reported.
    var now: T = .{};
    var was: R = .{};
    for (0..passes) |_| {
        now.pass(sm.lists, null, reps);
        was.pass(sm.lists, &refs, reps);
    }
    now.report("", sm.lists, reps, passes);
    was.report(" (before)", sm.lists, reps, passes);
}

/// The timed loops of the position benchmark, for our Position or the reference's.
/// States are copied into one working position first (as hot as the search's); the
/// copies alone are timed and taken off.
fn Timings(comptime P: type, comptime M: type) type {
    return struct {
        const Self = @This();
        copy: bench.Best = .{},
        make: bench.Best = .{},
        ucopy: bench.Best = .{},
        unmake: bench.Best = .{},
        hcopy: bench.Best = .{},
        hash: bench.Best = .{},
        pair: bench.Best = .{},

        fn state(c: *const Sample, refs: ?*const [3][]ref.Position, list: usize, i: usize) *const P {
            if (P == Position) return &c.p;
            return &refs.?[list][i];
        }

        fn pass(t: *Self, lists: [3]std.ArrayList(Sample), refs: ?*const [3][]ref.Position, reps: usize) void {
            var work: P = undefined;
            const makes = lists[0].items;
            const unmakes = lists[1].items;
            const hashes = lists[2].items;
            var t0 = bench.now();
            for (0..reps) |_| for (makes, 0..) |*c, i| {
                work = state(c, refs, 0, i).*;
                bench.keep(&work);
            };
            t.copy.pass(t0);
            t0 = bench.now();
            for (0..reps) |_| for (makes, 0..) |*c, i| {
                work = state(c, refs, 0, i).*;
                var u: M.Undo = .{};
                @call(.never_inline, P.makeMove, .{ &work, M.Move{ .from = c.move.from, .to = c.move.to, .flag = c.move.flag }, @as(M.Side, @fromBackingInt(@backingInt(c.side))), c.ply, &u });
                bench.keep(&work);
                bench.keep(&u);
            };
            t.make.pass(t0);
            t0 = bench.now();
            for (0..reps) |_| for (makes, 0..) |*c, i| {
                work = state(c, refs, 0, i).*;
                var u: M.Undo = .{};
                const m: M.Move = .{ .from = c.move.from, .to = c.move.to, .flag = c.move.flag };
                @call(.never_inline, P.makeMove, .{ &work, m, @as(M.Side, @fromBackingInt(@backingInt(c.side))), c.ply, &u });
                @call(.never_inline, P.unmakeMove, .{ &work, m, @as(M.Side, @fromBackingInt(@backingInt(c.side))), &u });
                bench.keep(&work);
            };
            t.pair.pass(t0);
            t0 = bench.now();
            for (0..reps) |_| for (unmakes, 0..) |*c, i| {
                work = state(c, refs, 1, i).*;
                bench.keep(&work);
            };
            t.ucopy.pass(t0);
            t0 = bench.now();
            for (0..reps) |_| for (unmakes, 0..) |*c, i| {
                work = state(c, refs, 1, i).*;
                var u: M.Undo = .{ .captured = c.undo.captured, .captured_slot = c.undo.captured_slot };
                @call(.never_inline, P.unmakeMove, .{ &work, M.Move{ .from = c.move.from, .to = c.move.to, .flag = c.move.flag }, @as(M.Side, @fromBackingInt(@backingInt(c.side))), &u });
                bench.keep(&work);
                bench.keep(&u);
            };
            t.unmake.pass(t0);
            // update_hash_key reads the board and the keys: only those are copied in.
            t0 = bench.now();
            for (0..reps) |_| for (hashes, 0..) |*c, i| {
                const s = state(c, refs, 2, i);
                work.board = s.board;
                work.hash_key = s.hash_key;
                work.pawn_hash_key = s.pawn_hash_key;
                bench.keep(&work);
            };
            t.hcopy.pass(t0);
            t0 = bench.now();
            for (0..reps) |_| for (hashes, 0..) |*c, i| {
                const s = state(c, refs, 2, i);
                work.board = s.board;
                work.hash_key = s.hash_key;
                work.pawn_hash_key = s.pawn_hash_key;
                @call(.never_inline, P.updateHashKeyWith, .{ &work, M.Move{ .from = c.move.from, .to = c.move.to, .flag = c.move.flag }, false });
                bench.keep(&work);
            };
            t.hash.pass(t0);
        }

        fn report(t: *const Self, comptime tag: []const u8, lists: [3]std.ArrayList(Sample), reps: usize, passes: usize) void {
            t.make.report("position make_move" ++ tag, reps * lists[0].items.len, passes, t.copy.ns);
            t.unmake.report("position unmake_move" ++ tag, reps * lists[1].items.len, passes, t.ucopy.ns);
            t.pair.report("position make_move + unmake_move" ++ tag, reps * lists[0].items.len, passes, t.copy.ns);
            t.hash.report("position update_hash_key" ++ tag, reps * lists[2].items.len, passes, t.hcopy.ns);
        }
    };
}

// ---------------------------------------------------------------------------
// Differential tests against src/position_reference.zig (the routines as they were
// before the speed pass), on states beyond the recorded ones
// ---------------------------------------------------------------------------

const ref = @import("position_reference.zig");

/// The differential tests run a million cases or more in the optimised builds
/// (`-Doptimize=ReleaseSafe` keeps every safety check) and a twentieth of that in Debug,
/// where they would otherwise take minutes.
pub const full_diff = @import("builtin").mode != .debug;
pub const diff_count: usize = if (full_diff) 1_000_000 else 50_000;
const mg = @import("movegen.zig");
const see_mod = @import("see.zig");
const setup = @import("setup.zig");
const fen = @import("fen.zig");

/// The reference module's position, field by field from ours.
fn toRef(p: *const Position) ref.Position {
    var r: ref.Position = undefined;
    inline for (@typeInfo(Position).@"struct".field_names) |name| @field(r, name) = @field(p.*, name);
    return r;
}

/// Is the reference position equal to ours, field by field?
fn sameAsRef(p: *const Position, r: *const ref.Position) bool {
    inline for (@typeInfo(Position).@"struct".field_names) |name| {
        if (!std.meta.eql(@field(p.*, name), @field(r.*, name))) return false;
    }
    return true;
}

/// A random walk through positions: random set-ups and the start position, moves
/// generated by the ported gen_all_moves and made and taken back with make_move and
/// unmake_move. Each state it reaches is a consistent search position.
pub const RandomWalk = struct {
    p: Position = .{},
    s: see_mod.Scratch = .{},
    v: mg.SearchVars = .{},
    list: mg.MoveList = @splat(.{ .from = 0, .to = 0, .flag = 0 }),
    n: usize = 0,
    rng: std.Random.DefaultPrng,
    side: pos.Side = .white,
    ply: usize = 0,
    made: [48]struct { move: pos.Move, undo: pos.Undo, side: pos.Side } = undefined,
    depth: usize = 0,

    pub fn init(seed: u64) RandomWalk {
        var w: RandomWalk = .{ .rng = .init(seed) };
        w.reset();
        return w;
    }

    fn random(w: *RandomWalk) std.Random {
        return w.rng.random();
    }

    /// A new start: the start position one time in four, else a random set-up with a
    /// random part of each side's men (no castling rights).
    pub fn reset(w: *RandomWalk) void {
        const r = w.random();
        w.depth = 0;
        w.ply = 0;
        var v: setup.SetupVars = .{};
        if (r.uintLessThan(u8, 4) == 0) {
            const d = fen.parse("rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1") catch unreachable;
            w.p = .{};
            setup.buildFromDescription(&w.p, &v, &d);
        } else {
            for (0..120) |q| v.board[q] = if (q < 21 or q > 98 or q % 10 == 0 or q % 10 == 9) pos.border else pos.empty;
            const wk = randomEmpty(r, &v.board, false);
            v.board[wk] = pos.white_king;
            var bk = randomEmpty(r, &v.board, false);
            while (kingsTouch(wk, bk)) bk = randomEmpty(r, &v.board, false);
            v.board[bk] = pos.black_king;
            const keep_piece = r.uintLessThan(u8, 101);
            const keep_pawn = r.uintLessThan(u8, 101);
            for ([2]u8{ 0, 7 }) |c| {
                for ([_]u8{ 2, 2, 3, 3, 4, 4, 5 }) |code| {
                    if (r.uintLessThan(u8, 100) < keep_piece) v.board[randomEmpty(r, &v.board, false)] = code + c;
                }
                // At most 6 pawns: the set-up gives a second bishop on one colour a pawn slot.
                for (0..6) |_| {
                    if (r.uintLessThan(u8, 100) < keep_pawn) v.board[randomEmpty(r, &v.board, true)] = 1 + c;
                }
            }
            v.side = r.uintLessThan(u8, 2);
            v.setup_side = v.side;
            w.p = .{};
            for (0..120) |q| w.p.board[q] = if (q < 21 or q > 98 or q % 10 == 0 or q % 10 == 9) pos.border else pos.empty;
            setup.build(&w.p, &v);
            w.p.oo_lost_at = .{ 0xFFFF, 0xFFFF };
            w.p.ooo_lost_at = .{ 0xFFFF, 0xFFFF };
        }
        w.side = @fromBackingInt(@intCast(v.side));
        w.p.hash_key = r.int(u48);
        w.p.pawn_hash_key = r.int(u48);
        w.v = .{};
        w.generate();
    }

    fn randomEmpty(r: std.Random, b: *const [121]u8, pawn: bool) usize {
        while (true) {
            const rank: usize = if (pawn) 1 + r.uintLessThan(usize, 6) else r.uintLessThan(usize, 8);
            const q = 21 + 10 * rank + r.uintLessThan(usize, 8);
            if (b[q] == pos.empty) return q;
        }
    }

    fn kingsTouch(a: usize, b: usize) bool {
        const d: isize = @as(isize, @intCast(a)) - @as(isize, @intCast(b));
        return switch (d) {
            -11, -10, -9, -1, 1, 9, 10, 11 => true,
            else => false,
        };
    }

    /// Generates the moves of the side to move into `list`; `n` is 0 when there are
    /// none or the side can take the king.
    fn generate(w: *RandomWalk) void {
        const c = mg.genAllMoves(.original, &w.p, &w.s, &w.v, &w.list, w.side, w.ply, .{});
        w.n = if (c == mg.king_capture or capturesKing(&w.p, w.list[0..c])) 0 else keepPlausible(&w.p, w.list[0..c], w.side);
    }

    /// A move of the side to move, or null when there is none.
    pub fn pick(w: *RandomWalk) ?pos.Move {
        if (w.n == 0) return null;
        return w.list[w.random().uintLessThan(usize, w.n)];
    }

    /// The ply index a move made now is recorded at: the generator at ply k reads the
    /// en-passant square of index k, which the move that led there wrote.
    pub fn makePly(w: *const RandomWalk) usize {
        return w.ply + 1;
    }

    /// Makes `move` (with the hash update before it, as the search does).
    pub fn make(w: *RandomWalk, move: pos.Move) void {
        w.p.updateHashKey(move, .original);
        var u: pos.Undo = .{};
        w.p.makeMove(move, w.side, w.makePly(), &u);
        w.made[w.depth] = .{ .move = move, .undo = u, .side = w.side };
        w.depth += 1;
        w.ply += 1;
        w.side = w.side.other();
        w.generate();
    }

    /// Takes back the last move.
    pub fn unmake(w: *RandomWalk) void {
        w.depth -= 1;
        w.ply -= 1;
        const m = w.made[w.depth];
        var u = m.undo;
        w.p.unmakeMove(m.move, m.side, &u);
        w.side = m.side;
        w.generate();
    }

    /// One step of the walk: usually a move forward, sometimes one back, a reset at a
    /// dead end or at the depth limit.
    pub fn step(w: *RandomWalk) void {
        const r = w.random();
        if (w.depth > 0 and (w.n == 0 or r.uintLessThan(u8, 4) == 0)) {
            w.unmake();
        } else if (w.n == 0 or w.depth == w.made.len) {
            w.reset();
        } else {
            w.make(w.pick().?);
        }
    }
};

/// Does a move of `list` take a king? The search never makes such a move (the
/// generators report it instead); the state after it is not one the routines are for.
fn capturesKing(p: *const Position, list: []const pos.Move) bool {
    for (list) |m| {
        if (p.board[m.to] == pos.white_king or p.board[m.to] == pos.black_king) return true;
    }
    return false;
}

/// Keeps at the front of `list` the moves that are possible on the board: an
/// en-passant capture needs the enemy pawn behind its target and the target empty, and
/// castling needs the king and rook at home with the squares between empty. (The
/// generator reads the en-passant square and castling stamps, which a state reached by
/// other means than the search need not keep in step.) Returns their number.
fn keepPlausible(p: *const Position, list: []pos.Move, side: pos.Side) usize {
    var n: usize = 0;
    const white = side == .white;
    for (list) |m| {
        const ok = switch (m.flag) {
            pos.flag_en_passant => p.board[m.to] == pos.empty and
                p.board[if (white) m.to - 10 else m.to + 10] == (if (white) pos.black_pawn else pos.white_pawn) and
                p.board[m.from] == (if (white) pos.white_pawn else pos.black_pawn),
            pos.flag_castle => blk: {
                const home: u8 = if (white) 25 else 95;
                const rook: u8 = if (white) pos.white_rook else pos.black_rook;
                const king: u8 = if (white) pos.white_king else pos.black_king;
                if (m.from != home or p.board[home] != king) break :blk false;
                if (m.to == home + 2) break :blk p.board[home + 3] == rook and p.board[home + 1] == 0 and p.board[home + 2] == 0;
                if (m.to == home - 2) break :blk p.board[home - 4] == rook and p.board[home - 1] == 0 and p.board[home - 2] == 0 and p.board[home - 3] == 0;
                break :blk false;
            },
            else => true,
        };
        if (ok) {
            list[n] = m;
            n += 1;
        }
    }
    return n;
}

/// Checks make_move, unmake_move and update_hash_key against the reference on the
/// state `p`, for `move` made by `side` at `ply`. Returns false at a difference.
fn diffMoveRoutines(p: *const Position, move: pos.Move, side: pos.Side, ply: usize, comptime check_hash: bool) !void {
    // update_hash_key, both fix settings.
    if (check_hash) {
        inline for (.{ pos.Fixes.original, pos.Fixes.corrected }, .{ ref.Fixes.original, ref.Fixes.corrected }) |fx, rfx| {
            var a = p.*;
            var b = toRef(p);
            a.updateHashKey(move, fx);
            b.updateHashKey(.{ .from = move.from, .to = move.to, .flag = move.flag, .score = move.score }, rfx);
            if (!sameAsRef(&a, &b)) {
                std.debug.print("update_hash_key differs: from {d} to {d} flag {d}\n", .{ move.from, move.to, move.flag });
                return error.DiffersFromReference;
            }
        }
    }
    // make_move, then unmake_move on the result.
    var a = p.*;
    var b = toRef(p);
    const rm: ref.Move = .{ .from = move.from, .to = move.to, .flag = move.flag, .score = move.score };
    const rside: ref.Side = @fromBackingInt(@backingInt(side));
    var ua: pos.Undo = .{ .captured = 0xA5, .captured_slot = 0xA5 };
    var ub: ref.Undo = .{ .captured = 0xA5, .captured_slot = 0xA5 };
    a.makeMove(move, side, ply, &ua);
    b.makeMove(rm, rside, ply, &ub);
    if (!sameAsRef(&a, &b) or ua.captured != ub.captured or ua.captured_slot != ub.captured_slot) {
        std.debug.print("make_move differs: from {d} to {d} flag {d} side {t}\n", .{ move.from, move.to, move.flag, side });
        return error.DiffersFromReference;
    }
    a.unmakeMove(move, side, &ua);
    b.unmakeMove(rm, rside, &ub);
    if (!sameAsRef(&a, &b) or ua.captured != ub.captured or ua.captured_slot != ub.captured_slot) {
        std.debug.print("unmake_move differs: from {d} to {d} flag {d} side {t}\n", .{ move.from, move.to, move.flag, side });
        return error.DiffersFromReference;
    }
}

test "position: make, unmake and hash update equal the reference on random walks" {
    var w = RandomWalk.init(0x5EED_0001);
    var checked: usize = 0;
    var steps: usize = 0;
    while (checked < diff_count) : (steps += 1) {
        // Every generated move of this state, through all three routines.
        for (w.list[0..w.n]) |m| {
            try diffMoveRoutines(&w.p, m, w.side, w.makePly(), true);
            checked += 1;
        }
        w.step();
    }
    std.debug.print("position: {d} moves on {d} random-walk states equal the reference\n", .{ checked, steps });
}

test "position: hash_from_scratch equals the reference on random walks" {
    var w = RandomWalk.init(0x5EED_0002);
    for (0..diff_count / 10) |_| {
        const a = w.p.hashFromScratch();
        const r = toRef(&w.p);
        const b = r.hashFromScratch();
        try std.testing.expectEqual(b.main, a.main);
        try std.testing.expectEqual(b.pawn, a.pawn);
        w.step();
    }
}

test "position: make, unmake and hash update equal the reference on recorded states" {
    // Every 29th recorded call's state, with the recorded move and with every move the
    // generator gives there for either side.
    const gpa = std.testing.allocator;
    var sm = try Sampler.collect(gpa, if (full_diff) 29 else 290, 40_000);
    defer sm.deinit();
    var v: mg.SearchVars = .{};
    var s: see_mod.Scratch = .{};
    var list: mg.MoveList = undefined;
    var checked: usize = 0;
    for (sm.lists[1].items) |*c| {
        // unmake_move on its recorded state and inputs.
        var a = c.p;
        var b = toRef(&c.p);
        var ua = c.undo;
        var ub: ref.Undo = .{ .captured = c.undo.captured, .captured_slot = c.undo.captured_slot };
        a.unmakeMove(c.move, c.side, &ua);
        b.unmakeMove(.{ .from = c.move.from, .to = c.move.to, .flag = c.move.flag }, @fromBackingInt(@backingInt(c.side)), &ub);
        try std.testing.expect(sameAsRef(&a, &b));
        try std.testing.expectEqual(ub.captured_slot, ua.captured_slot);
        checked += 1;
    }
    for ([2]usize{ 0, 2 }) |li| for (sm.lists[li].items) |*c| {
        // An update_hash_key record carries no side: the mover's colour gives it.
        const mover = c.p.board[c.move.from];
        if (mover == pos.empty or mover == pos.border) continue;
        const side: pos.Side = if (li == 0) c.side else if (mover >= pos.black_pawn) .black else .white;
        try diffMoveRoutines(&c.p, c.move, side, c.ply, true);
        checked += 1;
        for ([2]pos.Side{ .white, .black }) |gen_side| {
            var q = c.p;
            const g = mg.genAllMoves(.original, &q, &s, &v, &list, gen_side, c.ply, .{});
            if (g == mg.king_capture or capturesKing(&c.p, list[0..g])) continue;
            const n = keepPlausible(&c.p, list[0..g], gen_side);
            for (list[0..n]) |m| {
                try diffMoveRoutines(&c.p, m, gen_side, c.ply, true);
                checked += 1;
            }
        }
    };
    std.debug.print("position: {d} moves on recorded states equal the reference\n", .{checked});
}

test "position: update_hash_key equals the reference for every square pair, flag and board byte" {
    // Edge cases beyond legal moves: every mover and captured code 0..13 on every pair
    // of board squares, with every flag 0..6 and a promotion flag, on a fixed board.
    var p: Position = .{};
    var rng: std.Random.DefaultPrng = .init(0x5EED_0003);
    const r = rng.random();
    for (0..120) |q| p.board[q] = if (q < 21 or q > 98 or q % 10 == 0 or q % 10 == 9) pos.border else r.uintLessThan(u8, 14);
    var n: usize = 0;
    for (21..99) |from| for (21..99) |to| {
        if (from % 10 == 0 or from % 10 == 9 or to % 10 == 0 or to % 10 == 9 or from == to) continue;
        // Squares the en-passant and castling arms reach stay on the board.
        if (from < 31 or from > 88 or to < 25 or to > 94) continue;
        for ([_]u8{ 0, 1, 2, 3, 4, 5, 6 }) |flag| {
            p.board[from] = r.uintLessThan(u8, 14);
            p.board[to] = r.uintLessThan(u8, 14);
            if (p.board[from] == pos.border) p.board[from] = 0;
            if (p.board[to] == pos.border) p.board[to] = 0;
            p.hash_key = r.int(u48);
            p.pawn_hash_key = r.int(u48);
            const m: pos.Move = .{ .from = @intCast(from), .to = @intCast(to), .flag = flag };
            inline for (.{ pos.Fixes.original, pos.Fixes.corrected }, .{ ref.Fixes.original, ref.Fixes.corrected }) |fx, rfx| {
                var a = p;
                var b = toRef(&p);
                a.updateHashKey(m, fx);
                b.updateHashKey(.{ .from = m.from, .to = m.to, .flag = m.flag }, rfx);
                try std.testing.expectEqual(b.hash_key, a.hash_key);
                try std.testing.expectEqual(b.pawn_hash_key, a.pawn_hash_key);
                n += 1;
            }
        }
    };
    std.debug.print("position: update_hash_key equal on {d} edge cases\n", .{n});
}

// ---------------------------------------------------------------------------
// applyMove (docs/arch/60-engine-assembly.md section 9.5) against the three routines
// it replaces in the search: update_square_sums, update_hash_key and make_move
// ---------------------------------------------------------------------------

const ev = @import("evalvars.zig");
const updateSquareSums = @import("squaresums.zig").updateSquareSums;

/// Kinds of move applyMove must have met before its test counts as done.
const Coverage = struct {
    castle: [2][2]usize = @splat(@splat(0)), // side, wing (0 king side)
    en_passant: [2]usize = @splat(0),
    promotion: [2][4][2]usize = @splat(@splat(@splat(0))), // side, piece - knight, capture
    slot6_capture: [2]usize = @splat(0),
    capture: usize = 0,

    fn note(c: *Coverage, p: *const Position, m: pos.Move, side: pos.Side, u: pos.Undo) void {
        const s = @backingInt(side);
        const cap = p.board[m.to] != pos.empty;
        switch (m.flag) {
            pos.flag_castle => c.castle[s][if (m.to > m.from) 0 else 1] += 1,
            pos.flag_en_passant => c.en_passant[s] += 1,
            2...5 => c.promotion[s][m.flag - 2][@intFromBool(cap)] += 1,
            else => {},
        }
        if (u.captured != 0) {
            c.capture += 1;
            if (u.captured_slot == 6) c.slot6_capture[s] += 1;
        }
    }

    fn complete(c: *const Coverage) bool {
        for (c.castle) |a| for (a) |n| if (n == 0) return false;
        for (c.en_passant) |n| if (n == 0) return false;
        for (c.promotion) |a| for (a) |b| for (b) |n| if (n == 0) return false;
        for (c.slot6_capture) |n| if (n == 0) return false;
        return true;
    }

    fn print(c: *const Coverage, what: []const u8) void {
        std.debug.print("{s}: castling W O-O {d}, W O-O-O {d}, B O-O {d}, B O-O-O {d}; en passant W {d}, B {d}; slot-6 captures W {d}, B {d}; captures {d}\n", .{
            what,            c.castle[0][0],  c.castle[0][1],     c.castle[1][0],     c.castle[1][1],
            c.en_passant[0], c.en_passant[1], c.slot6_capture[0], c.slot6_capture[1], c.capture,
        });
        std.debug.print("{s}: promotions (N, B, R, Q; each quiet, capture) W {any}, B {any}\n", .{ what, c.promotion[0], c.promotion[1] });
    }
};

/// Square tables of random words: applyMove must equal the three routines whatever
/// prepare_eval put in the tables.
fn randomEvalVars(r: std.Random) ev.EvalVars {
    var v: ev.EvalVars = .{};
    for (&v.square_values) |*a| for (a) |*b| for (b) |*x| {
        x.* = r.int(u16);
    };
    v.pawn_square_sum = .{ r.int(u16), r.int(u16) };
    return v;
}

/// Fails, naming each differing field, unless both versions left the same position,
/// pawn sums and undo bytes.
fn expectSame(what: []const u8, m: pos.Move, side: pos.Side, a: *const Position, va: *const ev.EvalVars, ua: pos.Undo, b: *const Position, vb: *const ev.EvalVars, ub: pos.Undo) !void {
    if (std.meta.eql(a.*, b.*) and std.meta.eql(va.pawn_square_sum, vb.pawn_square_sum) and std.meta.eql(ua, ub)) return;
    std.debug.print("{s} differs: from {d} to {d} flag {d} side {t}\n", .{ what, m.from, m.to, m.flag, side });
    inline for (@typeInfo(Position).@"struct".field_names) |name| {
        if (!std.meta.eql(@field(a.*, name), @field(b.*, name))) std.debug.print("  differing field: {s}\n", .{name});
    }
    if (!std.meta.eql(va.pawn_square_sum, vb.pawn_square_sum)) std.debug.print("  pawn_square_sum: separate {any}, fused {any}\n", .{ va.pawn_square_sum, vb.pawn_square_sum });
    if (!std.meta.eql(ua, ub)) std.debug.print("  undo: separate {any}, fused {any}\n", .{ ua, ub });
    return error.FusedDiffersFromSeparate;
}

/// One move through both versions, with both settings of DEV-001: the three routines
/// `updateSquareSums; updateHashKey; makeMove` against `applyMove`, then unmake_move on
/// each result (the undo bytes and the state after it must agree too). `va` and `vb`
/// hold the same tables; the sums and DG:7182 are random words, so that every term
/// shows.
fn diffFused(p: *const Position, m: pos.Move, side: pos.Side, ply: usize, va: *ev.EvalVars, vb: *ev.EvalVars, r: std.Random, cov: ?*Coverage) !void {
    inline for (.{ pos.Fixes.original, pos.Fixes.corrected }) |fx| {
        var a = p.*;
        a.piece_square_sum = r.int(u16);
        var b = a;
        va.pawn_square_sum = .{ r.int(u16), r.int(u16) };
        vb.pawn_square_sum = va.pawn_square_sum;
        var ua: pos.Undo = .{ .captured = 0xA5, .captured_slot = 0xA5 };
        var ub = ua;
        updateSquareSums(&a, va, m);
        a.updateHashKey(m, fx);
        // make_move with the same fixes as applyMove (DEV-050 is make_move's own).
        a.makeMoveFixes(m, side, ply, &ua, fx);
        b.applyMove(vb, m, side, ply, &ub, fx);
        try expectSame("applyMove", m, side, &a, va, ua, &b, vb, ub);
        if (cov) |c| if (fx.dev001_ep_hash_square) c.note(p, m, side, ua);
        a.unmakeMoveFixes(m, side, &ua, fx);
        b.unmakeMoveFixes(m, side, &ub, fx);
        try expectSame("unmake_move after applyMove", m, side, &a, va, ua, &b, vb, ub);
        // With the fixes off the corrected routines are the original's.
        if (!fx.dev050_corner_rook_capture) {
            var c = p.*;
            var d = c;
            var uc: pos.Undo = .{ .captured = 0xA5, .captured_slot = 0xA5 };
            var ud = uc;
            c.makeMove(m, side, ply, &uc);
            d.makeMoveFixes(m, side, ply, &ud, fx);
            try std.testing.expect(std.meta.eql(c, d) and std.meta.eql(uc, ud));
            c.unmakeMove(m, side, &uc);
            d.unmakeMoveFixes(m, side, &ud, fx);
            try std.testing.expect(std.meta.eql(c, d) and std.meta.eql(uc, ud));
        }
    }
}

/// A start for the random walk with kings and rooks at home, all four castling rights
/// held, a random part of the other pieces, and random pawns or, half the time, pawns
/// placed so that en passant comes up.
fn castlingStart(w: *RandomWalk, r: std.Random) void {
    var v: setup.SetupVars = .{};
    for (0..120) |q| v.board[q] = if (q < 21 or q > 98 or q % 10 == 0 or q % 10 == 9) pos.border else pos.empty;
    v.board[25] = pos.white_king;
    v.board[21] = pos.white_rook;
    v.board[28] = pos.white_rook;
    v.board[95] = pos.black_king;
    v.board[91] = pos.black_rook;
    v.board[98] = pos.black_rook;
    const ep_prone = r.boolean();
    if (ep_prone) {
        // Pawns placed for en passant: on three files a White pawn on the 5th rank with
        // Black pawns beside its file on the 7th, and a Black pawn on the 4th with White
        // pawns beside it on the 2nd.
        for (0..3) |_| {
            const f = 1 + r.uintLessThan(u8, 6);
            const g = if (r.boolean()) f - 1 else f + 1;
            for ([_][2]u8{ .{ 61 + f, pos.white_pawn }, .{ 81 + g, pos.black_pawn }, .{ 51 + g, pos.black_pawn }, .{ 31 + f, pos.white_pawn } }) |e| {
                if (v.board[e[0]] == pos.empty) v.board[e[0]] = e[1];
            }
        }
    }
    for ([2]u8{ 0, 7 }) |c| {
        for ([_]u8{ 2, 2, 3, 3, 5 }) |code| {
            if (r.boolean()) v.board[RandomWalk.randomEmpty(r, &v.board, false)] = code + c;
        }
        if (!ep_prone) for (0..6) |_| if (r.boolean()) {
            v.board[RandomWalk.randomEmpty(r, &v.board, true)] = 1 + c;
        };
    }
    v.side = r.uintLessThan(u8, 2);
    v.setup_side = v.side;
    w.p = .{};
    for (0..120) |q| w.p.board[q] = if (q < 21 or q > 98 or q % 10 == 0 or q % 10 == 9) pos.border else pos.empty;
    setup.build(&w.p, &v);
    w.p.oo_lost_at = .{ 0, 0 };
    w.p.ooo_lost_at = .{ 0, 0 };
    w.side = @fromBackingInt(@intCast(v.side));
    w.depth = 0;
    w.ply = 0;
    w.p.hash_key = r.int(u48);
    w.p.pawn_hash_key = r.int(u48);
    w.v = .{};
    w.generate();
}

test "position: applyMove equals the three routines on random walks" {
    var w = RandomWalk.init(0x5EED_0F05);
    var rng: std.Random.DefaultPrng = .init(0xF05E_D001);
    const r = rng.random();
    const gpa = std.testing.allocator;
    const va = try gpa.create(ev.EvalVars);
    defer gpa.destroy(va);
    const vb = try gpa.create(ev.EvalVars);
    defer gpa.destroy(vb);
    va.* = randomEvalVars(r);
    vb.* = va.*;
    const tables = va.square_values;
    var cov: Coverage = .{};
    var checked: usize = 0;
    var steps: usize = 0;
    // Every generated move of each state reached, through both DEV-001 settings: a
    // million moves at least in the optimised builds, and on until every kind of move
    // in `Coverage` has been met. One new start in eight is a castling start.
    while (checked < diff_count or (full_diff and !cov.complete() and steps < 20 * diff_count)) : (steps += 1) {
        for (w.list[0..w.n]) |m| {
            try diffFused(&w.p, m, w.side, w.makePly(), va, vb, r, &cov);
            checked += 1;
        }
        if (w.depth == 0 and r.uintLessThan(u8, 8) == 0) castlingStart(&w, r) else w.step();
    }
    // Nothing but the pawn sums may have been written in the eval variables.
    try std.testing.expect(std.meta.eql(va.*, vb.*));
    try std.testing.expect(std.meta.eql(va.square_values, tables));
    cov.print("position applyMove, random walks");
    std.debug.print("position: applyMove equals the three routines on {d} moves ({d} walk states), both DEV-001 settings\n", .{ checked, steps });
    if (full_diff) try std.testing.expect(cov.complete());
}

test "position: applyMove equals the three routines on recorded states" {
    // The recorded states of every 29th make_move and update_hash_key call, with the
    // recorded move and with every move the generator gives there for either side.
    const gpa = std.testing.allocator;
    var sm = try Sampler.collect(gpa, if (full_diff) 29 else 290, 40_000);
    defer sm.deinit();
    var rng: std.Random.DefaultPrng = .init(0xF05E_D002);
    const r = rng.random();
    const va = try gpa.create(ev.EvalVars);
    defer gpa.destroy(va);
    const vb = try gpa.create(ev.EvalVars);
    defer gpa.destroy(vb);
    va.* = randomEvalVars(r);
    vb.* = va.*;
    var v: mg.SearchVars = .{};
    var s: see_mod.Scratch = .{};
    var list: mg.MoveList = undefined;
    var cov: Coverage = .{};
    var checked: usize = 0;
    for ([2]usize{ 0, 2 }) |li| for (sm.lists[li].items) |*c| {
        // An update_hash_key record carries no side: the mover's colour gives it.
        const mover = c.p.board[c.move.from];
        if (mover == pos.empty or mover == pos.border) continue;
        const side: pos.Side = if (li == 0) c.side else if (mover >= pos.black_pawn) .black else .white;
        try diffFused(&c.p, c.move, side, c.ply, va, vb, r, &cov);
        checked += 1;
        for ([2]pos.Side{ .white, .black }) |gen_side| {
            var q = c.p;
            const g = mg.genAllMoves(.original, &q, &s, &v, &list, gen_side, c.ply, .{});
            if (g == mg.king_capture or capturesKing(&c.p, list[0..g])) continue;
            const n = keepPlausible(&c.p, list[0..g], gen_side);
            for (list[0..n]) |m| {
                try diffFused(&c.p, m, gen_side, c.ply, va, vb, r, &cov);
                checked += 1;
            }
        }
    };
    try std.testing.expect(std.meta.eql(va.*, vb.*));
    cov.print("position applyMove, recorded states");
    std.debug.print("position: applyMove equals the three routines on {d} recorded-state cases\n", .{checked});
}

test "position: applyMove gives moves of another form to the three routines" {
    // Moves the search never makes take applyMove's other path, which must still leave
    // what the three routines leave: a quiet move of a piece claimed by the other side,
    // and a White pawn push with flag 7 (make_move's promotion arm, nothing in the
    // other two).
    const gpa = std.testing.allocator;
    var rng: std.Random.DefaultPrng = .init(0xF05E_D003);
    const r = rng.random();
    const va = try gpa.create(ev.EvalVars);
    defer gpa.destroy(va);
    const vb = try gpa.create(ev.EvalVars);
    defer gpa.destroy(vb);
    va.* = randomEvalVars(r);
    vb.* = va.*;
    var w = RandomWalk.init(0x5EED_0F06);
    var n: usize = 0;
    while (n < diff_count / 20) : (w.step()) {
        for (w.list[0..w.n]) |m| {
            const mover = w.p.board[m.from];
            if (m.flag != pos.flag_normal or w.p.board[m.to] != pos.empty) continue;
            if (mover == pos.white_pawn and m.to < 91) {
                try diffFused(&w.p, .{ .from = m.from, .to = m.to, .flag = 7 }, w.side, w.makePly(), va, vb, r, null);
                n += 1;
            } else if (mover != pos.white_pawn and mover != pos.black_pawn and mover != pos.white_king and mover != pos.black_king) {
                try diffFused(&w.p, m, w.side.other(), w.makePly(), va, vb, r, null);
                n += 1;
            }
        }
    }
    std.debug.print("position: applyMove equals the three routines on {d} moves of another form\n", .{n});
}

test "bench: position: applyMove against the three routines" {
    if (!bench.enabled) return;
    const gpa = std.testing.allocator;
    var rng: std.Random.DefaultPrng = .init(0xF05E_D004);
    const va = try gpa.create(ev.EvalVars);
    defer gpa.destroy(va);
    va.* = randomEvalVars(rng.random());

    const B = struct {
        fn three(p: *Position, v: *ev.EvalVars, m: pos.Move, side: pos.Side, ply: usize, u: *pos.Undo) void {
            @call(.never_inline, updateSquareSums, .{ p, v, m });
            @call(.never_inline, Position.updateHashKey, .{ p, m, pos.Fixes.original });
            @call(.never_inline, Position.makeMove, .{ p, m, side, ply, u });
        }
        fn fused(p: *Position, v: *ev.EvalVars, m: pos.Move, side: pos.Side, ply: usize, u: *pos.Undo) void {
            @call(.never_inline, Position.applyMove, .{ p, v, m, side, ply, u, pos.Fixes.original });
        }
    };
    var work: Position = undefined;

    // 1. As in a search: one position, every move made and taken back on it in turn
    // (unmake_move and the restore of the keys and sums after each). Random-walk states
    // (start and set-up positions), each copied once; the copies are timed alone and
    // taken off. Each pass times both versions, in alternating order.
    const State = struct { p: Position, side: pos.Side, ply: usize, moves: []const pos.Move };
    var states: std.ArrayList(State) = .empty;
    defer {
        for (states.items) |s| gpa.free(s.moves);
        states.deinit(gpa);
    }
    var w = RandomWalk.init(0x5EED_0F07);
    var total: usize = 0;
    while (states.items.len < 3000) : (w.step()) {
        if (w.n == 0) continue;
        try states.append(gpa, .{ .p = w.p, .side = w.side, .ply = w.makePly(), .moves = try gpa.dupe(pos.Move, w.list[0..w.n]) });
        total += w.n;
    }
    // Paired passes: each pass times both versions back to back (in alternating order),
    // so a slow spell of the machine falls on both; the median of the per-pass
    // differences is reported with the best pass of each.
    const wpasses = 101;
    var wcopy: bench.Best = .{};
    var wb: [2]bench.Best = @splat(.{});
    var diffs: [wpasses]f64 = undefined;
    var wins: usize = 0;
    for (0..wpasses) |pass| {
        var ns: [2]i96 = undefined;
        for (0..2) |k| {
            const fused = (k + pass) % 2 == 1;
            var t0 = bench.now();
            for (states.items) |*s| {
                work = s.p;
                bench.keep(&work);
            }
            const tc = bench.now() - t0;
            wcopy.pass(t0);
            t0 = bench.now();
            for (states.items) |*s| {
                work = s.p;
                const keys = .{ work.hash_key, work.pawn_hash_key, work.piece_square_sum, va.pawn_square_sum };
                for (s.moves) |m| {
                    var u: pos.Undo = .{};
                    if (fused) B.fused(&work, va, m, s.side, s.ply, &u) else B.three(&work, va, m, s.side, s.ply, &u);
                    bench.keep(&u);
                    @call(.never_inline, Position.unmakeMove, .{ &work, m, s.side, &u });
                    work.hash_key = keys[0];
                    work.pawn_hash_key = keys[1];
                    work.piece_square_sum = keys[2];
                    va.pawn_square_sum = keys[3];
                }
                bench.keep(&work);
            }
            ns[@intFromBool(fused)] = bench.now() - t0 - tc;
            wb[@intFromBool(fused)].pass(t0);
        }
        diffs[pass] = @as(f64, @floatFromInt(ns[0] - ns[1])) / @as(f64, @floatFromInt(total));
        if (ns[1] < ns[0]) wins += 1;
    }
    std.mem.sort(f64, &diffs, {}, std.sort.asc(f64));
    wb[0].report("position: walk states, every move: the three routines, unmake_move + restore", total, wpasses, wcopy.ns);
    wb[1].report("position: walk states, every move: applyMove, unmake_move + restore", total, wpasses, wcopy.ns);
    std.debug.print("bench position: walk states: applyMove saves {d:.1} ns per move (median of {d} paired passes; quartiles {d:.1}, {d:.1}); faster in {d} of {d} passes\n", .{ diffs[wpasses / 2], wpasses, diffs[wpasses / 4], diffs[3 * wpasses / 4], wins, wpasses });

    // 2. Every 97th recorded make_move state, copied fresh before each call.
    var sm = try Sampler.collect(gpa, 97, 4096);
    defer sm.deinit();
    const items = sm.lists[0].items;
    const reps = 64;
    const rpasses = 61;
    var copy: bench.Best = .{};
    var rb: [2]bench.Best = @splat(.{});
    var rdiffs: [rpasses]f64 = undefined;
    var rwins: usize = 0;
    for (0..rpasses) |pass| {
        var ns: [2]i96 = undefined;
        for (0..2) |k| {
            const fused = (k + pass) % 2 == 1;
            var t0 = bench.now();
            for (0..reps) |_| for (items) |*c| {
                work = c.p;
                bench.keep(&work);
            };
            const tc = bench.now() - t0;
            copy.pass(t0);
            t0 = bench.now();
            for (0..reps) |_| for (items) |*c| {
                work = c.p;
                var u: pos.Undo = .{};
                if (fused) B.fused(&work, va, c.move, c.side, c.ply, &u) else B.three(&work, va, c.move, c.side, c.ply, &u);
                bench.keep(&work);
                bench.keep(&u);
            };
            ns[@intFromBool(fused)] = bench.now() - t0 - tc;
            rb[@intFromBool(fused)].pass(t0);
        }
        rdiffs[pass] = @as(f64, @floatFromInt(ns[0] - ns[1])) / @as(f64, @floatFromInt(reps * items.len));
        if (ns[1] < ns[0]) rwins += 1;
    }
    std.mem.sort(f64, &rdiffs, {}, std.sort.asc(f64));
    rb[0].report("position: recorded states, fresh copy: the three routines", reps * items.len, rpasses, copy.ns);
    rb[1].report("position: recorded states, fresh copy: applyMove", reps * items.len, rpasses, copy.ns);
    std.debug.print("bench position: recorded states: applyMove saves {d:.1} ns per move (median of {d} paired passes; quartiles {d:.1}, {d:.1}); faster in {d} of {d} passes\n", .{ rdiffs[rpasses / 2], rpasses, rdiffs[rpasses / 4], rdiffs[3 * rpasses / 4], rwins, rpasses });
}
