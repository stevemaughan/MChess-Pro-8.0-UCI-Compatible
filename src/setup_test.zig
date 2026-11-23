//! Differential tests of src/setup.zig against calls recorded from the running original
//! (tests/golden/setup/*.zst, made by tools/port/gen_setup_vectors.py, whose docstring
//! defines the format).
//!
//! build_position_from_setup (38C0:6788): each recorded call gives the search position
//! (every field of tools/research/position/model.py FIELDS) and the set-up board at
//! entry, the side, setup side and en-passant square, and at the return the position,
//! the cleaned set-up board, the saved set-up copy, the game board and the game-state
//! variables. The test loads the entry state, builds, and compares everything.
//! setup_legality (38C0:6542): the board and side, and the returned AX.
//! new_game_position (0000:919A): the position at entry and at return.

const std = @import("std");
const pos = @import("position.zig");
const setup = @import("setup.zig");
const Position = pos.Position;

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

/// Moves the position to or from a state image, field by field in `fields` order.
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

/// Offset in the state image of check_by_ply[60] (DG:8C42), the first of the four
/// entries that alias the set-up board.
const check_alias_off = fieldOffset("check") + 60;

/// Offset in the state image of ep_square_by_ply[36], which is DG:9EEC (clock_side) in
/// the original: the build writes the side to move there.
const ep36_alias_off = fieldOffset("ep_sq") + 36;

fn fieldOffset(comptime name: []const u8) usize {
    comptime {
        var o: usize = 0;
        for (fields) |f| {
            if (std.mem.eql(u8, f.name, name)) return o;
            o += fieldSize(f);
        }
        unreachable;
    }
}

// ---------------------------------------------------------------------------
// Reading the vectors
// ---------------------------------------------------------------------------

fn readVectors(gpa: std.mem.Allocator, name: []const u8) ![]u8 {
    var path_buf: [256]u8 = undefined;
    const dir = @import("build_options").golden_dir;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/setup/{s}", .{ dir, name });
    const compressed = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, gpa, .limited(64 << 20));
    defer gpa.free(compressed);
    var in: std.Io.Reader = .fixed(compressed);
    const window = try gpa.alloc(u8, std.compress.zstd.default_window_len + std.compress.zstd.block_size_max);
    defer gpa.free(window);
    var zd = std.compress.zstd.Decompress.init(&in, window, .{});
    return zd.reader.allocRemaining(gpa, .limited(64 << 20));
}

const Cursor = struct {
    d: []const u8,
    i: usize = 0,

    fn take(c: *Cursor, n: usize) []const u8 {
        const s = c.d[c.i..][0..n];
        c.i += n;
        return s;
    }
    fn byte(c: *Cursor) u8 {
        return c.take(1)[0];
    }
    fn int(c: *Cursor, comptime T: type) T {
        return std.mem.readInt(T, c.take(@sizeOf(T))[0..@sizeOf(T)], .little);
    }
};

/// The extras of the vector file, in order: address, size, and the value the Zig
/// SetupVars holds for it.
fn extraValue(v: *const setup.SetupVars, i: usize) u16 {
    return switch (i) {
        0 => v.side_ae44,
        1 => v.side_9eec,
        2 => v.setup_side_saved,
        3 => v.side_word,
        4 => v.computer_side,
        5 => v.in_check,
        6 => v.book_off,
        7 => v.book_exit_ply,
        8 => v.move_number,
        9 => v.last_irreversible_ply,
        10 => v.oo_copy[0],
        11 => v.oo_copy[1],
        12 => v.ooo_copy[0],
        13 => v.ooo_copy[1],
        14, 15, 16 => v.zero_bytes[i - 14],
        17...23 => v.zero_words[i - 17],
        else => unreachable,
    };
}
const extra_dg = [_]u16{ 0xAE44, 0x9EEC, 0xB42A, 0xA36A, 0x8DDE, 0x7328, 0x70E4, 0x9FBC, 0xA84A, 0x7464, 0xA5E6, 0xA5E8, 0xA6A4, 0xA6A6, 0xB42B, 0xA4F3, 0xA4FA, 0xA8DA, 0x153C, 0x9D92, 0xA6AE, 0x2A8E, 0xA3FA, 0xA414 };

const Counts = struct { build: usize = 0, legality: usize = 0, new_game: usize = 0 };

fn replay(gpa: std.mem.Allocator, name: []const u8) !Counts {
    const data = try readVectors(gpa, name);
    defer gpa.free(data);
    var c: Cursor = .{ .d = data };
    try std.testing.expectEqualSlices(u8, "MCSV", c.take(4));
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
    const n_extra = c.int(u16);
    try std.testing.expectEqual(extra_dg.len, n_extra);
    var extra_size: [extra_dg.len]u8 = undefined;
    for (0..n_extra) |i| {
        try std.testing.expectEqual(extra_dg[i], c.int(u16));
        extra_size[i] = c.byte();
    }

    var counts: Counts = .{};
    var buf: [64]u8 = undefined;
    const nb = c.int(u32);
    for (0..nb) |k| {
        var img: Image = c.take(state_size)[0..state_size].*;
        var p: Position = .{};
        transfer(false, &p, &img);
        var v: setup.SetupVars = .{};
        @memcpy(&v.board, c.take(121));
        v.side = c.byte();
        v.setup_side = c.byte();
        v.ep_square = c.byte();
        const want: Image = c.take(state_size)[0..state_size].*;
        const want_board = c.take(121);
        const want_saved = c.take(78);
        const want_game = c.take(120);
        setup.build(&p, &v);
        var got: Image = undefined;
        transfer(true, &p, &got);
        // ep_square_by_ply[36] is DG:9EEC, which the build sets to the side to move
        // (SetupVars.side_9eec); the Zig Position keeps the two apart.
        got[ep36_alias_off] = v.side_9eec;
        for (0..state_size) |o| {
            if (got[o] != want[o]) {
                std.debug.print("setup build call {d} ({s}): {s} is {X:0>2}, the original's {X:0>2}\n", .{ k, name, describe(&buf, o), got[o], want[o] });
                return error.TestUnexpectedResult;
            }
        }
        if (!std.mem.eql(u8, &v.board, want_board)) {
            const i = std.mem.indexOfDiff(u8, &v.board, want_board).?;
            std.debug.print("setup build call {d}: set-up board DG:{X:0>4} is {X:0>2}, the original's {X:0>2}\n", .{ k, 0x8C42 + i, v.board[i], want_board[i] });
            return error.TestUnexpectedResult;
        }
        try std.testing.expectEqualSlices(u8, want_saved, v.saved_setup[0x15..0x63]);
        try std.testing.expectEqualSlices(u8, want_game, &v.game_board);
        for (0..n_extra) |i| {
            const raw = c.take(extra_size[i]);
            const want_v: u16 = if (extra_size[i] == 2) std.mem.readInt(u16, raw[0..2], .little) else raw[0];
            if (extraValue(&v, i) != want_v) {
                std.debug.print("setup build call {d}: DG:{X:0>4} is {X}, the original's {X}\n", .{ k, extra_dg[i], extraValue(&v, i), want_v });
                return error.TestUnexpectedResult;
            }
        }
        counts.build += 1;
    }
    const nl = c.int(u32);
    for (0..nl) |k| {
        var b: [121]u8 = undefined;
        @memcpy(&b, c.take(121));
        const side = c.byte();
        const ax = c.int(u16);
        const got = setup.legality(&b, side);
        if (@backingInt(got) != ax) {
            std.debug.print("setup legality call {d}: {d}, the original's {d}\n", .{ k, @backingInt(got), ax });
            return error.TestUnexpectedResult;
        }
        counts.legality += 1;
    }
    const nn = c.int(u32);
    for (0..nn) |k| {
        var img: Image = c.take(state_size)[0..state_size].*;
        var p: Position = .{};
        transfer(false, &p, &img);
        const want: Image = c.take(state_size)[0..state_size].*;
        var v: setup.SetupVars = .{};
        setup.newGame(&p, &v);
        var got: Image = undefined;
        transfer(true, &p, &got);
        // check_by_ply[60..63] alias the set-up board's first squares, which new game
        // writes through the board (v.board), not through check_by_ply.
        for (0..4) |i| try std.testing.expectEqual(@as(u8, 7), want[check_alias_off + i]);
        @memcpy(got[check_alias_off..][0..4], want[check_alias_off..][0..4]);
        for (0..state_size) |o| {
            if (got[o] != want[o]) {
                std.debug.print("new game call {d}: {s} is {X:0>2}, the original's {X:0>2}\n", .{ k, describe(&buf, o), got[o], want[o] });
                return error.TestUnexpectedResult;
            }
        }
        counts.new_game += 1;
    }
    try std.testing.expectEqual(data.len, c.i);
    return counts;
}

test "setup vectors: build_position_from_setup, setup_legality and new game replayed" {
    const gpa = std.testing.allocator;
    const c = try replay(gpa, "setup.zst");
    std.debug.print("setup vectors setup.zst: build_position_from_setup {d}, setup_legality {d}, new_game_position {d} calls replayed, all equal\n", .{ c.build, c.legality, c.new_game });
    try std.testing.expect(c.build > 0 and c.legality > 0 and c.new_game > 0);
}

test "legality: each refusal of Setup mode, in the order the checks run" {
    const Case = struct { fen: []const u8, side: u8, want: setup.Legality };
    const cases = [_]Case{
        .{ .fen = "4k3/8/8/8/8/8/8/8", .side = 0, .want = .no_white_king },
        .{ .fen = "4k3/8/8/8/8/8/8/K3K3", .side = 0, .want = .too_many_white_kings },
        .{ .fen = "8/8/8/8/8/8/8/4K3", .side = 0, .want = .no_black_king },
        .{ .fen = "4k3/8/8/8/8/P7/PPPPPPPP/4K3", .side = 0, .want = .too_many_white_pawns },
        .{ .fen = "4k3/8/8/8/8/8/PPPPPPPP/2B1KB1B", .side = 0, .want = .too_many_white_pieces },
        .{ .fen = "4k3/8/8/8/8/8/PPPPPPP1/2B1KB1B", .side = 0, .want = .legal },
        .{ .fen = "4k3/8/8/8/8/8/8/r3K3", .side = 1, .want = .white_in_check },
        .{ .fen = "8/8/8/8/8/8/3k4/4K3", .side = 0, .want = .black_in_check },
        .{ .fen = "8/8/8/8/8/8/3k4/4K3", .side = 1, .want = .white_in_check },
        .{ .fen = "P3k3/8/8/8/8/8/8/4K3", .side = 0, .want = .legal },
    };
    for (cases) |cs| {
        var b: [121]u8 = @splat(7);
        var rank: usize = 7;
        var file: usize = 0;
        for (0..8) |r| for (0..8) |f| {
            b[21 + 10 * r + f] = 0;
        };
        for (cs.fen) |ch| {
            switch (ch) {
                '/' => {
                    rank -= 1;
                    file = 0;
                },
                '1'...'8' => file += ch - '0',
                else => {
                    const code: u8 = switch (std.ascii.toLower(ch)) {
                        'p' => 1,
                        'n' => 2,
                        'b' => 3,
                        'r' => 4,
                        'q' => 5,
                        'k' => 6,
                        else => unreachable,
                    };
                    b[21 + 10 * rank + file] = if (std.ascii.isUpper(ch)) code else code + 7;
                    file += 1;
                },
            }
        }
        try std.testing.expectEqual(cs.want, setup.legality(&b, cs.side));
    }
}

// ---------------------------------------------------------------------------
// Benchmark (src/bench.zig): a FEN parsed, checked and built, as `position` does it
// ---------------------------------------------------------------------------

const bench = @import("bench.zig");
const fen = @import("fen.zig");

test "bench: setup: FEN parse, consistency check and build" {
    if (!bench.enabled) return;
    const texts = [_][]const u8{
        fen.startpos,
        "r1bqkb1r/pppp1ppp/2n2n2/4p3/2B1P3/5N2/PPPP1PPP/RNBQK2R w KQkq - 4 4",
        "8/8/8/4k3/8/8/3Q4/4K3 w - - 0 1",
        "r3k2r/p1ppqpb1/bn2pnp1/3PN3/1p2P3/2N2Q1p/PPPBBPPP/R3K2R w KQkq - 0 1",
    };
    const passes = 7;
    const reps = 20_000;
    var pf: bench.Best = .{};
    for (0..passes) |_| {
        const t0 = bench.now();
        for (0..reps) |_| for (texts) |t| {
            const d = try fen.parse(t);
            try fen.checkConsistency(&d);
            bench.keep(&d);
        };
        pf.pass(t0);
    }
    pf.report("setup: fen.parse + checkConsistency", reps * texts.len, passes, 0);
    var descs: [texts.len]fen.Description = undefined;
    for (&descs, texts) |*d, t| d.* = try fen.parse(t);
    var best: bench.Best = .{};
    var p: Position = .{};
    var v: setup.SetupVars = .{};
    for (0..passes) |_| {
        const t0 = bench.now();
        for (0..reps) |_| for (&descs) |*d| {
            setup.buildFromDescription(&p, &v, d);
            bench.keep(&p);
            bench.keep(&v);
        };
        best.pass(t0);
    }
    best.report("setup: buildFromDescription (38C0:6788)", reps * texts.len, passes, 0);
}
