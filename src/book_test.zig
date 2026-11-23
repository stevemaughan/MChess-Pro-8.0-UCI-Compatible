//! Differential tests of src/book.zig against calls of book_probe (4793:621E) recorded
//! from the running original (tests/golden/book/*.zst, made by
//! tools/port/gen_book_vectors.py, whose docstring defines the format).
//!
//! Each record gives what the probe read (mode, side, game ply, book flags, the
//! book-exit ply, the search board, the castling stamps, the en-passant square, the
//! rand() seed) and what it produced (whether it returned early, the key, the name
//! number, the book-exit ply after it, the return value, the display list for the ply
//! in order, and in mode 1 the move handed over, the rand() seed after the choice and
//! the book-move ply). The test runs `book.probe` on the inputs and compares every
//! output.
//!
//! The book files are read at test time from reference/original/M80/PRBOOK/, found from
//! the build's `golden_dir` (tests/golden, two levels below the project root). The test
//! is skipped, with a message, when that folder is absent.

const std = @import("std");
const book = @import("book.zig");
const pos = @import("position.zig");

const golden_dir = @import("build_options").golden_dir;
const book_dir = golden_dir ++ "/../../reference/original/M80/PRBOOK";

/// The recorded runs (docs/PORT_STATUS.md gives the commands).
const runs = [_][]const u8{ "mon.zst", "rand.zst", "rand2.zst", "play_t.zst", "play2_t.zst", "play_s.zst", "play2_s.zst", "play_v.zst", "play2_v.zst", "play_w.zst", "playlong.zst", "extra.zst", "newgame.zst", "bookoff.zst" };

// ---------------------------------------------------------------------------
// The book files
// ---------------------------------------------------------------------------

const Loaded = struct {
    bufs: [17][]u8,
    files: book.Files,

    fn deinit(l: *Loaded, gpa: std.mem.Allocator) void {
        for (l.bufs) |b| gpa.free(b);
    }
};

/// Reads the 17 book files, or returns null (after printing why) if the folder is
/// absent.
fn loadBook(gpa: std.mem.Allocator) !?Loaded {
    var l: Loaded = undefined;
    var n: usize = 0;
    errdefer for (l.bufs[0..n]) |b| gpa.free(b);
    for (0..17) |i| {
        var name_buf: [128]u8 = undefined;
        const path = if (i < 16)
            try std.fmt.bufPrint(&name_buf, "{s}/M80KEY.{X:0>3}", .{ book_dir, i })
        else
            try std.fmt.bufPrint(&name_buf, "{s}/PRBOOK.M80", .{book_dir});
        l.bufs[i] = std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, gpa, .limited(4 << 20)) catch |e| switch (e) {
            error.FileNotFound => {
                std.debug.print("\nbook: SKIPPED, the book files are not at {s} ({s} missing)\n", .{ book_dir, path });
                for (l.bufs[0..n]) |b| gpa.free(b);
                return null;
            },
            else => return e,
        };
        n += 1;
    }
    for (0..16) |i| l.files.index[i] = l.bufs[i];
    l.files.moves = l.bufs[16];
    return l;
}

// ---------------------------------------------------------------------------
// Reading a vector file
// ---------------------------------------------------------------------------

fn readVectors(gpa: std.mem.Allocator, name: []const u8) ![]u8 {
    var path_buf: [256]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/book/{s}", .{ golden_dir, name });
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
    fn bytes(c: *Cursor, n: usize) []const u8 {
        const s = c.d[c.i..][0..n];
        c.i += n;
        return s;
    }
};

const Counts = struct {
    calls: [4]usize = @splat(0),
    early: usize = 0,
    keys: usize = 0,
    found: usize = 0,
    lists: usize = 0,
    entries: usize = 0,
    tied_lists: usize = 0,
    black: usize = 0,
    ep: usize = 0,
    book_off: usize = 0,
    choices: [3]usize = @splat(0), // standard, tournament, variety
    played: usize = 0,
    rand_calls: usize = 0,
    max_rand_calls: usize = 0,

    fn add(t: *Counts, n: Counts) void {
        for (&t.calls, n.calls) |*a, b| a.* += b;
        for (&t.choices, n.choices) |*a, b| a.* += b;
        t.early += n.early;
        t.keys += n.keys;
        t.found += n.found;
        t.lists += n.lists;
        t.entries += n.entries;
        t.tied_lists += n.tied_lists;
        t.black += n.black;
        t.ep += n.ep;
        t.book_off += n.book_off;
        t.played += n.played;
        t.rand_calls += n.rand_calls;
        t.max_rand_calls = @max(t.max_rand_calls, n.max_rand_calls);
    }
};

/// Number of rand() calls that take the generator from `a` to `b` (at most 1000).
fn randCallsBetween(a: u32, b: u32) ?usize {
    var r: book.Rand = .{ .seed = a };
    for (0..1000) |n| {
        if (r.seed == b) return n;
        _ = r.next();
    }
    return null;
}

fn fail(name: []const u8, index: usize, mode: u8, side: u8, ply: u16, comptime what: []const u8, args: anytype) error{MismatchWithOriginal} {
    std.debug.print("\nbook vectors {s}: call {d} (mode {d}, side {d}, ply {d}) differs: " ++ what ++ "\n", .{ name, index, mode, side, ply } ++ args);
    return error.MismatchWithOriginal;
}

/// Replays every call in one vector file; fails at the first call whose result differs
/// from the original's, naming the call and the field.
fn replay(gpa: std.mem.Allocator, files: *const book.Files, name: []const u8) !Counts {
    const data = try readVectors(gpa, name);
    defer gpa.free(data);
    var c: Cursor = .{ .d = data };
    try std.testing.expectEqualSlices(u8, "MCBK", c.bytes(4));
    try std.testing.expectEqual(@as(u16, 1), c.int(u16));
    var n: Counts = .{};
    var index: usize = 0;
    while (true) {
        const tag = c.byte();
        if (tag == 0) {
            try std.testing.expectEqual(index, c.int(u32));
            break;
        }
        try std.testing.expectEqual(@as(u8, 1), tag);
        // Inputs.
        const mode_byte = c.byte();
        const side_byte = c.byte();
        const ply = c.int(u16);
        const flags = c.int(u16);
        const off = c.byte();
        const disabled = c.byte();
        const exit0 = c.int(i16);
        var board: [120]u8 = c.bytes(120)[0..120].*;
        var lost: [4]u16 = undefined;
        for (&lost) |*l| l.* = c.int(u16);
        const ep = c.byte();
        const seed0 = c.int(u32);
        // Outputs.
        const early = c.byte() != 0;
        const key = std.mem.readInt(u48, c.bytes(6)[0..6], .little);
        const name_no = c.byte();
        const exit1 = c.int(i16);
        const ax = c.int(u16);
        const nd = c.byte();
        const disp = c.bytes(4 * @as(usize, nd));
        var played: [3]u8 = undefined;
        var seed1: u32 = seed0;
        var move_ply: u16 = 0;
        if (mode_byte == 1) {
            played = c.bytes(3)[0..3].*;
            seed1 = c.int(u32);
            move_ply = c.int(u16);
        }

        const mode = std.enums.fromInt(book.Mode, mode_byte) orelse return error.BadMode;
        const side: pos.Side = @fromBackingInt(@intCast(side_byte));
        const settings = book.Settings.fromFlags(flags, off);
        var session: book.Session = .{ .book_exit_ply = exit0, .book_disabled = disabled != 0 };
        var rand: book.Rand = .{ .seed = seed0 };
        const bp: book.BookPosition = .{ .board = &board, .side = side, .castle_lost = lost, .ep_square = ep };
        const r = book.probe(&session, files, bp, ply, mode, settings, &rand);

        const F = struct { name: []const u8, index: usize, m: u8, s: u8, p: u16 };
        const f: F = .{ .name = name, .index = index, .m = mode_byte, .s = side_byte, .p = ply };
        if (r.early != early) return fail(f.name, f.index, f.m, f.s, f.p, "early return: got {}, want {}", .{ r.early, early });
        if (!early) {
            if (r.key != key) return fail(f.name, f.index, f.m, f.s, f.p, "book key DG:935A: got {X:0>12}, want {X:0>12}", .{ r.key, key });
            if (r.name != name_no) return fail(f.name, f.index, f.m, f.s, f.p, "name number DG:7449: got {d}, want {d}", .{ r.name, name_no });
            const got = r.display.slice();
            if (got.len != nd) return fail(f.name, f.index, f.m, f.s, f.p, "display list length: got {d}, want {d}", .{ got.len, nd });
            for (got, 0..) |e, k| {
                const want = disp[4 * k ..][0..4];
                const have = [4]u8{ e.from, e.to, e.piece_flag, e.grade_flags };
                for (have, want, 0..) |h, w, b| {
                    if (h != w) return fail(f.name, f.index, f.m, f.s, f.p, "display entry {d}, byte {d}: got {X:0>2}, want {X:0>2}", .{ k, b, h, w });
                }
            }
        }
        if (r.returnValue(mode) != ax) return fail(f.name, f.index, f.m, f.s, f.p, "return value AX: got {X:0>4}, want {X:0>4}", .{ r.returnValue(mode), ax });
        if (session.book_exit_ply != exit1) return fail(f.name, f.index, f.m, f.s, f.p, "book-exit ply DG:9FBC: got {d}, want {d}", .{ session.book_exit_ply, exit1 });
        if (rand.seed != seed1) return fail(f.name, f.index, f.m, f.s, f.p, "rand() seed DG:2DC8 after the call: got {X:0>8}, want {X:0>8}", .{ rand.seed, seed1 });
        if (mode == .play and ax & 0xFF == 1) {
            const m = r.chosen.?;
            const have = [3]u8{ m.from, m.to, m.flag };
            for (have, played, 0..) |h, w, b| {
                if (h != w) return fail(f.name, f.index, f.m, f.s, f.p, "book move DG:{X:0>4}: got {d}, want {d}", .{ 0x38A0 + b, h, w });
            }
            const bmp = session.book_move_ply[side_byte];
            if (bmp != move_ply) return fail(f.name, f.index, f.m, f.s, f.p, "book-move ply DG:{X:0>4}: got {d}, want {d}", .{ 0x2522 + 2 * @as(u16, side_byte), bmp, move_ply });
        }

        // Counts.
        n.calls[mode_byte] += 1;
        if (early) {
            n.early += 1;
        } else {
            n.keys += 1;
            n.found += @intFromBool(r.found);
            n.book_off += @intFromBool(settings.mchess_book_off);
            n.black += @intFromBool(side == .black);
            n.ep += @intFromBool(ep != 0);
            if (nd > 0) {
                n.lists += 1;
                n.entries += nd;
                for (r.display.slice()[1..], r.display.slice()[0 .. nd - 1]) |a, b| {
                    if (a.grade() == b.grade()) {
                        n.tied_lists += 1;
                        break;
                    }
                }
            }
            if (mode == .play and r.found) {
                n.choices[if (settings.variety) 2 else if (settings.tournament) 1 else 0] += 1;
                n.played += @intFromBool(r.chosen != null);
                const calls = randCallsBetween(seed0, seed1) orelse 0;
                n.rand_calls += calls;
                n.max_rand_calls = @max(n.max_rand_calls, calls);
            }
        }
        index += 1;
    }
    return n;
}

test "book: replay every recorded call of book_probe" {
    const gpa = std.testing.allocator;
    var loaded = (try loadBook(gpa)) orelse return error.SkipZigTest;
    defer loaded.deinit(gpa);
    var total: Counts = .{};
    for (runs) |name| {
        const n = try replay(gpa, &loaded.files, name);
        std.debug.print("book vectors {s}: {d} calls of book_probe replayed (modes 0/1/2/3: {d}/{d}/{d}/{d}), all equal\n", .{ name, n.calls[0] + n.calls[1] + n.calls[2] + n.calls[3], n.calls[0], n.calls[1], n.calls[2], n.calls[3] });
        total.add(n);
    }
    const t = total;
    std.debug.print(
        \\book vectors total: {d} calls (modes 0/1/2/3: {d}/{d}/{d}/{d}); {d} early returns; {d} keys ({d} for Black to move, {d} with an en-passant square, {d} with the M-Chess book off); {d} found
        \\  {d} display lists with moves, {d} entries, {d} lists with tied grades (qsort order)
        \\  {d} choices (standard {d}, tournament {d}, variety {d}), {d} moves handed over, {d} rand() calls (at most {d} in one choice), seed after each equal
        \\
    , .{
        t.calls[0] + t.calls[1] + t.calls[2] + t.calls[3], t.calls[0], t.calls[1],   t.calls[2],                                 t.calls[3],   t.early,      t.keys,       t.black,  t.ep,         t.book_off,       t.found,
        t.lists,                                           t.entries,  t.tied_lists, t.choices[0] + t.choices[1] + t.choices[2], t.choices[0], t.choices[1], t.choices[2], t.played, t.rand_calls, t.max_rand_calls,
    });
}

// ---------------------------------------------------------------------------
// The files as a whole, and the reader's examples (spec §1, §4.5)
// ---------------------------------------------------------------------------

test "book: the index files are sorted and every group's count is below 8000h" {
    const gpa = std.testing.allocator;
    var loaded = (try loadBook(gpa)) orelse return error.SkipZigTest;
    defer loaded.deinit(gpa);
    var entries: usize = 0;
    for (loaded.files.index) |d| {
        for (0..16) |g| {
            const rec = 0x10 + 10 * g;
            const off = std.mem.readInt(u32, d[rec + 4 ..][0..4], .little);
            const count = std.mem.readInt(u16, d[rec + 8 ..][0..2], .little);
            try std.testing.expect(count < 0x8000);
            try std.testing.expect(off + 8 * @as(usize, count) <= d.len);
            var prev: ?u40 = null;
            for (0..count) |k| {
                const e = d[off + 8 * k ..][0..5];
                const v = std.mem.readInt(u40, e, .big);
                if (prev) |p| try std.testing.expect(p < v);
                prev = v;
            }
            entries += count;
        }
    }
    try std.testing.expectEqual(@as(usize, 389_947), entries);
}

fn startBoard() [120]u8 {
    var b: [120]u8 = @splat(pos.border);
    const back = [8]u8{ 4, 2, 3, 5, 6, 3, 2, 4 };
    for (0..8) |r| for (0..8) |f| {
        b[21 + 10 * r + f] = pos.empty;
    };
    for (0..8) |f| {
        b[21 + f] = back[f];
        b[31 + f] = pos.white_pawn;
        b[81 + f] = pos.black_pawn;
        b[91 + f] = back[f] + 7;
    }
    return b;
}

test "book: the start position and 1.e4, as the reader lists them" {
    const gpa = std.testing.allocator;
    var loaded = (try loadBook(gpa)) orelse return error.SkipZigTest;
    defer loaded.deinit(gpa);
    var board = startBoard();
    var bp: book.BookPosition = .{ .board = &board, .side = .white, .castle_lost = .{ 0, 0, 0, 0 }, .ep_square = 0 };
    var session: book.Session = .{};
    var rand = book.Rand.srand(17);
    var r = book.probe(&session, &loaded.files, bp, 0, .refresh, .{}, &rand);
    try std.testing.expect(r.found);
    try std.testing.expectEqual(@as(u8, 1), r.name); // "The initial position."
    // d4 and e4 grade 6 first (in qsort's order), then the grade-1 moves.
    try std.testing.expectEqual(@as(u3, 6), r.display.entries[0].grade());
    try std.testing.expectEqual(@as(u3, 6), r.display.entries[1].grade());
    // 1.e4: the program, seeded with srand(17) as at the traced start-up, plays c5
    // (spec §5: rand() = 94, 94 % 24 = 22, slot 22 of c6 x9, e6 x9, e5 x3, c5 x3), and
    // the seed afterwards is 005E2290h.
    board[35] = pos.empty;
    board[55] = pos.white_pawn;
    bp.side = .black;
    r = book.probe(&session, &loaded.files, bp, 1, .play, .{}, &rand);
    const m = r.chosen.?;
    try std.testing.expectEqual(@as(u8, 83), m.from); // c7
    try std.testing.expectEqual(@as(u8, 63), m.to); // c5
    try std.testing.expectEqual(@as(u32, 0x005E2290), rand.seed);
}

// ---------------------------------------------------------------------------
// The branches the shipped book cannot reach (UNVERIFIED in book.zig), as the model
// has them: a hand-made list
// ---------------------------------------------------------------------------

fn word(from: u6, to: u6, grade: u3, last: bool) u16 {
    return @as(u16, from) | (@as(u16, to) << 6) | (@as(u16, grade) << 12) | (if (last) @as(u16, 0x8000) else 0);
}

fn rawList(words: []const u16) book.RawList {
    var l: book.RawList = .{};
    for (words, 0..) |w, i| {
        l.words[i] = w;
        const from: u6 = @truncate(w);
        const to: u6 = @truncate(w >> 6);
        if (from != to) l.grades[i] = @truncate((w >> 12) & 7);
    }
    l.count = @intCast(words.len);
    return l;
}

test "book: a grade-7 move is played without a draw; tournament rejects grades below 4" {
    var board = startBoard();
    const bp: book.BookPosition = .{ .board = &board, .side = .white, .castle_lost = .{ 0, 0, 0, 0 }, .ep_square = 0 };
    // e2e4 grade 3, d2d4 grade 7, g1f3 grade 6 (book squares: e2 12, e4 28, d2 11, d4 27, g1 6, f3 21).
    const l = rawList(&.{ word(12, 28, 3, false), word(11, 27, 7, false), word(6, 21, 6, true) });
    var rand = book.Rand.srand(5);
    const d = book.buildDraw(bp, &l, .{});
    try std.testing.expectEqual(@as(i16, 2 + 3 + 9), d.total);
    try std.testing.expectEqual(@as(?book.BookMove, word(11, 27, 0, false)), book.choose(&d, .{}, &rand));
    try std.testing.expectEqual(@as(u32, 5), rand.seed); // no rand() call
    // Without the grade-7 move: tournament draws until a slot of grade >= 4 (g1f3).
    const l2 = rawList(&.{ word(12, 28, 3, false), word(6, 21, 6, true) });
    const d2 = book.buildDraw(bp, &l2, .{});
    for (0..50) |_| try std.testing.expectEqual(@as(?book.BookMove, word(6, 21, 0, false)), book.choose(&d2, .{}, &rand));
}

test "book: a promotion prefix skipped with a grade-0 move attaches to the next move (suspected bug 2, as the model)" {
    // White pawns on b7 and c7 (book squares 49, 50), Black king a1-free board corner.
    var board: [120]u8 = @splat(pos.border);
    for (0..8) |r| for (0..8) |f| {
        board[21 + 10 * r + f] = pos.empty;
    };
    board[25] = pos.white_king;
    board[95] = pos.black_king;
    board[82] = pos.white_pawn; // b7
    board[83] = pos.white_pawn; // c7
    const bp: book.BookPosition = .{ .board = &board, .side = .white, .castle_lost = .{ 1, 1, 1, 1 }, .ep_square = 0 };
    // Prefix 3 (bishop), b7b8 grade 0, c7c8 grade 4: the decode loop gives b8=B grade 0
    // and c8 (queen); the choice walk keeps the prefix past the grade-0 move, so c8=B.
    const l = rawList(&.{ word(3, 3, 0, false), word(49, 57, 0, false), word(50, 58, 4, true) });
    const disp = book.displayList(bp, &l);
    try std.testing.expectEqual(@as(u8, 2), disp.len);
    var rand = book.Rand.srand(1);
    const d = book.buildDraw(bp, &l, .standard);
    const mv = book.choose(&d, .standard, &rand).?;
    try std.testing.expectEqual(@as(book.BookMove, (3 << 12) | word(50, 58, 0, false)), mv);
    try std.testing.expectEqual(@as(u8, 3), book.realMove(&board, mv, .white).flag);
}

// ---------------------------------------------------------------------------
// Benchmark (src/bench.zig): every recorded call's inputs, decoded once, then the probe
// ---------------------------------------------------------------------------

const bench = @import("bench.zig");

const BenchCall = struct {
    board: [120]u8,
    side: pos.Side,
    ply: u16,
    mode: book.Mode,
    settings: book.Settings,
    session: book.Session,
    lost: [4]u16,
    ep: u8,
    seed: u32,
};

fn decodeCalls(gpa: std.mem.Allocator, name: []const u8, out: *std.ArrayList(BenchCall)) !void {
    const data = try readVectors(gpa, name);
    defer gpa.free(data);
    var c: Cursor = .{ .d = data };
    _ = c.bytes(4);
    _ = c.int(u16);
    while (c.byte() != 0) {
        const mode_byte = c.byte();
        const side_byte = c.byte();
        const ply = c.int(u16);
        const flags = c.int(u16);
        const off = c.byte();
        const disabled = c.byte();
        const exit0 = c.int(i16);
        const board: [120]u8 = c.bytes(120)[0..120].*;
        var lost: [4]u16 = undefined;
        for (&lost) |*l| l.* = c.int(u16);
        const ep = c.byte();
        const seed0 = c.int(u32);
        _ = c.byte();
        _ = c.bytes(6);
        _ = c.byte();
        _ = c.int(i16);
        _ = c.int(u16);
        const nd = c.byte();
        _ = c.bytes(4 * @as(usize, nd));
        if (mode_byte == 1) {
            _ = c.bytes(3);
            _ = c.int(u32);
            _ = c.int(u16);
        }
        try out.append(gpa, .{
            .board = board,
            .side = @fromBackingInt(@intCast(side_byte)),
            .ply = ply,
            .mode = std.enums.fromInt(book.Mode, mode_byte) orelse return error.BadMode,
            .settings = book.Settings.fromFlags(flags, off),
            .session = .{ .book_exit_ply = exit0, .book_disabled = disabled != 0 },
            .lost = lost,
            .ep = ep,
            .seed = seed0,
        });
    }
}

test "bench: book: probe over the recorded calls" {
    if (!bench.enabled) return;
    const gpa = std.testing.allocator;
    var loaded = (try loadBook(gpa)) orelse return error.SkipZigTest;
    defer loaded.deinit(gpa);
    var calls: std.ArrayList(BenchCall) = .empty;
    defer calls.deinit(gpa);
    for (runs) |name| try decodeCalls(gpa, name, &calls);
    const passes = 7;
    var over: bench.Best = .{};
    for (0..passes) |_| {
        const t0 = bench.now();
        for (calls.items) |*c| {
            var session = c.session;
            var rand: book.Rand = .{ .seed = c.seed };
            bench.keep(&session);
            bench.keep(&rand);
        }
        over.pass(t0);
    }
    var best: bench.Best = .{};
    for (0..passes) |_| {
        const t0 = bench.now();
        for (calls.items) |*c| {
            var session = c.session;
            var rand: book.Rand = .{ .seed = c.seed };
            const bp: book.BookPosition = .{ .board = &c.board, .side = c.side, .castle_lost = c.lost, .ep_square = c.ep };
            const r = book.probe(&session, &loaded.files, bp, c.ply, c.mode, c.settings, &rand);
            bench.keep(&r);
            bench.keep(&session);
            bench.keep(&rand);
        }
        best.pass(t0);
    }
    best.report("book: probe (4793:621E), recorded calls", calls.items.len, passes, over.ns);
    var key: bench.Best = .{};
    for (0..passes) |_| {
        const t0 = bench.now();
        for (calls.items) |*c| {
            const bp: book.BookPosition = .{ .board = &c.board, .side = c.side, .castle_lost = c.lost, .ep_square = c.ep };
            bench.keep(book.bookKey(bp));
        }
        key.pass(t0);
    }
    key.report("book: bookKey (4793:5816)", calls.items.len, passes, 0);
}

test "DEV-026: corrected, a promotion prefix skipped with a grade-0 move does not attach to the next move" {
    var board: [120]u8 = @splat(pos.border);
    for (0..8) |r| for (0..8) |f| {
        board[21 + 10 * r + f] = pos.empty;
    };
    board[25] = pos.white_king;
    board[95] = pos.black_king;
    board[82] = pos.white_pawn; // b7
    board[83] = pos.white_pawn; // c7
    const bp: book.BookPosition = .{ .board = &board, .side = .white, .castle_lost = .{ 1, 1, 1, 1 }, .ep_square = 0 };
    // Prefix 3 (bishop), b7b8 grade 0, c7c8 grade 4: the original draws c8=B (the test
    // above); corrected, c8 with no prefix, the move the decode loop lists.
    const l = rawList(&.{ word(3, 3, 0, false), word(49, 57, 0, false), word(50, 58, 4, true) });
    const fixed = comptime blk: {
        var f = pos.Fixes.original;
        f.dev026_promotion_prefix = true;
        break :blk f;
    };
    var rand = book.Rand.srand(1);
    const d = book.buildDrawFixes(fixed, bp, &l, .standard);
    const mv = book.choose(&d, .standard, &rand).?;
    try std.testing.expectEqual(word(50, 58, 0, false), mv);
    const orig = book.buildDraw(bp, &l, .standard);
    try std.testing.expect(orig.slot_move[0] != d.slot_move[0]);
    // The same with grade 1 outside the variety book.
    const l1 = rawList(&.{ word(3, 3, 0, false), word(49, 57, 1, false), word(50, 58, 4, true) });
    try std.testing.expectEqual(word(50, 58, 0, false), book.buildDrawFixes(fixed, bp, &l1, .standard).slot_move[0]);
    try std.testing.expectEqual((3 << 12) | word(50, 58, 0, false), book.buildDraw(bp, &l1, .standard).slot_move[0]);
}

test "DEV-026: past a weight total of 400 the walk stops before the move, so every draw falls on a written slot" {
    // 50 moves of grade 6 (weight 9 each): 44 fit (396 slots), the 45th would make 405.
    var board = startBoard();
    board[25] = pos.white_king;
    const bp: book.BookPosition = .{ .board = &board, .side = .white, .castle_lost = .{ 0, 0, 0, 0 }, .ep_square = 0 };
    var words: [50]u16 = undefined;
    for (&words) |*w| w.* = word(12, 28, 6, false); // e2e4, repeated
    words[49] |= 0x8000;
    const l = rawList(&words);
    const d = book.buildDraw(bp, &l, .{});
    try std.testing.expect(d.overflow);
    try std.testing.expectEqual(@as(u16, 396), d.slots);
    try std.testing.expectEqual(@as(i16, 396), d.total); // the original's would be 405
    var rand = book.Rand.srand(7);
    for (0..2000) |_| try std.testing.expect(book.choose(&d, .{}, &rand) != null);
}
