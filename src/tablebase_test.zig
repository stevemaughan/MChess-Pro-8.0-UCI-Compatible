//! Differential test of src/tablebase.zig against direct calls of the original tablebase
//! probe (2B9F:BB76) on made-up positions, with the real tablebase files
//! (tests/golden/tablebase/probe.zst, made by tools/port/gen_tablebase_vectors.py, whose
//! docstring defines the format). The files are read at test time from
//! reference/original/M80/TB/ (next to tests/golden/ under the build root); the test is
//! skipped, with a message, if that folder is absent.

const std = @import("std");
const pos = @import("position.zig");
const tb = @import("tablebase.zig");

const golden_dir = @import("build_options").golden_dir;
/// The program's tablebase folder, relative to the build root (the test's cwd), found
/// from the golden-vector path the build gives.
const tb_dir = golden_dir ++ "/../../reference/original/M80/TB";

const file_names = [_][]const u8{ "KPK.TBW", "KPK.TBB", "KQK.TBW", "KQK.TBB", "KRK.TBW", "KRK.TBB" };

/// The test's file supplier: the program's `TB` folder holds the six files; the second
/// directory (an empty string at run time, so the drive's root) holds none, as in the
/// recorded runs.
const TestFiles = struct {
    data: [file_names.len]?[]u8 = @splat(null),

    fn lookup(ctx: ?*const anyopaque, loc: tb.Location, name: []const u8) ?[]const u8 {
        const self: *const TestFiles = @ptrCast(@alignCast(ctx.?));
        if (loc != .program_tb) return null;
        for (file_names, 0..) |n, i| {
            if (std.ascii.eqlIgnoreCase(n, name)) return self.data[i];
        }
        return null;
    }

    fn files(self: *const TestFiles) tb.Files {
        return .{ .ctx = self, .lookupFn = lookup };
    }

    fn deinit(self: *TestFiles, gpa: std.mem.Allocator) void {
        for (&self.data) |*d| if (d.*) |x| gpa.free(x);
    }
};

fn loadFiles(gpa: std.mem.Allocator) !TestFiles {
    var t: TestFiles = .{};
    errdefer t.deinit(gpa);
    for (file_names, 0..) |n, i| {
        var buf: [256]u8 = undefined;
        const path = try std.fmt.bufPrint(&buf, "{s}/{s}", .{ tb_dir, n });
        t.data[i] = std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, gpa, .limited(1 << 20)) catch |err| switch (err) {
            error.FileNotFound => {
                std.debug.print("tablebase test skipped: {s} not found (the tablebase files are read from {s})\n", .{ path, tb_dir });
                return error.SkipZigTest;
            },
            else => return err,
        };
    }
    return t;
}

fn readVectors(gpa: std.mem.Allocator, name: []const u8) ![]u8 {
    var path_buf: [256]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/tablebase/{s}", .{ golden_dir, name });
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
    fn take(c: *Cursor, n: usize) []const u8 {
        const v = c.d[c.i..][0..n];
        c.i += n;
        return v;
    }
};

/// One recorded call: the inputs.
const Call = struct {
    side: u1,
    ply: u16,
    p: pos.Position,
    st: tb.State,
    stale: u8,
    set: u8,
    model_index: u32,
};

const set_names = [_][]const u8{ "probe.py seed 5", "probe.py seed 6", "probe.py seed 7", "wide", "seed 1 negative index", "seed 2 negative index", "seed 3 negative index" };

const Stats = struct {
    calls: usize = 0,
    returned_1: usize = 0,
    no_signature: usize = 0,
    ply0: usize = 0,
    byte_read: usize = 0,
    past_end: usize = 0,
    negative_index: usize = 0,
    no_file: usize = 0,
    per_set: [set_names.len]usize = @splat(0),
    /// Per set: calls whose index is negative and whose file exists (the seek the old
    /// emulator refused; the read returns nothing and the stale byte is used).
    negative_per_set: [set_names.len]usize = @splat(0),
    black_first: usize = 0,
    pawns: usize = 0,
    transposed_or_flipped: usize = 0,
};

fn fail(index: usize, c: *const Call, comptime fmt: []const u8, args: anytype) error{TestUnexpectedResult} {
    std.debug.print("tablebase call {d} ({s}): side {d}, ply {d}, [239C] {X:0>2}: ", .{ index, set_names[c.set], c.side, c.ply, c.st.mode });
    std.debug.print(fmt ++ "\n", args);
    return error.TestUnexpectedResult;
}

fn replay(gpa: std.mem.Allocator, files: tb.Files, name: []const u8, stats: *Stats) !void {
    const d = try readVectors(gpa, name);
    defer gpa.free(d);
    var c: Cursor = .{ .d = d };
    try std.testing.expectEqualSlices(u8, "MCTB", c.take(4));
    try std.testing.expectEqual(@as(u16, 1), c.int(u16));
    const nsig = c.int(i16);
    const nwords = c.int(u16);
    var sig_buf: [64]u16 = undefined;
    for (0..nwords) |k| sig_buf[k] = c.int(u16);
    const sigs = sig_buf[0..nwords];
    _ = c.take(c.byte()); // the program directory (documentation: the test maps it to tb_dir)
    const dir2 = c.take(c.byte());
    try std.testing.expectEqual(@as(usize, 0), dir2.len); // so the second place is the root: no files

    var index: usize = 0;
    while (true) : (index += 1) {
        const tag = c.byte();
        if (tag == 0) {
            try std.testing.expectEqual(@as(u32, @intCast(index)), c.int(u32));
            break;
        }
        try std.testing.expectEqual(@as(u8, 1), tag);
        var call: Call = .{
            .side = @intCast(c.byte()),
            .ply = c.int(u16),
            .p = .{},
            .st = .{ .signature_count = nsig, .signatures = sigs },
            .stale = 0,
            .set = 0,
            .model_index = 0,
        };
        call.st.mode = c.byte();
        call.st.program_side = c.byte();
        call.st.score_bound = c.int(i16);
        call.p.side_pawn_count = .{ c.byte(), c.byte() };
        call.p.piece_material = .{ c.int(u16), c.int(u16) };
        call.p.pawn_count = c.byte();
        call.p.ep_square_by_ply[2] = c.byte();
        call.p.piece_list[7] = c.byte();
        call.p.piece_list[16 + 7] = c.byte();
        call.stale = c.byte();
        call.st.score = c.int(i16);
        @memcpy(&call.p.board, c.take(120));
        call.set = c.byte();
        call.model_index = c.int(u32);
        const want_ax = c.int(u16);
        const want_score = c.int(i16);
        const wrote = c.byte();

        stats.calls += 1;
        stats.per_set[call.set] += 1;
        if (call.ply == 0) stats.ply0 += 1;

        const loc = tb.locate(&call.p, &call.st, call.side, call.ply);
        if (wrote != 0) {
            const b521 = c.byte();
            const cw = c.int(u16);
            const cb = c.int(u16);
            const men = c.int(u16);
            const want_name = c.take(men + 4);
            if (c.byte() != 0) return fail(index, &call, "recorded name not NUL-terminated", .{});
            const l = loc orelse return fail(index, &call, "the original passed the signature test, the port did not", .{});
            if (@intFromBool(l.first_black) != b521) return fail(index, &call, "DG:B521 (Black named first): original {d}, port {any}", .{ b521, l.first_black });
            if (l.counts[0] != cw or l.counts[1] != cb or l.men != men)
                return fail(index, &call, "men (DG:8BB8, 8BBA, 9EBC): original {d} {d} {d}, port {d} {d} {d}", .{ cw, cb, men, l.counts[0], l.counts[1], l.men });
            if (!std.mem.eql(u8, want_name, l.name())) return fail(index, &call, "file name (DG:B50E): original {s}, port {s}", .{ want_name, l.name() });
            for (0..men) |k| {
                const w = c.int(u16);
                if (w != l.entries[k]) return fail(index, &call, "square entry {d} (DG:{X:0>4}): original {X:0>4}, port {X:0>4}", .{ k, 0x8FCA + 2 * k, w, l.entries[k] });
            }
            if (l.first_black) stats.black_first += 1;
            if (call.p.pawn_count != 0) stats.pawns += 1;
            var flags = (if (call.ply == 0) @as(u8, 0x0A) else 0x06) & call.st.mode;
            if (call.ply != 0 and call.st.mode & 1 == 0) flags &= 4;
            if (flags != 0) {
                // The index is not in DGROUP; the recorder stored the model's (which matched
                // the original on every recorded call, AX and every DGROUP byte).
                if (l.index != call.model_index)
                    return fail(index, &call, "file index: model {d}, port {d}", .{ call.model_index, l.index });
                // what the read will meet (for the counts only): the program's TB folder is
                // tried only with flags 04h or 08h; the second place never has a file here
                const found = if (flags & 0x0C != 0) files.lookup(.program_tb, l.name()) else null;
                if (found) |data| {
                    if (l.index >= 0x8000_0000) {
                        stats.negative_index += 1;
                        stats.negative_per_set[call.set] += 1;
                    }
                    if (l.index < data.len) stats.byte_read += 1 else stats.past_end += 1;
                } else stats.no_file += 1;
            }
        } else {
            stats.no_signature += 1;
            if (loc != null) return fail(index, &call, "the original failed the signature test, the port passed it", .{});
        }

        var st = call.st;
        const got = tb.probe(tb.Fixes.original, &call.p, &st, files, call.side, call.ply, call.stale);
        if (@intFromBool(got) != want_ax) return fail(index, &call, "AX: original {d}, port {any}", .{ want_ax, got });
        if (st.score != want_score) return fail(index, &call, "score DG:7466: original {d}, port {d}", .{ want_score, st.score });
        if (got) stats.returned_1 += 1;
    }
}

test "tablebase probe: replay every recorded call of the original" {
    const gpa = std.testing.allocator;
    var tf = try loadFiles(gpa);
    defer tf.deinit(gpa);
    var stats: Stats = .{};
    try replay(gpa, tf.files(), "probe.zst", &stats);
    std.debug.print(
        "tablebase vectors: {d} calls of tb_probe (2B9F:BB76) replayed, all equal to the original " ++
            "(AX, score DG:7466, and when written the file name, order flag, counts and the 8FCA squares): " ++
            "{d} returned 1; {d} failed the signature test; {d} at ply 0; {d} read a byte, {d} read past the end " ++
            "({d} with a negative index) and used the stale byte; {d} looked for a file that does not exist; " ++
            "{d} named Black first; {d} with pawns\n",
        .{ stats.calls, stats.returned_1, stats.no_signature, stats.ply0, stats.byte_read, stats.past_end, stats.negative_index, stats.no_file, stats.black_first, stats.pawns },
    );
    std.debug.print("  per set:", .{});
    for (set_names, stats.per_set, stats.negative_per_set) |n, k, neg| std.debug.print(" {s} {d} ({d} negative index);", .{ n, k, neg });
    std.debug.print("\n", .{});
}

// ---------------------------------------------------------------------------
// DEV-025: original and corrected behaviour
// ---------------------------------------------------------------------------

/// A supplier with one short KQK.TBW in the program's folder: every index past its end.
const ShortFile = struct {
    data: []const u8,
    fn lookup(ctx: ?*const anyopaque, loc: tb.Location, name: []const u8) ?[]const u8 {
        const self: *const ShortFile = @ptrCast(@alignCast(ctx.?));
        if (loc == .program_tb and std.mem.eql(u8, name, "KQK.TBW")) return self.data;
        return null;
    }
};

fn kqkPosition() pos.Position {
    var p: pos.Position = .{};
    for (&p.board, 0..) |*b, s| b.* = if (s % 10 == 0 or s % 10 == 9 or s < 21 or s > 98) pos.border else pos.empty;
    p.board[25] = pos.white_king; // e1
    p.board[54] = pos.white_queen; // d4
    p.board[95] = pos.black_king; // e8
    p.piece_list[7] = 25;
    p.piece_list[16 + 7] = 95;
    p.piece_material = .{ 2000, 0 };
    return p;
}

test "DEV-025: a read past the end of the file (original: the stale stack byte; corrected: no result)" {
    const p = kqkPosition();
    const short: ShortFile = .{ .data = &.{0} }; // one byte: the probe's index is past it
    const files: tb.Files = .{ .ctx = &short, .lookupFn = ShortFile.lookup };
    const l = tb.locate(&p, &tb.State{}, 0, 0).?;
    try std.testing.expectEqualStrings("KQK.TBW", l.name());
    try std.testing.expect(l.index >= 1);

    // Ply 0, mode 08h: only the program's TB folder is tried.
    var st: tb.State = .{ .mode = 0x08, .program_side = 1, .score = 1234 };
    // Original: the stale byte 5 is taken as "win in 5".
    try std.testing.expect(tb.probe(tb.Fixes.original, &p, &st, files, 0, 0, 5));
    try std.testing.expectEqual(@as(i16, 2 * (5 + 0x2691)), st.score);
    // Original with a stale byte outside -126..126: no result, score untouched.
    st.score = 1234;
    try std.testing.expect(!tb.probe(tb.Fixes.original, &p, &st, files, 0, 0, 0x80));
    try std.testing.expectEqual(@as(i16, 1234), st.score);
    // Corrected: no result whatever the stack held; the score is not written.
    st.score = 1234;
    try std.testing.expect(!tb.probe(tb.Fixes.corrected, &p, &st, files, 0, 0, 5));
    try std.testing.expectEqual(@as(i16, 1234), st.score);
}

test "tablebase probe: colour reversal names the same file and index" {
    // K+Q v K with White to move and its colour-reversed twin (Black K+Q, ranks flipped,
    // Black to move) read the same file at the same index.
    const p = kqkPosition();
    var q: pos.Position = .{};
    q.board = p.board;
    q.board[25] = pos.empty;
    q.board[54] = pos.empty;
    q.board[95] = pos.empty;
    q.board[95] = pos.black_king; // e8 (e1 flipped)
    q.board[64] = pos.black_queen; // d5 (d4 flipped)
    q.board[25] = pos.white_king; // e1 (e8 flipped)
    q.piece_list[7] = 25;
    q.piece_list[16 + 7] = 95;
    q.piece_material = .{ 0, 2000 };
    const a = tb.locate(&p, &tb.State{}, 0, 0).?;
    const b = tb.locate(&q, &tb.State{}, 1, 0).?;
    try std.testing.expectEqualStrings("KQK.TBW", a.name());
    try std.testing.expectEqualStrings("KQK.TBW", b.name());
    try std.testing.expectEqual(a.index, b.index);
}

// ---------------------------------------------------------------------------
// Benchmark (src/bench.zig): the recorded calls, decoded once, then the probe alone
// ---------------------------------------------------------------------------

const bench = @import("bench.zig");

/// The inputs of every recorded call, for the benchmark. `sigs` holds the signature
/// words the calls' `st.signatures` point into.
const Decoded = struct {
    calls: []Call,
    sigs: []u16,

    fn deinit(d: *Decoded, gpa: std.mem.Allocator) void {
        gpa.free(d.calls);
        gpa.free(d.sigs);
    }
};

fn decodeCalls(gpa: std.mem.Allocator, name: []const u8) !Decoded {
    const d = try readVectors(gpa, name);
    defer gpa.free(d);
    var c: Cursor = .{ .d = d };
    _ = c.take(4);
    _ = c.int(u16);
    const nsig = c.int(i16);
    const nwords = c.int(u16);
    const sigs = try gpa.alloc(u16, nwords);
    errdefer gpa.free(sigs);
    for (sigs) |*s| s.* = c.int(u16);
    _ = c.take(c.byte());
    _ = c.take(c.byte());
    var list: std.ArrayList(Call) = .empty;
    errdefer list.deinit(gpa);
    while (c.byte() != 0) {
        var call: Call = .{
            .side = @intCast(c.byte()),
            .ply = c.int(u16),
            .p = .{},
            .st = .{ .signature_count = nsig, .signatures = sigs },
            .stale = 0,
            .set = 0,
            .model_index = 0,
        };
        call.st.mode = c.byte();
        call.st.program_side = c.byte();
        call.st.score_bound = c.int(i16);
        call.p.side_pawn_count = .{ c.byte(), c.byte() };
        call.p.piece_material = .{ c.int(u16), c.int(u16) };
        call.p.pawn_count = c.byte();
        call.p.ep_square_by_ply[2] = c.byte();
        call.p.piece_list[7] = c.byte();
        call.p.piece_list[16 + 7] = c.byte();
        call.stale = c.byte();
        call.st.score = c.int(i16);
        @memcpy(&call.p.board, c.take(120));
        call.set = c.byte();
        call.model_index = c.int(u32);
        _ = c.int(u16);
        _ = c.int(i16);
        if (c.byte() != 0) {
            _ = c.byte();
            _ = c.int(u16);
            _ = c.int(u16);
            const men = c.int(u16);
            _ = c.take(men + 4);
            _ = c.byte();
            _ = c.take(2 * @as(usize, men));
        }
        try list.append(gpa, call);
    }
    return .{ .calls = try list.toOwnedSlice(gpa), .sigs = sigs };
}

test "bench: tablebase: probe and locate over the recorded calls" {
    if (!bench.enabled) return;
    const gpa = std.testing.allocator;
    var tf = try loadFiles(gpa);
    defer tf.deinit(gpa);
    var dec = try decodeCalls(gpa, "probe.zst");
    defer dec.deinit(gpa);
    const calls = dec.calls;
    const files = tf.files();
    const passes = 7;

    var over: bench.Best = .{};
    for (0..passes) |_| {
        const t0 = bench.now();
        for (calls) |*c| {
            var st = c.st;
            bench.keep(&st);
        }
        over.pass(t0);
    }
    var best: bench.Best = .{};
    for (0..passes) |_| {
        const t0 = bench.now();
        for (calls) |*c| {
            var st = c.st;
            bench.keep(tb.probe(tb.Fixes.original, &c.p, &st, files, c.side, c.ply, c.stale));
            bench.keep(&st);
        }
        best.pass(t0);
    }
    best.report("tablebase: probe (2B9F:BB76), recorded calls", calls.len, passes, over.ns);

    var loc: bench.Best = .{};
    for (0..passes) |_| {
        const t0 = bench.now();
        for (calls) |*c| {
            var st = c.st;
            bench.keep(tb.locate(&c.p, &st, c.side, c.ply));
            bench.keep(&st);
        }
        loc.pass(t0);
    }
    loc.report("tablebase: locate alone (no file looked up)", calls.len, passes, over.ns);

    // Only the calls that pass the signature test and so scan the board.
    var located: std.ArrayList(*const Call) = .empty;
    defer located.deinit(gpa);
    for (calls) |*c| if (tb.locate(&c.p, &c.st, c.side, c.ply) != null) try located.append(gpa, c);
    var loc2: bench.Best = .{};
    for (0..passes) |_| {
        const t0 = bench.now();
        for (located.items) |c| bench.keep(tb.locate(&c.p, &c.st, c.side, c.ply));
        loc2.pass(t0);
    }
    loc2.report("tablebase: locate, calls that build a name", located.items.len, passes, 0);

    // The same calls with the position already in cache, as it is in a search: each call
    // made 8 times in a row. The reference (the ten-scan locate) is timed alongside.
    const reps = 8;
    inline for (.{ .{ "tablebase: locate warm, this port", tb }, .{ "tablebase: locate warm, reference (before)", ref } }) |v| {
        var warm: bench.Best = .{};
        for (0..passes) |_| {
            const t0 = bench.now();
            for (located.items) |c| {
                const st: v[1].State = .{ .signature_count = c.st.signature_count, .signatures = c.st.signatures };
                for (0..reps) |_| bench.keep(v[1].locate(&c.p, &st, c.side, c.ply));
            }
            warm.pass(t0);
        }
        warm.report(v[0], reps * located.items.len, passes, 0);
    }
    inline for (.{ .{ "tablebase: probe warm, this port", tb, files }, .{ "tablebase: probe warm, reference (before)", ref, ref.Files{ .ctx = &tf, .lookupFn = refLookup } } }) |v| {
        var warm: bench.Best = .{};
        for (0..passes) |_| {
            const t0 = bench.now();
            for (calls) |*c| {
                var st: v[1].State = .{ .signature_count = c.st.signature_count, .signatures = c.st.signatures, .mode = c.st.mode, .program_side = c.st.program_side, .score_bound = c.st.score_bound, .score = c.st.score };
                for (0..reps) |_| bench.keep(v[1].probe(v[1].Fixes.original, &c.p, &st, v[2], c.side, c.ply, c.stale));
                bench.keep(&st);
            }
            warm.pass(t0);
        }
        warm.report(v[0], reps * calls.len, passes, 0);
    }
}

fn refLookup(ctx: ?*const anyopaque, loc: ref.Location, name: []const u8) ?[]const u8 {
    return TestFiles.lookup(ctx, if (loc == .program_tb) .program_tb else .second_dir, name);
}

// ---------------------------------------------------------------------------
// The one-scan `locate` against the ten-scan reference (src/tablebase_reference.zig) on
// generated positions
// ---------------------------------------------------------------------------

const ref = @import("tablebase_reference.zig");

/// Files for both the port and the reference: the program's TB folder serves the real
/// files, the second directory a 3,000-byte file under every name, so that indexes past
/// its end (the stale-byte path) are met too.
const DiffFiles = struct {
    real: *const TestFiles,
    short: []const u8,

    fn find(self: *const DiffFiles, program_tb: bool, name: []const u8) ?[]const u8 {
        if (!program_tb) return self.short;
        return TestFiles.lookup(self.real, .program_tb, name);
    }
    fn lookupNew(ctx: ?*const anyopaque, loc: tb.Location, name: []const u8) ?[]const u8 {
        const self: *const DiffFiles = @ptrCast(@alignCast(ctx.?));
        return self.find(loc == .program_tb, name);
    }
    fn lookupRef(ctx: ?*const anyopaque, loc: ref.Location, name: []const u8) ?[]const u8 {
        const self: *const DiffFiles = @ptrCast(@alignCast(ctx.?));
        return self.find(loc == .program_tb, name);
    }
};

const real_squares = blk: {
    var t: [64]u8 = undefined;
    for (0..64) |i| t[i] = 21 + 10 * (i / 8) + i % 8;
    break :blk t;
};

/// Takes a random square out of the first `n` of `f`.
fn takeSquare(r: std.Random, f: *[64]u8, n: *usize) u8 {
    const i = r.uintLessThan(usize, n.*);
    const v = f[i];
    n.* -= 1;
    f[i] = f[n.*];
    return v;
}

/// A position for the probe: two kings, up to four more men a side (four gives no
/// result), now and then stray bytes on empty squares and, with pawns on the board, men
/// on the border files; an en-passant byte that sometimes lies beside a pawn.
fn randomPosition(r: std.Random, p: *pos.Position) void {
    p.* = .{};
    for (&p.board, 0..) |*b, s| b.* = if (s < 21 or s > 98 or s % 10 == 0 or s % 10 == 9) pos.border else pos.empty;
    var free: [64]u8 = real_squares;
    var nfree: usize = 64;
    const wk = takeSquare(r, &free, &nfree);
    const bk = takeSquare(r, &free, &nfree);
    p.board[wk] = pos.white_king;
    p.board[bk] = pos.black_king;
    p.piece_list[7] = wk;
    p.piece_list[16 + 7] = bk;
    var pawns: u8 = 0;
    var pawn_sq: [8]u8 = undefined;
    for (0..2) |s| {
        const n: usize = switch (r.uintLessThan(u8, 16)) {
            0...2 => 0,
            3...7 => 1,
            8...11 => 2,
            12...14 => 3,
            else => 4,
        };
        for (0..n) |_| {
            const t: u8 = r.intRangeAtMost(u8, 1, 5);
            const sq = takeSquare(r, &free, &nfree);
            p.board[sq] = t + 7 * @as(u8, @intCast(s));
            if (t == 1) {
                pawn_sq[pawns] = sq;
                pawns += 1;
            }
        }
    }
    if (r.uintLessThan(u8, 8) == 0) {
        // Bytes the probe does not count: extra kings, the border code, others.
        const junk = [_]u8{ 6, 13, 7, 14, 15, 0x78, 0x80, 0xFF };
        for (0..r.intRangeAtMost(usize, 1, 3)) |_| p.board[takeSquare(r, &free, &nfree)] = junk[r.uintLessThan(usize, junk.len)];
    }
    if (pawns != 0 and r.uintLessThan(u8, 8) == 0) {
        // A man on a border file inside 21..98, which the scan also reads (with pawns
        // only: as the last man of a pawnless ending it would index past DG:237E).
        const edges = [_]u8{ 29, 30, 39, 40, 49, 50, 59, 60, 69, 70, 79, 80, 89, 90 };
        const t: u8 = r.intRangeAtMost(u8, 1, 5);
        p.board[edges[r.uintLessThan(usize, edges.len)]] = t + 7 * r.uintLessThan(u8, 2);
    }
    p.pawn_count = pawns;
    if (pawns == 0 and r.uintLessThan(u8, 10) == 0) p.pawn_count = r.intRangeAtMost(u8, 1, 255);
    p.ep_square_by_ply[2] = switch (r.uintLessThan(u8, 10)) {
        0...4 => 0,
        5...7 => if (pawns != 0) blk: {
            const ps = pawn_sq[r.uintLessThan(usize, pawns)];
            break :blk if (r.boolean()) ps -% 10 else ps +% 10;
        } else 0,
        else => r.int(u8),
    };
    const mats = [_]u16{ 0, 650, 700, 1100, 2000, 2650, 3100 };
    p.side_pawn_count = .{ r.uintLessThan(u8, 3), r.uintLessThan(u8, 3) };
    p.piece_material = .{ mats[r.uintLessThan(usize, mats.len)], mats[r.uintLessThan(usize, mats.len)] };
    if (r.uintLessThan(u8, 8) == 0) p.piece_material = .{ r.int(u16), r.int(u16) };
}

test "tablebase: the one-scan locate and the probe equal the reference on 1,000,000 generated positions" {
    const gpa = std.testing.allocator;
    var tf = try loadFiles(gpa);
    defer tf.deinit(gpa);
    var short: [3000]u8 = undefined;
    for (&short, 0..) |*b, i| b.* = @truncate(i *% 37 +% 11);
    const df: DiffFiles = .{ .real = &tf, .short = &short };
    const files_new: tb.Files = .{ .ctx = &df, .lookupFn = DiffFiles.lookupNew };
    const files_ref: ref.Files = .{ .ctx = &df, .lookupFn = DiffFiles.lookupRef };
    const run_sigs = [_]u16{ 0x4000, 0x1F00, 0x1100, 0x40, 0x1F, 0x11 };

    var prng = std.Random.DefaultPrng.init(0x7AB1EBA5E);
    const r = prng.random();
    var p: pos.Position = .{};
    var located: usize = 0;
    var too_many: usize = 0;
    var pawnless: usize = 0;
    var first_black: usize = 0;
    var returned: usize = 0;
    const cases = 1_000_000;
    for (0..cases) |case| {
        randomPosition(r, &p);
        const side: u1 = @intCast(r.uintLessThan(u8, 2));
        const ply: u16 = if (r.boolean()) 0 else r.int(u16);
        const nsig: i16 = switch (r.uintLessThan(u8, 4)) {
            0 => -1,
            1 => 0,
            2 => 6,
            else => r.intRangeAtMost(i16, 0, 6),
        };
        const st_new: tb.State = .{
            .signature_count = nsig,
            .signatures = &run_sigs,
            .mode = r.int(u8),
            .program_side = if (r.uintLessThan(u8, 8) == 0) r.int(u8) else r.uintLessThan(u8, 2),
            .score_bound = r.int(i16),
            .score = r.int(i16),
        };
        const st_ref: ref.State = .{
            .signature_count = st_new.signature_count,
            .signatures = st_new.signatures,
            .mode = st_new.mode,
            .program_side = st_new.program_side,
            .score_bound = st_new.score_bound,
            .score = st_new.score,
        };
        const stale = r.int(u8);

        const a = tb.locate(&p, &st_new, side, ply);
        const b = ref.locate(&p, &st_ref, side, ply);
        if ((a == null) != (b == null)) {
            std.debug.print("case {d}: locate null {any}, reference null {any}\n", .{ case, a == null, b == null });
            return error.TestUnexpectedResult;
        }
        if (a) |x| {
            const y = b.?;
            located += 1;
            pawnless += @intFromBool(p.pawn_count == 0);
            first_black += @intFromBool(x.first_black);
            const same = x.first_black == y.first_black and x.men == y.men and
                std.mem.eql(u8, &x.counts, &y.counts) and std.mem.eql(u8, x.name(), y.name()) and
                std.mem.eql(u16, x.entries[0..x.men], y.entries[0..y.men]) and x.index == y.index;
            if (!same) {
                std.debug.print("case {d}: locate {s} {any} {d}, reference {s} {any} {d}\n", .{ case, x.name(), x.entries[0..x.men], x.index, y.name(), y.entries[0..y.men], y.index });
                return error.TestUnexpectedResult;
            }
        } else if (ply == 0 or nsig < 0) too_many += 1;

        inline for (.{ .{ tb.Fixes.original, ref.Fixes.original }, .{ tb.Fixes.corrected, ref.Fixes.corrected } }) |fx| {
            var s1 = st_new;
            var s2 = st_ref;
            const g1 = tb.probe(fx[0], &p, &s1, files_new, side, ply, stale);
            const g2 = ref.probe(fx[1], &p, &s2, files_ref, side, ply, stale);
            if (g1 != g2 or s1.score != s2.score) {
                std.debug.print("case {d}: probe {any} score {d}, reference {any} score {d}\n", .{ case, g1, s1.score, g2, s2.score });
                return error.TestUnexpectedResult;
            }
            returned += @intFromBool(g1);
        }
    }
    std.debug.print("tablebase locate vs reference: {d} positions, {d} located ({d} pawnless, {d} Black named first), {d} with too many men, {d} probes gave a score; all equal\n", .{ cases, located, pawnless, first_black, too_many, returned });
    try std.testing.expect(located > cases / 4 and too_many > 1000 and pawnless > 1000 and returned > 1000);
}

/// A supplier that counts the files asked for.
const CountingFiles = struct {
    asked: usize = 0,
    data: [1]u8 = .{3},
    fn lookup(ctx: ?*const anyopaque, loc: tb.Location, name: []const u8) ?[]const u8 {
        _ = loc;
        _ = name;
        const self: *CountingFiles = @ptrCast(@alignCast(@constCast(ctx.?)));
        self.asked += 1;
        return &self.data;
    }
};

test "DEV-029: at ply 0 a side with more than four men gives no result and no file is read" {
    // The original (2B9F:BB76) has no men-count test at ply 0 (the signature test that
    // limits the men is made only at ply != 0): a fifth man on a side overruns its 8-byte
    // lists and the multiplier array (an overrun, class A). Every caller requires five
    // men or fewer in all, so it cannot run; the port gives no result.
    var p = kqkPosition();
    p.board[21] = pos.white_rook; // a1
    p.board[28] = pos.white_rook; // h1
    p.board[23] = pos.white_bishop; // c1: the king and four men
    var cf: CountingFiles = .{};
    const files: tb.Files = .{ .ctx = &cf, .lookupFn = CountingFiles.lookup };
    try std.testing.expect(tb.locate(&p, &tb.State{}, 0, 0) == null);
    var st: tb.State = .{ .mode = 0x0A, .program_side = 1, .score = 1234 };
    inline for (.{ tb.Fixes.original, tb.Fixes.corrected }) |fx| {
        try std.testing.expect(!tb.probe(fx, &p, &st, files, 0, 0, 5));
        try std.testing.expect(!tb.probe(fx, &p, &st, files, 1, 0, 5));
    }
    try std.testing.expectEqual(@as(i16, 1234), st.score);
    try std.testing.expectEqual(@as(usize, 0), cf.asked);
    // The same men for Black.
    var q: pos.Position = .{};
    for (&q.board, 0..) |*b, s| b.* = if (s % 10 == 0 or s % 10 == 9 or s < 21 or s > 98) pos.border else pos.empty;
    q.board[25] = pos.white_king;
    q.board[95] = pos.black_king;
    for ([_]u8{ 91, 92, 93, 94 }) |s| q.board[s] = pos.black_rook;
    try std.testing.expect(tb.locate(&q, &tb.State{}, 1, 0) == null);
    // Four men on a side (the king and three) are located: the boundary.
    p.board[23] = pos.empty;
    try std.testing.expect(tb.locate(&p, &tb.State{}, 0, 0) != null);
}
