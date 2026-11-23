//! The tablebase probe (src/tablebase.zig) with four men: the direct calls of the original
//! in tests/golden/tablebase/probe4.zst (tools/research/tablebase/gen_tb4_vectors.py, the
//! original run with the "cd" tablebase set: the six shipped files and 60 of
//! reference/tablebases/m80-cd), replayed with the files of the engine's own cd set
//! (src/tb_store.zig: the shipped six embedded, the 60 decompressed from
//! reference/extracted/tablebases). The format is that of probe.zst
//! (tools/port/gen_tablebase_vectors.py); the replay is src/tablebase_test.zig's, with room
//! for the 62 signatures of the cd set.

const std = @import("std");
const pos = @import("position.zig");
const tb = @import("tablebase.zig");
const tb_store = @import("tb_store.zig");

const golden_dir = @import("build_options").golden_dir;

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

const set_names = [_][]const u8{ "probe.py seed 5", "probe.py seed 6", "probe.py seed 7", "wide", "seed 1 negative index", "seed 2 negative index", "seed 3 negative index", "four-man" };

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
    var sig_buf: [0x50]u16 = undefined;
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

test "tablebase probe: the 20,000 four-man calls of probe4.zst (the original with the cd set) replayed with the engine's cd files" {
    const gpa = std.testing.allocator;
    var store = tb_store.TbStore.init(gpa, .cd);
    defer store.deinit();
    var stats: Stats = .{};
    try replay(gpa, store.files(), "probe4.zst", &stats);
    std.debug.print(
        "tablebase probe4: {d} calls replayed, all equal to the original: {d} returned 1; {d} failed the signature test; {d} at ply 0; {d} read a byte, {d} past the end; {d} no file; {d} Black first; {d} with pawns; {d} files decompressed\n",
        .{ stats.calls, stats.returned_1, stats.no_signature, stats.ply0, stats.byte_read, stats.past_end, stats.no_file, stats.black_first, stats.pawns, store.loads },
    );
    try std.testing.expectEqual(@as(usize, 20_000), stats.calls);
    try std.testing.expectEqual(@as(usize, 20_000), stats.per_set[7]);
}
