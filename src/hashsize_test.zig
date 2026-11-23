//! Differential test of src/hashsize.zig against the original's hash sizing, recorded over a
//! grid of XMS memory sizes, sizes typed into Settings / Hash-tables, and levels
//! (tests/golden/hashsize/vectors.txt, made by tools/research/hashsize/grid.py and
//! check.py --vectors, whose header lines give the format).
//!
//!   S  one start-up: hash_setup (0000:7180) from the memory the XMS driver offered
//!   R  one call of hash_resize (0000:6C3A) from its recorded inputs; for a call from main,
//!      also main's request from the level, the previous base and the total
//!   M  one Settings / Hash-tables entry: the total left
//!
//! On a mismatch the test names the line and the first field that differs.

const std = @import("std");
const hs = @import("hashsize.zig");

const golden_dir = @import("build_options").golden_dir;

fn fail(line_no: usize, line: []const u8, field: []const u8, got: i64, want: i64) error{DiffersFromOriginal} {
    std.debug.print("hashsize vectors line {d} ({s}): {s} = {d}, the original {d}\n", .{ line_no, line, field, got, want });
    return error.DiffersFromOriginal;
}

fn check(line_no: usize, line: []const u8, field: []const u8, got: i64, want: i64) !void {
    if (got != want) return fail(line_no, line, field, got, want);
}

test "hashsize: recorded grid" {
    const gpa = std.testing.allocator;
    const path = golden_dir ++ "/hashsize/vectors.txt";
    const text = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, gpa, .limited(4 << 20));
    defer gpa.free(text);
    var counts = [3]usize{ 0, 0, 0 };
    var run: hs.Setup = .{};
    var run_xms: i64 = -1;
    var lines = std.mem.splitScalar(u8, text, '\n');
    var line_no: usize = 0;
    while (lines.next()) |raw| {
        line_no += 1;
        const line = std.mem.trimEnd(u8, raw, "\r");
        if (line.len == 0 or line[0] == '#') continue;
        var tok = std.mem.tokenizeScalar(u8, line, ' ');
        const kind = tok.next().?;
        var v: [16]i64 = undefined;
        var n: usize = 0;
        while (tok.next()) |t| : (n += 1) v[n] = try std.fmt.parseInt(i64, t, 10);
        switch (kind[0]) {
            'S' => {
                const s = hs.setup(if (v[0] == 0) null else @intCast(@min(v[0], 0xFFFF)));
                try check(line_no, line, "size", s.tables.size_kb, v[1]);
                try check(line_no, line, "total", s.total_kb, v[2]);
                try check(line_no, line, "mask", s.tables.mask, v[3]);
                try check(line_no, line, "mode", s.tables.mode, v[4]);
                try check(line_no, line, "enabled", s.tables.enabled, v[5]);
                try check(line_no, line, "avail", s.mem.avail_kb, v[6]);
                try check(line_no, line, "block", s.block_kb, v[7]);
                run = s;
                run_xms = v[0];
                counts[0] += 1;
            },
            'R' => {
                const caller = v[0];
                if (caller == 0) {
                    try check(line_no, line, "requested", hs.mainRequest(@intCast(v[1]), @intCast(v[2]), @intCast(v[3])), v[4]);
                }
                const mem: hs.Memory = .{ .avail_kb = @intCast(v[5]), .conv = @intCast(v[6]), .xms_ready = v[7] != 0 };
                const t = hs.resize(@intCast(v[4]), mem, .{});
                try check(line_no, line, "ax", t.enabled, v[8]);
                try check(line_no, line, "size", t.size_kb, v[9]);
                if (mem.xms_ready) {
                    try check(line_no, line, "mask", t.mask, v[10]);
                    try check(line_no, line, "table_bytes", t.table_bytes, v[13]);
                }
                try check(line_no, line, "mode", t.mode, v[11]);
                try check(line_no, line, "enabled", t.enabled, v[12]);
                if (caller == 0) {
                    // The same search from the run's own state: start-up, menu entries and
                    // earlier searches, as the engine would carry them.
                    try check(line_no, line, "run total", run.total_kb, v[3]);
                    const cleared = hs.beforeSearch(&run, @intCast(v[1]), @intCast(v[2]));
                    try check(line_no, line, "run cleared", @intFromBool(cleared), @intFromBool(v[8] != 0));
                    try check(line_no, line, "run size", run.tables.size_kb, v[9]);
                    try check(line_no, line, "run mask", run.tables.mask, v[10]);
                    try check(line_no, line, "run mode", run.tables.mode, v[11]);
                }
                counts[1] += 1;
            },
            'M' => {
                // The run's state after its start-up and earlier menu entries.
                try check(line_no, line, "xms", run_xms, v[0]);
                const cleared = hs.menu(&run, @intCast(v[1]));
                try check(line_no, line, "cleared", @intFromBool(cleared), @intFromBool(v[2] != 0));
                try check(line_no, line, "total", run.total_kb, v[3]);
                counts[2] += 1;
            },
            else => return error.BadVectorLine,
        }
    }
    try std.testing.expect(counts[0] > 0 and counts[1] > 0 and counts[2] > 0);
}

test "hashsize: a timed level asks for 320 KB only below a base of 91 ticks" {
    try std.testing.expectEqual(@as(i32, 320), hs.mainRequest(1, 90, 61440));
    try std.testing.expectEqual(@as(i32, 61440), hs.mainRequest(1, 91, 61440));
    try std.testing.expectEqual(@as(i32, 61440), hs.mainRequest(3, 0, 61440));
    try std.testing.expectEqual(@as(i32, 320), hs.mainRequest(0, -5, 321));
    try std.testing.expectEqual(@as(i32, 320), hs.mainRequest(1, 0, 320));
    var s = hs.setup(64512);
    try std.testing.expect(hs.beforeSearch(&s, 1, 0));
    try std.testing.expectEqual(@as(i32, 160), s.tables.size_kb);
    try std.testing.expectEqual(@as(u32, 0x3FFF), s.tables.mask);
    try std.testing.expect(hs.unclearedTail(s.tables.table_bytes, s.block_kb) == null);
}

test "hashsize: no driver, or under 80 KB, gives no tables" {
    var s = hs.setup(null);
    try std.testing.expect(!hs.beforeSearch(&s, 3, 0));
    try std.testing.expectEqual(@as(u32, 0), s.tables.mask);
    s = hs.setup(79);
    try std.testing.expect(!hs.beforeSearch(&s, 3, 0));
    s = hs.setup(80);
    try std.testing.expect(hs.beforeSearch(&s, 3, 0));
    try std.testing.expectEqual(@as(i32, 40), s.tables.size_kb);
    try std.testing.expectEqual(@as(u32, 4096), hs.slots(s.tables));
}
