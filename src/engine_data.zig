//! The original's data files the engine needs, embedded in the executable by the build
//! (build.zig) from the pinned reference files and never retyped (AGENTS.md §7, step 3.1),
//! so that the engine needs no reference folder at run time (DEV-F: embedded files).
//!
//! - The six tablebase files of the shipped `TB` folder (reference/original/M80/TB), which
//!   the original finds at start-up (tb_scan_files 2B9F:C158) and opens by name in its
//!   probe (2B9F:BB76) as `<program>\TB\<name>` (docs/arch/41-tablebases.md).
//! - The opening book: `PRBOOK\M80KEY.000`-`.00F` (the index) and `PRBOOK\PRBOOK.M80` (the
//!   move lists), which book_probe (4793:621E) opens (docs/arch/40-opening-book.md).

const std = @import("std");
const tablebase = @import("tablebase.zig");
const book = @import("book.zig");

/// The tablebase files: name as the probe forms it, and contents.
pub const tb_names = [_][]const u8{ "KPK.TBW", "KPK.TBB", "KQK.TBW", "KQK.TBB", "KRK.TBW", "KRK.TBB" };
pub const tb_data = [tb_names.len][]const u8{
    @embedFile("tb/KPK.TBW"),
    @embedFile("tb/KPK.TBB"),
    @embedFile("tb/KQK.TBW"),
    @embedFile("tb/KQK.TBB"),
    @embedFile("tb/KRK.TBW"),
    @embedFile("tb/KRK.TBB"),
};

/// The probe's file lookup over the embedded files: the program's `TB` folder holds the
/// six shipped files; the additional path (`5A7B:5038`, empty by default) holds nothing.
/// Names compare without regard to case, as DOS opens them.
fn lookup(ctx: ?*const anyopaque, loc: tablebase.Location, name: []const u8) ?[]const u8 {
    _ = ctx;
    if (loc != .program_tb) return null;
    for (tb_names, 0..) |n, i| if (std.ascii.eqlIgnoreCase(n, name)) return tb_data[i];
    return null;
}

/// The files of the shipped `TB` folder, for `EngineRoot.tb_files`.
pub const tb_files: tablebase.Files = .{ .ctx = null, .lookupFn = lookup };

/// SHA-256 of the reference files the build embeds (reference/CHECKSUMS.txt).
pub const tb_sha256 = [tb_names.len][]const u8{
    "401ef69b10d6317604caa7ff856a6bcf1fb643cdb69153e0f57737e4605ce155",
    "57e218abc725aa0d1ec269d037d7ba73a07feb22f47843931421e499e18817c0",
    "e18dea9ed2364f010087e411a6d5d524467b4365b152aa1c3fee727e0c0536e2",
    "3bca4cb9cc9d33476593d78707bae4bdec3d826053ba816af485fca7d11528f3",
    "77be55427217e3b08386e75cc112d068e2ac5aee4caf3aaac440182a9b8d18d7",
    "605214dd3b5a04368331c7a726ca5351a0e4aafef80e6309cb0ddbf50ecc8056",
};

/// The hash recorded for `path` in reference/CHECKSUMS.txt (lines `<hex> *<path>`).
fn checksumOf(sums: []const u8, path: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, sums, '\n');
    while (lines.next()) |raw| {
        const l = std.mem.trimEnd(u8, raw, "\r");
        if (l.len < 66 or l[64] != ' ') continue;
        const p = if (l[65] == '*') l[66..] else l[65..];
        if (std.mem.eql(u8, p, path)) return l[0..64];
    }
    return null;
}

test "engine data: every embedded tablebase file hashes to its entry in reference/CHECKSUMS.txt" {
    const gpa = std.testing.allocator;
    var buf: [256]u8 = undefined;
    const sums_path = try std.fmt.bufPrint(&buf, "{s}/../../reference/CHECKSUMS.txt", .{@import("build_options").golden_dir});
    const sums = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, sums_path, gpa, .limited(1 << 20));
    defer gpa.free(sums);
    for (tb_names, tb_data, tb_sha256) |n, d, want| {
        var path_buf: [64]u8 = undefined;
        const listed = checksumOf(sums, try std.fmt.bufPrint(&path_buf, "original/M80/TB/{s}", .{n})) orelse return error.NotInChecksums;
        try std.testing.expectEqualStrings(want, listed);
        var h: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(d, &h, .{});
        const hex = std.fmt.bytesToHex(h, .lower);
        try std.testing.expectEqualStrings(listed, &hex);
    }
    // The lookup: the program's folder only, any case.
    try std.testing.expect(tb_files.lookup(.program_tb, "krk.tbw").?.ptr == tb_data[4].ptr);
    try std.testing.expect(tb_files.lookup(.program_tb, "KBK.TBW") == null);
}

/// The opening book's files (reference/original/M80/PRBOOK).
pub const book_files: book.Files = .{
    .index = .{
        @embedFile("book/M80KEY.000"), @embedFile("book/M80KEY.001"), @embedFile("book/M80KEY.002"), @embedFile("book/M80KEY.003"),
        @embedFile("book/M80KEY.004"), @embedFile("book/M80KEY.005"), @embedFile("book/M80KEY.006"), @embedFile("book/M80KEY.007"),
        @embedFile("book/M80KEY.008"), @embedFile("book/M80KEY.009"), @embedFile("book/M80KEY.00A"), @embedFile("book/M80KEY.00B"),
        @embedFile("book/M80KEY.00C"), @embedFile("book/M80KEY.00D"), @embedFile("book/M80KEY.00E"), @embedFile("book/M80KEY.00F"),
    },
    .moves = @embedFile("book/PRBOOK.M80"),
};

test "engine data: every embedded book file hashes to its entry in reference/CHECKSUMS.txt" {
    const gpa = std.testing.allocator;
    var buf: [256]u8 = undefined;
    const sums_path = try std.fmt.bufPrint(&buf, "{s}/../../reference/CHECKSUMS.txt", .{@import("build_options").golden_dir});
    const sums = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, sums_path, gpa, .limited(1 << 20));
    defer gpa.free(sums);
    var path_buf: [64]u8 = undefined;
    for (book_files.index, 0..) |d, i| {
        const listed = checksumOf(sums, try std.fmt.bufPrint(&path_buf, "original/M80/PRBOOK/M80KEY.{X:0>3}", .{i})) orelse return error.NotInChecksums;
        var h: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(d, &h, .{});
        try std.testing.expectEqualStrings(listed, &std.fmt.bytesToHex(h, .lower));
    }
    const listed = checksumOf(sums, "original/M80/PRBOOK/PRBOOK.M80") orelse return error.NotInChecksums;
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(book_files.moves, &h, .{});
    try std.testing.expectEqualStrings(listed, &std.fmt.bytesToHex(h, .lower));
}
