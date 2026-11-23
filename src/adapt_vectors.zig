//! Test support for the Stage A replays (src/adapt_*_test.zig): reading a recorded
//! vector file, and a record image whose regions lie at known DGROUP addresses.
//!
//! The vector tools (tools/port/gen_*_vectors.py) record a call's state as a "record
//! image": the regions the routine reads or writes, one after another. A Stage A replay
//! keeps the state in a whole DGROUP image instead (`dgroup.Image`): `Regions` maps each
//! record offset to its DGROUP address, so that a recorded change can be applied to the
//! DGROUP image, and the DGROUP image can be read back as a record image and compared
//! with the recording.

const std = @import("std");
const dgroup = @import("dgroup.zig");

pub fn readVectors(gpa: std.mem.Allocator, sub: []const u8, name: []const u8) ![]u8 {
    var path_buf: [256]u8 = undefined;
    const dir = @import("build_options").golden_dir;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/{s}/{s}", .{ dir, sub, name });
    const compressed = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, gpa, .limited(64 << 20));
    defer gpa.free(compressed);
    var in: std.Io.Reader = .fixed(compressed);
    const window = try gpa.alloc(u8, std.compress.zstd.default_window_len + std.compress.zstd.block_size_max);
    defer gpa.free(window);
    var zd = std.compress.zstd.Decompress.init(&in, window, .{});
    return zd.reader.allocRemaining(gpa, .limited(512 << 20));
}

pub const Cursor = struct {
    d: []const u8,
    i: usize = 0,

    pub fn byte(c: *Cursor) u8 {
        const v = c.d[c.i];
        c.i += 1;
        return v;
    }
    pub fn int(c: *Cursor, comptime T: type) T {
        const n = @sizeOf(T);
        const v = std.mem.readInt(T, c.d[c.i..][0..n], .little);
        c.i += n;
        return v;
    }
    pub fn take(c: *Cursor, n: usize) []const u8 {
        const v = c.d[c.i..][0..n];
        c.i += n;
        return v;
    }
    pub fn varint(c: *Cursor) usize {
        var n: usize = 0;
        var shift: std.math.Log2Int(usize) = 0;
        while (true) {
            const b = c.byte();
            n |= @as(usize, b & 0x7F) << shift;
            if (b & 0x80 == 0) return n;
            shift += 7;
        }
    }
    /// Apply a change list (count, then per change: gap varint, XOR byte) to the record
    /// image `rec`, and, when `regions` and `img` are given, the same bytes to the DGROUP
    /// image. Returns whether anything changed.
    pub fn apply(c: *Cursor, rec: []u8, regions: ?*const Regions, img: ?*dgroup.Image) bool {
        const n = c.varint();
        var prev: isize = -1;
        for (0..n) |_| {
            const off: usize = @intCast(prev + 1 + @as(isize, @intCast(c.varint())));
            rec[off] ^= c.byte();
            if (regions) |r| img.?[r.addr[off]] = rec[off];
            prev = @intCast(off);
        }
        return n != 0;
    }
};

/// A record image's layout: the DGROUP address of every record offset.
pub const Regions = struct {
    pub const Region = struct { name: []const u8, dg: u16, len: usize };
    addr: []u16,
    list: []const Region,

    pub fn init(gpa: std.mem.Allocator, list: []const Region) !Regions {
        var n: usize = 0;
        for (list) |r| n += r.len;
        const addr = try gpa.alloc(u16, n);
        var o: usize = 0;
        for (list) |r| {
            for (0..r.len) |i| addr[o + i] = @intCast(r.dg + i);
            o += r.len;
        }
        return .{ .addr = addr, .list = list };
    }
    pub fn deinit(r: *Regions, gpa: std.mem.Allocator) void {
        gpa.free(r.addr);
    }
    pub fn len(r: *const Regions) usize {
        return r.addr.len;
    }
    /// Put a record image into the DGROUP image.
    pub fn scatter(r: *const Regions, rec: []const u8, img: *dgroup.Image) void {
        for (r.addr, rec) |a, b| img[a] = b;
    }
    /// Read the DGROUP image as a record image.
    pub fn gather(r: *const Regions, img: *const dgroup.Image, rec: []u8) void {
        for (r.addr, rec) |a, *b| b.* = img[a];
    }
    /// Region name and index of record offset `off`.
    pub fn describe(r: *const Regions, buf: []u8, off: usize) []const u8 {
        var o: usize = 0;
        for (r.list) |g| {
            if (off < o + g.len) return std.fmt.bufPrint(buf, "{s}+{d} (DG:{X:0>4})", .{ g.name, off - o, g.dg + off - o }) catch g.name;
            o += g.len;
        }
        return "?";
    }
};

/// Fails, printing the first differing byte, when `got` and `want` differ.
pub fn expectRecord(regions: *const Regions, want: []const u8, got: []const u8, comptime fmt: []const u8, args: anytype) !void {
    if (std.mem.eql(u8, want, got)) return;
    std.debug.print("\n" ++ fmt ++ "\n", args);
    var buf: [96]u8 = undefined;
    for (want, got, 0..) |w, h, off| {
        if (w != h) {
            std.debug.print("  first differing byte: {s}: want {X:0>2}, got {X:0>2}\n", .{ regions.describe(&buf, off), w, h });
            break;
        }
    }
    return error.MismatchWithOriginal;
}
