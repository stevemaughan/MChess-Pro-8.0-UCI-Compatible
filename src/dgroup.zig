//! The original's data segment, DGROUP (segment 61E4), as the definition of every
//! variable's address. In Stage A of the assembly (docs/arch/60-engine-assembly.md, section
//! 4.3) a 64 KB image of it was the single store of engine state; since Stage B step 8,
//! stage 8, the engine holds no image: its state is its members (src/engine_state.zig
//! `Members`, the node's `searchnode.State`, the game record), each byte at one home. What
//! is left here, and why:
//!
//! - `Image` and `initial`: DGROUP laid out as the original lays it out, and its contents as
//!   the program is loaded (the executable's initialised data, DG:0000-31FF, then zeros, as
//!   the C start-up code leaves the uninitialised data and the stack). The engine decodes
//!   `initial` into its members once, at start-up (`engine_state` `decodeFrom`): the one
//!   image the engine reads. The tests load the engine from the oracle's images and compare
//!   it with them (src/state_image.zig, the tests' codec).
//! - `Map(T, entries)`: a struct bound to its field map, generated from the `DG:` comments
//!   by `tools/port/state_inventory.py` (src/dgroup_maps.zig), which moves the struct's
//!   fields between an image and the struct: `load` fills the struct from the image;
//!   `snapshot` gives the bytes as the struct sees them; `storeChanged` writes back only
//!   the bytes that differ from a snapshot. The maps define every member's addresses: the
//!   holding rule (`engine_state.Layout`), the start-up decode, the checkpoints' restore
//!   (`restoreMembers`) and the tests' codec read them, and src/dgroup_test.zig proves them.
//!   The replay tests and the Stage A adapters (src/adapt_*.zig, test-only since stage 8)
//!   load a unit's structs from an image the same way.
//! - `ImageMem` and the `mem*` helpers: DGROUP (or the far segment) by address on a store
//!   of the caller's choosing, for the routines that address the original's variables:
//!   the engine's homes in the engine (src/engine_root.zig `EngineRoot.Home`, `RecordHome`), an
//!   image in the tests.
//!
//! Each element is held in the image in the original's width, little-endian: an
//! integer of N bits in ceil(N/8) bytes (`u48` keys in 6, a `u1` side in 1), a `bool` in
//! one byte, an extern struct (`Move`) as its bytes, an enum as its backing integer.
//! Narrow types lose information on the way in (a `u1` keeps bit 0 of the byte, a `bool`
//! reads any non-zero byte as 1); because only changed bytes are written back, such a
//! byte is rewritten only when the unit changes the value.

const std = @import("std");
const original = @import("original.zig");
pub const maps = @import("dgroup_maps.zig");
pub const Entry = maps.Entry;

pub const size = 0x10000;
pub const Image = [size]u8;

const exe = @embedFile("mcp8_exe");

const file_offset: usize = blk: {
    const header_paragraphs = std.mem.readInt(u16, exe[8..10], .little);
    break :blk @as(usize, header_paragraphs) * 16 + original.dgroup_segment * 16;
};

/// Bytes of DGROUP the executable file holds (DG:0000 up to the end of the file).
pub const initialised_len: usize = @min(size, exe.len - file_offset);

/// The image as the program is loaded: the executable's initialised data, then zeros.
pub const initial: Image = blk: {
    @setEvalBranchQuota(10_000);
    var img: Image = @splat(0);
    @memcpy(img[0..initialised_len], exe[file_offset..][0..initialised_len]);
    break :blk img;
};

/// A fresh image, as `initial`.
pub fn init(img: *Image) void {
    img.* = initial;
}

// ---------------------------------------------------------------------------
// By address, at a store of the routine's choosing
// ---------------------------------------------------------------------------

/// DGROUP (or the far segment 5A7B) by address on an image. The routines that address the
/// original's variables by address (src/newgame.zig, src/gameslide.zig, src/adapt_setup.zig,
/// the hash dialog) take any store `m` with `get(m, a) u8` and `set(m, a, v)`: this one in
/// their tests, the engine's homes in the engine (src/engine_root.zig `EngineRoot.Home`: each byte
/// at the member that holds it; `EngineRoot.RecordHome`: the far segment at the game record's
/// fields). The helpers below build words from bytes, little-endian, as the original
/// stores them.
pub const ImageMem = struct {
    img: *[size]u8,
    pub fn get(m: ImageMem, a: u16) u8 {
        return m.img[a];
    }
    pub fn set(m: ImageMem, a: u16, v: u8) void {
        m.img[a] = v;
    }
};

pub fn memWord(m: anytype, a: u16) u16 {
    return @as(u16, m.get(a)) | @as(u16, m.get(a +% 1)) << 8;
}
pub fn memSetWord(m: anytype, a: u16, v: u16) void {
    m.set(a, @truncate(v));
    m.set(a +% 1, @truncate(v >> 8));
}
pub fn memDword(m: anytype, a: u16) u32 {
    return @as(u32, memWord(m, a)) | @as(u32, memWord(m, a +% 2)) << 16;
}
pub fn memSetDword(m: anytype, a: u16, v: u32) void {
    memSetWord(m, a, @truncate(v));
    memSetWord(m, a +% 2, @truncate(v >> 16));
}
/// `n` bytes from `a` set to `v` (a memset).
pub fn memFill(m: anytype, a: u16, n: usize, v: u8) void {
    for (0..n) |k| m.set(@intCast(a + k), v);
}
/// `n` bytes from `src` to `dst` in ascending order (a memcpy of two runs that do not
/// overlap, as every caller's are).
pub fn memCopy(m: anytype, dst: u16, src: u16, n: usize) void {
    for (0..n) |k| m.set(@intCast(dst + k), m.get(@intCast(src + k)));
}

// ---------------------------------------------------------------------------
// Elements
// ---------------------------------------------------------------------------

/// The element type of `F` with every array dimension removed.
pub fn Flat(comptime F: type) type {
    return switch (@typeInfo(F)) {
        .array => |a| Flat(a.child),
        else => F,
    };
}

/// Number of elements of `F` flattened.
pub fn flatLen(comptime F: type) usize {
    return switch (@typeInfo(F)) {
        .array => |a| a.len * flatLen(a.child),
        else => 1,
    };
}

/// The original's size of one element, in bytes.
pub fn elemSize(comptime E: type) usize {
    return switch (@typeInfo(E)) {
        .int => |i| (i.bits + 7) / 8,
        .bool => 1,
        .@"enum" => |e| elemSize(e.tag_type),
        .@"struct" => |s| if (s.layout == .@"extern") @sizeOf(E) else @compileError("dgroup: a non-extern struct element: " ++ @typeName(E)),
        else => @compileError("dgroup: unsupported element type " ++ @typeName(E)),
    };
}

fn decodeInt(comptime I: type, b: []const u8) I {
    const n = comptime elemSize(I);
    const U = @Int(.unsigned, n * 8);
    const raw = std.mem.readInt(U, b[0..n], .little);
    const UI = @Int(.unsigned, @bitSizeOf(I));
    const v: UI = @truncate(raw);
    return @bitCast(v);
}

fn encodeInt(comptime I: type, x: I, b: []u8) void {
    const n = comptime elemSize(I);
    const U = @Int(.unsigned, n * 8);
    const UI = @Int(.unsigned, @bitSizeOf(I));
    const v: UI = @bitCast(x);
    std.mem.writeInt(U, b[0..n], v, .little);
}

/// One element from its bytes in the image.
pub fn decode(comptime E: type, b: []const u8) E {
    return switch (@typeInfo(E)) {
        .int => decodeInt(E, b),
        .bool => b[0] != 0,
        .@"enum" => |e| @fromBackingInt(decodeInt(e.tag_type, b)),
        .@"struct" => std.mem.bytesToValue(E, b[0..@sizeOf(E)]),
        else => @compileError("dgroup: unsupported element type " ++ @typeName(E)),
    };
}

/// One element's bytes in the image.
pub fn encode(comptime E: type, x: E, b: []u8) void {
    switch (@typeInfo(E)) {
        .int => encodeInt(E, x, b),
        .bool => b[0] = @intFromBool(x),
        .@"enum" => |e| encodeInt(e.tag_type, @backingInt(x), b),
        .@"struct" => @memcpy(b[0..@sizeOf(E)], std.mem.asBytes(&x)),
        else => @compileError("dgroup: unsupported element type " ++ @typeName(E)),
    }
}

// ---------------------------------------------------------------------------
// Field maps
// ---------------------------------------------------------------------------

/// Bytes an entry covers in the image, clipped at the end of the segment.
pub fn entryBytes(comptime e: Entry) usize {
    return @min(e.count * e.esize, size - @as(usize, e.addr));
}

/// `T` bound to its field map. Checks at compile time that every field exists, that its
/// element has the size the map gives, and that the entry lies inside the field.
pub fn Map(comptime T: type, comptime entries: []const Entry) type {
    comptime {
        for (entries) |e| {
            if (!@hasField(T, e.field)) @compileError("dgroup: " ++ @typeName(T) ++ " has no field " ++ e.field);
            const F = @FieldType(T, e.field);
            if (elemSize(Flat(F)) != e.esize) @compileError("dgroup: element size of " ++ @typeName(T) ++ "." ++ e.field ++ " differs from the map");
            if (e.first + e.count > flatLen(F)) @compileError("dgroup: map entry beyond " ++ @typeName(T) ++ "." ++ e.field);
        }
    }
    return struct {
        pub const Struct = T;
        pub const map = entries;

        /// Bytes of all entries, in map order.
        pub const snapshot_len: usize = blk: {
            var n: usize = 0;
            for (entries) |e| n += entryBytes(e);
            break :blk n;
        };
        /// The struct's fields as image bytes, entry after entry.
        pub const Snapshot = [snapshot_len]u8;

        fn elems(comptime e: Entry, s: anytype) [*]Flat(@FieldType(T, e.field)) {
            return @ptrCast(&@field(s, e.field));
        }

        /// An entry whose elements are held in memory exactly as the image holds them
        /// (an integer of a whole number of bytes, or an extern struct, with no padding):
        /// `encode` and `decode` of each element are then a copy of its bytes, and the
        /// entry is moved with one `@memcpy` (the result is the same bytes).
        fn plain(comptime e: Entry) bool {
            const E = Flat(@FieldType(T, e.field));
            if (entryBytes(e) % e.esize != 0) return false;
            if (@sizeOf(E) != e.esize) return false;
            return switch (@typeInfo(E)) {
                .int => |i| i.bits == 8 * e.esize,
                .@"struct" => |st| st.layout == .@"extern",
                else => false,
            };
        }

        /// Fill the struct's mapped fields from the image. Fields the map does not name
        /// are left as they are.
        pub fn load(s: *T, img: *const Image) void {
            inline for (entries) |e| {
                const n = entryBytes(e) / e.esize;
                if (comptime plain(e)) {
                    const dst: [*]u8 = @ptrCast(elems(e, s) + e.first);
                    @memcpy(dst[0 .. n * e.esize], img[e.addr..][0 .. n * e.esize]);
                } else {
                    const E = Flat(@FieldType(T, e.field));
                    const p = elems(e, s);
                    for (0..n) |i| p[e.first + i] = decode(E, img[e.addr + i * e.esize ..][0..e.esize]);
                }
            }
        }

        /// The struct's mapped fields as image bytes, in map order.
        pub fn snapshot(s: *const T, out: *Snapshot) void {
            var o: usize = 0;
            inline for (entries) |e| {
                const E = Flat(@FieldType(T, e.field));
                const p: [*]const E = @ptrCast(&@field(s, e.field));
                const n = entryBytes(e) / e.esize;
                if (comptime plain(e)) {
                    const src: [*]const u8 = @ptrCast(p + e.first);
                    @memcpy(out[o..][0 .. n * e.esize], src[0 .. n * e.esize]);
                } else {
                    for (0..n) |i| encode(E, p[e.first + i], out[o + i * e.esize ..][0..e.esize]);
                }
                o += entryBytes(e);
            }
        }

        /// `load` and `snapshot` element by element, as before the copies (the tests'
        /// reference for the fast paths).
        pub fn loadReference(s: *T, img: *const Image) void {
            inline for (entries) |e| {
                const E = Flat(@FieldType(T, e.field));
                const p = elems(e, s);
                const n = entryBytes(e) / e.esize;
                for (0..n) |i| p[e.first + i] = decode(E, img[e.addr + i * e.esize ..][0..e.esize]);
            }
        }
        pub fn snapshotReference(s: *const T, out: *Snapshot) void {
            var o: usize = 0;
            inline for (entries) |e| {
                const E = Flat(@FieldType(T, e.field));
                const p: [*]const E = @ptrCast(&@field(s, e.field));
                const n = entryBytes(e) / e.esize;
                for (0..n) |i| encode(E, p[e.first + i], out[o + i * e.esize ..][0..e.esize]);
                o += entryBytes(e);
            }
        }

        /// `load`, then the snapshot `storeChanged` compares with.
        pub fn loadSnap(s: *T, img: *const Image, before: *Snapshot) void {
            load(s, img);
            snapshot(s, before);
        }

        /// Write back the bytes of the mapped fields that differ from `before`. Returns
        /// the number of bytes written.
        pub fn storeChanged(s: *const T, img: *Image, before: *const Snapshot) usize {
            var after: Snapshot = undefined;
            snapshot(s, &after);
            var written: usize = 0;
            var o: usize = 0;
            inline for (entries) |e| {
                const n = entryBytes(e);
                // In blocks of 64 bytes: a block that compares equal has no byte to write.
                var i: usize = 0;
                while (i < n) {
                    const len = @min(64, n - i);
                    if (!std.mem.eql(u8, after[o + i ..][0..len], before[o + i ..][0..len])) {
                        for (i..i + len) |k| {
                            if (after[o + k] != before[o + k]) {
                                img[e.addr + k] = after[o + k];
                                written += 1;
                            }
                        }
                    }
                    i += len;
                }
                o += n;
            }
            return written;
        }

        /// `loadSnap` from a store by address (`ImageMem`, or the engine's homes): every
        /// mapped byte read with `m.get`, decoded as `load` decodes it, and the snapshot
        /// taken from the struct as `loadSnap` takes it.
        pub fn loadSnapVia(s: *T, m: anytype, before: *Snapshot) void {
            var o: usize = 0;
            inline for (entries) |e| {
                const n = entryBytes(e);
                for (0..n) |k| before[o + k] = m.get(@intCast(e.addr + k));
                o += n;
            }
            loadFromSnapshot(s, before);
            snapshot(s, before);
        }

        /// The struct's mapped fields decoded from snapshot bytes (`snapshot`'s inverse,
        /// as `load` decodes the image).
        pub fn loadFromSnapshot(s: *T, snap: *const Snapshot) void {
            var o: usize = 0;
            inline for (entries) |e| {
                const E = Flat(@FieldType(T, e.field));
                const p = elems(e, s);
                const cnt = entryBytes(e) / e.esize;
                for (0..cnt) |i| p[e.first + i] = decode(E, snap[o + i * e.esize ..][0..e.esize]);
                o += entryBytes(e);
            }
        }

        /// `storeChanged` into a store by address: the changed bytes, in the same order.
        pub fn storeChangedVia(s: *const T, m: anytype, before: *const Snapshot) usize {
            var after: Snapshot = undefined;
            snapshot(s, &after);
            var written: usize = 0;
            var o: usize = 0;
            inline for (entries) |e| {
                for (0..entryBytes(e)) |k| {
                    if (after[o + k] != before[o + k]) {
                        m.set(@intCast(e.addr + k), after[o + k]);
                        written += 1;
                    }
                }
                o += entryBytes(e);
            }
            return written;
        }

        /// Write every mapped field (used to put a whole struct into a fresh image).
        pub fn storeAll(s: *const T, img: *Image) void {
            var after: Snapshot = undefined;
            snapshot(s, &after);
            var o: usize = 0;
            inline for (entries) |e| {
                const n = entryBytes(e);
                @memcpy(img[e.addr..][0..n], after[o..][0..n]);
                o += n;
            }
        }

        /// Whether some entry covers DGROUP address `addr`.
        pub fn covers(addr: usize) bool {
            inline for (entries) |e| {
                if (addr >= e.addr and addr < e.addr + entryBytes(e)) return true;
            }
            return false;
        }

        /// The field and element at DGROUP address `addr`, for messages.
        pub fn describe(buf: []u8, addr: usize) []const u8 {
            inline for (entries) |e| {
                if (addr >= e.addr and addr < e.addr + entryBytes(e)) {
                    const i = e.first + (addr - e.addr) / e.esize;
                    return std.fmt.bufPrint(buf, "{s}.{s}[{d}] (DG:{X:0>4})", .{ @typeName(T), e.field, i, addr }) catch e.field;
                }
            }
            return std.fmt.bufPrint(buf, "DG:{X:0>4} (no field of {s})", .{ addr, @typeName(T) }) catch "?";
        }
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "dgroup: the initial image is the executable's data segment" {
    // The file holds DG:0000-31FF (the decrypted executable is 431,168 bytes).
    try std.testing.expectEqual(@as(usize, 0x3200), initialised_len);
    const n = 0x3200;
    try std.testing.expectEqualSlices(u8, &original.dgroup(0, n), initial[0..n]);
    for (initial[n..]) |b| try std.testing.expectEqual(@as(u8, 0), b);
    // A known table: the exchange values at DG:1A71.
    try std.testing.expectEqualSlices(u8, &.{ 1, 3, 9, 9, 15, 27, 0 }, initial[0x1A71..][0..7]);
}

test "dgroup: every constant table a unit reads from the executable equals the image's bytes" {
    inline for (maps.constant_reads) |r| {
        if (@as(usize, r.addr) + r.len > initialised_len) {
            std.debug.print("constant table DG:{X:0>4}+{d} ({s}:{d}) runs past the executable's data\n", .{ r.addr, r.len, r.file, r.line });
            return error.ConstantPastData;
        }
        try std.testing.expectEqualSlices(u8, &original.dgroup(r.addr, r.len), initial[r.addr..][0..r.len]);
    }
}

test "dgroup: element encodings round-trip in the original's widths" {
    var b: [8]u8 = undefined;
    encode(u48, 0x0102_0304_0506, b[0..6]);
    try std.testing.expectEqualSlices(u8, &.{ 6, 5, 4, 3, 2, 1 }, b[0..6]);
    try std.testing.expectEqual(@as(u48, 0x0102_0304_0506), decode(u48, b[0..6]));
    encode(i16, -2, b[0..2]);
    try std.testing.expectEqualSlices(u8, &.{ 0xFE, 0xFF }, b[0..2]);
    try std.testing.expectEqual(@as(i16, -2), decode(i16, b[0..2]));
    try std.testing.expectEqual(@as(u1, 1), decode(u1, &.{3}));
    try std.testing.expect(decode(bool, &.{2}));
    try std.testing.expectEqual(@as(usize, 6), elemSize(u48));
    try std.testing.expectEqual(@as(usize, 1), elemSize(u1));
}

test "dgroup: only changed bytes are written back, so a narrow type does not clobber its byte" {
    const S = struct { flag: u1 = 0, wide: [3]u16 = @splat(0) };
    const entries = [_]Entry{
        .{ .field = "flag", .first = 0, .count = 1, .addr = 0x5000, .esize = 1 },
        .{ .field = "wide", .first = 1, .count = 2, .addr = 0x5002, .esize = 2 },
    };
    const M = Map(S, &entries);
    const img = try std.testing.allocator.create(Image);
    defer std.testing.allocator.destroy(img);
    img.* = @splat(0);
    img[0x5000] = 0x83; // bit 0 set, other bits set too
    img[0x5002] = 0x34;
    img[0x5003] = 0x12;
    var s: S = .{};
    var before: M.Snapshot = undefined;
    M.loadSnap(&s, img, &before);
    try std.testing.expectEqual(@as(u1, 1), s.flag);
    try std.testing.expectEqual(@as(u16, 0x1234), s.wide[1]);
    s.wide[2] = 0xBEEF;
    try std.testing.expectEqual(@as(usize, 2), M.storeChanged(&s, img, &before));
    try std.testing.expectEqual(@as(u8, 0x83), img[0x5000]); // untouched: unchanged value
    try std.testing.expectEqual(@as(u16, 0xBEEF), std.mem.readInt(u16, img[0x5004..0x5006], .little));
    s.flag = 0;
    _ = M.storeChanged(&s, img, &before);
    try std.testing.expectEqual(@as(u8, 0), img[0x5000]);
}

test "dgroup: the copies of plain entries give the bytes and values of the element-by-element path, for every generated map" {
    var prng = std.Random.DefaultPrng.init(0xD6_0001);
    const rnd = prng.random();
    const img = try std.testing.allocator.create(Image);
    defer std.testing.allocator.destroy(img);
    @setEvalBranchQuota(100_000);
    var checked: usize = 0;
    inline for (@typeInfo(maps).@"struct".decl_names) |file| {
        const F = @field(maps, file);
        if (@TypeOf(F) == type and @typeInfo(F) == .@"struct") {
            inline for (@typeInfo(F).@"struct".decl_names) |st| {
                const list = @field(F, st);
                const L = @TypeOf(list);
                if (@typeInfo(L) == .array and @typeInfo(L).array.child == Entry) {
                    const T = comptime structOf(file, st);
                    if (T != void) {
                        const M = Map(T, &list);
                        for (0..20) |_| {
                            rnd.bytes(img);
                            const a = try std.testing.allocator.create(T);
                            defer std.testing.allocator.destroy(a);
                            const b = try std.testing.allocator.create(T);
                            defer std.testing.allocator.destroy(b);
                            @memset(std.mem.asBytes(a), 0);
                            @memset(std.mem.asBytes(b), 0);
                            M.load(a, img);
                            M.loadReference(b, img);
                            var sa: M.Snapshot = undefined;
                            var sb: M.Snapshot = undefined;
                            @memset(&sa, 0);
                            @memset(&sb, 0);
                            M.snapshot(a, &sa);
                            M.snapshotReference(b, &sb);
                            try std.testing.expectEqualSlices(u8, &sb, &sa);
                            // The same struct snapshot both ways, after a change of bytes.
                            M.snapshotReference(a, &sb);
                            try std.testing.expectEqualSlices(u8, &sb, &sa);
                            checked += 1;
                        }
                    }
                }
            }
        }
    }
    try std.testing.expect(checked > 100);
}

/// The struct a generated map belongs to, for the test above (void: one this file cannot
/// name, or one whose fields hold pointers).
fn structOf(comptime file: []const u8, comptime st: []const u8) type {
    const units = .{
        .{ "position", @import("position.zig") },       .{ "evalvars", @import("evalvars.zig") },
        .{ "eval_state", @import("eval_state.zig") },   .{ "movegen", @import("movegen.zig") },
        .{ "see", @import("see.zig") },                 .{ "leaf", @import("leaf.zig") },
        .{ "evalthreats", @import("evalthreats.zig") }, .{ "searchnode", @import("searchnode.zig") },
        .{ "rootprep", @import("rootprep.zig") },       .{ "rootsearch", @import("rootsearch.zig") },
        .{ "gamemove", @import("gamemove.zig") },       .{ "evaltables", @import("evaltables.zig") },
        .{ "timebudget", @import("timebudget.zig") },   .{ "setup", @import("setup.zig") },
    };
    inline for (units) |u| {
        if (comptime std.mem.eql(u8, u[0], file)) {
            if (@hasDecl(u[1], st)) return @field(u[1], st);
        }
    }
    return void;
}
