//! Differential test of src/evaltables.zig against calls of prepare_eval recorded from
//! the running original (tests/golden/evaltables/*.zst, made by
//! tools/port/gen_evaltables_vectors.py, whose docstring defines the format).
//!
//! Each recorded call gives the state (the position's fields, the tables and the other
//! inputs) at the routine's entry and at the first arrival at every section boundary.
//! The test proves each section separately, as tools/research/evaltables/stages.py does:
//! from the recorded state at its start, with the locals the earlier sections leave
//! (taken from a run of the port from the entry), the section must give the recorded
//! state at its end. Where a boundary was not reached in a call (the endgame skips
//! D7B3-DE24), the sections between the reached boundaries are checked together.
//! Then `prepareEval` is run on the entry state and must give the state at the retf.
//! Every class C fix is off in the replay. The three fixes of the routine (DEV-010,
//! DEV-011, DEV-012; `prepareEvalFixes`) have their own tests below, each showing the
//! original and the corrected values on the recorded states.

const std = @import("std");
const pos = @import("position.zig");
const et = @import("evaltables.zig");
const Position = pos.Position;

// ---------------------------------------------------------------------------
// The DGROUP image and the regions the vectors carry
// ---------------------------------------------------------------------------

const DG = [0x10000]u8;

fn xfer(comptime store: bool, ptr: anytype, dg: *DG, addr: usize) void {
    const T = @typeInfo(@TypeOf(ptr)).pointer.child;
    switch (@typeInfo(T)) {
        .int => {
            const n = @typeInfo(T).int.bits / 8;
            const bytes = dg[addr..][0..n];
            if (store) std.mem.writeInt(T, bytes, ptr.*, .little) else ptr.* = std.mem.readInt(T, bytes, .little);
        },
        .array => |a| {
            for (ptr, 0..) |*e, i| xfer(store, e, dg, addr + i * @sizeOf(a.child));
        },
        else => @compileError("unsupported field type"),
    }
}

fn byteSize(comptime T: type) usize {
    return switch (@typeInfo(T)) {
        .int => |i| i.bits / 8,
        .array => |a| a.len * byteSize(a.child),
        else => @compileError("unsupported field type"),
    };
}

/// The position's fields the routine reads or writes, with their DGROUP addresses.
const PosField = struct { name: []const u8, dg: u16, len: u16 };
const position_fields = [_]PosField{
    .{ .name = "board", .dg = 0x9EF6, .len = 120 },                .{ .name = "piece_list", .dg = 0xA03A, .len = 32 },
    .{ .name = "pawn_attacks[white]", .dg = 0xA51C, .len = 120 },  .{ .name = "pawn_attacks[black]", .dg = 0x37DA, .len = 120 },
    .{ .name = "pawns_per_file[white]", .dg = 0xA8C8, .len = 10 }, .{ .name = "pawns_per_file[black]", .dg = 0x9EA8, .len = 10 },
    .{ .name = "material[white]", .dg = 0x8DE4, .len = 2 },        .{ .name = "material[black]", .dg = 0x8DE6, .len = 2 },
    .{ .name = "piece_material[white]", .dg = 0xAE38, .len = 2 },  .{ .name = "piece_material[black]", .dg = 0xAE3A, .len = 2 },
    .{ .name = "piece_material_sum", .dg = 0x378E, .len = 2 },     .{ .name = "total_material", .dg = 0xA420, .len = 2 },
    .{ .name = "material_balance", .dg = 0xA35E, .len = 2 },       .{ .name = "piece_balance", .dg = 0xA8D2, .len = 2 },
    .{ .name = "material_balance_2", .dg = 0xA4C6, .len = 2 },     .{ .name = "piece_square_sum", .dg = 0x7182, .len = 2 },
    .{ .name = "men", .dg = 0x154A, .len = 1 },                    .{ .name = "piece_count[white]", .dg = 0x931A, .len = 1 },
    .{ .name = "piece_count[black]", .dg = 0x931B, .len = 1 },     .{ .name = "pawn_count", .dg = 0x90AA, .len = 1 },
    .{ .name = "side_pawn_count[white]", .dg = 0xAB1E, .len = 1 }, .{ .name = "side_pawn_count[black]", .dg = 0x741A, .len = 1 },
    .{ .name = "pawns_on_dark[white]", .dg = 0xB520, .len = 1 },   .{ .name = "pawns_on_dark[black]", .dg = 0xA354, .len = 1 },
    .{ .name = "king_file[white]", .dg = 0xA22E, .len = 1 },       .{ .name = "king_file[black]", .dg = 0xA22F, .len = 1 },
    .{ .name = "king_rank[white]", .dg = 0x70F0, .len = 1 },       .{ .name = "king_rank[black]", .dg = 0x70F1, .len = 1 },
    .{ .name = "oo_lost_at[white]", .dg = 0xB426, .len = 2 },      .{ .name = "ooo_lost_at[white]", .dg = 0x3A30, .len = 2 },
    .{ .name = "oo_lost_at[black]", .dg = 0xB428, .len = 2 },      .{ .name = "ooo_lost_at[black]", .dg = 0x3A32, .len = 2 },
    .{ .name = "game_ply", .dg = 0x9FC8, .len = 2 },               .{ .name = "hash_key", .dg = 0x8CCC, .len = 6 },
    .{ .name = "pawn_hash_key", .dg = 0x8CD2, .len = 6 },
};

fn transferPosition(comptime store: bool, p: *Position, dg: *DG) void {
    xfer(store, &p.board, dg, 0x9EF6);
    xfer(store, &p.piece_list, dg, 0xA03A);
    xfer(store, &p.pawn_attacks[0], dg, 0xA51C);
    xfer(store, &p.pawn_attacks[1], dg, 0x37DA);
    xfer(store, &p.pawns_per_file[0], dg, 0xA8C8);
    xfer(store, &p.pawns_per_file[1], dg, 0x9EA8);
    xfer(store, &p.material[0], dg, 0x8DE4);
    xfer(store, &p.material[1], dg, 0x8DE6);
    xfer(store, &p.piece_material[0], dg, 0xAE38);
    xfer(store, &p.piece_material[1], dg, 0xAE3A);
    xfer(store, &p.piece_material_sum, dg, 0x378E);
    xfer(store, &p.total_material, dg, 0xA420);
    xfer(store, &p.material_balance, dg, 0xA35E);
    xfer(store, &p.piece_balance, dg, 0xA8D2);
    xfer(store, &p.material_balance_2, dg, 0xA4C6);
    xfer(store, &p.piece_square_sum, dg, 0x7182);
    xfer(store, &p.men, dg, 0x154A);
    xfer(store, &p.piece_count[0], dg, 0x931A);
    xfer(store, &p.piece_count[1], dg, 0x931B);
    xfer(store, &p.pawn_count, dg, 0x90AA);
    xfer(store, &p.side_pawn_count[0], dg, 0xAB1E);
    xfer(store, &p.side_pawn_count[1], dg, 0x741A);
    xfer(store, &p.pawns_on_dark[0], dg, 0xB520);
    xfer(store, &p.pawns_on_dark[1], dg, 0xA354);
    xfer(store, &p.king_file[0], dg, 0xA22E);
    xfer(store, &p.king_file[1], dg, 0xA22F);
    xfer(store, &p.king_rank[0], dg, 0x70F0);
    xfer(store, &p.king_rank[1], dg, 0x70F1);
    xfer(store, &p.oo_lost_at[0], dg, 0xB426);
    xfer(store, &p.ooo_lost_at[0], dg, 0x3A30);
    xfer(store, &p.oo_lost_at[1], dg, 0xB428);
    xfer(store, &p.ooo_lost_at[1], dg, 0x3A32);
    xfer(store, &p.game_ply, dg, 0x9FC8);
    xfer(store, &p.hash_key, dg, 0x8CCC);
    xfer(store, &p.pawn_hash_key, dg, 0x8CD2);
}

fn transferStruct(comptime store: bool, comptime S: type, s: *S, dg: *DG) void {
    inline for (@typeInfo(S).@"struct".field_names) |name| xfer(store, &@field(s, name), dg, @field(addrs(S), name));
}

/// The DGROUP addresses of the fields of `S`: `TableValues` has the fields of `Tables`, at
/// `Tables.dg`.
fn addrs(comptime S: type) @TypeOf(if (S == et.TableValues) et.Tables.dg else S.dg) {
    return if (S == et.TableValues) et.Tables.dg else S.dg;
}

const Region = struct { dg: u16, len: u16 };

const regions: [regionCount()]Region = blk: {
    @setEvalBranchQuota(100_000);
    var r: [regionCount()]Region = undefined;
    var n: usize = 0;
    for (position_fields) |f| {
        r[n] = .{ .dg = f.dg, .len = f.len };
        n += 1;
    }
    for (.{ et.TableValues, et.Inputs }) |S| {
        for (@typeInfo(S).@"struct".field_names, @typeInfo(S).@"struct".field_types) |fname, T| {
            if (continued(S, fname)) continue;
            r[n] = .{ .dg = @field(addrs(S), fname), .len = recordedLen(S, fname, T) };
            n += 1;
        }
    }
    // sorted by address, as the vectors list them
    for (1..r.len) |i| {
        var j = i;
        while (j > 0 and r[j - 1].dg > r[j].dg) : (j -= 1) {
            const x = r[j];
            r[j] = r[j - 1];
            r[j - 1] = x;
        }
    }
    break :blk r;
};

/// A field's bytes in the vector files' region image: its size, but for the irreversible-move
/// flags DG:3490, of which the vector tool records the first 256 (tools/port/
/// gen_evaltables_vectors.py `INPUTS`; every recorded call is at a game ply below 256). The
/// rest of the field is read from the DGROUP buffer outside the regions.
/// The mobility weights DG:A074 are one region of 28 bytes in the vectors, the two fields
/// `mobility_weights` and `mobility_weights_rest` of `Tables` (12 and 16 bytes) in the port.
fn recordedLen(comptime S: type, comptime fname: []const u8, comptime T: type) u16 {
    if (S == et.Inputs and std.mem.eql(u8, fname, "irreversible_by_ply")) return 256;
    if (S == et.TableValues and std.mem.eql(u8, fname, "mobility_weights")) return 28;
    return byteSize(T);
}

/// A field whose bytes the region of the field before it covers (`recordedLen`).
fn continued(comptime S: type, comptime fname: []const u8) bool {
    return S == et.TableValues and std.mem.eql(u8, fname, "mobility_weights_rest");
}

fn regionCount() usize {
    return position_fields.len + @typeInfo(et.TableValues).@"struct".field_names.len - 1 + @typeInfo(et.Inputs).@"struct".field_names.len;
}

const image_size = blk: {
    var n: usize = 0;
    for (regions) |r| n += r.len;
    break :blk n;
};
const Image = [image_size]u8;

fn expand(img: *const Image, dg: *DG) void {
    var o: usize = 0;
    for (regions) |r| {
        @memcpy(dg[r.dg..][0..r.len], img[o..][0..r.len]);
        o += r.len;
    }
}

fn gather(dg: *const DG, img: *Image) void {
    var o: usize = 0;
    for (regions) |r| {
        @memcpy(img[o..][0..r.len], dg[r.dg..][0..r.len]);
        o += r.len;
    }
}

fn imageAddress(off: usize) usize {
    var o: usize = 0;
    for (regions) |r| {
        if (off < o + r.len) return r.dg + (off - o);
        o += r.len;
    }
    unreachable;
}

/// The name of the field holding DGROUP byte `addr`.
fn describe(buf: []u8, addr: usize) []const u8 {
    for (position_fields) |f| {
        if (addr >= f.dg and addr < f.dg + f.len) return std.fmt.bufPrint(buf, "Position.{s} +{d} (DG:{X:0>4})", .{ f.name, addr - f.dg, addr }) catch f.name;
    }
    inline for (.{ et.TableValues, et.Inputs }, .{ "Tables", "Inputs" }) |S, sname| {
        const info = @typeInfo(S).@"struct";
        inline for (info.field_names, info.field_types) |fname, T| {
            const base: usize = @field(addrs(S), fname);
            const unit: usize = switch (@typeInfo(T)) {
                .array => |a| byteSize(a.child),
                else => byteSize(T),
            };
            if (addr >= base and addr < base + byteSize(T))
                return std.fmt.bufPrint(buf, "{s}.{s}[{d}] (DG:{X:0>4})", .{ sname, fname, (addr - base) / unit, addr }) catch fname;
        }
    }
    return "?";
}

// ---------------------------------------------------------------------------
// Reading a vector file
// ---------------------------------------------------------------------------

fn readVectors(gpa: std.mem.Allocator, name: []const u8) ![]u8 {
    var path_buf: [256]u8 = undefined;
    const dir = @import("build_options").golden_dir;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/evaltables/{s}", .{ dir, name });
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

const nsec = et.sections.len;

/// A recorded state: the position, the tables as values and the inputs. Copied by value;
/// prepare_eval runs on it through a `Tables` bound to `t` (`tables`) after any copy.
const State = struct {
    p: Position = .{},
    t: et.TableValues = .{},
    in: et.Inputs = .{},

    /// A `Tables` pointing at `s.t`.
    fn tables(s: *State) et.Tables {
        return et.tablesOf(&s.t);
    }

    fn load(s: *State, img: *const Image, dg: *DG) void {
        expand(img, dg);
        transferPosition(false, &s.p, dg);
        transferStruct(false, et.TableValues, &s.t, dg);
        transferStruct(false, et.Inputs, &s.in, dg);
    }
    /// The image after the routine: `before` with the position's fields and the tables
    /// written back (the inputs are never written).
    fn result(s: *State, before: *const Image, dg: *DG, out: *Image) void {
        expand(before, dg);
        transferPosition(true, &s.p, dg);
        transferStruct(true, et.TableValues, &s.t, dg);
        gather(dg, out);
    }
};

const Counts = struct {
    calls: usize = 0,
    alone: [nsec]usize = @splat(0),
    grouped: [nsec]usize = @splat(0),
};

fn mismatch(name: []const u8, call: usize, scen: u16, ncall: u16, what: []const u8, want: *const Image, got: *const Image) error{MismatchWithOriginal} {
    var buf: [96]u8 = undefined;
    std.debug.print("\n{s}: call {d} (scenario {d}, call {d}) differs after {s}\n", .{ name, call, scen, ncall, what });
    var shown: usize = 0;
    for (want, got, 0..) |w, g, off| {
        if (w != g) {
            const addr = imageAddress(off);
            std.debug.print("  {s}: want {X:0>2}, got {X:0>2}\n", .{ describe(&buf, addr), w, g });
            shown += 1;
            if (shown == 8) break;
        }
    }
    return error.MismatchWithOriginal;
}

fn replay(gpa: std.mem.Allocator, name: []const u8) !Counts {
    const data = try readVectors(gpa, name);
    defer gpa.free(data);
    var c: Cursor = .{ .d = data };
    try std.testing.expectEqualSlices(u8, "MCET", data[0..4]);
    c.i = 4;
    try std.testing.expectEqual(@as(u16, 1), c.int(u16));
    // The vectors' regions are the port's fields, address for address.
    try std.testing.expectEqual(@as(u16, regions.len), c.int(u16));
    for (regions) |r| {
        try std.testing.expectEqual(r.dg, c.int(u16));
        try std.testing.expectEqual(r.len, c.int(u16));
    }
    try std.testing.expectEqual(@as(u16, nsec + 1), c.int(u16));
    for (et.sections) |s| try std.testing.expectEqual(s.start, c.int(u16));
    try std.testing.expectEqual(et.sections[nsec - 1].end, c.int(u16));

    const dg = try gpa.create(DG);
    defer gpa.destroy(dg);
    @memset(dg, 0);
    const truth = try gpa.create(Image);
    defer gpa.destroy(truth);
    @memset(truth, 0);
    const entry = try gpa.create(Image);
    defer gpa.destroy(entry);
    const start = try gpa.create(Image);
    defer gpa.destroy(start);
    const got = try gpa.create(Image);
    defer gpa.destroy(got);
    const scratch = try gpa.create(State);
    defer gpa.destroy(scratch);
    const check = try gpa.create(State);
    defer gpa.destroy(check);

    var counts: Counts = .{};
    while (true) {
        const tag = c.byte();
        if (tag == 0) {
            try std.testing.expectEqual(counts.calls, c.int(u32));
            return counts;
        }
        if (tag != 1) return error.BadRecordTag;
        const scen = c.int(u16);
        const ncall = c.int(u16);
        _ = c.int(u16); // SP at entry
        c.apply(truth);
        entry.* = truth.*;
        scratch.* = .{};
        scratch.load(entry, dg);
        var l: et.Locals = .{};
        var scratch_t = scratch.tables();
        var ctx: et.Ctx = .{ .p = &scratch.p, .t = &scratch_t, .in = &scratch.in, .l = &l };
        start.* = truth.*;
        var start_k: usize = 0;
        var start_locals = l;
        for (et.sections, 0..) |s, k| {
            const reached = c.byte() != 0;
            if (reached) c.apply(truth);
            s.run(&ctx);
            if (!reached) continue;
            // sections start_k..k from the recorded state at boundary start_k
            check.* = .{};
            check.load(start, dg);
            var l2 = start_locals;
            var check_t = check.tables();
            var ctx2: et.Ctx = .{ .p = &check.p, .t = &check_t, .in = &check.in, .l = &l2 };
            for (et.sections[start_k .. k + 1]) |s2| s2.run(&ctx2);
            check.result(start, dg, got);
            if (!std.mem.eql(u8, truth, got)) {
                var what: [96]u8 = undefined;
                const label = std.fmt.bufPrint(&what, "section(s) {X:0>4}-{X:0>4} {s}..{s}", .{ et.sections[start_k].start, s.end, et.sections[start_k].name, s.name }) catch "sections";
                return mismatch(name, counts.calls, scen, ncall, label, truth, got);
            }
            if (start_k == k) {
                counts.alone[k] += 1;
            } else {
                for (start_k..k + 1) |j| counts.grouped[j] += 1;
            }
            start.* = truth.*;
            start_k = k + 1;
            start_locals = l;
        }
        // The whole routine through its entry point, from the entry state.
        check.* = .{};
        check.load(entry, dg);
        var check_t = check.tables();
        et.prepareEval(&check.p, &check_t, &check.in);
        check.result(entry, dg, got);
        if (!std.mem.eql(u8, truth, got)) return mismatch(name, counts.calls, scen, ncall, "prepareEval (whole routine)", truth, got);
        counts.calls += 1;
    }
}

/// all.zst: the 22 scenarios of 51- §5.3 (Normal style). custom.zst: scenarios run in the
/// custom style (style 0, Aggression 137, piece values 100 300 330 500 950), set at each
/// call site by `gen_evaltables_vectors.py record`. probe.zst: the original called directly
/// on made-up states (`gen_evaltables_vectors.py probe`): the calls that reach code the
/// recorded games do not, and a sample of the rest; with them every basic block of the
/// routine has run except three (51- §5.5).
const runs = [_][]const u8{ "all.zst", "custom.zst", "probe.zst" };

/// A recorded call's entry: the state and the region image.
const Entry = struct { s: State, img: Image };

/// The entry of every recorded call of a vector file, in order.
fn loadEntries(gpa: std.mem.Allocator, name: []const u8, out: *std.ArrayList(Entry)) !void {
    const data = try readVectors(gpa, name);
    defer gpa.free(data);
    var c: Cursor = .{ .d = data };
    c.i = 8 + 4 * regions.len + 2 + 2 * (nsec + 1);
    const dg = try gpa.create(DG);
    defer gpa.destroy(dg);
    @memset(dg, 0);
    const truth = try gpa.create(Image);
    defer gpa.destroy(truth);
    @memset(truth, 0);
    while (c.byte() == 1) {
        c.i += 6;
        c.apply(truth);
        const e = try out.addOne(gpa);
        e.s = .{};
        e.s.load(truth, dg);
        e.img = truth.*;
        for (0..nsec) |_| {
            if (c.byte() != 0) c.apply(truth);
        }
    }
}

// ---------------------------------------------------------------------------
// The class C fixes of prepare_eval (DEV-010, DEV-011, DEV-012; AGENTS.md §9.2)
// ---------------------------------------------------------------------------

const only_dev010: pos.Fixes = blk: {
    var f = pos.Fixes.original;
    f.dev010_passed_h_pawn = true;
    break :blk f;
};
const only_dev011: pos.Fixes = blk: {
    var f = pos.Fixes.original;
    f.dev011_blocked_wing_table = true;
    break :blk f;
};
const only_dev012: pos.Fixes = blk: {
    var f = pos.Fixes.original;
    f.dev012_white_pawn_table = true;
    break :blk f;
};

/// The region image after prepare_eval with `fixes`, from a recorded entry.
fn runImage(comptime fixes: pos.Fixes, e: *const Entry, work: *State, dg: *DG, out: *Image) void {
    work.* = e.s;
    var tb = work.tables();
    et.prepareEvalFixes(&work.p, &tb, &work.in, fixes);
    work.result(&e.img, dg, out);
}

const bench = @import("bench.zig");

test "bench: evaltables: prepareEval on every recorded entry state" {
    if (!bench.enabled) return;
    const gpa = std.testing.allocator;
    var entries: std.ArrayList(Entry) = .empty;
    defer entries.deinit(gpa);
    for (runs) |name| try loadEntries(gpa, name, &entries);
    const work = try gpa.create(State);
    defer gpa.destroy(work);
    const passes = 7;
    var overhead: bench.Best = .{};
    for (0..passes) |_| {
        const t0 = bench.now();
        for (entries.items) |*e| {
            work.* = e.s;
            bench.keep(work);
        }
        overhead.pass(t0);
    }
    inline for (.{ pos.Fixes.original, pos.Fixes.corrected }, .{ "original", "corrected" }) |fixes, label| {
        var best: bench.Best = .{};
        for (0..passes) |_| {
            const t0 = bench.now();
            for (entries.items) |*e| {
                work.* = e.s;
                var tb = work.tables();
                et.prepareEvalFixes(&work.p, &tb, &work.in, fixes);
                bench.keep(work);
            }
            best.pass(t0);
        }
        best.report("evaltables: prepareEval (" ++ label ++ ")", entries.items.len, passes, overhead.ns);
    }
}

/// How many recorded calls of each file a fix changes, and the first few bytes it changes.
fn sweep(comptime fixes: pos.Fixes, label: []const u8, entries: []const Entry, verbose: bool) !usize {
    const gpa = std.testing.allocator;
    const dg = try gpa.create(DG);
    defer gpa.destroy(dg);
    @memset(dg, 0);
    const work = try gpa.create(State);
    defer gpa.destroy(work);
    const a = try gpa.create(Image);
    defer gpa.destroy(a);
    const b = try gpa.create(Image);
    defer gpa.destroy(b);
    var changed: usize = 0;
    for (entries, 0..) |*e, i| {
        runImage(pos.Fixes.original, e, work, dg, a);
        runImage(fixes, e, work, dg, b);
        if (std.mem.eql(u8, a, b)) continue;
        changed += 1;
        if (!verbose or changed > 3) continue;
        std.debug.print("{s}: call {d} changes:\n", .{ label, i });
        var buf: [96]u8 = undefined;
        var shown: usize = 0;
        for (a, b, 0..) |x, y, off| {
            if (x == y) continue;
            std.debug.print("  {s}: original {X:0>2}, corrected {X:0>2}\n", .{ describe(&buf, imageAddress(off)), x, y });
            shown += 1;
            if (shown == 12) break;
        }
    }
    return changed;
}

fn sectionIndex(comptime name: []const u8) usize {
    inline for (et.sections, 0..) |s, k| {
        if (comptime std.mem.eql(u8, s.name, name)) return k;
    }
    @compileError("no section " ++ name);
}

/// Runs sections from..to-1 of prepare_eval with `fixes` on `s`.
fn runSections(comptime fixes: pos.Fixes, s: *State, l: *et.Locals, from: usize, to: usize) void {
    var tb = s.tables();
    var ctx: et.Ctx = .{ .p = &s.p, .t = &tb, .in = &s.in, .l = l };
    const secs = comptime et.sectionsFor(fixes);
    for (secs[from..to]) |sec| sec.run(&ctx);
}

/// For one recorded entry: the state and locals at the start of section `k` (the original
/// up to there), and the states after section k alone with the original and with `fixes`.
const SectionPair = struct {
    start: State,
    l: et.Locals,
    original: State,
    corrected: State,

    fn run(sp: *SectionPair, comptime fixes: pos.Fixes, e: *const Entry, k: usize) void {
        sp.start = e.s;
        sp.l = .{};
        runSections(pos.Fixes.original, &sp.start, &sp.l, 0, k);
        sp.original = sp.start;
        var l1 = sp.l;
        runSections(pos.Fixes.original, &sp.original, &l1, k, k + 1);
        sp.corrected = sp.start;
        var l2 = sp.l;
        runSections(fixes, &sp.corrected, &l2, k, k + 1);
    }
};

fn loadAll(gpa: std.mem.Allocator, entries: *std.ArrayList(Entry)) !void {
    for (runs) |name| try loadEntries(gpa, name, entries);
}

const rank_code = @import("original.zig").dgroup(0x1078, 120);
const file_code = @import("original.zig").dgroup(0x100A, 120);

test "prepare_eval DEV-010: square + 2 is on the pawn's rank for files a to g, the next rank for h" {
    // every square a pawn can stand on (ranks 2 to 7)
    for (31..89) |sq| {
        const f = file_code[sq];
        if (f < 1 or f > 8) continue;
        const want: u8 = if (f == 8) rank_code[sq] + 1 else rank_code[sq];
        try std.testing.expectEqual(want, rank_code[sq + 2]);
    }
}

test "prepare_eval DEV-010: corrected, a passed h-pawn's run of bonuses starts on the square ahead of it" {
    const gpa = std.testing.allocator;
    var entries: std.ArrayList(Entry) = .empty;
    defer entries.deinit(gpa);
    try loadAll(gpa, &entries);
    const k = sectionIndex("passed_centrality");
    const sp = try gpa.create(SectionPair);
    defer gpa.destroy(sp);
    var changed: usize = 0;
    var h_pawns: [2]usize = .{ 0, 0 };
    for (entries.items) |*e| {
        sp.run(only_dev010, e, k);
        // What the correction must change: for each passed h-pawn the section treats, the
        // run computed from the pawn's own rank R in place of rank R + 1 (White) / the
        // rank R + 1 read for Black (B215, B318).
        var want: [120]u8 = @splat(0);
        const t = &sp.start.t;
        for (8..16) |slot| {
            const w = sp.start.p.piece_list[slot];
            if (w < 0x63 and sp.start.p.board[w] == pos.white_pawn and w > 0x30 and t.passed_pawn_sq_white[slot] != 0 and file_code[w] == 8) {
                const r: i32 = rank_code[w];
                h_pawns[0] += 1;
                // corrected: d = R+1 .. 9, 4(R-2)+d; original: d = R+2 .. 9, 4(R-1)+d
                var d: i32 = r + 1;
                while (d <= 9) : (d += 1) {
                    const o: usize = @intCast(d * 10 + 8);
                    want[o] +%= @truncate(@as(u32, @bitCast(4 * (r - 2) + d)));
                    if (d >= r + 2) want[o] -%= @truncate(@as(u32, @bitCast(4 * (r - 1) + d)));
                }
            }
            const b = sp.start.p.piece_list[16 + slot];
            if (b < 0x63 and sp.start.p.board[b] == pos.black_pawn and b < 0x47 and t.passed_pawn_sq_black[slot] != 0 and file_code[b] == 8) {
                const r: i32 = rank_code[b];
                h_pawns[1] += 1;
                // corrected: r' = 11 - R, d = r'+1 .. 9; original: r' = 10 - R, d = r'+1 .. 9
                var d: i32 = 12 - r;
                while (d <= 9) : (d += 1) {
                    const o: usize = @intCast(118 - d * 10);
                    want[o] +%= @truncate(@as(u32, @bitCast(4 * (9 - r) + d)));
                }
                d = 11 - r;
                while (d <= 9) : (d += 1) {
                    const o: usize = @intCast(118 - d * 10);
                    want[o] -%= @truncate(@as(u32, @bitCast(4 * (8 - r) + d)));
                }
            }
        }
        var any = false;
        for (0..120) |sq| {
            const dw = sp.corrected.t.centrality_white[sq] -% sp.original.t.centrality_white[sq];
            const db = sp.corrected.t.centrality_black[sq] -% sp.original.t.centrality_black[sq];
            try std.testing.expectEqual(want[sq], dw);
            try std.testing.expectEqual(want[sq], db);
            if (dw != 0) any = true;
        }
        if (any) changed += 1;
    }
    std.debug.print("evaltables DEV-010: {d} of {d} recorded calls change in B146-B361 ({d} White, {d} Black passed h-pawns treated)\n", .{ changed, entries.items.len, h_pawns[0], h_pawns[1] });
    try std.testing.expectEqual(@as(usize, 119), changed);
    try std.testing.expect(h_pawns[0] > 0 and h_pawns[1] > 0);

    // probe.zst call 0 (entries: all.zst 569, custom.zst 31, then probe.zst): a White
    // passed pawn on h7 (square 88, rank code 8). The original reads the rank code of
    // square 90, 9, so its run (d = 10..9) is empty: h8 gets nothing. Corrected, the run
    // starts on h8 (d = 9) with 4 * (8 - 2) + 9 = 33.
    sp.run(only_dev010, &entries.items[600], k);
    try std.testing.expectEqual(@as(u8, 49), sp.original.t.centrality_white[98]);
    try std.testing.expectEqual(@as(u8, 82), sp.corrected.t.centrality_white[98]);
    try std.testing.expectEqual(@as(u8, 48), sp.original.t.centrality_black[98]);
    try std.testing.expectEqual(@as(u8, 81), sp.corrected.t.centrality_black[98]);
}

test "prepare_eval DEV-011: corrected, the blocked-wing rules take the per-file table's answer" {
    const gpa = std.testing.allocator;
    var entries: std.ArrayList(Entry) = .empty;
    defer entries.deinit(gpa);
    try loadAll(gpa, &entries);
    const k = sectionIndex("closed_wings");
    const sp = try gpa.create(SectionPair);
    defer gpa.destroy(sp);
    const ref = try gpa.create(State);
    defer gpa.destroy(ref);
    const dg = try gpa.create(DG);
    defer gpa.destroy(dg);
    @memset(dg, 0);
    const a = try gpa.create(Image);
    defer gpa.destroy(a);
    const b = try gpa.create(Image);
    defer gpa.destroy(b);
    var changed: usize = 0;
    var differ: usize = 0;
    var first: ?usize = null;
    for (entries.items, 0..) |*e, i| {
        sp.run(only_dev011, e, k);
        // The original routine on the same state with [A3FE + f] and [8CE6 + f] (f = 1..8)
        // made to hold the per-file answer: the corrected routine must equal it.
        ref.* = sp.start;
        var per_slot_differs = false;
        for (1..9) |f| {
            if ((ref.t.passed_pawn_sq_white[f] == 0) != (ref.t.passed_rank_by_file_white[f - 1] == 0)) per_slot_differs = true;
            if ((ref.t.passed_pawn_sq_black[f] == 0) != (ref.t.passed_rank_by_file_black[f - 1] == 0)) per_slot_differs = true;
            ref.t.passed_pawn_sq_white[f] = ref.t.passed_rank_by_file_white[f - 1];
            ref.t.passed_pawn_sq_black[f] = ref.t.passed_rank_by_file_black[f - 1];
        }
        if (per_slot_differs) differ += 1;
        var l = sp.l;
        runSections(pos.Fixes.original, ref, &l, k, k + 1);
        ref.t.passed_pawn_sq_white = sp.start.t.passed_pawn_sq_white;
        ref.t.passed_pawn_sq_black = sp.start.t.passed_pawn_sq_black;
        ref.result(&e.img, dg, a);
        sp.corrected.result(&e.img, dg, b);
        try std.testing.expectEqualSlices(u8, a, b);
        sp.original.result(&e.img, dg, a);
        if (!std.mem.eql(u8, a, b)) {
            changed += 1;
            if (first == null) first = i;
        }
    }
    std.debug.print("evaltables DEV-011: the two tables answer differently for some file in {d} of {d} recorded calls; the section's result changes in {d}\n", .{ differ, entries.items.len, changed });
    try std.testing.expectEqual(@as(usize, 92), changed);
    try std.testing.expectEqual(@as(usize, 211), first.?);

    // all.zst call 211, from a game: Black's passed pawn in slot 8 stands on d4 (square
    // 54), and Black has no passed h-pawn. The h-file rule reads [8CEE] (file 8), which is
    // slot 8's square, 54, and is skipped; corrected, the per-file table says no passed
    // h-pawn, and with Black's O-O stamp set the rooks on g8 and h8 lose 16.
    sp.run(only_dev011, &entries.items[211], k);
    const t = &sp.start.t;
    try std.testing.expectEqual(@as(u8, 54), t.passed_pawn_sq_black[8]);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 5, 0, 0, 0, 0 }, &t.passed_rank_by_file_black);
    try std.testing.expectEqual(@as(i16, 180), sp.original.t.rook_black[97]);
    try std.testing.expectEqual(@as(i16, 164), sp.corrected.t.rook_black[97]);
    try std.testing.expectEqual(@as(i16, 180), sp.original.t.rook_black[98]);
    try std.testing.expectEqual(@as(i16, 164), sp.corrected.t.rook_black[98]);
}

/// White's pawn table as the 0620 fill leaves it: the signed byte 5857:0620 at the
/// mirrored square (DG:19DE), squares 31..88.
fn fill0620(sq: usize) i16 {
    const exe = @embedFile("mcp8_exe");
    const header_bytes: usize = @as(usize, std.mem.readInt(u16, exe[8..10], .little)) * 16;
    const mirror = @import("original.zig").dgroup(0x19DE, 100);
    return @as(i8, @bitCast(exe[header_bytes + 0x58570 + 0x620 + mirror[sq]]));
}

test "prepare_eval DEV-012: corrected, White's pawn table with only O-O lost is the 0620 fill, as Black's" {
    const gpa = std.testing.allocator;
    var entries: std.ArrayList(Entry) = .empty;
    defer entries.deinit(gpa);
    try loadAll(gpa, &entries);
    const k = sectionIndex("kings_pawns");
    const sp = try gpa.create(SectionPair);
    defer gpa.destroy(sp);
    const e2 = try gpa.create(Entry);
    defer gpa.destroy(e2);
    // Recorded calls, and each recorded call made into the case: White king on e1, the
    // O-O stamp set and the O-O-O stamp 0 (the king and rook are not moved, only the
    // stamps, which is all the section reads of castling).
    var recorded: usize = 0;
    var made: usize = 0;
    for (entries.items) |*e| {
        for (0..2) |variant| {
            e2.* = e.*;
            if (variant == 1) {
                if (e2.s.p.king_file[0] != 5) continue;
                if (e2.s.p.oo_lost_at[0] == 0) e2.s.p.oo_lost_at[0] = 1;
                e2.s.p.ooo_lost_at[0] = 0;
            }
            sp.run(only_dev012, e2, k);
            const s = &sp.start;
            // The path of 9FF4 with `long` (see kingsPawns).
            const queenless_b = @as(i16, @bitCast(s.p.piece_material[1])) <= 0xE10 and !sp.l.qb;
            const long_ok = s.p.ooo_lost_at[0] == 0 and s.p.pawns_per_file[1][1] != 0 and s.p.pawns_per_file[1][2] != 0 and
                s.p.pawns_per_file[0][1] != 0 and s.p.pawns_per_file[0][2] != 0;
            const case = !queenless_b and s.p.king_file[0] == 5 and s.p.oo_lost_at[0] != 0 and long_ok;
            if (!case) {
                try std.testing.expectEqualSlices(i16, &sp.original.t.pawn_white, &sp.corrected.t.pawn_white);
                continue;
            }
            if (variant == 0) recorded += 1 else made += 1;
            var differs = false;
            for (31..89) |sq| {
                try std.testing.expectEqual(fill0620(sq), sp.corrected.t.pawn_white[sq]);
                if (sp.corrected.t.pawn_white[sq] != sp.original.t.pawn_white[sq]) differs = true;
            }
            try std.testing.expect(differs);
            // the rest of the section is unchanged
            sp.corrected.t.pawn_white = sp.original.t.pawn_white;
            try std.testing.expect(std.meta.eql(sp.original.t.king_white, sp.corrected.t.king_white));
        }
    }
    std.debug.print("evaltables DEV-012: the case in {d} recorded calls and {d} made from them\n", .{ recorded, made });
    try std.testing.expectEqual(@as(usize, 1), recorded);
    try std.testing.expect(made > 0);

    // The recorded case, probe.zst call 5 (entry 605). After the section, pawn_white[a2]
    // is 6 from 05BC (original) and 30 from 0620 (corrected); after the whole routine, with
    // the +12 of A5C2, 18 and 42.
    sp.run(only_dev012, &entries.items[605], k);
    try std.testing.expectEqual(@as(i16, 6), sp.original.t.pawn_white[31]);
    try std.testing.expectEqual(@as(i16, 30), sp.corrected.t.pawn_white[31]);
}

// The whole routine, each fix alone and all three, against the original: how many
// recorded calls change. With every switch off `prepareEvalFixes` is the original, which
// the replay test below proves. The corrected routine was also compared with the
// corrected Python model (tools/research/evaltables/model.py, FIX_DEV010_* ...) on every
// recorded call, by a hash of the whole region image: equal for all 974 calls in all
// five settings (2026-11-20).
/// The three fixes of the routine before DEV-056 (`pos.Fixes.corrected` now has four).
const dev010_011_012: pos.Fixes = blk: {
    var f = pos.Fixes.original;
    f.dev010_passed_h_pawn = true;
    f.dev011_blocked_wing_table = true;
    f.dev012_white_pawn_table = true;
    break :blk f;
};

const only_dev056: pos.Fixes = blk: {
    var f = pos.Fixes.original;
    f.dev056_king_ring_wrap = true;
    break :blk f;
};

test "prepare_eval DEV-056: how many recorded calls the king rings' wrap changes" {
    // A king on the a- or h-file in the middlegame at the root: the ring offsets of 3 files
    // then reach the far side of another rank (centralityKings).
    const gpa = std.testing.allocator;
    var total: usize = 0;
    var changed: usize = 0;
    for (runs) |name| {
        var entries: std.ArrayList(Entry) = .empty;
        defer entries.deinit(gpa);
        try loadEntries(gpa, name, &entries);
        const n = try sweep(only_dev056, "DEV-056", entries.items, false);
        std.debug.print("evaltables DEV-056 {s}: {d} calls, {d} changed\n", .{ name, entries.items.len, n });
        total += entries.items.len;
        changed += n;
    }
    try std.testing.expectEqual(@as(usize, 170), changed);
}

test "prepare_eval fixes: how many recorded calls each fix changes" {
    const gpa = std.testing.allocator;
    const want = [_][4]usize{ .{ 74, 33, 0, 87 }, .{ 0, 0, 0, 0 }, .{ 45, 59, 1, 96 } };
    inline for (runs, want) |name, w| {
        var entries: std.ArrayList(Entry) = .empty;
        defer entries.deinit(gpa);
        try loadEntries(gpa, name, &entries);
        const n10 = try sweep(only_dev010, "DEV-010 " ++ name, entries.items, false);
        const n11 = try sweep(only_dev011, "DEV-011 " ++ name, entries.items, false);
        const n12 = try sweep(only_dev012, "DEV-012 " ++ name, entries.items, false);
        const nall = try sweep(dev010_011_012, "all " ++ name, entries.items, false);
        std.debug.print("evaltables fixes {s}: {d} calls; changed by DEV-010 {d}, DEV-011 {d}, DEV-012 {d}, all three {d}\n", .{ name, entries.items.len, n10, n11, n12, nall });
        try std.testing.expectEqual(w, [4]usize{ n10, n11, n12, nall });
    }
}

test "prepare_eval: replay every recorded call of the original, section by section" {
    const gpa = std.testing.allocator;
    var total: Counts = .{};
    for (runs) |name| {
        const n = try replay(gpa, name);
        std.debug.print("evaltables vectors {s}: prepare_eval {d} calls replayed, all equal (whole routine and every section)\n", .{ name, n.calls });
        total.calls += n.calls;
        for (0..nsec) |k| {
            total.alone[k] += n.alone[k];
            total.grouped[k] += n.grouped[k];
        }
    }
    var proved: usize = 0;
    for (et.sections, 0..) |s, k| {
        if (total.alone[k] > 0) proved += 1;
        std.debug.print("  {X:0>4}-{X:0>4} {s:<26} proved alone in {d} calls, with its neighbours in {d}\n", .{ s.start, s.end, s.name, total.alone[k], total.grouped[k] });
    }
    std.debug.print("evaltables: {d} calls, {d} of {d} sections proved separately\n", .{ total.calls, proved, et.sections.len });
}
