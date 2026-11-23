//! Differential tests of src/evalpawns.zig, src/pawnhash.zig, src/squaresums.zig and
//! src/staticeval.zig against calls recorded from the running original
//! (tests/golden/evalpawns/*.zst, made by tools/port/gen_evalpawns_vectors.py, whose
//! docstring defines the format).

const std = @import("std");
const builtin = @import("builtin");
const pos = @import("position.zig");
const EvalVars = @import("evalvars.zig").EvalVars;
const evalpawns = @import("evalpawns.zig");
const pawnEval = evalpawns.pawnEval;
const pawnhash = @import("pawnhash.zig");
const PawnHash = pawnhash.PawnHash;
const updateSquareSums = @import("squaresums.zig").updateSquareSums;
const se = @import("staticeval.zig");
const staticEval = se.staticEval;
const dg = @import("original.zig").dgroup;

comptime {
    // The image is copied to and from the fields' bytes.
    if (builtin.cpu.arch.endian() != .little) @compileError("the replay test assumes a little-endian host");
}

/// The recorder's image, in its order (gen_evalpawns_vectors.py IMAGE).
const Region = struct { name: []const u8, dg: u16, len: usize };
const regions = [_]Region{
    .{ .name = "board", .dg = 0x9EF6, .len = 120 },
    .{ .name = "piece lists", .dg = 0xA03A, .len = 32 },
    .{ .name = "White pawn attacks", .dg = 0xA51C, .len = 120 },
    .{ .name = "Black pawn attacks", .dg = 0x37DA, .len = 120 },
    .{ .name = "White pawns per file", .dg = 0xA8C8, .len = 10 },
    .{ .name = "Black pawns per file", .dg = 0x9EA8, .len = 10 },
    .{ .name = "pawn_count", .dg = 0x90AA, .len = 1 },
    .{ .name = "White pawns", .dg = 0xAB1E, .len = 1 },
    .{ .name = "Black pawns", .dg = 0x741A, .len = 1 },
    .{ .name = "late_endgame", .dg = 0xA72C, .len = 1 },
    .{ .name = "weak_pawns", .dg = 0x8EB6, .len = 1 },
    .{ .name = "White passed_pawns", .dg = 0xA6C2, .len = 1 },
    .{ .name = "Black passed_pawns", .dg = 0x9D8C, .len = 1 },
    .{ .name = "pawn_hash_key", .dg = 0x8CD2, .len = 6 },
    .{ .name = "piece_material_sum", .dg = 0x378E, .len = 2 },
    .{ .name = "style_normal", .dg = 0x1548, .len = 2 },
    .{ .name = "pawn_structure_weight", .dg = 0x2916, .len = 4 },
    .{ .name = "centrality_weight", .dg = 0x290E, .len = 4 },
    .{ .name = "piece_square_sum", .dg = 0x7182, .len = 2 },
    .{ .name = "White pawn_square_sum", .dg = 0x90B6, .len = 2 },
    .{ .name = "Black pawn_square_sum", .dg = 0x369A, .len = 2 },
    .{ .name = "material_balance_2", .dg = 0xA4C6, .len = 2 },
    .{ .name = "Black queen_gone_at_root", .dg = 0x9354, .len = 1 },
    .{ .name = "White queen_gone_at_root", .dg = 0x7100, .len = 1 },
    .{ .name = "material", .dg = 0x8DE4, .len = 4 },
    .{ .name = "piece_material", .dg = 0xAE38, .len = 4 },
    .{ .name = "piece_balance", .dg = 0xA8D2, .len = 2 },
    .{ .name = "total_material", .dg = 0xA420, .len = 2 },
    .{ .name = "king_file", .dg = 0xA22E, .len = 2 },
    .{ .name = "king_rank", .dg = 0x70F0, .len = 2 },
    .{ .name = "black_king_by_passer", .dg = 0x39AE, .len = 1 },
    .{ .name = "passer_flags", .dg = 0xA5F5, .len = 1 },
    .{ .name = "draw_flag", .dg = 0xA8DE, .len = 1 },
    .{ .name = "promotion_square", .dg = 0x8CCA, .len = 1 },
    .{ .name = "promotion_flags", .dg = 0x9EBA, .len = 1 },
    .{ .name = "piece_count", .dg = 0x931A, .len = 2 },
    .{ .name = "material_balance", .dg = 0xA35E, .len = 2 },
    .{ .name = "endgame", .dg = 0xA6C3, .len = 1 },
    .{ .name = "square_slot", .dg = 0xA28C, .len = 120 },
    .{ .name = "passed_pawns_weight", .dg = 0x291A, .len = 4 },
    .{ .name = "passer_rank_tables", .dg = 0x0144, .len = 80 },
    .{ .name = "passer table 746C", .dg = 0x746C, .len = 178 },
    .{ .name = "passer table 718C", .dg = 0x718C, .len = 178 },
    .{ .name = "passer table 90BA", .dg = 0x90BA, .len = 178 },
    .{ .name = "passer table AE46", .dg = 0xAE46, .len = 178 },
    .{ .name = "passer table A792", .dg = 0xA792, .len = 178 },
    .{ .name = "passer table 369E", .dg = 0x369E, .len = 178 },
    // The square-value tables, squares 0..99 only: they lie 108 words apart, and the
    // weak-pawn mask DG:8EB6 is White's queen table at square 102.
    .{ .name = "square values White P", .dg = 0xA8EC, .len = 200 },
    .{ .name = "square values White N", .dg = 0x75CA, .len = 200 },
    .{ .name = "square values White B", .dg = 0xAC2A, .len = 200 },
    .{ .name = "square values White R", .dg = 0x9182, .len = 200 },
    .{ .name = "square values White Q", .dg = 0x8DEA, .len = 200 },
    .{ .name = "square values Black P", .dg = 0xAA2C, .len = 200 },
    .{ .name = "square values Black N", .dg = 0x76A2, .len = 200 },
    .{ .name = "square values Black B", .dg = 0xACF4, .len = 200 },
    .{ .name = "square values Black R", .dg = 0x924A, .len = 200 },
    .{ .name = "square values Black Q", .dg = 0x8EB8, .len = 200 },
    .{ .name = "pawn hash, White to move (5A7B:174E)", .dg = 0, .len = 2560 },
    .{ .name = "pawn hash, Black to move (5A7B:6A7C)", .dg = 0, .len = 2560 },
};
const image_size = blk: {
    var n: usize = 0;
    for (regions) |r| n += r.len;
    break :blk n;
};
const Image = [image_size]u8;

const State = struct {
    p: pos.Position = .{},
    v: EvalVars = .{},
    h: PawnHash = .{},
};

fn transfer(comptime to_image: bool, s: *State, img: *Image) void {
    var key: [6]u8 = undefined;
    if (to_image) std.mem.writeInt(u48, &key, s.p.pawn_hash_key, .little);
    const p = &s.p;
    const v = &s.v;
    const sv = std.mem.asBytes(&v.square_values);
    const ph = std.mem.asBytes(&s.h.tables);
    const pt = std.mem.asBytes(&v.passer_tables);
    const parts = [_][]u8{
        &p.board,                                  &p.piece_list,
        &p.pawn_attacks[0],                        &p.pawn_attacks[1],
        &p.pawns_per_file[0],                      &p.pawns_per_file[1],
        std.mem.asBytes(&p.pawn_count),            std.mem.asBytes(&p.side_pawn_count[0]),
        std.mem.asBytes(&p.side_pawn_count[1]),    std.mem.asBytes(&v.late_endgame),
        std.mem.asBytes(&v.weak_pawns),            std.mem.asBytes(&v.passed_pawns[0]),
        std.mem.asBytes(&v.passed_pawns[1]),       &key,
        std.mem.asBytes(&p.piece_material_sum),    std.mem.asBytes(&v.style_normal),
        std.mem.asBytes(&v.pawn_structure_weight), std.mem.asBytes(&v.centrality_weight),
        std.mem.asBytes(&p.piece_square_sum),      std.mem.asBytes(&v.pawn_square_sum[0]),
        std.mem.asBytes(&v.pawn_square_sum[1]),    std.mem.asBytes(&p.material_balance_2),
        std.mem.asBytes(&v.queen_gone_at_root[1]), std.mem.asBytes(&v.queen_gone_at_root[0]),
        std.mem.asBytes(&p.material),              std.mem.asBytes(&p.piece_material),
        std.mem.asBytes(&p.piece_balance),         std.mem.asBytes(&p.total_material),
        std.mem.asBytes(&p.king_file),             std.mem.asBytes(&p.king_rank),
        std.mem.asBytes(&v.black_king_by_passer),  std.mem.asBytes(&v.passer_flags),
        std.mem.asBytes(&v.draw_flag),             std.mem.asBytes(&v.promotion_square),
        std.mem.asBytes(&v.promotion_flags),       std.mem.asBytes(&p.piece_count),
        std.mem.asBytes(&p.material_balance),      std.mem.asBytes(&v.endgame),
        &p.square_slot,                            std.mem.asBytes(&v.passed_pawns_weight),
        std.mem.asBytes(&v.passer_rank_tables),    pt[0..178],
        pt[178..356],                              pt[356..534],
        pt[534..712],                              pt[712..890],
        pt[890..1068],                             sv[0..][0..200],
        sv[200..][0..200],                         sv[400..][0..200],
        sv[600..][0..200],                         sv[800..][0..200],
        sv[1000..][0..200],                        sv[1200..][0..200],
        sv[1400..][0..200],                        sv[1600..][0..200],
        sv[1800..][0..200],                        ph[0..2560],
        ph[2560..5120],
    };
    comptime std.debug.assert(parts.len == regions.len);
    var o: usize = 0;
    inline for (parts, regions) |part, r| {
        std.debug.assert(part.len == r.len);
        if (to_image) @memcpy(img[o..][0..r.len], part) else @memcpy(part, img[o..][0..r.len]);
        o += r.len;
    }
    std.debug.assert(o == image_size);
    if (!to_image) s.p.pawn_hash_key = std.mem.readInt(u48, &key, .little);
}

fn describe(buf: []u8, off: usize) []const u8 {
    var o: usize = 0;
    for (regions) |r| {
        if (off < o + r.len) {
            if (r.dg == 0) return std.fmt.bufPrint(buf, "{s} byte {d} (entry {d}, +{d})", .{ r.name, off - o, (off - o) / 10, (off - o) % 10 }) catch r.name;
            return std.fmt.bufPrint(buf, "{s}[{d}] (DG:{X:0>4})", .{ r.name, off - o, r.dg + off - o }) catch r.name;
        }
        o += r.len;
    }
    return "?";
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
    /// Pass over a change list without applying it.
    fn skipDelta(c: *Cursor) void {
        const n = c.varint();
        for (0..n) |_| {
            _ = c.varint();
            _ = c.byte();
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

fn readVectors(gpa: std.mem.Allocator, name: []const u8) ![]u8 {
    var path_buf: [256]u8 = undefined;
    const dir = @import("build_options").golden_dir;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/evalpawns/{s}", .{ dir, name });
    const compressed = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, gpa, .limited(64 << 20));
    defer gpa.free(compressed);
    var in: std.Io.Reader = .fixed(compressed);
    const window = try gpa.alloc(u8, std.compress.zstd.default_window_len + std.compress.zstd.block_size_max);
    defer gpa.free(window);
    var zd = std.compress.zstd.Decompress.init(&in, window, .{});
    return zd.reader.allocRemaining(gpa, .limited(512 << 20));
}

const names = [_][]const u8{ "", "pawn_eval_wtm", "pawn_eval_btm", "pawn_hash_wtm", "pawn_hash_btm", "pawn_store_wtm", "pawn_store_btm", "clear_pawn_hash", "update_square_sums", "static_eval" };

const Counts = struct {
    /// Calls replayed and found equal, by record tag 1..9.
    by_tag: [10]usize = @splat(0),
    /// static_eval calls that ran the full body past its first section (2B9F:0A33).
    full_bodies: usize = 0,
    /// static_eval calls that returned from the full body's first section (special endings).
    section1_returns: usize = 0,
    hits: usize = 0,
    keyframes: usize = 0,
    /// DEV-053: the recorded exchange calls of the passed-pawn prefilters (2B9F:1BAA,
    /// 281E, made through the prefilter: equal pawn-attack counts), those whose prefilter
    /// DEV-053 closes (DEV-015 corrected in both), and of those the ones whose recorded
    /// result was negative (a passed-pawn threat flag the corrected call does not set).
    dev053_prefilter_calls: usize = 0,
    dev053_closed: usize = 0,
    dev053_closed_negative: usize = 0,
};

const se_053: se.Fixes = .{ .dev015_knight_test = true, .dev053_line_tables_other = true };

/// Whether static_eval's prefilter lets the exchange call at `site` (1BAA: a Black passer
/// on `sq`, White's pieces; 281E: a White passer, Black's pieces) through, when the pawn
/// attacks on the square are equal (2B9F:1AD6-1B79, 274A-27ED).
fn prefilterOpen(p: *const pos.Position, site: u16, sq: usize, fixes: se.Fixes) bool {
    if (site == 0x1BAA) {
        if (sq > 0x30 and p.board[sq - 10] == 0) return se.rooksOnLine(p, 0, sq, fixes);
        return se.whitePieceReaches(p, sq, fixes, .{});
    }
    if (sq < 0x47 and p.board[sq + 10] == 0) return se.rooksOnLine(p, 1, sq, fixes);
    return se.blackPieceReaches(p, sq, fixes, .{});
}

fn mismatch(name: []const u8, index: usize, tag: u8, args: []const u8, want_ax: ?u16, got_ax: ?u16, truth: *const Image, got: *const Image) error{MismatchWithOriginal} {
    var buf: [96]u8 = undefined;
    std.debug.print("\n{s}: call {d} differs: {s}({s})", .{ name, index, names[tag], args });
    if (want_ax) |w| std.debug.print(": AX want {X:0>4}, got {X:0>4}", .{ w, got_ax orelse 0 });
    std.debug.print("\n", .{});
    for (truth, got, 0..) |want, have, off| {
        if (want != have) {
            std.debug.print("  first differing byte: {s}: want {X:0>2}, got {X:0>2}\n", .{ describe(&buf, off), want, have });
            break;
        }
    }
    return error.MismatchWithOriginal;
}

/// Replay a vector file. `memo` (possibly empty) is attached to the pawn hash and kept
/// for the whole file, as the engine keeps it.
fn replay(gpa: std.mem.Allocator, name: []const u8, memo: []pawnhash.Memo.Slot) !Counts {
    const data = try readVectors(gpa, name);
    defer gpa.free(data);
    var c: Cursor = .{ .d = data };
    try std.testing.expectEqualSlices(u8, "MCEP", c.take(4));
    try std.testing.expectEqual(@as(u16, 4), c.int(u16));
    try std.testing.expectEqual(@as(u16, image_size), c.int(u16));
    // The constant tables, as they were in the running original, equal what the port
    // reads from the executable: DG:0042, 0850, 0102 (five word tables), 15E8 (two byte
    // tables), 100A, 1DDC, and the bytes section 1 of static_eval reads by square
    // (DG:0788..084F) and by a square difference (DG:0CBC..0D57).
    const const_size = c.int(u16);
    const const_ranges = [_][2]usize{ .{ 0x0042, 8 }, .{ 0x0850, 120 }, .{ 0x0102, 50 }, .{ 0x15E8, 12 }, .{ 0x100A, 120 }, .{ 0x1DDC, 18 }, .{ 0x0788, 0xC8 }, .{ 0x0CBC, 0x9C }, .{ 0x0134, 0x10 }, .{ 0x0193, 0x119 }, .{ 0x042A, 14 }, .{ 0x0E16, 100 }, .{ 0x0E7A, 0x190 }, .{ 0x0CB0, 0xB0 }, .{ 0x10DC, 120 }, .{ 0x11A4, 0x60 }, .{ 0x128C, 14 }, .{ 0x1078, 120 }, .{ 0x097E, 0x3E4 }, .{ 0x0438, 14 }, .{ 0x1140, 120 }, .{ 0x02A0, 0x52 } };
    var total_const: usize = 0;
    for (const_ranges) |r| total_const += r[1];
    try std.testing.expectEqual(total_const, const_size);
    inline for (const_ranges) |r| try std.testing.expectEqualSlices(u8, c.take(r[1]), &dg(r[0], r[1]));

    var truth: Image = c.take(image_size)[0..image_size].*;
    const s = try gpa.create(State);
    defer gpa.destroy(s);
    s.* = .{};
    if (memo.len != 0) s.h.attachMemo(memo);
    var got: Image = undefined;
    var counts: Counts = .{};
    var index: usize = 0;
    var args_buf: [64]u8 = undefined;
    var previous_calls: CalleeReplay = .{ .s = s, .data = data };
    var previous_stray: se.StrayBytes = .{};
    while (true) : (index += 1) {
        const tag = c.byte();
        switch (tag) {
            0 => {
                for (1..10) |t| {
                    const recorded = c.int(u32);
                    const replayed = counts.by_tag[t];
                    try std.testing.expectEqual(@as(usize, recorded), replayed);
                }
                return counts;
            },
            10 => {
                // A keyframe: the replayed chain of changes gives the recorded image.
                try std.testing.expectEqualSlices(u8, c.take(image_size), &truth);
                counts.keyframes += 1;
                continue;
            },
            1...9 => {},
            else => return error.BadRecordTag,
        }
        c.apply(&truth);
        transfer(false, s, &truth);
        var want_ax: ?u16 = null;
        var got_ax: ?u16 = null;
        var args: []const u8 = "";
        switch (tag) {
            1, 2 => {
                want_ax = c.int(u16);
                got_ax = @bitCast(if (tag == 1) pawnEval(&s.p, &s.v, .white) else pawnEval(&s.p, &s.v, .black));
            },
            3, 4 => {
                want_ax = c.int(u16);
                if (c.byte() != 0) counts.hits += 1;
                got_ax = @bitCast(if (tag == 3) s.h.probe(&s.p, &s.v, .white) else s.h.probe(&s.p, &s.v, .black));
            },
            5, 6 => {
                want_ax = c.int(u16);
                got_ax = if (tag == 5) s.h.store(&s.p, &s.v, .white) else s.h.store(&s.p, &s.v, .black);
            },
            7 => s.h.clear(),
            8 => {
                const m = c.take(4);
                const move: pos.Move = .{ .from = m[0], .to = m[1], .flag = m[2], .score = m[3] };
                args = std.fmt.bufPrint(&args_buf, "from {d}, to {d}, flag {d}", .{ m[0], m[1], m[2] }) catch "";
                updateSquareSums(&s.p, &s.v, move);
            },
            9 => {
                const side = c.int(u16);
                const arg2 = c.int(u16);
                const path = c.byte();
                const ax = c.int(u16);
                args = std.fmt.bufPrint(&args_buf, "side {d}, arg2 {d}", .{ side, arg2 }) catch "";
                var reached = false;
                var cp: []const u8 = &.{};
                // The callee records of this call, then those of the call before it: a
                // call that restarts itself (0A6E) is recorded after the call it made.
                var replay_list: CalleeReplay = .{ .s = s, .data = data };
                if (path == 1) {
                    reached = c.byte() != 0;
                    if (reached) cp = c.take(2 + 2 * 6 + 5 + 2);
                    const n = c.byte();
                    for (0..n) |_| {
                        const rec: CalleeRecord = .{ .site = c.int(u16), .a0 = c.int(u16), .a1 = c.int(u16), .ax = c.int(u16), .delta = c.i };
                        c.skipDelta();
                        replay_list.push(rec);
                    }
                    if (c.byte() != 0) {
                        // The state at 2B9F:10B6 (Black's loop head), recorded for a port
                        // that stops there; this one runs to the end.
                        _ = c.take(2 + 2 * 10 + 7);
                        c.skipDelta();
                    }
                }
                const own_calls = replay_list.n;
                for (replay_list.recs[0..own_calls]) |rec| {
                    if (rec.site != 0x1BAA and rec.site != 0x281E) continue;
                    const sq: usize = rec.a0;
                    if (sq < 21 or sq > 98 or s.p.pawn_attacks[0][sq] != s.p.pawn_attacks[1][sq]) continue;
                    counts.dev053_prefilter_calls += 1;
                    if (prefilterOpen(&s.p, rec.site, sq, se.Fixes.corrected) and !prefilterOpen(&s.p, rec.site, sq, se_053)) {
                        counts.dev053_closed += 1;
                        if (@as(i16, @bitCast(rec.ax)) < 0) counts.dev053_closed_negative += 1;
                    }
                }
                for (previous_calls.recs[0..previous_calls.n]) |rec| replay_list.push(rec);
                const iface = replay_list.interface();
                // DEV-015: the frame bytes the original reads without writing them, from
                // the recorded call (and from the call it restarts with, recorded before it).
                const stray: se.StrayBytes = if (reached) .{ .bp29 = cp[19], .bp2B = cp[20] } else .{};
                const r = staticEval(&s.p, &s.v, &s.h, &iface, side, arg2, se.Fixes.original, .{ stray, previous_stray });
                previous_stray = stray;
                if (replay_list.failed) |msg| {
                    std.debug.print("\n{s}: call {d}: static_eval({s}): {s}\n", .{ name, index, args, msg });
                    return error.MismatchWithOriginal;
                }
                previous_calls = .{ .s = s, .data = data };
                for (replay_list.recs[0..own_calls]) |rec| previous_calls.push(rec);
                // Every call is compared whole: AX, and every byte of the image at the return.
                want_ax = ax;
                got_ax = @bitCast(r);
                if (path == 1) {
                    if (reached) counts.full_bodies += 1 else counts.section1_returns += 1;
                }
            },
            else => unreachable,
        }
        c.apply(&truth);
        transfer(true, s, &got);
        if (want_ax != got_ax or !std.mem.eql(u8, &truth, &got)) {
            return mismatch(name, index, tag, args, want_ax, got_ax, &truth, &got);
        }
        counts.by_tag[tag] += 1;
    }
}

const runs = [_][]const u8{ "A.zst", "B.zst", "C.zst", "D.zst", "E.zst", "F.zst" };

test "pawn evaluation, pawn hash, update_square_sums, static_eval: replay every recorded call of the original" {
    const gpa = std.testing.allocator;
    var total: Counts = .{};
    for (runs) |name| {
        const n = try replay(gpa, name, &.{});
        std.debug.print("evalpawns vectors {s}:", .{name});
        for (1..10) |t| std.debug.print(" {s} {d},", .{ names[t], n.by_tag[t] });
        std.debug.print(" (pawn-hash hits {d}; static_eval full bodies {d}, of which {d} returned from section 1; keyframes {d}) all equal\n", .{ n.hits, n.full_bodies + n.section1_returns, n.section1_returns, n.keyframes });
        for (1..10) |t| total.by_tag[t] += n.by_tag[t];
        total.section1_returns += n.section1_returns;
        total.full_bodies += n.full_bodies;
        total.hits += n.hits;
        total.dev053_prefilter_calls += n.dev053_prefilter_calls;
        total.dev053_closed += n.dev053_closed;
        total.dev053_closed_negative += n.dev053_closed_negative;
    }
    std.debug.print("DEV-053: of {d} recorded exchange calls through static_eval's passed-pawn prefilters (2B9F:1BAA, 281E), the correction closes the prefilter of {d}; {d} of those returned a negative exchange (a threat flag lost)\n", .{ total.dev053_prefilter_calls, total.dev053_closed, total.dev053_closed_negative });
    std.debug.print("evalpawns vectors total:", .{});
    for (1..10) |t| std.debug.print(" {s} {d},", .{ names[t], total.by_tag[t] });
    std.debug.print(" (static_eval full bodies {d}, of which {d} returned from section 1)\n", .{ total.full_bodies + total.section1_returns, total.section1_returns });
}

test "pawn hash: the custom style's weight truncates toward zero" {
    // 4793:8AF0 is the C run-time's long division: -7 * 150 / 100 = -10.5 -> -10.
    try std.testing.expectEqual(@as(i16, -10), pawnhash.scalePercent(-7, 150));
    try std.testing.expectEqual(@as(i16, 10), pawnhash.scalePercent(7, 150));
    try std.testing.expectEqual(@as(i16, -7), pawnhash.scalePercent(-7, 100));
}

test "pawn hash: an entry is 10 bytes, found by byte 4 of the key and verified by the other five" {
    var s: State = .{};
    s.p.pawn_hash_key = 0x01AB_0204_0506; // bytes 06 05 04 02 AB 01, little-endian
    s.p.pawn_count = 0;
    const first = s.h.probe(&s.p, &s.v, .white);
    const e = s.h.tables[0][0xAB];
    try std.testing.expectEqualSlices(u8, &.{ 0x06, 0x05, 0x04, 0x02, 0x01 }, &e.key);
    try std.testing.expectEqual(@as(usize, 10), @sizeOf(pawnhash.Entry));
    // Change the evaluator's inputs: a hit returns the stored score, not a fresh one.
    s.v.passed_pawns = .{ 0xFF, 0xFF };
    s.p.pawns_per_file[0][1] = 3;
    try std.testing.expectEqual(first, s.h.probe(&s.p, &s.v, .white));
    try std.testing.expectEqual([2]u8{ 0, 0 }, s.v.passed_pawns);
    // Byte 5 differs: a miss, which replaces the entry.
    s.p.pawn_hash_key ^= 0x8000_0000_0000;
    _ = s.h.probe(&s.p, &s.v, .white);
    try std.testing.expectEqual(@as(u8, 0x81), s.h.tables[0][0xAB].key[4]);
}

/// A call static_eval made to a routine outside it, as recorded.
const CalleeRecord = struct { site: u16, a0: u16, a1: u16, ax: u16, delta: usize };

/// The routines static_eval calls that are not ported yet, implemented from the
/// recorded calls: each call must be the next recorded one, to the same routine with the
/// same arguments; it returns the recorded AX and makes the recorded changes.
const CalleeReplay = struct {
    s: *State,
    data: []const u8,
    recs: [64]CalleeRecord = undefined,
    n: usize = 0,
    next: usize = 0,
    failed: ?[]const u8 = null,
    msg_buf: [160]u8 = undefined,

    fn push(r: *CalleeReplay, rec: CalleeRecord) void {
        if (r.n < r.recs.len) {
            r.recs[r.n] = rec;
            r.n += 1;
        }
    }

    fn call(r: *CalleeReplay, sites: []const u16, a0: u16, a1: ?u16) u16 {
        if (r.failed != null) return 0;
        if (r.next >= r.n) {
            r.failed = std.fmt.bufPrint(&r.msg_buf, "the port called 2B9F:{X:0>4}'s routine ({d}, {d}); the original made no further call", .{ sites[0], a0, a1 orelse 0 }) catch "an extra call";
            return 0;
        }
        const rec = r.recs[r.next];
        r.next += 1;
        if (std.mem.indexOfScalar(u16, sites, rec.site) == null or rec.a0 != a0 or (a1 != null and rec.a1 != a1.?)) {
            r.failed = std.fmt.bufPrint(&r.msg_buf, "the port called the routine of 2B9F:{X:0>4} ({d}, {d}); the original called at 2B9F:{X:0>4} ({d}, {d})", .{ sites[0], a0, a1 orelse 0, rec.site, rec.a0, rec.a1 }) catch "a different call";
            return 0;
        }
        var img: Image = undefined;
        transfer(true, r.s, &img);
        var cc: Cursor = .{ .d = r.data, .i = rec.delta };
        cc.apply(&img);
        transfer(false, r.s, &img);
        return rec.ax;
    }

    fn self(ctx: *anyopaque) *CalleeReplay {
        return @ptrCast(@alignCast(ctx));
    }
    fn seeWhite(ctx: *anyopaque, sq: u16, v: u16) u16 {
        return self(ctx).call(&.{0x0C90}, sq, v);
    }
    fn seeBlack(ctx: *anyopaque, sq: u16, v: u16) u16 {
        return self(ctx).call(&.{0x330C}, sq, v);
    }
    fn r4CEC(ctx: *anyopaque, sq: u16, v: u16) u16 {
        return self(ctx).call(&.{ 0x105F, 0x1BAA }, sq, v);
    }
    fn r41B6(ctx: *anyopaque, sq: u16, v: u16) u16 {
        return self(ctx).call(&.{ 0x281E, 0x36E5 }, sq, v);
    }
    fn r4A76(ctx: *anyopaque, sq: u16) u16 {
        return self(ctx).call(&.{0x19B1}, sq, null);
    }
    fn r4AD4(ctx: *anyopaque, sq: u16) u16 {
        return self(ctx).call(&.{0x262B}, sq, null);
    }

    fn interface(r: *CalleeReplay) se.Callees {
        return .{ .see_white = seeWhite, .see_black = seeBlack, .r4793_4CEC = r4CEC, .r4793_41B6 = r41B6, .r2B9F_4A76 = r4A76, .r2B9F_4AD4 = r4AD4, .ctx = r };
    }
};

test "DEV-015: the reachability tests OR in a never-written frame byte; corrected, the knight test" {
    // A position where only one knight could reach the square: every other list entry
    // is set to a value whose table bytes are all 0 for this square.
    var p: pos.Position = .{};
    const sq: usize = 43; // c3
    const quiet: u8 = blk: {
        for (0..256) |e| {
            p.piece_list = @splat(@intCast(e));
            var any: u8 = 0;
            for (0..32) |i| {
                for ([_]usize{ 0x0B66, 0x0A68, 0x0C64, 0x0CFF }) |t| any |= se.constByteForTest(t + sq - p.piece_list[i]);
            }
            if (any == 0) break :blk @intCast(e);
        }
        return error.NoQuietEntry;
    };
    p.piece_list = @splat(quiet);
    // White: the knight in slot 1 a knight's move away (d = 21); its test is the one the
    // original drops. Black: the knight in slot 0, likewise.
    p.piece_list[1] = sq - 21;
    p.piece_list[16 + 0] = sq - 21;
    const zero: se.StrayBytes = .{};
    // The original with a 0 stray byte misses the knight; corrected, it sees it.
    try std.testing.expect(!se.whitePieceReaches(&p, sq, se.Fixes.original, zero));
    try std.testing.expect(se.whitePieceReaches(&p, sq, se.Fixes.corrected, zero));
    try std.testing.expect(!se.blackPieceReaches(&p, sq, se.Fixes.original, zero));
    try std.testing.expect(se.blackPieceReaches(&p, sq, se.Fixes.corrected, zero));
    // A non-zero stray byte makes the original say "reachable" whatever the pieces.
    p.piece_list[1] = quiet;
    p.piece_list[16 + 0] = quiet;
    try std.testing.expect(se.whitePieceReaches(&p, sq, se.Fixes.original, .{ .bp29 = 1 }));
    try std.testing.expect(!se.whitePieceReaches(&p, sq, se.Fixes.corrected, .{ .bp29 = 1 }));
    try std.testing.expect(se.blackPieceReaches(&p, sq, se.Fixes.original, .{ .bp2B = 1 }));
    try std.testing.expect(!se.blackPieceReaches(&p, sq, se.Fixes.corrected, .{ .bp2B = 1 }));
    // The knight of the other slot is tested by both.
    p.piece_list[0] = sq - 21;
    try std.testing.expect(se.whitePieceReaches(&p, sq, se.Fixes.original, zero));
    try std.testing.expect(se.whitePieceReaches(&p, sq, se.Fixes.corrected, zero));
}

// ---------------------------------------------------------------------------
// The pawn evaluators against their reference (src/evalpawns_reference.zig, the
// original's decision tree as first ported) on inputs beyond the recorded ones.
// ---------------------------------------------------------------------------

const ref = @import("evalpawns_reference.zig");
const mg = @import("movegen.zig");
const see_mod = @import("see.zig");
const setup = @import("setup.zig");
const file_of_sq: [120]u8 = dg(0x100A, 120);

const PawnDiff = struct {
    cases: usize = 0,

    /// Both routines, each way of evaluating (one pawn at a time, and all at once where
    /// the target allows), with `late_endgame` as given: the return value and every
    /// EvalVars field must agree with the reference.
    fn check(d: *PawnDiff, p: *const pos.Position, v0: *const EvalVars) !void {
        inline for (.{ false, true }) |lanes| {
            if (!lanes or evalpawns.lanes_available) try d.checkWith(p, v0, lanes);
        }
    }

    fn checkWith(d: *PawnDiff, p: *const pos.Position, v0: *const EvalVars, comptime lanes: bool) !void {
        inline for (.{ Side.white, Side.black }) |stm| {
            var a = v0.*;
            var b = v0.*;
            const ra = evalpawns.pawnEvalWith(p, &a, stm, lanes);
            const rb = ref.pawnEval(p, &b, stm);
            if (ra != rb or !std.meta.eql(a, b)) {
                std.debug.print("\npawnEval({s}, lanes {}) differs from the reference after {d} cases: score {d} / {d}, weak {X:0>2} / {X:0>2}, passed {X:0>2} {X:0>2} / {X:0>2} {X:0>2}, late {d}, pawn_count {d}\n", .{ @tagName(stm), lanes, d.cases, ra, rb, a.weak_pawns, b.weak_pawns, a.passed_pawns[0], a.passed_pawns[1], b.passed_pawns[0], b.passed_pawns[1], v0.late_endgame, p.pawn_count });
                // Each slot alone (the others emptied): which pawn's terms differ.
                for (0..32) |e| {
                    if (e % 16 < 8) continue;
                    var q = p.*;
                    for (8..16) |s| {
                        if (s != e % 16 or e < 16) q.piece_list[16 + s] = 0xFF;
                        if (s != e % 16 or e >= 16) q.piece_list[s] = 0xFF;
                    }
                    var a1 = v0.*;
                    var b1 = v0.*;
                    const x = evalpawns.pawnEvalWith(&q, &a1, stm, lanes);
                    const y = ref.pawnEval(&q, &b1, stm);
                    std.debug.print("  entry {d}: square {d}: {d} / {d}{s}\n", .{ e, p.piece_list[e], x, y, if (x != y or !std.meta.eql(a1, b1)) " DIFFERS" else "" });
                    if (x != y and p.piece_list[e] < 120) {
                        const sq = p.piece_list[e];
                        for ([_]i32{ -40, -30, -20, -11, -10, -9, -1, 0, 1, 9, 10, 11, 20, 30, 40 }) |o| {
                            const i = @as(i32, sq) + o;
                            if (i < 0 or i >= 120) continue;
                            const u: usize = @intCast(i);
                            std.debug.print("    {d:>3}: board {d:>2} wa {d:>4} ba {d:>4}\n", .{ o, p.board[u], @as(i8, @bitCast(p.pawn_attacks[0][u])), @as(i8, @bitCast(p.pawn_attacks[1][u])) });
                        }
                        std.debug.print("    wpf {any}\n    bpf {any}\n", .{ p.pawns_per_file[0], p.pawns_per_file[1] });
                    }
                }
                return error.DiffersFromReference;
            }
            d.cases += 1;
        }
    }
};

const Side = pos.Side;

/// The squares the space terms read: values there are kept small, since the original
/// indexes a 6-byte table with them (a larger count is not a position).
fn spaceSquare(sq: usize) bool {
    return (sq >= 42 and sq <= 47) or (sq >= 52 and sq <= 57) or (sq >= 62 and sq <= 67) or (sq >= 72 and sq <= 77);
}

/// Rebuild the pawn tables from the pawns on the board named by the piece lists.
fn rebuildPawnTables(p: *pos.Position) void {
    p.pawn_attacks = @splat(@splat(0));
    p.pawns_per_file = @splat(@splat(0));
    p.side_pawn_count = .{ 0, 0 };
    for (8..16) |s| {
        const w = p.piece_list[s];
        if (w < 120 and p.board[w] == pos.white_pawn) {
            p.pawn_attacks[0][w + 9] +%= 1;
            p.pawn_attacks[0][w + 11] +%= 1;
            p.pawns_per_file[0][file_of_sq[w]] +%= 1;
            p.side_pawn_count[0] += 1;
        }
        const b = p.piece_list[16 + s];
        if (b < 120 and p.board[b] == pos.black_pawn) {
            p.pawn_attacks[1][b - 9] +%= 1;
            p.pawn_attacks[1][b - 11] +%= 1;
            p.pawns_per_file[1][file_of_sq[b]] +%= 1;
            p.side_pawn_count[1] += 1;
        }
    }
    p.pawn_count = p.side_pawn_count[0] + p.side_pawn_count[1];
}

fn randomSquare(r: std.Random, lo_rank: u8, hi_rank: u8) u8 {
    const rank = lo_rank + r.uintLessThan(u8, hi_rank - lo_rank + 1);
    return 21 + 10 * rank + r.uintLessThan(u8, 8);
}

/// A random pawn structure: up to 8 pawns a side anywhere on ranks 1-8 (mostly 2-7),
/// in random slots; empty slots hold a captured mark or a stale square; other pieces
/// scattered. With `garble`, some table bytes are then set to arbitrary values.
fn randomStructure(r: std.Random, p: *pos.Position, garble: bool) void {
    p.board = @import("fen.zig").emptyBoard();
    const others = [_]u8{ 2, 3, 4, 5, 6, 9, 10, 11, 12, 13 };
    for (0..r.uintLessThan(usize, 12)) |_| p.board[randomSquare(r, 0, 7)] = others[r.uintLessThan(usize, others.len)];
    inline for (.{ 0, 16 }, .{ pos.white_pawn, pos.black_pawn }) |base, code| {
        const n = r.uintAtMost(usize, 8);
        var slots: [8]u8 = .{ 8, 9, 10, 11, 12, 13, 14, 15 };
        r.shuffle(u8, &slots);
        for (slots, 0..) |s, k| {
            if (k < n) {
                var sq: u8 = undefined;
                while (true) {
                    sq = if (r.uintLessThan(u8, 10) == 0) randomSquare(r, 0, 7) else randomSquare(r, 1, 6);
                    if (p.board[sq] != pos.white_pawn and p.board[sq] != pos.black_pawn) break;
                }
                p.board[sq] = code;
                p.piece_list[base + s] = sq;
            } else switch (r.uintLessThan(u8, 3)) {
                0, 1 => p.piece_list[base + s] = randomSquare(r, 0, 7) + 0x63,
                else => p.piece_list[base + s] = randomSquare(r, 0, 7), // stale or promoted
            }
        }
    }
    rebuildPawnTables(p);
    if (r.uintLessThan(u8, 8) == 0) p.pawn_count = r.int(u8);
    if (garble) {
        const odd = [_]u8{ 0, 1, 2, 3, 4, 0x7F, 0x80, 0x81, 0xFE, 0xFF };
        for (0..1 + r.uintLessThan(usize, 12)) |_| {
            const sq = 21 + r.uintLessThan(usize, 98);
            const t = r.uintLessThan(usize, 2);
            p.pawn_attacks[t][sq] = if (spaceSquare(sq) or sq == 44 or sq == 45 or sq == 74 or sq == 75) r.uintAtMost(u8, 2) else odd[r.uintLessThan(usize, odd.len)];
        }
        for (0..r.uintLessThan(usize, 4)) |_| p.pawns_per_file[r.uintLessThan(usize, 2)][r.uintLessThan(usize, 10)] = odd[r.uintLessThan(usize, odd.len)];
    }
}

test "pawn evaluators: equal to the reference on random structures, random games and changed recorded positions" {
    const gpa = std.testing.allocator;
    var prng: std.Random.DefaultPrng = .init(0x5EED_9A57);
    const r = prng.random();
    var d: PawnDiff = .{};
    const s = try gpa.create(State);
    defer gpa.destroy(s);
    s.* = .{};
    const v = &s.v;

    // Random structures, consistent and garbled.
    for (0..300_000) |i| {
        randomStructure(r, &s.p, i % 3 == 2);
        v.late_endgame = @intFromBool(r.boolean());
        try d.check(&s.p, v);
    }

    // Random games from the start: pseudo-legal moves from the ported generator, captures
    // preferred half the time, made with make_move; every position is evaluated.
    {
        const sv = try gpa.create(mg.SearchVars);
        defer gpa.destroy(sv);
        sv.* = .{};
        const setup_vars = try gpa.create(setup.SetupVars);
        defer gpa.destroy(setup_vars);
        var scratch: see_mod.Scratch = .{};
        var list: mg.MoveList = undefined;
        var games: usize = 0;
        var positions: usize = 0;
        while (positions < 300_000) : (games += 1) {
            setup_vars.* = .{};
            s.p = .{};
            setup.newGame(&s.p, setup_vars);
            var side: Side = .white;
            for (0..60) |ply| {
                const n = mg.genAllMoves(.corrected, &s.p, &scratch, sv, &list, side, ply, .{});
                if (n == mg.king_capture or n == 0) break;
                var pick = r.uintLessThan(usize, n);
                if (r.boolean()) {
                    var captures: [mg.list_len]usize = undefined;
                    var k: usize = 0;
                    for (list[0..n], 0..) |m, j| {
                        if (s.p.board[m.to] != pos.empty) {
                            captures[k] = j;
                            k += 1;
                        }
                    }
                    if (k != 0) pick = captures[r.uintLessThan(usize, k)];
                }
                // A move that takes a king ends the game (the generator lists some).
                const target = s.p.board[list[pick].to];
                if (target == pos.white_king or target == pos.black_king) break;
                var undo: pos.Undo = .{};
                s.p.makeMove(list[pick], side, ply, &undo);
                side = side.other();
                v.late_endgame = @intFromBool(r.uintLessThan(u8, 4) == 0);
                try d.check(&s.p, v);
                positions += 1;
            }
        }
        try std.testing.expect(games > 1000);
    }

    // The recorded positions, as recorded and then changed: a pawn moved, removed or
    // added, a piece dropped on a square, the flag flipped, the tables rebuilt.
    {
        var bd: BenchData = .{};
        defer bd.deinit(gpa);
        for ([_][]const u8{ "C.zst", "D.zst" }) |name| try collect(gpa, name, &bd, std.math.maxInt(usize));
        for ([_][]const PawnInput{ bd.eval_inputs.items, bd.hash_inputs.items }) |inputs| {
            for (inputs) |*in| {
                in.put(&s.p, v);
                try d.check(&s.p, v);
                for (0..2) |_| {
                    const side: usize = r.uintLessThan(usize, 2);
                    const slot = 16 * side + 8 + r.uintLessThan(usize, 8);
                    const code: u8 = if (side == 0) pos.white_pawn else pos.black_pawn;
                    const old = s.p.piece_list[slot];
                    switch (r.uintLessThan(u8, 4)) {
                        0 => { // move or add the pawn
                            if (old < 120 and s.p.board[old] == code) s.p.board[old] = pos.empty;
                            const sq = randomSquare(r, 1, 6);
                            s.p.board[sq] = code;
                            s.p.piece_list[slot] = sq;
                        },
                        1 => { // capture it
                            if (old < 120) {
                                s.p.board[old] = pos.empty;
                                s.p.piece_list[slot] = old + 0x63;
                            }
                        },
                        2 => {
                            const codes = [_]u8{ 0, 2, 5, 9, 12 };
                            s.p.board[randomSquare(r, 1, 6)] = codes[r.uintLessThan(usize, codes.len)];
                        },
                        else => v.late_endgame ^= 1,
                    }
                }
                rebuildPawnTables(&s.p);
                try d.check(&s.p, v);
            }
        }
    }
    std.debug.print("pawn evaluators: {d} calls equal to the reference (vector lanes {s})\n", .{ d.cases, if (evalpawns.lanes_available) "included" else "not available on this target" });
    try std.testing.expect(d.cases >= 1_000_000);
}

// ---------------------------------------------------------------------------
// Benchmarks (src/bench.zig): the recorded calls, decoded once, then timed.
// ---------------------------------------------------------------------------

const bench = @import("bench.zig");

/// What the pawn evaluators read, and the probe's other inputs.
const PawnInput = struct {
    board: [120]u8,
    piece_list: [32]u8,
    pawn_attacks: [2][120]u8,
    pawns_per_file: [2][10]u8,
    pawn_count: u8,
    late_endgame: u8,
    pawn_hash_key: u48,
    piece_material_sum: u16,
    style_normal: u16,
    pawn_structure_weight: i32,

    fn take(s: *const State) PawnInput {
        return .{ .board = s.p.board, .piece_list = s.p.piece_list, .pawn_attacks = s.p.pawn_attacks, .pawns_per_file = s.p.pawns_per_file, .pawn_count = s.p.pawn_count, .late_endgame = s.v.late_endgame, .pawn_hash_key = s.p.pawn_hash_key, .piece_material_sum = s.p.piece_material_sum, .style_normal = s.v.style_normal, .pawn_structure_weight = s.v.pawn_structure_weight };
    }
    inline fn put(in: *const PawnInput, p: *pos.Position, v: *EvalVars) void {
        p.board = in.board;
        p.piece_list = in.piece_list;
        p.pawn_attacks = in.pawn_attacks;
        p.pawns_per_file = in.pawns_per_file;
        p.pawn_count = in.pawn_count;
        v.late_endgame = in.late_endgame;
        p.pawn_hash_key = in.pawn_hash_key;
        p.piece_material_sum = in.piece_material_sum;
        v.style_normal = in.style_normal;
        v.pawn_structure_weight = in.pawn_structure_weight;
    }
};

/// A static_eval call: the whole state at entry and the callee results in order.
const StaticCall = struct {
    p: pos.Position,
    v: EvalVars,
    side: u16,
    arg2: u16,
    stray: [2]se.StrayBytes,
    ax_start: u32,
    ax_n: u32,
    full: bool,
};

const BenchData = struct {
    /// Tag 1/2 calls (the evaluators), in order.
    eval_tags: std.ArrayList(u8) = .empty,
    eval_inputs: std.ArrayList(PawnInput) = .empty,
    /// Tags 3..7 (probe, store, clear), in order, with each file's hash at its first.
    hash_tags: std.ArrayList(u8) = .empty,
    hash_inputs: std.ArrayList(PawnInput) = .empty,
    hash_file_start: std.ArrayList(u32) = .empty,
    hash_initial: std.ArrayList(PawnHash) = .empty,
    statics: std.ArrayList(StaticCall) = .empty,
    static_ax: std.ArrayList(u16) = .empty,

    fn deinit(d: *BenchData, gpa: std.mem.Allocator) void {
        d.eval_tags.deinit(gpa);
        d.eval_inputs.deinit(gpa);
        d.hash_tags.deinit(gpa);
        d.hash_inputs.deinit(gpa);
        d.hash_file_start.deinit(gpa);
        d.hash_initial.deinit(gpa);
        d.statics.deinit(gpa);
        d.static_ax.deinit(gpa);
    }
};

/// Walk a vector file's chain of images and keep the inputs of every call (static_eval:
/// every `static_every`-th call).
fn collect(gpa: std.mem.Allocator, name: []const u8, d: *BenchData, static_every: usize) !void {
    const data = try readVectors(gpa, name);
    defer gpa.free(data);
    var c: Cursor = .{ .d = data };
    _ = c.take(4);
    _ = c.int(u16);
    _ = c.int(u16);
    const const_size = c.int(u16);
    _ = c.take(const_size);
    var truth: Image = c.take(image_size)[0..image_size].*;
    const s = try gpa.create(State);
    defer gpa.destroy(s);
    s.* = .{};
    var first_hash_op = true;
    var static_index: usize = 0;
    while (true) {
        const tag = c.byte();
        switch (tag) {
            0 => return,
            10 => {
                _ = c.take(image_size);
                continue;
            },
            1...9 => {},
            else => return error.BadRecordTag,
        }
        c.apply(&truth);
        transfer(false, s, &truth);
        switch (tag) {
            1, 2 => {
                _ = c.int(u16);
                try d.eval_tags.append(gpa, tag);
                try d.eval_inputs.append(gpa, PawnInput.take(s));
            },
            3...7 => {
                if (tag == 3 or tag == 4) {
                    _ = c.int(u16);
                    _ = c.byte();
                } else if (tag == 5 or tag == 6) {
                    _ = c.int(u16);
                }
                if (first_hash_op) {
                    first_hash_op = false;
                    try d.hash_file_start.append(gpa, @intCast(d.hash_tags.items.len));
                    try d.hash_initial.append(gpa, s.h);
                }
                try d.hash_tags.append(gpa, tag);
                try d.hash_inputs.append(gpa, PawnInput.take(s));
            },
            8 => _ = c.take(4),
            9 => {
                const side = c.int(u16);
                const arg2 = c.int(u16);
                const path = c.byte();
                _ = c.int(u16);
                var reached = false;
                var cp: []const u8 = &.{};
                const ax_start = d.static_ax.items.len;
                if (path == 1) {
                    reached = c.byte() != 0;
                    if (reached) cp = c.take(2 + 2 * 6 + 5 + 2);
                    const n = c.byte();
                    for (0..n) |_| {
                        _ = c.int(u16);
                        _ = c.int(u16);
                        _ = c.int(u16);
                        try d.static_ax.append(gpa, c.int(u16));
                        c.skipDelta();
                    }
                    if (c.byte() != 0) {
                        _ = c.take(2 + 2 * 10 + 7);
                        c.skipDelta();
                    }
                }
                const stray: se.StrayBytes = if (reached) .{ .bp29 = cp[19], .bp2B = cp[20] } else .{};
                if (static_index % static_every == 0) {
                    try d.statics.append(gpa, .{ .p = s.p, .v = s.v, .side = side, .arg2 = arg2, .stray = .{ stray, stray }, .ax_start = @intCast(ax_start), .ax_n = @intCast(d.static_ax.items.len - ax_start), .full = path == 1 });
                } else {
                    d.static_ax.shrinkRetainingCapacity(ax_start);
                }
                static_index += 1;
            },
            else => unreachable,
        }
        c.apply(&truth);
    }
}

/// Callees for timing static_eval: each returns the next recorded result. The changes
/// the original's callee made are not applied, so the work after a call is
/// representative, not exact.
const BenchCallees = struct {
    ax: []const u16,
    i: usize = 0,

    fn next(ctx: *anyopaque) u16 {
        const r: *BenchCallees = @ptrCast(@alignCast(ctx));
        if (r.i >= r.ax.len) return 0;
        r.i += 1;
        return r.ax[r.i - 1];
    }
    fn two(ctx: *anyopaque, a: u16, b: u16) u16 {
        _ = a;
        _ = b;
        return next(ctx);
    }
    fn one(ctx: *anyopaque, a: u16) u16 {
        _ = a;
        return next(ctx);
    }
    fn interface(r: *BenchCallees) se.Callees {
        return .{ .see_white = two, .see_black = two, .r4793_4CEC = two, .r4793_41B6 = two, .r2B9F_4A76 = one, .r2B9F_4AD4 = one, .ctx = r };
    }
};

test "bench: evalpawns: pawn evaluators, pawn hash, static_eval" {
    if (!bench.enabled) return;
    const gpa = std.heap.page_allocator;
    var d: BenchData = .{};
    defer d.deinit(gpa);
    for (runs) |name| try collect(gpa, name, &d, 4);
    const passes = 15;
    const s = try gpa.create(State);
    defer gpa.destroy(s);
    s.* = .{};

    // The evaluators.
    {
        var best: bench.Best = .{};
        var over: bench.Best = .{};
        for (0..passes) |_| {
            var t0 = bench.now();
            for (d.eval_inputs.items, d.eval_tags.items) |*in, tag| {
                in.put(&s.p, &s.v);
                bench.keep(&s.p);
                bench.keep(tag);
            }
            over.pass(t0);
            t0 = bench.now();
            for (d.eval_inputs.items, d.eval_tags.items) |*in, tag| {
                in.put(&s.p, &s.v);
                bench.keep(&s.p);
                const r = if (tag == 1) pawnEval(&s.p, &s.v, .white) else pawnEval(&s.p, &s.v, .black);
                bench.keep(r);
                bench.keep(&s.v);
            }
            best.pass(t0);
        }
        best.report("evalpawns: pawnEval (both sides)", d.eval_inputs.items.len, passes, over.ns);
    }
    // The pawn hash: every probe, store and clear in order from each file's first.
    {
        var best: bench.Best = .{};
        var over: bench.Best = .{};
        const h = try gpa.create(PawnHash);
        defer gpa.destroy(h);
        for (0..passes) |_| {
            const t0 = bench.now();
            for (d.hash_inputs.items, d.hash_tags.items) |*in, tag| {
                in.put(&s.p, &s.v);
                bench.keep(&s.p);
                bench.keep(tag);
            }
            over.pass(t0);
            var total: i96 = 0;
            for (d.hash_file_start.items, 0..) |start, fi| {
                const end = if (fi + 1 < d.hash_file_start.items.len) d.hash_file_start.items[fi + 1] else d.hash_tags.items.len;
                h.* = d.hash_initial.items[fi];
                const t1 = bench.now();
                for (d.hash_inputs.items[start..end], d.hash_tags.items[start..end]) |*in, tag| {
                    in.put(&s.p, &s.v);
                    bench.keep(&s.p);
                    const r: u16 = switch (tag) {
                        3 => @bitCast(h.probe(&s.p, &s.v, .white)),
                        4 => @bitCast(h.probe(&s.p, &s.v, .black)),
                        5 => h.store(&s.p, &s.v, .white),
                        6 => h.store(&s.p, &s.v, .black),
                        else => blk: {
                            h.clear();
                            break :blk 0;
                        },
                    };
                    bench.keep(r);
                    bench.keep(&s.v);
                }
                total += bench.now() - t1;
            }
            best.pass(bench.now() - total);
        }
        best.report("evalpawns: pawn hash probe/store/clear (misses evaluate)", d.hash_tags.items.len, passes, over.ns);
    }
    // static_eval: the quick path, and the full body.
    inline for (.{ false, true }) |full| {
        var best: bench.Best = .{};
        var over: bench.Best = .{};
        var n: usize = 0;
        const h = try gpa.create(PawnHash);
        defer gpa.destroy(h);
        h.* = .{};
        for (0..passes) |_| {
            n = 0;
            var t0 = bench.now();
            for (d.statics.items) |*call| {
                if (call.full != full) continue;
                s.p = call.p;
                s.v = call.v;
                bench.keep(&s.p);
                bench.keep(&s.v);
                n += 1;
            }
            over.pass(t0);
            t0 = bench.now();
            for (d.statics.items) |*call| {
                if (call.full != full) continue;
                s.p = call.p;
                s.v = call.v;
                bench.keep(&s.p);
                bench.keep(&s.v);
                var cal: BenchCallees = .{ .ax = d.static_ax.items[call.ax_start..][0..call.ax_n] };
                const iface = cal.interface();
                const r = staticEval(&s.p, &s.v, h, &iface, call.side, call.arg2, se.Fixes.original, call.stray);
                bench.keep(r);
                bench.keep(&s.v);
            }
            best.pass(t0);
        }
        best.report(if (full) "evalpawns: static_eval, full body (every 4th call)" else "evalpawns: static_eval, quick path (every 4th call)", n, passes, over.ns);
    }
}

// ---------------------------------------------------------------------------
// The evaluator memo (src/pawnhash.zig `Memo`) against the pawn hash without it
// (src/pawnhash_reference.zig, the pawn hash as it was before the memo).
// ---------------------------------------------------------------------------

const ref_hash = @import("pawnhash_reference.zig");
const Memo = pawnhash.Memo;
const RandomWalk = @import("position_test.zig").RandomWalk;

test "pawn memo: replay every recorded call of the original with the memo attached" {
    const gpa = std.testing.allocator;
    const memo = try gpa.alloc(Memo.Slot, Memo.slots_measured);
    defer gpa.free(memo);
    const tiny = try gpa.alloc(Memo.Slot, 4);
    defer gpa.free(tiny);
    var calls: usize = 0;
    for (runs) |name| {
        // The measured size, and (for half the files) four slots: collisions and replacement.
        for ([_][]Memo.Slot{ memo, tiny }) |m| {
            if (m.len == 4 and (name[0] - 'A') % 2 == 1) continue;
            const n = try replay(gpa, name, m);
            for (n.by_tag) |k| calls += k;
        }
    }
    std.debug.print("pawn memo: {d} recorded calls replayed with the memo ({d} and 4 slots), all equal to the original\n", .{ calls, Memo.slots_measured });
}

/// How the memo was used, seen from outside before each call.
const MemoStats = struct {
    /// Calls where the original runs the evaluator: probes that missed, forced stores.
    evaluations: usize = 0,
    hits: usize = 0,
    /// Misses that replaced another key's result.
    replacements: usize = 0,
    /// Evaluations made without the memo, the inputs being outside the key's domain.
    bypassed: usize = 0,

    fn print(m: MemoStats, label: []const u8, calls: usize) void {
        std.debug.print("pawn memo: {s}: {d} probes and stores equal to the reference; {d} evaluations, of which {d} memo hits, {d} memo replacements, {d} not looked up\n", .{ label, calls, m.evaluations, m.hits, m.replacements, m.bypassed });
    }
};

/// The pawn hash with a memo, and without one (the reference, src/pawnhash_reference.zig,
/// whose evaluator works the default way), given the same calls. With the memo the
/// evaluator works as `lanes` says.
fn HashDiff(comptime lanes: bool) type {
    return struct {
        const Self = @This();
        const Without = ref_hash.PawnHash;

        with: *PawnHash,
        without: *Without,
        calls: usize = 0,
        stats: MemoStats = .{},

        fn init(gpa: std.mem.Allocator, memo: []Memo.Slot) !Self {
            const a = try gpa.create(PawnHash);
            a.* = .{};
            a.attachMemo(memo);
            const b = try gpa.create(Without);
            b.* = .{};
            return .{ .with = a, .without = b };
        }

        fn deinit(d: *Self, gpa: std.mem.Allocator) void {
            gpa.destroy(d.with);
            gpa.destroy(d.without);
        }

        fn clear(d: *Self) void {
            d.with.clear();
            d.without.clear();
        }

        fn observe(d: *Self, p: *const pos.Position, v: *const EvalVars, store: bool, comptime stm: Side) void {
            var kb: [6]u8 = undefined;
            std.mem.writeInt(u48, &kb, p.pawn_hash_key, .little);
            const e = &d.with.tables[@backingInt(stm)][kb[4]];
            const table_hit = std.mem.eql(u8, &e.key, &[5]u8{ kb[0], kb[1], kb[2], kb[3], kb[5] });
            if (!store and table_hit) return;
            d.stats.evaluations += 1;
            const k = Memo.key(p, v.late_endgame, stm, lanes) orelse {
                d.stats.bypassed += 1;
                return;
            };
            const s = &d.with.memo[Memo.index(k) & (d.with.memo.len - 1)];
            if (std.mem.eql(u64, &s.key, &k)) {
                d.stats.hits += 1;
            } else if (s.key[6] != 0) {
                d.stats.replacements += 1;
            }
        }

        /// A probe (`store` false) or a forced store, made with both from `v`; `v` then
        /// holds what they left. The return value, every EvalVars field and the entry
        /// written must be the same.
        fn op(d: *Self, p: *const pos.Position, v: *EvalVars, store: bool, comptime stm: Side) !void {
            d.observe(p, v, store, stm);
            var a = v.*;
            var b = v.*;
            const ra: u16 = if (store) d.with.storeWith(p, &a, stm, lanes) else @bitCast(d.with.probeWith(p, &a, stm, lanes));
            const rb: u16 = if (store) d.without.store(p, &b, stm) else @bitCast(d.without.probe(p, &b, stm));
            const i: u8 = @truncate(p.pawn_hash_key >> 32);
            const t = @backingInt(stm);
            const ea = std.mem.asBytes(&d.with.tables[t][i]);
            const eb = std.mem.asBytes(&d.without.tables[t][i]);
            if (ra != rb or !std.meta.eql(a, b) or !std.mem.eql(u8, ea, eb)) {
                std.debug.print("\npawn memo (lanes {}): call {d}, {s}({s}) differs: AX {X:0>4} / {X:0>4}, weak {X:0>2} / {X:0>2}, passed {X:0>2} {X:0>2} / {X:0>2} {X:0>2}, entry {X} / {X}\n", .{ lanes, d.calls, if (store) "store" else "probe", @tagName(stm), ra, rb, a.weak_pawns, b.weak_pawns, a.passed_pawns[0], a.passed_pawns[1], b.passed_pawns[0], b.passed_pawns[1], ea, eb });
                return error.MemoDiffers;
            }
            v.* = a;
            d.calls += 1;
        }

        /// Both tables, every byte.
        fn tablesEqual(d: *Self) !void {
            try std.testing.expectEqualSlices(u8, std.mem.asBytes(&d.without.tables), std.mem.asBytes(&d.with.tables));
        }
    };
}

/// Random walks (the ported generator, make_move with the hash update before it, and
/// unmake_move), with probes and forced stores of both sides at each position, until
/// `calls` calls. The pawn hash is cleared now and then, as before each search; the
/// memo never. Every reached position must be in the key's domain.
fn walkCompare(comptime lanes: bool, d: *HashDiff(lanes), w: *RandomWalk, r: std.Random, calls: usize) !void {
    var v: EvalVars = .{};
    var steps: usize = 0;
    while (d.calls < calls) : (steps += 1) {
        w.step();
        if (w.depth == 0) {
            // A new game: a new `late_endgame` (any non-zero value means set), style.
            const lates = [_]u8{ 0, 0, 0, 1, 1, 0x80 };
            v.late_endgame = lates[r.uintLessThan(usize, lates.len)];
            v.style_normal = @intFromBool(r.uintLessThan(u8, 4) != 0);
            v.pawn_structure_weight = if (r.boolean()) 100 else r.intRangeAtMost(i32, 0, 200);
        }
        if (steps % 5000 == 0) {
            try d.tablesEqual();
            d.clear();
        }
        const before = d.stats.bypassed;
        for (0..1 + r.uintLessThan(usize, 3)) |_| {
            const store = r.uintLessThan(u8, 8) == 0;
            // Now and then a key that misses the table, whatever it holds.
            const key = w.p.pawn_hash_key;
            if (r.uintLessThan(u8, 8) == 0) w.p.pawn_hash_key = r.int(u48);
            if (r.boolean()) try d.op(&w.p, &v, store, .white) else try d.op(&w.p, &v, store, .black);
            w.p.pawn_hash_key = key;
        }
        if (d.stats.bypassed != before) {
            std.debug.print("\npawn memo: a position of the walk is outside the key's domain (the pawn tables are not those of the pawns on the board)\n", .{});
            return error.WalkOutsideKeyDomain;
        }
    }
    try d.tablesEqual();
}

test "pawn memo: the pawn hash with the memo equals the pawn hash without it, over random walks" {
    const gpa = std.testing.allocator;
    var prng: std.Random.DefaultPrng = .init(0x9A57_3E30);
    const r = prng.random();
    const w = try gpa.create(RandomWalk);
    defer gpa.destroy(w);
    w.* = .init(0x3E30_9A57);
    const big = try gpa.alloc(Memo.Slot, Memo.slots_measured);
    defer gpa.free(big);
    var tiny: [8]Memo.Slot = undefined;
    var one: [1]Memo.Slot = undefined;
    inline for (.{ evalpawns.lanes_available, !evalpawns.lanes_available }) |lanes| {
        if (!lanes or evalpawns.lanes_available) {
            const sizes = [_][]Memo.Slot{ big, &tiny, &one };
            // A million calls on the path the engine uses the memo with.
            const counts = [_]usize{ if (lanes) 300_000 else 1_000_000, 150_000, 100_000 };
            for (sizes, counts) |m, n| {
                var d: HashDiff(lanes) = try .init(gpa, m);
                defer d.deinit(gpa);
                try walkCompare(lanes, &d, w, r, n);
                var label_buf: [64]u8 = undefined;
                d.stats.print(std.fmt.bufPrint(&label_buf, "random walks, {d} slots, lanes {}", .{ m.len, lanes }) catch "", d.calls);
                try std.testing.expect(d.stats.hits > d.stats.evaluations / 50);
                if (m.len < 16) try std.testing.expect(d.stats.replacements > d.stats.evaluations / 4);
            }
        }
    }
}

test "pawn memo: the recorded probes and stores give the same results, tables and masks with the memo" {
    const gpa = std.testing.allocator;
    var bd: BenchData = .{};
    defer bd.deinit(gpa);
    for (runs) |name| try collect(gpa, name, &bd, std.math.maxInt(usize));
    const memo = try gpa.alloc(Memo.Slot, Memo.slots_measured);
    defer gpa.free(memo);
    var tiny: [4]Memo.Slot = undefined;
    inline for (.{ false, true }) |lanes| if (!lanes or evalpawns.lanes_available) for ([_][]Memo.Slot{ memo, &tiny }) |m| {
        var d: HashDiff(lanes) = try .init(gpa, m);
        defer d.deinit(gpa);
        var p: pos.Position = .{};
        var v: EvalVars = .{};
        for (bd.hash_file_start.items, 0..) |start, fi| {
            const end = if (fi + 1 < bd.hash_file_start.items.len) bd.hash_file_start.items[fi + 1] else bd.hash_tags.items.len;
            d.with.tables = bd.hash_initial.items[fi].tables;
            @memcpy(std.mem.asBytes(&d.without.tables), std.mem.asBytes(&bd.hash_initial.items[fi].tables));
            for (bd.hash_inputs.items[start..end], bd.hash_tags.items[start..end]) |*in, tag| {
                in.put(&p, &v);
                switch (tag) {
                    3 => try d.op(&p, &v, false, .white),
                    4 => try d.op(&p, &v, false, .black),
                    5 => try d.op(&p, &v, true, .white),
                    6 => try d.op(&p, &v, true, .black),
                    else => d.clear(),
                }
            }
            try d.tablesEqual();
        }
        var label_buf: [64]u8 = undefined;
        d.stats.print(std.fmt.bufPrint(&label_buf, "recorded calls, {d} slots, lanes {}", .{ m.len, lanes }) catch "", d.calls);
    };
}

/// Change an input the memo's key leaves out (see `Memo`). `what` picks the change.
fn changeOutsideKey(r: std.Random, p: *pos.Position, v: *EvalVars, what: u8) void {
    switch (what) {
        0 => { // a piece other than a pawn, or an empty or border byte, on a square without a pawn
            const codes = [_]u8{ 0, 2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 14, 0xFF };
            const sq = r.uintLessThan(usize, 120);
            if (p.board[sq] != pos.white_pawn and p.board[sq] != pos.black_pawn) p.board[sq] = codes[r.uintLessThan(usize, codes.len)];
        },
        1 => p.piece_list[r.uintLessThan(usize, 8) + 16 * r.uintLessThan(usize, 2)] = r.int(u8), // pieces and kings
        2 => {
            p.square_slot[r.uintLessThan(usize, 120)] = r.int(u8);
            p.king_rays[r.uintLessThan(usize, 2)][r.uintLessThan(usize, 120)] = r.int(u8);
        },
        3 => {
            p.material[r.uintLessThan(usize, 2)] = r.int(u16);
            p.piece_material_sum = r.int(u16);
            p.men = r.int(u8);
            p.piece_count = .{ r.int(u8), r.int(u8) };
            p.side_pawn_count = .{ r.int(u8), r.int(u8) };
            p.pawns_on_dark = .{ r.int(u8), r.int(u8) };
            p.king_file = .{ r.int(u8), r.int(u8) };
            p.king_rank = .{ r.int(u8), r.int(u8) };
            p.oo_lost_at[r.uintLessThan(usize, 2)] = r.int(u16);
            p.ooo_lost_at[r.uintLessThan(usize, 2)] = r.int(u16);
            p.game_ply = r.int(u16);
            p.hash_key = r.int(u48);
            p.pawn_hash_key = r.int(u48);
            p.ep_square_by_ply[r.uintLessThan(usize, pos.max_ply)] = r.int(u8);
            p.check_by_ply[r.uintLessThan(usize, pos.max_ply)] = r.int(u8);
        },
        4 => {
            v.square_values[r.uintLessThan(usize, 2)][r.uintLessThan(usize, 5)][r.uintLessThan(usize, 100)] = r.int(u16);
            v.queen_gone_at_root = .{ r.int(u8), r.int(u8) };
            v.endgame = r.int(u8);
            v.passer_tables[r.uintLessThan(usize, 6)][r.uintLessThan(usize, 89)] = r.int(u16);
            v.passer_rank_tables[r.uintLessThan(usize, 4)][r.uintLessThan(usize, 10)] = r.int(u16);
            v.style_normal = r.int(u16);
            v.centrality_weight = r.int(i32);
            v.pawn_structure_weight = r.int(i32);
            v.passed_pawns_weight = r.int(i32);
            v.pawn_square_sum = .{ r.int(u16), r.int(u16) };
            // The evaluator's outputs, as inputs: it overwrites them.
            v.weak_pawns = r.int(u8);
            v.passed_pawns = .{ r.int(u8), r.int(u8) };
            v.black_king_by_passer = r.int(u8);
            v.passer_flags = r.int(u8);
            v.draw_flag = r.int(u8);
            v.promotion_square = r.int(u8);
            v.promotion_flags = r.int(u8);
        },
        5 => { // `late_endgame`: another value of the same truth
            if (v.late_endgame != 0) v.late_endgame = 1 + r.uintLessThan(u8, 255);
        },
        6 => { // every pawn-attack byte off the 64 squares (the border)
            for (0..120) |sq| {
                if (onBoard(sq)) continue;
                p.pawn_attacks[0][sq] = r.int(u8);
                p.pawn_attacks[1][sq] = r.int(u8);
            }
        },
        else => { // a pawn slot holding 120 or more (a captured pawn's mark): another such value
            const i = 16 * r.uintLessThan(usize, 2) + 8 + r.uintLessThan(usize, 8);
            if (p.piece_list[i] >= 120) p.piece_list[i] = 120 + r.uintLessThan(u8, 136);
        },
    }
}

const outside_changes = 8;

/// One of the 64 squares of the board.
fn onBoard(sq: usize) bool {
    return sq >= 21 and sq <= 98 and sq % 10 >= 1 and sq % 10 <= 8;
}

/// Change an input the key holds, or one it checks (`Memo`). Returns false when the
/// change could not be made in this position.
fn changeInsideKey(r: std.Random, p: *pos.Position, v: *EvalVars, what: u8) bool {
    const side = r.uintLessThan(usize, 2);
    const code: u8 = if (side == 0) pos.white_pawn else pos.black_pawn;
    const base = 16 * side + 8;
    var present: [8]usize = undefined;
    var np: usize = 0;
    var absent: [8]usize = undefined;
    var na: usize = 0;
    for (0..8) |k| {
        const sq = p.piece_list[base + k];
        if (sq < 120 and p.board[sq] == code) {
            present[np] = base + k;
            np += 1;
        } else {
            absent[na] = base + k;
            na += 1;
        }
    }
    switch (what) {
        0 => { // a pawn moved to an empty square, the tables rebuilt
            if (np == 0) return false;
            const i = present[r.uintLessThan(usize, np)];
            const to = randomSquare(r, 1, 6);
            if (p.board[to] != pos.empty) return false;
            p.board[p.piece_list[i]] = pos.empty;
            p.board[to] = code;
            p.piece_list[i] = to;
            rebuildPawnTables(p);
        },
        1 => { // two slots of one colour exchanged
            const a = base + r.uintLessThan(usize, 8);
            const b = base + r.uintLessThan(usize, 8);
            if (a == b or p.piece_list[a] == p.piece_list[b]) return false;
            // Two slots that both hold no pawn: the evaluator cannot tell them apart.
            const a_here = p.piece_list[a] < 120 and p.board[p.piece_list[a]] == code;
            const b_here = p.piece_list[b] < 120 and p.board[p.piece_list[b]] == code;
            if (!a_here and !b_here) return false;
            std.mem.swap(u8, &p.piece_list[a], &p.piece_list[b]);
        },
        2 => { // a pawn captured, the tables rebuilt
            if (np == 0) return false;
            const i = present[r.uintLessThan(usize, np)];
            p.board[p.piece_list[i]] = pos.empty;
            p.piece_list[i] +%= 0x63;
            rebuildPawnTables(p);
        },
        3 => { // a pawn added in a free slot, the tables rebuilt
            if (na == 0) return false;
            const to = randomSquare(r, 1, 6);
            if (p.board[to] != pos.empty) return false;
            p.board[to] = code;
            p.piece_list[absent[r.uintLessThan(usize, na)]] = to;
            rebuildPawnTables(p);
        },
        4 => { // a pawns-per-file byte
            const odd = [_]u8{ 0, 1, 2, 3, 0x7F, 0x80, 0xFF };
            const f = r.uintLessThan(usize, 10);
            const x = odd[r.uintLessThan(usize, odd.len)];
            if (p.pawns_per_file[side][f] == x) return false;
            p.pawns_per_file[side][f] = x;
        },
        5 => { // the pawn count, often across the 8 the space terms test
            const x: u8 = if (r.boolean()) 6 + r.uintLessThan(u8, 6) else r.int(u8);
            if (p.pawn_count == x) return false;
            p.pawn_count = x;
        },
        6 => v.late_endgame = if (v.late_endgame == 0) 1 + r.uintLessThan(u8, 255) else 0,
        7 => { // a pawn-attack byte on the board (small where the space terms index a table with it)
            const sq = 21 + r.uintLessThan(usize, 78);
            if (!onBoard(sq)) return false;
            const small = spaceSquare(sq) or sq == 44 or sq == 45 or sq == 74 or sq == 75;
            const odd = [_]u8{ 0, 1, 2, 3, 0x7F, 0x80, 0xFF };
            const x = if (small) r.uintAtMost(u8, 2) else odd[r.uintLessThan(usize, odd.len)];
            if (p.pawn_attacks[side][sq] == x) return false;
            p.pawn_attacks[side][sq] = x;
        },
        11 => { // a pawn moved to rank 1 or 8, the tables rebuilt
            if (np == 0) return false;
            const i = present[r.uintLessThan(usize, np)];
            const rank: u8 = if (r.boolean()) 0 else 7;
            const to = randomSquare(r, rank, rank);
            if (p.board[to] != pos.empty) return false;
            p.board[p.piece_list[i]] = pos.empty;
            p.board[to] = code;
            p.piece_list[i] = to;
            rebuildPawnTables(p);
        },
        8 => { // a pawn on the board that no slot names
            const to = randomSquare(r, 1, 6);
            if (p.board[to] != pos.empty) return false;
            p.board[to] = code;
        },
        9 => { // a pawn's square given another piece, slot and tables left
            if (np == 0) return false;
            p.board[p.piece_list[present[r.uintLessThan(usize, np)]]] = if (side == 0) pos.white_knight else pos.black_knight;
        },
        10 => { // a slot naming a pawn another slot names
            if (np == 0 or na == 0) return false;
            p.piece_list[absent[r.uintLessThan(usize, na)]] = p.piece_list[present[r.uintLessThan(usize, np)]];
        },
        else => unreachable,
    }
    return true;
}

const inside_changes = 12;

test "pawn memo: inputs outside the key do not change the result; inputs inside it do, and are never answered wrongly" {
    const gpa = std.testing.allocator;
    var prng: std.Random.DefaultPrng = .init(0x0B5E_55ED);
    const r = prng.random();
    const w = try gpa.create(RandomWalk);
    defer gpa.destroy(w);
    w.* = .init(0x51DE_CA5E);
    const memo = try gpa.alloc(Memo.Slot, Memo.slots_measured);
    defer gpa.free(memo);
    const h = try gpa.create(PawnHash);
    defer gpa.destroy(h);
    h.* = .{};
    h.attachMemo(memo);
    var outside: usize = 0;
    var inside: usize = 0;
    var inside_changed: usize = 0;
    var inside_same_key: usize = 0;
    var inside_bypassed: usize = 0;
    var stacked: usize = 0;
    var changed_by: [inside_changes]usize = @splat(0);
    var positions: usize = 0;
    while (positions < 25_000) {
        w.step();
        positions += 1;
        var v: EvalVars = .{};
        v.late_endgame = @intFromBool(r.uintLessThan(u8, 3) == 0);
        inline for (.{ Side.white, Side.black }) |stm| {
            inline for (.{ evalpawns.lanes_available, false }) |lanes| {
                // The position as reached: through the memo (recording it), and fresh.
                var v0 = v;
                const r0 = h.evaluate(&w.p, &v0, stm, lanes);
                var vf = v;
                try std.testing.expectEqual(evalpawns.pawnEvalWith(&w.p, &vf, stm, lanes), r0);
                try std.testing.expect(std.meta.eql(v0, vf));
                const k0 = Memo.key(&w.p, v.late_endgame, stm, lanes) orelse return error.WalkOutsideKeyDomain;
                for (0..2) |_| {
                    var q = w.p;
                    var u = v;
                    const what = r.uintLessThan(u8, outside_changes + 1);
                    if (what == outside_changes) {
                        for (0..4) |_| changeOutsideKey(r, &q, &u, r.uintLessThan(u8, outside_changes));
                    } else changeOutsideKey(r, &q, &u, what);
                    var um = u;
                    var uf = u;
                    const rm = h.evaluate(&q, &um, stm, lanes);
                    const rf = evalpawns.pawnEvalWith(&q, &uf, stm, lanes);
                    // The memo agrees with the evaluator, the key is unchanged, and so is
                    // the evaluator's result: the change does not matter.
                    try std.testing.expectEqual(rf, rm);
                    try std.testing.expect(std.meta.eql(um, uf));
                    const k = Memo.key(&q, u.late_endgame, stm, lanes) orelse return error.OutsideChangeLeftDomain;
                    try std.testing.expectEqualSlices(u64, &k0, &k);
                    try std.testing.expectEqual(r0, rf);
                    try std.testing.expectEqual(v0.weak_pawns, uf.weak_pawns);
                    try std.testing.expectEqual(v0.passed_pawns, uf.passed_pawns);
                    outside += 1;
                }
                for (0..3) |_| {
                    var q = w.p;
                    var u = v;
                    const what = r.uintLessThan(u8, inside_changes);
                    if (!changeInsideKey(r, &q, &u, what)) continue;
                    // The memo holds the unchanged position's result; the changed one must
                    // be evaluated or found under its own key.
                    var v1 = v;
                    _ = h.evaluate(&w.p, &v1, stm, lanes);
                    var um = u;
                    var uf = u;
                    const rm = h.evaluate(&q, &um, stm, lanes);
                    const rf = evalpawns.pawnEvalWith(&q, &uf, stm, lanes);
                    try std.testing.expectEqual(rf, rm);
                    try std.testing.expect(std.meta.eql(um, uf));
                    if (Memo.key(&q, u.late_endgame, stm, lanes)) |k| {
                        if (std.mem.eql(u64, &k, &k0)) inside_same_key += 1;
                        // The changed state is in the domain: a change outside the key on
                        // top of it must not matter either.
                        var q2 = q;
                        var v2 = u;
                        changeOutsideKey(r, &q2, &v2, r.uintLessThan(u8, outside_changes));
                        var vm2 = v2;
                        var vf2 = v2;
                        const rm2 = h.evaluate(&q2, &vm2, stm, lanes);
                        const rf2 = evalpawns.pawnEvalWith(&q2, &vf2, stm, lanes);
                        try std.testing.expectEqual(rf2, rm2);
                        try std.testing.expect(std.meta.eql(vm2, vf2));
                        const k2 = Memo.key(&q2, v2.late_endgame, stm, lanes) orelse return error.OutsideChangeLeftDomain;
                        try std.testing.expectEqualSlices(u64, &k, &k2);
                        try std.testing.expectEqual(rf, rf2);
                        try std.testing.expectEqual(uf.weak_pawns, vf2.weak_pawns);
                        try std.testing.expectEqual(uf.passed_pawns, vf2.passed_pawns);
                        stacked += 1;
                    } else inside_bypassed += 1;
                    if (rf != r0 or uf.weak_pawns != v0.weak_pawns or !std.meta.eql(uf.passed_pawns, v0.passed_pawns)) {
                        inside_changed += 1;
                        changed_by[what] += 1;
                    }
                    inside += 1;
                }
            }
        }
    }
    std.debug.print("pawn memo: {d} changes outside the key, none changed the result; {d} changes inside it or its checks, {d} changed the result (by kind {any}), {d} kept the key, {d} left the key's domain; {d} changes outside the key on top of one inside it, none changed the result; every result equal to the evaluator's\n", .{ outside, inside, inside_changed, changed_by, inside_same_key, inside_bypassed, stacked });
    // Every change of this kind changes the key or leaves its domain.
    try std.testing.expectEqual(@as(usize, 0), inside_same_key);
    for (changed_by) |n| try std.testing.expect(n > 0);
}

test "bench: evalpawns: pawn memo: the pawn hash and the evaluator with and without the memo" {
    if (!bench.enabled) return;
    const gpa = std.heap.page_allocator;
    var d: BenchData = .{};
    defer d.deinit(gpa);
    // Each file's first evaluator call, so that a memo can start empty at each run.
    var eval_start: std.ArrayList(usize) = .empty;
    defer eval_start.deinit(gpa);
    for (runs) |name| {
        try eval_start.append(gpa, d.eval_inputs.items.len);
        try collect(gpa, name, &d, 1 << 30);
    }
    const passes = 15;
    const s = try gpa.create(State);
    defer gpa.destroy(s);
    s.* = .{};
    const h = try gpa.create(PawnHash);
    defer gpa.destroy(h);
    const memo = try gpa.alloc(Memo.Slot, 1 << 16);
    defer gpa.free(memo);
    const sizes = [_]usize{ 0, 1 << 12, 1 << 14 };
    inline for (.{ true, false }) |lanes| {
        if (!lanes or evalpawns.lanes_available) {
            // The pawn hash: every recorded probe, store and clear in order, each file
            // from its recorded first state, the memo (if any) empty at each file.
            for (sizes) |size| {
                var best: bench.Best = .{};
                var over: bench.Best = .{};
                for (0..passes) |_| {
                    const t0 = bench.now();
                    for (d.hash_inputs.items, d.hash_tags.items) |*in, tag| {
                        in.put(&s.p, &s.v);
                        bench.keep(&s.p);
                        bench.keep(tag);
                    }
                    over.pass(t0);
                    var total: i96 = 0;
                    for (d.hash_file_start.items, 0..) |start, fi| {
                        const end = if (fi + 1 < d.hash_file_start.items.len) d.hash_file_start.items[fi + 1] else d.hash_tags.items.len;
                        h.* = d.hash_initial.items[fi];
                        h.memo = &.{};
                        if (size != 0) h.attachMemo(memo[0..size]);
                        const t1 = bench.now();
                        for (d.hash_inputs.items[start..end], d.hash_tags.items[start..end]) |*in, tag| {
                            in.put(&s.p, &s.v);
                            bench.keep(&s.p);
                            const r: u16 = switch (tag) {
                                3 => @bitCast(h.probeWith(&s.p, &s.v, .white, lanes)),
                                4 => @bitCast(h.probeWith(&s.p, &s.v, .black, lanes)),
                                5 => h.storeWith(&s.p, &s.v, .white, lanes),
                                6 => h.storeWith(&s.p, &s.v, .black, lanes),
                                else => blk: {
                                    h.clear();
                                    break :blk 0;
                                },
                            };
                            bench.keep(r);
                            bench.keep(&s.v);
                        }
                        total += bench.now() - t1;
                    }
                    best.pass(bench.now() - total);
                }
                var label: [128]u8 = undefined;
                best.report(std.fmt.bufPrint(&label, "evalpawns: pawn memo: pawn hash probe/store/clear, {s} path, memo {d} slots", .{ if (lanes) "vector" else "per-slot", size }) catch "", d.hash_tags.items.len, passes, over.ns);
            }
            // The evaluator calls the original made (the pawn hash's misses and stores),
            // plain and through the memo, empty at each file.
            for (sizes) |size| {
                var best: bench.Best = .{};
                var over: bench.Best = .{};
                for (0..passes) |_| {
                    var t0 = bench.now();
                    for (d.eval_inputs.items, d.eval_tags.items) |*in, tag| {
                        in.put(&s.p, &s.v);
                        bench.keep(&s.p);
                        bench.keep(tag);
                    }
                    over.pass(t0);
                    var total: i96 = 0;
                    for (eval_start.items, 0..) |start, fi| {
                        const end = if (fi + 1 < eval_start.items.len) eval_start.items[fi + 1] else d.eval_inputs.items.len;
                        h.memo = &.{};
                        if (size != 0) h.attachMemo(memo[0..size]);
                        t0 = bench.now();
                        for (d.eval_inputs.items[start..end], d.eval_tags.items[start..end]) |*in, tag| {
                            in.put(&s.p, &s.v);
                            bench.keep(&s.p);
                            const r = if (tag == 1) h.evaluate(&s.p, &s.v, .white, lanes) else h.evaluate(&s.p, &s.v, .black, lanes);
                            bench.keep(r);
                            bench.keep(&s.v);
                        }
                        total += bench.now() - t0;
                    }
                    best.pass(bench.now() - total);
                }
                // How many of the calls the memo answered (an untimed pass).
                var hits: usize = 0;
                if (size != 0) {
                    for (eval_start.items, 0..) |start, fi| {
                        const end = if (fi + 1 < eval_start.items.len) eval_start.items[fi + 1] else d.eval_inputs.items.len;
                        h.attachMemo(memo[0..size]);
                        for (d.eval_inputs.items[start..end], d.eval_tags.items[start..end]) |*in, tag| {
                            in.put(&s.p, &s.v);
                            const k = (if (tag == 1) Memo.key(&s.p, s.v.late_endgame, .white, lanes) else Memo.key(&s.p, s.v.late_endgame, .black, lanes)).?;
                            if (std.mem.eql(u64, &h.memo[Memo.index(k) & (size - 1)].key, &k)) hits += 1;
                            _ = if (tag == 1) h.evaluate(&s.p, &s.v, .white, lanes) else h.evaluate(&s.p, &s.v, .black, lanes);
                        }
                    }
                }
                var label: [160]u8 = undefined;
                best.report(std.fmt.bufPrint(&label, "evalpawns: pawn memo: evaluator calls, {s} path, memo {d} slots ({d} answered by the memo)", .{ if (lanes) "vector" else "per-slot", size, hits }) catch "", d.eval_inputs.items.len, passes, over.ns);
            }
            // The memo's lookup alone: the key and the slot, on the recorded evaluator calls.
            {
                var best: bench.Best = .{};
                var over: bench.Best = .{};
                for (0..passes) |_| {
                    var t0 = bench.now();
                    for (d.eval_inputs.items) |*in| {
                        in.put(&s.p, &s.v);
                        bench.keep(&s.p);
                    }
                    over.pass(t0);
                    t0 = bench.now();
                    for (d.eval_inputs.items, d.eval_tags.items) |*in, tag| {
                        in.put(&s.p, &s.v);
                        bench.keep(&s.p);
                        const k = if (tag == 1) Memo.key(&s.p, s.v.late_endgame, .white, lanes) else Memo.key(&s.p, s.v.late_endgame, .black, lanes);
                        bench.keep(if (k) |x| Memo.index(x) else 0);
                    }
                    best.pass(t0);
                }
                best.report(if (lanes) "evalpawns: pawn memo: key and index alone, vector path" else "evalpawns: pawn memo: key and index alone, per-slot path", d.eval_inputs.items.len, passes, over.ns);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// DEV-053: the line tables' pseudo-lines in the passed-pawn prefilters
// ---------------------------------------------------------------------------

fn mirrorSquare(s: usize) usize {
    return (11 - s / 10) * 10 + s % 10;
}

/// A position for the prefilters alone: every list entry captured (an entry whose table
/// bytes are all 0 for `sq`, as in the DEV-015 test) but the ones given.
fn prefilterPosition(sq: usize, entries: []const struct { usize, u8 }) !pos.Position {
    var p: pos.Position = .{};
    const quiet: u8 = blk: {
        for (0x63..256) |e| {
            var any: u8 = 0;
            for ([_]usize{ 0x0B66, 0x0A68, 0x0C64, 0x0CFF }) |t| any |= se.constByteForTest(t + sq - e);
            if (any == 0) break :blk @intCast(e);
        }
        return error.NoQuietEntry;
    };
    p.piece_list = @splat(quiet);
    for (entries) |x| p.piece_list[x[0]] = x[1];
    return p;
}

test "DEV-053: static_eval's prefilters: a pseudo-rank and a pseudo-diagonal, and their mirrors" {
    const corrected = se.Fixes.corrected;
    const fixed = se_053;
    // A Black passer on b2 (32) and White's rook on g1 (27), slot 4: b2 - g1 = 5, which
    // DG:0C64 + 5 takes for a rank (-1). The original's prefilter opens (1B8A, and 1B55 in
    // the general one); corrected it does not.
    const b2: usize = 32;
    var p = try prefilterPosition(b2, &.{.{ 4, 27 }});
    try std.testing.expect(se.rooksOnLine(&p, 0, b2, corrected));
    try std.testing.expect(!se.rooksOnLine(&p, 0, b2, fixed));
    try std.testing.expect(se.whitePieceReaches(&p, b2, corrected, .{}));
    try std.testing.expect(!se.whitePieceReaches(&p, b2, fixed, .{}));
    // The mirror: a White passer on b7, Black's rook on g8 (b7 - g8 = -15: no step).
    var m = try prefilterPosition(mirrorSquare(b2), &.{.{ 16 + 4, @intCast(mirrorSquare(27)) }});
    try std.testing.expect(!se.rooksOnLine(&m, 1, mirrorSquare(b2), corrected));
    try std.testing.expect(!se.rooksOnLine(&m, 1, mirrorSquare(b2), fixed));
    try std.testing.expect(!se.blackPieceReaches(&m, mirrorSquare(b2), corrected, .{}));
    // A real rank: White's rook on h2 (38) opens both.
    p = try prefilterPosition(b2, &.{.{ 5, 38 }});
    try std.testing.expect(se.rooksOnLine(&p, 0, b2, fixed) and se.rooksOnLine(&p, 0, b2, corrected));

    // A White passer on g7 (87) and Black's bishop on a2 (31), slot 18: g7 - a2 = 56 has no
    // step; the mirror, a Black passer on g2 (37) and White's bishop on a7 (81): g2 - a7 =
    // -44, which DG:0B66 - 44 takes for a diagonal (+11). Corrected, neither opens.
    const g7: usize = 87;
    p = try prefilterPosition(g7, &.{.{ 16 + 2, 31 }});
    try std.testing.expect(!se.blackPieceReaches(&p, g7, corrected, .{}));
    m = try prefilterPosition(mirrorSquare(g7), &.{.{ 2, @intCast(mirrorSquare(31)) }});
    try std.testing.expect(se.whitePieceReaches(&m, mirrorSquare(g7), corrected, .{}));
    try std.testing.expect(!se.whitePieceReaches(&m, mirrorSquare(g7), fixed, .{}));
    try std.testing.expect(!se.blackPieceReaches(&p, g7, fixed, .{}));
}

test "DEV-053: static_eval's prefilters equal their colour mirror on every square of generated positions" {
    var prng: std.Random.DefaultPrng = .init(0x5345_3035_3353_4546);
    const r = prng.random();
    var cases: usize = 0;
    var differs_before: usize = 0;
    var differs_after: usize = 0;
    var changed: usize = 0;
    for (0..20_000) |_| {
        // Random list entries: each a board square, or a captured entry (square + 63h).
        var p: pos.Position = .{};
        // The kings stay on the board: a king is never captured, and the king table DG:0CFF
        // read at a captured entry is not colour-symmetric (outside DEV-053).
        for (&p.piece_list, 0..) |*e, i| {
            const s: u8 = 21 + 10 * r.uintLessThan(u8, 8) + r.uintLessThan(u8, 8);
            const keep = i % 16 == 7;
            e.* = if (!keep and r.uintLessThan(u8, 4) == 0) s + 0x63 else s;
        }
        var m: pos.Position = .{};
        for (0..2) |c| for (0..16) |i| {
            const e = p.piece_list[16 * c + i];
            m.piece_list[16 * (1 - c) + i] = if (e < 120) @intCast(mirrorSquare(e)) else e;
        };
        var sq: usize = 21;
        while (sq <= 98) : (sq += 1) {
            if (sq % 10 == 0 or sq % 10 == 9) continue;
            const ms = mirrorSquare(sq);
            inline for (.{ se.Fixes.corrected, se_053 }, 0..) |f, k| {
                const a = se.whitePieceReaches(&p, sq, f, .{});
                const b = se.blackPieceReaches(&m, ms, f, .{});
                const ra = se.rooksOnLine(&p, 0, sq, f);
                const rb = se.rooksOnLine(&m, 1, ms, f);
                if (a != b or ra != rb) {
                    if (k == 0) differs_before += 1 else differs_after += 1;
                }
            }
            if (se.whitePieceReaches(&p, sq, se.Fixes.corrected, .{}) != se.whitePieceReaches(&p, sq, se_053, .{})) changed += 1;
            cases += 1;
        }
    }
    std.debug.print("DEV-053: static_eval's prefilters on {d} generated (position, square) cases: DEV-053 changes White's general prefilter in {d}; differ from the colour mirror: {d} before, {d} with DEV-053\n", .{ cases, changed, differs_before, differs_after });
    try std.testing.expectEqual(@as(usize, 0), differs_after);
}
