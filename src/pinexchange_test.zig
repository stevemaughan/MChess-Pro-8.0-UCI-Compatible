//! Tests of src/pinexchange.zig (4793:41B6, 4793:4CEC):
//!
//! - every call of the two routines recorded from the original (tests/golden/evalthreats/,
//!   tags 1 and 2: the calls the threat evaluators made, with their entry image and the
//!   original's AX and changed bytes; format in tools/port/gen_evalthreats_vectors.py),
//!   replayed on a `Position` built from the image: AX and every work-area byte, and a
//!   check that the original changed no other byte of DGROUP (outside the stack and the
//!   interrupt bytes the recordings leave out);
//! - a differential test against the machine-lifted routines (src/attackers.zig, through
//!   `lifted_machine.attackersOnPosition`) on generated calls: random-walk positions,
//!   every square, both sides, a range of values, work areas from random bytes, and
//!   changed states (pieces placed along lines, pins forced on both kings' maps, pawns
//!   next to the square, pawn-attack counts); AX and every work-area byte, and on a
//!   sample every byte of the lifted routine's DGROUP image outside its stack;
//! - a benchmark against the lifted routines in the same run.

const std = @import("std");
const pos = @import("position.zig");
const see = @import("see.zig");
const px = @import("pinexchange.zig");
const lifted = @import("lifted_machine.zig");
const attackers = @import("attackers.zig");
const dg = @import("original.zig").dgroup;
const position_test = @import("position_test.zig");
const RandomWalk = position_test.RandomWalk;
const full_diff = position_test.full_diff;
const diff_count = position_test.diff_count;

const Image = [0x10000]u8;

// ---------------------------------------------------------------------------
// The recorded calls
// ---------------------------------------------------------------------------

/// tools/research/evalthreats/check.py INTERRUPT_BYTES: written by the timer and
/// keyboard interrupts, left out of the recordings.
const irq_bytes = [_]u16{ 0x0058, 0x0059, 0x2A68, 0x2A69, 0xAB1C, 0xAB1D, 0x75B6, 0x3682, 0x8DDC, 0x9EB2, 0x367C, 0x8DD6, 0x8DD4 };
/// The 2 KB below the caller's SP, left out of the recordings.
const slack = 0x800;

const Cursor = struct {
    d: []const u8,
    i: usize = 0,

    fn byte(c: *Cursor) u8 {
        const v = c.d[c.i];
        c.i += 1;
        return v;
    }
    fn word(c: *Cursor) u16 {
        const v = std.mem.readInt(u16, c.d[c.i..][0..2], .little);
        c.i += 2;
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
    fn skipDelta(c: *Cursor) void {
        for (0..c.varint()) |_| {
            _ = c.varint();
            _ = c.byte();
        }
    }
    fn delta(c: *Cursor, img: *Image) void {
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
    const path = try std.fmt.bufPrint(&path_buf, "{s}/evalthreats/{s}", .{ dir, name });
    const compressed = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, gpa, .limited(64 << 20));
    defer gpa.free(compressed);
    var in: std.Io.Reader = .fixed(compressed);
    const window = try gpa.alloc(u8, std.compress.zstd.default_window_len + std.compress.zstd.block_size_max);
    defer gpa.free(window);
    var zd = std.compress.zstd.Decompress.init(&in, window, .{});
    return zd.reader.allocRemaining(gpa, .limited(512 << 20));
}

const files = [_][]const u8{ "A.zst", "B.zst", "C.zst", "D.zst", "E.zst" };

/// The state the routines read, and their work areas, from a DGROUP image.
fn fromImage(img: *const Image, p: *pos.Position, s: *px.Scratch) void {
    @memcpy(&p.board, img[0x9EF6..][0..120]);
    @memcpy(&p.piece_list, img[0xA03A..][0..32]);
    @memcpy(&p.pawn_attacks[0], img[0xA51C..][0..120]);
    @memcpy(&p.pawn_attacks[1], img[0x37DA..][0..120]);
    @memcpy(&p.king_rays[0], img[0xA09E..][0..120]);
    @memcpy(&p.king_rays[1], img[0xA164..][0..120]);
    @memcpy(&s.attackers, img[0x9FEC..][0..116]);
    @memcpy(&s.defenders, img[0xA060..][0..32]);
    @memcpy(&s.gain, img[0x70E5..][0..11]);
    @memcpy(&s.net, img[0xB4E6..][0..11]);
}

/// The work areas, as (DG address, bytes) pairs.
fn areas(s: *const px.Scratch) [4]struct { a: u16, b: []const u8 } {
    return .{ .{ .a = 0x9FEC, .b = &s.attackers }, .{ .a = 0xA060, .b = &s.defenders }, .{ .a = 0x70E5, .b = &s.gain }, .{ .a = 0xB4E6, .b = &s.net } };
}

fn inWorkArea(a: usize) bool {
    return (a >= 0x9FEC and a < 0x9FEC + 116) or (a >= 0xA060 and a < 0xA060 + 32) or
        (a >= 0x70E5 and a < 0x70E5 + 11) or (a >= 0xB4E6 and a < 0xB4E6 + 11);
}

/// Left out of the recordings: the 2 KB below the caller's SP and the interrupt bytes.
fn notRecorded(a: usize, caller_sp: u16) bool {
    const lo: u16 = caller_sp -% slack;
    const w: u16 = @intCast(a);
    if (lo <= caller_sp) {
        if (w >= lo and w < caller_sp) return true;
    } else if (w >= lo or w < caller_sp) return true;
    return std.mem.indexOfScalar(u16, &irq_bytes, w) != null;
}

const Replayed = struct {
    calls: [2]usize = .{ 0, 0 },
    early: usize = 0,
    off_board_sq: usize = 0,
    /// Recorded calls whose result DEV-023 corrected changes.
    changed023: usize = 0,
    /// Recorded calls whose result DEV-058 corrected changes (a knight entry of 0).
    changed058: usize = 0,
};

const fix058: pos.Fixes = .{ .dev001_ep_hash_square = false, .dev058_lifted_knight_entry = true };

const fix023: pos.Fixes = .{ .dev001_ep_hash_square = false, .dev023_pinned_bishop = true };

fn replay(gpa: std.mem.Allocator, name: []const u8, n: *Replayed) !void {
    const data = try readVectors(gpa, name);
    defer gpa.free(data);
    var c: Cursor = .{ .d = data };
    try std.testing.expectEqualSlices(u8, "MCET", c.take(4));
    try std.testing.expectEqual(@as(u16, 1), c.word());
    const img = try gpa.create(Image);
    defer gpa.destroy(img);
    const want = try gpa.create(Image);
    defer gpa.destroy(want);
    img.* = @splat(0);
    var index: usize = 0;
    while (true) : (index += 1) {
        const tag = c.byte();
        if (tag == 0) break;
        c.delta(img);
        var regs: [8]u16 = undefined;
        for (&regs) |*r| r.* = c.word();
        switch (tag) {
            1, 2 => {
                const ax = c.word();
                want.* = img.*;
                c.delta(want);
                const sp = regs[7];
                const sq = std.mem.readInt(u16, img[sp +% 4 ..][0..2], .little);
                const v = std.mem.readInt(u16, img[sp +% 6 ..][0..2], .little);
                const side: pos.Side = if (tag == 1) .white else .black;
                // Every argument is a board square (the port takes squares 11..108).
                if (sq < 21 or sq > 98 or sq % 10 == 0 or sq % 10 == 9) n.off_board_sq += 1;
                try std.testing.expect(sq >= 11 and sq <= 108);
                var p: pos.Position = .{};
                var s: px.Scratch = .{};
                fromImage(img, &p, &s);
                const got = px.exchange(&p, &s, side, @intCast(sq), v);
                if (got != ax) {
                    std.debug.print("\n{s}: record {d}: {s}({d}, {d}): AX want {X:0>4}, got {X:0>4}\n", .{ name, index, if (tag == 1) "41B6" else "4CEC", sq, v, ax, got });
                    return error.MismatchWithOriginal;
                }
                for (areas(&s)) |r| for (r.b, 0..) |byte, k| if (byte != want[r.a + k]) {
                    std.debug.print("\n{s}: record {d}: {s}({d}, {d}): DG:{X:0>4}: want {X:0>2}, got {X:0>2}\n", .{ name, index, if (tag == 1) "41B6" else "4CEC", sq, v, r.a + k, want[r.a + k], byte });
                    return error.MismatchWithOriginal;
                };
                // The original changed nothing else that the recording holds.
                for (0..0x10000) |a| {
                    if (img[a] == want[a] or inWorkArea(a) or notRecorded(a, sp +% 4)) continue;
                    std.debug.print("\n{s}: record {d}: the original changed DG:{X:0>4}, outside the work areas\n", .{ name, index, a });
                    return error.UnexpectedWrite;
                }
                if (s8(@truncate(v)) < s8(see_value(p.board[sq]))) n.early += 1;
                n.calls[tag - 1] += 1;
                // DEV-023 corrected on the same call: count the calls it changes.
                var p2: pos.Position = .{};
                var s2: px.Scratch = .{};
                fromImage(img, &p2, &s2);
                if (px.exchangeFixes(fix023, &p2, &s2, side, @intCast(sq), v) != ax) n.changed023 += 1;
                fromImage(img, &p2, &s2);
                if (px.exchangeFixes(fix058, &p2, &s2, side, @intCast(sq), v) != ax) n.changed058 += 1;
            },
            3, 4 => {
                _ = c.word();
                _ = c.take(c.varint() * 9);
                _ = c.word();
                c.skipDelta();
                if (c.byte() != 0) _ = c.take(c.varint() * 25);
            },
            else => return error.BadVectorFile,
        }
    }
}

inline fn s8(x: u8) i8 {
    return @bitCast(x);
}

fn see_value(code: u8) u8 {
    const t = comptime dg(0x1A71 - 128, 256);
    return t[code +% 128];
}

test "pinexchange: 4793:41B6 and 4CEC equal the original on every recorded call" {
    const gpa = std.testing.allocator;
    var n: Replayed = .{};
    for (files) |f| try replay(gpa, f, &n);
    std.debug.print("pinexchange: recorded calls replayed on a Position: 41B6 {d}, 4CEC {d}, all equal (AX, work areas; nothing else written); {d} early returns, {d} on border squares; DEV-023 corrected changes {d}, DEV-058 {d}\n", .{ n.calls[0], n.calls[1], n.early, n.off_board_sq, n.changed023, n.changed058 });
    try std.testing.expect(n.calls[0] > 0 and n.calls[1] > 0);
}

// ---------------------------------------------------------------------------
// Differential test against the machine-lifted routines
// ---------------------------------------------------------------------------

const knight_reach = dg(0x0A68 - 255, 375);

/// DG:A03A - DG:9FEC: where the piece lists lie inside `see.Scratch.attackers`.
const piece_lists_in_attackers = 0xA03A - 0x9FEC;

/// Does a knight entry make the routine index a king ray map beyond its end for target
/// `sq`? Only an entry no position holds (0..20, C6h..FFh) can; the walk and the set-up
/// never make one, but the forced lines below may leave a knight slot pointing anywhere.
fn knightIndexesOffMap(p: *const pos.Position, sq: usize) bool {
    for ([_]u8{ 0, 1, 16, 17 }) |slot| {
        const e = p.piece_list[slot];
        if (e >= 120 and knight_reach[sq + 255 - e] != 0) return true;
    }
    return false;
}

const Diff = struct {
    aimg: *lifted.AttackerImage,
    expect: *Image,
    rng: std.Random,
    calls: usize = 0,
    image_checks: usize = 0,
    nonzero: usize = 0,
    early: usize = 0,
    changed023: usize = 0,

    /// One call through both, from the same work areas. `see.Scratch.attackers` spans
    /// DG:9FEC..A05F, which holds the piece lists at DG:A03A (entries 78..109): those
    /// bytes are set to the position's lists, as they are in the original's memory (the
    /// lifted routine's image is filled from the work areas after the position, so it
    /// would otherwise read them as its piece lists).
    fn one(d: *Diff, p: *const pos.Position, s_in: *const px.Scratch, side: pos.Side, sq: u8, v: u16) !void {
        var a = s_in.*;
        @memcpy(a.attackers[piece_lists_in_attackers..][0..32], &p.piece_list);
        var b = a;
        const check_image = d.calls % 61 == 0;
        if (check_image) d.expect.* = d.aimg.mem;
        const rb = lifted.attackersOnPosition(d.aimg, p, &b, side, sq, v);
        const ra = px.exchange(p, &a, side, sq, v);
        if (ra != rb or !std.mem.eql(u8, std.mem.asBytes(&a), std.mem.asBytes(&b))) {
            std.debug.print("\npinexchange differs from the lifted routine: side {t} sq {d} v {X:0>4}: AX {X:0>4}, lifted {X:0>4}\n", .{ side, sq, v, ra, rb });
            std.debug.print("  own {any}\n  lifted {any}\n  opp {any}\n  lifted {any}\n", .{ a.attackers[0..8], b.attackers[0..8], a.defenders[0..8], b.defenders[0..8] });
            std.debug.print("  board/White map/Black map by rank:\n", .{});
            for (0..12) |rk| {
                const row = 11 - rk;
                std.debug.print("  {d:>3}: ", .{row * 10});
                for (0..10) |f| std.debug.print("{X:0>2}/{X:0>2}{X:0>2} ", .{ p.board[row * 10 + f], p.king_rays[0][row * 10 + f], p.king_rays[1][row * 10 + f] });
                std.debug.print("\n", .{});
            }
            std.debug.print("  lists {any}\n  pawn att w {d} b {d}\n", .{ p.piece_list, p.pawn_attacks[0][sq], p.pawn_attacks[1][sq] });
            for (areas(&a), areas(&b)) |x, y| for (x.b, y.b, 0..) |g, w, k| if (g != w) {
                std.debug.print("  first differing work-area byte DG:{X:0>4}: {X:0>2}, lifted {X:0>2}\n", .{ x.a + k, g, w });
                return error.DiffersFromLifted;
            };
            return error.DiffersFromLifted;
        }
        if (check_image) {
            // The lifted routine's image after the call is the image before it with the
            // state copied in and the work areas copied out; only its stack may differ.
            const e = d.expect;
            @memcpy(e[0x9EF6..][0..120], &p.board);
            @memcpy(e[0xA03A..][0..32], &p.piece_list);
            @memcpy(e[0xA51C..][0..120], &p.pawn_attacks[0]);
            @memcpy(e[0x37DA..][0..120], &p.pawn_attacks[1]);
            @memcpy(e[0xA09E..][0..120], &p.king_rays[0]);
            @memcpy(e[0xA164..][0..120], &p.king_rays[1]);
            for (areas(&a)) |r| @memcpy(e[r.a..][0..r.b.len], r.b);
            for (0..0xF000) |i| if (e[i] != d.aimg.mem[i]) {
                std.debug.print("\nlifted routine wrote DG:{X:0>4} ({X:0>2} -> {X:0>2}): side {t} sq {d} v {X:0>4}\n", .{ i, e[i], d.aimg.mem[i], side, sq, v });
                return error.UnexpectedWrite;
            };
            d.image_checks += 1;
        }
        d.calls += 1;
        if (ra != 0) d.nonzero += 1;
        if (s8(@truncate(v)) < s8(see_value(p.board[sq]))) d.early += 1;
        // DEV-023 corrected on the same call: how often it changes the result
        var c = s_in.*;
        @memcpy(c.attackers[piece_lists_in_attackers..][0..32], &p.piece_list);
        if (px.exchangeFixes(fix023, p, &c, side, sq, v) != ra) d.changed023 += 1;
    }

    /// Every square 21..98 (the border files included), both sides, the callers' values
    /// and some others, from work areas of random bytes.
    fn allSquares(d: *Diff, p: *const pos.Position) !void {
        var s: px.Scratch = undefined;
        d.rng.bytes(std.mem.asBytes(&s));
        for (21..99) |sq| {
            if (knightIndexesOffMap(p, sq)) continue;
            for ([2]pos.Side{ .white, .black }) |side| {
                for ([_]u16{ 6, 18, 30, 54, 9, 27, d.rng.int(u16) }) |v| try d.one(p, &s, side, @intCast(sq), v);
            }
        }
    }

    /// `n` random squares 21..98, both sides, the callers' values and one other.
    fn someSquares(d: *Diff, p: *const pos.Position, n: usize) !void {
        var s: px.Scratch = undefined;
        d.rng.bytes(std.mem.asBytes(&s));
        for (0..n) |_| {
            const sq = 21 + d.rng.uintLessThan(usize, 78);
            if (knightIndexesOffMap(p, sq)) continue;
            for ([2]pos.Side{ .white, .black }) |side| {
                for ([_]u16{ 6, 18, 30, 54, 9, 27, d.rng.int(u16) }) |v| try d.one(p, &s, side, @intCast(sq), v);
            }
        }
    }
};

const dirs = [8]i8{ 9, 11, -9, -11, 10, -10, 1, -1 };
const dir_step = dg(0x0490, 17);
const dir_bit = dg(0x047E, 17);
const slider_bits = dg(0x0470, 14);

fn onBoard(sq: i32) bool {
    return sq >= 21 and sq <= 98 and @mod(sq, 10) != 0 and @mod(sq, 10) != 9;
}

/// Changes a consistent position into one the walk rarely reaches: along a line from a
/// target square, two to five pieces of either colour (mostly sliders of the line's
/// kind, some pawns, knights and kings), one or two of them put on a king ray map (of
/// either colour, with any ray code of that map) with an enemy slider of the ray's kind
/// placed beyond them, so that they are pinned or (when the ray is the line) not;
/// sometimes pawns next to the target and pawn-attack counts. Returns the target.
fn forceLines(r: std.Random, p: *pos.Position) u8 {
    var sq: i32 = undefined;
    while (true) {
        sq = 21 + 10 * @as(i32, r.uintLessThan(u8, 8)) + r.uintLessThan(u8, 8);
        break;
    }
    const nlines = 1 + r.uintLessThan(u8, 3);
    for (0..nlines) |_| {
        const d: i32 = dirs[r.uintLessThan(usize, 8)];
        const diagonal = d == 9 or d == 11 or d == -9 or d == -11;
        var at = sq;
        // Half the lines are random pieces; the other half follow a pattern of the scan
        // states (S = the line's slider, Q = queen; x and y the two colours, either way
        // round): own queen then sliders, an opponent queen then an own queen then
        // sliders of either colour (the "mixed" state), and the like.
        const patterns = [_][]const u8{ "QxSx", "QxSxSx", "QxQySy", "QxQySx", "QxQyQySy", "SxQxSy", "QxSyQy", "SxSyQx", "QxQxSx" };
        const pattern = if (r.boolean()) patterns[r.uintLessThan(usize, patterns.len)] else "";
        const x_black = r.boolean();
        const count = if (pattern.len > 0) pattern.len / 2 else 2 + r.uintLessThan(u8, 4);
        var placed: [6]i32 = undefined;
        var np: usize = 0;
        for (0..count) |k| {
            at += d;
            while (onBoard(at) and r.uintLessThan(u8, 3) == 0) at += d; // gaps
            if (!onBoard(at)) break;
            if (pattern.len > 0) {
                const kind: u8 = if (pattern[2 * k] == 'Q') 5 else if (diagonal) 3 else 4;
                const black = (pattern[2 * k + 1] == 'x') == x_black;
                p.board[@intCast(at)] = kind + @as(u8, if (black) 7 else 0);
            } else {
                const kinds = if (diagonal) [_]u8{ 3, 3, 5, 5, 4, 1, 2, 6 } else [_]u8{ 4, 4, 5, 5, 3, 1, 2, 6 };
                const black = r.boolean();
                p.board[@intCast(at)] = kinds[r.uintLessThan(usize, kinds.len)] + @as(u8, if (black) 7 else 0);
            }
            placed[np] = at;
            np += 1;
        }
        // pins on one or two of the placed pieces, often the last
        if (np == 0) continue;
        for (0..1 + r.uintLessThan(u8, 2)) |_| {
            const x = if (r.boolean()) placed[np - 1] else placed[r.uintLessThan(usize, np)];
            const map_side = r.uintLessThan(usize, 2);
            const code: u8 = @intCast(1 + 8 * map_side + r.uintLessThan(usize, 8));
            p.king_rays[map_side][@intCast(x)] = code;
            const e: i32 = @as(i8, @bitCast(dir_step[code]));
            var y = x + e;
            while (onBoard(y) and p.board[@intCast(y)] == pos.empty and r.uintLessThan(u8, 3) != 0) y += e;
            if (!onBoard(y) or r.uintLessThan(u8, 5) == 0) continue; // sometimes no pinner
            // a slider whose bits meet the ray's bit (map side 0 = White's king: a Black
            // slider), occasionally the wrong kind
            var cands: [6]u8 = undefined;
            var nc: usize = 0;
            for (1..14) |pc| if (pc != 7 and slider_bits[pc] & dir_bit[code] != 0) {
                cands[nc] = @intCast(pc);
                nc += 1;
            };
            const any_slider = [_]u8{ 3, 4, 5, 10, 11, 12 };
            p.board[@intCast(y)] = if (nc == 0 or r.uintLessThan(u8, 6) == 0) any_slider[r.uintLessThan(usize, 6)] else cands[r.uintLessThan(usize, nc)];
        }
    }
    // pawns next to the target, maybe on a ray, and the counts
    for ([_]i32{ 9, 11, -9, -11 }) |off| {
        const ps = sq + off;
        if (!onBoard(ps) or r.uintLessThan(u8, 3) != 0) continue;
        p.board[@intCast(ps)] = if (r.boolean()) pos.white_pawn else pos.black_pawn;
        if (r.boolean()) {
            const map_side = r.uintLessThan(usize, 2);
            p.king_rays[map_side][@intCast(ps)] = @intCast(1 + 8 * map_side + r.uintLessThan(usize, 8));
        }
    }
    for (0..2) |side| {
        if (r.uintLessThan(u8, 3) == 0) p.pawn_attacks[side][@intCast(sq)] = r.uintLessThan(u8, 3);
    }
    // knights' and kings' entries: sometimes a random board square or a captured entry
    for ([_]usize{ 0, 1, 7, 16, 17, 23 }) |slot| {
        if (r.uintLessThan(u8, 6) != 0) continue;
        const q: u8 = @intCast(21 + 10 * @as(u16, r.uintLessThan(u8, 8)) + r.uintLessThan(u8, 8));
        p.piece_list[slot] = if (slot % 16 != 7 and r.boolean()) q + 0x63 else q;
    }
    return @intCast(sq);
}

test "pinexchange: equals the lifted routines on random walks and forced lines and pins" {
    const gpa = std.testing.allocator;
    const aimg = try gpa.create(lifted.AttackerImage);
    defer gpa.destroy(aimg);
    aimg.init();
    const expect = try gpa.create(Image);
    defer gpa.destroy(expect);
    var rng: std.Random.DefaultPrng = .init(0x41B6_4CEC_5EED);
    var d: Diff = .{ .aimg = aimg, .expect = expect, .rng = rng.random() };
    var w = RandomWalk.init(0x41B6_0001);
    var states: usize = 0;
    var forced: usize = 0;
    const target = 2 * diff_count;
    while (d.calls < target) : (states += 1) {
        // every square of one walk state in 16, a sample of squares of the others
        if (states % 16 == 0) try d.allSquares(&w.p) else try d.someSquares(&w.p, 12);
        // and the state changed by forced lines, each target with many values
        for (0..8) |_| {
            var p = w.p;
            const sq = forceLines(d.rng, &p);
            forced += 1;
            var s: px.Scratch = undefined;
            d.rng.bytes(std.mem.asBytes(&s));
            if (knightIndexesOffMap(&p, sq)) continue;
            for ([2]pos.Side{ .white, .black }) |side| {
                for ([_]u16{ 6, 18, 30, 54, 9, 15, 27, 3, 0x80, d.rng.int(u16) }) |v| try d.one(&p, &s, side, sq, v);
            }
            if (forced % 16 == 0) try d.allSquares(&p);
        }
        w.step();
    }
    std.debug.print("pinexchange vs lifted: {d} calls equal ({d} non-zero, {d} early returns) on {d} walk states and {d} forced states; {d} full-image checks of the lifted routine; DEV-023 corrected changes {d}\n", .{ d.calls, d.nonzero, d.early, states, forced, d.image_checks, d.changed023 });
}

/// A position for the DEV-023 test: `pieces` on an empty board, the king ray codes in
/// `rays` (White's map for codes 1..8, Black's for 9..16), every knight slot captured.
/// With `mirrored`, every square's rank is mirrored and every piece's colour swapped
/// (ray codes +8 / -8), which turns a 41B6 case into the matching 4CEC case.
fn devPosition(pieces: []const [2]u8, rays: []const [2]u8, kings: [2]u8, mirrored: bool) pos.Position {
    const M = struct {
        fn sq(q: u8, m: bool) u8 {
            return if (m) (11 - q / 10) * 10 + q % 10 else q;
        }
        fn code(c: u8, m: bool) u8 {
            if (!m) return c;
            return if (c >= 1 and c <= 6) c + 7 else if (c >= 8 and c <= 13) c - 7 else c;
        }
    };
    var p: pos.Position = .{};
    for (0..120) |q| p.board[q] = if (onBoard(@intCast(q))) pos.empty else pos.border;
    for (pieces) |pc| p.board[M.sq(pc[0], mirrored)] = M.code(pc[1], mirrored);
    for (rays) |ry| {
        const c = if (!mirrored) ry[1] else if (ry[1] <= 8) ry[1] + 8 else ry[1] - 8;
        p.king_rays[if (c <= 8) 0 else 1][M.sq(ry[0], mirrored)] = c;
    }
    for ([_]usize{ 0, 1, 16, 17 }) |slot| p.piece_list[slot] = 0x78;
    const ks = [2]u8{ M.sq(kings[0], mirrored), M.sq(kings[1], mirrored) };
    p.piece_list[7] = if (mirrored) ks[1] else ks[0];
    p.piece_list[16 + 7] = if (mirrored) ks[0] else ks[1];
    p.board[p.piece_list[7]] = pos.white_king;
    p.board[p.piece_list[16 + 7]] = pos.black_king;
    return p;
}

/// Runs 41B6 on the position and 4CEC on its mirror, each checked against the lifted
/// routine, and returns the capturer's lists.
fn devRun(aimg: *lifted.AttackerImage, pieces: []const [2]u8, rays: []const [2]u8, kings: [2]u8, sq: u8, v: u16) ![2][6]u8 {
    var out: [2][6]u8 = undefined;
    for ([2]bool{ false, true }, 0..) |mirrored, i| {
        const p = devPosition(pieces, rays, kings, mirrored);
        const side: pos.Side = if (mirrored) .black else .white;
        const t: u8 = if (mirrored) (11 - sq / 10) * 10 + sq % 10 else sq;
        var s: px.Scratch = .{};
        var sl: px.Scratch = .{};
        const got = px.exchange(&p, &s, side, t, v);
        const want = lifted.attackersOnPosition(aimg, &p, &sl, side, t, v);
        try std.testing.expectEqual(want, got);
        try std.testing.expectEqualSlices(u8, std.mem.asBytes(&sl), std.mem.asBytes(&s));
        out[i] = s.attackers[0..6].*;
    }
    return out;
}

test "pinexchange: DEV-023: 41B6 and 4CEC are not mirrors in two places" {
    const gpa = std.testing.allocator;
    const aimg = try gpa.create(lifted.AttackerImage);
    defer gpa.destroy(aimg);
    aimg.init();
    // 1. An own bishop behind an own queen on a diagonal, the bishop pinned. White: a
    // White queen takes a Black rook on e5 (65); the queen on d4 (54), the bishop on c3
    // (43) behind it, pinned against the White king on b3 (42) by a Black rook on f3 (46)
    // (ray code 5, step +1). 41B6 (4574) counts the bishop: own list 27 (v), 27, 9, 0.
    // The mirror, Black capturing on e4: 4CEC (50A2) tests it, finds it pinned and ends
    // the direction: 27, 27, 0.
    {
        const pieces = [_][2]u8{ .{ 65, pos.black_rook }, .{ 54, pos.white_queen }, .{ 43, pos.white_bishop }, .{ 46, pos.black_rook } };
        const lists = try devRun(aimg, &pieces, &.{.{ 43, 5 }}, .{ 42, 98 }, 65, 27);
        try std.testing.expectEqualSlices(u8, &.{ 27, 27, 9, 0 }, lists[0][0..4]);
        try std.testing.expectEqualSlices(u8, &.{ 27, 27, 0 }, lists[1][0..3]);
    }
    // 2. The mixed state: an opponent queen, then an own queen, then an own bishop, the
    // bishop pinned. White: Black queen d4 (54), White queen c3 (43), White bishop b2
    // (32), pinned against the White king on a2 (31) by a Black rook on f2 (36). 41B6
    // (4718) tests the bishop and ends the direction: own list 27, 27, 0. The mirror:
    // 4CEC (525E) counts it: 27, 27, 9, 0.
    {
        const pieces = [_][2]u8{ .{ 65, pos.black_rook }, .{ 54, pos.black_queen }, .{ 43, pos.white_queen }, .{ 32, pos.white_bishop }, .{ 36, pos.black_rook } };
        const lists = try devRun(aimg, &pieces, &.{.{ 32, 5 }}, .{ 31, 98 }, 65, 27);
        try std.testing.expectEqualSlices(u8, &.{ 27, 27, 0 }, lists[0][0..3]);
        try std.testing.expectEqualSlices(u8, &.{ 27, 27, 9, 0 }, lists[1][0..4]);
    }
}

/// `exchangeFixes` on the DEV-023 position (41B6) or its mirror (4CEC): the result and
/// the capturer's list.
fn devRunFixes(comptime fixes: pos.Fixes, pieces: []const [2]u8, rays: []const [2]u8, kings: [2]u8, sq: u8, v: u16, mirrored: bool) struct { ax: i16, list: [6]u8 } {
    const p = devPosition(pieces, rays, kings, mirrored);
    const side: pos.Side = if (mirrored) .black else .white;
    const t: u8 = if (mirrored) (11 - sq / 10) * 10 + sq % 10 else sq;
    var s: px.Scratch = .{};
    const r = px.exchangeFixes(fixes, &p, &s, side, t, v);
    return .{ .ax = @bitCast(r), .list = s.attackers[0..6].* };
}

test "pinexchange: DEV-023 corrected: the pinned bishop is tested in all four places" {
    // With the switch off, exchangeFixes is exchange (the original).
    // Case 1 (41B6 4574): a White queen takes on e5 with a White bishop behind it on c3,
    // pinned against the king on b3 by the rook on f3. Case 2 (4CEC 525E): the mirror of
    // the mixed state. In each, one routine counts the pinned bishop and the other ends
    // the direction; corrected, both end it.
    const case1 = [_][2]u8{ .{ 65, pos.black_rook }, .{ 54, pos.white_queen }, .{ 43, pos.white_bishop }, .{ 46, pos.black_rook } };
    const case2 = [_][2]u8{ .{ 65, pos.black_rook }, .{ 54, pos.black_queen }, .{ 43, pos.white_queen }, .{ 32, pos.white_bishop }, .{ 36, pos.black_rook } };
    const C = struct { pieces: []const [2]u8, rays: []const [2]u8, kings: [2]u8, orig_counts: [2]bool };
    // orig_counts: whether the original counts the bishop, 41B6 then 4CEC
    const cases = [_]C{
        .{ .pieces = &case1, .rays = &.{.{ 43, 5 }}, .kings = .{ 42, 98 }, .orig_counts = .{ true, false } },
        .{ .pieces = &case2, .rays = &.{.{ 32, 5 }}, .kings = .{ 31, 98 }, .orig_counts = .{ false, true } },
    };
    for (cases) |cs| {
        for ([2]bool{ false, true }, 0..) |mirrored, i| {
            const o = devRunFixes(pos.Fixes.original, cs.pieces, cs.rays, cs.kings, 65, 27, mirrored);
            const f = devRunFixes(fix023, cs.pieces, cs.rays, cs.kings, 65, 27, mirrored);
            // corrected: the bishop is pin-tested and ends the direction, both colours
            try std.testing.expectEqualSlices(u8, &.{ 27, 27, 0 }, f.list[0..3]);
            if (cs.orig_counts[i]) {
                try std.testing.expectEqualSlices(u8, &.{ 27, 27, 9, 0 }, o.list[0..4]);
            } else {
                try std.testing.expectEqual(o.ax, f.ax);
                try std.testing.expectEqualSlices(u8, &o.list, &f.list);
            }
        }
        // corrected, the two routines agree on mirrored positions
        const w = devRunFixes(fix023, cs.pieces, cs.rays, cs.kings, 65, 27, false);
        const b = devRunFixes(fix023, cs.pieces, cs.rays, cs.kings, 65, 27, true);
        try std.testing.expectEqual(w.ax, b.ax);
    }
}

test "pinexchange: DEV-023: positions where the exchange value changes" {
    // A Black pawn on e5 defended by Black rooks on e8 and e7 (case 1) or by a rook on e8
    // and the Black queen on d4 (case 2); White captures first with a piece of value 3 (a
    // pawn's), then has its queen and, behind it, a bishop pinned against its king by a
    // rook on the third or second rank: behind its queen (case 1) or in the mixed state
    // (case 2).
    const case1 = [_][2]u8{ .{ 54, pos.white_queen }, .{ 43, pos.white_bishop }, .{ 46, pos.black_rook }, .{ 65, pos.black_pawn }, .{ 95, pos.black_rook }, .{ 85, pos.black_rook } };
    const case2 = [_][2]u8{ .{ 54, pos.black_queen }, .{ 43, pos.white_queen }, .{ 32, pos.white_bishop }, .{ 36, pos.black_rook }, .{ 65, pos.black_pawn }, .{ 95, pos.black_rook } };
    // Case 1, 41B6 (4574): the original counts the pinned bishop (own list 3, 27, 9)
    // against the two rooks and wins the pawn (3); corrected, the bishop is pinned and
    // ends the diagonal (3, 27): 0. 4CEC on the mirror (50A2) already gives 0.
    {
        const o = devRunFixes(pos.Fixes.original, &case1, &.{.{ 43, 5 }}, .{ 42, 98 }, 65, 3, false);
        const f = devRunFixes(fix023, &case1, &.{.{ 43, 5 }}, .{ 42, 98 }, 65, 3, false);
        try std.testing.expectEqual(@as(i16, 3), o.ax);
        try std.testing.expectEqualSlices(u8, &.{ 3, 27, 9, 0 }, o.list[0..4]);
        try std.testing.expectEqual(@as(i16, 0), f.ax);
        try std.testing.expectEqualSlices(u8, &.{ 3, 27, 0 }, f.list[0..3]);
        const ob = devRunFixes(pos.Fixes.original, &case1, &.{.{ 43, 5 }}, .{ 42, 98 }, 65, 3, true);
        const fb = devRunFixes(fix023, &case1, &.{.{ 43, 5 }}, .{ 42, 98 }, 65, 3, true);
        try std.testing.expectEqual(@as(i16, 0), ob.ax);
        try std.testing.expectEqual(@as(i16, 0), fb.ax);
    }
    // Case 2, 4CEC on the mirror (525E): the original counts the pinned bishop (3, 27,
    // 9) and wins the pawn (3); corrected, it ends the diagonal (3, 27): 0, which is what
    // 41B6 (4718) gives on the unmirrored position, original or corrected.
    {
        const ow = devRunFixes(pos.Fixes.original, &case2, &.{.{ 32, 5 }}, .{ 31, 98 }, 65, 3, false);
        const fw = devRunFixes(fix023, &case2, &.{.{ 32, 5 }}, .{ 31, 98 }, 65, 3, false);
        const o = devRunFixes(pos.Fixes.original, &case2, &.{.{ 32, 5 }}, .{ 31, 98 }, 65, 3, true);
        const f = devRunFixes(fix023, &case2, &.{.{ 32, 5 }}, .{ 31, 98 }, 65, 3, true);
        try std.testing.expectEqual(@as(i16, 3), o.ax);
        try std.testing.expectEqualSlices(u8, &.{ 3, 27, 9, 0 }, o.list[0..4]);
        try std.testing.expectEqual(@as(i16, 0), f.ax);
        try std.testing.expectEqualSlices(u8, &.{ 3, 27, 0 }, f.list[0..3]);
        try std.testing.expectEqual(@as(i16, 0), ow.ax);
        try std.testing.expectEqual(@as(i16, 0), fw.ax);
    }
}

// ---------------------------------------------------------------------------
// Benchmark: -Dbench=true -Dtest-filter="bench: pinexchange"
// ---------------------------------------------------------------------------

const bench = @import("bench.zig");

const BenchIn = struct { p: pos.Position, s: px.Scratch, side: pos.Side, sq: u8, v: u16 };
const Patch = struct { off: u16, b: u8 };
const BenchCall = struct { tag: u8, regs: [8]u16, d0: u32, d1: u32, u0: u32, u1: u32 };

test "bench: pinexchange: 41B6/4CEC hand-written against the lifted routines on every recorded call" {
    if (!bench.enabled) return;
    const gpa = std.heap.page_allocator;
    var ins: std.ArrayList(BenchIn) = .empty;
    defer ins.deinit(gpa);
    var calls: std.ArrayList(BenchCall) = .empty;
    defer calls.deinit(gpa);
    var deltas: std.ArrayList(Patch) = .empty;
    defer deltas.deinit(gpa);
    var undo: std.ArrayList(Patch) = .empty;
    defer undo.deinit(gpa);
    const img = try gpa.create(Image);
    defer gpa.destroy(img);
    const work = try gpa.create(Image);
    defer gpa.destroy(work);
    // One sequence over all files: each file starts from a zero image (a record whose
    // delta resets it is added first).
    for (files) |name| {
        const data = try readVectors(gpa, name);
        defer gpa.free(data);
        var c: Cursor = .{ .d = data[6..] };
        // a reset: the bytes that are non-zero now, back to 0
        {
            const d0: u32 = @intCast(deltas.items.len);
            for (0..0x10000) |i| if (img[i] != 0) try deltas.append(gpa, .{ .off = @intCast(i), .b = img[i] });
            img.* = @splat(0);
            try calls.append(gpa, .{ .tag = 0, .regs = @splat(0), .d0 = d0, .d1 = @intCast(deltas.items.len), .u0 = 0, .u1 = 0 });
        }
        while (true) {
            const tag = c.byte();
            if (tag == 0) break;
            const d0: u32 = @intCast(deltas.items.len);
            {
                const n = c.varint();
                var prev: isize = -1;
                for (0..n) |_| {
                    const off: usize = @intCast(prev + 1 + @as(isize, @intCast(c.varint())));
                    const x = c.byte();
                    img[off] ^= x;
                    try deltas.append(gpa, .{ .off = @intCast(off), .b = x });
                    prev = @intCast(off);
                }
            }
            var regs: [8]u16 = undefined;
            for (&regs) |*r| r.* = c.word();
            switch (tag) {
                1, 2 => {
                    _ = c.word();
                    c.skipDelta();
                },
                3, 4 => {
                    _ = c.word();
                    _ = c.take(c.varint() * 9);
                    _ = c.word();
                    c.skipDelta();
                    if (c.byte() != 0) _ = c.take(c.varint() * 25);
                    try calls.append(gpa, .{ .tag = 0, .regs = regs, .d0 = d0, .d1 = @intCast(deltas.items.len), .u0 = 0, .u1 = 0 });
                    continue;
                },
                else => return error.BadVectorFile,
            }
            var call: BenchCall = .{ .tag = tag, .regs = regs, .d0 = d0, .d1 = @intCast(deltas.items.len), .u0 = 0, .u1 = 0 };
            work.* = img.*;
            var m: lifted.Machine = .{ .mem = work, .ax = regs[0], .bx = regs[1], .cx = regs[2], .dx = regs[3], .si = regs[4], .di = regs[5], .bp = regs[6], .sp = regs[7] };
            if (tag == 1) attackers.run41B6(&m, attackers.entry_41b6) else attackers.run4CEC(&m, attackers.entry_4cec);
            call.u0 = @intCast(undo.items.len);
            for (0..0x10000) |i| if (work[i] != img[i]) try undo.append(gpa, .{ .off = @intCast(i), .b = img[i] });
            call.u1 = @intCast(undo.items.len);
            try calls.append(gpa, call);
            var e: BenchIn = .{ .p = .{}, .s = .{}, .side = if (tag == 1) .white else .black, .sq = img[regs[7] +% 4], .v = std.mem.readInt(u16, img[regs[7] +% 6 ..][0..2], .little) };
            fromImage(img, &e.p, &e.s);
            try ins.append(gpa, e);
        }
    }
    const passes = 40;
    // The lifted routines on the image (as the threat evaluators call them): every
    // record's delta applied, the attacker calls run and their changes put back; the loop
    // without the calls is timed and taken off.
    var lif: bench.Best = .{};
    var lif_over: bench.Best = .{};
    for (0..passes) |_| {
        inline for (.{ false, true }) |run| {
            img.* = @splat(0);
            const t0 = bench.now();
            for (calls.items) |call| {
                for (deltas.items[call.d0..call.d1]) |pt| img[pt.off] ^= pt.b;
                if (call.tag == 0) continue;
                if (run) {
                    const r = call.regs;
                    var m: lifted.Machine = .{ .mem = img, .ax = r[0], .bx = r[1], .cx = r[2], .dx = r[3], .si = r[4], .di = r[5], .bp = r[6], .sp = r[7] };
                    if (call.tag == 1) attackers.run41B6(&m, attackers.entry_41b6) else attackers.run4CEC(&m, attackers.entry_4cec);
                    bench.keep(m.ax);
                }
                for (undo.items[call.u0..call.u1]) |pt| img[pt.off] = pt.b;
            }
            if (run) lif.pass(t0) else lif_over.pass(t0);
        }
    }
    lif.report("pinexchange: lifted 41B6/4CEC on the DGROUP image", ins.items.len, passes, lif_over.ns);

    // On a `Position`. In a search the position is in the first-level cache; here the
    // recorded positions are not, so (as src/see_test.zig does) the loop copies what the
    // routines read (board, lists, pawn attacks, king rays) into a small ring of working
    // positions `ahead` calls before each is used; the loop with the copies alone is
    // timed and taken off. The three routines are timed one after another in each pass.
    const aimg = try gpa.create(lifted.AttackerImage);
    defer gpa.destroy(aimg);
    aimg.init();
    const ahead = 8;
    const ring = try gpa.alloc(pos.Position, 2 * ahead);
    defer gpa.free(ring);
    for (ring) |*w| w.* = .{};
    const reps = 8;
    const items = ins.items;
    const Load = struct {
        inline fn load(w: *pos.Position, e: *const BenchIn) void {
            w.board = e.p.board;
            w.piece_list = e.p.piece_list;
            w.pawn_attacks = e.p.pawn_attacks;
            w.king_rays = e.p.king_rays;
        }
    };
    var over: bench.Best = .{};
    var best: [6]bench.Best = @splat(.{});
    for (0..passes) |_| {
        var t0 = bench.now();
        for (0..reps) |_| for (items, 0..) |*e, i| {
            Load.load(&ring[(i + ahead) % (2 * ahead)], &items[(i + ahead) % items.len]);
            bench.keep(e.sq);
            bench.keep(&ring[i % (2 * ahead)]);
        };
        over.pass(t0);
        inline for (0..6) |k| {
            var s: px.Scratch = .{};
            for (items[0..ahead], 0..) |*e, i| Load.load(&ring[i], e);
            t0 = bench.now();
            for (0..reps) |_| for (items, 0..) |*e, i| {
                Load.load(&ring[(i + ahead) % (2 * ahead)], &items[(i + ahead) % items.len]);
                const w = &ring[i % (2 * ahead)];
                const r = switch (k) {
                    0 => @call(.never_inline, px.exchange, .{ w, &s, e.side, e.sq, e.v }),
                    1 => lifted.attackersOnPosition(aimg, w, &s, e.side, e.sq, e.v),
                    3 => @call(.never_inline, px.exchangeFixes, .{ fix023, w, &s, e.side, e.sq, e.v }),
                    4 => @call(.never_inline, px.exchangeFixes, .{ fix058, w, &s, e.side, e.sq, e.v }),
                    5 => @call(.never_inline, see.seeFixes, .{ fix058, w, &s, e.side, e.sq, e.v }),
                    else => @call(.never_inline, see.see, .{ w, &s, e.side, e.sq, e.v }),
                };
                bench.keep(r);
            };
            best[k].pass(t0);
        }
    }
    best[0].report("pinexchange: hand-written 41B6/4CEC on a Position", reps * items.len, passes, over.ns);
    best[1].report("pinexchange: lifted 41B6/4CEC through attackersOnPosition (copies in and out)", reps * items.len, passes, over.ns);
    best[2].report("pinexchange: see.see (2B9F:C32A/CAC2) on the same inputs (yardstick)", reps * items.len, passes, over.ns);
    best[3].report("pinexchange: hand-written 41B6/4CEC with DEV-023 corrected", reps * items.len, passes, over.ns);
    best[4].report("pinexchange: hand-written 41B6/4CEC with DEV-058 corrected", reps * items.len, passes, over.ns);
    best[5].report("pinexchange: see.seeFixes with DEV-058 corrected (yardstick)", reps * items.len, passes, over.ns);
}
