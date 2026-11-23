//! Stage A, step 7: the threat-evaluator wrapper (src/adapt_threats.zig) and the attacker
//! routines on the shared image (src/adapt_staticeval.zig `attackersOnImage`), against
//! every call recorded in tests/golden/evalthreats/*.zst (format:
//! tools/port/gen_evalthreats_vectors.py; src/threats_test.zig reads it the same way).
//!
//! Each recorded call carries the whole of DGROUP and the registers at entry. The
//! wrapper is called as the node calls it: the arguments are taken from the recorded
//! stack (`[sp+4]` ply, `[sp+6]` count, `[sp+8]` the counter's address), the counter
//! byte from the recorded frame; the wrapper builds its own frame and stack. AX, the
//! counter after the call and every byte of DGROUP must equal the original's, except
//! the two stacks (2 KB below the recorded SP, as threats_test.zig, and the wrapper's
//! own stack area; for the threat routines also the original's return address and three
//! argument words above its SP), the original's counter byte (compared through `counter`), and the
//! bytes the timer interrupt writes.

const std = @import("std");
const dgroup = @import("dgroup.zig");
const at = @import("adapt_threats.zig");
const ase = @import("adapt_staticeval.zig");
const vec = @import("adapt_vectors.zig");

const Image = dgroup.Image;

/// tools/research/evalthreats/check.py INTERRUPT_BYTES (as threats_test.zig).
const irq_bytes = [_]u16{ 0x0058, 0x0059, 0x2A68, 0x2A69, 0xAB1C, 0xAB1D, 0x75B6, 0x3682, 0x8DDC, 0x9EB2, 0x367C, 0x8DD6, 0x8DD4 };
const slack = 0x800;
/// The wrapper's stack area: from below its call SP to the top of the segment.
const own_stack_lo: usize = at.call_sp - slack;

fn word(img: *const Image, a: u16) u16 {
    return @as(u16, img[a]) | @as(u16, img[a +% 1]) << 8;
}

fn excluded(a: usize, caller_sp: u16, flagp: ?u16) bool {
    const lo: u16 = caller_sp -% slack;
    const x: u16 = @intCast(a);
    if (lo <= caller_sp) {
        if (x >= lo and x < caller_sp) return true;
    } else if (x >= lo or x < caller_sp) return true;
    if (a >= own_stack_lo) return true;
    if (flagp != null and x == flagp.?) return true;
    return std.mem.indexOfScalar(u16, &irq_bytes, x) != null;
}

fn firstDiff(got: *const Image, want: *const Image, caller_sp: u16, flagp: ?u16) ?usize {
    for (0..0x10000) |i| {
        if (got[i] != want[i] and !excluded(i, caller_sp, flagp)) return i;
    }
    return null;
}

const Counts = struct { att: [2]usize = .{ 0, 0 }, threats: [2]usize = .{ 0, 0 }, sp_min: u16 = 0xFFFF, sp_max: u16 = 0, used_above: usize = 0 };

fn replay(gpa: std.mem.Allocator, name: []const u8, n: *Counts) !void {
    const data = try vec.readVectors(gpa, "evalthreats", name);
    defer gpa.free(data);
    var c: vec.Cursor = .{ .d = data };
    try std.testing.expectEqualSlices(u8, "MCET", c.take(4));
    try std.testing.expectEqual(@as(u16, 1), c.int(u16));
    const img = try gpa.create(Image);
    defer gpa.destroy(img);
    const work = try gpa.create(Image);
    defer gpa.destroy(work);
    const want = try gpa.create(Image);
    defer gpa.destroy(want);
    img.* = @splat(0);
    var index: usize = 0;
    while (true) : (index += 1) {
        const tag = c.byte();
        if (tag == 0) return;
        _ = c.apply(img, null, null);
        var regs: [8]u16 = undefined;
        for (&regs) |*r| r.* = c.int(u16);
        const sp = regs[7];
        n.sp_min = @min(n.sp_min, sp);
        n.sp_max = @max(n.sp_max, sp);
        // Whether the original ever held anything in the wrapper's stack area.
        for (img[own_stack_lo..]) |b| n.used_above += @intFromBool(b != 0);
        work.* = img.*;
        switch (tag) {
            1, 2 => {
                const ax = c.int(u16);
                want.* = img.*;
                _ = c.apply(want, null, null);
                // a far call: [sp] IP, [sp+2] CS, [sp+4] square, [sp+6] value
                const sq = word(img, sp +% 4);
                const v = word(img, sp +% 6);
                const got = ase.attackersOnImage(work, if (tag == 1) .white else .black, sq, v);
                if (got != ax) {
                    std.debug.print("\n{s}: record {d}: attackers {s}({d}, {d}) on the image: AX want {X:0>4}, got {X:0>4}\n", .{ name, index, if (tag == 1) "41B6" else "4CEC", sq, v, ax, got });
                    return error.MismatchWithOriginal;
                }
                if (firstDiff(work, want, sp +% 4, null)) |off| {
                    std.debug.print("\n{s}: record {d}: attackers({d}, {d}) on the image: DG:{X:0>4} want {X:0>2}, got {X:0>2}\n", .{ name, index, sq, v, off, want[off], work[off] });
                    return error.MismatchWithOriginal;
                }
                n.att[tag - 1] += 1;
            },
            3, 4 => {
                const flagp = c.int(u16);
                const ncalls = c.varint();
                _ = c.take(ncalls * 9);
                const ax = c.int(u16);
                want.* = img.*;
                _ = c.apply(want, null, null);
                if (c.byte() != 0) _ = c.take(c.varint() * 25);
                const ply: i16 = @bitCast(word(img, sp +% 4));
                const count = word(img, sp +% 6);
                try std.testing.expectEqual(flagp, word(img, sp +% 8));
                var counter = img[flagp];
                const got: i16 = at.threats(work, if (tag == 3) .white else .black, ply, count, &counter);
                if (@as(u16, @bitCast(got)) != ax or counter != want[flagp]) {
                    std.debug.print("\n{s}: record {d}: threats({s}, ply {d}, count {d}): AX want {d}, got {d}; counter want {d}, got {d}\n", .{ name, index, if (tag == 3) "A026" else "CD20", ply, count, @as(i16, @bitCast(ax)), got, want[flagp], counter });
                    return error.MismatchWithOriginal;
                }
                // The original's arguments (the routine overwrites the ply with 100 in the
                // first two iterations) lie in its stack; the wrapper's in its own.
                if (firstDiff(work, want, sp +% 10, flagp)) |off| {
                    std.debug.print("\n{s}: record {d}: threats(ply {d}): DG:{X:0>4} want {X:0>2}, got {X:0>2}\n", .{ name, index, ply, off, want[off], work[off] });
                    return error.MismatchWithOriginal;
                }
                n.threats[tag - 3] += 1;
            },
            else => return error.BadVectorFile,
        }
    }
}

test "stage A: threat evaluators and attacker routines on the shared image, as the node and static_eval call them" {
    const gpa = std.testing.allocator;
    var n: Counts = .{};
    for ([_][]const u8{ "A.zst", "B.zst", "C.zst", "D.zst", "E.zst" }) |f| try replay(gpa, f, &n);
    std.debug.print("stage A threats: A026 {d}, CD20 {d} through the wrapper; 41B6 {d}, 4CEC {d} on the image; all equal (recorded SP {X:0>4}-{X:0>4}, the wrapper's stack from {X:0>4})\n", .{ n.threats[0], n.threats[1], n.att[0], n.att[1], n.sp_min, n.sp_max, own_stack_lo });
    try std.testing.expect(n.threats[0] > 0 and n.threats[1] > 0 and n.att[0] > 0 and n.att[1] > 0);
    // The wrapper's stack must lie above every recorded SP's 2 KB, and the original's
    // stack must not reach the wrapper's frame, or the exclusions would hide state.
    try std.testing.expect(n.sp_max < own_stack_lo);
    // The wrapper's stack area held only zeros in every recorded image of the original:
    // no variable lives there for the wrapper to overwrite.
    try std.testing.expectEqual(@as(usize, 0), n.used_above);
}
