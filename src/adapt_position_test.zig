//! Stage A, step 3 (docs/arch/60-engine-assembly.md section 5): the position vectors
//! (tests/golden/position/*.zst, format in tools/port/gen_position_vectors.py) replayed
//! through the DGROUP image. The state lives only in the image: the recorded changes
//! between calls are applied to it, each call goes through src/adapt_position.zig, and
//! after each call the image, read back at the recording's addresses, must equal the
//! original's state. A field missing from the generated map, or mapped to the wrong
//! address, fails at the first call that reads or writes it.

const std = @import("std");
const pos = @import("position.zig");
const dgroup = @import("dgroup.zig");
const adapt = @import("adapt_position.zig");
const vec = @import("adapt_vectors.zig");

const Routine = enum(u8) { make = 1, unmake = 2, hash = 3 };
const Counts = struct { make: usize = 0, unmake: usize = 0, hash: usize = 0 };

fn replay(gpa: std.mem.Allocator, name: []const u8) !Counts {
    const data = try vec.readVectors(gpa, "position", name);
    defer gpa.free(data);
    var c: vec.Cursor = .{ .d = data };
    try std.testing.expectEqualSlices(u8, "MCPV", c.take(4));
    try std.testing.expectEqual(@as(u16, 1), c.int(u16));
    const state_size = c.int(u16);
    const nfields = c.int(u16);
    // The recorder's field table gives each region's DGROUP address.
    var list: [64]vec.Regions.Region = undefined;
    var names: [64][8]u8 = undefined;
    for (0..nfields) |i| {
        _ = c.int(u16); // offset in the record image: regions follow in order
        const dg = c.int(u16);
        const kind = c.byte();
        const count = c.byte();
        const n = std.fmt.bufPrint(&names[i], "f{d}", .{i}) catch unreachable;
        list[i] = .{ .name = n, .dg = dg, .len = @as(usize, count) * (if (kind == 'w') @as(usize, 2) else 1) };
        // Every recorded byte is a byte of the generated Position map.
        for (0..list[i].len) |k| {
            if (!adapt.PositionMap.covers(dg + k)) {
                std.debug.print("DG:{X:0>4} is recorded but not in the Position map\n", .{dg + k});
                return error.MapMissesRecordedByte;
            }
        }
    }
    var regions = try vec.Regions.init(gpa, list[0..nfields]);
    defer regions.deinit(gpa);
    try std.testing.expectEqual(@as(usize, state_size), regions.len());

    const truth = try gpa.alloc(u8, state_size);
    defer gpa.free(truth);
    const got = try gpa.alloc(u8, state_size);
    defer gpa.free(got);
    @memcpy(truth, c.take(state_size));
    const img = try gpa.create(dgroup.Image);
    defer gpa.destroy(img);
    dgroup.init(img);
    regions.scatter(truth, img);

    var counts: Counts = .{};
    var index: usize = 0;
    while (true) {
        const tag = c.byte();
        if (tag == 0) {
            try std.testing.expectEqual(counts.make, c.int(u32));
            try std.testing.expectEqual(counts.unmake, c.int(u32));
            try std.testing.expectEqual(counts.hash, c.int(u32));
            return counts;
        }
        if (tag == 4) {
            regions.gather(img, got);
            try vec.expectRecord(&regions, c.take(state_size), got, "{s}: checkpoint after call {d}", .{ name, index });
            continue;
        }
        const routine = std.enums.fromInt(Routine, tag) orelse return error.BadRecordTag;
        _ = c.apply(truth, &regions, img);
        const move: pos.Move = .{ .from = c.byte(), .to = c.byte(), .flag = c.byte() };
        var undo: pos.Undo = .{};
        var out_ok = true;
        switch (routine) {
            .make => {
                const side = c.byte();
                const ply = c.int(u16);
                const cap = c.byte();
                const written = c.byte() != 0;
                const slot_out = c.byte();
                undo = .{ .captured = 0xA5, .captured_slot = 0xA5 };
                adapt.makeMove(img, move, @fromBackingInt(@as(u1, @intCast(side))), ply, &undo);
                out_ok = undo.captured == cap and undo.captured_slot == (if (written) slot_out else 0xA5);
                counts.make += 1;
            },
            .unmake => {
                const side = c.byte();
                const cap = c.byte();
                const slot_in = c.byte();
                const slot_out = c.byte();
                undo = .{ .captured = cap, .captured_slot = slot_in };
                adapt.unmakeMove(img, move, @fromBackingInt(@as(u1, @intCast(side))), &undo);
                out_ok = undo.captured == cap and undo.captured_slot == slot_out;
                counts.unmake += 1;
            },
            .hash => {
                adapt.updateHashKey(img, move, .original);
                counts.hash += 1;
            },
        }
        _ = c.apply(truth, null, null);
        if (!out_ok) {
            std.debug.print("\n{s}: call {d} ({t}): the captured piece or slot differs\n", .{ name, index, routine });
            return error.MismatchWithOriginal;
        }
        regions.gather(img, got);
        try vec.expectRecord(&regions, truth, got, "{s}: call {d} differs: {t} from {d} to {d} flag {d}", .{ name, index, routine, move.from, move.to, move.flag });
        index += 1;
    }
}

test "stage A: position vectors replayed through the DGROUP image" {
    const gpa = std.testing.allocator;
    var total: Counts = .{};
    for ([_][]const u8{ "A.zst", "C.zst", "D.zst", "E.zst" }) |name| {
        const n = try replay(gpa, name);
        total.make += n.make;
        total.unmake += n.unmake;
        total.hash += n.hash;
    }
    std.debug.print("stage A position: make_move {d}, unmake_move {d}, update_hash_key {d} calls through the image, all equal\n", .{ total.make, total.unmake, total.hash });
}

test "stage A: the Position map covers model.FIELDS at their addresses" {
    // tools/research/position/model.py FIELDS (the recorder's field table), with the
    // Position field each must land in: a map that names the right bytes but the wrong
    // field would load one variable into another.
    const Want = struct { dg: u16, field: []const u8, index: usize };
    const want = [_]Want{
        .{ .dg = 0x9EF6, .field = "board", .index = 0 },              .{ .dg = 0xA03A, .field = "piece_list", .index = 0 },
        .{ .dg = 0xA04A, .field = "piece_list", .index = 16 },        .{ .dg = 0xA28C, .field = "square_slot", .index = 0 },
        .{ .dg = 0xA51C, .field = "pawn_attacks", .index = 0 },       .{ .dg = 0x37DA, .field = "pawn_attacks", .index = 120 },
        .{ .dg = 0xA09E, .field = "king_rays", .index = 0 },          .{ .dg = 0xA164, .field = "king_rays", .index = 120 },
        .{ .dg = 0xA8C8, .field = "pawns_per_file", .index = 0 },     .{ .dg = 0x9EA8, .field = "pawns_per_file", .index = 10 },
        .{ .dg = 0x8DE4, .field = "material", .index = 0 },           .{ .dg = 0x8DE6, .field = "material", .index = 1 },
        .{ .dg = 0xAE38, .field = "piece_material", .index = 0 },     .{ .dg = 0xAE3A, .field = "piece_material", .index = 1 },
        .{ .dg = 0x378E, .field = "piece_material_sum", .index = 0 }, .{ .dg = 0xA420, .field = "total_material", .index = 0 },
        .{ .dg = 0xA35E, .field = "material_balance", .index = 0 },   .{ .dg = 0xA8D2, .field = "piece_balance", .index = 0 },
        .{ .dg = 0xA4C6, .field = "material_balance_2", .index = 0 }, .{ .dg = 0x7182, .field = "piece_square_sum", .index = 0 },
        .{ .dg = 0x154A, .field = "men", .index = 0 },                .{ .dg = 0x931A, .field = "piece_count", .index = 0 },
        .{ .dg = 0x931B, .field = "piece_count", .index = 1 },        .{ .dg = 0x90AA, .field = "pawn_count", .index = 0 },
        .{ .dg = 0xAB1E, .field = "side_pawn_count", .index = 0 },    .{ .dg = 0x741A, .field = "side_pawn_count", .index = 1 },
        .{ .dg = 0xB520, .field = "pawns_on_dark", .index = 0 },      .{ .dg = 0xA354, .field = "pawns_on_dark", .index = 1 },
        .{ .dg = 0xA22E, .field = "king_file", .index = 0 },          .{ .dg = 0xA22F, .field = "king_file", .index = 1 },
        .{ .dg = 0x70F0, .field = "king_rank", .index = 0 },          .{ .dg = 0x70F1, .field = "king_rank", .index = 1 },
        .{ .dg = 0xB426, .field = "oo_lost_at", .index = 0 },         .{ .dg = 0x3A30, .field = "ooo_lost_at", .index = 0 },
        .{ .dg = 0xB428, .field = "oo_lost_at", .index = 1 },         .{ .dg = 0x3A32, .field = "ooo_lost_at", .index = 1 },
        .{ .dg = 0x9FC8, .field = "game_ply", .index = 0 },           .{ .dg = 0x8CCC, .field = "hash_key", .index = 0 },
        .{ .dg = 0x8CD2, .field = "pawn_hash_key", .index = 0 },      .{ .dg = 0x9EC8, .field = "ep_square_by_ply", .index = 0 },
        .{ .dg = 0x8C06, .field = "check_by_ply", .index = 0 },       .{ .dg = 0x8BBE, .field = "reversible_by_ply", .index = 0 },
        .{ .dg = 0x3626, .field = "quiet_move_by_ply", .index = 0 },
    };
    for (want) |w| {
        var found = false;
        inline for (adapt.PositionMap.map) |e| {
            if (e.addr == w.dg and std.mem.eql(u8, e.field, w.field) and e.first == w.index) found = true;
        }
        if (!found) {
            std.debug.print("no map entry puts DG:{X:0>4} at Position.{s}[{d}]\n", .{ w.dg, w.field, w.index });
            return error.MapDisagreesWithTransfer;
        }
    }
    try std.testing.expectEqual(want.len, adapt.PositionMap.map.len);
}

test "stage A: make and unmake through the image leave the image as the struct calls do" {
    // From the start position built in the image, a few moves made and taken back through
    // the adapters must leave the same image as the same calls on a Position stored whole.
    const gpa = std.testing.allocator;
    const a = try gpa.create(dgroup.Image);
    defer gpa.destroy(a);
    const b = try gpa.create(dgroup.Image);
    defer gpa.destroy(b);
    dgroup.init(a);
    var p: pos.Position = .{};
    adapt.PositionMap.load(&p, a);
    const setup = @import("setup.zig");
    var sv: setup.SetupVars = .{};
    setup.newGame(&p, &sv);
    adapt.PositionMap.storeAll(&p, a);
    b.* = a.*;
    const moves = [_]pos.Move{
        .{ .from = 35, .to = 55, .flag = 0 }, // e2e4
        .{ .from = 84, .to = 64, .flag = 0 }, // d7d5
        .{ .from = 55, .to = 64, .flag = 0 }, // e4xd5
    };
    var undos: [3]pos.Undo = undefined;
    var saved: [3]pos.Undo = undefined;
    var side: pos.Side = .white;
    for (moves, 0..) |m, i| {
        undos[i] = .{};
        adapt.updateHashKey(a, m, .original);
        adapt.makeMove(a, m, side, i + 1, &undos[i]);
        var u: pos.Undo = .{};
        p.updateHashKey(m, .original);
        p.makeMove(m, side, i + 1, &u);
        try std.testing.expectEqual(u, undos[i]);
        saved[i] = u;
        side = side.other();
    }
    var i: usize = moves.len;
    while (i > 0) {
        i -= 1;
        side = side.other();
        adapt.unmakeMove(a, moves[i], side, &undos[i]);
        var u = saved[i];
        p.unmakeMove(moves[i], side, &u);
    }
    adapt.PositionMap.storeAll(&p, b);
    try std.testing.expectEqualSlices(u8, b, a);
}
