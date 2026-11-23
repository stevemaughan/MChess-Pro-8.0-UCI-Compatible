//! Stage B step 7, stages 3b and 3c-1 (docs/arch/60-engine-assembly.md section 5): the
//! iteration loop's view (`rootsearch.RootState`) and main's view (`rootprep.PrepState`)
//! inside the node domain.
//!
//! Since stage 3c-1 the domain is entered once for the whole search (src/engine_root.zig
//! `search`), and main's view is bound by the same rule as the loop's (`rootprep.bindDomain`).
//!
//! While the search runs, the node domain's structs hold the state: every variable of a view
//! whose byte a struct of the domain holds must be reached in that struct, at that byte, and
//! every other field must be one no struct of the domain holds or covers, so that a byte never
//! has two homes during the search. Until stage 3c-2 the root variables that lay inside the
//! over-long bishop activity tables (A356, A35C, A362, A3F5, A3F6, A3FA) were an exception;
//! since the tables have the original's room of 100 bytes no struct covers them, and their
//! one home is the image, where the root's views write them (the coverage test below).
//!
//! Since stage 3c-2 prepare_eval runs inside the domain too: its tables (`evaltables.Tables`)
//! point at the domain's structs by the same rule (`evaltables.bindDomain`, the last test).

const std = @import("std");
const si = @import("state_image.zig");
const est = @import("engine_state.zig");
const ert = @import("engine_root.zig");
const rs = @import("rootsearch.zig");
const rp = @import("rootprep.zig");
const sn = @import("searchnode.zig");
const dgroup = @import("dgroup.zig");
const evaltables = @import("evaltables.zig");
const gamemove = @import("gamemove.zig");
const tbud = @import("timebudget.zig");
const ert_test = @import("engine_root_test.zig");

/// The loop's view's tables, by field and DGROUP address (`rootsearch.bindRoot`,
/// `bindDomain`).
const tables = rs.tables;

/// Main's tables (`rootprep.bindRoot`, `bindDomain`).
const prep_tables = rp.tables;

/// Bytes a field of type `F` covers in the image, in the original's widths (a pointer:
/// what it points at).
fn imageBytes(comptime F: type) usize {
    const T = switch (@typeInfo(F)) {
        .pointer => |p| p.child,
        else => F,
    };
    return dgroup.flatLen(T) * dgroup.elemSize(dgroup.Flat(T));
}

/// The member that holds DG byte `a` (none: -1), and its offset.
fn holder(l: *const est.Layout, a: usize) struct { m: i32, off: i32 } {
    for (0..est.n_members) |m| {
        const off = l.offOf(m)[a];
        if (off < 0) continue;
        return .{ .m = @intCast(m), .off = off };
    }
    return .{ .m = -1, .off = -1 };
}

const Homes = struct {
    st: *sn.State,
    d: *est.Members,
    img: *dgroup.Image,

    fn base(h: Homes, m: usize) usize {
        return switch (@as(est.Member, @fromBackingInt(@intCast(m)))) {
            .st => @intFromPtr(h.st),
            .p => @intFromPtr(&h.d.p),
            .ev => @intFromPtr(&h.d.ev),
            .sv => @intFromPtr(&h.d.sv),
            .s => @intFromPtr(&h.d.s),
            .lv => @intFromPtr(&h.d.lv),
            .tv => @intFromPtr(&h.d.tv),
            .gv => @intFromPtr(&h.d.gv),
            .ts => @intFromPtr(&h.d.ts),
            .rv => @intFromPtr(&h.d.rv),
            .pg => @intFromPtr(&h.d.pg),
        };
    }
};

/// The bytes of `st`'s fields that are not where the rule above puts them; prints the
/// first few. `bound` counts the bytes reached in the domain.
fn misplaced(l: *const est.Layout, h: Homes, st: *const rs.RootState, bound: *usize) usize {
    var bad: usize = 0;
    inline for (ert.root_layout) |f| bad += misplacedField(rs.RootState, f[0], f[1], l, h, st, bound, bad, null);
    inline for (tables) |f| bad += misplacedField(rs.RootState, f[0], f[1], l, h, st, bound, bad, null);
    return bad;
}

/// `misplaced` for main's view (`rootprep.PrepState`, stage 3c-1). The low page is two
/// tables, around DG:62-63, the node's ply ceiling, which main reads through its own field
/// `ply_ceiling` (`rootprep.lowByte`) and never writes.
fn misplacedPrep(l: *const est.Layout, h: Homes, st: *const rp.PrepState, bound: *usize) usize {
    var bad: usize = 0;
    inline for (ert.prep_layout) |f| bad += misplacedField(rp.PrepState, f[0], f[1], l, h, st, bound, bad, null);
    inline for (prep_tables) |f| bad += misplacedField(rp.PrepState, f[0], f[1], l, h, st, bound, bad, null);
    return bad;
}

fn misplacedField(comptime S: type, comptime name: []const u8, addr: u16, l: *const est.Layout, h: Homes, st: *const S, bound: *usize, bad_before: usize, skip: ?[2]usize) usize {
    const F = @FieldType(S, name);
    const n = comptime imageBytes(F);
    var bad: usize = 0;
    for (0..n) |k| {
        const a = @as(usize, addr) + k;
        if (skip) |sk| if (a >= sk[0] and a < sk[1]) continue;
        const hd = holder(l, a);
        var why: ?[]const u8 = null;
        if (comptime @typeInfo(F) == .pointer) {
            const at = @intFromPtr(@field(st, name)) + k;
            if (hd.m < 0) {
                // Stage B step 8, stage 7: every byte has a member for its home.
                why = "no member holds it";
            } else if (at != h.base(@intCast(hd.m)) + @as(usize, @intCast(hd.off))) {
                why = "the field does not point at the byte of the struct that holds it";
            } else bound.* += 1;
        } else if (hd.m >= 0) why = "a struct of the domain holds it, and the field is a copy";
        if (why) |w| {
            if (bad_before + bad < 10) std.debug.print("{s}.{s} byte {d} (DG:{X:0>4}): {s} (holder {d})\n", .{ @typeName(S), name, k, a, w, hd.m });
            bad += 1;
        }
    }
    return bad;
}

test "stage B: every byte of the loop's view is reached at its one home, in the member that holds it (bindDomain, bindRoot)" {
    const gpa = std.testing.allocator;
    var l = try est.Layout.build(gpa, false);
    defer l.deinit(gpa);
    const d = try est.Members.create(gpa);
    defer d.destroy(gpa);
    const st_node = try gpa.create(sn.State);
    defer gpa.destroy(st_node);
    st_node.* = .{};
    const img = try gpa.create(dgroup.Image);
    defer gpa.destroy(img);
    img.* = @splat(0);
    const st = try gpa.create(rs.RootState);
    defer gpa.destroy(st);
    st.* = .{};
    rs.bindRoot(st, &d.rv, &d.pg);
    rs.bindDomain(st, st_node, &d.p, &d.ev, &d.tv, &d.s);
    const h: Homes = .{ .st = st_node, .d = d, .img = img };
    var bound: usize = 0;
    try std.testing.expectEqual(@as(usize, 0), misplaced(&l, h, st, &bound));
    // The tables of the root moves, the PV rows, the PV moves to follow, the board and the
    // root scores, the 30 variables `bindDomain` names and the 48 `bindRoot` binds
    // (Stage B step 8, stage 7: every byte of the view, none in the image).
    std.debug.print("stage B 3b, step 8 stage 7: {d} bytes of the loop's view are reached at their homes\n", .{bound});
    try std.testing.expect(bound > 400 + 74 * 3 + 120 + 200);

    // A field pointed one byte off is caught: the domain's, and `RootVars`'.
    const saved = st.*;
    st.hard = @ptrFromInt(@intFromPtr(st.hard) + 1);
    var b2: usize = 0;
    try std.testing.expect(misplaced(&l, h, st, &b2) > 0);
    st.* = saved;
    st.base = @ptrFromInt(@intFromPtr(st.base) + 1);
    try std.testing.expect(misplaced(&l, h, st, &b2) > 0);
    st.* = saved;
    st.root_scores = @ptrFromInt(@intFromPtr(st.root_scores) + 2);
    try std.testing.expect(misplaced(&l, h, st, &b2) > 0);
}

test "stage B: every byte of main's view is reached at its one home, in the member that holds it (rootprep.bindDomain, bindRoot)" {
    const gpa = std.testing.allocator;
    var l = try est.Layout.build(gpa, false);
    defer l.deinit(gpa);
    const d = try est.Members.create(gpa);
    defer d.destroy(gpa);
    const st_node = try gpa.create(sn.State);
    defer gpa.destroy(st_node);
    st_node.* = .{};
    const img = try gpa.create(dgroup.Image);
    defer gpa.destroy(img);
    img.* = @splat(0);
    var st: rp.PrepState = .{};
    rp.bindRoot(&st, &d.rv, &d.pg);
    rp.bindDomain(&st, st_node, &d.p, &d.ev, &d.tv, &d.s, &d.lv);
    const h: Homes = .{ .st = st_node, .d = d, .img = img };
    var bound: usize = 0;
    try std.testing.expectEqual(@as(usize, 0), misplacedPrep(&l, h, &st, &bound));
    // The board, the leaf map, the root moves, the PV row and the PV moves to follow (806
    // bytes), the 62 variables `bindDomain` names, and since Stage B step 8, stage 7, the
    // low page, the irreversible-move area, the root copy, the root scores (678 bytes) and
    // the 64 variables `bindRoot` binds.
    std.debug.print("stage B 3c-1, step 8 stage 7: {d} bytes of main's view are reached at their homes\n", .{bound});
    try std.testing.expect(bound > 120 + 120 + 400 + 74 + 72 + 0xC8 + 2 + 0x196 + 0x4E + 200);
    // The ply ceiling, read through its own field, is the domain's; the low page around it
    // and the root copy are `RootVars`' and `ProgramVars`'.
    try std.testing.expectEqual(@intFromPtr(&st_node.ply_ceiling), @intFromPtr(st.ply_ceiling));
    try std.testing.expectEqual(@intFromPtr(&d.rv.low_page), @intFromPtr(st.low_page));
    try std.testing.expectEqual(@intFromPtr(&d.rv.low_page_rest), @intFromPtr(st.low_page_rest));
    try std.testing.expectEqual(@intFromPtr(&d.pg.setup_board[0x8C57 - 0x8C46]), @intFromPtr(st.root_copy));

    // A field pointed one byte off is caught: the domain's, and `RootVars`'.
    const saved = st;
    st.book_exit_ply = @ptrFromInt(@intFromPtr(st.book_exit_ply) + 1);
    var b2: usize = 0;
    try std.testing.expect(misplacedPrep(&l, h, &st, &b2) > 0);
    st = saved;
    st.level = @ptrFromInt(@intFromPtr(st.level) + 1);
    try std.testing.expect(misplacedPrep(&l, h, &st, &b2) > 0);
    st = saved;
    st.root_copy = @ptrFromInt(@intFromPtr(st.root_copy) + 1);
    try std.testing.expect(misplacedPrep(&l, h, &st, &b2) > 0);
}

test "stage B 3c-2: the root's variables after the bishop activity tables are covered by no struct of the domain but their homes" {
    const gpa = std.testing.allocator;
    var l = try est.Layout.build(gpa, false);
    defer l.deinit(gpa);
    // A356 the iteration's start time, A35C the depth reached, A360 single bishops, A362 the
    // soft limit (White's bishop table A2F0 ends at A353); A3F5 and A3F6 the fail-high bytes,
    // A3FA the reply list's validity, A3FE.. White's passed-pawn squares (Black's, A390, ends at A3F3).
    // Since Stage B step 8, stage 7, each is held by `RootVars` or `ProgramVars` and covered
    // by no other member.
    for ([_]u16{ 0xA356, 0xA357, 0xA358, 0xA359, 0xA35C, 0xA360, 0xA362, 0xA363, 0xA364, 0xA365, 0xA3F5, 0xA3F6, 0xA3FA, 0xA3FB, 0xA3FE }) |a| {
        const hd = holder(&l, a).m;
        try std.testing.expect(hd == @backingInt(est.Member.rv) or hd == @backingInt(est.Member.pg));
        for (0..est.n_members) |m| try std.testing.expect(m == hd or l.covOf(m)[a] < 0);
    }
    // The bytes between are other variables, each with one holder.
    for ([_]u16{ 0xA354, 0xA35A, 0xA35E, 0xA3F4, 0xA3F8 }) |a| try std.testing.expect(holder(&l, a).m >= 0);
    // The two bishop tables keep the original's 100 bytes.
    for ([_]u16{ 0xA2F0, 0xA353, 0xA390, 0xA3F3 }) |a| try std.testing.expectEqual(@as(i32, @backingInt(est.Member.ev)), holder(&l, a).m);
}

/// `misplaced` for prepare_eval's tables (`evaltables.Tables`, stage 3c-2): every field is a
/// pointer, at the domain's byte where a struct of the domain holds it, else at the image's.
fn misplacedTables(l: *const est.Layout, h: Homes, t: *const evaltables.Tables, bound: *usize) usize {
    var bad: usize = 0;
    inline for (@typeInfo(evaltables.Tables).@"struct".field_names) |name| bad += misplacedField(evaltables.Tables, name, @field(evaltables.Tables.dg, name), l, h, t, bound, bad, null);
    return bad;
}

test "stage B 3c-2: every byte of prepare_eval's tables is reached at its one home, in the member that holds it (evaltables.bindDomain)" {
    const gpa = std.testing.allocator;
    var l = try est.Layout.build(gpa, false);
    defer l.deinit(gpa);
    const d = try est.Members.create(gpa);
    defer d.destroy(gpa);
    const st_node = try gpa.create(sn.State);
    defer gpa.destroy(st_node);
    st_node.* = .{};
    const img = try gpa.create(dgroup.Image);
    defer gpa.destroy(img);
    img.* = @splat(0);
    var t: evaltables.Tables = .{};
    evaltables.bindDomain(&t, st_node, &d.p, &d.ev, &d.s, &d.lv, &d.tv, &d.rv, &d.pg);
    const h: Homes = .{ .st = st_node, .d = d, .img = img };
    var bound: usize = 0;
    try std.testing.expectEqual(@as(usize, 0), misplacedTables(&l, h, &t, &bound));
    // The 31 tables of `EvalVars` (10 square-value tables and 4 king tables of 200 bytes, 6
    // activity tables of 120 and 2 of 100, 2 rook-byte tables of 100, 6 storm and passer
    // tables of 178, the shelter table of 10) and 23 small fields of the domain's structs.
    std.debug.print("stage B 3c-2: {d} bytes of prepare_eval's tables are reached in the node domain\n", .{bound});
    try std.testing.expect(bound >= 14 * 200 + 6 * 120 + 4 * 100 + 6 * 178 + 10);
    // No byte the image keeps is covered by any struct of the domain: no struct holds a stale
    // copy of a byte prepare_eval writes in the image.
    inline for (@typeInfo(evaltables.Tables).@"struct".field_names) |name| {
        const a0: usize = @field(evaltables.Tables.dg, name);
        for (a0..a0 + @sizeOf(evaltables.Tables.Pointee(name))) |a| {
            if (holder(&l, a).m >= 0) continue;
            for (0..est.n_members) |m| try std.testing.expect(l.covOf(m)[a] < 0);
        }
    }
    // The inputs the node domain's structs hold are the three engine_root's
    // `prepareEvalDomain` takes from them (the passed-pawn masks, the bytes past the board);
    // since Stage B step 8, stage 7, every other byte of `Inputs` is `RootVars`' or
    // `ProgramVars'`, covered by no other member, and read at its home.
    const held = [_][]const u8{ "passed_mask_white", "passed_mask_black", "beyond_board" };
    inline for (@typeInfo(evaltables.Inputs).@"struct".field_names, @typeInfo(evaltables.Inputs).@"struct".field_types) |name, T| {
        const from_domain = comptime for (held) |x| {
            if (std.mem.eql(u8, x, name)) break true;
        } else false;
        const a0: usize = @field(evaltables.Inputs.dg, name);
        for (a0..a0 + imageBytes(T)) |a| {
            const hd = holder(&l, a).m;
            if (from_domain) {
                try std.testing.expect(hd >= 0 and hd != @backingInt(est.Member.rv) and hd != @backingInt(est.Member.pg));
            } else {
                try std.testing.expect(hd == @backingInt(est.Member.rv) or hd == @backingInt(est.Member.pg));
                for (0..est.n_members) |m| try std.testing.expect(m == hd or l.covOf(m)[a] < 0);
            }
        }
    }

    // Since prepare_eval runs inside the domain, no `enter` after it reloads the copies that
    // over-long declarations of other structs keep of the bytes it writes. These are all such
    // copies (struct, DG range): key_history[42..44] and [50..51] (LeafVars; read only through
    // `atRoom`, plies 0..40), square_slot[100..119] (Position; read only at board squares),
    // quiet_move_by_ply[58..63] (Position; plies 0..40), black_rays_after[88..101] (ThreatVars;
    // `boardAt` reads indices 0..77) and attackers[20..21] (see.Scratch, DG:A000, the root's
    // game ply, which `refreshRootAliases` copies from its holder before each threat
    // evaluation). A new one fails here.
    const Alias = struct { m: est.Member, lo: u16, hi: u16 };
    const known = [_]Alias{
        .{ .m = .lv, .lo = 0x9EBE, .hi = 0x9EC8 }, .{ .m = .lv, .lo = 0x9EEE, .hi = 0x9EF6 },
        .{ .m = .p, .lo = 0xA2F0, .hi = 0xA304 },  .{ .m = .p, .lo = 0x369A, .hi = 0x369C },
        .{ .m = .p, .lo = 0x369E, .hi = 0x36A6 },  .{ .m = .tv, .lo = 0xA234, .hi = 0xA242 },
        .{ .m = .s, .lo = 0xA000, .hi = 0xA002 },
    };
    var aliases: usize = 0;
    inline for (@typeInfo(evaltables.Tables).@"struct".field_names) |name| {
        const a0: usize = @field(evaltables.Tables.dg, name);
        for (a0..a0 + @sizeOf(evaltables.Tables.Pointee(name))) |a| {
            for (0..est.n_members) |m| {
                if (l.covOf(m)[a] < 0 or l.offOf(m)[a] >= 0) continue;
                aliases += 1;
                const listed = for (known) |k| {
                    if (@backingInt(k.m) == m and a >= k.lo and a < k.hi) break true;
                } else false;
                if (!listed) std.debug.print("DG:{X:0>4} ({s}) has a copy in member {d} not listed\n", .{ a, name, m });
                try std.testing.expect(listed);
            }
        }
    }
    var known_bytes: usize = 0;
    for (known) |k| known_bytes += k.hi - k.lo;
    try std.testing.expectEqual(known_bytes, aliases);

    // A field pointed one byte off is caught: a table, and a small field.
    const saved = t;
    t.king_white = @ptrFromInt(@intFromPtr(t.king_white) + 1);
    var b2: usize = 0;
    try std.testing.expect(misplacedTables(&l, h, &t, &b2) > 0);
    t = saved;
    t.endgame = @ptrFromInt(@intFromPtr(t.endgame) + 1);
    try std.testing.expect(misplacedTables(&l, h, &t, &b2) > 0);
}

// Stage B step 8, stage 1: the domain stays entered for the root's life, and whatever works
// on the image is bracketed (engine_root `imageBegin`, `imageEnd`). A write into the image
// outside a bracket, at a byte the domain holds, is reported by the image check at the next
// store-back (`exit`; and at the start of a search, `checkImage`).
test "stage B step 8: the image check reports a byte written into the image while the domain held it, and nothing written in a bracket" {
    if (!est.image_check) return; // the check is on in Debug and ReleaseSafe only
    const gpa = std.testing.allocator;
    const R = ert.EngineRoot(@import("position.zig").Fixes.original);
    const s = try R.init(gpa, 16);
    defer s.deinit();
    s.startUp(.{}, .{}, .{}, 3);
    try std.testing.expect(s.node.codec.in_domain);
    si.toImage(s); // start-up runs on the members (stage 4): the image made current
    s.node.codec.image_panic = false;
    var l = try est.Layout.build(gpa, false);
    defer l.deinit(gpa);
    const a1: u16 = 0x9EF6 + 21; // the search board's a1: `Position`'s
    // A byte no member holds (since Stage B step 8, stage 7, no variable the engine reads
    // or writes): the first such byte above the executable's initialised data.
    const best: u16 = for (0x3200..0x10000) |a| {
        if (l.canon[a] < 0) break @intCast(a);
    } else unreachable;
    try std.testing.expectEqual(@as(i8, @backingInt(est.Member.p)), l.canon[a1]);
    try std.testing.expectEqual(@as(i8, -1), l.canon[best]);
    // In a bracket: the image is the truth, and the domain takes the change at its end.
    const rook = s.test_img[a1];
    si.imageBegin(s);
    s.test_img[a1] = 0;
    si.imageEnd(s);
    try std.testing.expectEqual(@as(u8, 0), s.node.dom.p.board[21]);
    si.imageBegin(s);
    s.test_img[a1] = rook;
    si.imageEnd(s);
    try std.testing.expectEqual(rook, s.node.dom.p.board[21]);
    // A byte no member holds may be written at any time (the root's own variables).
    s.test_img[best] +%= 1;
    si.toImage(s);
    try std.testing.expectEqual(@as(u64, 0), s.node.codec.image_writes);
    // A byte the domain holds, written while it is entered: reported at the store-back.
    s.test_img[a1] +%= 1;
    si.toImage(s);
    try std.testing.expectEqual(@as(u64, 1), s.node.codec.image_writes);
    try std.testing.expectEqual(a1, s.node.codec.image_first);
    // The store-back writes only the bytes the domain changed, so the stray byte survived it
    // and the reload took it into the domain: the corruption the check exists to report.
    try std.testing.expectEqual(rook +% 1, s.node.dom.p.board[21]);
    si.imageBegin(s);
    s.test_img[a1] = rook;
    si.imageEnd(s);
    // And at the start of a search.
    try std.testing.expect(s.autoPlay());
    s.test_img[a1] +%= 1;
    si.checkImage(&s.node);
    try std.testing.expectEqual(@as(u64, 2), s.node.codec.image_writes);
    std.debug.print("image check: a write at DG:{X:0>4} (Position's) while the domain held it is reported; bracketed writes and DG:{X:0>4} (no member's) are not\n", .{ a1, best });
}

// Stage B step 8, stage 2: the game's variables (`gamemove.GameVars`) are a member of the
// domain. Their value fields are the variables no other struct declares, held by the
// member; every pointer field points at its variable's one home: the byte of the member
// that holds it, or the image's where none does (`engine_state` `bindGameVars`).
fn misplacedGameVars(l: *const est.Layout, h: Homes, gv: *const gamemove.GameVars, bound: *usize) usize {
    var bad: usize = 0;
    inline for (@typeInfo(gamemove.GameVars).@"struct".field_names) |name| {
        const addr: usize = @field(gamemove.var_addresses, name);
        const n = comptime gamemove.varBytes(name);
        for (0..n) |k| {
            const a = addr + k;
            const hd = holder(l, a);
            var why: ?[]const u8 = null;
            if (comptime gamemove.isPointerVar(name)) {
                const at = @intFromPtr(@field(gv, name)) + k;
                if (hd.m < 0) {
                    // Stage B step 8, stage 7: every byte has a member for its home.
                    why = "no member holds it";
                } else if (hd.m == @backingInt(est.Member.gv)) {
                    why = "a pointer field at a byte GameVars itself holds";
                } else if (at != h.base(@intCast(hd.m)) + @as(usize, @intCast(hd.off))) {
                    why = "the field does not point at the byte of the member that holds it";
                } else bound.* += 1;
            } else if (hd.m != @backingInt(est.Member.gv) or @as(usize, @intCast(hd.off)) != @offsetOf(gamemove.GameVars, name) + (k / dgroup.elemSize(dgroup.Flat(@FieldType(gamemove.GameVars, name)))) * @sizeOf(dgroup.Flat(@FieldType(gamemove.GameVars, name))) + k % dgroup.elemSize(dgroup.Flat(@FieldType(gamemove.GameVars, name)))) {
                why = "a value field whose byte GameVars does not hold at its own offset";
            } else if (ert.viewDeclares(a) or ert.timeStateCovers(a) or ert.SetupVarsMap.covers(a) or inEvalTables(a)) {
                why = "a value field whose byte another struct of the engine also declares";
            }
            if (why) |w| {
                if (bad < 10) std.debug.print("GameVars.{s} byte {d} (DG:{X:0>4}): {s} (holder {d})\n", .{ name, k, a, w, hd.m });
                bad += 1;
            }
        }
    }
    return bad;
}

fn inEvalTables(a: usize) bool {
    inline for (@typeInfo(evaltables.Tables).@"struct".field_names) |name| {
        const a0: usize = @field(evaltables.Tables.dg, name);
        if (a >= a0 and a < a0 + @sizeOf(evaltables.Tables.Pointee(name))) return true;
    }
    inline for (@typeInfo(evaltables.Inputs).@"struct".field_names, @typeInfo(evaltables.Inputs).@"struct".field_types) |name, T| {
        const a0: usize = @field(evaltables.Inputs.dg, name);
        if (a >= a0 and a < a0 + imageBytes(T)) return true;
    }
    return false;
}

test "stage B step 8: every pointer field of the domain's GameVars points at its variable's one home, and its value fields are bytes only GameVars declares (bindGameVars)" {
    const gpa = std.testing.allocator;
    const R = ert.EngineRoot(@import("position.zig").Fixes.original);
    const s = try R.init(gpa, 16);
    defer s.deinit();
    var l = try est.Layout.build(gpa, false);
    defer l.deinit(gpa);
    try std.testing.expect(est.checkOneHolder(&l));
    const h: Homes = .{ .st = s.node_state, .d = s.node.dom, .img = s.test_img };
    var bound: usize = 0;
    try std.testing.expectEqual(@as(usize, 0), misplacedGameVars(&l, h, &s.node.dom.gv, &bound));
    // The 24 fields a member holds: the stop flag, the depth, the predicted reply's captured
    // piece (the node's State), pondering, 3675, A2A7, A2ED (Position), the last irreversible
    // ply, the draw flag, the passer flags, the endgame flag, the pawn square sums
    // (EvalVars), the replay mode word (Scratch), the leaf map's first 120 bytes, 9E96 and
    // the Book menu's byte 9EB6 (LeafVars), the book-exit ply, analysis and the ply limits,
    // the iteration and the mate switch (ThreatVars).
    std.debug.print("stage B step 8: {d} bytes of GameVars are reached in the node domain's members\n", .{bound});
    // Since Stage B step 8, stage 7, every byte of every pointer field: the 153 bytes above
    // and the 662 of the 36 fields whose home was the image (`RootVars`, `ProgramVars`).
    comptime var pointer_bytes: usize = 0;
    inline for (@typeInfo(gamemove.GameVars).@"struct".field_names) |name| {
        if (comptime gamemove.isPointerVar(name)) pointer_bytes += comptime gamemove.varBytes(name);
    }
    try std.testing.expectEqual(pointer_bytes, bound);
    try std.testing.expectEqual(@as(usize, 120 + 2 + 2 + 3 + 4 + 2 + 3 + 4 + 2 + 2 + 1 + 1 + 6 + 1 + 662), bound);
    // The holders of hazard 1 keep their bytes: the book-exit ply, analysis (ThreatVars'
    // tail), the replay mode word (Scratch's), pondering (Position's), the Book menu's byte
    // (LeafVars').
    const tv = @backingInt(est.Member.tv);
    try std.testing.expectEqual(@as(i32, tv), holder(&l, 0x9FBC).m);
    try std.testing.expectEqual(@as(i32, tv), holder(&l, 0x9FCF).m);
    try std.testing.expectEqual(@as(i32, @backingInt(est.Member.s)), holder(&l, 0xA00A).m);
    try std.testing.expectEqual(@as(i32, @backingInt(est.Member.p)), holder(&l, 0x3676).m);
    try std.testing.expectEqual(@as(i32, @backingInt(est.Member.lv)), holder(&l, 0x9EB6).m);
    try std.testing.expectEqual(@intFromPtr(&s.node.dom.tv.board_after[0x9FBC - 0x9F6E]), @intFromPtr(s.node.dom.gv.book_exit_ply));

    // A field pointed one byte off is caught: a member's, and an image one.
    var gv = s.node.dom.gv;
    gv.book_exit_ply = @ptrFromInt(@intFromPtr(gv.book_exit_ply) + 1);
    var b2: usize = 0;
    try std.testing.expect(misplacedGameVars(&l, h, &gv, &b2) > 0);
    gv = s.node.dom.gv;
    gv.computer_side = @ptrFromInt(@intFromPtr(gv.computer_side) + 1);
    try std.testing.expect(misplacedGameVars(&l, h, &gv, &b2) > 0);
}

// Stage B step 8, stage 5: the time budget's state (`timebudget.TimeState`) is a member of
// the domain, as `GameVars` is: its value fields are the variables no other struct
// declares, held by the member; every pointer field points at its variable's one home
// (`engine_state` `bindTimeState`).
fn misplacedTimeState(l: *const est.Layout, h: Homes, ts: *const tbud.TimeState, bound: *usize) usize {
    var bad: usize = 0;
    inline for (@typeInfo(tbud.TimeState).@"struct".field_names) |name| {
        const addr: usize = @field(tbud.var_addresses, name);
        const n = comptime tbud.varBytes(name);
        for (0..n) |k| {
            const a = addr + k;
            const hd = holder(l, a);
            var why: ?[]const u8 = null;
            if (comptime tbud.isPointerVar(name)) {
                const at = @intFromPtr(@field(ts, name)) + k;
                if (hd.m < 0) {
                    // Stage B step 8, stage 7: every byte has a member for its home.
                    why = "no member holds it";
                } else if (hd.m == @backingInt(est.Member.ts)) {
                    why = "a pointer field at a byte TimeState itself holds";
                } else if (at != h.base(@intCast(hd.m)) + @as(usize, @intCast(hd.off))) {
                    why = "the field does not point at the byte of the member that holds it";
                } else bound.* += 1;
            } else {
                const E = dgroup.Flat(@FieldType(tbud.TimeState, name));
                const es = dgroup.elemSize(E);
                if (hd.m != @backingInt(est.Member.ts) or @as(usize, @intCast(hd.off)) != @offsetOf(tbud.TimeState, name) + (k / es) * @sizeOf(E) + k % es) {
                    why = "a value field whose byte TimeState does not hold at its own offset";
                } else if (ert.viewDeclares(a) or ert.gameVarsCover(a) or ert.SetupVarsMap.covers(a) or inEvalTables(a)) {
                    why = "a value field whose byte another struct of the engine also declares";
                }
            }
            if (why) |w| {
                if (bad < 10) std.debug.print("TimeState.{s} byte {d} (DG:{X:0>4}): {s} (holder {d})\n", .{ name, k, a, w, hd.m });
                bad += 1;
            }
        }
    }
    return bad;
}

test "stage B step 8, stage 5: every pointer field of the domain's TimeState points at its variable's one home, and its value fields are bytes only TimeState declares (bindTimeState)" {
    const gpa = std.testing.allocator;
    const R = ert.EngineRoot(@import("position.zig").Fixes.original);
    const s = try R.init(gpa, 16);
    defer s.deinit();
    var l = try est.Layout.build(gpa, false);
    defer l.deinit(gpa);
    try std.testing.expect(est.checkOneHolder(&l));
    const h: Homes = .{ .st = s.node_state, .d = s.node.dom, .img = s.test_img };
    var bound: usize = 0;
    try std.testing.expectEqual(@as(usize, 0), misplacedTimeState(&l, h, &s.node.dom.ts, &bound));
    // The 12 bytes a member holds: pondering, the clock side and the game ply (Position),
    // `hard` (EvalVars), the book-exit ply, analysis and `clear_best` (ThreatVars' tails).
    std.debug.print("stage B step 8, stage 5: {d} bytes of TimeState are reached in the node domain's members\n", .{bound});
    // Since Stage B step 8, stage 7, every byte of every pointer field: the 12 bytes above
    // and the 65 of the 15 fields whose home was the image (`RootVars`).
    comptime var pointer_bytes: usize = 0;
    inline for (@typeInfo(tbud.TimeState).@"struct".field_names) |name| {
        if (comptime tbud.isPointerVar(name)) pointer_bytes += comptime tbud.varBytes(name);
    }
    try std.testing.expectEqual(pointer_bytes, bound);
    try std.testing.expectEqual(@as(usize, 1 + 1 + 2 + 4 + 2 + 1 + 1 + 65), bound);
    const p = @backingInt(est.Member.p);
    const tv = @backingInt(est.Member.tv);
    try std.testing.expectEqual(@as(i32, p), holder(&l, 0x3676).m);
    try std.testing.expectEqual(@as(i32, p), holder(&l, 0x9EEC).m);
    try std.testing.expectEqual(@as(i32, p), holder(&l, 0x9FC8).m);
    try std.testing.expectEqual(@as(i32, @backingInt(est.Member.ev)), holder(&l, 0x9DB8).m);
    try std.testing.expectEqual(@as(i32, tv), holder(&l, 0x9FBC).m);
    try std.testing.expectEqual(@as(i32, tv), holder(&l, 0x9FCF).m);
    try std.testing.expectEqual(@as(i32, tv), holder(&l, 0xA22C).m);
    // TimeState holds its value fields: the preset seconds, Game in N, the speed, the base
    // shift and the displayed clocks (62 bytes).
    var own: usize = 0;
    for (0..0x10000) |a| {
        if (l.canon[a] != @backingInt(est.Member.ts)) continue;
        own += 1;
        // No other member covers them: no member lost a byte to TimeState, and no member
        // keeps a copy of one.
        for (0..est.n_members) |m| {
            if (m != @backingInt(est.Member.ts)) try std.testing.expect(l.covOf(m)[a] < 0);
        }
    }
    try std.testing.expectEqual(@as(usize, 40 + 2 + 4 + 2 + 12), own);
    try std.testing.expectEqual(@intFromPtr(&s.node.dom.tv.board_after[0x9FBC - 0x9F6E]), @intFromPtr(s.node.dom.ts.book_exit_ply));
    try std.testing.expectEqual(@intFromPtr(&s.node.dom.rv.base), @intFromPtr(s.node.dom.ts.base));

    // A field pointed one byte off is caught: a member's, and an image one.
    var ts = s.node.dom.ts;
    ts.hard = @ptrFromInt(@intFromPtr(ts.hard) + 1);
    var b2: usize = 0;
    try std.testing.expect(misplacedTimeState(&l, h, &ts, &b2) > 0);
    ts = s.node.dom.ts;
    ts.mtg = @ptrFromInt(@intFromPtr(ts.mtg) + 1);
    try std.testing.expect(misplacedTimeState(&l, h, &ts, &b2) > 0);
    ts = s.node.dom.ts;
    ts.tc = @ptrFromInt(@intFromPtr(ts.tc) + 1);
    try std.testing.expect(misplacedTimeState(&l, h, &ts, &b2) > 0);
}

// Stage B step 8, stage 7: the root's own variables (`rootvars.RootVars`) and every other
// variable the engine reads or writes that no unit's struct held (`rootvars.ProgramVars`)
// are members. Each holds every byte it declares, at its own offset, and no other member
// covers any of them: no member lost a byte to them (each was held by none before), and no
// member keeps a copy of one.
fn misplacedRootVars(comptime S: type, comptime m: est.Member, l: *const est.Layout, h: Homes, own: *usize) usize {
    var bad: usize = 0;
    inline for (@typeInfo(S).@"struct".field_names) |name| {
        const addr: usize = @field(S.dg, name);
        const F = @FieldType(S, name);
        const E = dgroup.Flat(F);
        const es = dgroup.elemSize(E);
        const n = dgroup.flatLen(F) * es;
        for (0..n) |k| {
            const a = addr + k;
            const hd = holder(l, a);
            var why: ?[]const u8 = null;
            if (hd.m != @backingInt(m)) {
                why = "a byte the member does not hold";
            } else if (h.base(@intCast(hd.m)) + @as(usize, @intCast(hd.off)) != h.base(@backingInt(m)) + @offsetOf(S, name) + (k / es) * @sizeOf(E) + k % es) {
                why = "held, but not at the field's own offset";
            } else {
                for (0..est.n_members) |o| {
                    if (o != @backingInt(m) and l.covOf(o)[a] >= 0) why = "another member covers it";
                }
            }
            if (why) |w| {
                if (bad < 10) std.debug.print("{s}.{s} byte {d} (DG:{X:0>4}): {s} (holder {d})\n", .{ @typeName(S), name, k, a, w, hd.m });
                bad += 1;
            } else own.* += 1;
        }
    }
    return bad;
}

test "stage B step 8, stage 7: RootVars and ProgramVars hold every byte they declare, and no other member covers one" {
    const gpa = std.testing.allocator;
    const rvm = @import("rootvars.zig");
    const R = ert.EngineRoot(@import("position.zig").Fixes.original);
    const s = try R.init(gpa, 16);
    defer s.deinit();
    var l = try est.Layout.build(gpa, false);
    defer l.deinit(gpa);
    try std.testing.expect(est.checkOneHolder(&l));
    const h: Homes = .{ .st = s.node_state, .d = s.node.dom, .img = s.test_img };
    var own_rv: usize = 0;
    var own_pg: usize = 0;
    try std.testing.expectEqual(@as(usize, 0), misplacedRootVars(rvm.RootVars, .rv, &l, h, &own_rv));
    try std.testing.expectEqual(@as(usize, 0), misplacedRootVars(rvm.ProgramVars, .pg, &l, h, &own_pg));
    std.debug.print("stage B step 8, stage 7: RootVars holds {d} bytes, ProgramVars {d}\n", .{ own_rv, own_pg });
    // Every byte the members hold: no byte of the image is the home of a variable the
    // engine reads or writes but the ones no unit declares (the screen's, the menus').
    var held: usize = 0;
    for (0..0x10000) |a| {
        if (l.canon[a] >= 0) held += 1;
    }
    std.debug.print("stage B step 8, stage 7: {d} DGROUP bytes are held by a member\n", .{held});
    // The check catches a wrong holder: RootVars' bytes checked as ProgramVars'.
    var dummy: usize = 0;
    try std.testing.expect(misplacedRootVars(rvm.RootVars, .pg, &l, h, &dummy) > 0);
}

// Stage B step 8, stage 5: after this stage no callee of main before the loop (the time
// budget, book_probe and its legality test, hash_resize, rand, as well as those of the
// earlier stages) and none of the loop leaves the node domain: a search without a hook
// makes no `exit` at all (`EngineRoot.search_exits`, counted in test builds). Searches from the
// start at Fixed depth (the time budget, hash_resize and the tables cleared), with the
// M-Chess book bound and on (book_probe drawing a move, played from main; and after the
// book), and one with a Random Limit (main's rand()).
test "stage B step 8, stage 5: the search makes no image bracket: no callee leaves the node domain" {
    const gpa = std.testing.allocator;
    const R = ert.EngineRoot(@import("position.zig").Fixes.original);
    const s = try R.init(gpa, 3_145_728); // the original's 30,720 KB tables
    defer s.deinit();
    s.book_files = &@import("engine_data.zig").book_files;
    s.startUp(.{}, .{}, .{}, 2);
    s.togglePondering(); // pondering off, as the engine plays
    try std.testing.expect(s.autoPlay());
    // The book on, as the Book menu sets it (src/engine.zig `setBook`): DG:A5EE = 0 is the
    // M-Chess book on; the seed of the tournament draw.
    s.home().set(0xA5EE, 0);
    s.home().set(0xA5EF, 0);
    dgroup.memSetDword(s.home(), 0x2DC8, 17);
    const C = @import("rootprep.zig").Callee;
    const calls = struct {
        fn of(r: *R, c: C) u64 {
            return r.prep_calls[@backingInt(c)];
        }
    };
    var books: u32 = 0;
    var searched: u32 = 0;
    var k: u32 = 0;
    while (k < 24) : (k += 1) {
        if (k == 12) s.home().set(0xA5EE, 1); // the M-Chess book off: searches from here
        const x = s.search(.own);
        if (s.failure) |f| std.debug.print("search {d}: {s}\n", .{ k, f });
        try std.testing.expect(s.failure == null);
        try std.testing.expectEqual(@as(u64, 0), s.search_exits);
        if (s.book_played) books += 1 else if (x.exit == .iteration_loop) searched += 1;
        if (!s.book_played) s.playMove();
        s.nextTurnAutoPlay();
        if (s.failure != null) break;
    }
    // Main's rand() (0CC7) runs only at the per-move level with preset 0 and a Random
    // Limit, which no search here uses: the callee itself, as main calls it in the domain.
    const exits0 = s.node.codec.exits;
    const seed0 = dgroup.memDword(s.home(), 0x2DC8);
    var r: @import("book.zig").Rand = .{ .seed = seed0 };
    const want = r.next();
    try std.testing.expectEqual(@as(u32, want), s.dispatchPrep(0x0CC7, .rand, &.{}));
    try std.testing.expectEqual(r.seed, dgroup.memDword(s.home(), 0x2DC8));
    try std.testing.expectEqual(r.seed, s.node.dom.pg.rand_seed);
    try std.testing.expectEqual(exits0, s.node.codec.exits);
    std.debug.print("stage B step 8, stage 5: {d} searches, {d} book moves, {d} searched, {d} image brackets in all; calls: moves_to_go {d}, set_time_budget {d}, book_probe {d}, hash_resize {d}, rand {d}\n", .{ k, books, searched, s.node.codec.exits, calls.of(s, .moves_to_go), calls.of(s, .set_time_budget), calls.of(s, .book_probe), calls.of(s, .hash_resize), calls.of(s, .rand) });
    try std.testing.expect(books > 0 and searched > 0);
    try std.testing.expect(calls.of(s, .hash_resize) > 0 and calls.of(s, .set_time_budget) > 0 and calls.of(s, .moves_to_go) > 0 and calls.of(s, .book_probe) > 0);
}

/// The far segments of every subtree file (the oracle's game records at a node).
const recorded_far = [_][]const u8{ "subtree/check-evasion-d4-s1-subtree-1050.zst", "subtree/check-evasion-d4-s1-subtree-1572.zst", "subtree/check-evasion-d4-s1-subtree-1800.zst", "subtree/check-evasion-d4-s1-subtree-300.zst", "subtree/check-evasion-d4-s1-subtree-3796.zst", "subtree/check-evasion-d4-s1-subtree-450.zst", "subtree/check-evasion-d4-s2-subtree-52388.zst", "subtree/check-evasion-d4-s2-subtree-91604.zst", "subtree/open-game-d5-s2-subtree-38801.zst", "subtree/open-game-d5-s2-subtree-46022.zst", "subtree/pawn-ending-d5-s2-subtree-1260.zst", "subtree/pawn-ending-d5-s3-subtree-790.zst", "subtree/rook-ending-d4-s2-subtree-21305.zst", "subtree/rook-ending-d4-s2-subtree-6311.zst", "subtree/sicilian-najdorf-d4-s2-subtree-20201.zst", "subtree/start-d3-s1-subtree-1.zst", "subtree/start-d3-s1-subtree-114.zst", "subtree/start-d3-s1-subtree-207.zst", "whole/advanced-pawns-d3-s1-subtree-1.zst", "whole/advanced-pawns-d3-s2-subtree-1.zst", "whole/advanced-pawns-d3-s3-subtree-1.zst", "whole/open-game-d4-s1-subtree-1.zst", "whole/open-game-d4-s2-subtree-1.zst", "whole/open-game-d4-s3-subtree-1.zst", "whole/start-d3-s1-subtree-1.zst", "whole/start-d3-s2-subtree-1.zst", "whole/start-d3-s3-subtree-1.zst", "whole/start-d3-s4-subtree-1.zst", "whole/corpus1/advanced-pawns-d4-s1-subtree-1.zst", "whole/corpus1/caro-kann-d4-s1-subtree-1.zst", "whole/corpus1/english-d4-s1-subtree-1.zst", "whole/corpus1/evans-gambit-d4-s1-subtree-1.zst", "whole/corpus1/french-d4-s1-subtree-1.zst", "whole/corpus1/kings-indian-d4-s1-subtree-1.zst", "whole/corpus1/open-game-d4-s1-subtree-1.zst", "whole/corpus1/open-game-d5-s1-subtree-1.zst", "whole/corpus1/queens-off-d4-s1-subtree-1.zst", "whole/corpus1/queens-off-d5-s1-subtree-1.zst", "whole/corpus1/ruy-lopez-d4-s1-subtree-1.zst", "whole/corpus1/scandinavian-d4-s1-subtree-1.zst", "whole/corpus1/selfplay-d3-s1-subtree-1.zst", "whole/corpus1/sicilian-najdorf-d4-s1-subtree-1.zst", "whole/corpus1/sicilian-najdorf-d5-s1-subtree-1.zst", "whole/corpus1/start-d4-s1-subtree-1.zst", "whole/corpus2/back-rank-mate-d4-s1-subtree-1.zst", "whole/corpus2/check-evasion-d4-s1-subtree-1.zst", "whole/corpus2/isolated-queen-pawn-d4-s1-subtree-1.zst", "whole/corpus2/kings-attack-d4-s1-subtree-1.zst", "whole/corpus2/knight-vs-bishop-d4-s1-subtree-1.zst", "whole/corpus2/minor-ending-d4-s1-subtree-1.zst", "whole/corpus2/opposite-castling-d4-s1-subtree-1.zst", "whole/corpus2/pawn-ending-d5-s1-subtree-1.zst", "whole/corpus2/pawn-ending-passed-d5-s1-subtree-1.zst", "whole/corpus2/queen-ending-d4-s1-subtree-1.zst", "whole/corpus2/rook-ending-d4-s1-subtree-1.zst", "whole/corpus2/rook-pawn-vs-rook-d4-s1-subtree-1.zst", "whole/longgame/long-ply258-d3-s1-subtree-1.zst", "whole/longgame/long-ply397-d3-s1-subtree-1.zst", "whole/normal1/np-checks-white-d3-s1-subtree-1.zst", "whole/normal1/np-ending-black-d5-s1-subtree-1.zst", "whole/normal1/np-middle-black-d5-s1-subtree-1.zst", "whole/normal1/np-middle-white-d4-s1-subtree-1.zst", "whole/normal1/np-open-black-d4-s1-subtree-1.zst", "whole/normal1/np-open-white-d3-s1-subtree-1.zst" };

test "stage B step 8: the game record's fields give the far segment's bytes at every offset of every recorded far segment, and back" {
    const gpa = std.testing.allocator;
    const rec = try gpa.create(gamemove.GameRecord);
    defer gpa.destroy(rec);
    const far = try gpa.create([0x10000]u8);
    defer gpa.destroy(far);
    const back = try gpa.create([0x10000]u8);
    defer gpa.destroy(back);
    var checked: usize = 0;
    for (recorded_far) |name| {
        const compressed = try ert_test.readGolden(gpa, name);
        defer gpa.free(compressed);
        var in: std.Io.Reader = .fixed(compressed);
        const window = try gpa.alloc(u8, std.compress.zstd.default_window_len + std.compress.zstd.block_size_max);
        defer gpa.free(window);
        var zd = std.compress.zstd.Decompress.init(&in, window, .{});
        const raw = try zd.reader.allocRemaining(gpa, .limited(64 << 20));
        defer gpa.free(raw);
        try std.testing.expect(std.mem.eql(u8, raw[0..8], "MCSUBT1\x00"));
        @memcpy(far, raw[25 + 0x10000 ..][0..0x10000]);
        rec.* = .{};
        rec.fromFar(far);
        var fields: usize = 0;
        for (0..0x10000) |off| {
            if (rec.byteAt(@intCast(off))) |v| {
                fields += 1;
                if (v != far[off]) {
                    std.debug.print("{s}: 5A7B:{X:0>4}: the record gives {X:0>2}, the far segment {X:0>2}\n", .{ name, off, v, far[off] });
                    return error.TestUnexpectedResult;
                }
            }
        }
        try std.testing.expectEqual(@as(usize, 6 + 6 * 406 + 406 + 406 + 812 + 6 * 485 + 406 + 6 * gamemove.key_room + 2 + 406), fields);
        // Written back over zeros, the record gives the far segment's bytes where it has
        // fields; written over the segment itself, the segment unchanged.
        back.* = @splat(0);
        rec.toFar(back);
        for (0..0x10000) |off| try std.testing.expectEqual(if (rec.byteAt(@intCast(off)) != null) far[off] else 0, back[off]);
        back.* = far.*;
        rec.toFar(back);
        try std.testing.expectEqualSlices(u8, far, back);
        // setByteAt and byteAt agree.
        const sv = rec.byteAt(0x3A34 + 6 * 7 + 3).?;
        try std.testing.expect(rec.setByteAt(0x3A34 + 6 * 7 + 3, sv +% 1));
        try std.testing.expectEqual(sv +% 1, rec.byteAt(0x3A34 + 6 * 7 + 3).?);
        try std.testing.expect(rec.setByteAt(0x68E4, 1)); // between the keys' room and gave_check: `key_gap`
        try std.testing.expect(!rec.setByteAt(0x01C9, 1)); // before the move table's slot -1
        checked += 1;
    }
    std.debug.print("stage B step 8: the game record of {d} recorded far segments, every offset\n", .{checked});
}

fn readRecordedFar(gpa: std.mem.Allocator, name: []const u8, far: *[0x10000]u8) !void {
    const compressed = try ert_test.readGolden(gpa, name);
    defer gpa.free(compressed);
    var in: std.Io.Reader = .fixed(compressed);
    const window = try gpa.alloc(u8, std.compress.zstd.default_window_len + std.compress.zstd.block_size_max);
    defer gpa.free(window);
    var zd = std.compress.zstd.Decompress.init(&in, window, .{});
    const raw = try zd.reader.allocRemaining(gpa, .limited(64 << 20));
    defer gpa.free(raw);
    @memcpy(far, raw[25 + 0x10000 ..][0..0x10000]);
}

// Stage B step 8, stage 4: the slide of the game record past move 201 (DEV-F19) runs on
// the record in place (`EngineRoot.RecordHome`) and on DGROUP's homes (`EngineRoot.Home`), with no
// bracket. It must leave every byte of both segments as the slide on the images does.
test "stage B step 8, stage 4: the slide on the members and the record in place gives the slide on the images, every byte of DGROUP and of the far segment" {
    const gpa = std.testing.allocator;
    const R = ert.EngineRoot(@import("position.zig").Fixes.original);
    const s = try R.init(gpa, 16);
    defer s.deinit();
    const img = try gpa.create(dgroup.Image);
    defer gpa.destroy(img);
    const far = try gpa.create([0x10000]u8);
    defer gpa.destroy(far);
    const ref_img = try gpa.create(dgroup.Image);
    defer gpa.destroy(ref_img);
    const ref_far = try gpa.create([0x10000]u8);
    defer gpa.destroy(ref_far);
    const gs = @import("gameslide.zig");
    var checked: usize = 0;
    for (recorded_far[0..8], 0..) |name, i| {
        try readRecordedFar(gpa, name, far);
        // A DGROUP whose game ply and past plies give the slide something to renumber.
        img.* = dgroup.initial;
        const m = dgroup.ImageMem{ .img = img };
        dgroup.memSetWord(m, gs.game_ply_addr, @intCast(300 + 2 * i));
        dgroup.memSetWord(m, gs.move_number_addr, @intCast(150 + i));
        dgroup.memSetWord(m, gs.last_irreversible_addr, 290);
        dgroup.memSetWord(m, 0xB426, 5);
        dgroup.memSetWord(m, 0x9FBC, 250);
        dgroup.memSetWord(m, 0xA000, 299);
        for (0..0x196) |k| img[gs.flags_addr + k] = @truncate(k *% 7);
        ref_img.* = img.*;
        ref_far.* = far.*;
        const d = gs.maxSlide(ref_img);
        try std.testing.expect(d >= 98);
        try gs.slide(ref_img, ref_far, d);
        si.fromImage(s, img, far);
        try std.testing.expect(s.node.codec.in_domain and s.node.codec.depth == 0);
        s.slideIfDue();
        try std.testing.expectEqual(@as(u64, d), s.dropped_plies);
        s.dropped_plies = 0;
        si.toImage(s);
        try std.testing.expectEqualSlices(u8, ref_img, s.test_img);
        try std.testing.expectEqualSlices(u8, ref_far, s.test_far);
        checked += 1;
    }
    std.debug.print("stage B step 8, stage 4: the slide in place equals the slide on the images for {d} recorded far segments\n", .{checked});
}

/// The copies the turn routines may leave stale (measured by the test below), each out of
/// every reader's reach (docs/arch/60-engine-assembly.md, the step 5 and step 7 notes and
/// section 10.7.12): `see.Scratch.attackers` over the piece lists (DG:A03A-A059, which
/// `evalthreats` `boardAt` reads from `Position.piece_list`) and over the root's game ply
/// and material balance (DG:A000-A001, A05A-A05B, which `threats` copies from their
/// holders before each call, `refreshRootAliases`), `LeafVars.key_history` past its room
/// of 36 keys (DG:9E96-9F3D: read at the search's plies only), and
/// `ThreatVars.board_after` at the game ply (DG:9FC8-9FC9, which `boardAt` reads from
/// `Position.game_ply`).
const unread_copies = [_]struct { m: est.Member, lo: u16, hi: u16 }{
    .{ .m = .s, .lo = 0xA03A, .hi = 0xA059 },
    .{ .m = .s, .lo = 0xA000, .hi = 0xA001 },
    .{ .m = .s, .lo = 0xA05A, .hi = 0xA05B },
    .{ .m = .lv, .lo = 0x9E96, .hi = 0x9F3D },
    .{ .m = .tv, .lo = 0x9FC8, .hi = 0x9FC9 },
};

/// Fails if a stale copy lies outside `unread_copies`.
fn pinned(n: usize, out: []const est.NodeEnv(@import("position.zig").Fixes.original).Stale) !void {
    try std.testing.expect(n <= out.len);
    for (out[0..n]) |x| {
        const ok = for (unread_copies) |u| {
            if (x.m == u.m and x.addr >= u.lo and x.addr <= u.hi) break true;
        } else false;
        if (!ok) {
            std.debug.print("a stale copy within a reader's reach: {s} DG:{X:0>4}\n", .{ @tagName(x.m), x.addr });
            return error.TestUnexpectedResult;
        }
    }
}
/// The stale copies a step leaves (`NodeEnv.staleAliases`), printed as runs.
fn staleAfter(s: anytype, label: []const u8, out: []est.NodeEnv(@import("position.zig").Fixes.original).Stale) !usize {
    const n = try s.node.staleAliases(std.testing.allocator, out);
    std.debug.print("stale copies after {s}: {d}", .{ label, n });
    var i: usize = 0;
    while (i < @min(n, out.len)) {
        var j = i + 1;
        while (j < @min(n, out.len) and out[j].m == out[i].m and out[j].addr == out[j - 1].addr + 1) j += 1;
        std.debug.print(" {s}:{X:0>4}-{X:0>4}", .{ @tagName(out[i].m), out[i].addr, out[j - 1].addr });
        i = j;
    }
    std.debug.print("\n", .{});
    return n;
}
// Stage B step 8, stage 4: with no bracket around them, the routines between searches no
// longer reload the members' copies of bytes another member holds (or that the image
// holds: `engine_state` `Aliases`), which every bracket's `enter` did. Measured here: each
// routine run from a domain just refreshed (`syncImage`), the copies it leaves different
// from their homes. Start-up, New game and Setup mode refresh the copies at their end
// (`EngineRoot.refreshCopies`); measured without that, and checked with it.
test "stage B step 8, stage 4: the copies of bytes another member holds that start-up, New game, Setup mode, the turn, the slide and the hash dialog leave stale" {
    const gpa = std.testing.allocator;
    const pos = @import("position.zig");
    const fen = @import("fen.zig");
    const as = @import("adapt_setup.zig");
    const gs = @import("gameslide.zig");
    const R = ert.EngineRoot(pos.Fixes.original);
    const s = try R.init(gpa, 16);
    defer s.deinit();
    var buf: [4096]R.NodeEnv.Stale = undefined;
    for ([_]bool{ false, true }) |refresh| {
        s.refresh_copies = refresh;
        std.debug.print("-- refresh_copies = {}\n", .{refresh});
        s.startUp(.{}, .{}, .{}, 2);
        const n_start = try staleAfter(s, "start-up", &buf);
        si.toImage(s);
        try std.testing.expectEqual(@as(usize, 0), try s.node.staleAliases(gpa, &buf));
        s.togglePondering(); // pondering off, as the engine plays
        try pinned(try staleAfter(s, "the ponder key", &buf), &buf);
        si.toImage(s);
        try std.testing.expect(s.autoPlay());
        try pinned(try staleAfter(s, "Ctrl-A", &buf), &buf);
        s.home().set(0x9FCF, 0); // normal play, as the engine plays
        s.home().set(0xAE44, s.home().get(0x717C)); // as src/engine.zig rebuild
        si.toImage(s);
        _ = s.search(.own);
        si.toImage(s);
        s.playMove();
        try pinned(try staleAfter(s, "play_best_move", &buf), &buf);
        si.toImage(s);
        try std.testing.expect(s.toOpponentMove());
        try pinned(try staleAfter(s, "the turn to the opponent's move", &buf), &buf);
        si.toImage(s);
        try std.testing.expect(s.enterMove(97, 76, 'q')); // ...Ng8-f6, legal after any first move
        try pinned(try staleAfter(s, "the opponent's move", &buf), &buf);
        si.toImage(s);
        _ = s.search(.own);
        si.toImage(s);
        s.playMove();
        si.toImage(s);
        s.nextTurnAutoPlay();
        try pinned(try staleAfter(s, "the turn in auto-play", &buf), &buf);
        si.toImage(s);
        _ = s.hashMenu(16 * 1024);
        try pinned(try staleAfter(s, "the hash dialog", &buf), &buf);
        si.toImage(s);
        dgroup.memSetWord(s.home(), gs.game_ply_addr, 300);
        dgroup.memSetWord(s.home(), gs.move_number_addr, 150);
        si.toImage(s);
        s.slideIfDue();
        try pinned(try staleAfter(s, "the slide", &buf), &buf);
        si.toImage(s);
        s.newGameCommand(.{});
        const n_new = try staleAfter(s, "the New game command", &buf);
        si.toImage(s);
        s.mainAfterNewGame();
        try pinned(try staleAfter(s, "main after New game", &buf), &buf);
        var n_setup: usize = 0;
        for ([_][]const u8{
            "rnbqkb1r/1p2pppp/p2p1n2/8/3NP3/2N5/PPP2PPP/R1BQKB1R w KQkq - 0 6",
            "r3k2r/p6p/8/8/8/8/P6P/R3K2R w Kq - 0 1",
            "r3k2r/p6p/8/8/8/8/P6P/R3K2R b - - 0 1",
            "rnbqkbnr/ppp1p1pp/8/3pPp2/8/8/PPPP1PPP/RNBQKBNR w KQkq f6 0 3",
            "8/8/8/4K3/Pk6/8/8/8 b - - 0 1",
        }) |text| {
            si.toImage(s);
            const d = try fen.parse(text);
            try std.testing.expectEqual(@import("setup.zig").Legality.legal, as.enterFen(s, &d));
            n_setup += try staleAfter(s, "Setup mode", &buf);
            si.toImage(s);
            try std.testing.expect(s.autoPlay());
            try pinned(try staleAfter(s, "Ctrl-A after Setup mode", &buf), &buf);
        }
        if (refresh) {
            try std.testing.expectEqual(@as(usize, 0), n_start + n_new + n_setup);
        }
    }
}
