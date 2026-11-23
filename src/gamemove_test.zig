//! Replay test of src/gamemove.zig against calls recorded from the running original
//! (tests/golden/gamemove/*.zst, made by tools/port/gen_gamemove_vectors.py, whose
//! docstring defines the format, from recordings of tools/research/gamemove/record.py).
//!
//! Each recorded call of play_best_move, play_entered_move, check_entered_move,
//! take_back_ply or new_game_position gives the DGROUP and game-record images at its
//! entry, every call it made in order (site, target, the images at the call and after
//! it, AX), and the images at its return. The port runs on the entry state. At every
//! callee it reaches through `ctx`, the test checks the callee against the next
//! recorded call, compares every field of the port's state (Position, GameVars,
//! GameRecord, the ply-0 move list) with the image the original had at that call,
//! then takes the callee's effects from the recording (the state is reloaded from the
//! image after the call; its AX is returned). For the two callees the port does itself
//! (update_castle_stamps, repetition_count) the state and AX are compared with the
//! image after the call instead. At the return the state and AX are compared with the
//! return images. Class C fixes do not apply to this unit.
//!
//! normal.zst (task predicted-reply) adds normal play: set_predicted_reply, whose
//! callees are answered the same way (make_move's captured piece and slot are read from
//! its locals in the recording), and legal_move_exists and king_attacked, which are
//! ported whole and compared with the original at their return (and, as callees of the
//! other routines, on the AX the original returned).

const std = @import("std");
const pos = @import("position.zig");
const gm = @import("gamemove.zig");
const setup = @import("setup.zig");
const Position = pos.Position;

const FAR_OWN = 0x7690;

const State = struct {
    p: Position = .{},
    gv: gm.GameVars = .{},
    rec: gm.GameRecord = .{},
    list: [100]pos.Move = @splat(.{ .from = 0, .to = 0, .flag = 0 }),
    /// The home of `gv`'s pointer fields (the variables other structs of the engine also
    /// declare): a copy of the image, as the engine binds them on the image
    /// (`GameVars.bindImage`).
    img: [0x10000]u8 = undefined,
};

// ---------------------------------------------------------------------------
// The state and the images
// ---------------------------------------------------------------------------

fn byteSize(comptime T: type) usize {
    return switch (@typeInfo(T)) {
        .int => |i| i.bits / 8,
        .array => |a| a.len * byteSize(a.child),
        else => @compileError("unsupported field type"),
    };
}

fn readT(comptime T: type, img: []const u8, addr: usize) T {
    switch (@typeInfo(T)) {
        .int => return std.mem.readInt(T, img[addr..][0..comptime byteSize(T)], .little),
        .array => |a| {
            var v: T = undefined;
            for (&v, 0..) |*x, k| x.* = readT(a.child, img, addr + k * byteSize(a.child));
            return v;
        },
        else => unreachable,
    }
}

fn writeT(comptime T: type, img: []u8, addr: usize, v: T) void {
    switch (@typeInfo(T)) {
        .int => std.mem.writeInt(T, img[addr..][0..comptime byteSize(T)], v, .little),
        .array => |a| for (v, 0..) |x, k| writeT(a.child, img, addr + k * byteSize(a.child), x),
        else => unreachable,
    }
}

const var_names = @typeInfo(@TypeOf(gm.var_addresses)).@"struct".field_names;
const rec_names = @typeInfo(@TypeOf(gm.record_offsets)).@"struct".field_names;

comptime {
    // every field of GameVars and GameRecord has an address
    if (@typeInfo(gm.GameVars).@"struct".field_names.len != var_names.len) @compileError("var_addresses incomplete");
    if (@typeInfo(gm.GameRecord).@"struct".field_names.len != rec_names.len) @compileError("record_offsets incomplete");
}

/// The Position's fields with their DGROUP addresses (the regions of
/// tools/research/position/model.py FIELDS).
fn posTransfer(comptime to: bool, p: *Position, img: []u8) void {
    const T = struct {
        fn b(im: []u8, a: usize, s: []u8) void {
            if (to) @memcpy(im[a..][0..s.len], s) else @memcpy(s, im[a..][0..s.len]);
        }
        fn w(im: []u8, a: usize, s: []u16) void {
            for (s, 0..) |*x, k| {
                if (to) std.mem.writeInt(u16, im[a + 2 * k ..][0..2], x.*, .little) else x.* = std.mem.readInt(u16, im[a + 2 * k ..][0..2], .little);
            }
        }
        fn key(im: []u8, a: usize, k: *u48) void {
            if (to) std.mem.writeInt(u48, im[a..][0..6], k.*, .little) else k.* = std.mem.readInt(u48, im[a..][0..6], .little);
        }
    };
    T.b(img, 0x9EF6, &p.board);
    T.b(img, 0xA03A, &p.piece_list);
    T.b(img, 0xA28C, &p.square_slot);
    T.b(img, 0xA51C, &p.pawn_attacks[0]);
    T.b(img, 0x37DA, &p.pawn_attacks[1]);
    T.b(img, 0xA09E, &p.king_rays[0]);
    T.b(img, 0xA164, &p.king_rays[1]);
    T.b(img, 0xA8C8, &p.pawns_per_file[0]);
    T.b(img, 0x9EA8, &p.pawns_per_file[1]);
    T.w(img, 0x8DE4, &p.material);
    T.w(img, 0xAE38, &p.piece_material);
    T.w(img, 0x378E, (&p.piece_material_sum)[0..1]);
    T.w(img, 0xA420, (&p.total_material)[0..1]);
    T.w(img, 0xA35E, (&p.material_balance)[0..1]);
    T.w(img, 0xA8D2, (&p.piece_balance)[0..1]);
    T.w(img, 0xA4C6, (&p.material_balance_2)[0..1]);
    T.w(img, 0x7182, (&p.piece_square_sum)[0..1]);
    T.b(img, 0x154A, (&p.men)[0..1]);
    T.b(img, 0x931A, &p.piece_count);
    T.b(img, 0x90AA, (&p.pawn_count)[0..1]);
    T.b(img, 0xAB1E, p.side_pawn_count[0..1]);
    T.b(img, 0x741A, p.side_pawn_count[1..2]);
    T.b(img, 0xB520, p.pawns_on_dark[0..1]);
    T.b(img, 0xA354, p.pawns_on_dark[1..2]);
    T.b(img, 0xA22E, &p.king_file);
    T.b(img, 0x70F0, &p.king_rank);
    T.w(img, 0xB426, &p.oo_lost_at);
    T.w(img, 0x3A30, &p.ooo_lost_at);
    T.w(img, 0x9FC8, (&p.game_ply)[0..1]);
    T.key(img, 0x8CCC, &p.hash_key);
    T.key(img, 0x8CD2, &p.pawn_hash_key);
    T.b(img, 0x9EC8, p.ep_square_by_ply[0..46]);
    T.b(img, 0x8C06, p.check_by_ply[0..60]);
    T.w(img, 0x8BBE, p.reversible_by_ply[0..36]);
    T.w(img, 0x3626, p.quiet_move_by_ply[0..40]);
}

fn listTransfer(comptime to: bool, list: *[100]pos.Move, img: []u8) void {
    for (list, 0..) |*m, k| {
        const a = 0x3A34 + 4 * k;
        if (to) {
            img[a] = m.from;
            img[a + 1] = m.to;
            img[a + 2] = m.flag;
            img[a + 3] = m.score;
        } else m.* = .{ .from = img[a], .to = img[a + 1], .flag = img[a + 2], .score = img[a + 3] };
    }
}

fn load(st: *State, dg: []u8, far: []u8) void {
    posTransfer(false, &st.p, dg);
    listTransfer(false, &st.list, dg);
    @memcpy(&st.img, dg[0..0x10000]);
    st.gv.bindImage(&st.img);
    inline for (var_names) |n| {
        if (comptime !gm.isPointerVar(n)) @field(st.gv, n) = readT(@TypeOf(@field(st.gv, n)), dg, @field(gm.var_addresses, n));
    }
    inline for (rec_names) |n| @field(st.rec, n) = readT(@TypeOf(@field(st.rec, n)), far, @field(gm.record_offsets, n));
}

fn store(st: *State, dg: []u8, far: []u8) void {
    posTransfer(true, &st.p, dg);
    listTransfer(true, &st.list, dg);
    inline for (var_names) |n| {
        const a = @field(gm.var_addresses, n);
        if (comptime gm.isPointerVar(n)) {
            const len = comptime gm.varBytes(n);
            @memcpy(dg[a..][0..len], st.img[a..][0..len]);
        } else writeT(@TypeOf(@field(st.gv, n)), dg, a, @field(st.gv, n));
    }
    inline for (rec_names) |n| writeT(@TypeOf(@field(st.rec, n)), far, @field(gm.record_offsets, n), @field(st.rec, n));
}

fn nameOfDg(a: usize) []const u8 {
    inline for (var_names) |n| {
        const lo = @field(gm.var_addresses, n);
        if (a >= lo and a < lo + comptime gm.varBytes(n)) return "GameVars." ++ n;
    }
    if (a >= 0x3A34 and a < 0x3A34 + 400) return "move list (DG:3A34)";
    return "Position";
}

fn nameOfFar(a: usize) []const u8 {
    inline for (rec_names) |n| {
        const lo = @field(gm.record_offsets, n);
        if (a >= lo and a < lo + byteSize(@TypeOf(@field(@as(gm.GameRecord, .{}), n)))) return "GameRecord." ++ n;
    }
    return "?";
}

const interrupt_bytes = [_]u16{ 0x0058, 0x0059, 0x2A68, 0xAB1C, 0xAB1D, 0x75B6, 0x75B7, 0x3682, 0x3683, 0x8DDC, 0x8DDD, 0x9EB2, 0x9EB3, 0x367C, 0x367D, 0x8DD6, 0x8DD7, 0x8DD4, 0x8DD5 };

/// Compare the port's state with the reference images; a description of the first
/// difference, or null. Bytes of the stack window and, when `interrupted`, the timer
/// interrupt's bytes are left out.
fn compareState(st: *State, dg: []const u8, far: []const u8, sp: u16, interrupted: bool, buf: []u8) ?[]const u8 {
    var sdg: [0x10000]u8 = undefined;
    var sfar: [FAR_OWN]u8 = undefined;
    @memcpy(&sdg, dg);
    @memcpy(&sfar, far);
    store(st, &sdg, &sfar);
    const lo: usize = @max(0xB700, @as(usize, sp) -| 0x3000);
    const hi: usize = @min(0x10000, @as(usize, sp) + 0x10);
    for (0..0x10000) |a| {
        if (sdg[a] == dg[a] or (a >= lo and a < hi)) continue;
        if (interrupted and std.mem.indexOfScalar(u16, &interrupt_bytes, @intCast(a)) != null) continue;
        return std.fmt.bufPrint(buf, "DG:{X:0>4} ({s}): port {X:0>2}, original {X:0>2}", .{ a, nameOfDg(a), sdg[a], dg[a] }) catch "differs";
    }
    for (0..FAR_OWN) |a| {
        if (sfar[a] != far[a])
            return std.fmt.bufPrint(buf, "5A7B:{X:0>4} ({s}): port {X:0>2}, original {X:0>2}", .{ a, nameOfFar(a), sfar[a], far[a] }) catch "differs";
    }
    return null;
}

// ---------------------------------------------------------------------------
// Reading the file
// ---------------------------------------------------------------------------

const Cursor = struct {
    d: []const u8,
    i: usize = 0,
    fn byte(c: *Cursor) u8 {
        const v = c.d[c.i];
        c.i += 1;
        return v;
    }
    fn int(c: *Cursor, comptime T: type) T {
        const v = std.mem.readInt(T, c.d[c.i..][0..@sizeOf(T)], .little);
        c.i += @sizeOf(T);
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
    fn changes(c: *Cursor, img: []u8) void {
        const n = c.varint();
        var prev: isize = -1;
        for (0..n) |_| {
            const a: usize = @intCast(prev + 1 + @as(isize, @intCast(c.varint())));
            img[a] = c.byte();
            prev = @intCast(a);
        }
    }
};

const Call = struct { site: u16, seg: u16, off: u16, pre: usize, ax: u16 };

const Replay = struct {
    st: *State,
    file: []const u8,
    calls: []const Call,
    next: usize = 0,
    entry_dg: *const [0x10000]u8,
    entry_far: *const [FAR_OWN]u8,
    sp: u16,
    interrupted: bool,
    failure: ?[]const u8 = null,
    buf: [240]u8 = undefined,
    kind_name: []const u8,
    /// The recorded call images keep the routine's own locals (set_predicted_reply).
    locals: bool = false,

    fn fail(r: *Replay, comptime f: []const u8, args: anytype) void {
        if (r.failure != null) return;
        r.failure = std.fmt.bufPrint(&r.buf, f, args) catch "failure";
    }

    /// The images at recorded call c (`after`: after it).
    fn images(r: *Replay, c: Call, after: bool, dg: *[0x10000]u8, far: *[FAR_OWN]u8) void {
        @memcpy(dg, r.entry_dg);
        @memcpy(far, r.entry_far);
        var cur: Cursor = .{ .d = r.file, .i = c.pre };
        cur.changes(dg);
        cur.changes(far);
        if (after) {
            cur.changes(dg);
            cur.changes(far);
        }
    }

    /// Consume the next recorded call: it must be `seg:off` (and at `site`, if given).
    /// `ported`: the port did the callee itself; compare with the images after it.
    fn take(r: *Replay, seg: u16, off: u16, site: ?u16, after_call: bool) u16 {
        if (r.failure != null) return 0;
        if (r.next >= r.calls.len) {
            r.fail("{s}: the port calls {X:0>4}:{X:0>4}, the original made no more calls", .{ r.kind_name, seg, off });
            return 0;
        }
        const c = r.calls[r.next];
        r.next += 1;
        if (c.seg != seg or c.off != off or (site != null and site.? != c.site)) {
            r.fail("{s} call {d}: the port calls {X:0>4}:{X:0>4} (site {?X}), the original {X:0>4}:{X:0>4} at {X:0>4}", .{ r.kind_name, r.next, seg, off, site, c.seg, c.off, c.site });
            return 0;
        }
        var dg: [0x10000]u8 = undefined;
        var far: [FAR_OWN]u8 = undefined;
        r.images(c, after_call, &dg, &far);
        var b2: [200]u8 = undefined;
        if (compareState(r.st, &dg, &far, r.sp, r.interrupted, &b2)) |d| {
            r.fail("{s}, {s} {X:0>4}:{X:0>4} at {X:0>4}: {s}", .{ r.kind_name, if (after_call) "after" else "before", seg, off, c.site, d });
            return 0;
        }
        if (!after_call) {
            r.images(c, true, &dg, &far);
            load(r.st, &dg, &far);
        }
        return c.ax;
    }

    // ---- the ctx interface of gamemove.zig ----
    pub fn notation(r: *Replay, from: u8, to: u8, moving: u8) u8 {
        _ = .{ from, to, moving };
        return @truncate(r.take(0x38C0, 0xD5E2, null, false));
    }
    pub fn squareSums(r: *Replay, move: [3]u8) void {
        _ = move;
        _ = r.take(0x0000, 0x69DC, null, false);
    }
    pub fn makeMove(r: *Replay, buf: *[5]u8, side: u8, ply: u16) void {
        _ = .{ side, ply };
        _ = r.take(0x1E9D, 0x000C, null, false);
        if (r.locals and r.failure == null) {
            // set_predicted_reply: make_move's outputs went to its locals [bp-4] and
            // [bp-15h] (bp = entry SP - 2), which the recording keeps.
            var dg: [0x10000]u8 = undefined;
            var far: [FAR_OWN]u8 = undefined;
            r.images(r.calls[r.next - 1], true, &dg, &far);
            buf[3] = dg[r.sp - 6];
            buf[4] = dg[r.sp - 0x17];
        }
    }
    pub fn unmakeMove(r: *Replay, move: [5]u8, side: u8) void {
        _ = .{ move, side };
        _ = r.take(0x1E9D, 0x0960, null, false);
    }
    pub fn bookKey(r: *Replay, side: u8) void {
        _ = side;
        _ = r.take(0x4793, 0x5816, null, false);
    }
    pub fn hashFromScratch(r: *Replay) void {
        _ = r.take(0x4793, 0x4026, null, false);
    }
    pub fn legalMoveExists(r: *Replay, side: u8) u16 {
        // The port's answer, on the state at the call (the board is restored), must be
        // the original's.
        const mine = if (r.failure == null) gm.legalMoveExists(&r.st.p, side, 0) else 0;
        const ax = r.take(0x2B9F, 0x458A, null, false);
        if (r.failure == null and mine != ax) r.fail("{s}: legal_move_exists {d}, the original {d}", .{ r.kind_name, mine, ax });
        return ax;
    }
    pub fn replyCall(r: *Replay, c: gm.ReplyCallee, a: u16, b: u16) u16 {
        _ = .{ a, b };
        const at = gm.reply_callee_address.get(c);
        return r.take(at[0], at[1], null, false);
    }
    pub fn predictReply(r: *Replay, arg: u16) void {
        _ = arg;
        _ = r.take(0x38C0, 0x0D22, null, false);
    }
    pub fn bookProbe(r: *Replay, mode: u16, side: u8) void {
        _ = .{ mode, side };
        _ = r.take(0x4793, 0x621E, null, false);
    }
    pub fn resetMoveTime(r: *Replay) void {
        _ = r.take(0x1E9D, 0x7E8A, null, false);
    }
    pub fn genMoves(r: *Replay, side: u8, in_check: bool) u16 {
        _ = side;
        return if (in_check) r.take(0x38C0, 0xE260, null, false) else r.take(0x1E9D, 0x3938, null, false);
    }
    pub fn kingAttacked(r: *Replay, side: u8) u16 {
        const mine = if (r.failure == null) gm.kingAttacked(&r.st.p, side) else 0;
        const ax = r.take(0x2B9F, 0x4B32, null, false);
        if (r.failure == null and mine != ax) r.fail("{s}: king_attacked {d}, the original {d}", .{ r.kind_name, mine, ax });
        return ax;
    }
    pub fn gameBoard(r: *Replay, sq: u8) u8 {
        return r.entry_dg[0x7520 + @as(usize, sq)];
    }
    pub fn ported(r: *Replay, site: u16, ax: u16) void {
        if (r.failure != null or r.next >= r.calls.len) return r.fail("{s}: ported callee at {X:0>4} not recorded", .{ r.kind_name, site });
        const c = r.calls[r.next];
        if (c.site != site) return r.fail("{s}: ported callee at {X:0>4}, the original called at {X:0>4}", .{ r.kind_name, site, c.site });
        const got = r.take(c.seg, c.off, site, true);
        if (r.failure == null and c.off == 0x402A and got != ax) r.fail("{s}: repetition_count {d}, the original {d}", .{ r.kind_name, ax, got });
    }
    pub fn ui(r: *Replay, site: u16) void {
        if (r.failure != null or r.next >= r.calls.len) return r.fail("{s}: UI call at {X:0>4} not recorded", .{ r.kind_name, site });
        const c = r.calls[r.next];
        _ = r.take(c.seg, c.off, site, false);
    }
};

fn readVectors(gpa: std.mem.Allocator, name: []const u8) ![]u8 {
    var path_buf: [256]u8 = undefined;
    const dir = @import("build_options").golden_dir;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/gamemove/{s}", .{ dir, name });
    const compressed = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, gpa, .limited(64 << 20));
    defer gpa.free(compressed);
    var in: std.Io.Reader = .fixed(compressed);
    const window = try gpa.alloc(u8, std.compress.zstd.default_window_len + std.compress.zstd.block_size_max);
    defer gpa.free(window);
    var zd = std.compress.zstd.Decompress.init(&in, window, .{});
    return zd.reader.allocRemaining(gpa, .limited(512 << 20));
}

const kind_names = [_][]const u8{ "", "play_best_move", "play_entered_move", "check_entered_move", "take_back_ply", "new_game_position", "set_predicted_reply", "legal_move_exists", "king_attacked" };

const Totals = struct { events: [9]usize = @splat(0), calls: usize = 0, failures: usize = 0, quiet: bool = false };

fn replayFile(comptime fixes: pos.Fixes, gpa: std.mem.Allocator, name: []const u8, tot: *Totals) !void {
    const raw = try readVectors(gpa, name);
    defer gpa.free(raw);
    try std.testing.expectEqualSlices(u8, "MCGM", raw[0..4]);
    const version = std.mem.readInt(u16, raw[4..6], .little);
    try std.testing.expect(version == 1 or version == 2);
    var c: Cursor = .{ .d = raw, .i = 6 };
    const entry_dg = try gpa.create([0x10000]u8);
    defer gpa.destroy(entry_dg);
    const entry_far = try gpa.create([FAR_OWN]u8);
    defer gpa.destroy(entry_far);
    const out_dg = try gpa.create([0x10000]u8);
    defer gpa.destroy(out_dg);
    const out_far = try gpa.create([FAR_OWN]u8);
    defer gpa.destroy(out_far);
    const work_dg = try gpa.create([0x10000]u8);
    defer gpa.destroy(work_dg);
    const work_far = try gpa.create([FAR_OWN]u8);
    defer gpa.destroy(work_far);
    @memset(entry_dg, 0);
    @memset(entry_far, 0);
    const st = try gpa.create(State);
    defer gpa.destroy(st);
    var calls: std.ArrayList(Call) = .empty;
    defer calls.deinit(gpa);
    var n: usize = 0;
    while (true) : (n += 1) {
        const kind = c.byte();
        if (kind == 0) break;
        const arg = c.int(u16);
        const arg2: u16 = if (version >= 2) c.int(u16) else 0;
        const ax = c.int(u16);
        const interrupted = c.byte() != 0;
        const sp = c.int(u16);
        c.changes(entry_dg);
        c.changes(entry_far);
        const ncalls = c.int(u16);
        calls.clearRetainingCapacity();
        for (0..ncalls) |_| {
            const site = c.int(u16);
            const seg = c.int(u16);
            const off = c.int(u16);
            const pre = c.i;
            var dummy_dg: [0x10000]u8 = undefined;
            var dummy_far: [FAR_OWN]u8 = undefined;
            for (0..4) |k| if (k % 2 == 0) c.changes(&dummy_dg) else c.changes(&dummy_far);
            try calls.append(gpa, .{ .site = site, .seg = seg, .off = off, .pre = pre, .ax = c.int(u16) });
        }
        @memcpy(out_dg, entry_dg);
        @memcpy(out_far, entry_far);
        c.changes(out_dg);
        c.changes(out_far);
        tot.events[kind] += 1;
        tot.calls += ncalls;

        @memcpy(work_dg, entry_dg);
        @memcpy(work_far, entry_far);
        st.* = .{};
        load(st, work_dg, work_far);
        var r: Replay = .{ .st = st, .file = raw, .calls = calls.items, .entry_dg = entry_dg, .entry_far = entry_far, .sp = sp, .interrupted = interrupted, .kind_name = kind_names[kind], .locals = kind == 6 };
        var ret: ?u16 = null;
        switch (kind) {
            1 => {
                const ptr = std.mem.readInt(u16, entry_dg[0x73F8..][0..2], .little);
                gm.playBestMove(&st.p, &st.gv, &st.rec, arg, entry_dg[ptr..][0..3].*, &r);
            },
            2 => ret = gm.playEnteredMove(&st.p, &st.gv, &st.rec, &r),
            3 => ret = gm.checkEnteredMove(&st.p, &st.gv, &st.rec, &st.list, &r),
            4 => gm.takeBackPly(&st.p, &st.gv, &st.rec, &r),
            5 => {
                // The board, lists and maps (setup.newGame), then the game variables; the
                // recorded callees (the two king maps, hash_from_scratch) are setup's.
                var sv: setup.SetupVars = .{};
                setup.newGame(&st.p, &sv);
                const seg = std.mem.readInt(u16, out_dg[0xA512..][0..2], .little);
                gm.newGameVars(&st.p, &st.gv, &st.rec, seg);
                r.next = r.calls.len;
            },
            6 => gm.setPredictedReplyFixes(fixes, &st.p, &st.gv, &st.list, &r),
            // Ported whole: the recorded calls inside them are not consulted.
            7 => {
                ret = gm.legalMoveExists(&st.p, arg, arg2);
                r.next = r.calls.len;
            },
            8 => {
                ret = gm.kingAttacked(&st.p, arg);
                r.next = r.calls.len;
            },
            else => return error.BadKind,
        }
        if (r.failure == null and r.next != r.calls.len) r.fail("{s}: the original made {d} calls, the port {d}", .{ r.kind_name, r.calls.len, r.next });
        if (r.failure == null) {
            var b2: [200]u8 = undefined;
            if (compareState(st, out_dg, out_far, sp, interrupted, &b2)) |d| r.fail("{s} at the return: {s}", .{ r.kind_name, d });
        }
        if (r.failure == null and ret != null and ret.? != ax) r.fail("{s}: AX {X:0>4}, the original {X:0>4}", .{ r.kind_name, ret.?, ax });
        if (r.failure) |f| {
            tot.failures += 1;
            if (tot.failures <= 5 and !tot.quiet) std.debug.print("gamemove {s} event {d}: {s}\n", .{ name, n, f });
        }
    }
    try std.testing.expectEqual(@as(u32, @intCast(n)), c.int(u32));
}

test "gamemove: replay of recorded game-move calls" {
    const gpa = std.testing.allocator;
    var tot: Totals = .{};
    const files = [_][]const u8{ "games.zst", "normal.zst" };
    for (files) |f| try replayFile(pos.Fixes.original, gpa, f, &tot);
    std.debug.print("gamemove: {d} play_best_move, {d} play_entered_move, {d} check_entered_move, {d} take_back_ply, {d} new_game_position, {d} set_predicted_reply, {d} legal_move_exists, {d} king_attacked; {d} calls; {d} failures\n", .{ tot.events[1], tot.events[2], tot.events[3], tot.events[4], tot.events[5], tot.events[6], tot.events[7], tot.events[8], tot.calls, tot.failures });
    try std.testing.expectEqual(@as(usize, 0), tot.failures);
    try std.testing.expect(tot.events[1] > 0 and tot.events[2] > 0 and tot.events[3] > 0);
    try std.testing.expect(tot.events[6] > 0 and tot.events[7] > 0 and tot.events[8] > 0);
}

fn positionOf(text: []const u8) !Position {
    const d = try @import("fen.zig").parse(text);
    var p: Position = .{};
    var v: setup.SetupVars = .{};
    setup.buildFromDescription(&p, &v, &d);
    return p;
}

// No recorded call returned 0 (no stalemate arose in the recorded games): these
// positions check the paths to 0 and the pin tests by hand.
test "gamemove: legal_move_exists finds stalemate, pinned pieces and free ones" {
    // Black: Ka8 alone against Kb6, Qc7: every king step attacked.
    var p = try positionOf("k7/2Q5/1K6/8/8/8/8/8 b - - 0 1");
    try std.testing.expectEqual(@as(u16, 0), gm.legalMoveExists(&p, 1, 0));
    try std.testing.expectEqual(@as(u16, 1), gm.legalMoveExists(&p, 0, 0));
    // Black: Kh8, Ng7 pinned on the long diagonal by Qa1; g8 and h7 attacked.
    p = try positionOf("7k/5Kn1/6P1/8/8/8/8/Q7 b - - 0 1");
    try std.testing.expectEqual(@as(u16, 0), gm.legalMoveExists(&p, 1, 0));
    // The same without the queen: the knight moves.
    p = try positionOf("7k/5Kn1/6P1/8/8/8/8/8 b - - 0 1");
    try std.testing.expectEqual(@as(u16, 1), gm.legalMoveExists(&p, 1, 0));
    // A pinned bishop moves along the pin (made, tested, restored): Kh8, Bg7, Qa1.
    p = try positionOf("7k/5Kb1/6P1/8/8/8/8/Q7 b - - 0 1");
    const before = p.board;
    try std.testing.expectEqual(@as(u16, 1), gm.legalMoveExists(&p, 1, 0));
    try std.testing.expectEqualSlices(u8, &before, &p.board);
    // king_attacked: the rook's file is blocked by the White king; then open.
    p = try positionOf("4k3/8/4K3/8/8/8/8/4R3 b - - 0 1");
    try std.testing.expectEqual(@as(u16, 0), gm.kingAttacked(&p, 1));
    p = try positionOf("4k3/8/8/8/8/8/8/K3R3 b - - 0 1");
    try std.testing.expectEqual(@as(u16, 1), gm.kingAttacked(&p, 1));
    try std.testing.expectEqual(@as(u16, 0), gm.kingAttacked(&p, 0));
}

test "gamemove: update_castle_stamps stamps a captured corner rook only" {
    var p: Position = .{};
    p.game_ply = 9;
    p.piece_list[4] = 0x1C + 0x63; // White h1 rook captured
    p.piece_list[5] = 0x15; // a1 rook at home
    p.piece_list[16 + 4] = 0x62 + 0x63;
    p.ooo_lost_at[1] = 3; // already lost
    p.piece_list[16 + 5] = 0x5B + 0x63;
    gm.updateCastleStamps(&p);
    try std.testing.expectEqual(@as(u16, 9), p.oo_lost_at[0]);
    try std.testing.expectEqual(@as(u16, 0), p.ooo_lost_at[0]);
    try std.testing.expectEqual(@as(u16, 9), p.oo_lost_at[1]);
    try std.testing.expectEqual(@as(u16, 3), p.ooo_lost_at[1]);
}

test "gamemove: repetition_count counts plies g-4, g-6, ... back to the last irreversible ply" {
    var p: Position = .{};
    var gv: gm.GameVars = .{};
    var last: u16 = 0;
    gv.last_irreversible_ply = &last;
    const rec = try std.testing.allocator.create(gm.GameRecord);
    defer std.testing.allocator.destroy(rec);
    rec.* = .{};
    p.game_ply = 12;
    p.hash_key = 0xABCDEF;
    last = 4;
    for ([_]usize{ 8, 4, 6, 11 }) |g| rec.keys[g] = 0xABCDEF;
    try std.testing.expectEqual(@as(u16, 3), gm.repetitionCount(&p, &gv, rec)); // 8, 6, 4 (not 11)
    last = 9;
    try std.testing.expectEqual(@as(u16, 0), gm.repetitionCount(&p, &gv, rec)); // g-4 = 8 < 9
}

test "DEV-046: the Black reply's first threat term subtracts the bonus when corrected" {
    // Replays every recorded call with the fix on. A set_predicted_reply call scoring Black
    // replies with at least one attacked piece (bonus > 0) gets other reply scores, so its
    // replay no longer matches; every other event is unchanged.
    const gpa = std.testing.allocator;
    const fixes = comptime blk: {
        var f = pos.Fixes.original;
        f.dev046_reply_sign = true;
        break :blk f;
    };
    var tot: Totals = .{ .quiet = true };
    for ([_][]const u8{ "games.zst", "normal.zst" }) |f| try replayFile(fixes, gpa, f, &tot);
    std.debug.print("DEV-046: {d} of {d} recorded set_predicted_reply calls change with the fix on\n", .{ tot.failures, tot.events[6] });
    try std.testing.expect(tot.failures > 0 and tot.failures <= tot.events[6]);
}
