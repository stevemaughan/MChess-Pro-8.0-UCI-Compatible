//! Stage B, step 8, stage 6 (docs/arch/60-engine-assembly.md section 10.7.14): the engine's
//! commands (src/engine.zig) and the reporter (src/uci_report.zig) run on the members, with
//! no image bracket; the start-up checkpoint and `rebuild`'s one-move copy are taken and
//! restored whole (`EngineRoot.saveState`, `restoreState`).
//!
//! - The commands of a game of every kind make no image bracket (`EngineRoot.image_brackets`,
//!   counted in test builds only).
//! - The start-up checkpoint restored after a game gives the start-up image on every byte,
//!   the node's `State` (the killers, the hash sizing) and the game record included, and a
//!   game after `ucinewgame` is the game a fresh engine plays, every line.
//! - The members' copies of bytes another member holds (`engine_state` `Aliases`) that the
//!   commands leave stale, at every command and at the points of a `go` where the state is
//!   handed on, each out of every reader's reach.

const std = @import("std");
const si = @import("state_image.zig");
const fen = @import("fen.zig");
const pos = @import("position.zig");
const uci_engine = @import("uci_engine.zig");
const engine_mod = @import("engine.zig");
const ert = @import("engine_root.zig");
const est = @import("engine_state.zig");
const dgroup = @import("dgroup.zig");

const E = engine_mod.EngineOf(pos.Fixes.original);
const Stale = E.EngineRoot.NodeEnv.Stale;

const Capture = struct {
    buf: [1 << 16]u8 = undefined,
    len: usize = 0,
    fn lineFn(ctx: ?*anyopaque, line: []const u8) void {
        const c: *Capture = @ptrCast(@alignCast(ctx.?));
        if (c.len + line.len + 1 > c.buf.len) return;
        @memcpy(c.buf[c.len..][0..line.len], line);
        c.len += line.len;
        c.buf[c.len] = '\n';
        c.len += 1;
    }
    fn text(c: *const Capture) []const u8 {
        return c.buf[0..c.len];
    }
    fn out(c: *Capture) uci_engine.Output {
        return .{ .ctx = c, .lineFn = lineFn };
    }
};

/// Every `info` line with its `time` and `nps` values taken out, and the result, for
/// comparing two engines' output.
fn normalized(gpa: std.mem.Allocator, text: []const u8, r: uci_engine.Result) ![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |l| {
        var it = std.mem.tokenizeScalar(u8, l, ' ');
        var skip = false;
        while (it.next()) |t| {
            if (skip) {
                skip = false;
                continue;
            }
            if (std.mem.eql(u8, t, "time") or std.mem.eql(u8, t, "nps")) {
                skip = true;
                continue;
            }
            try list.appendSlice(gpa, t);
            try list.append(gpa, ' ');
        }
        try list.append(gpa, '\n');
    }
    var mb: [5]u8 = undefined;
    try list.print(gpa, "bestmove {s}", .{if (r.best) |b| fen.formatMove(b, &mb) else "none"});
    if (r.ponder) |p| try list.print(gpa, " ponder {s}", .{fen.formatMove(p, &mb)});
    try list.append(gpa, '\n');
    return list.toOwnedSlice(gpa);
}

/// An engine driven as a GUI drives it, recording what it says.
const Session = struct {
    gpa: std.mem.Allocator,
    e: *E,
    log: std.ArrayList(u8) = .empty,
    /// The game so far, from the start position.
    game: [512]fen.UciMove = undefined,
    n: usize = 0,
    /// The ponder move of the last `go`.
    ponder: ?fen.UciMove = null,

    fn init(gpa: std.mem.Allocator) !Session {
        const e = try gpa.create(E);
        errdefer gpa.destroy(e);
        e.* = try E.init(gpa);
        // The shell hands the engine its options once at start-up (src/uci.zig `init`).
        e.engine().applyOptions(&.{});
        return .{ .gpa = gpa, .e = e };
    }
    fn deinit(s: *Session) void {
        s.e.deinit();
        s.gpa.destroy(s.e);
        s.log.deinit(s.gpa);
    }
    fn eng(s: *Session) uci_engine.Engine {
        return s.e.engine();
    }
    fn options(s: *Session, o: uci_engine.Options) void {
        s.eng().applyOptions(&o);
    }
    fn newGame(s: *Session) void {
        s.eng().newGame();
        s.n = 0;
    }
    /// `position startpos moves <the first k of the game>`.
    fn startpos(s: *Session, k: usize) !void {
        const start = try fen.parse(fen.startpos);
        s.n = k;
        if (s.eng().setPosition(&start, .new_game, s.game[0..k])) |why| {
            std.debug.print("stage 6: position rejected: {s}\n", .{why});
            return error.Rejected;
        }
    }
    fn fenPosition(s: *Session, text: []const u8, moves: []const []const u8) !void {
        const d = try fen.parse(text);
        var ms: [8]fen.UciMove = undefined;
        for (moves, 0..) |m, i| ms[i] = try fen.parseMove(m);
        if (s.eng().setPosition(&d, .setup, ms[0..moves.len])) |why| {
            std.debug.print("stage 6: position fen rejected: {s}\n", .{why});
            return error.Rejected;
        }
    }
    /// `go` with `limits`; `stop` set before it (the search stops at its first test of the
    /// request); `ponderhit` set before it (a ponder hit). The move played is added to the
    /// game when `keep`.
    fn go(s: *Session, limits: uci_engine.Limits, stop: bool, keep: bool) !uci_engine.Result {
        var cap: Capture = .{};
        var sig: uci_engine.Signals = .{};
        if (stop) sig.stop.store(true, .release);
        if (limits.ponder) sig.ponderhit.store(true, .release);
        const r = s.eng().search(&limits, &sig, cap.out());
        const t = try normalized(s.gpa, cap.text(), r);
        defer s.gpa.free(t);
        try s.log.print(s.gpa, "-- nodes {d} makes {d} line {s}\n", .{ s.e.root.nodes, s.e.root.makes, s.e.root.lineHex() });
        try s.log.appendSlice(s.gpa, t);
        s.ponder = r.ponder;
        if (keep) if (r.best) |b| {
            s.game[s.n] = b;
            s.n += 1;
        };
        return r;
    }
    /// The opponent's move: the program's predicted reply, else the first of `fallback`
    /// that the engine accepts.
    fn reply(s: *Session, fallback: []const []const u8) !void {
        if (s.ponder) |p| {
            s.game[s.n] = p;
            s.n += 1;
            return s.startpos(s.n);
        }
        for (fallback) |m| {
            s.game[s.n] = try fen.parseMove(m);
            const start = try fen.parse(fen.startpos);
            if (s.eng().setPosition(&start, .new_game, s.game[0 .. s.n + 1]) == null) {
                s.n += 1;
                return;
            }
        }
        return error.NoReply;
    }
};

/// A game of every kind of command the shell sends (docs/UCI.md, "The operator script"):
/// continued moves, ponder searches hit and stopped, `stop` during a search, take-backs of
/// 1, 2, 3 and 6 plies, a new line, a second `go` on one position, `setoption` between
/// searches, `ucinewgame`, `position fen` (refused and accepted), and `go infinite` then
/// `stop` in a tablebase position. `between` is called after each command.
fn playEveryKind(s: *Session, between: anytype) !void {
    const fallback = [_][]const u8{ "e7e5", "d7d5", "g8f6", "b8c6", "e7e6", "c7c5", "g7g6", "a7a6", "h7h6", "e2e4", "d2d4", "g1f3", "b1c3" };
    try s.startpos(0);
    try between.at(s, "position startpos");
    _ = try s.go(.{ .depth = 3 }, false, true);
    try between.at(s, "go depth 3");
    var k: usize = 0;
    while (k < 8) : (k += 1) {
        try s.reply(&fallback);
        try between.at(s, "position, continued");
        if (k == 3) {
            _ = try s.go(.{ .depth = 3, .ponder = true }, false, true); // a ponder hit
            try between.at(s, "go ponder, ponderhit");
        } else if (k == 5) {
            _ = try s.go(.{ .depth = 30 }, true, true); // stop during a search
            try between.at(s, "go, stop");
        } else {
            _ = try s.go(.{ .depth = 2 + @as(u32, @intCast(k % 3)) }, false, true);
            try between.at(s, "go depth N");
        }
    }
    // A ponder search stopped (a ponder miss), then the position the opponent chose.
    _ = try s.go(.{ .depth = 30, .ponder = true }, true, false);
    try between.at(s, "go ponder, stop");
    // A second `go` on the same position.
    try s.startpos(s.n);
    _ = try s.go(.{ .depth = 2 }, false, false);
    try between.at(s, "go, again on one position");
    // Take-backs of 1, 2, 3 and 6 plies, each searched.
    for ([_]usize{ 1, 2, 3, 6 }) |back| {
        try s.startpos(s.n - back);
        try between.at(s, "position, a take-back");
        _ = try s.go(.{ .depth = 2 }, false, true);
        try between.at(s, "go after a take-back");
    }
    // setoption between searches, then the game continued.
    s.options(.{ .hash_mb = 16, .own_book = false, .use_tablebases = false, .seed = 5 });
    try between.at(s, "setoption");
    try s.reply(&fallback);
    _ = try s.go(.{ .depth = 3 }, false, true);
    try between.at(s, "go after setoption");
    // ucinewgame, options back, a new game with the book.
    s.newGame();
    s.options(.{ .own_book = true, .book = .variety, .seed = 1234 });
    try between.at(s, "ucinewgame, setoption");
    try s.startpos(0);
    var b: usize = 0;
    while (b < 4) : (b += 1) {
        _ = try s.go(.{ .depth = 2 }, false, true);
        try between.at(s, "go with the book");
        try s.reply(&fallback);
    }
    s.options(.{});
    // A rejected position, then a good one.
    const d = try fen.parse("4k3/8/8/8/8/8/8/K3K3 w - - 0 1");
    try std.testing.expect(s.eng().setPosition(&d, .setup, &.{}) != null);
    try between.at(s, "position fen, refused");
    try s.fenPosition("rnbqkb1r/1p2pppp/p2p1n2/8/3NP3/2N5/PPP2PPP/R1BQKB1R w KQkq - 0 6", &.{});
    try between.at(s, "position fen");
    _ = try s.go(.{ .depth = 3 }, false, false);
    try between.at(s, "go after position fen");
    try s.fenPosition("rnbqkb1r/1p2pppp/p2p1n2/8/3NP3/2N5/PPP2PPP/R1BQKB1R w KQkq - 0 6", &.{"c1e3"});
    _ = try s.go(.{ .depth = 3 }, false, false);
    try between.at(s, "go after position fen moves");
    // go infinite, then stop, in a tablebase position; then a tablebase move.
    try s.fenPosition("8/8/8/4K3/Pk6/8/8/8 b - - 0 1", &.{});
    _ = try s.go(.{ .infinite = true }, true, false);
    try between.at(s, "go infinite, stop (tablebase position)");
    try s.fenPosition("8/5k2/8/8/3R4/8/5K2/8 w - - 0 1", &.{});
    _ = try s.go(.{ .depth = 4 }, false, false);
    try between.at(s, "go, a tablebase move");
}

const NoCheck = struct {
    fn at(_: NoCheck, _: *Session, _: []const u8) !void {}
};

test "stage B step 8, stage 6: the engine's commands make no image bracket during a game of every kind" {
    const gpa = std.testing.allocator;
    var s = try Session.init(gpa);
    defer s.deinit();
    s.e.reporting = true;
    const brackets0 = s.e.root.image_brackets;
    const checkpoints0 = s.e.root.checkpoints;
    try playEveryKind(&s, NoCheck{});
    const brackets = s.e.root.image_brackets - brackets0;
    const checkpoints = s.e.root.checkpoints - checkpoints0;
    std.debug.print("stage 6: a game of every kind: {d} image brackets, {d} checkpoints taken or restored, {d} positions continued, {d} rebuilt\n", .{ brackets, checkpoints, s.e.continued, s.e.rebuilt });
    try std.testing.expectEqual(@as(u64, 0), brackets);
    try std.testing.expect(checkpoints >= s.e.rebuilt);
    try std.testing.expect(s.e.continued >= 8 and s.e.rebuilt >= 10);
}

/// Pages the process may not touch: the image and the far segment moved there for the test
/// below, so that a read or a write of either faults.
const Guard = struct {
    const kernel32 = struct {
        extern "kernel32" fn VirtualAlloc(addr: ?*anyopaque, size: usize, kind: u32, protect: u32) callconv(.winapi) ?*anyopaque;
        extern "kernel32" fn VirtualProtect(addr: *anyopaque, size: usize, protect: u32, old: *u32) callconv(.winapi) i32;
        extern "kernel32" fn VirtualFree(addr: *anyopaque, size: usize, kind: u32) callconv(.winapi) i32;
    };
    const mem_commit = 0x1000;
    const mem_reserve = 0x2000;
    const mem_release = 0x8000;
    const page_noaccess = 0x01;
    const page_readwrite = 0x04;
    const size = 2 * 0x10000;

    base: [*]u8,

    fn init(image: *const dgroup.Image, far_segment: *const [0x10000]u8) !Guard {
        const p = kernel32.VirtualAlloc(null, size, mem_commit | mem_reserve, page_readwrite) orelse return error.OutOfMemory;
        const g: Guard = .{ .base = @ptrCast(p) };
        @memcpy(g.base[0..0x10000], image);
        @memcpy(g.base[0x10000..size], far_segment);
        return g;
    }
    fn img(g: Guard) *dgroup.Image {
        return g.base[0..0x10000];
    }
    fn far(g: Guard) *[0x10000]u8 {
        return g.base[0x10000..size];
    }
    fn protect(g: Guard, on: bool) void {
        var old: u32 = 0;
        _ = kernel32.VirtualProtect(@ptrCast(g.base), size, if (on) page_noaccess else page_readwrite, &old);
    }
    fn deinit(g: Guard) void {
        _ = kernel32.VirtualFree(@ptrCast(g.base), 0, mem_release);
    }
};

// Stage B step 8, stage 7: every variable the engine reads or writes has a member for its
// home, and the checkpoints are values; so a game of every kind of command neither reads nor
// writes the 64 KB image or the far segment. Proved by moving both to pages with no access
// before the game: any read or write of either, by any routine, faults and ends the test
// process. The image check (Debug, ReleaseSafe), which reads the image to compare it with
// what the last `enter` loaded, is switched off for the game (`image_guarded`); nothing else
// is. The bytes of both are compared with what they held before. (A byte or far offset no
// member holds is not counted since Stage B step 8, stage 8: `NodeEnv.dgPtr`,
// `checkpointPtr` and the record's offsets panic on one, so the game ending at all shows
// none was reached.) Since stage 8 the image and the far segment are the tests' alone
// (src/state_image.zig): the engine build has none.
test "stage B step 8, stage 7: a game of every kind of command neither reads nor writes the image or the far segment" {
    if (@import("builtin").os.tag != .windows) return error.SkipZigTest;
    const gpa = std.testing.allocator;
    var s = try Session.init(gpa);
    defer s.deinit();
    s.e.reporting = true;
    const root = s.e.root;
    const g = try Guard.init(root.test_img, root.test_far);
    defer g.deinit();
    const img0 = root.test_img;
    const far0 = root.test_far;
    root.test_img = g.img();
    root.test_far = g.far();
    root.node.codec.img = g.img();
    root.node.codec.image_guarded = true;
    g.protect(true);
    const brackets0 = root.image_brackets;
    const exits0 = root.node.codec.exits;
    playEveryKind(&s, NoCheck{}) catch |err| {
        g.protect(false);
        root.test_img = img0;
        root.test_far = far0;
        root.node.codec.img = img0;
        root.node.codec.image_guarded = false;
        return err;
    };
    g.protect(false);
    root.node.codec.image_guarded = false;
    // Nothing written: the guarded copies are the image and far segment as they were.
    try std.testing.expectEqualSlices(u8, img0, g.img());
    try std.testing.expectEqualSlices(u8, far0, g.far());
    root.test_img = img0;
    root.test_far = far0;
    root.node.codec.img = img0;
    try std.testing.expectEqual(brackets0, root.image_brackets);
    try std.testing.expectEqual(exits0, root.node.codec.exits);
    std.debug.print("stage 7: a game of every kind ({d} positions continued, {d} rebuilt) with the image and the far segment on pages with no access: no fault, no byte changed\n", .{ s.e.continued, s.e.rebuilt });
    try std.testing.expect(s.e.continued >= 8 and s.e.rebuilt >= 10);
}

test "stage B step 8, stage 6: the start-up checkpoint restored after a game gives the start-up image on every byte, the node's State and the game record included; and a game after ucinewgame is a fresh engine's" {
    const gpa = std.testing.allocator;
    var used = try Session.init(gpa);
    defer used.deinit();
    try playEveryKind(&used, NoCheck{});
    var fresh = try Session.init(gpa);
    defer fresh.deinit();
    // The checkpoint restored, as every rebuild begins, and made current in the image.
    used.e.resetToLoop();
    si.toImage(used.e.root);
    fresh.e.resetToLoop();
    si.toImage(fresh.e.root);
    var differ: usize = 0;
    for (used.e.root.test_img, fresh.e.root.test_img, 0..) |x, y, a| {
        if (x != y) {
            if (differ < 20) std.debug.print("stage 6: DG:{X:0>4}: after a game {X:0>2}, fresh {X:0>2}\n", .{ a, x, y });
            differ += 1;
        }
    }
    for (used.e.root.test_far, fresh.e.root.test_far, 0..) |x, y, a| {
        if (x != y) {
            if (differ < 20) std.debug.print("stage 6: 5A7B:{X:0>4}: after a game {X:0>2}, fresh {X:0>2}\n", .{ a, x, y });
            differ += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 0), differ);
    // Every byte some unit maps is among them (the image holds every member's after the
    // sync); the node's State by name: the killers and the hash sizing.
    const a = used.e.root.node_state;
    const b = fresh.e.root.node_state;
    try std.testing.expect(std.mem.eql(u8, std.mem.asBytes(&a.killer), std.mem.asBytes(&b.killer)));
    try std.testing.expectEqual(b.hash_mask, a.hash_mask);
    try std.testing.expectEqual(b.hash_size_mode, a.hash_size_mode);
    try std.testing.expectEqual(b.hash_enabled, a.hash_enabled);
    try std.testing.expectEqual(b.conv_mask, a.conv_mask);
    try std.testing.expect(std.mem.eql(u8, std.mem.asBytes(used.e.root.rec), std.mem.asBytes(fresh.e.root.rec)));
    var mapped: usize = 0;
    for (0..dgroup.size) |x| {
        if (ert.mappedByAUnit(x)) mapped += 1;
    }
    std.debug.print("stage 6: the start-up checkpoint after a game: every byte of DGROUP ({d} mapped by a unit) and of the far segment equal to a fresh engine's\n", .{mapped});
    // A game after `ucinewgame` (the options changed and set back) against a fresh engine:
    // every line but its time and nps, every bestmove and ponder move.
    used.newGame();
    used.options(.{ .hash_mb = 8, .own_book = true, .seed = 99 });
    used.options(.{});
    used.log.clearRetainingCapacity();
    const fallback = [_][]const u8{ "e7e5", "d7d5", "g8f6", "b8c6", "e7e6", "c7c5" };
    for ([_]*Session{ &used, &fresh }) |s| {
        try s.startpos(0);
        var k: usize = 0;
        while (k < 6) : (k += 1) {
            _ = try s.go(.{ .depth = 4 }, false, true);
            try s.reply(&fallback);
        }
    }
    try std.testing.expectEqualStrings(fresh.log.items, used.log.items);
}

/// The copies the engine's commands may leave stale (measured by the test below), each out
/// of every reader's reach: the set of src/engine_root_domain_test.zig `unread_copies`
/// (stage 4), the copies the stage 5 note lists, which the search and its preparation
/// leave (docs/arch/60-engine-assembly.md sections 10.7.12 and 10.7.13), and one more that
/// this stage measured: `ThreatVars.black_rays_after[83]` over DG:A22F (Black's king file,
/// `Position.king_file[1]`), stale after play_best_move. `black_rays_after` (DG:A1DC, 136
/// bytes) is read only by `evalthreats` `kingRayAt`, at a captured piece's entry less 120,
/// and a captured piece's entry is its square + 63h, 78h..C5h (DEV-022): index 77 (DG:A229)
/// at most. So the whole tail from A22A is out of reach (A22C, the easy-move flag, is
/// `ThreatVars`' own and never a copy).
const unread_copies = [_]struct { m: est.Member, lo: u16, hi: u16 }{
    .{ .m = .s, .lo = 0xA03A, .hi = 0xA059 }, // `Scratch.attackers` over the piece lists
    .{ .m = .s, .lo = 0xA000, .hi = 0xA001 }, // over the root's game ply
    .{ .m = .s, .lo = 0xA05A, .hi = 0xA05B }, // over the root's material balance
    .{ .m = .lv, .lo = 0x9E96, .hi = 0x9F3D }, // `LeafVars.key_history` past its room
    .{ .m = .tv, .lo = 0x9FC8, .hi = 0x9FC9 }, // `ThreatVars.board_after` at the game ply
    .{ .m = .p, .lo = 0x369A, .hi = 0x369B }, // `Position.quiet_move_by_ply` over 369A
    .{ .m = .tv, .lo = 0xA22A, .hi = 0xA263 }, // `ThreatVars.black_rays_after` past index 77
    .{ .m = .ev, .lo = 0x9DC4, .hi = 0x9DD3 }, // `EvalVars.ply_flag[48..63]`
};

const StaleCheck = struct {
    gpa: std.mem.Allocator,
    buf: *[8192]Stale,
    /// Every stale copy seen, by member and address (bit set), and where each was first seen.
    seen: *[est.n_members][dgroup.size]bool,
    outside: *usize,
    points: *usize,

    fn record(c: StaleCheck, s: *Session, label: []const u8) !void {
        const n = try s.e.root.node.staleAliases(c.gpa, c.buf);
        try std.testing.expect(n <= c.buf.len);
        c.points.* += 1;
        for (c.buf[0..n]) |x| {
            const i = @backingInt(x.m);
            if (c.seen[i][x.addr]) continue;
            c.seen[i][x.addr] = true;
            const ok = for (unread_copies) |u| {
                if (x.m == u.m and x.addr >= u.lo and x.addr <= u.hi) break true;
            } else false;
            if (!ok) {
                c.outside.* += 1;
                std.debug.print("stage 6: a stale copy outside the pinned set, first at \"{s}\": {s} DG:{X:0>4}\n", .{ label, @tagName(x.m), x.addr });
            }
        }
    }
    fn at(c: StaleCheck, s: *Session, label: []const u8) !void {
        try c.record(s, label);
    }
    fn probe(ctx: *anyopaque, label: []const u8) void {
        const pair: *struct { c: StaleCheck, s: *Session } = @ptrCast(@alignCast(ctx));
        pair.c.record(pair.s, label) catch @panic("stage 6: staleAliases");
    }
};

test "stage B step 8, stage 6: the copies of bytes another member holds that the engine's commands leave stale, at every command and inside each go, are out of every reader's reach" {
    const gpa = std.testing.allocator;
    var s = try Session.init(gpa);
    defer s.deinit();
    const buf = try gpa.create([8192]Stale);
    defer gpa.destroy(buf);
    const seen = try gpa.create([est.n_members][dgroup.size]bool);
    defer gpa.destroy(seen);
    for (seen) |*row| row.* = @splat(false);
    var outside: usize = 0;
    var points: usize = 0;
    const c: StaleCheck = .{ .gpa = gpa, .buf = buf, .seen = seen, .outside = &outside, .points = &points };
    var pair: struct { c: StaleCheck, s: *Session } = .{ .c = c, .s = &s };
    s.e.probe = .{ .ctx = &pair, .call = StaleCheck.probe };
    try playEveryKind(&s, c);
    s.e.probe = null;
    // The set seen, as runs.
    var total: usize = 0;
    for (seen, 0..) |row, i| {
        var a: usize = 0;
        while (a < dgroup.size) {
            if (!row[a]) {
                a += 1;
                continue;
            }
            var z = a;
            while (z + 1 < dgroup.size and row[z + 1]) z += 1;
            std.debug.print("stage 6: stale at some point: {s} DG:{X:0>4}-{X:0>4}\n", .{ @tagName(@as(est.Member, @fromBackingInt(@intCast(i)))), a, z });
            total += z - a + 1;
            a = z + 1;
        }
    }
    std.debug.print("stage 6: {d} points measured; {d} copies stale at some point, {d} outside the pinned set\n", .{ points, total, outside });
    try std.testing.expectEqual(@as(usize, 0), outside);
}
