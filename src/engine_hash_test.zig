//! The UCI option `Hash` (owner decision 24; docs/UCI.md, "Hash"): N MB is N x 1,024 KB
//! typed into the original's Settings / Hash-tables dialog (38C0:4C36-4CE6), applied when
//! the option is set (src/engine.zig `setHash`). Proved against tests/golden/hash.jsonl,
//! the original with 1,024, 8,192, 32,768, 49,152 and 61,440 KB typed into that dialog
//! (docs/arch/35-hash-sizing.md section 4.2; tools/oracle/README.md):
//!
//! - every auto-play search, continued as the oracle played it (the tables carried from
//!   search to search where the original carried them), and each through `position
//!   startpos moves ...` and `go depth N` (a rebuild);
//! - the normal-play game at 1 MB, continued move by move as a GUI sends it;
//! - the size, mask and 3/4 mode each value of the option gives, against src/hashsize.zig
//!   `menu` and the headers' `hash_in_use`; the default changes nothing.

const std = @import("std");
const si = @import("state_image.zig");
const fen = @import("fen.zig");
const pos = @import("position.zig");
const uci_engine = @import("uci_engine.zig");
const engine_mod = @import("engine.zig");
const engine_root = @import("engine_root.zig");
const hashsize = @import("hashsize.zig");
const ert_test = @import("engine_root_test.zig");
const rp = @import("rootprep.zig");
const dgroup = @import("dgroup.zig");

const E = engine_mod.EngineOf(pos.Fixes.original); // the golden files record DEV-001 uncorrected

const Capture = struct {
    buf: [1 << 14]u8 = undefined,
    len: usize = 0,
    fn lineFn(ctx: ?*anyopaque, line: []const u8) void {
        const c: *Capture = @ptrCast(@alignCast(ctx.?));
        if (c.len + line.len + 1 > c.buf.len) c.len = 0;
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

fn newEngine(gpa: std.mem.Allocator, mb: u32) !*E {
    const e = try gpa.create(E);
    errdefer gpa.destroy(e);
    e.* = try E.init(gpa);
    var o: uci_engine.Options = .{};
    o.hash_mb = mb;
    e.engine().applyOptions(&o);
    return e;
}

fn freeEngine(gpa: std.mem.Allocator, e: *E) void {
    e.deinit();
    gpa.destroy(e);
}

fn word(img: []const u8, a: usize) u16 {
    return std.mem.readInt(u16, img[a..][0..2], .little);
}
fn dword(img: []const u8, a: usize) u32 {
    return std.mem.readInt(u32, img[a..][0..4], .little);
}

/// The size in use the scenario's header reports (main's first resize: 0000:0818), against
/// what the engine's image holds after its own resize before the search.
fn checkInUse(h: std.json.ObjectMap, m: anytype) !void {
    // At each variable's home (`EngineRoot.Home`: the mask and mode the node's `State`'s, the
    // sizes the image's), which reads nothing into the image (Stage B step 8, stage 6).
    const u = h.get("hash_in_use").?.object;
    try std.testing.expectEqual(u.get("size_kb").?.integer, @as(i64, dgroup.memDword(m, 0x12C6)));
    try std.testing.expectEqual(u.get("mask").?.integer, @as(i64, dgroup.memDword(m, 0xB624)));
    try std.testing.expectEqual(u.get("mode").?.integer, @as(i64, m.get(0x9316)));
    try std.testing.expectEqual(u.get("total_kb").?.integer, @as(i64, dgroup.memDword(m, 0x12CA)));
    try std.testing.expectEqual(h.get("hash_kb").?.integer, 2 * @as(i64, dgroup.memDword(m, 0x12C6)));
}

const Totals = struct {
    ran: u32 = 0,
    equal: u32 = 0,
    /// Per search in file order: equal on all four values; the original kept its tables.
    ok: [32]bool = @splat(false),
    kept: [32]bool = @splat(false),
    header_kept: u32 = 0,
};

/// Every auto-play scenario of hash.jsonl: start-up with the dialog's size (`Hash` typed
/// kb / 1,024 MB), `position startpos moves <setup>` (the rebuild: auto-play of the moves,
/// the path of the golden corpora), then the program plays on in auto-play, the tables
/// carried. `uci`: each search instead as `position startpos moves <setup and the moves
/// before>` and `go depth N`.
fn autoPlay(gpa: std.mem.Allocator, uci: bool) !Totals {
    const jl = try ert_test.readGolden(gpa, "hash.jsonl");
    defer gpa.free(jl);
    var lines = std.mem.splitScalar(u8, jl, '\n');
    var t: Totals = .{};
    var e: ?*E = null;
    defer if (e) |x| freeEngine(gpa, x);
    var header: ?std.json.Parsed(std.json.Value) = null;
    defer if (header) |h| h.deinit();
    const start = try fen.parse(fen.startpos);
    var game: [64]fen.UciMove = undefined;
    var n: usize = 0;
    var depth: u16 = 0;
    var skip = false;
    while (lines.next()) |text| {
        if (text.len == 0) continue;
        const parsed = try std.json.parseFromSlice(std.json.Value, gpa, text, .{});
        defer parsed.deinit();
        const o = parsed.value.object;
        if (o.get("search") == null) {
            if (header) |h| h.deinit();
            header = try std.json.parseFromSlice(std.json.Value, gpa, text, .{});
            const h = header.?.value.object;
            skip = h.get("mode") != null;
            if (skip) continue;
            t.header_kept += @intCast(h.get("hash_kept").?.integer);
            if (e) |x| freeEngine(gpa, x);
            const kb = h.get("hash_typed").?.integer;
            try std.testing.expectEqual(@as(i64, 0), @mod(kb, 1024));
            e = try newEngine(gpa, @intCast(@divExact(kb, 1024)));
            depth = @intCast(h.get("depth").?.integer);
            n = 0;
            for (h.get("setup").?.array.items) |m| {
                game[n] = try fen.parseMove(m.string);
                n += 1;
            }
            if (!uci) {
                const x = e.?;
                try std.testing.expect(x.engine().setPosition(&start, .new_game, game[0..n]) == null);
                // Auto-play on, the Fixed depth level (what the engine's `go depth` writes).
                x.root.home().set(0x9FCF, 1);
                x.root.home().set(0xA274, 3);
                dgroup.memSetWord(x.root.home(), 0x1E02, depth);
            }
            continue;
        }
        if (skip) continue;
        const x = e.?;
        const s = x.root;
        const k = o.get("search").?.integer;
        const want = ert_test.expectedOf(parsed.value);
        var played: [5]u8 = undefined;
        var mv: []const u8 = undefined;
        var line: [64]u8 = undefined;
        var nodes: u64 = 0;
        var makes: u64 = 0;
        if (uci) {
            const eng = x.engine();
            if (eng.setPosition(&start, .new_game, game[0..n])) |why| {
                std.debug.print("hash: position rejected: {s}\n", .{why});
                return error.Rejected;
            }
            var cap: Capture = .{};
            var sig: uci_engine.Signals = .{};
            const r = eng.search(&.{ .depth = depth }, &sig, cap.out());
            const best = r.best orelse return error.NoMove;
            mv = fen.formatMove(best, &played);
            // hashfull is a share of the slots in use.
            if (std.mem.indexOf(u8, cap.text(), " hashfull ") == null) return error.NoHashfull;
        } else {
            if (k > 1) {
                s.playMove();
                s.nextTurnAutoPlay();
            }
            s.failure = null;
            const clears = s.prep_calls[@backingInt(rp.Callee.hash_clear)];
            const out = s.search(.own);
            t.kept[t.ran] = s.prep_calls[@backingInt(rp.Callee.hash_clear)] == clears;
            if (s.failure) |f| std.debug.print("hash: failure: {s}\n", .{f});
            mv = ert_test.moveText(out.best, &played);
        }
        line = s.lineHex();
        nodes = s.nodes;
        makes = s.makes;
        if (k == 1) try checkInUse(header.?.value.object, s.home());
        const ok = std.mem.eql(u8, mv, want.played) and nodes == want.nodes and makes == want.makes and std.mem.eql(u8, &line, want.line);
        t.ok[t.ran] = ok;
        t.ran += 1;
        if (ok) t.equal += 1;
        std.debug.print("hash {s} ({s}): search {d}: played {s} ({s}), nodes {d} ({d}), makes {d} ({d}), line {s}; {d} slots in use\n", .{ o.get("scenario").?.string, if (uci) "uci" else "auto-play", k, mv, want.played, nodes, want.nodes, makes, want.makes, if (std.mem.eql(u8, &line, want.line)) "equal" else "differs", s.hashSlotsInUse() });
        game[n] = try fen.parseMove(want.played);
        n += 1;
    }
    return t;
}

test "hash: tests/golden/hash.jsonl auto-play as the oracle played it (the dialog's size typed through Hash, the tables carried), every search equal; and through setoption Hash, position startpos moves ... and go depth N, every search equal but those in which the original kept its tables" {
    if (@import("builtin").mode == .debug) return; // too long in Debug: run in ReleaseSafe or ReleaseFast // 2.9 million nodes, twice
    const gpa = std.testing.allocator;
    const a = try autoPlay(gpa, false);
    try std.testing.expectEqual(@as(u32, 20), a.ran);
    try std.testing.expectEqual(a.ran, a.equal);
    // The searches in which the original kept its tables (main 07C4: no resize, no clear)
    // are as many as the headers' hash_kept.
    var kept: u32 = 0;
    for (a.kept[0..a.ran]) |k| kept += @intFromBool(k);
    try std.testing.expectEqual(a.header_kept, kept);
    // A position that does not continue the held game is rebuilt with empty tables
    // (docs/UCI.md, "The operator script"), so those differ there; every other is equal.
    const u = try autoPlay(gpa, true);
    try std.testing.expectEqual(a.ran, u.ran);
    for (0..u.ran) |i| if (!a.kept[i]) try std.testing.expect(u.ok[i]);
    std.debug.print("hash: {d} auto-play searches equal; through UCI {d} equal, {d} after kept tables\n", .{ a.equal, u.equal, kept });
}

test "hash: the normal-play game of tests/golden/hash.jsonl at 1 MB, continued move by move as a GUI sends it" {
    if (@import("builtin").mode == .debug) return; // too long in Debug: run in ReleaseSafe or ReleaseFast
    const gpa = std.testing.allocator;
    const jl = try ert_test.readGolden(gpa, "hash.jsonl");
    defer gpa.free(jl);
    var lines = std.mem.splitScalar(u8, jl, '\n');
    var e: ?*E = null;
    defer if (e) |x| freeEngine(gpa, x);
    var header: ?std.json.Parsed(std.json.Value) = null;
    defer if (header) |h| h.deinit();
    const start = try fen.parse(fen.startpos);
    var game: [64]fen.UciMove = undefined;
    var game_len: usize = 0;
    var depth: u32 = 0;
    var ran: u32 = 0;
    var equal: u32 = 0;
    var active = false;
    while (lines.next()) |text| {
        if (text.len == 0) continue;
        const parsed = try std.json.parseFromSlice(std.json.Value, gpa, text, .{});
        defer parsed.deinit();
        const o = parsed.value.object;
        if (o.get("search") == null) {
            active = o.get("mode") != null;
            if (!active) continue;
            if (header) |h| h.deinit();
            header = try std.json.parseFromSlice(std.json.Value, gpa, text, .{});
            const h = header.?.value.object;
            try std.testing.expect(h.get("fen").? == .null);
            e = try newEngine(gpa, @intCast(@divExact(h.get("hash_typed").?.integer, 1024)));
            e.?.engine().newGame();
            depth = @intCast(h.get("depth").?.integer);
            for (h.get("game").?.array.items, 0..) |m, i| game[i] = try fen.parseMove(m.string);
            game_len = h.get("game").?.array.items.len;
            continue;
        }
        if (!active) continue;
        const x = e.?;
        const eng = x.engine();
        const k: usize = @intCast(o.get("search").?.integer);
        const want = ert_test.expectedOf(parsed.value);
        const n = 2 * k - 1;
        if (n > game_len) return error.GoldenTooShort;
        if (eng.setPosition(&start, .new_game, game[0..n])) |why| {
            std.debug.print("hash np: rejected: {s}\n", .{why});
            return error.Rejected;
        }
        var cap: Capture = .{};
        var sig: uci_engine.Signals = .{};
        const r = eng.search(&.{ .depth = depth }, &sig, cap.out());
        var mb: [5]u8 = undefined;
        const played = if (r.best) |b| fen.formatMove(b, &mb) else "none";
        const line = x.root.lineHex();
        const ok = std.mem.eql(u8, played, want.played) and x.root.nodes == want.nodes and x.root.makes == want.makes and std.mem.eql(u8, &line, want.line);
        if (k == 1) try checkInUse(header.?.value.object, x.root.home());
        ran += 1;
        if (ok) equal += 1;
        std.debug.print("hash np {s}: search {d}: played {s} ({s}), nodes {d} ({d}), makes {d} ({d}), line {s}\n", .{ o.get("scenario").?.string, k, played, want.played, x.root.nodes, want.nodes, x.root.makes, want.makes, if (std.mem.eql(u8, &line, want.line)) "equal" else "differs" });
    }
    try std.testing.expect(ran >= 6);
    try std.testing.expectEqual(ran, equal);
    // Every search after the first continued the held game (the tables carried).
    try std.testing.expectEqual(ran - 1, e.?.continued);
}

/// The engine's start-up checkpoint as an image (every byte a member holds; zeros elsewhere).
fn checkpointImage(gpa: std.mem.Allocator, e: *E) !*@import("dgroup.zig").Image {
    const img = try gpa.create(@import("dgroup.zig").Image);
    img.* = @splat(0);
    const far = try gpa.create([0x10000]u8);
    defer gpa.destroy(far);
    far.* = @splat(0);
    si.checkpointToImage(e.root, e.loop_cp, img, far);
    return img;
}

test "hash: each value of Hash gives the ladder's size, mask and mode as the dialog does (src/hashsize.zig menu), in the start-up image and the game held; the default types nothing" {
    const gpa = std.testing.allocator;
    const e = try newEngine(gpa, 60);
    defer freeEngine(gpa, e);
    // The default: the start-up image as at start-up (two tables of 30,720 KB).
    const fresh = try gpa.create(E);
    defer gpa.destroy(fresh);
    fresh.* = try E.init(gpa);
    defer fresh.deinit();
    // The images before any option is applied, and the default options with Hash 60. The
    // start-up checkpoint is taken in the members (Stage B step 8, stage 7): the image is
    // made current first.
    si.toImage(fresh.root);
    const before = try gpa.dupe(u8, fresh.root.test_img);
    defer gpa.free(before);
    fresh.engine().applyOptions(&.{});
    // The engine's commands run on the members (Stage B step 8, stage 6): the images are
    // made current before they are compared.
    si.toImage(fresh.root);
    si.toImage(e.root);
    try std.testing.expectEqual(@as(u32, 61440), dword(before, 0x12CA));
    for ([_]u16{ 0x12CA, 0x12C6, 0xB624, 0x005A }) |a| try std.testing.expectEqual(dword(before, a), dword(fresh.root.test_img, a));
    try std.testing.expectEqual(before[0x9316], fresh.root.test_img[0x9316]);
    // The start-up checkpoints (Stage B step 8, stage 7: members as values), as images.
    const fresh_cp = try checkpointImage(gpa, fresh);
    defer gpa.destroy(fresh_cp);
    var e_cp = try checkpointImage(gpa, e);
    try std.testing.expectEqualSlices(u8, fresh_cp, e_cp);
    gpa.destroy(e_cp);
    try std.testing.expectEqualSlices(u8, fresh.root.test_img, e.root.test_img);
    try std.testing.expectEqual(@as(u32, 3_145_728), e.root.hashSlotsInUse());
    var mb: u32 = 1;
    while (mb <= 60) : (mb += 1) {
        var o: uci_engine.Options = .{};
        o.hash_mb = mb;
        e.engine().applyOptions(&o);
        si.toImage(e.root);
        var model = hashsize.setup(64512);
        try std.testing.expect(hashsize.menu(&model, @intCast(mb * 1024)));
        e_cp = try checkpointImage(gpa, e);
        defer gpa.destroy(e_cp);
        for ([_][]const u8{ e_cp, e.root.test_img }) |img| {
            try std.testing.expectEqual(@as(u32, @bitCast(model.total_kb)), dword(img, 0x12CA));
            try std.testing.expectEqual(@as(u32, @bitCast(model.tables.size_kb)), dword(img, 0x12C6));
            try std.testing.expectEqual(model.tables.mask, dword(img, 0xB624));
            try std.testing.expectEqual(model.tables.mode, img[0x9316]);
            try std.testing.expectEqual(@as(u16, 1), word(img, 0xA3F8));
        }
        // The size in use is the rung at or below half the total.
        const half: i32 = @intCast(mb * 512);
        try std.testing.expect(model.tables.size_kb <= half);
        try std.testing.expectEqual(@as(u32, @intCast(model.tables.size_kb)) * 1024 / 10, e.root.hashSlotsInUse());
        try std.testing.expect(e.root.hashSlotsInUse() <= engine_mod.table_slots);
    }
    // Back to 60: the start-up tables again (the dialog's 61,440 KB is start-up's total).
    var o: uci_engine.Options = .{};
    e.engine().applyOptions(&o);
    e_cp = try checkpointImage(gpa, e);
    defer gpa.destroy(e_cp);
    for ([_]u16{ 0x12CA, 0x12C6, 0xB624, 0x9316, 0xA3F8, 0x005A }) |a| {
        try std.testing.expectEqual(dword(fresh_cp, a) & (if (a == 0x9316) @as(u32, 0xFF) else 0xFFFFFFFF), dword(e_cp, a) & (if (a == 0x9316) @as(u32, 0xFF) else 0xFFFFFFFF));
    }
    // The 3/4 mode at 30 to 39 MB (15,360 KB) and 60 MB (30,720 KB) only.
    for ([_]struct { u32, u32, u8 }{ .{ 1, 320, 0 }, .{ 8, 2560, 0 }, .{ 32, 15360, 1 }, .{ 48, 20480, 0 }, .{ 60, 30720, 1 } }) |c| {
        o.hash_mb = c[0];
        e.engine().applyOptions(&o);
        si.toImage(e.root);
        try std.testing.expectEqual(c[1], dword(e.root.test_img, 0x12C6));
        try std.testing.expectEqual(c[2], e.root.test_img[0x9316]);
    }
}
