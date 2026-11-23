//! The UCI options that select the original's own settings (docs/UCI.md, "Options"):
//!
//! - `Use Tablebases` (owner decision 22): off is the original with its Tablebases dialog's
//!   "Use tablebases" box unticked (DG:239C 0Ah -> 02h); an infinite search (`go infinite`,
//!   and a `go` with no limit) never uses them, whatever the option. Proved against
//!   tests/golden/tboff.jsonl (the original with the box unticked) both ways, and against
//!   the engine with the files unbound.
//! - `Book` (owner decision 23): the Book menu's Standard, Tournament and Variety
//!   (DG:A6A0 bits 5 and 2), proved against tests/golden/book2.jsonl in
//!   src/engine_book_test.zig; here, that the option changes the draw for a fixed seed.

const std = @import("std");
const si = @import("state_image.zig");
const builtin = @import("builtin");
const fen = @import("fen.zig");
const pos = @import("position.zig");
const uci_engine = @import("uci_engine.zig");
const engine_mod = @import("engine.zig");
const ert_test = @import("engine_root_test.zig");

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

const How = enum {
    /// `Use Tablebases` false, `go depth N`.
    option_off,
    /// `Use Tablebases` true (the default), `go infinite depth N`.
    infinite,
    /// `Use Tablebases` true, `go depth N`, the files unbound from the root.
    unbound,
    /// The default: `Use Tablebases` true, `go depth N`.
    default,
};

const Searched = struct { played: [5]u8 = undefined, nodes: u64 = 0, makes: u64 = 0, line: [64]u8 = undefined };

/// Every search of the named scenarios of a golden file of auto-play searches from a FEN
/// (tboff.jsonl, corpus2.jsonl), each as `position fen <fen> moves <the moves before it>`
/// and a `go` as `how` says; compared on the move, node entries, makes and line hash.
/// Returns the number run and the number that differ; `got` receives each search.
fn replay(gpa: std.mem.Allocator, file: []const u8, scenario: []const u8, how: How, got: []Searched) !struct { ran: u32, differ: u32 } {
    const e = try gpa.create(E);
    defer gpa.destroy(e);
    e.* = try E.init(gpa);
    defer e.deinit();
    var o: uci_engine.Options = .{};
    if (how == .option_off) o.use_tablebases = false;
    e.engine().applyOptions(&o);
    if (how == .unbound) e.root.tb_files = null;
    const eng = e.engine();
    const jl = try ert_test.readGolden(gpa, file);
    defer gpa.free(jl);
    var ran: u32 = 0;
    var differ: u32 = 0;
    var lines = std.mem.splitScalar(u8, jl, '\n');
    var start: fen.Description = undefined;
    var depth: u32 = 0;
    var played: [16]fen.UciMove = undefined;
    var n: usize = 0;
    while (lines.next()) |text| {
        if (text.len == 0) continue;
        const parsed = try std.json.parseFromSlice(std.json.Value, gpa, text, .{});
        defer parsed.deinit();
        const obj = parsed.value.object;
        if (!std.mem.eql(u8, obj.get("scenario").?.string, scenario)) continue;
        if (obj.get("search") == null) {
            start = try fen.parse(obj.get("fen").?.string);
            start.castling = @import("adapt_setup.zig").rightsFromBoard(&start.board);
            depth = @intCast(obj.get("depth").?.integer);
            continue;
        }
        const want = ert_test.expectedOf(parsed.value);
        if (eng.setPosition(&start, .setup, played[0..n])) |why| {
            std.debug.print("options: {s}: position rejected: {s}\n", .{ scenario, why });
            return error.Rejected;
        }
        var cap: Capture = .{};
        var sig: uci_engine.Signals = .{};
        const limits: uci_engine.Limits = .{ .depth = depth, .infinite = how == .infinite };
        const r = eng.search(&limits, &sig, cap.out());
        // The setting is restored after an infinite search.
        const tb_word = @import("dgroup.zig").memWord(e.root.home(), 0x239C); // at its home, the node's `State`
        if (tb_word != if (how == .option_off) @as(u16, 0x02) else 0x0A) return error.TbSettingNotRestored;
        const best = r.best orelse return error.NoMove;
        var mb: [5]u8 = undefined;
        const mv = fen.formatMove(best, &mb);
        const line = e.root.lineHex();
        if (ran < got.len) {
            got[ran] = .{ .nodes = e.root.nodes, .makes = e.root.makes, .line = line };
            @memcpy(got[ran].played[0..mv.len], mv);
            if (mv.len < 5) got[ran].played[4] = 0;
        }
        const ok = std.mem.eql(u8, mv, want.played) and e.root.nodes == want.nodes and e.root.makes == want.makes and std.mem.eql(u8, &line, want.line);
        ran += 1;
        if (!ok) differ += 1;
        std.debug.print("options {s} ({s}): search {d}: played {s} ({s}), nodes {d} ({d}), makes {d} ({d}), line {s}\n", .{ scenario, @tagName(how), obj.get("search").?.integer, mv, want.played, e.root.nodes, want.nodes, e.root.makes, want.makes, if (std.mem.eql(u8, &line, want.line)) "equal" else "differs" });
        if (!ok) std.debug.print("{s}", .{cap.text()});
        played[n] = try fen.parseMove(want.played);
        n += 1;
    }
    return .{ .ran = ran, .differ = differ };
}

const tboff_scenarios = [_][]const u8{ "krk-d4-tboff", "kqk-d4-tboff", "kpk-d4-tboff", "promotion-race-d5-tboff" };

/// Search 4 of krk-d4-tboff is the one search of tboff.jsonl in which the original kept
/// its main hash tables from the search before (the header's `hash_kept`: 1; docs/arch/
/// 33-root-preparation.md step 9: four reversible king and rook moves). Through `position
/// fen ... moves` it is a rebuild, which starts with empty tables (docs/UCI.md, "The
/// operator script"), so it differs there; the continuous replay below runs it.
const rebuild_differs = 1;

fn tboffThroughUci(how: How) !void {
    const gpa = std.testing.allocator;
    var ran: u32 = 0;
    var differ: u32 = 0;
    var got: [8]Searched = undefined;
    for (tboff_scenarios) |name| {
        const r = try replay(gpa, "tboff.jsonl", name, how, &got);
        ran += r.ran;
        differ += r.differ;
    }
    std.debug.print("options: {s}: {d} searches, {d} differ\n", .{ @tagName(how), ran, differ });
    try std.testing.expectEqual(@as(u32, 14), ran);
    try std.testing.expectEqual(@as(u32, rebuild_differs), differ);
}

test "options: Use Tablebases false: the searches of tests/golden/tboff.jsonl (the original with its tablebases off) through position fen ... moves and go depth N" {
    try tboffThroughUci(.option_off);
}

test "options: go infinite never uses the tablebases: tests/golden/tboff.jsonl with Use Tablebases true and go infinite depth N" {
    try tboffThroughUci(.infinite);
}

test "options: Use Tablebases false: tests/golden/tboff.jsonl replayed as the oracle played it (auto-play, the hash tables carried), every search equal" {
    const gpa = std.testing.allocator;
    const as = @import("adapt_setup_test.zig");
    const e = try gpa.create(E);
    defer gpa.destroy(e);
    e.* = try E.init(gpa);
    defer e.deinit();
    const s = e.root;
    const jl = try ert_test.readGolden(gpa, "tboff.jsonl");
    defer gpa.free(jl);
    var lines = std.mem.splitScalar(u8, jl, '\n');
    var ran: u32 = 0;
    var matched: u32 = 0;
    while (lines.next()) |text| {
        if (text.len == 0) continue;
        const parsed = try std.json.parseFromSlice(std.json.Value, gpa, text, .{});
        defer parsed.deinit();
        const o = parsed.value.object;
        if (o.get("search") == null) {
            // Start-up, the Tablebases dialog's "Use tablebases" unticked (what the option
            // writes), Setup mode with the FEN, Ctrl-A.
            const d = try as.descriptionOf(o.get("fen").?.string);
            s.startUp(.{}, .{}, .{}, @intCast(o.get("depth").?.integer));
            si.toImage(s); // start-up runs on the members (Stage B step 8, stage 4)
            var opts: uci_engine.Options = .{};
            opts.use_tablebases = false;
            s.saveState(e.loop_cp);
            e.engine().applyOptions(&opts);
            try std.testing.expectEqual(@as(i64, 2), o.get("tb_settings").?.integer);
            try std.testing.expectEqual(@as(u16, 2), @import("dgroup.zig").memWord(s.home(), 0x239C));
            try std.testing.expect(@import("adapt_setup.zig").enter(s, &d) == .legal);
            try std.testing.expect(s.autoPlay());
            continue;
        }
        if (o.get("search").?.integer > 1) {
            s.playMove();
            s.nextTurnAutoPlay();
        }
        const want = ert_test.expectedOf(parsed.value);
        s.failure = null;
        const out = s.search(.own);
        ran += 1;
        const v = ert_test.verdictOf(s, out, want);
        const ok = ert_test.allEqual(v) and s.failure == null;
        if (ok) matched += 1;
        var mb: [5]u8 = undefined;
        std.debug.print("options: tboff {s} search {d} continued: played {s} ({s}), nodes {d} ({d}), makes {d} ({d}), line {s}\n", .{ o.get("scenario").?.string, o.get("search").?.integer, ert_test.moveText(out.best, &mb), want.played, out.nodes, want.nodes, out.makes, want.makes, if (v.line) "equal" else "differs" });
    }
    try std.testing.expectEqual(@as(u32, 14), ran);
    try std.testing.expectEqual(ran, matched);
}

test "options: the tablebase option off is the same search as the files unbound (every probe failing), on the positions of tboff.jsonl" {
    const gpa = std.testing.allocator;
    for (tboff_scenarios) |name| {
        var a: [8]Searched = undefined;
        var b: [8]Searched = undefined;
        const ra = try replay(gpa, "tboff.jsonl", name, .option_off, &a);
        const rb = try replay(gpa, "tboff.jsonl", name, .unbound, &b);
        try std.testing.expectEqual(ra.ran, rb.ran);
        for (a[0..ra.ran], b[0..rb.ran]) |x, y| {
            try std.testing.expectEqualSlices(u8, x.played[0..4], y.played[0..4]);
            try std.testing.expectEqual(x.nodes, y.nodes);
            try std.testing.expectEqual(x.makes, y.makes);
            try std.testing.expectEqualSlices(u8, &x.line, &y.line);
        }
    }
}

test "options: with Use Tablebases true and a go that is not infinite, the tablebases are used (corpus2.jsonl krk-d4)" {
    const gpa = std.testing.allocator;
    var got: [8]Searched = undefined;
    const r = try replay(gpa, "corpus2.jsonl", "krk-d4", .default, &got);
    try std.testing.expect(r.ran >= 3);
    try std.testing.expectEqual(@as(u32, 0), r.differ);
}

/// The book's first moves for the program Black after `opening` with `Seed` `seed`,
/// `OwnBook` on and `Book` `kind`, as `position startpos moves ...` and `go depth 1`.
fn bookReplies(gpa: std.mem.Allocator, kind: uci_engine.BookKind, seed: i32, opening: []const []const u8, out: [][5]u8) !void {
    const e = try gpa.create(E);
    defer gpa.destroy(e);
    e.* = try E.init(gpa);
    defer e.deinit();
    var o: uci_engine.Options = .{};
    o.own_book = true;
    o.book = kind;
    o.seed = seed;
    const eng = e.engine();
    eng.applyOptions(&o);
    const start = try fen.parse(fen.startpos);
    var game: [16]fen.UciMove = undefined;
    var n: usize = 0;
    for (opening, 0..) |m, i| {
        game[n] = try fen.parseMove(m);
        n += 1;
        try std.testing.expect(eng.setPosition(&start, .new_game, game[0..n]) == null);
        var cap: Capture = .{};
        var sig: uci_engine.Signals = .{};
        const r = eng.search(&.{ .depth = 1 }, &sig, cap.out());
        const best = r.best orelse return error.NoMove;
        try std.testing.expect(std.mem.indexOf(u8, cap.text(), "info string book move") != null);
        var mb: [5]u8 = undefined;
        const t = fen.formatMove(best, &mb);
        out[i] = @splat(0);
        @memcpy(out[i][0..t.len], t);
        game[n] = best;
        n += 1;
    }
}

test "options: Book selects the original's draw: Variety plays a grade-1 move, Standard a grade-3 move beside grade 6, where Tournament cannot (docs/arch/40-opening-book.md section 6)" {
    const gpa = std.testing.allocator;
    var got: [2][5]u8 = undefined;
    // Seed 15, 1.e4 c5 2.Nf3: the variety book plays 2...Nc6 (grade 1, which only it plays).
    try bookReplies(gpa, .variety, 15, &.{ "e2e4", "g1f3" }, &got);
    try std.testing.expectEqualStrings("c7c5", std.mem.sliceTo(&got[0], 0));
    try std.testing.expectEqualStrings("b8c6", std.mem.sliceTo(&got[1], 0));
    var t: [2][5]u8 = undefined;
    try bookReplies(gpa, .tournament, 15, &.{ "e2e4", "g1f3" }, &t);
    try std.testing.expect(!std.mem.eql(u8, &t[0], &got[0]) or !std.mem.eql(u8, &t[1], &got[1]));
    // Seed 46, 1.e4 e5 2.Nf3: the standard book plays 2...Nf6 (grade 3 beside grade 6).
    try bookReplies(gpa, .standard, 46, &.{ "e2e4", "g1f3" }, &got);
    try std.testing.expectEqualStrings("e7e5", std.mem.sliceTo(&got[0], 0));
    try std.testing.expectEqualStrings("g8f6", std.mem.sliceTo(&got[1], 0));
    try bookReplies(gpa, .tournament, 46, &.{ "e2e4", "g1f3" }, &t);
    try std.testing.expect(!std.mem.eql(u8, &t[1], &got[1]) or !std.mem.eql(u8, &t[0], &got[0]));
}

test "options: Book writes DG:A6A0 and DG:9EB6 as the Book menu does, and the default leaves the start-up image unchanged" {
    const gpa = std.testing.allocator;
    const e = try gpa.create(E);
    defer gpa.destroy(e);
    e.* = try E.init(gpa);
    defer e.deinit();
    // The start-up checkpoint is taken in the members (Stage B step 8, stage 7): the image
    // is made current before it is read.
    si.toImage(e.root);
    const before = std.mem.readInt(u16, e.root.test_img[0xA6A0..][0..2], .little);
    const tb_before = std.mem.readInt(u16, e.root.test_img[0x239C..][0..2], .little);
    try std.testing.expectEqual(@as(u16, 0x0063), before);
    try std.testing.expectEqual(@as(u16, 0x000A), tb_before);
    const eng = e.engine();
    var o: uci_engine.Options = .{};
    eng.applyOptions(&o);
    si.toImage(e.root); // the members stored: the image is read through the codec
    try std.testing.expectEqual(before, std.mem.readInt(u16, e.root.test_img[0xA6A0..][0..2], .little));
    try std.testing.expectEqual(tb_before, std.mem.readInt(u16, e.root.test_img[0x239C..][0..2], .little));
    o.book = .standard;
    eng.applyOptions(&o);
    try std.testing.expectEqual(@as(u16, 0x0043), @import("dgroup.zig").memWord(e.root.checkpointHome(e.loop_cp), 0xA6A0));
    o.book = .variety;
    eng.applyOptions(&o);
    si.toImage(e.root);
    try std.testing.expectEqual(@as(u16, 0x0047), std.mem.readInt(u16, e.root.test_img[0xA6A0..][0..2], .little));
    try std.testing.expectEqual(@as(u8, 0x47), e.root.test_img[0x9EB6]);
    o.use_tablebases = false;
    eng.applyOptions(&o);
    try std.testing.expectEqual(@as(u16, 0x0002), @import("dgroup.zig").memWord(e.root.checkpointHome(e.loop_cp), 0x239C));
}

const PvLines = struct {
    buf: [1 << 15]u8 = undefined,
    len: usize = 0,
    fn lineFn(ctx: ?*anyopaque, l: []const u8) void {
        const c: *PvLines = @ptrCast(@alignCast(ctx.?));
        if (!std.mem.startsWith(u8, l, "info depth") or std.mem.indexOf(u8, l, " pv ") == null) return;
        if (c.len + l.len + 1 > c.buf.len) return;
        @memcpy(c.buf[c.len..][0..l.len], l);
        c.len += l.len;
        c.buf[c.len] = '\n';
        c.len += 1;
    }
};

test "options: the PV sent is cut at its first illegal move (AGENTS.md 9.3 item 4): self-play with the held games continued, illegal tails of the original's PV array cut, every pv line legal; a checkmated program answers no move" {
    const gpa = std.testing.allocator;
    // The game is played by the original's logic (every class C fix off), which the golden
    // tests pin: the PV cut and the no-move answer are the shell's, the same under any fixes,
    // and a game played by the corrected engine changes whenever a fix is added.
    const OriginalEngine = engine_mod.EngineOf(pos.Fixes.original);
    var es: [2]*OriginalEngine = undefined;
    for (&es) |*p| {
        p.* = try gpa.create(OriginalEngine);
        p.*.* = try OriginalEngine.init(gpa);
    }
    defer for (es) |p| {
        p.deinit();
        gpa.destroy(p);
    };
    const start = try fen.parse(fen.startpos);
    var g: [200]fen.UciMove = undefined;
    var n: usize = 0;
    var cuts: u32 = 0;
    var lines: u32 = 0;
    var mated = false;
    while (n < g.len - 2) {
        const e = es[n % 2];
        const eng = e.engine();
        try std.testing.expect(eng.setPosition(&start, .new_game, g[0..n]) == null);
        var sig: uci_engine.Signals = .{};
        var cap: PvLines = .{};
        const r = eng.search(&.{ .nodes = 30000 }, &sig, .{ .ctx = &cap, .lineFn = PvLines.lineFn });
        cuts += e.pv_cuts;
        if (e.pv_cuts > 0) {
            const fc = e.first_cut.?;
            std.debug.print("options: pv cut at ply {d}: {d} of {d} moves kept\n", .{ n, fc.kept, fc.len });
        }
        // Every pv line printed is legal from the root, move by move.
        var it = std.mem.splitScalar(u8, cap.buf[0..cap.len], '\n');
        while (it.next()) |l| {
            if (l.len == 0) continue;
            lines += 1;
            const at = std.mem.indexOf(u8, l, " pv ").?;
            var words: [40]u16 = undefined;
            var k: usize = 0;
            var first_flag: u8 = 0;
            var mt = std.mem.tokenizeScalar(u8, l[at + 4 ..], ' ');
            while (mt.next()) |t| : (k += 1) {
                const m = try fen.parseMove(t);
                if (k == 0) first_flag = m.promotion;
                words[k] = @as(u16, m.from) | @as(u16, m.to) << 8;
            }
            try std.testing.expectEqual(k, e.pv_check.legalPrefix(pos.Fixes.original, words[0..k], first_flag));
        }
        const b = r.best orelse {
            mated = true;
            break;
        };
        g[n] = b;
        n += 1;
    }
    std.debug.print("options: self-play: {d} plies, {d} pv lines, {d} cut, game over: {}\n", .{ n, lines, cuts, mated });
    try std.testing.expect(cuts >= 1);
    try std.testing.expect(mated);
}
