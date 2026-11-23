//! Whole searches with the "cd" tablebase set (owner decision 33; docs/arch/41-tablebases.md,
//! "The four-man tablebases"): every search of tests/golden/tb4.jsonl (the original with the
//! six shipped files and 60 of reference/tablebases/m80-cd in its TB folder, auto-play)
//! through the engine with pos.Fixes.original and its own cd set (src/tb_store.zig):
//! the move, the node entries, the makes and the line hash. A table play is one with no
//! node entry. Two routes: the set-up route (start-up with the cd set's signatures, Setup
//! mode with the scenario's FEN, Ctrl-A, then auto-play), and the UCI route (`position fen
//! <fen> moves <the moves before>`, `go depth N`) for the scenarios the oracle played with
//! no hash table kept between searches.

const std = @import("std");
const si = @import("state_image.zig");
const pos = @import("position.zig");
const fen = @import("fen.zig");
const setup = @import("setup.zig");
const newgame = @import("newgame.zig");
const ert_test = @import("engine_root_test.zig");
const as = @import("adapt_setup.zig");
const ast = @import("adapt_setup_test.zig");
const tb_store = @import("tb_store.zig");
const uci_engine = @import("uci_engine.zig");
const engine_mod = @import("engine.zig");

const R = ert_test.R;

fn headerSet(o: std.json.ObjectMap) []const u8 {
    return if (o.get("tbset")) |v| v.string else "shipped";
}

test "tb4: every search of tests/golden/tb4.jsonl through the set-up route with the engine's cd tablebase set" {
    const gpa = std.testing.allocator;
    const s = try R.init(gpa, ert_test.golden_slots);
    defer s.deinit();
    var store = tb_store.TbStore.init(gpa, .cd);
    defer store.deinit();
    s.tb_files = store.files();
    const jl = try ert_test.readGolden(gpa, "tb4.jsonl");
    defer gpa.free(jl);
    var lines = std.mem.splitScalar(u8, jl, '\n');
    var scenarios: u32 = 0;
    var ran: u32 = 0;
    var matched: u32 = 0;
    var table_plays: u32 = 0;
    var current_buf: [64]u8 = undefined;
    var current: []const u8 = "";
    while (lines.next()) |text| {
        if (text.len == 0) continue;
        const parsed = try std.json.parseFromSlice(std.json.Value, gpa, text, .{});
        defer parsed.deinit();
        const o = parsed.value.object;
        if (o.get("search") == null) {
            try std.testing.expectEqualStrings("cd", headerSet(o));
            try std.testing.expectEqualStrings("move", o.get("dev003").?.string);
            const name = o.get("scenario").?.string;
            @memcpy(current_buf[0..name.len], name);
            current = current_buf[0..name.len];
            const d = try ast.descriptionOf(o.get("fen").?.string);
            s.startUp(.{ .tb_signatures = &newgame.cd_tb_signatures }, .{}, .{}, @intCast(o.get("depth").?.integer));
            si.toImage(s); // start-up runs on the members (Stage B step 8, stage 4)
            try std.testing.expectEqual(@as(u16, 62), std.mem.readInt(u16, s.test_img[0x239A..][0..2], .little));
            try std.testing.expectEqual(setup.Legality.legal, as.enter(s, &d));
            try std.testing.expect(s.autoPlay());
            try std.testing.expect(s.failure == null);
            scenarios += 1;
            continue;
        }
        const search = o.get("search").?.integer;
        if (search > 1) {
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
        if (want.nodes == 0) table_plays += 1;
        var mb: [5]u8 = undefined;
        if (!ok or want.nodes != 0)
            std.debug.print("tb4: {s} search {d}: played {s} ({s}), nodes {d} ({d}), makes {d} ({d}), line {s}{s}{s}\n", .{ current, search, ert_test.moveText(out.best, &mb), want.played, out.nodes, want.nodes, out.makes, want.makes, if (v.line) "equal" else "differs", if (s.failure != null) "; " else "", s.failure orelse "" });
    }
    std.debug.print("tb4: set-up route, cd set: {d} scenarios, {d} searches, {d} equal on move, nodes, makes and line ({d} table plays, no node); {d} files decompressed\n", .{ scenarios, ran, matched, table_plays, store.loads });
    try std.testing.expectEqual(@as(u32, 44), scenarios);
    try std.testing.expectEqual(@as(u32, 122), ran);
    try std.testing.expectEqual(ran, matched);
    try std.testing.expectEqual(@as(u32, 106), table_plays);
}

/// Every search of the scenarios of tb4.jsonl in which the oracle kept no hash table from
/// one search to the next (`hash_kept` 0: a rebuild then gives the same search) through the
/// UCI route of an engine with the cd set: `position fen <fen> moves <moves before>`,
/// `go depth N`. Returns searches run and differing; counts the files decompressed inside a
/// probe (none: `setPosition` prepared them).
fn tb4ThroughUci(gpa: std.mem.Allocator) !struct { ran: u32, differ: u32, scenarios: u32, at_probe: u32, loads: u32, max_prepare_ms: u64 } {
    const E = engine_mod.EngineOf(pos.Fixes.original);
    const e = try gpa.create(E);
    defer gpa.destroy(e);
    e.* = try E.initSet(gpa, .cd);
    defer e.deinit();
    e.reporting = false;
    e.io = std.testing.io;
    const eng = e.engine();
    const jl = try ert_test.readGolden(gpa, "tb4.jsonl");
    defer gpa.free(jl);
    var lines = std.mem.splitScalar(u8, jl, '\n');
    var ran: u32 = 0;
    var differ: u32 = 0;
    var scenarios: u32 = 0;
    var start: fen.Description = undefined;
    var depth: u32 = 0;
    var played: [16]fen.UciMove = undefined;
    var n: usize = 0;
    var skip = true;
    var name_buf: [64]u8 = undefined;
    var name: []const u8 = "";
    while (lines.next()) |text| {
        if (text.len == 0) continue;
        const parsed = try std.json.parseFromSlice(std.json.Value, gpa, text, .{});
        defer parsed.deinit();
        const o = parsed.value.object;
        if (o.get("search") == null) {
            skip = o.get("hash_kept").?.integer != 0;
            if (skip) continue;
            const nm = o.get("scenario").?.string;
            @memcpy(name_buf[0..nm.len], nm);
            name = name_buf[0..nm.len];
            start = try ast.descriptionOf(o.get("fen").?.string);
            depth = @intCast(o.get("depth").?.integer);
            n = 0;
            scenarios += 1;
            continue;
        }
        if (skip) continue;
        const want = ert_test.expectedOf(parsed.value);
        if (eng.setPosition(&start, .setup, played[0..n])) |why| {
            std.debug.print("tb4 uci: {s}: position rejected: {s}\n", .{ name, why });
            return error.Rejected;
        }
        var sig: uci_engine.Signals = .{};
        const r = eng.search(&.{ .depth = depth }, &sig, .{ .ctx = null, .lineFn = struct {
            fn f(_: ?*anyopaque, _: []const u8) void {}
        }.f });
        const best = r.best orelse return error.NoMove;
        var mb: [5]u8 = undefined;
        const got = fen.formatMove(best, &mb);
        const line = e.root.lineHex();
        const ok = std.mem.eql(u8, got, want.played) and e.root.nodes == want.nodes and e.root.makes == want.makes and std.mem.eql(u8, &line, want.line);
        ran += 1;
        if (!ok) {
            differ += 1;
            std.debug.print("tb4 uci: {s} search {d}: played {s} ({s}), nodes {d} ({d}), makes {d} ({d}), line {s}\n", .{ name, o.get("search").?.integer, got, want.played, e.root.nodes, want.nodes, e.root.makes, want.makes, if (std.mem.eql(u8, &line, want.line)) "equal" else "differs" });
        }
        played[n] = try fen.parseMove(want.played);
        n += 1;
    }
    return .{ .ran = ran, .differ = differ, .scenarios = scenarios, .at_probe = e.tb_store.loads_at_probe, .loads = e.tb_store.loads, .max_prepare_ms = e.tb_store.max_prepare_ns / std.time.ns_per_ms };
}

test "tb4: the searches of tests/golden/tb4.jsonl through position fen ... moves and go depth N with the cd set; every file prepared at the position command" {
    const gpa = std.testing.allocator;
    const r = try tb4ThroughUci(gpa);
    std.debug.print("tb4 uci: {d} scenarios, {d} searches, {d} differ; {d} files decompressed, {d} of them inside a probe; the longest prepare {d} ms\n", .{ r.scenarios, r.ran, r.differ, r.loads, r.at_probe, r.max_prepare_ms });
    try std.testing.expect(r.ran >= 60);
    try std.testing.expectEqual(@as(u32, 0), r.differ);
    try std.testing.expectEqual(@as(u32, 0), r.at_probe);
}

test "tb4: the shipped engine's set leaves the four-man positions to the search; the cd set plays them from the files" {
    const gpa = std.testing.allocator;
    const E = engine_mod.EngineOf(pos.Fixes.original);
    inline for (.{ tb_store.TbSet.shipped, tb_store.TbSet.cd }) |set| {
        const e = try gpa.create(E);
        defer gpa.destroy(e);
        e.* = try E.initSet(gpa, set);
        defer e.deinit();
        e.reporting = false;
        // DG:239A at its home (`ProgramVars`, Stage B step 8, stage 7).
        try std.testing.expectEqual(@as(u16, if (set == .cd) 62 else 6), @import("dgroup.zig").memWord(e.root.home(), 0x239A));
        const eng = e.engine();
        const d = try fen.parse("8/8/8/3k4/8/8/2r5/K3Q3 w - - 0 1"); // KQKR
        try std.testing.expect(eng.setPosition(&d, .setup, &.{}) == null);
        var sig: uci_engine.Signals = .{};
        const r = eng.search(&.{ .depth = 3 }, &sig, .{ .ctx = null, .lineFn = struct {
            fn f(_: ?*anyopaque, _: []const u8) void {}
        }.f });
        try std.testing.expect(r.best != null);
        if (set == .cd) {
            try std.testing.expectEqual(@as(u64, 0), e.root.nodes);
            var mb: [5]u8 = undefined;
            try std.testing.expectEqualStrings("e1d1", fen.formatMove(r.best.?, &mb));
        } else try std.testing.expect(e.root.nodes > 0);
    }
}

test "tb4: the signature table with the cd set: a probe away from the root reads all 62 words (the fault of six copied, 2B9F:BBD1 with [239A] = 62)" {
    // The search's own probes (root_search 0000:260A at ply 1, the nodes) need [239C] >= 0Bh
    // ("Dynamic tablebases", off as shipped and in the engine; the node's probe is not even
    // bound: src/engine_state.zig). The root's probe binding (engine_root `tbProbeDomain`, the
    // one main and root_search reach through `dispatchPrep`) is called here at ply 1, so that
    // the signature test runs with the cd set's 62 signatures: before the table was sized
    // from [239A] it read 62 words of a six-word copy (out of bounds: a safety panic in Debug
    // and ReleaseSafe). The result must be the probe's own with the whole table.
    const gpa = std.testing.allocator;
    const tablebase = @import("tablebase.zig");
    const PositionMap = @import("adapt_position.zig").PositionMap;
    const s = try R.init(gpa, ert_test.golden_slots);
    defer s.deinit();
    var store = tb_store.TbStore.init(gpa, .cd);
    defer store.deinit();
    s.tb_files = store.files();
    // KRKP, either side to move: the signatures 1140h and 4011h are words 29 and 61 of the
    // table, past the sixth.
    for ([_][]const u8{ "8/8/8/8/3k4/3p4/3K4/7R w", "8/8/8/8/3k4/3p4/3K4/7R b" }) |text| {
        const d = try ast.descriptionOf(text);
        s.startUp(.{ .tb_signatures = &newgame.cd_tb_signatures }, .{}, .{}, 3);
        try std.testing.expectEqual(setup.Legality.legal, as.enter(s, &d));
        // Until Stage B step 8, stage 8, on the image, outside the domain, through Stage A's
        // binding (engine_root `tbProbe`); since then the engine has only the binding on the
        // members (`tbProbeDomain`, which reads [239C] in the node's `State` and the
        // signatures in `ProgramVars`), called here. The setting is written at its home,
        // the image made current (src/state_image.zig) for the probe's own inputs.
        s.home().set(0x239C, 0x0E);
        si.toImage(s);
        const side: u16 = if (text[text.len - 1] == 'w') 0 else 1;
        // The probe with the whole table, on the same position and state.
        var p: pos.Position = .{};
        PositionMap.load(&p, s.test_img);
        var st: tablebase.State = .{
            .signature_count = 62,
            .signatures = &newgame.cd_tb_signatures,
            .mode = 0x0E,
            .program_side = s.test_img[0x8DDE],
            .score_bound = @bitCast(std.mem.readInt(u16, s.test_img[0xAFC4..][0..2], .little)),
            .score = @bitCast(std.mem.readInt(u16, s.test_img[0x7466..][0..2], .little)),
        };
        const want = tablebase.probe(tablebase.Fixes.corrected, &p, &st, store.files(), @intCast(side), 1, 0);
        const got = s.dispatchPrep(0x260A, .tb_probe, &.{ side, 1 });
        std.debug.print("tb4: {s}: the probe at ply 1 with 62 signatures: AX {d}, score {d}\n", .{ text, got, st.score });
        try std.testing.expect(want);
        try std.testing.expectEqual(@as(u32, 1), got);
        si.toImage(s);
        try std.testing.expectEqual(st.score, @as(i16, @bitCast(std.mem.readInt(u16, s.test_img[0x7466..][0..2], .little))));
    }
}

test "tb4: DEV-029's bound holds with the cd set: no position the root can probe has more than three men besides a king" {
    // The root probes positions of five men or fewer ([154A] < 6, 0000:0F7D), so a side has
    // at most four men with its king: the probe's lists hold them (tablebase.max_men_per_side).
    // A five-man position with four on one side names a file no set holds; the probe reads
    // nothing.
    const gpa = std.testing.allocator;
    var store = tb_store.TbStore.init(gpa, .cd);
    defer store.deinit();
    const tablebase = @import("tablebase.zig");
    var p: pos.Position = .{};
    for (&p.board, 0..) |*b, sq| b.* = if (sq % 10 == 0 or sq % 10 == 9 or sq < 21 or sq > 98) pos.border else pos.empty;
    p.board[25] = pos.white_king;
    p.board[24] = pos.white_queen;
    p.board[21] = pos.white_rook;
    p.board[23] = pos.white_bishop;
    p.board[95] = pos.black_king;
    p.piece_list[7] = 25;
    p.piece_list[16 + 7] = 95;
    var st: tablebase.State = .{ .mode = 0x0A };
    const l = tablebase.locate(&p, &st, 1, 0).?;
    try std.testing.expectEqualStrings("KQRBK.TBB", l.name());
    try std.testing.expect(!tablebase.probe(tablebase.Fixes.corrected, &p, &st, store.files(), 1, 0, 0));
    try std.testing.expectEqual(@as(u32, 0), store.loads);
}
