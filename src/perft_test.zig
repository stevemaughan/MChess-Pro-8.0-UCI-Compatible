//! Perft of the original's move generation, against true perft (AGENTS.md section 11 item 5,
//! Phase 4 item 3).
//!
//! Expected counts: tests/golden/perft/perft.jsonl, made by tools/research/perft/
//! gen_perft.py with python-chess 1.11.2, an independent implementation, itself checked
//! there against the published perft of the start position (depth 5) and Kiwipete
//! (depth 4).
//!
//! What is counted is what the engine accepts as a legal move. Each position is entered
//! through the engine's own set-up path (start-up, then Setup mode with the FEN, as
//! `position fen` takes it: `adapt_setup.enterFen`), and the search position is read from
//! the image. At every node the moves are those of the original's root and of
//! check_entered_move (38C0:5864): in check (the check byte of the ply non-zero),
//! gen_evasions (38C0:E260, `helpers.genEvasions`); otherwise gen_all_moves (1E9D:3938,
//! `movegen.genAllMoves`). A move counts when, after update_hash_key and make_move
//! (`Position.updateHashKey`, `Position.makeMove`), the mover's king is not attacked by
//! 2B9F:4B32 (`gamemove.kingAttacked`), the test check_entered_move and the engine's
//! `findLegal` (src/engine.zig) apply. The tree is walked with make_move and unmake_move
//! only, as the search walks it (update_castle_stamps, 38C0:0130, runs between game moves,
//! not in the tree). At depth 1 the moves are also counted the way `findLegal` takes the
//! moves of a `position ... moves` command: gen_all_moves even in check.
//!
//! The root pre-scoring tests a root move with the attack map instead (leaf_attack_map,
//! 2B9F:40A8 / 42DA, `[8FE4 + king]`, docs/arch/33-root-preparation.md step 17), which
//! marks no pawn attacks: at depth 1 its verdicts are compared with 2B9F:4B32's and must
//! agree. (With five men or fewer and the tablebases on, a root move the tablebase probe
//! answers skips that test; not looked at here.)
//!
//! After every unmake at the top two plies (every ply in Debug) the position must equal
//! the one before the make: board, piece lists, slot map, pawn-attack and king-ray maps,
//! counts, material, castling stamps, game ply, and the per-ply en-passant and check
//! bytes of the plies above; and the hash key's incremental update must agree with a key
//! computed from scratch (as a difference, since a set-up position's key need not equal
//! the scratch key: docs/arch/23-position-setup.md, suspected bug 2).
//!
//! Divergences from true perft are listed in `known` below, each with the counts the
//! original gives, so that the test passes with them and fails if one changes.
//!
//! The original's generation can equal true perft only where no node has more than 100
//! pseudo-legal moves: gen_all_moves keeps 100 of them (1E9D:48D8, DEV-063), so a count
//! below such a node falls short (at the root of the 218-move position of
//! tests/golden/manymoves.jsonl, 100 against 218). No node of these positions reaches a
//! full list; the test counts them and requires none.
//!
//! The second test compares the port's root move list (gen_all_moves, or gen_evasions in
//! check), in order and with its flags, with the original's for seven set-up positions
//! (castling through an attacked square, in check, promotions of every kind for both
//! colours, double check, pins on every line, a king step onto a pawn-attacked square):
//! tests/golden/perft/oracle_roots.jsonl, from the oracle's trace of the root pre-scoring
//! (tools/research/perft/oracle_roots.py).

const std = @import("std");
const si = @import("state_image.zig");
const builtin = @import("builtin");
const pos = @import("position.zig");
const mg = @import("movegen.zig");
const helpers = @import("helpers.zig");
const see_mod = @import("see.zig");
const gamemove = @import("gamemove.zig");
const fen = @import("fen.zig");
const as = @import("adapt_setup.zig");
const ap = @import("adapt_position.zig");
const ert_test = @import("engine_root_test.zig");
const setup = @import("setup.zig");
const leaf = @import("leaf.zig");

const Position = pos.Position;
const Side = pos.Side;
const Move = pos.Move;

const max_depth = 6;
const debug_restore = false;

/// How a node's moves are generated.
const Mode = enum {
    /// The root and check_entered_move: gen_evasions in check, else gen_all_moves.
    entry,
    /// The engine's `findLegal` for the moves of a `position` command: gen_all_moves.
    all_moves,
};

/// How a made move is judged legal.
const Legality = enum {
    /// 2B9F:4B32, `gamemove.kingAttacked`: check_entered_move and the engine's findLegal.
    king_attacked,
    /// The root pre-scoring's test (0000:09FE-0A2E, docs/arch/33-root-preparation.md step
    /// 17): the opponent's leaf attack map (2B9F:40A8 / 42DA) at the mover's king.
    attack_map,
};

const Walk = struct {
    p: Position = .{},
    s: see_mod.Scratch = .{},
    v: mg.SearchVars = .{},
    lists: [max_depth + 2]mg.MoveList = undefined,
    /// Legal moves found at each level below the root (index 0: depth 1).
    counts: [max_depth]u64 = @splat(0),
    /// Plies at which the restore check is made (1: the root's moves; 2: also theirs).
    check_plies: usize = 2,
    /// Nodes where the generator answered FFFFh (the side to move can take the king).
    king_captures: u64 = 0,
    /// Nodes whose list was full (100 moves: DEV-063's cap may have cut it).
    full_lists: u64 = 0,
    restore_failures: u64 = 0,
    key_failures: u64 = 0,
    first_failure: ?[]const u8 = null,
    /// DEV-050 corrected (`pos.Fixes.corrected`, the engine's setting): a rook captured
    /// on its corner takes the castling right away. False: the original's make_move.
    fix050: bool = false,

    fn generate(w: *Walk, side: Side, ply: usize, mode: Mode) []const Move {
        const list = &w.lists[ply];
        const n = if (mode == .entry and w.p.check_by_ply[ply] != 0)
            helpers.genEvasions(&w.p, &w.v, list, side, ply)
        else
            mg.genAllMoves(mg.Fixes.corrected, &w.p, &w.s, &w.v, list, side, ply, .{});
        if (n == mg.king_capture) {
            w.king_captures += 1;
            return list[0..0];
        }
        if (n >= mg.list_len) w.full_lists += 1;
        return list[0..n];
    }

    fn fail(w: *Walk, what: []const u8) void {
        if (w.first_failure == null) w.first_failure = what;
    }

    /// Counts the legal moves of the side to move, `depth` plies deep, at ply `ply`.
    fn perft(w: *Walk, side: Side, ply: usize, depth: usize, level: usize) void {
        const moves = w.generate(side, ply, .entry);
        for (moves) |mv| {
            const check = ply <= w.check_plies or builtin.mode == .debug;
            var before: Position = undefined;
            var scratch_diff: u48 = 0;
            if (check) {
                before = w.p;
                scratch_diff = w.p.hash_key ^ w.p.hashFromScratch().main;
            }
            const key = w.p.hash_key;
            const pawn_key = w.p.pawn_hash_key;
            w.p.updateHashKey(mv, pos.Fixes.corrected);
            var u: pos.Undo = .{};
            if (w.fix050) w.p.makeMoveFixes(mv, side, ply + 1, &u, pos.Fixes.corrected) else w.p.makeMove(mv, side, ply + 1, &u);
            // With DEV-001 corrected (the engine's setting); the original's key is wrong
            // after an en-passant capture (docs/DEVIATIONS.md, DEV-001).
            if (check and (w.p.hash_key ^ w.p.hashFromScratch().main) != scratch_diff) {
                w.key_failures += 1;
                w.fail("the incremental hash key differs from the key from scratch after a make");
            }
            if (gamemove.kingAttacked(&w.p, @backingInt(side)) == 0) {
                w.counts[level] += 1;
                if (depth > 1) w.perft(side.other(), ply + 1, depth - 1, level + 1);
            }
            if (w.fix050) w.p.unmakeMoveFixes(mv, side, &u, pos.Fixes.corrected) else w.p.unmakeMove(mv, side, &u);
            w.p.hash_key = key;
            w.p.pawn_hash_key = pawn_key;
            if (check and !restored(&before, &w.p, ply)) {
                w.restore_failures += 1;
                w.fail("the position after unmake differs from the one before the make");
                if (debug_restore) {
                    var b: [5]u8 = undefined;
                    std.debug.print("restore: after {s} at ply {d}\n", .{ uciText(mv, &b), ply });
                    for (0..120) |sq| {
                        if (before.board[sq] != w.p.board[sq]) std.debug.print("  board[{d}] {d} -> {d}\n", .{ sq, before.board[sq], w.p.board[sq] });
                        for (0..2) |c| {
                            if (before.king_rays[c][sq] != w.p.king_rays[c][sq]) std.debug.print("  king_rays[{d}][{d}] {d} -> {d}\n", .{ c, sq, before.king_rays[c][sq], w.p.king_rays[c][sq] });
                            if (before.pawn_attacks[c][sq] != w.p.pawn_attacks[c][sq]) std.debug.print("  pawn_attacks[{d}][{d}] {d} -> {d}\n", .{ c, sq, before.pawn_attacks[c][sq], w.p.pawn_attacks[c][sq] });
                        }
                        if (before.square_slot[sq] != w.p.square_slot[sq]) std.debug.print("  square_slot[{d}] {d} -> {d}\n", .{ sq, before.square_slot[sq], w.p.square_slot[sq] });
                    }
                }
            }
        }
    }

    /// The moves accepted at the root in `mode`, as UCI text, sorted.
    fn rootMoves(w: *Walk, gpa: std.mem.Allocator, side: Side, mode: Mode, legality: Legality) ![][]const u8 {
        var out: std.ArrayList([]const u8) = .empty;
        errdefer out.deinit(gpa);
        const moves = w.generate(side, 1, mode);
        for (moves) |mv| {
            const key = w.p.hash_key;
            const pawn_key = w.p.pawn_hash_key;
            w.p.updateHashKey(mv, pos.Fixes.corrected);
            var u: pos.Undo = .{};
            w.p.makeMove(mv, side, 2, &u);
            const ok = switch (legality) {
                .king_attacked => gamemove.kingAttacked(&w.p, @backingInt(side)) == 0,
                .attack_map => blk: {
                    // The root pre-scoring (0000:09FE): the opponent's leaf attack map, the
                    // mover's king square.
                    var lv: leaf.LeafVars = .{};
                    switch (side) {
                        .white => leaf.leafAttackMap(&w.p, &lv, .black),
                        .black => leaf.leafAttackMap(&w.p, &lv, .white),
                    }
                    break :blk lv.leaf_map[w.p.piece_list[16 * @as(usize, @backingInt(side)) + 7]] == 0;
                },
            };
            w.p.unmakeMove(mv, side, &u);
            w.p.hash_key = key;
            w.p.pawn_hash_key = pawn_key;
            if (ok) {
                var buf: [5]u8 = undefined;
                try out.append(gpa, try gpa.dupe(u8, uciText(mv, &buf)));
            }
        }
        const s = try out.toOwnedSlice(gpa);
        std.mem.sort([]const u8, s, {}, lessText);
        return s;
    }
};

fn freeList(gpa: std.mem.Allocator, l: [][]const u8) void {
    for (l) |m| gpa.free(m);
    gpa.free(l);
}

fn lessText(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

/// The position fields make and unmake must give back, and the per-ply bytes of the plies
/// up to `ply` (those above are the child's own).
fn restored(a: *const Position, b: *const Position, ply: usize) bool {
    inline for (.{
        "board",          "piece_list",       "pawn_attacks",    "king_rays",
        "pawns_per_file", "material",         "piece_material",  "piece_material_sum",
        "total_material", "material_balance", "piece_balance",   "men",
        "piece_count",    "pawn_count",       "side_pawn_count", "pawns_on_dark",
        "king_file",      "oo_lost_at",       "ooo_lost_at",     "game_ply",
        "hash_key",       "pawn_hash_key",
    }) |f| {
        if (!std.meta.eql(@field(a, f), @field(b, f))) {
            if (debug_restore) std.debug.print("restore: field {s} differs\n", .{f});
            return false;
        }
    }
    // The slot map under each man. Under an empty square it holds whatever was last
    // written there (the square of a pawn taken en passant keeps its slot until a later
    // make overwrites it with FFh), and nothing reads it there.
    for (a.board, 0..) |c, sq| {
        if (c != pos.empty and c != pos.border and a.square_slot[sq] != b.square_slot[sq]) {
            if (debug_restore) std.debug.print("restore: square_slot[{d}] differs\n", .{sq});
            return false;
        }
    }
    if (!std.mem.eql(u8, a.ep_square_by_ply[0 .. ply + 1], b.ep_square_by_ply[0 .. ply + 1])) return false;
    if (!std.mem.eql(u8, a.check_by_ply[0 .. ply + 1], b.check_by_ply[0 .. ply + 1])) return false;
    return true;
}

fn uciText(mv: Move, buf: *[5]u8) []const u8 {
    buf[0] = 'a' + (mv.from % 10) - 1;
    buf[1] = '1' + (mv.from / 10) - 2;
    buf[2] = 'a' + (mv.to % 10) - 1;
    buf[3] = '1' + (mv.to / 10) - 2;
    const promo: ?u8 = switch (mv.flag) {
        2 => 'n',
        3 => 'b',
        4 => 'r',
        5 => 'q',
        else => null,
    };
    if (promo) |c| {
        buf[4] = c;
        return buf[0..5];
    }
    return buf[0..4];
}

/// A divergence from true perft that the original has: the counts it gives instead.
const Known = struct {
    name: []const u8,
    /// The counts of depths 1..n the original gives (the file's depth, or less in Debug).
    nodes: []const u64,
    /// Root moves (UCI) the original adds to the legal ones, and legal ones it lacks.
    extra: []const []const u8 = &.{},
    missing: []const []const u8 = &.{},
};

/// A rook captured on its corner square does not take away the castling right inside the
/// tree: make_move stamps a right lost only when the king moves or a rook moves off its
/// corner (1E9D:0124..0290, `Position.rookMoved`); update_castle_stamps (38C0:0130), which
/// stamps the right when the wing's rook (piece-list slot 4 or 5) has been captured, runs
/// only between game moves. The castling generator (1E9D:3938, castling tests 388C / 37E0)
/// then castles with any rook of the side that stands on the corner. Here 1...Bxh1 2.Rxh1
/// K-any 3.O-O: the five king moves give five extra leaves at depth 4, 28 at depth 5.
const known = [_]Known{
    .{ .name = "castle-rook-captured-on-corner", .nodes = &.{ 18, 376, 5248, 127895, 1707452 } },
    .{ .name = "castle-rook-captured-on-corner-mirror", .nodes = &.{ 18, 376, 5248, 127895, 1707452 } },
    .{ .name = "castle-rook-captured-on-corner-long", .nodes = &.{ 18, 357, 5059, 118790, 1605794 } },
    .{ .name = "castle-rook-captured-on-corner-long-mirror", .nodes = &.{ 18, 357, 5059, 118790, 1605794 } },
};

/// Positions in check where gen_all_moves (1E9D:3938), which the engine's `findLegal`
/// (src/engine.zig) uses for the moves of a `position ... moves` command of two moves or
/// more, offers castling: its castling tests (388C / 37E0) look at the square the king
/// passes and the one it lands on, never at the king's own square. The original's root
/// and check_entered_move call gen_evasions in check instead, so only the engine's
/// adaptation can accept these moves (the king's own test after the move clears them).
const AllMovesExtra = struct { name: []const u8, extra: []const []const u8 };
const known_all_moves = [_]AllMovesExtra{
    .{ .name = "castle-out-of-check-rook", .extra = &.{ "e1c1", "e1g1" } },
    .{ .name = "castle-out-of-check-rook-mirror", .extra = &.{ "e8c8", "e8g8" } },
    .{ .name = "castle-out-of-check-bishop", .extra = &.{ "e1c1", "e1g1" } },
    .{ .name = "castle-out-of-check-bishop-mirror", .extra = &.{ "e8c8", "e8g8" } },
    .{ .name = "castle-out-of-check-knight", .extra = &.{ "e1c1", "e1g1" } },
    .{ .name = "castle-out-of-check-knight-mirror", .extra = &.{ "e8c8", "e8g8" } },
    .{ .name = "castle-out-of-check-pawn", .extra = &.{"e1g1"} },
    .{ .name = "castle-out-of-check-pawn-mirror", .extra = &.{"e8g8"} },
    .{ .name = "golden-027-castling", .extra = &.{"e8c8"} },
    .{ .name = "golden-343-normal1", .extra = &.{"e1g1"} },
};

fn findAllMovesExtra(name: []const u8) ?AllMovesExtra {
    for (known_all_moves) |k| if (std.mem.eql(u8, k.name, name)) return k;
    return null;
}

fn findKnown(name: []const u8) ?Known {
    for (known) |k| if (std.mem.eql(u8, k.name, name)) return k;
    return null;
}

const R = ert_test.R;

/// The engine's state for `d`: start-up, `adapt_setup.enterFen`, the search position read
/// from the image, with the root's en-passant square and check byte at ply 1 as main
/// takes them from the game record (DG:9EC9, DG:8C07; the record holds Setup's ply-0
/// values).
fn enterPosition(s: *R, loop_img: anytype, loop_far: anytype, d: *const fen.Description, p: *Position) !setup.Legality {
    // The members loaded from the start-up image (the tests' codec), Setup mode on them,
    // and the image made current for the search position.
    si.fromImage(s, loop_img, loop_far);
    s.pawn_hash.clear();
    for (s.tables) |*t| t.clear();
    s.failure = null;
    const r = as.enterFen(s, d);
    if (r != .legal) return r;
    si.toImage(s);
    p.* = .{};
    ap.PositionMap.load(p, s.test_img);
    p.ep_square_by_ply[1] = p.ep_square_by_ply[0];
    p.check_by_ply[1] = p.check_by_ply[0];
    return .legal;
}

fn diffLists(gpa: std.mem.Allocator, got: []const []const u8, want: []const []const u8, extra: *std.ArrayList([]const u8), missing: *std.ArrayList([]const u8)) !void {
    for (got) |g| {
        var found = false;
        for (want) |x| found = found or std.mem.eql(u8, g, x);
        if (!found) try extra.append(gpa, g);
    }
    for (want) |x| {
        var found = false;
        for (got) |g| found = found or std.mem.eql(u8, g, x);
        if (!found) try missing.append(gpa, x);
    }
}

fn joinText(buf: []u8, items: []const []const u8) []const u8 {
    var n: usize = 0;
    for (items, 0..) |it, i| {
        if (n + it.len + 1 > buf.len) break;
        if (i != 0) {
            buf[n] = ' ';
            n += 1;
        }
        @memcpy(buf[n..][0..it.len], it);
        n += it.len;
    }
    return buf[0..n];
}

fn eqTextLists(a: []const []const u8, b: []const []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| if (!std.mem.eql(u8, x, y)) return false;
    return true;
}

test "perft: the original's move generation and legality test against true perft (tests/golden/perft/perft.jsonl)" {
    const gpa = std.testing.allocator;
    const s = try R.init(gpa, 16);
    defer s.deinit();
    s.startUp(.{}, .{}, .{}, 5);
    si.toImage(s); // start-up runs on the members (Stage B step 8, stage 4)
    const loop_img = try gpa.create(@TypeOf(s.test_img.*));
    defer gpa.destroy(loop_img);
    const loop_far = try gpa.create(@TypeOf(s.test_far.*));
    defer gpa.destroy(loop_far);
    loop_img.* = s.test_img.*;
    loop_far.* = s.test_far.*;

    const jl = try ert_test.readGolden(gpa, "perft/perft.jsonl");
    defer gpa.free(jl);
    // Debug runs every position to depth 3 at most.
    const debug_cap: usize = 3;
    const w = try gpa.create(Walk);
    defer gpa.destroy(w);

    var positions: u32 = 0;
    var refused: u32 = 0;
    var equal: u32 = 0;
    var as_known: u32 = 0;
    var unexpected: u32 = 0;
    var nodes: u64 = 0;
    var findlegal_differs: u32 = 0;
    var rootmap_differs: u32 = 0;
    var lines = std.mem.splitScalar(u8, jl, '\n');
    while (lines.next()) |text| {
        if (text.len == 0) continue;
        const parsed = try std.json.parseFromSlice(std.json.Value, gpa, text, .{});
        defer parsed.deinit();
        const o = parsed.value.object;
        const name = o.get("name").?.string;
        const fen_text = o.get("fen").?.string;
        var depth: usize = @intCast(o.get("depth").?.integer);
        if (builtin.mode == .debug) {
            const cap: usize = debug_cap;
            depth = @min(depth, cap);
        }
        const want_nodes = o.get("nodes").?.array.items;
        var want_moves: std.ArrayList([]const u8) = .empty;
        defer want_moves.deinit(gpa);
        for (o.get("moves").?.array.items) |m| try want_moves.append(gpa, m.string);

        const d = try fen.parse(fen_text);
        positions += 1;
        w.* = .{};
        const r = try enterPosition(s, loop_img, loop_far, &d, &w.p);
        if (r != .legal) {
            refused += 1;
            std.debug.print("perft: {s}: {s}: refused by Setup mode: {s}\n", .{ name, fen_text, as.refusalText(r) });
            unexpected += 1;
            continue;
        }
        const side = d.side_to_move;
        // Depth 1, both ways a root move is taken.
        const entry_moves = try w.rootMoves(gpa, side, .entry, .king_attacked);
        defer freeList(gpa, entry_moves);
        const all_moves = try w.rootMoves(gpa, side, .all_moves, .king_attacked);
        defer freeList(gpa, all_moves);
        const map_moves = try w.rootMoves(gpa, side, .entry, .attack_map);
        defer freeList(gpa, map_moves);
        {
            var ex: std.ArrayList([]const u8) = .empty;
            defer ex.deinit(gpa);
            var mi: std.ArrayList([]const u8) = .empty;
            defer mi.deinit(gpa);
            try diffLists(gpa, map_moves, entry_moves, &ex, &mi);
            if (ex.items.len != 0 or mi.items.len != 0) {
                rootmap_differs += 1;
                var b1: [256]u8 = undefined;
                var b2: [256]u8 = undefined;
                std.debug.print("perft: {s}: the root's attack-map test against 2B9F:4B32: accepts [{s}], refuses [{s}]\n", .{ name, joinText(&b1, ex.items), joinText(&b2, mi.items) });
                unexpected += 1;
            }
        }
        {
            var ex: std.ArrayList([]const u8) = .empty;
            defer ex.deinit(gpa);
            var mi: std.ArrayList([]const u8) = .empty;
            defer mi.deinit(gpa);
            try diffLists(gpa, all_moves, entry_moves, &ex, &mi);
            if (ex.items.len != 0 or mi.items.len != 0) findlegal_differs += 1;
            const want_extra: []const []const u8 = if (findAllMovesExtra(name)) |k| k.extra else &.{};
            if (mi.items.len != 0 or !eqTextLists(ex.items, want_extra)) {
                var b1: [256]u8 = undefined;
                var b2: [256]u8 = undefined;
                std.debug.print("perft: {s}: gen_all_moves (findLegal) against the entry path: adds [{s}], lacks [{s}] (not as listed in `known_all_moves`)\n", .{ name, joinText(&b1, ex.items), joinText(&b2, mi.items) });
                unexpected += 1;
            }
        }
        w.perft(side, 1, depth, 0);
        var got: [max_depth]u64 = undefined;
        for (0..depth) |k| got[k] = w.counts[k];
        nodes += got[depth - 1];

        var extra: std.ArrayList([]const u8) = .empty;
        defer extra.deinit(gpa);
        var missing: std.ArrayList([]const u8) = .empty;
        defer missing.deinit(gpa);
        try diffLists(gpa, entry_moves, want_moves.items, &extra, &missing);
        var counts_equal = true;
        for (0..depth) |k| counts_equal = counts_equal and got[k] == @as(u64, @intCast(want_nodes[k].integer));

        if (w.restore_failures != 0 or w.key_failures != 0 or w.king_captures != 0) {
            std.debug.print("perft: {s}: {d} restore failures, {d} key failures, {d} king captures: {s}\n", .{ name, w.restore_failures, w.key_failures, w.king_captures, w.first_failure orelse "the generator answered FFFFh" });
            unexpected += 1;
        }
        if (w.full_lists != 0) {
            std.debug.print("perft: {s}: {d} nodes with a full list of 100 moves (DEV-063)\n", .{ name, w.full_lists });
            unexpected += 1;
        }
        // A listed divergence must give the listed counts (in Debug, where the depth is
        // capped, those of the depths run, which may still equal true perft).
        if (findKnown(name)) |kk| {
            if (kk.nodes.len >= depth and std.mem.eql(u64, kk.nodes[0..depth], got[0..depth]) and
                eqTextLists(kk.extra, extra.items) and eqTextLists(kk.missing, missing.items))
            {
                as_known += 1;
                continue;
            }
        } else if (counts_equal and extra.items.len == 0 and missing.items.len == 0) {
            equal += 1;
            continue;
        }
        unexpected += 1;
        var b1: [512]u8 = undefined;
        var b2: [512]u8 = undefined;
        std.debug.print("perft: {s}: {s}\n  original {any}\n  true     ", .{ name, fen_text, got[0..depth] });
        for (want_nodes[0..depth]) |x| std.debug.print("{d} ", .{x.integer});
        std.debug.print("\n  root moves the original adds: [{s}]; lacks: [{s}]\n", .{ joinText(&b1, extra.items), joinText(&b2, missing.items) });
    }
    std.debug.print("perft: {d} positions, {d} leaf nodes at the depths run; {d} equal true perft, {d} differ as listed in `known`, {d} unexpected, {d} refused by Setup mode; gen_all_moves at the root differs from the entry path in {d}\n", .{ positions, nodes, equal, as_known, unexpected, refused, findlegal_differs });
    try std.testing.expectEqual(@as(u32, 0), unexpected);
    try std.testing.expectEqual(@as(u32, known.len), as_known);
    try std.testing.expectEqual(@as(u32, known_all_moves.len), findlegal_differs);
}

test "perft: with DEV-050 corrected (a rook captured on its corner takes the castling right away) every position equals true perft" {
    const gpa = std.testing.allocator;
    const s = try R.init(gpa, 16);
    defer s.deinit();
    s.startUp(.{}, .{}, .{}, 5);
    si.toImage(s); // start-up runs on the members (Stage B step 8, stage 4)
    const loop_img = try gpa.create(@TypeOf(s.test_img.*));
    defer gpa.destroy(loop_img);
    const loop_far = try gpa.create(@TypeOf(s.test_far.*));
    defer gpa.destroy(loop_far);
    loop_img.* = s.test_img.*;
    loop_far.* = s.test_far.*;
    const jl = try ert_test.readGolden(gpa, "perft/perft.jsonl");
    defer gpa.free(jl);
    const w = try gpa.create(Walk);
    defer gpa.destroy(w);

    var positions: u32 = 0;
    var equal: u32 = 0;
    var known_now_equal: u32 = 0;
    var nodes: u64 = 0;
    var lines = std.mem.splitScalar(u8, jl, '\n');
    while (lines.next()) |text| {
        if (text.len == 0) continue;
        const parsed = try std.json.parseFromSlice(std.json.Value, gpa, text, .{});
        defer parsed.deinit();
        const o = parsed.value.object;
        const name = o.get("name").?.string;
        var depth: usize = @intCast(o.get("depth").?.integer);
        // Debug runs to depth 3 at most, where the correction cannot show yet (it needs
        // four plies); the other builds run the file's depth.
        if (builtin.mode == .debug) depth = @min(depth, 3);
        const want_nodes = o.get("nodes").?.array.items;
        const d = try fen.parse(o.get("fen").?.string);
        positions += 1;
        w.* = .{};
        if (try enterPosition(s, loop_img, loop_far, &d, &w.p) != .legal) return error.RefusedBySetup;
        w.fix050 = true;
        w.perft(d.side_to_move, 1, depth, 0);
        nodes += w.counts[depth - 1];
        var ok = w.restore_failures == 0 and w.key_failures == 0 and w.king_captures == 0;
        for (0..depth) |k| ok = ok and w.counts[k] == @as(u64, @intCast(want_nodes[k].integer));
        if (ok) {
            equal += 1;
            // One of the original's divergences, now equal at a depth where it showed.
            if (findKnown(name)) |kk| {
                if (depth >= 4 and kk.nodes[depth - 1] != w.counts[depth - 1]) known_now_equal += 1;
            }
            continue;
        }
        std.debug.print("perft (DEV-050 corrected): {s}: {any} against true perft; {d} restore failures, {d} key failures: {s}\n", .{ name, w.counts[0..depth], w.restore_failures, w.key_failures, w.first_failure orelse "" });
    }
    std.debug.print("perft (DEV-050 corrected): {d} positions, {d} leaf nodes; {d} equal true perft, of them {d} that differ in the original\n", .{ positions, nodes, equal, known_now_equal });
    try std.testing.expectEqual(positions, equal);
    if (builtin.mode != .debug) try std.testing.expectEqual(@as(u32, known.len), known_now_equal);
}

test "perft: the root move lists of set-up positions equal the original's, in order (tests/golden/perft/oracle_roots.jsonl)" {
    const gpa = std.testing.allocator;
    const s = try R.init(gpa, 16);
    defer s.deinit();
    s.startUp(.{}, .{}, .{}, 5);
    si.toImage(s); // start-up runs on the members (Stage B step 8, stage 4)
    const loop_img = try gpa.create(@TypeOf(s.test_img.*));
    defer gpa.destroy(loop_img);
    const loop_far = try gpa.create(@TypeOf(s.test_far.*));
    defer gpa.destroy(loop_far);
    loop_img.* = s.test_img.*;
    loop_far.* = s.test_far.*;
    const jl = try ert_test.readGolden(gpa, "perft/oracle_roots.jsonl");
    defer gpa.free(jl);
    const w = try gpa.create(Walk);
    defer gpa.destroy(w);
    var lists: u32 = 0;
    var moves_compared: u32 = 0;
    var lines = std.mem.splitScalar(u8, jl, '\n');
    while (lines.next()) |text| {
        if (text.len == 0) continue;
        const parsed = try std.json.parseFromSlice(std.json.Value, gpa, text, .{});
        defer parsed.deinit();
        const o = parsed.value.object;
        const name = o.get("name").?.string;
        // Setup mode: the rights from the board, no en-passant square.
        var buf: [128]u8 = undefined;
        var d = try fen.parse(try std.fmt.bufPrint(&buf, "{s} - - 0 1", .{o.get("fen").?.string}));
        d.castling = as.rightsFromBoard(&d.board);
        w.* = .{};
        try std.testing.expectEqual(setup.Legality.legal, try enterPosition(s, loop_img, loop_far, &d, &w.p));
        const got = w.generate(d.side_to_move, 1, .entry);
        const want = o.get("moves").?.array.items;
        var ok = got.len == want.len;
        for (want, 0..) |m, i| {
            if (i >= got.len) break;
            const t = m.array.items;
            const g = got[i];
            if (g.from != t[0].integer or g.to != t[1].integer or g.flag != t[2].integer) {
                if (ok) std.debug.print("perft: {s}: root move {d}: engine {d}-{d} flag {d}, original {d}-{d} flag {d}\n", .{ name, i, g.from, g.to, g.flag, t[0].integer, t[1].integer, t[2].integer });
                ok = false;
            }
        }
        if (got.len != want.len) std.debug.print("perft: {s}: {d} root moves, the original {d}\n", .{ name, got.len, want.len });
        try std.testing.expect(ok);
        lists += 1;
        moves_compared += @intCast(want.len);
    }
    std.debug.print("perft: {d} root lists equal the original's ({d} moves, order and flags)\n", .{ lists, moves_compared });
    try std.testing.expect(lists >= 7);
}
