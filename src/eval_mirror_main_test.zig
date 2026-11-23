//! The colour mirror of the whole evaluation, with every class C fix on but the five of
//! the mirror's own candidates (DEV-054, 055, 056, 058, 059): the copy of
//! src/eval_mirror_test.zig that guards the counts as they were before those five, so
//! that both states are asserted (the file there runs the shipped engine, with them).
//! Only the fixes, the test names and the tests kept differ from that file: the searches,
//! the Setup-slot run and the large set are run there only.
//!
//! The colour mirror of the whole evaluation (task eval-mirror, 2026-11-21;
//! docs/arch/50-evaluation-map.md section 14). A position and its colour mirror (ranks
//! reversed, colours exchanged, the side to move, castling rights and en-passant square
//! exchanged) are the same position seen from the other side; an evaluation without a
//! colour preference scores them alike from the mover's view. Every case here is run with
//! every class C fix on (`pos.Fixes.corrected`, the shipped engine).
//!
//! Three levels, each on the engine's own state (the DGROUP image of src/engine_root.zig,
//! the position entered through Setup mode as `position fen` enters it):
//!
//! 1. prepare_eval: the root and its mirror are each set up and taken through main to the
//!    iteration loop (rootprep, prepare_eval among it); then every table it writes
//!    (`evaltables.Tables`) is compared with the other colour's table at the mirrored
//!    square (`compareTables`).
//! 2. The leaf: from the two prepared images, the same random walk is played (each move and
//!    its mirror, `Ctx.applyMove`), and at every node the evaluation routines the node calls
//!    are run in the stand pat's order on both (`evalTerms`): pawn evaluation, the
//!    attacked-piece count, static_eval and the flags it sets, the endgame king term,
//!    0EF8:0006, the threat evaluator, the mobility term, and the leaf terms. Each is
//!    compared with its mirror (`differ`); a difference that is only an arithmetic shift's
//!    rounding is told apart (`rounding`). The move generators are compared at every node
//!    too, as sets with their score bytes, and for order, and the two exchange evaluators
//!    on every square of every third node.
//! 3. The search: a fixed-depth search of the position and of its mirror
//!    (`EngineOf(pos.Fixes.corrected)`), with the move, the score, the node count and the
//!    first difference between the two traces.
//!
//! Setup mode gives slots by scanning from a1 upwards for both colours (src/setup.zig
//! `assignSlots`), so a position and its mirror set up are not slot for slot each other's
//! mirror. Levels 1 and 2 take the mirror's slots from the root's (`remapSlots`): the
//! mirror as play from the start position would reach it. Level 3 is measured both ways.
//!
//! What is symmetric is asserted to be; what is not is asserted at its exact count, with
//! its cause (the candidates DEV-054 to DEV-061 of docs/DEVIATIONS.md),
//! so that a correction must update the counts it changes. Each candidate also has a
//! position that shows it. The default run takes about 20 seconds in ReleaseFast;
//! MCHESS_LONG_TESTS=1 adds a large generated set, on which only the invariants are
//! asserted.

const std = @import("std");
const si = @import("state_image.zig");
const builtin = @import("builtin");
const build_options = @import("build_options");
const pos = @import("position.zig");
const fen = @import("fen.zig");
const mg = @import("movegen.zig");
const engine_mod = @import("engine.zig");
const uci_report = @import("uci_report.zig");
const uci_engine = @import("uci_engine.zig");
const adapt_setup = @import("adapt_setup.zig");
const ap = @import("adapt_position.zig");
const am = @import("adapt_movegen.zig");
const adapt_eval = @import("adapt_eval.zig");
const an = @import("adapt_node.zig");
const sn = @import("searchnode.zig");
const et = @import("evaltables.zig");
const dgroup = @import("dgroup.zig");
const PawnHash = @import("pawnhash.zig").PawnHash;
const see_mod = @import("see.zig");
const pinexchange = @import("pinexchange.zig");

const Image = dgroup.Image;
const Position = pos.Position;
/// The shipped engine without the five fixes of the mirror's candidates (DEV-054, 055, 056,
/// 058, 059; owner decision 34): the state of main before they were merged into it
/// (decision 35), whose counts this file guards.
const fixes: pos.Fixes = blk: {
    var f = pos.Fixes.corrected;
    for ([_][]const u8{ "dev054_unstoppable_passer_mirror", "dev055_passer_block_extra_test", "dev056_king_ring_wrap", "dev058_lifted_knight_entry", "dev059_opposite_bishops_flag", "dev062_king_test_rank" }) |n| @field(f, n) = false;
    break :blk f;
};
const Eng = engine_mod.EngineOf(fixes);
const Ctx = an.Ctx(.hand, fixes);

// ---- mirroring ---------------------------------------------------------------------------

pub fn mirrorSquare(s: usize) usize {
    return (11 - s / 10) * 10 + s % 10;
}

fn msq(s: u8) u8 {
    return @intCast(mirrorSquare(s));
}

pub fn swapCode(b: u8) u8 {
    return if (b >= 1 and b <= 6) b + 7 else if (b >= 8 and b <= 13) b - 7 else b;
}

pub fn mirrorDesc(d: *const fen.Description) fen.Description {
    var m = d.*;
    for (0..120) |s| m.board[mirrorSquare(s)] = swapCode(d.board[s]);
    m.side_to_move = if (d.side_to_move == .white) .black else .white;
    m.castling = .{ .white_short = d.castling.black_short, .white_long = d.castling.black_long, .black_short = d.castling.white_short, .black_long = d.castling.white_long };
    m.en_passant = if (d.en_passant) |e| msq(e) else null;
    return m;
}

/// The mirror's piece lists and slot map from the root's: slot i of one colour holds the
/// mirror of slot i of the other.
fn remapSlots(m: *Position, r: *const Position) void {
    for (0..2) |c| for (0..16) |i| {
        const e = r.piece_list[16 * c + i];
        m.piece_list[16 * (1 - c) + i] = if (e < 100) msq(e) else e;
    };
    for (20..100) |s| m.square_slot[mirrorSquare(s)] = r.square_slot[s];
}

fn fenText(d: *const fen.Description, buf: []u8) []const u8 {
    var n: usize = 0;
    var rank: usize = 8;
    while (rank > 0) {
        rank -= 1;
        var gap: u8 = 0;
        for (0..8) |f| {
            const c = d.board[21 + f + 10 * rank];
            if (c == 0) {
                gap += 1;
                continue;
            }
            if (gap > 0) {
                buf[n] = '0' + gap;
                n += 1;
                gap = 0;
            }
            buf[n] = fen.letterFromPiece(c) orelse '?';
            n += 1;
        }
        if (gap > 0) {
            buf[n] = '0' + gap;
            n += 1;
        }
        if (rank > 0) {
            buf[n] = '/';
            n += 1;
        }
    }
    buf[n] = ' ';
    buf[n + 1] = if (d.side_to_move == .white) 'w' else 'b';
    n += 2;
    return buf[0..n];
}

// ---- positions ---------------------------------------------------------------------------

/// The golden files' searches, each as a position (board, side, the rights the board
/// allows, as src/engine_fixes_test.zig takes them).
const golden_files = [_][]const u8{ "smoke", "corpus1", "corpus2", "normal1", "castling", "longgame" };

fn loadGolden(arena: std.mem.Allocator) ![]fen.Description {
    var list: std.ArrayList(fen.Description) = .empty;
    for (golden_files) |name| {
        const path = try std.fmt.allocPrint(arena, "{s}/{s}.jsonl", .{ build_options.golden_dir, name });
        const text = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, arena, .limited(1 << 24));
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            const v = try std.json.parseFromSliceLeaky(std.json.Value, arena, line, .{});
            const o = v.object;
            if (o.get("search") == null) continue;
            const f = try std.fmt.allocPrint(arena, "{s} {s}", .{ o.get("board").?.string, o.get("side").?.string });
            var d = try fen.parse(f);
            d.castling = adapt_setup.rightsFromBoard(&d.board);
            try list.append(arena, d);
        }
    }
    return list.items;
}

fn kingsAdjacent(a: u8, b: u8) bool {
    const df = @abs(@as(i16, a % 10) - @as(i16, b % 10));
    const dr = @abs(@as(i16, a / 10) - @as(i16, b / 10));
    return df <= 1 and dr <= 1;
}

fn randomSquare(r: std.Random, lo_rank: u8, hi_rank: u8) u8 {
    return 21 + r.uintLessThan(u8, 8) + 10 * (lo_rank + r.uintLessThan(u8, hi_rank - lo_rank + 1));
}

/// A random position: kings anywhere (a third of them in a corner), each side 0..8 pawns on
/// ranks 2..7, 0..2 knights, bishops and rooks, 0..1 queens and now and then a second
/// (promoted) queen; either side to move; the castling rights the board allows.
pub fn randomDesc(r: std.Random) fen.Description {
    var d: fen.Description = .{ .board = fen.emptyBoard(), .side_to_move = if (r.boolean()) .white else .black, .castling = .none, .en_passant = null, .halfmove_clock = 0, .fullmove_number = 1 };
    const corners = [_]u8{ 21, 28, 91, 98 };
    const wk = if (r.uintLessThan(u8, 3) == 0) corners[@as(usize, @intCast(r.uintLessThan(u64, 4)))] else randomSquare(r, 0, 7);
    var bk: u8 = undefined;
    while (true) {
        bk = if (r.uintLessThan(u8, 3) == 0) corners[@as(usize, @intCast(r.uintLessThan(u64, 4)))] else randomSquare(r, 0, 7);
        if (bk != wk and !kingsAdjacent(wk, bk)) break;
    }
    d.board[wk] = pos.white_king;
    d.board[bk] = pos.black_king;
    const sparse = r.uintLessThan(u8, 3) == 0;
    for (0..2) |c| {
        const off: u8 = @intCast(7 * c);
        const n_pawns = if (sparse) r.uintLessThan(u8, 4) else r.uintLessThan(u8, 9);
        const counts = [_]u8{ n_pawns, r.uintLessThan(u8, 3), r.uintLessThan(u8, 3), r.uintLessThan(u8, 3), @as(u8, if (r.uintLessThan(u8, 3) != 0) 1 else 0) + @as(u8, if (r.uintLessThan(u8, 12) == 0) 1 else 0) };
        for (counts, 0..) |n, k| {
            const n_eff = if (sparse and k > 0) n / 2 else n;
            for (0..n_eff) |_| {
                for (0..20) |_| {
                    const s = if (k == 0) randomSquare(r, 1, 6) else randomSquare(r, 0, 7);
                    if (d.board[s] != 0) continue;
                    d.board[s] = @intCast(1 + k + off);
                    break;
                }
            }
        }
    }
    d.castling = adapt_setup.rightsFromBoard(&d.board);
    return d;
}

// ---- level 1 and 2: the prepared root ----------------------------------------------------

/// The ply limits of an iteration of depth `d` as the root writes them (ThreatVars:
/// A272 = d + 2, 9356 = d + 4, A5EC = d + 6, the iteration A3F4 = d), written into both
/// images alike (the iteration loop itself is not run, so that the two images differ only
/// by what prepare_eval and Setup made of the two positions).
fn setLimits(img: *Image, d: i16) void {
    std.mem.writeInt(i16, img[0xA272..][0..2], d + 2, .little);
    std.mem.writeInt(i16, img[0x9356..][0..2], d + 4, .little);
    std.mem.writeInt(i16, img[0xA5EC..][0..2], d + 6, .little);
    img[0xA3F4] = @bitCast(@as(i8, @intCast(d)));
}

/// `d` entered through Setup mode (the engine's `position fen`), the slots optionally
/// taken from `slots_from` mirrored, then main from 0526 to the iteration loop (rootprep,
/// prepare_eval among it). `setup_pos` receives the position as Setup left it. False if
/// Setup refuses it or main does not reach the loop.
fn prepareRoot(e: *Eng, d: *const fen.Description, slots_from: ?*const Position, setup_pos: ?*Position) bool {
    if (e.engine().setPosition(d, .setup, &.{}) != null) return false;
    const s = e.root;
    // On the image, as before step 8: `state_image.prepare` loads the members from it and stores them back.
    si.imageBegin(s);
    defer si.imageEnd(s);
    if (setup_pos) |sp| {
        sp.* = .{};
        ap.PositionMap.load(sp, s.test_img);
    }
    if (slots_from) |src| {
        var p: Position = .{};
        ap.PositionMap.load(&p, s.test_img);
        remapSlots(&p, src);
        ap.PositionMap.storeAll(&p, s.test_img);
    }
    s.test_img[0xA274] = 3;
    std.mem.writeInt(u16, s.test_img[0x1E02..][0..2], 2, .little);
    s.beginSearch();
    // main from the image and back to it, as before step 8 (src/state_image.zig).
    const x = si.prepare(s, .own);
    return x == .iteration_loop and s.failure == null;
}

const Kind = enum { square_pair, scalar_pair, scalar_neg_pair, same, neg_same, code_pair, code_cross_pair, rank_by_file, slot_square };
const Check = struct { name: []const u8, kind: Kind, a: []const u8, b: []const u8 = "" };

/// Every table and flag prepare_eval writes (evaltables.Tables), with how a mirror is
/// expected to see it.
const checks = [_]Check{
    .{ .name = "promoted queen slot", .kind = .same, .a = "promoted_queen_slot" }, // compared swapped below
    .{ .name = "computer side", .kind = .same, .a = "computer_side" }, // swapped: see `special`
    .{ .name = "pawn sum bases A008 / 7468", .kind = .scalar_neg_pair, .a = "base_white_pawns", .b = "base_black_pawns" },
    .{ .name = "piece sum base A5E2", .kind = .neg_same, .a = "base_pieces" },
    .{ .name = "castling gone 3675 / A4F2", .kind = .scalar_pair, .a = "white_castling_gone", .b = "black_castling_gone" },
    .{ .name = "passed counts 9D8B / 724C", .kind = .scalar_pair, .a = "passed_count_white", .b = "passed_count_black" },
    .{ .name = "passed rank by file A8E0 / 9EEE", .kind = .rank_by_file, .a = "passed_rank_by_file_white", .b = "passed_rank_by_file_black" },
    .{ .name = "passed pawn squares A3FE / 8CE6", .kind = .slot_square, .a = "passed_pawn_sq_white", .b = "passed_pawn_sq_black" },
    .{ .name = "passed count both 8CC4", .kind = .same, .a = "passed_count_both" },
    .{ .name = "shelter by rank 9EBE", .kind = .same, .a = "shelter_by_rank" },
    .{ .name = "phase developing 9FC7", .kind = .same, .a = "phase_developing" },
    .{ .name = "phase opening A8D7", .kind = .same, .a = "phase_opening" },
    .{ .name = "single bishops A360", .kind = .same, .a = "single_bishops_same_slot" },
    .{ .name = "KBN v K B622", .kind = .same, .a = "kbn_vs_king" },
    .{ .name = "no pawns A6A3", .kind = .same, .a = "no_pawns" },
    .{ .name = "endgame A6C3", .kind = .same, .a = "endgame" },
    .{ .name = "late endgame A72C", .kind = .same, .a = "late_endgame" },
    .{ .name = "mobility weights A074", .kind = .code_pair, .a = "mobility_weights" },
    .{ .name = "centrality B522 / B5A8", .kind = .square_pair, .a = "centrality_white", .b = "centrality_black" },
    .{ .name = "pawn table A8EC / AA2C", .kind = .square_pair, .a = "pawn_white", .b = "pawn_black" },
    .{ .name = "knight table 75CA / 76A2", .kind = .square_pair, .a = "knight_white", .b = "knight_black" },
    .{ .name = "bishop table AC2A / ACF4", .kind = .square_pair, .a = "bishop_white", .b = "bishop_black" },
    .{ .name = "rook table 9182 / 924A", .kind = .square_pair, .a = "rook_white", .b = "rook_black" },
    .{ .name = "queen table 8DEA / 8EB8", .kind = .square_pair, .a = "queen_white", .b = "queen_black" },
    .{ .name = "king table 7260 / 732A", .kind = .square_pair, .a = "king_white", .b = "king_black" },
    .{ .name = "king zone AEFA / B03E", .kind = .square_pair, .a = "king_zone_white", .b = "king_zone_black" },
    .{ .name = "root queenless 7100 / 9354", .kind = .scalar_pair, .a = "root_white_queenless", .b = "root_black_queenless" },
    .{ .name = "king tucked 8BBC / B628", .kind = .scalar_pair, .a = "white_king_tucked", .b = "black_king_tucked" },
    .{ .name = "knight activity A84E / A9B4", .kind = .square_pair, .a = "activity_knight_white", .b = "activity_knight_black" },
    .{ .name = "bishop activity A2F0 / A390", .kind = .square_pair, .a = "activity_bishop_white", .b = "activity_bishop_black" },
    .{ .name = "rook activity ABA0 / AFC6", .kind = .square_pair, .a = "activity_rook_white", .b = "activity_rook_black" },
    .{ .name = "queen activity AB20 / ADBE", .kind = .square_pair, .a = "activity_queen_white", .b = "activity_queen_black" },
    .{ .name = "rook bytes A6C8 / A72E", .kind = .square_pair, .a = "rook_bytes_white", .b = "rook_bytes_black" },
    .{ .name = "storm 746C / AE46", .kind = .square_pair, .a = "storm_746c", .b = "storm_ae46" },
    .{ .name = "storm 718C / A792", .kind = .square_pair, .a = "storm_718c", .b = "storm_a792" },
    .{ .name = "tables 90BA / 369E", .kind = .square_pair, .a = "table_90ba", .b = "table_369e" },
    .{ .name = "table 7692", .kind = .same, .a = "table_7692" },
    .{ .name = "table 3766", .kind = .same, .a = "table_3766" },
    // Constant tables by piece code, each the other's with the colours exchanged.
    .{ .name = "endgame king source A234 / 77DA", .kind = .code_cross_pair, .a = "endgame_king_src_white", .b = "endgame_king_src_black" },
    .{ .name = "endgame king weights 933E / 3A22", .kind = .code_cross_pair, .a = "endgame_king_weights_white", .b = "endgame_king_weights_black" },
    .{ .name = "piece values 14D0", .kind = .code_pair, .a = "piece_value_2" },
    .{ .name = "promotion gains 14EC", .kind = .code_pair, .a = "promotion_gain_2" },
    .{ .name = "pawn sums 90B6 / 369A", .kind = .scalar_neg_pair, .a = "square_sum_white_pawns", .b = "square_sum_black_pawns" },
    // Setup gives Black to move game ply 1: the plies are compared as distances.
    .{ .name = "root ply A000 - last irreversible ply 7464", .kind = .same, .a = "root_ply" },
};

fn eqlAny(a: anytype, b: @TypeOf(a)) bool {
    return std.meta.eql(a, b);
}

fn neg(x: i16) i16 {
    return 0 -% x;
}

/// A check's field of the tables, by value. The mobility weights (DG:A074, 14 words) are
/// two fields of `evaltables.Tables`, `mobility_weights` and `mobility_weights_rest`: here
/// they are one array again.
fn Get(comptime name: []const u8) type {
    return if (std.mem.eql(u8, name, "mobility_weights")) [14]i16 else @FieldType(et.TableValues, name);
}
fn get(t: *const et.TableValues, comptime name: []const u8) Get(name) {
    if (comptime std.mem.eql(u8, name, "mobility_weights")) {
        var r: [14]i16 = undefined;
        r[0..6].* = t.mobility_weights;
        r[6..].* = t.mobility_weights_rest;
        return r;
    }
    return @field(t, name);
}

/// Whether check `c` holds between the root's tables `t` and the mirror's `u`.
fn holds(comptime c: Check, t: *const et.TableValues, u: *const et.TableValues) bool {
    const A = get(t, c.a);
    switch (c.kind) {
        .same => {
            if (comptime std.mem.eql(u8, c.a, "promoted_queen_slot")) return A[0] == u.promoted_queen_slot[1] and A[1] == u.promoted_queen_slot[0];
            if (comptime std.mem.eql(u8, c.a, "computer_side")) return A == 1 - u.computer_side;
            if (comptime std.mem.eql(u8, c.a, "root_ply")) return @as(i32, A) - t.last_irreversible_ply == @as(i32, u.root_ply) - u.last_irreversible_ply;
            return eqlAny(A, get(u, c.a));
        },
        .neg_same => return A == neg(get(u, c.a)),
        .scalar_pair => return eqlAny(A, get(u, c.b)) and eqlAny(get(t, c.b), get(u, c.a)),
        .scalar_neg_pair => return A == neg(get(u, c.b)) and get(t, c.b) == neg(get(u, c.a)),
        .code_pair => {
            for (0..14) |k| if (A[k] != get(u, c.a)[swapCode(@intCast(k))]) return false;
            return true;
        },
        .code_cross_pair => {
            for (0..14) |k| if (A[k] != get(u, c.b)[swapCode(@intCast(k))] or get(t, c.b)[k] != get(u, c.a)[swapCode(@intCast(k))]) return false;
            return true;
        },
        .square_pair => {
            const B = get(t, c.b);
            const lo: usize = if (A.len == 89) 31 else 21;
            const hi: usize = if (A.len == 89) 88 else 98;
            for (lo..hi + 1) |s| {
                if (s % 10 == 0 or s % 10 == 9) continue;
                const m = mirrorSquare(s);
                if (A[s] != get(u, c.b)[m] or B[s] != get(u, c.a)[m]) return false;
            }
            return true;
        },
        .rank_by_file => {
            const mr = struct {
                fn f(r: u8) u8 {
                    return if (r == 0) 0 else 11 - r;
                }
            }.f;
            for (0..8) |k| if (A[k] != mr(get(u, c.b)[k]) or get(t, c.b)[k] != mr(get(u, c.a)[k])) return false;
            return true;
        },
        .slot_square => {
            const ms = struct {
                fn f(x: u8) u8 {
                    return if (x >= 21 and x <= 98) msq(x) else x;
                }
            }.f;
            for (8..16) |k| if (A[k] != ms(get(u, c.b)[k]) or get(t, c.b)[k] != ms(get(u, c.a)[k])) return false;
            return true;
        },
    }
}

/// The first square (or index) where a square-pair check fails, and the four values.
fn squareDetail(comptime c: Check, t: *const et.TableValues, u: *const et.TableValues, buf: []u8) []const u8 {
    if (c.kind != .square_pair) {
        if (comptime c.b.len == 0) return std.fmt.bufPrint(buf, "root {any}; mirror {any}", .{ get(t, c.a), get(u, c.a) }) catch "";
        return std.fmt.bufPrint(buf, "root {any} / {any}; mirror {any} / {any}", .{ get(t, c.a), get(t, c.b), get(u, c.a), get(u, c.b) }) catch "";
    }
    const A = get(t, c.a);
    const B = get(t, c.b);
    const lo: usize = if (A.len == 89) 31 else 21;
    const hi: usize = if (A.len == 89) 88 else 98;
    for (lo..hi + 1) |s| {
        if (s % 10 == 0 or s % 10 == 9) continue;
        const m = mirrorSquare(s);
        if (A[s] != get(u, c.b)[m] or B[s] != get(u, c.a)[m])
            return std.fmt.bufPrint(buf, "sq {d}: root W {d} B {d}; mirror at {d}: W {d} B {d}", .{ s, A[s], B[s], m, get(u, c.a)[m], get(u, c.b)[m] }) catch "";
    }
    return "";
}

const TableTally = struct {
    roots: usize = 0,
    fails: [checks.len]usize = @splat(0),
    example: [checks.len]?struct { fen: [100]u8, len: usize, detail: [400]u8, dlen: usize } = @splat(null),
};

fn compareTables(t: *const et.TableValues, u: *const et.TableValues, d: *const fen.Description, tally: *TableTally) bool {
    tally.roots += 1;
    var all = true;
    inline for (checks, 0..) |c, i| {
        if (!holds(c, t, u)) {
            all = false;
            tally.fails[i] += 1;
            if (tally.example[i] == null) {
                tally.example[i] = .{ .fen = undefined, .len = 0, .detail = undefined, .dlen = 0 };
                const x = &tally.example[i].?;
                x.len = fenText(d, &x.fen).len;
                x.dlen = squareDetail(c, t, u, &x.detail).len;
            }
        }
    }
    return all;
}

fn reportTables(what: []const u8, t: *const TableTally) void {
    std.debug.print("eval mirror, prepare_eval, {s}: {d} roots\n", .{ what, t.roots });
    for (checks, t.fails, t.example) |c, n, ex| {
        if (n == 0) continue;
        std.debug.print("  {s}: differs in {d} roots", .{ c.name, n });
        if (ex) |x| std.debug.print("; first {s} {s}", .{ x.fen[0..x.len], x.detail[0..x.dlen] });
        std.debug.print("\n", .{});
    }
}

// ---- level 2: the leaf -------------------------------------------------------------------

/// The evaluation routines' results at one node, in the stand pat's order (docs/arch/
/// 50-evaluation-map.md section 6.2), then the leaf terms.
const Terms = struct {
    pawn: i16, // 18E8 / 19D4, White's view
    count: u16, // CE3E / CC4E
    static: i16, // 2B9F:000E, White's view
    flags: [5]u8, // 39AE, A5F5, A8DE, 8CCA, 9EBA after static_eval
    passed: [2]u8, // A6C2, 9D8C after the pawn evaluation
    weak: u8, // 8EB6
    endgame: i16, // 3416 / 35FB, White's view
    piece: i16, // 0EF8:0006, White's view
    threat: i16, // A026 / CD20, White's view
    counter: u8,
    mobility: i16, // 2E72, White's view
    leaf_a: i16, // 4BFE / 5534, side to move's view
    leaf_b: i16, // 450E / 454C
    pawn_ending: i16, // 1E30 / 16E4 (crossed)
    /// The pawn evaluator itself (0EF8:89DC / 8F82), before the probe's scaling.
    raw_pawn: i16,
    /// piece_activity_white and _black (1E9D:16E4, 1E30), the two halves of 2E72.
    activity: [2]i16,
};

pub const term_names = [_][]const u8{ "pawn evaluation (18E8/19D4)", "attacked count (CE3E/CC4E)", "static_eval (2B9F:000E)", "static_eval flags", "passed-pawn masks", "weak-pawn mask 8EB6", "endgame king (3416/35FB)", "pieces and kings (0EF8:0006)", "threats (A026/CD20)", "threat counter", "mobility (2E72)", "hanging pieces (4BFE/5534)", "king ring (450E/454C)", "activity, crossed (1E30/16E4)", "pawn evaluator, unscaled (89DC/8F82)", "activity, both (16E4, 1E30)" };

/// Bits of `differ` that are the rounding of an arithmetic shift alone: the probe's
/// `score - (score >> 2)` (0000:19A0 region; 3.5) and 2E72's `x + (x >> 4)`, where the
/// unscaled inputs are each other's mirror and the results differ by one.
fn rounding(a: *const Terms, b: *const Terms, no_pawns: bool, pawns: u8) u32 {
    var m: u32 = 0;
    // The pawn evaluator's three quarters with 8 pawns or fewer, `cx - (cx >> 2)` (8E5E),
    // then the probe's with [378E] <= 5000: one or two points.
    const raw_round = a.raw_pawn != neg(b.raw_pawn) and pawns <= 8 and @abs(@as(i32, a.raw_pawn) + b.raw_pawn) == 1;
    if (raw_round) m |= 1 << 14;
    if ((raw_round or a.raw_pawn == neg(b.raw_pawn)) and a.pawn != neg(b.pawn) and @abs(@as(i32, a.pawn) + b.pawn) <= 2) m |= 1 << 0;
    // static_eval's no-pawn branch, `di >>= 2` or `di >>= 1` (2B9F:00B6; 4.1 step 7).
    if (no_pawns and a.static != neg(b.static) and @abs(@as(i32, a.static) + b.static) == 1) m |= 1 << 2;
    if (a.activity[0] == b.activity[1] and a.activity[1] == b.activity[0] and a.mobility != neg(b.mobility) and @abs(@as(i32, a.mobility) + b.mobility) == 1) m |= 1 << 10;
    return m;
}

/// A bit per term of `term_names` where the root's `a` and the mirror's `b` disagree.
fn differ(a: *const Terms, b: *const Terms) u32 {
    var m: u32 = 0;
    if (a.pawn != neg(b.pawn)) m |= 1 << 0;
    if (a.count != b.count) m |= 1 << 1;
    if (a.static != neg(b.static)) m |= 1 << 2;
    // 8CCA holds a square (mirrored); the others are flags.
    if (a.flags[0] != b.flags[0] or a.flags[1] != b.flags[1] or a.flags[2] != b.flags[2] or a.flags[4] != b.flags[4] or a.flags[3] != (if (b.flags[3] >= 21 and b.flags[3] <= 98) msq(b.flags[3]) else b.flags[3])) m |= 1 << 3;
    if (a.passed[0] != b.passed[1] or a.passed[1] != b.passed[0]) m |= 1 << 4;
    if (a.weak != b.weak) m |= 1 << 5;
    if (a.endgame != neg(b.endgame)) m |= 1 << 6;
    if (a.piece != neg(b.piece)) m |= 1 << 7;
    if (a.threat != neg(b.threat)) m |= 1 << 8;
    if (a.counter != b.counter) m |= 1 << 9;
    if (a.mobility != neg(b.mobility)) m |= 1 << 10;
    if (a.leaf_a != b.leaf_a) m |= 1 << 11;
    if (a.leaf_b != b.leaf_b) m |= 1 << 12;
    if (a.pawn_ending != b.pawn_ending) m |= 1 << 13;
    if (a.raw_pawn != neg(b.raw_pawn)) m |= 1 << 14;
    if (a.activity[0] != b.activity[1] or a.activity[1] != b.activity[0]) m |= 1 << 15;
    return m;
}

/// Term `i` of `term_names`, for the report.
fn termValue(t: *const Terms, i: usize) i32 {
    return switch (i) {
        0 => t.pawn,
        1 => t.count,
        2 => t.static,
        3 => @as(i32, t.flags[0]) | @as(i32, t.flags[1]) << 8 | @as(i32, t.flags[2]) << 16 | @as(i32, t.flags[4]) << 24,
        4 => @as(i32, t.passed[0]) | @as(i32, t.passed[1]) << 8,
        5 => t.weak,
        6 => t.endgame,
        7 => t.piece,
        8 => t.threat,
        9 => t.counter,
        10 => t.mobility,
        11 => t.leaf_a,
        12 => t.leaf_b,
        13 => t.pawn_ending,
        14 => t.raw_pawn,
        else => @as(i32, t.activity[0]) * 1000 + t.activity[1],
    };
}

fn evalTerms(c: *Ctx, side: sn.Side, ply: i16) Terms {
    c.pawn_hash.clear();
    var t: Terms = undefined;
    t.raw_pawn = adapt_eval.pawnEval(&c.work.eval, c.img, if (side == 0) .white else .black);
    an.imageToState(c.img, c.st);
    t.activity = .{ adapt_eval.pieceActivityWhiteFixes(fixes, &c.work.eval, c.img), adapt_eval.pieceActivityBlackFixes(fixes, &c.work.eval, c.img) };
    t.pawn = c.pawnEval(side);
    t.passed = .{ c.img[0xA6C2], c.img[0x9D8C] };
    t.weak = c.img[0x8EB6];
    t.count = c.countAttacked(side);
    const limit2 = std.mem.readInt(i16, c.img[0x9356..][0..2], .little);
    t.static = c.staticEval(side, ply -% limit2);
    t.flags = .{ c.img[0x39AE], c.img[0xA5F5], c.img[0xA8DE], c.img[0x8CCA], c.img[0x9EBA] };
    t.endgame = c.endgameKing(side);
    t.piece = c.pieceEval(side, ply);
    var counter: u8 = 0;
    t.threat = c.threats(side, ply, t.count, &counter);
    t.counter = counter;
    t.mobility = c.kingSafety();
    c.leafAttackMap(side);
    t.leaf_a = c.leafTermA(side);
    t.leaf_b = c.leafTermB(side);
    t.pawn_ending = c.pawnEndingTerm(side);
    return t;
}

// A move generator of the walk's own, independent of the original's (which writes the
// image's work areas): pseudo-legal moves from the board, kept when the mover's king is
// not attacked afterwards.
const knight_steps = [_]i8{ -21, -19, -12, -8, 8, 12, 19, 21 };
const king_steps = [_]i8{ -11, -10, -9, -1, 1, 9, 10, 11 };
const diag_steps = [_]i8{ -11, -9, 9, 11 };
const line_steps = [_]i8{ -10, -1, 1, 10 };

fn colourOf(code: u8) ?u1 {
    if (code >= 1 and code <= 6) return 0;
    if (code >= 8 and code <= 13) return 1;
    return null;
}

fn at(b: *const [120]u8, s: i16) u8 {
    if (s < 0 or s >= 120) return pos.border;
    return b[@intCast(s)];
}

/// Whether `by` attacks `sq` on board `b`.
fn attacked(b: *const [120]u8, sq: u8, by: u1) bool {
    const off: u8 = 7 * @as(u8, by);
    const s: i16 = sq;
    // pawns: a White pawn on x attacks x + 9 and x + 11
    const pd: i16 = if (by == 0) -1 else 1;
    if (at(b, s + pd * 9) == 1 + off or at(b, s + pd * 11) == 1 + off) return true;
    for (knight_steps) |d| if (at(b, s + d) == 2 + off) return true;
    for (king_steps) |d| if (at(b, s + d) == 6 + off) return true;
    for (diag_steps) |d| {
        var t = s + d;
        while (at(b, t) == 0) t += d;
        const c = at(b, t);
        if (c == 3 + off or c == 5 + off) return true;
    }
    for (line_steps) |d| {
        var t = s + d;
        while (at(b, t) == 0) t += d;
        const c = at(b, t);
        if (c == 4 + off or c == 5 + off) return true;
    }
    return false;
}

const MoveBuf = struct {
    m: [256]pos.Move = undefined,
    n: usize = 0,
    fn add(mb: *MoveBuf, from: u8, to: u8, flag: u8) void {
        if (mb.n < mb.m.len) {
            mb.m[mb.n] = .{ .from = from, .to = to, .flag = flag };
            mb.n += 1;
        }
    }
};

/// Legal moves of `side` in `p`; `ep` is the square a pawn passed over on the last move
/// (0 for none).
fn legalMoves(p: *const Position, side: u1, ep: u8, out: *MoveBuf) void {
    out.n = 0;
    var pseudo: MoveBuf = .{};
    const b = &p.board;
    const off: u8 = 7 * @as(u8, side);
    const fwd: i16 = if (side == 0) 10 else -10;
    for (21..99) |fs| {
        const code = b[fs];
        if (colourOf(code) != side) continue;
        const from: u8 = @intCast(fs);
        const s: i16 = from;
        switch (code - off) {
            1 => {
                const last_rank = if (side == 0) s + fwd >= 91 else s + fwd <= 28;
                const one = s + fwd;
                const flags: []const u8 = if (last_rank) &.{ 5, 2, 3, 4 } else &.{0};
                if (at(b, one) == 0) {
                    for (flags) |f| pseudo.add(from, @intCast(one), f);
                    const home = if (side == 0) from / 10 == 3 else from / 10 == 8;
                    if (home and at(b, one + fwd) == 0) pseudo.add(from, @intCast(one + fwd), 0);
                }
                for ([_]i16{ fwd - 1, fwd + 1 }) |d| {
                    const t = s + d;
                    const c = at(b, t);
                    if (colourOf(c)) |cc| if (cc != side and c - 7 * @as(u8, cc) != 6) {
                        for (flags) |f| pseudo.add(from, @intCast(t), f);
                    };
                    if (ep != 0 and t == ep) pseudo.add(from, ep, pos.flag_en_passant);
                }
            },
            2, 6 => {
                const steps: []const i8 = if (code - off == 2) &knight_steps else &king_steps;
                for (steps) |d| {
                    const t = s + d;
                    const c = at(b, t);
                    if (c == pos.border) continue;
                    if (colourOf(c)) |cc| if (cc == side or c - 7 * @as(u8, cc) == 6) continue;
                    pseudo.add(from, @intCast(t), 0);
                }
            },
            3, 4, 5 => {
                const k = code - off;
                const sets = [2][]const i8{ if (k != 4) &diag_steps else &.{}, if (k != 3) &line_steps else &.{} };
                for (sets) |steps| for (steps) |d| {
                    var t = s + d;
                    while (true) : (t += d) {
                        const c = at(b, t);
                        if (c == pos.border) break;
                        if (colourOf(c)) |cc| {
                            if (cc != side and c - 7 * @as(u8, cc) != 6) pseudo.add(from, @intCast(t), 0);
                            break;
                        }
                        pseudo.add(from, @intCast(t), 0);
                    }
                };
            },
            else => {},
        }
    }
    // Castling, with the rights the engine keeps (oo_lost_at / ooo_lost_at 0) and the rook
    // and king at home.
    const ks: u8 = if (side == 0) 25 else 95;
    if (b[ks] == 6 + off and !attacked(b, ks, 1 - side)) {
        if (p.oo_lost_at[side] == 0 and b[ks + 3] == 4 + off and b[ks + 1] == 0 and b[ks + 2] == 0 and !attacked(b, ks + 1, 1 - side) and !attacked(b, ks + 2, 1 - side))
            pseudo.add(ks, ks + 2, pos.flag_castle);
        if (p.ooo_lost_at[side] == 0 and b[ks - 4] == 4 + off and b[ks - 1] == 0 and b[ks - 2] == 0 and b[ks - 3] == 0 and !attacked(b, ks - 1, 1 - side) and !attacked(b, ks - 2, 1 - side))
            pseudo.add(ks, ks - 2, pos.flag_castle);
    }
    const ps: pos.Side = if (side == 0) .white else .black;
    for (pseudo.m[0..pseudo.n]) |mv| {
        var q = p.*;
        var u: pos.Undo = .{};
        q.makeMove(mv, ps, 2, &u);
        var ksq: u8 = 0;
        for (21..99) |x| if (q.board[x] == 6 + off) {
            ksq = @intCast(x);
        };
        if (ksq == 0 or attacked(&q.board, ksq, 1 - side)) continue;
        out.add(mv.from, mv.to, mv.flag);
    }
}

const gens = [_]am.Generator{ .all_moves, .tactical, .tactical_no_losers, .quiescence, .captures };

const GenTally = struct {
    lists: [gens.len + 1]usize = @splat(0),
    /// The mirror's list is not the mirror of the root's as a set (moves with their flags
    /// and score bytes), or the counts differ.
    set_differs: [gens.len + 1]usize = @splat(0),
    /// Equal as sets, in a different order.
    order_differs: [gens.len + 1]usize = @splat(0),
    /// Of `set_differs`: the same moves, a score byte different.
    score_only: [gens.len + 1]usize = @splat(0),
    example: [gens.len + 1]?struct { fen: [100]u8, len: usize } = @splat(null),
};

fn listOf(img: *const Image, ply: usize, n: u16) []const pos.Move {
    return std.mem.bytesAsSlice(pos.Move, img[am.listAddr(ply)..][0 .. 4 * @as(usize, @min(n, 100))]);
}

/// Every generator on scratch copies of the two images, compared.
fn compareGenerators(imgR: *const Image, imgM: *const Image, side: u1, ply: usize, in_check: bool, sR: *Image, sM: *Image, buf: *am.GenStateBuf, t: *GenTally, d: *const fen.Description) void {
    const sideR: pos.Side = if (side == 0) .white else .black;
    const sideM: pos.Side = if (side == 0) .black else .white;
    for (0..gens.len + 1) |gi| {
        // gen_evasions reads the check record of the ply (DG:8C06), which make_move writes:
        // at the walk's first node it holds what the root left, so it is compared from ply 2.
        if (gi == gens.len and (!in_check or ply < 2)) continue;
        @memcpy(sR, imgR);
        @memcpy(sM, imgM);
        const nR = if (gi < gens.len) am.generateFixes(buf, sR, mg.Fixes.corrected, fixes, gens[gi], sideR, ply, .{}) else am.genEvasions(buf, sR, sideR, ply);
        const nM = if (gi < gens.len) am.generateFixes(buf, sM, mg.Fixes.corrected, fixes, gens[gi], sideM, ply, .{}) else am.genEvasions(buf, sM, sideM, ply);
        t.lists[gi] += 1;
        var set_ok = nR == nM;
        var order_ok = set_ok;
        var moves_ok = set_ok;
        if (set_ok and nR != mg.king_capture) {
            const lR = listOf(sR, ply, nR);
            const lM = listOf(sM, ply, nM);
            for (lR, lM) |a, b| {
                if (a.from != msq(b.from) or a.to != msq(b.to) or a.flag != b.flag or a.score != b.score) order_ok = false;
            }
            if (!order_ok) {
                for (lR) |a| {
                    var found = false;
                    var found_move = false;
                    for (lM) |b| {
                        if (a.from == msq(b.from) and a.to == msq(b.to) and a.flag == b.flag) {
                            found_move = true;
                            if (a.score == b.score) found = true;
                        }
                    }
                    if (!found) set_ok = false;
                    if (!found_move) moves_ok = false;
                }
            }
        }
        if (moves_ok and !set_ok) t.score_only[gi] += 1;
        if (!set_ok) {
            t.set_differs[gi] += 1;
            if (t.example[gi] == null) {
                t.example[gi] = .{ .fen = undefined, .len = 0 };
                t.example[gi].?.len = fenText(d, &t.example[gi].?.fen).len;
            }
        } else if (!order_ok) t.order_differs[gi] += 1;
    }
}

/// The exchange evaluators on the two images' positions, compared.
fn compareExchanges(imgR: *const Image, imgM: *const Image, t: *LeafTally, d: *const fen.Description) void {
    var pR: Position = .{};
    var pM: Position = .{};
    ap.PositionMap.load(&pR, imgR);
    ap.PositionMap.load(&pM, imgM);
    for (21..99) |s| {
        if (s % 10 == 0 or s % 10 == 9) continue;
        const sq: u8 = @intCast(s);
        if (pR.board[sq] == pos.white_king or pR.board[sq] == pos.black_king) continue;
        for ([_]pos.Side{ .white, .black }) |sd| {
            const ms: pos.Side = if (sd == .white) .black else .white;
            for ([_]u16{ 3, 9, 15, 27 }) |v| {
                var sR: see_mod.Scratch = .{};
                var sM: see_mod.Scratch = .{};
                const a = see_mod.see(&pR, &sR, sd, sq, v);
                const b = see_mod.see(&pM, &sM, ms, msq(sq), v);
                t.see_calls += 1;
                if (a != b) {
                    t.see_differ += 1;
                    if (t.see_example == null) {
                        var buf: [100]u8 = @splat(0);
                        var fb: [100]u8 = undefined;
                        _ = std.fmt.bufPrint(&buf, "{s} sq {d} {s} v {d}: {d} / {d}", .{ fenText(d, &fb), sq, @tagName(sd), v, @as(i16, @bitCast(a)), @as(i16, @bitCast(b)) }) catch "";
                        t.see_example = buf;
                    }
                }
                sR = .{};
                sM = .{};
                const x = pinexchange.exchangeFixes(fixes, &pR, &sR, sd, sq, v);
                const y = pinexchange.exchangeFixes(fixes, &pM, &sM, ms, msq(sq), v);
                t.att_calls += 1;
                if (x != y) {
                    t.att_differ += 1;
                    if (t.att_example == null) {
                        var buf: [100]u8 = @splat(0);
                        var fb: [100]u8 = undefined;
                        _ = std.fmt.bufPrint(&buf, "{s} sq {d} {s} v {d}: {d} / {d}", .{ fenText(d, &fb), sq, @tagName(sd), v, @as(i16, @bitCast(x)), @as(i16, @bitCast(y)) }) catch "";
                        t.att_example = buf;
                    }
                }
            }
        }
    }
}

const LeafExample = struct { fen: [100]u8, len: usize, ply: i16, men: usize, a: Terms, b: Terms, root: [100]u8 = undefined, root_len: usize = 0, moves: [16]pos.Move = undefined, n_moves: usize = 0, depth: i16 = 0 };

const LeafTally = struct {
    nodes: usize = 0,
    walks: usize = 0,
    /// Nodes where at least one term differs.
    nodes_differ: usize = 0,
    by_term: [term_names.len]usize = @splat(0),
    /// Of `by_term`: the rounding of an arithmetic shift alone (`rounding`).
    by_round: [term_names.len]usize = @splat(0),
    /// The differing node (not rounding alone) with the fewest men, per term.
    example: [term_names.len]?LeafExample = @splat(null),
    /// More examples of static_eval (term 2) and 0EF8:0006 (term 7), the fewest men first.
    more: [2][6]?LeafExample = @splat(@splat(null)),
    gen: GenTally = .{},
    /// The exchange evaluators (see.zig, 2B9F:C32A / CAC2; pinexchange.zig, 4793:41B6 /
    /// 4CEC) on every square of the node, for either side capturing first, with each
    /// capturer value, fresh work areas: calls, and calls whose result differs from the
    /// mirror's.
    see_calls: usize = 0,
    see_differ: usize = 0,
    att_calls: usize = 0,
    att_differ: usize = 0,
    see_example: ?[100]u8 = null,
    att_example: ?[100]u8 = null,
    in_check: usize = 0,
    captures: usize = 0,
    promotions: usize = 0,
    castlings: usize = 0,
    ep: usize = 0,
};

const Pair = struct {
    cR: Ctx,
    cM: Ctx,
    sR: *Image,
    sM: *Image,
    gbuf: *am.GenStateBuf,

    fn init(gpa: std.mem.Allocator, e: *Eng) !Pair {
        var pr: Pair = undefined;
        inline for (.{ "cR", "cM" }) |f| {
            const img = try gpa.create(Image);
            const st = try gpa.create(sn.State);
            st.* = .{};
            const work = try gpa.create(an.Work);
            work.* = .{};
            const ph = try gpa.create(PawnHash);
            ph.* = .{};
            @field(pr, f) = .{ .img = img, .st = st, .work = work, .pawn_hash = ph, .tables = e.root.tables, .game_keys = e.root.rec.keys[0..], .gpa = gpa };
        }
        pr.sR = try gpa.create(Image);
        pr.sM = try gpa.create(Image);
        pr.gbuf = try gpa.create(am.GenStateBuf);
        pr.gbuf.* = .{};
        return pr;
    }

    fn deinit(pr: *Pair, gpa: std.mem.Allocator) void {
        inline for (.{ "cR", "cM" }) |f| {
            const c = &@field(pr, f);
            gpa.destroy(c.img);
            gpa.destroy(c.st);
            gpa.destroy(c.work);
            gpa.destroy(c.pawn_hash);
        }
        gpa.destroy(pr.sR);
        gpa.destroy(pr.sM);
        gpa.destroy(pr.gbuf);
    }
};

/// One random walk from the two prepared images, the terms compared at every node.
fn walk(pr: *Pair, imgR: *const Image, imgM: *const Image, side0: u1, len: usize, r: std.Random, t: *LeafTally, compare_gens: bool, root: *const fen.Description, depth: i16) void {
    var played: [16]pos.Move = undefined;
    pr.cR.img.* = imgR.*;
    pr.cM.img.* = imgM.*;
    an.imageToState(pr.cR.img, pr.cR.st);
    an.imageToState(pr.cM.img, pr.cM.st);
    t.walks += 1;
    var side = side0;
    var ep: u8 = 0;
    var k: usize = 0;
    while (true) : (k += 1) {
        const ply: i16 = @intCast(1 + k);
        var p: Position = .{};
        ap.PositionMap.load(&p, pr.cR.img);
        const a = evalTerms(&pr.cR, side, ply);
        const b = evalTerms(&pr.cM, 1 - side, ply);
        t.nodes += 1;
        const dm = differ(&a, &b);
        const rm = rounding(&a, &b, p.pawn_count == 0, p.pawn_count);
        const d: fen.Description = .{ .board = p.board, .side_to_move = if (side == 0) .white else .black, .castling = .none, .en_passant = null, .halfmove_clock = 0, .fullmove_number = 1 };
        if (dm != 0) {
            t.nodes_differ += 1;
            var men: usize = 0;
            for (21..99) |x| men += @intFromBool(colourOf(p.board[x]) != null);
            for (0..term_names.len) |i| if (dm & (@as(u32, 1) << @intCast(i)) != 0) {
                t.by_term[i] += 1;
                if (rm & (@as(u32, 1) << @intCast(i)) != 0) {
                    t.by_round[i] += 1;
                    continue;
                }
                if (i == 2 or i == 7) {
                    const row = &t.more[if (i == 2) 0 else 1];
                    var worst: usize = 0;
                    for (row, 0..) |x, q| {
                        if (x == null) {
                            worst = q;
                            break;
                        }
                        if (x.?.men > row[worst].?.men) worst = q;
                    }
                    if (row[worst] == null or row[worst].?.men > men) {
                        row[worst] = .{ .fen = undefined, .len = 0, .ply = ply, .men = men, .a = a, .b = b };
                        row[worst].?.len = fenText(&d, &row[worst].?.fen).len;
                        row[worst].?.root_len = fenText(root, &row[worst].?.root).len;
                        row[worst].?.n_moves = @min(k, 16);
                        row[worst].?.depth = depth;
                        @memcpy(row[worst].?.moves[0..@min(k, 16)], played[0..@min(k, 16)]);
                    }
                }
                if (t.example[i] == null or t.example[i].?.men > men) {
                    t.example[i] = .{ .fen = undefined, .len = 0, .ply = ply, .men = men, .a = a, .b = b };
                    t.example[i].?.len = fenText(&d, &t.example[i].?.fen).len;
                    t.example[i].?.root_len = fenText(root, &t.example[i].?.root).len;
                    t.example[i].?.n_moves = k;
                    t.example[i].?.depth = depth;
                    @memcpy(t.example[i].?.moves[0..k], played[0..k]);
                }
            };
        }
        var ksq: u8 = 0;
        for (21..99) |x| if (p.board[x] == 6 + 7 * @as(u8, side)) {
            ksq = @intCast(x);
        };
        const in_check = ksq != 0 and attacked(&p.board, ksq, 1 - side);
        if (in_check) t.in_check += 1;
        // The exchange evaluators at every third node (each node costs 2,000 or so calls).
        if (compare_gens and t.nodes % 3 == 0) compareExchanges(pr.cR.img, pr.cM.img, t, &d);
        if (compare_gens) compareGenerators(pr.cR.img, pr.cM.img, side, @intCast(ply), in_check, pr.sR, pr.sM, pr.gbuf, &t.gen, &d);
        if (k >= len) break;
        var moves: MoveBuf = .{};
        legalMoves(&p, side, ep, &moves);
        if (moves.n == 0) break;
        // Half the time a capture or promotion when there is one.
        var pick = moves.m[@as(usize, @intCast(r.uintLessThan(u64, moves.n)))];
        if (r.boolean()) {
            var caps: usize = 0;
            for (moves.m[0..moves.n]) |m| caps += @intFromBool(p.board[m.to] != 0 or m.flag != 0);
            if (caps > 0) {
                var j = @as(usize, @intCast(r.uintLessThan(u64, caps)));
                for (moves.m[0..moves.n]) |m| if (p.board[m.to] != 0 or m.flag != 0) {
                    if (j == 0) {
                        pick = m;
                        break;
                    }
                    j -= 1;
                };
            }
        }
        if (p.board[pick.to] != 0) t.captures += 1;
        if (pick.flag >= 2 and pick.flag <= 5) t.promotions += 1;
        if (pick.flag == pos.flag_castle) t.castlings += 1;
        if (pick.flag == pos.flag_en_passant) t.ep += 1;
        const mirrored: pos.Move = .{ .from = msq(pick.from), .to = msq(pick.to), .flag = pick.flag };
        var uR: pos.Undo = .{};
        var uM: pos.Undo = .{};
        if (k < played.len) played[k] = pick;
        pr.cR.applyMove(side, ply + 1, pick, &uR);
        pr.cM.applyMove(1 - side, ply + 1, mirrored, &uM);
        const pawn = p.board[pick.from] == 1 + 7 * @as(u8, side);
        const dist = @abs(@as(i16, pick.to) - @as(i16, pick.from));
        ep = if (pawn and dist == 20) @intCast((@as(u16, pick.from) + pick.to) / 2) else 0;
        side = 1 - side;
    }
}

fn reportLeaf(what: []const u8, t: *const LeafTally) void {
    std.debug.print("eval mirror, leaf terms, {s}: {d} walks, {d} nodes ({d} in check; moves played: {d} captures, {d} promotions, {d} castlings, {d} en passant); nodes where a term differs: {d}\n", .{ what, t.walks, t.nodes, t.in_check, t.captures, t.promotions, t.castlings, t.ep, t.nodes_differ });
    for (term_names, t.by_term, t.by_round, t.example, 0..) |n, c, cr, ex, i| {
        if (c == 0) continue;
        std.debug.print("  {s}: {d} ({d} the rounding of a shift alone)", .{ n, c, cr });
        if (ex) |x| {
            std.debug.print("; fewest men {s} ply {d}: {d} / {d}; from the root {s} (depth {d}) by", .{ x.fen[0..x.len], x.ply, termValue(&x.a, i), termValue(&x.b, i), x.root[0..x.root_len], x.depth });
            for (x.moves[0..x.n_moves]) |mv| std.debug.print(" {d}-{d}/{d}", .{ mv.from, mv.to, mv.flag });
        }
        std.debug.print("\n", .{});
    }
    for (t.more, 0..) |row, q| for (row) |ex| if (ex) |x| {
        std.debug.print("  more {s}: {s} ply {d}: {d} / {d}; from {s} (depth {d}) by", .{ if (q == 0) "static_eval" else "0006", x.fen[0..x.len], x.ply, termValue(&x.a, if (q == 0) 2 else 7), termValue(&x.b, if (q == 0) 2 else 7), x.root[0..x.root_len], x.depth });
        for (x.moves[0..x.n_moves]) |mv| std.debug.print(" {d}-{d}/{d}", .{ mv.from, mv.to, mv.flag });
        std.debug.print("\n", .{});
    };
    std.debug.print("  exchange (see.zig): {d} calls, {d} differ", .{ t.see_calls, t.see_differ });
    if (t.see_example) |x| std.debug.print("; first {s}", .{std.mem.sliceTo(&x, 0)});
    std.debug.print("\n  pin-aware exchange (pinexchange.zig): {d} calls, {d} differ", .{ t.att_calls, t.att_differ });
    if (t.att_example) |x| std.debug.print("; first {s}", .{std.mem.sliceTo(&x, 0)});
    std.debug.print("\n", .{});
    const gnames = [_][]const u8{ "gen_all_moves", "gen_tactical_moves", "gen_tactical_moves_no_losers", "gen_quiescence_moves", "gen_captures", "gen_evasions" };
    for (gnames, 0..) |n, i| {
        if (t.gen.lists[i] == 0) continue;
        std.debug.print("  generator {s}: {d} lists; not the mirror as a set {d} (of which the same moves with a score byte different {d}); the mirror's set in another order {d}", .{ n, t.gen.lists[i], t.gen.set_differs[i], t.gen.score_only[i], t.gen.order_differs[i] });
        if (t.gen.example[i]) |x| std.debug.print("; first {s}", .{x.fen[0..x.len]});
        std.debug.print("\n", .{});
    }
}

const Run = struct {
    tables: TableTally = .{},
    /// Walks from roots whose tables are each other's mirror, and from the others.
    leaf: LeafTally = .{},
    leaf_asym: LeafTally = .{},
    refused: usize = 0,
};

/// Levels 1 and 2 for every root of `roots`: each root and its mirror prepared (the
/// mirror's slots taken from the root's when `remap`), the tables compared, then `walks`
/// random walks of up to `walk_len` plies.
fn runRoots(gpa: std.mem.Allocator, roots: []const fen.Description, remap: bool, walks: usize, walk_len: usize, seed: u64, compare_gens: bool) !Run {
    const e = try gpa.create(Eng);
    defer gpa.destroy(e);
    e.* = try Eng.init(gpa);
    defer e.deinit();
    e.reporting = false;
    e.setTablebases(false);
    var pr = try Pair.init(gpa, e);
    defer pr.deinit(gpa);
    const imgR = try gpa.create(Image);
    defer gpa.destroy(imgR);
    const imgM = try gpa.create(Image);
    defer gpa.destroy(imgM);
    var run: Run = .{};
    var prng: std.Random.DefaultPrng = .init(seed);
    const r = prng.random();
    for (roots) |*d| {
        const m = mirrorDesc(d);
        var setup_pos: Position = .{};
        if (!prepareRoot(e, d, null, &setup_pos)) {
            run.refused += 1;
            continue;
        }
        imgR.* = e.root.test_img.*;
        if (!prepareRoot(e, &m, if (remap) &setup_pos else null, null)) {
            run.refused += 1;
            continue;
        }
        imgM.* = e.root.test_img.*;
        var tR: et.TableValues = .{};
        var tM: et.TableValues = .{};
        adapt_eval.TablesMap.load(&tR, imgR);
        adapt_eval.TablesMap.load(&tM, imgM);
        const sym = compareTables(&tR, &tM, d, &run.tables);
        const tally = if (sym) &run.leaf else &run.leaf_asym;
        const depth: i16 = 1 + @as(i16, r.uintLessThan(u8, 4));
        setLimits(imgR, depth);
        setLimits(imgM, depth);
        const side0: u1 = if (d.side_to_move == .white) 0 else 1;
        for (0..walks) |_| walk(&pr, imgR, imgM, side0, @as(usize, @intCast(r.uintLessThan(u64, walk_len + 1))), r, tally, compare_gens, d, depth);
    }
    return run;
}

fn longTests() bool {
    return std.testing.environ.containsUnempty(std.testing.allocator, "MCHESS_LONG_TESTS") catch false;
}

fn randomRoots(arena: std.mem.Allocator, n: usize, seed: u64) ![]fen.Description {
    var prng: std.Random.DefaultPrng = .init(seed);
    const out = try arena.alloc(fen.Description, n);
    for (out) |*d| d.* = randomDesc(prng.random());
    return out;
}

// ---- the present state, asserted ---------------------------------------------------------
//
// The counts below are those of the sets as built here (constant seeds, the same in every
// build mode). Where the evaluation is symmetric the count is 0. Where it is not, the
// count is exact and names its cause (docs/arch/50-evaluation-map.md section 14; the
// candidates DEV-054 to DEV-061 of docs/DEVIATIONS.md): a correction
// of one of them must update the counts it changes, and nothing else may change them.

/// What one run is expected to give: the roots whose tables differ, per check of `checks`
/// (only the ones named; every other check 0), and for the walks from roots whose tables
/// are each other's mirror (`leaf`) and from the others (`leaf_asym`): per term of
/// `term_names` the nodes that differ and, of them, those that are a shift's rounding; per
/// generator the lists that are not the mirror's as a set.
const Expect = struct {
    roots: usize,
    refused: usize,
    tables: []const struct { []const u8, usize },
    leaf: Leaf,
    leaf_asym: Leaf,

    const Leaf = struct {
        nodes: usize,
        by_term: [term_names.len]usize,
        by_round: [term_names.len]usize,
        gen_set: [gens.len + 1]usize,
    };
};

fn expectLeaf(what: []const u8, e: *const Expect.Leaf, t: *const LeafTally) !void {
    errdefer std.debug.print("eval mirror: {s}: the counts have changed; now nodes {d}, by_term {any}, by_round {any}, gen_set {any}\n", .{ what, t.nodes, t.by_term, t.by_round, t.gen.set_differs });
    try std.testing.expectEqual(e.nodes, t.nodes);
    try std.testing.expectEqualSlices(usize, &e.by_term, &t.by_term);
    try std.testing.expectEqualSlices(usize, &e.by_round, &t.by_round);
    try std.testing.expectEqualSlices(usize, &e.gen_set, &t.gen.set_differs);
    // The exchange evaluators are each other's mirror on every call (pieces on the board).
    try std.testing.expectEqual(@as(usize, 0), t.see_differ);
    try std.testing.expectEqual(@as(usize, 0), t.att_differ);
}

fn expectRun(what: []const u8, e: *const Expect, run: *const Run) !void {
    @setEvalBranchQuota(100_000);
    errdefer printExpect(what, run);
    try std.testing.expectEqual(e.roots, run.tables.roots);
    try std.testing.expectEqual(e.refused, run.refused);
    inline for (checks, 0..) |c, i| {
        var want: usize = 0;
        for (e.tables) |x| {
            if (std.mem.eql(u8, x[0], c.name)) want = x[1];
        }
        if (run.tables.fails[i] != want) {
            std.debug.print("eval mirror: {s}: table check \"{s}\" differs in {d} roots, expected {d}\n", .{ what, c.name, run.tables.fails[i], want });
            return error.TestExpectedEqual;
        }
    }
    try expectLeaf(what, &e.leaf, &run.leaf);
    try expectLeaf(what, &e.leaf_asym, &run.leaf_asym);
}

/// The terms that are symmetric in every run with the mirror's slots taken from the root's:
/// the attacked-piece count, static_eval's flags, the passed- and weak-pawn masks, the
/// endgame king term, the two leaf terms (indices of `term_names`).
const always_symmetric = [_]usize{ 1, 3, 4, 5, 6, 11, 12 };

/// For the long runs, whose counts are not recorded: what must hold in any set.
fn expectInvariants(run: *const Run) !void {
    @setEvalBranchQuota(100_000);
    for (always_symmetric) |i| {
        try std.testing.expectEqual(@as(usize, 0), run.leaf.by_term[i]);
        try std.testing.expectEqual(@as(usize, 0), run.leaf_asym.by_term[i]);
    }
    // With the tables each other's mirror: the pawn evaluation and the mobility term
    // differ only by a shift's rounding; the activity routines not at all.
    for ([_]usize{ 0, 10, 14 }) |i| try std.testing.expectEqual(run.leaf.by_round[i], run.leaf.by_term[i]);
    for ([_]usize{ 13, 15 }) |i| try std.testing.expectEqual(@as(usize, 0), run.leaf.by_term[i]);
    for ([_]*const LeafTally{ &run.leaf, &run.leaf_asym }) |t| {
        try std.testing.expectEqual(@as(usize, 0), t.see_differ);
        try std.testing.expectEqual(@as(usize, 0), t.att_differ);
        // gen_captures and gen_evasions are each other's mirror as sets.
        try std.testing.expectEqual(@as(usize, 0), t.gen.set_differs[4]);
        try std.testing.expectEqual(@as(usize, 0), t.gen.set_differs[5]);
    }
    // Every table but the centrality around the kings (DEV-056) and the four activity
    // tables made from it.
    inline for (checks, 0..) |c, i| {
        const derived = comptime std.mem.startsWith(u8, c.name, "centrality") or std.mem.indexOf(u8, c.name, "activity") != null;
        if (!derived) try std.testing.expectEqual(@as(usize, 0), run.tables.fails[i]);
    }
}

/// The run as an `Expect` literal, printed when a run differs from its expectation.
fn printExpect(what: []const u8, run: *const Run) void {
    std.debug.print("eval mirror, {s}, as found: .{{ .roots = {d}, .refused = {d}, .tables = &.{{", .{ what, run.tables.roots, run.refused });
    for (checks, run.tables.fails) |c, n| if (n != 0) std.debug.print(" .{{ \"{s}\", {d} }},", .{ c.name, n });
    std.debug.print(" }}", .{});
    inline for (.{ "leaf", "leaf_asym" }) |name| {
        const l = &@field(run, name);
        std.debug.print(", .{s} = .{{ .nodes = {d}, .by_term = .{any}, .by_round = .{any}, .gen_set = .{any} }}", .{ name, l.nodes, l.by_term, l.by_round, l.gen.set_differs });
    }
    std.debug.print(" }}\n", .{});
}

fn report(what: []const u8, run: *const Run) void {
    reportTables(what, &run.tables);
    std.debug.print("eval mirror, {s}: {d} roots refused by Setup or not reaching the iteration loop\n", .{ what, run.refused });
    reportLeaf("roots with mirrored tables", &run.leaf);
    reportLeaf("roots whose tables differ", &run.leaf_asym);
}

// DEV-056 changes the centrality around the kings, and through it the four activity tables.
const dev_c_golden = [_]struct { []const u8, usize }{
    .{ "centrality B522 / B5A8", 14 },
    .{ "knight activity A84E / A9B4", 14 },
    .{ "bishop activity A2F0 / A390", 14 },
    .{ "rook activity ABA0 / AFC6", 14 },
    .{ "queen activity AB20 / ADBE", 14 },
};

// Terms (`term_names`): 0 pawn evaluation, 2 static_eval, 7 0EF8:0006, 8 threats, 10
// mobility, 13 crossed activity, 14 the pawn evaluator unscaled, 15 both activities.
// Generators: gen_all_moves, gen_tactical_moves, then the four others.
// - by_round, 0, 10, 14 (and 2 without pawns): an arithmetic shift's rounding (class D).
// - static_eval otherwise: DEV-054, DEV-055, DEV-061. 0006: DEV-059. Threats: DEV-058.
// - leaf_asym, 10, 13, 15: the activity tables of DEV-056.
// - gen_set: DEV-057 (both), DEV-060 (gen_tactical_moves).
const expect_golden: Expect = .{
    .roots = 405,
    .refused = 0,
    .tables = &dev_c_golden,
    .leaf = .{ .nodes = 9371, .by_term = .{ 2280, 0, 2, 0, 0, 0, 0, 0, 0, 0, 8170, 0, 0, 0, 1504, 0 }, .by_round = .{ 2280, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8170, 0, 0, 0, 1504, 0 }, .gen_set = .{ 167, 272, 0, 0, 0, 0 } },
    .leaf_asym = .{ .nodes = 309, .by_term = .{ 26, 0, 0, 0, 0, 0, 0, 0, 0, 0, 287, 0, 0, 194, 14, 285 }, .by_round = .{ 26, 0, 0, 0, 0, 0, 0, 0, 0, 0, 22, 0, 0, 0, 14, 0 }, .gen_set = .{ 23, 53, 0, 0, 0, 0 } },
};

const dev_c_generated = [_]struct { []const u8, usize }{
    .{ "centrality B522 / B5A8", 106 },
    .{ "knight activity A84E / A9B4", 106 },
    .{ "bishop activity A2F0 / A390", 106 },
    .{ "rook activity ABA0 / AFC6", 106 },
    .{ "queen activity AB20 / ADBE", 106 },
};

const expect_generated: Expect = .{
    .roots = 373,
    .refused = 227,
    .tables = &dev_c_generated,
    .leaf = .{ .nodes = 5353, .by_term = .{ 3510, 0, 330, 0, 0, 0, 0, 1, 4, 0, 4743, 0, 0, 0, 2346, 0 }, .by_round = .{ 3510, 0, 8, 0, 0, 0, 0, 0, 0, 0, 4743, 0, 0, 0, 2346, 0 }, .gen_set = .{ 164, 211, 0, 0, 0, 0 } },
    .leaf_asym = .{ .nodes = 2077, .by_term = .{ 702, 0, 167, 0, 0, 0, 0, 0, 0, 0, 1669, 0, 0, 1084, 690, 1600 }, .by_round = .{ 702, 0, 9, 0, 0, 0, 0, 0, 0, 0, 445, 0, 0, 0, 690, 0 }, .gen_set = .{ 158, 196, 0, 0, 0, 0 } },
};

test "eval mirror, without the five mirror fixes: the golden files' positions, prepare_eval and the leaf terms against the mirror" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena_state.deinit();
    const roots = try loadGolden(arena_state.allocator());
    const run = try runRoots(gpa, roots, true, 4, 10, 0xE7A1_0001, true);
    report("golden", &run);
    try expectInvariants(&run);
    try expectRun("golden", &expect_golden, &run);
}

test "eval mirror, without the five mirror fixes: generated positions, prepare_eval and the leaf terms against the mirror" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena_state.deinit();
    const roots = try randomRoots(arena_state.allocator(), 600, 0xE7A1_0002);
    const run = try runRoots(gpa, roots, true, 4, 8, 0xE7A1_0003, true);
    report("generated", &run);
    try expectInvariants(&run);
    try expectRun("generated", &expect_generated, &run);
}

// ---- a position for each difference ------------------------------------------------------

/// A root (Setup's route), the ply limits of depth `depth`, and moves played from it (each
/// mirrored for the mirror); the terms at the node reached, for the root's side of the
/// board and the mirror's.
const Case = struct {
    what: []const u8,
    root: []const u8,
    depth: i16,
    moves: []const [3]u8 = &.{},
    /// The term of `term_names`, and its value at the node and at the mirror's node.
    term: usize,
    value: i32,
    mirror_value: i32,
};

fn nodeOf(e: *Eng, pr: *Pair, c: *const Case) !u1 {
    var d = try fen.parse(c.root);
    d.castling = adapt_setup.rightsFromBoard(&d.board);
    const md = mirrorDesc(&d);
    var sp: Position = .{};
    try std.testing.expect(prepareRoot(e, &d, null, &sp));
    pr.cR.img.* = e.root.test_img.*;
    try std.testing.expect(prepareRoot(e, &md, &sp, null));
    pr.cM.img.* = e.root.test_img.*;
    setLimits(pr.cR.img, c.depth);
    setLimits(pr.cM.img, c.depth);
    an.imageToState(pr.cR.img, pr.cR.st);
    an.imageToState(pr.cM.img, pr.cM.st);
    var side: u1 = if (d.side_to_move == .white) 0 else 1;
    for (c.moves, 0..) |mv, k| {
        const ply: i16 = @intCast(2 + k);
        var u1_: pos.Undo = .{};
        var u2_: pos.Undo = .{};
        pr.cR.applyMove(side, ply, .{ .from = mv[0], .to = mv[1], .flag = mv[2] }, &u1_);
        pr.cM.applyMove(1 - side, ply, .{ .from = msq(mv[0]), .to = msq(mv[1]), .flag = mv[2] }, &u2_);
        side = 1 - side;
    }
    return side;
}

const term_cases = [_]Case{
    // DEV-054: White K e2, R a1, P h3 against K d4, P f4. With Black to move in the mirror,
    // Black's h-pawn is unstoppable at 2B9F:1E04 (White has no pieces) without the test of
    // White's passed pawns that White's twin makes at 2B9F:2C45: the race term differs by
    // 300 (1260 against 1560).
    .{ .what = "DEV-054", .root = "8/8/8/8/3k1p2/7P/4K3/R7 w", .depth = 2, .term = 2, .value = 1260, .mirror_value = -1560 },
    // DEV-058: a White knight on b3 lifted for its escape squares (0EF8:BE44, entry 0) is
    // seen by the pin-aware exchange on a1 (square 0 + 21); the mirror's knight on b6,
    // lifted the same way, does not reach a8.
    .{ .what = "DEV-058", .root = "4Q3/1Bb3p1/1p2P3/q1PK1p2/P7/rNk1p3/7P/B7 b", .depth = 1, .moves = &.{ .{ 43, 33, 0 }, .{ 38, 48, 0 }, .{ 61, 63, 0 } }, .term = 8, .value = -24, .mirror_value = 48 },
    // DEV-059: the opposite-bishop flag of 0EF8:1ABA reads White's light-bishop slot against
    // Black's (and White's piece count): a promoted Black bishop is in a pawn slot.
    .{ .what = "DEV-059", .root = "8/5P2/2B3p1/2k4K/1N6/2p3r1/3p4/8 w", .depth = 3, .moves = &.{ .{ 68, 78, 0 }, .{ 63, 52, 0 }, .{ 86, 96, 4 }, .{ 47, 37, 0 }, .{ 96, 91, 0 }, .{ 34, 24, 3 } }, .term = 7, .value = -23, .mirror_value = 83 },
    .{ .what = "DEV-059 (White's piece count)", .root = "kn5Q/4P3/8/8/5p1n/1b1KP3/8/8 b", .depth = 4, .moves = &.{ .{ 56, 45, 0 }, .{ 44, 45, 0 } }, .term = 7, .value = -149, .mirror_value = 89 },
    // DEV-061: Black's few-pawns section (2B9F:01C8) runs before White's (0410): against K+N+N
    // its special ending returns before White's -200 for two minor pieces without pawns.
    .{ .what = "DEV-061", .root = "K7/2p5/5P2/8/6Pk/2n5/4p3/8 w", .depth = 1, .moves = &.{ .{ 91, 82, 0 }, .{ 35, 25, 2 }, .{ 82, 92, 0 }, .{ 58, 57, 0 }, .{ 92, 83, 0 } }, .term = 2, .value = -376, .mirror_value = 576 },
};

test "eval mirror, without the five mirror fixes: a position for each difference of the evaluation" {
    const gpa = std.testing.allocator;
    const e = try gpa.create(Eng);
    defer gpa.destroy(e);
    e.* = try Eng.init(gpa);
    defer e.deinit();
    e.reporting = false;
    e.setTablebases(false);
    var pr = try Pair.init(gpa, e);
    defer pr.deinit(gpa);
    for (&term_cases) |*c| {
        const side = try nodeOf(e, &pr, c);
        const ply: i16 = @intCast(1 + c.moves.len);
        const a = evalTerms(&pr.cR, side, ply);
        const b = evalTerms(&pr.cM, 1 - side, ply);
        std.debug.print("eval mirror: {s}: {s}, {s}: {d} / mirror {d}\n", .{ c.what, c.root, term_names[c.term], termValue(&a, c.term), termValue(&b, c.term) });
        try std.testing.expect(differ(&a, &b) & (@as(u32, 1) << @intCast(c.term)) != 0);
        try std.testing.expectEqual(c.value, termValue(&a, c.term));
        try std.testing.expectEqual(c.mirror_value, termValue(&b, c.term));
    }
}

/// The score byte the generator `gen` gives the move `from`-`to` at the node of `c`, for
/// the root and for the mirror.
const GenCase = struct { what: []const u8, root: []const u8, gen: am.Generator, from: u8, to: u8, score: u8, mirror_score: u8 };

const gen_cases = [_]GenCase{
    // DEV-057: the White queen's check Qc7-f4 beside the Black king g5 (offset -11): DG:0CFF
    // gives 21 below the king, 19 above, so the mirror's Qc2-f5 beside the White king g4
    // scores 2 less.
    .{ .what = "DEV-057", .root = "7K/2QpN1pb/5p1p/2pB2kp/B7/3p4/8/5R2 w", .gen = .all_moves, .from = 83, .to = 56, .score = 23, .mirror_score = 21 },
    // DEV-060: a knight that uncovers a check (gen_tactical_moves, 1E9D:57C0): each move is
    // scored the code of the piece taken + 8 (1E9D:580C), Black's codes 7 above White's.
    .{ .what = "DEV-060", .root = "2b4K/p2r1P1P/8/6Q1/N1B2P2/7p/r6P/k1N2R2 w", .gen = .tactical, .from = 23, .to = 31, .score = 19, .mirror_score = 12 },
};

fn scoreOf(img: *Image, buf: *am.GenStateBuf, gen: am.Generator, side: pos.Side, from: u8, to: u8) ?u8 {
    const n = am.generateFixes(buf, img, mg.Fixes.corrected, fixes, gen, side, 1, .{});
    if (n == mg.king_capture) return null;
    for (listOf(img, 1, n)) |m| if (m.from == from and m.to == to) return m.score;
    return null;
}

test "eval mirror, without the five mirror fixes: a position for each difference of the move generators' scores" {
    const gpa = std.testing.allocator;
    const e = try gpa.create(Eng);
    defer gpa.destroy(e);
    e.* = try Eng.init(gpa);
    defer e.deinit();
    e.reporting = false;
    e.setTablebases(false);
    var pr = try Pair.init(gpa, e);
    defer pr.deinit(gpa);
    for (&gen_cases) |*g| {
        const c: Case = .{ .what = g.what, .root = g.root, .depth = 2, .term = 0, .value = 0, .mirror_value = 0 };
        const side = try nodeOf(e, &pr, &c);
        const sR: pos.Side = if (side == 0) .white else .black;
        const sM: pos.Side = if (side == 0) .black else .white;
        const a = scoreOf(pr.cR.img, pr.gbuf, g.gen, sR, g.from, g.to);
        const b = scoreOf(pr.cM.img, pr.gbuf, g.gen, sM, msq(g.from), msq(g.to));
        std.debug.print("eval mirror: {s}: {s}, {s} {d}-{d}: score {?d} / mirror {?d}\n", .{ g.what, g.root, @tagName(g.gen), g.from, g.to, a, b });
        try std.testing.expectEqual(@as(?u8, g.score), a);
        try std.testing.expectEqual(@as(?u8, g.mirror_score), b);
    }
}

test "eval mirror, without the five mirror fixes: DEV-056, the king rings of prepare_eval wrap at the a- and h-files" {
    // The middlegame centrality around each king (0000:AF48-B145) adds to the squares at
    // the 13 offsets of DG:1520 (White) and DG:152E (Black), tested only against the
    // range 21..98: from a king on the h-file the offsets +3, +13, +23, +33 (White) and
    // -7, -17, -27 (Black) land on the a-file of another rank, and their mirrors do not.
    const gpa = std.testing.allocator;
    const e = try gpa.create(Eng);
    defer gpa.destroy(e);
    e.* = try Eng.init(gpa);
    defer e.deinit();
    e.reporting = false;
    e.setTablebases(false);
    var d = try fen.parse("1r5k/3q2pp/5p2/p7/2Q1p3/PP2P3/3r2PP/N1R3K1 w");
    d.castling = adapt_setup.rightsFromBoard(&d.board);
    const md = mirrorDesc(&d);
    var sp: Position = .{};
    const img = try gpa.create(Image);
    defer gpa.destroy(img);
    try std.testing.expect(prepareRoot(e, &d, null, &sp));
    img.* = e.root.test_img.*;
    try std.testing.expect(prepareRoot(e, &md, &sp, null));
    var t: et.TableValues = .{};
    var u: et.TableValues = .{};
    adapt_eval.TablesMap.load(&t, img);
    adapt_eval.TablesMap.load(&u, e.root.test_img);
    // The Black king on h8: its ring reaches a8, a7, a6 (offsets -7, -17, -27): White's
    // centrality there, and the mirror's Black centrality on a1, a2, a3.
    std.debug.print("eval mirror: DEV-056: White centrality a4 {d}, the mirror's Black centrality a5 {d}\n", .{ t.centrality_white[51], u.centrality_black[61] });
    var tally: TableTally = .{};
    _ = compareTables(&t, &u, &d, &tally);
    try std.testing.expectEqual(@as(usize, 1), tally.fails[comptime checkIndex("centrality B522 / B5A8")]);
    try std.testing.expect(t.centrality_white[51] != u.centrality_black[61]);
}

fn checkIndex(comptime name: []const u8) usize {
    @setEvalBranchQuota(100_000);
    for (checks, 0..) |c, i| {
        if (std.mem.eql(u8, c.name, name)) return i;
    }
    @compileError("no check " ++ name);
}

// ---- level 3: the search -----------------------------------------------------------------

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
    fn out(c: *Capture) uci_engine.Output {
        return .{ .ctx = c, .lineFn = lineFn };
    }
    fn lastScore(c: *const Capture) []const u8 {
        var it = std.mem.splitBackwardsScalar(u8, c.buf[0..c.len], '\n');
        while (it.next()) |l| {
            const i = std.mem.indexOf(u8, l, " score ") orelse continue;
            const rest = l[i + 7 ..];
            const sp = std.mem.indexOfScalar(u8, rest, ' ') orelse continue;
            const end = std.mem.indexOfScalarPos(u8, rest, sp + 1, ' ') orelse rest.len;
            return rest[0..end];
        }
        return "";
    }
};

const SearchResult = struct {
    ok: bool = false,
    move: ?fen.UciMove = null,
    nodes: u64 = 0,
    score: [16]u8 = @splat(0),
    score_len: usize = 0,
};

fn searchOne(e: *Eng, d: *const fen.Description, depth: u32, slots_from: ?*const Position, setup_pos: ?*Position, events: *std.ArrayList(@import("engine_root.zig").Event), gpa: std.mem.Allocator) !SearchResult {
    var res: SearchResult = .{};
    if (e.engine().setPosition(d, .setup, &.{}) != null) return res;
    si.imageBegin(e.root);
    if (setup_pos) |sp| {
        sp.* = .{};
        ap.PositionMap.load(sp, e.root.test_img);
    }
    if (slots_from) |src| {
        var p: Position = .{};
        ap.PositionMap.load(&p, e.root.test_img);
        remapSlots(&p, src);
        ap.PositionMap.storeAll(&p, e.root.test_img);
    }
    si.imageEnd(e.root);
    e.root.trace = true;
    defer e.root.trace = false;
    var cap: Capture = .{};
    var sig: uci_engine.Signals = .{};
    const r = e.engine().search(&.{ .depth = depth }, &sig, cap.out());
    res.ok = r.best != null;
    res.move = r.best;
    res.nodes = e.root.nodes;
    // The raw root score, as this test has always counted it: the score sent to a GUI is
    // halved since DEV-F23, and a pair that differs by one unit must still count as
    // different.
    var raw_buf: [16]u8 = undefined;
    const s = if (e.last_score) |raw|
        (if (uci_report.isMate(raw)) uci_report.scoreText(raw, &raw_buf) else std.fmt.bufPrint(&raw_buf, "cp {d}", .{raw}) catch "")
    else
        cap.lastScore();
    res.score_len = @min(s.len, 16);
    @memcpy(res.score[0..res.score_len], s[0..res.score_len]);
    events.clearRetainingCapacity();
    try events.appendSlice(gpa, e.root.events.items);
    return res;
}

const Ev = @import("engine_root.zig").Event;

/// Whether event `a` of the root's search and `b` of the mirror's are each other's mirror.
fn eventMirrors(a: Ev, b: Ev) bool {
    return switch (a) {
        .make => |x| b == .make and b.make.ply == x.ply and msq(b.make.from) == x.from and msq(b.make.to) == x.to and b.make.flag == x.flag,
        .node => |x| b == .node and b.node.side != x.side and b.node.ply == x.ply and b.node.alpha == x.alpha and b.node.beta == x.beta,
        .ply2 => |x| b == .ply2 and b.ply2.side != x.side and b.ply2.alpha == x.alpha and b.ply2.beta == x.beta,
    };
}

const SearchTally = struct {
    pairs: usize = 0,
    refused: usize = 0,
    same_move: usize = 0,
    same_score: usize = 0,
    same_nodes: usize = 0,
    identical_trace: usize = 0,
    /// The first difference of the traces: a make (the move order), a node's window
    /// after the same makes (a value), or the kind of event.
    first_make: usize = 0,
    first_window: usize = 0,
    first_kind: usize = 0,
    nodes_r: u64 = 0,
    nodes_m: u64 = 0,
    example: ?struct { fen: [100]u8, len: usize, at: usize, nodes_r: u64, nodes_m: u64 } = null,
    window_example: ?struct { fen: [100]u8, len: usize, at: usize } = null,
};

fn runSearches(gpa: std.mem.Allocator, roots: []const fen.Description, depth: u32, remap: bool, t: *SearchTally) !void {
    const e = try gpa.create(Eng);
    defer gpa.destroy(e);
    e.* = try Eng.init(gpa);
    defer e.deinit();
    e.reporting = true;
    e.setTablebases(false);
    var evR: std.ArrayList(Ev) = .empty;
    defer evR.deinit(gpa);
    var evM: std.ArrayList(Ev) = .empty;
    defer evM.deinit(gpa);
    for (roots) |*d| {
        const m = mirrorDesc(d);
        var sp: Position = .{};
        const a = try searchOne(e, d, depth, null, &sp, &evR, gpa);
        const b = try searchOne(e, &m, depth, if (remap) &sp else null, null, &evM, gpa);
        if (!a.ok or !b.ok) {
            t.refused += 1;
            continue;
        }
        t.pairs += 1;
        t.nodes_r += a.nodes;
        t.nodes_m += b.nodes;
        if (a.move.?.from == msq(b.move.?.from) and a.move.?.to == msq(b.move.?.to)) t.same_move += 1;
        if (std.mem.eql(u8, a.score[0..a.score_len], b.score[0..b.score_len])) t.same_score += 1;
        if (a.nodes == b.nodes) t.same_nodes += 1;
        const n = @min(evR.items.len, evM.items.len);
        var i: usize = 0;
        while (i < n and eventMirrors(evR.items[i], evM.items[i])) i += 1;
        if (i == n and evR.items.len == evM.items.len) {
            t.identical_trace += 1;
            continue;
        }
        if (i < n) {
            const x = evR.items[i];
            const y = evM.items[i];
            if (std.meta.activeTag(x) != std.meta.activeTag(y)) t.first_kind += 1 else if (x == .make) t.first_make += 1 else {
                t.first_window += 1;
                if (t.window_example == null) {
                    t.window_example = .{ .fen = undefined, .len = 0, .at = i };
                    t.window_example.?.len = fenText(d, &t.window_example.?.fen).len;
                }
            }
        } else t.first_kind += 1;
        if (t.example == null) {
            t.example = .{ .fen = undefined, .len = 0, .at = i, .nodes_r = a.nodes, .nodes_m = b.nodes };
            t.example.?.len = fenText(d, &t.example.?.fen).len;
        }
    }
}

fn reportSearch(what: []const u8, depth: u32, t: *const SearchTally) void {
    std.debug.print("eval mirror, search, {s}, depth {d}: {d} pairs ({d} refused); mirrored move {d}, same score {d}, same nodes {d}, identical traces {d}; first difference a make {d}, a window {d}, the kind of event {d}; nodes {d} against the mirror's {d}\n", .{ what, depth, t.pairs, t.refused, t.same_move, t.same_score, t.same_nodes, t.identical_trace, t.first_make, t.first_window, t.first_kind, t.nodes_r, t.nodes_m });
    if (t.example) |x| std.debug.print("  first differing: {s} at event {d}, nodes {d} / {d}\n", .{ x.fen[0..x.len], x.at, x.nodes_r, x.nodes_m });
    if (t.window_example) |x| std.debug.print("  first differing by a window: {s} at event {d}\n", .{ x.fen[0..x.len], x.at });
}

/// One search set's expected result (optimised builds; Debug runs a part of the set).
const SearchExpect = struct { pairs: usize, refused: usize, same_move: usize, same_score: usize, same_nodes: usize, identical_trace: usize, first_make: usize, first_window: usize, first_kind: usize };

fn expectSearch(what: []const u8, e: SearchExpect, t: *const SearchTally, failed: *bool) void {
    if (builtin.mode == .debug) return;
    const got: SearchExpect = .{ .pairs = t.pairs, .refused = t.refused, .same_move = t.same_move, .same_score = t.same_score, .same_nodes = t.same_nodes, .identical_trace = t.identical_trace, .first_make = t.first_make, .first_window = t.first_window, .first_kind = t.first_kind };
    if (!std.meta.eql(e, got)) {
        std.debug.print("eval mirror, search, {s}: expected {any}, got {any}\n", .{ what, e, got });
        failed.* = true;
    }
}

/// Golden with the mirror's slots remapped, generated remapped, golden with Setup's slots,
/// generated with Setup's slots. "refused": no move on one side (a position Setup refuses,
/// or one with no legal move).
const search_expect = [4]SearchExpect{
    .{ .pairs = 405, .refused = 0, .same_move = 397, .same_score = 101, .same_nodes = 34, .identical_trace = 1, .first_make = 348, .first_window = 56, .first_kind = 0 },
    .{ .pairs = 37, .refused = 23, .same_move = 36, .same_score = 21, .same_nodes = 3, .identical_trace = 0, .first_make = 33, .first_window = 4, .first_kind = 0 },
    .{ .pairs = 405, .refused = 0, .same_move = 394, .same_score = 100, .same_nodes = 16, .identical_trace = 1, .first_make = 372, .first_window = 32, .first_kind = 0 },
    .{ .pairs = 37, .refused = 23, .same_move = 36, .same_score = 19, .same_nodes = 3, .identical_trace = 0, .first_make = 34, .first_window = 3, .first_kind = 0 },
};
