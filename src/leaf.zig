//! The search node's small callees: the repetition test (0000:1B88), the null move
//! (1E9D:16BE), the endgame king term (1E9D:3416 / 35FB), the leaf attack map
//! (2B9F:40A8 / 42DA), the king ring map (2B9F:450E / 454C) and the hanging-piece
//! term leafTermA (2B9F:4BFE / 5534).
//! Specification: docs/arch/24-node-leaf-routines.md; proved Python models:
//! tools/research/leaf/leafmodel.py and tools/research/leaf/hanging.py.
//!
//! Fixes of owner decision 27 (docs/DEVIATIONS.md):
//! - DEV-040 (class C, switch `pos.Fixes.dev040_hanging_ray_start`, read by
//!   `hangingPiecesFixes`; `hangingPieces` is the original): a diagonal skipped for a
//!   pawn on its first square leaves the next ray's start moved.
//! - DEV-037 and DEV-039 (class A, no switch): a captured piece's list entry is skipped
//!   by the leaf attack maps and the hanging-piece test, where the original reads bytes
//!   beyond the board, the map and the pawn-attack counts as if it were a square. Those
//!   bytes were 0 in every recorded call, and 0 makes the original skip the entry too.

const std = @import("std");
const EvalState = @import("eval_state.zig").EvalState;
const EvalVars = @import("evalvars.zig").EvalVars;
const position = @import("position.zig");
const see = @import("see.zig");
const dg = @import("original.zig").dgroup;
const Position = position.Position;
const Side = position.Side;

/// State these routines read or write beyond `Position`, by DGROUP address.
pub const LeafVars = struct {
    /// DG:8FE4 + square: the leaf map. 40A8/42DA mark the squares a side's knights,
    /// bishops, rooks, queen and king attack; 450E/454C mark the ring of a king. Both clear
    /// only squares 21..98 (DG:8FF9, 78 bytes) first.
    leaf_map: [120]u8 = @splat(0),
    /// The 78 bytes past the search board, which the original reads when a piece-list entry
    /// is a captured piece's (square + 63h); no longer read (see `pieceAt`), kept for the
    /// tests that show it, and not part of the shared state (its home is
    /// `evalthreats.ThreatVars.board_after`).
    past_board: [78]u8 = @splat(0),
    /// DG:933E: endgame king table, White king's orthogonal neighbours, by piece code.
    wk_orth: [14]u8 = @splat(0),
    /// DG:A234: the same for the White king's diagonal neighbours.
    wk_diag: [14]u8 = @splat(0),
    /// DG:3A22: the Black king's orthogonal neighbours.
    bk_orth: [14]u8 = @splat(0),
    /// DG:77DA: the Black king's diagonal neighbours.
    bk_diag: [14]u8 = @splat(0),
    /// DG:9DBE + 6 * ply: the position key at each ply (written by the node).
    key_history: [position.max_ply]u48 = @splat(0),
    /// DG:A000: game ply at the root.
    root_game_ply: u16 = 0,
    /// DG:A4CA: the swap list of leafTermA (`hangingPieces`), words: the balance before
    /// the side to move's capture in each round. Written and read within one call; kept
    /// because the original leaves it.
    swap_gain: [11]u16 = @splat(0),
    /// DG:905C: the 78 bytes after the leaf map, which `hangingPieces` reads as the map
    /// byte of a captured piece's list entry (square + 63h, 120..197).
    map_past: [78]u8 = @splat(0),
    /// DG:A594 (White) and DG:3852 (Black): the 78 bytes after each side's pawn-attack
    /// counts, read the same way.
    pawn_attacks_past: [2][78]u8 = @splat(@splat(0)),
};

inline fn s16(x: u16) i16 {
    return @bitCast(x);
}

/// Port of is_repetition (0000:1B88). `game_keys[g]` is the game record's key at game
/// ply g (far segment 5A7B:3A34 + 6g in the original, outside DGROUP). The per-ply last
/// irreversible plies (DG:9D94) and the game ply of the last irreversible game move
/// (DG:7464) are read from their home, `EvalState` (`ply_flag`, `last_irreversible_ply`).
pub fn isRepetition(p: *const Position, v: *const LeafVars, e: *const EvalState, game_keys: []const u48, ply: i16) bool {
    const di: i32 = e.ply_flag[@intCast(ply)];
    if (ply > 4) {
        var si: i32 = ply - 4;
        while (di <= si) : (si -= 2) {
            if (v.key_history[@intCast(si)] == p.hash_key) return true;
        }
    }
    if (di != 0) return false;
    const li: i32 = s16(e.last_irreversible_ply);
    var g: i32 = li + ((s16(p.game_ply) - li) & 1);
    const root: i32 = s16(v.root_game_ply);
    while (root >= g) : (g += 2) {
        if (game_keys[@intCast(g)] == p.hash_key) return true;
    }
    return false;
}

/// Port of make_null_move (1E9D:16BE). The node passes ply + 1 and undoes only the game
/// ply (`game_ply -= 1`) after the child.
pub fn makeNull(p: *Position, ply: u16) void {
    p.game_ply +%= 1;
    p.ep_square_by_ply[ply] = 0;
    p.check_by_ply[ply] = 0;
    p.quiet_move_by_ply[ply] = 0;
    p.reversible_by_ply[ply] = 0xFFFF;
}

// ---------------------------------------------------------------- endgame king term

const EK = struct {
    p: *const Position,
    v: *LeafVars,
    dx: u16 = 0,
    ch: u8 = 0,

    inline fn bd(e: *const EK, sq: i32) u8 {
        return e.p.board[@intCast(sq)];
    }
    inline fn add(e: *EK, x: u16) void {
        e.dx +%= x;
    }
    inline fn sub(e: *EK, x: u16) void {
        e.dx -%= x;
    }
    inline fn bpa(e: *const EK, sq: i32) u8 {
        return e.p.pawn_attacks[1][@intCast(sq)];
    }
    inline fn wpa(e: *const EK, sq: i32) u8 {
        return e.p.pawn_attacks[0][@intCast(sq)];
    }
    /// The forward squares of the White king (K+9, K+10, K+11): attacked by a Black pawn
    /// -16; a White pawn blocked -16; empty or border nothing; else + table[piece].
    /// Returns the piece code it added for, or 0.
    fn whiteFront(e: *EK, t: *const [14]u8, k: i32, d: i32) u8 {
        if (e.bpa(k + d) != 0) {
            e.sub(16);
            return 0;
        }
        const b = e.bd(k + d);
        const sb: i8 = @bitCast(b);
        if (sb == 1 and e.bd(k + d + 10) != 0) {
            e.sub(16);
            return 0;
        }
        if (sb >= 1) {
            e.add(t[b]);
            return b;
        }
        return 0;
    }
    /// The squares behind the Black king (Q-9, Q-10, Q-11): attacked by a White pawn +16;
    /// a Black pawn blocked +16; else - table[piece]. Returns the piece subtracted, or 0.
    fn blackBack(e: *EK, t: *const [14]u8, q: i32, d: i32) u8 {
        if (e.wpa(q + d) != 0) {
            e.add(16);
            return 0;
        }
        const b = e.bd(q + d);
        if (b == 8 and e.bd(q + d - 10) != 0) {
            e.add(16);
            return 0;
        }
        e.sub(t[b]);
        return b;
    }
};

/// Port of the endgame king term, 1E9D:3416 (`side` = white, the White node) and 35FB
/// (black). Both return the same score (White's view); they differ in the pawn count
/// written to the passer flags DG:A5F5 (`EvalVars.passer_flags`, their home): 3416 counts White pawns at the Black king,
/// 35FB Black pawns at the White king (specification §3, §4).
pub fn endgameKing(p: *const Position, v: *LeafVars, ev: *EvalVars, comptime side: Side) i16 {
    var e: EK = .{ .p = p, .v = v };
    const k: i32 = p.piece_list[7];
    const q: i32 = p.piece_list[23];
    const ck: i8 = @bitCast(@as(u8, @intCast(k)));
    const cq: i8 = @bitCast(@as(u8, @intCast(q)));
    // White king, added.
    inline for (.{ 1, -1 }) |d| {
        const b = e.bd(k + d);
        e.add(v.wk_orth[b]);
        if (b == 8 and e.bpa(k + d) == 0) {
            e.add(12);
            if (side == .black) {
                e.ch +%= 1;
                if (e.bd(k + d - 10) == 1 or ck <= 0x30) e.ch +%= 10;
            }
        }
    }
    const f = e.whiteFront(&v.wk_orth, k, 10);
    if (side == .black and f == 8) {
        e.ch +%= 1;
        if (ck <= 0x26) e.ch +%= 10;
    }
    {
        const b = e.bd(k - 10);
        e.add(v.wk_orth[b]);
        if (side == .black and b == 8 and e.bpa(k - 10) == 0) {
            e.ch +%= 1;
            if (e.bd(k - 20) == 1 or ck <= 0x30) e.ch +%= 10;
        }
    }
    inline for (.{ -11, -9 }) |d| {
        const b = e.bd(k + d);
        e.add(v.wk_diag[b]);
        if (side == .black and b == 8 and e.bpa(k + d) == 0) {
            e.ch +%= 1;
            if (e.bd(k + d - 10) == 1 or ck <= 0x30) e.ch +%= 10;
        }
    }
    _ = e.whiteFront(&v.wk_diag, k, 9);
    _ = e.whiteFront(&v.wk_diag, k, 11);
    // Black king, subtracted.
    inline for (.{ 1, -1 }) |d| {
        const b = e.bd(q + d);
        e.sub(v.bk_orth[b]);
        if (b == 1 and e.wpa(q + d) == 0) {
            e.sub(12);
            if (side == .white) {
                e.ch +%= 1;
                if (e.bd(q + d + 10) == 8 or cq >= 0x47) e.ch +%= 10;
            }
        }
    }
    {
        const b = e.bd(q + 10);
        e.sub(v.bk_orth[b]);
        if (side == .white and b == 1 and e.wpa(q + 10) == 0) {
            e.ch +%= 1;
            if (e.bd(q + 20) == 8 or cq >= 0x47) e.ch +%= 10;
        }
    }
    if (e.blackBack(&v.bk_orth, q, -10) == 1 and side == .white) {
        e.ch +%= 1;
        if (cq >= 0x51) e.ch +%= 10;
    }
    _ = e.blackBack(&v.bk_diag, q, -11);
    _ = e.blackBack(&v.bk_diag, q, -9);
    inline for (.{ 9, 11 }) |d| {
        const b = e.bd(q + d);
        e.sub(v.bk_diag[b]);
        if (side == .white and b == 1 and e.wpa(q + d) == 0) {
            e.ch +%= 1;
            if (e.bd(q + d + 10) == 8 or cq >= 0x47) e.ch +%= 10;
        }
    }
    var ax = s16(e.dx);
    if (@as(i8, @bitCast(p.pawn_count)) <= 4) ax >>= 1;
    ev.passer_flags = e.ch;
    return ax;
}

// ---------------------------------------------------------------- leaf maps

fn clearMap(v: *LeafVars) void {
    @memset(v.leaf_map[21..99], 0);
}

/// Port of 2B9F:40A8 (White) / 42DA (Black): mark in `leaf_map` every square the side's
/// knights, bishops, rooks, queen and king attack (sliders: the first non-empty square of
/// each ray, whatever it holds). Pawns are not marked.
///
/// DEV-037 (class A, fixed without a switch): the original reads the board byte at every
/// list entry (40C5 White, 42F7 Black), so a captured piece's entry (square + 63h, 120 or
/// more) reads DG:9F6E-9FBB (`LeafVars.past_board`) as if it were a square. The byte was
/// 0 in every recorded call, which the original skips; were it one of the side's piece
/// codes, it would mark squares past the 120-byte map and overwrite what follows (the
/// pawn count at DG:90AA). The port skips a captured entry, which is the recorded
/// behaviour; `past_board` is no longer read.
pub fn leafAttackMap(p: *const Position, v: *LeafVars, comptime side: Side) void {
    clearMap(v);
    const base: i32 = if (side == .white) 2 else 9;
    const list = p.piece_list[if (side == .white) 0 else 16..][0..16];
    var i: usize = 16;
    while (i > 0) {
        i -= 1;
        const sq = list[i];
        if (sq >= 120) continue; // DEV-037: a captured piece
        const code: i32 = @as(i8, @bitCast(p.board[sq]));
        const s: i32 = sq;
        switch (code - base) {
            0 => for ([_]i32{ 8, 12, 19, 21, -8, -12, -19, -21 }) |d| {
                v.leaf_map[@intCast(s + d)] = 1;
            },
            4 => for ([_]i32{ 1, 9, 10, 11, -1, -9, -10, -11 }) |d| {
                v.leaf_map[@intCast(s + d)] = 1;
            },
            1 => slide(p, v, s, &.{ 9, -9, 11, -11 }),
            2 => slide(p, v, s, &.{ 1, -1, 10, -10 }),
            3 => slide(p, v, s, &.{ 1, -1, 10, -10, 9, -9, 11, -11 }),
            else => {},
        }
    }
}

fn slide(p: *const Position, v: *LeafVars, from: i32, dirs: []const i32) void {
    for (dirs) |d| {
        var t = from + d;
        while (p.board[@intCast(t)] == 0) t += d;
        v.leaf_map[@intCast(t)] = 1;
    }
}

/// Port of 2B9F:450E (White) / 454C (Black): clear the map (squares 21..98) and mark the
/// eight squares around the side's king. Returns 1, as the original's AX; the node
/// discards it.
pub fn kingRingMap(p: *const Position, v: *LeafVars, comptime side: Side) i16 {
    clearMap(v);
    const k: i32 = p.piece_list[if (side == .white) 7 else 23];
    for ([_]i32{ 1, 9, 10, 11, -1, -9, -10, -11 }) |d| v.leaf_map[@intCast(k + d)] = 1;
    return 1;
}

// ---------------------------------------------------------------- hanging pieces (leafTermA)

/// DG:0A68 + d and DG:0CFF + d: non-zero when d is a knight step / a king step. Index
/// d + 255, d = -255..119, as in src/see.zig.
const knight_reach = dg(0x0A68 - 255, 375);
const king_reach = dg(0x0CFF - 255, 375);
/// DG:0490, DG:047E, DG:0470: king-ray code to step and to line bit; piece code to the
/// line bits it slides along (the tables src/see.zig uses).
const dir_step: [17]i8 = @bitCast(dg(0x0490, 17));
const dir_bit = dg(0x047E, 17);
const slider_bits = dg(0x0470, 14);
/// DG:0446: the victim's value by piece code: P 8, N 28, B 28, R 44, Q 80, K 0.
const victim_value = dg(0x0446, 14);
/// DG:003A + slot: the slot's bit in a passed-pawn mask (1 << (slot - 8) for the pawn
/// slots; the copyright text "t Copr\x1a\x00" for slots 0..7, read the same way).
const slot_bit = dg(0x003A, 16);
/// DG:08B4 + sq (a White pawn, read by 5534) and DG:0918 + sq (a Black pawn, read by
/// 4BFE): a passed pawn's value by square, 10 to 18 rising towards promotion.
const passed_value = [2][120]u8{ dg(0x08B4, 120), dg(0x0918, 120) };
/// DG:1510: the eight steps in the order the rays are scanned.
const ray_steps: [8]i8 = @bitCast(dg(0x1510, 8));
comptime {
    std.debug.assert(std.mem.eql(i8, &ray_steps, &.{ 9, 11, -9, -11, 1, 10, -1, -10 }));
}

/// The exchange values the lists hold: pawn 8, knight and bishop 28, rook 44, queen 80,
/// king 90.
const xv_pawn: u8 = 0x08;
const xv_minor: u8 = 0x1C;
const xv_rook: u8 = 0x2C;
const xv_queen: u8 = 0x50;
const xv_king: u8 = 0x5A;

inline fn step(sq: usize, d: i32) usize {
    return @intCast(@as(i32, @intCast(sq)) + d);
}

/// The first non-empty square after `sq` along `d`.
inline fn walk(p: *const Position, sq: usize, d: i32) usize {
    var s = step(sq, d);
    while (p.board[s] == position.empty) s = step(s, d);
    return s;
}

/// The piece on `sq` and its king ray: the ray's step, the first piece beyond `sq` along
/// it, and whether that piece slides along this kind of line (the piece on `sq` is then
/// pinned). `colour` is the king's (0 White, 1 Black); `king_rays[colour][sq]` is not 0.
const Pin = struct { step: i8, pinner: u8, pinned: bool };
inline fn pinAt(p: *const Position, colour: usize, sq: usize) Pin {
    const code = p.king_rays[colour][sq];
    const st = dir_step[code];
    const q = p.board[walk(p, sq, st)];
    return .{ .step = st, .pinner = q, .pinned = dir_bit[code] & slider_bits[q] != 0 };
}

/// Port of the pin helpers 2B9F:4B56 (White king's rays) and 4BAA (Black): the piece on
/// `sq` is pinned to its king along a line other than the step `d`.
inline fn pinnedOffLine(p: *const Position, colour: usize, sq: usize, comptime d: i8) bool {
    const pin = pinAt(p, colour, sq);
    return pin.pinned and pin.step != d and pin.step != -d;
}

/// One call of leafTermA for the side `us` to move: the lists, accumulators and flags,
/// indexed by colour (0 White, 1 Black) where the original's two copies differ only in
/// which colour is the capturer.
fn Hanging(comptime us: Side, comptime fixes: position.Fixes) type {
    const white = us == .white;
    return struct {
        const Self = @This();
        /// The capturer's colour (`a`) and the victims' (`d`).
        const a: usize = if (white) 0 else 1;
        const d: usize = 1 - a;
        const a_pawn: u8 = if (white) position.white_pawn else position.black_pawn;
        const d_pawn: u8 = if (white) position.black_pawn else position.white_pawn;
        const a_queen: u8 = if (white) position.white_queen else position.black_queen;
        const d_queen: u8 = if (white) position.black_queen else position.white_queen;
        /// The capturer's pawns stand behind the victim (White: T-9, T-11), the victim's
        /// defending pawns in front of it (White node: T+9, T+11).
        const a_pawn_dirs: [2]i8 = if (white) .{ -9, -11 } else .{ 9, 11 };
        const d_pawn_dirs: [2]i8 = if (white) .{ 9, 11 } else .{ -9, -11 };

        p: *const Position,
        s: *see.Scratch,
        /// Next free entry of each colour's list ([bp-12h] the capturer's, [bp-18h] the
        /// victim side's).
        len: [2]usize = .{ 0, 0 },
        /// [bp-1Eh] / [bp-1Ch], by colour: a pawn or knight of the other colour was found
        /// pinned by a queen of this colour, so this colour's queens are not counted on
        /// the rays.
        ignore_queens: [2]bool = .{ false, false },
        /// Per ray: queens (+10h each) and the bishops or rooks behind them (+1 each).
        /// The capturer's is [bp-0Ah], the victim side's [bp-8].
        acc: [2]u16 = .{ 0, 0 },
        /// The sums over the diagonals ([bp-16h], [bp-1Ah]) and lines ([bp-6], [bp-10h]).
        diag: [2]u16 = .{ 0, 0 },
        orth: [2]u16 = .{ 0, 0 },

        inline fn list(r: *Self, colour: usize) []u8 {
            return if (colour == a) &r.s.attackers else &r.s.defenders;
        }

        inline fn push(r: *Self, colour: usize, v: u8) void {
            r.list(colour)[r.len[colour]] = v;
            r.len[colour] += 1;
        }

        /// A bishop, rook or queen of `colour` on a ray. Returns false when the ray ends
        /// here (an ignored queen, or a piece pinned off this line).
        inline fn rayPiece(r: *Self, sq: usize, comptime colour: usize, comptime queen: bool, comptime st: i8, comptime value: u8) bool {
            if (queen and r.ignore_queens[colour]) return false;
            if (r.p.king_rays[colour][sq] != 0 and pinnedOffLine(r.p, colour, sq, st)) return false;
            if (queen) {
                r.acc[colour] +%= 0x10;
            } else if (r.acc[colour] != 0) {
                r.acc[colour] +%= 1;
            } else r.push(colour, value);
            return true;
        }

        /// One ray (5039..5063, 50A9..50D3, 510B..5135), from `start`, which is examined
        /// first. Every bishop (or rook) and queen of either colour is taken in turn
        /// until another piece or the border.
        fn ray(r: *Self, start: usize, comptime st: i8, comptime orth: bool) void {
            const w_slider: u8 = if (orth) position.white_rook else position.white_bishop;
            const b_slider: u8 = if (orth) position.black_rook else position.black_bishop;
            const value: u8 = if (orth) xv_rook else xv_minor;
            var si = start;
            while (true) : (si = step(si, st)) {
                const pc = r.p.board[si];
                const go = switch (pc) {
                    position.empty => true,
                    w_slider => r.rayPiece(si, 0, false, st, value),
                    b_slider => r.rayPiece(si, 1, false, st, value),
                    position.white_queen => r.rayPiece(si, 0, true, st, value),
                    position.black_queen => r.rayPiece(si, 1, true, st, value),
                    else => false,
                };
                if (!go) break;
            }
            const tot = if (orth) &r.orth else &r.diag;
            for (0..2) |c| {
                tot[c] +%= r.acc[c];
                r.acc[c] = 0;
            }
        }

        /// The queens and the bishops or rooks behind them, after every other entry
        /// (5350..53C2, 53E7..544F): "80, 28" once if a bishop is behind a diagonal
        /// queen; "80, 44" and another 44 for each further rook behind line queens; then
        /// 80 for each sixteen (rounded up) of what is left. 16-bit arithmetic.
        fn queens(r: *Self, colour: usize) void {
            var qd = r.diag[colour];
            var qo = r.orth[colour];
            if (qd & 0x0F != 0) {
                r.push(colour, xv_queen);
                r.push(colour, xv_minor);
                qd -%= 0x11;
            }
            if (qo & 0x0F != 0) {
                r.push(colour, xv_queen);
                r.push(colour, xv_rook);
                qo -%= 0x11;
                // A second (and further) rook behind line queens (5391..53A1, 5424..5431
                // and the Black copies).
                while (qo & 0x0F != 0) : (qo -%= 1) r.push(colour, xv_rook);
            }
            qd +%= qo;
            if (@as(i16, @bitCast(qd)) > 0) {
                var n = (qd +% 0x0F) >> 4;
                while (n != 0) : (n -= 1) r.push(colour, xv_queen);
            }
        }

        /// A pawn or knight on `sq` (which its king's rays reach) is pinned; when the
        /// pinner is the other colour's queen, that queen's colour is ignored on the rays.
        inline fn pinnedMinor(r: *Self, comptime colour: usize, sq: usize, comptime line: ?i8) bool {
            const pin = pinAt(r.p, colour, sq);
            if (line) |l| if (pin.step == -l) return false;
            if (!pin.pinned) return false;
            if (pin.pinner == (if (colour == 0) position.black_queen else position.white_queen))
                r.ignore_queens[1 - colour] = true;
            return true;
        }

        /// The victim on `t`; returns the best gain of the swap-off, or null when the
        /// piece is skipped.
        fn victim(r: *Self, v: *LeafVars, t: usize, slot: usize, passed_mask: u8) ?u16 {
            const p = r.p;
            const s = r.s;
            const map_t = v.leaf_map[t];
            s.attackers[0] = 0;
            s.defenders[0] = 0;
            r.* = .{ .p = p, .s = s };
            // 1. The capturer's pawns (4C4D..4D51).
            if (p.pawn_attacks[a][t] != 0) {
                inline for (a_pawn_dirs, 0..) |pd, n| {
                    const ps = step(t, pd);
                    if (p.board[ps] == a_pawn) {
                        const pinned = p.king_rays[a][ps] != 0 and blk: {
                            const pin = pinAt(p, a, ps);
                            break :blk pin.step != -pd and pin.pinned;
                        };
                        if (pinned) {
                            // 4D13: no pawn counted and the victim not in the map: skipped.
                            if (n == 1 and r.len[a] == 0 and map_t == 0) return null;
                            if (pinAt(p, a, ps).pinner == d_queen) r.ignore_queens[d] = true;
                        } else r.push(a, xv_pawn);
                    } else if (n == 1 and r.len[a] == 0 and map_t == 0) return null; // 4D36
                }
            }
            // 2. The capturer's knights, slots 0 and 1; a pinned knight is not counted.
            inline for (0..2) |k| {
                const e = p.piece_list[16 * a + k];
                if (knight_reach[t + 255 - e] != 0) {
                    // Only a knight on the board reaches a square (entries 120..197 of
                    // captured knights reach none; see the specification).
                    if (e >= 120) @panic("leafTermA: a knight's list entry off the board reaches the victim");
                    if (p.king_rays[a][e] == 0 or !r.pinnedMinor(a, e, null)) r.push(a, xv_minor);
                }
            }
            // 3. The victim side's pawns, if its pawn-attack count is not 0.
            if (p.pawn_attacks[d][t] != 0) {
                inline for (d_pawn_dirs) |pd| {
                    const ps = step(t, pd);
                    if (p.board[ps] == d_pawn) {
                        if (p.king_rays[d][ps] == 0 or !r.pinnedMinor(d, ps, pd)) r.push(d, xv_pawn);
                    }
                }
            }
            // 4. The victim side's knights.
            inline for (0..2) |k| {
                const e = p.piece_list[16 * d + k];
                if (knight_reach[t + 255 - e] != 0) {
                    if (e >= 120) @panic("leafTermA: a knight's list entry off the board reaches the victim");
                    if (p.king_rays[d][e] == 0 or !r.pinnedMinor(d, e, null)) r.push(d, xv_minor);
                }
            }
            // 5. The rays. A pawn on the first square of a diagonal (Black's on +9, +11,
            // White's on -9, -11) is passed over when its colour's list starts with a
            // pawn; otherwise the diagonal is skipped and the start square is not put
            // back, so the next ray starts one step further (5030, 50A0; reproduced).
            var cur = t;
            inline for (ray_steps[0..4], 0..) |st, k| blk: {
                cur = step(cur, st);
                const pawn_colour: usize = if (k < 2) 1 else 0;
                const pawn: u8 = if (k < 2) position.black_pawn else position.white_pawn;
                var si = cur;
                if (p.board[cur] == pawn) {
                    if (r.list(pawn_colour)[0] != xv_pawn) {
                        // DEV-040: the original jumps from 5035 (50A5; Black 596B, 59DB)
                        // to the loop's end at 507D (50ED), past 5063, where every other
                        // ray puts its start back on the victim's square ([bp-0Eh] =
                        // [bp-14h]); the next ray then starts from the pawn's square.
                        // Corrected, the skipped diagonal puts it back too.
                        if (fixes.dev040_hanging_ray_start) cur = t;
                        break :blk;
                    }
                    si = step(cur, st);
                }
                r.ray(si, st, false);
                cur = t;
            }
            inline for (ray_steps[4..8]) |st| {
                r.ray(step(cur, st), st, true);
                cur = t;
            }
            // 6. Queens and king of the capturer; no capturer at all: skipped.
            r.queens(a);
            if (king_reach[t + 255 - p.piece_list[16 * a + 7]] != 0) r.push(a, xv_king);
            if (s.attackers[0] == 0) return null;
            r.queens(d);
            if (king_reach[t + 255 - p.piece_list[16 * d + 7]] != 0) r.push(d, xv_king);
            s.defenders[r.len[d]] = 0;
            s.attackers[r.len[a]] = 0;
            // 7. The swap-off (546C..5523), 16-bit signed.
            const vic = p.board[t];
            const v0: u8 = if (slot_bit[slot] & passed_mask != 0 and vic == d_pawn) passed_value[d][t] else victim_value[vic];
            const g = &v.swap_gain;
            g[0] = @bitCast(@as(i16, @as(i8, @bitCast(v0))));
            var di: usize = 0;
            while (true) {
                if (s.defenders[di] == 0) {
                    setNet(s, di, g[di]);
                    break;
                }
                const h = g[di] -% sx(s.attackers[di]);
                setNet(s, di, h);
                if (s.attackers[di + 1] == 0) break;
                g[di + 1] = sx(s.defenders[di]) +% h;
                di += 1;
                // After ten rounds (54D0, 5E06) the swap-off stops without writing the
                // balance of the tenth; the loop below reads whatever that entry holds
                // (replayed: tests/golden/leaf/H5.zst, H6.zst).
                if (di == 10) break;
            }
            // The first maximum of the balances after each capture (above 0), then the
            // smallest balance before a capture up to that round.
            var best: i16 = 0;
            var at: usize = 0;
            for (0..di + 1) |j| {
                const x: i16 = @bitCast(getNet(s, j));
                if (x > best) {
                    best = x;
                    at = j;
                }
            }
            if (best <= 0) return null;
            var j = at + 1;
            while (j > 0) {
                j -= 1;
                const x: i16 = @bitCast(g[j]);
                if (x < best) best = x;
            }
            return @bitCast(best);
        }
    };
}

inline fn sx(b: u8) u16 {
    return @bitCast(@as(i16, @as(i8, @bitCast(b))));
}

/// DG:A010 + 2i: the balance after the capturer's capture in round i, words. They lie
/// inside the capturer's list area (DG:9FEC + 24h), so they are kept there.
const net_offset = 0xA010 - 0x9FEC;
inline fn getNet(s: *const see.Scratch, i: usize) u16 {
    return std.mem.readInt(u16, s.attackers[net_offset + 2 * i ..][0..2], .little);
}
inline fn setNet(s: *see.Scratch, i: usize, x: u16) void {
    std.mem.writeInt(u16, s.attackers[net_offset + 2 * i ..][0..2], x, .little);
}

/// Port of leafTermA: 2B9F:4BFE-5533 (`side` = white, the White node) and 2B9F:5534-5E69
/// (black), with the pin helpers 2B9F:4B56 and 4BAA. The two are colour mirrors.
///
/// For each piece of the side not to move (list entries 15 down to 0) that is marked in
/// `leaf_map` or attacked by a pawn of the side to move, it lists both sides' exchange
/// values on that square (the side to move's in `s.attackers`, DG:9FEC, the other's in
/// `s.defenders`, DG:A060: the same work areas as see_capture_by_white/black, which the
/// joined engine must share), runs a swap-off, and keeps the best gain. Returns 25 times
/// the best gain (0 if none), from the side to move's view; 16-bit, wrapping.
/// First the map byte of the victims' king square is cleared (4C0F).
/// `passed_pawns` are the passed-pawn masks DG:A6C2 (White) and DG:9D8C (Black).
pub fn hangingPieces(p: *const Position, v: *LeafVars, s: *see.Scratch, comptime side: Side, passed_pawns: [2]u8) i16 {
    return hangingPiecesFixes(.original, p, v, s, side, passed_pawns);
}

/// `hangingPieces` with the class C fixes of `fixes`: DEV-040
/// (`dev040_hanging_ray_start`), the start of the ray after a skipped diagonal.
pub fn hangingPiecesFixes(comptime fixes: position.Fixes, p: *const Position, v: *LeafVars, s: *see.Scratch, comptime side: Side, passed_pawns: [2]u8) i16 {
    const H = Hanging(side, fixes);
    var r: H = .{ .p = p, .s = s };
    v.leaf_map[p.piece_list[16 * H.d + 7]] = 0;
    var best: i16 = 0;
    var i: usize = 16;
    while (i > 0) {
        i -= 1;
        const t = p.piece_list[16 * H.d + i];
        // DEV-039 (class A, fixed without a switch): a captured piece's entry (square +
        // 63h, 120 or more) is skipped. The original uses it as the victim's square
        // (4C24, 4C2A; Black 555A, 5560) and reads the map and the capturer's pawn-attack
        // count beyond their 120 bytes (`LeafVars.map_past`, DG:905C-90A9;
        // `pawn_attacks_past`, DG:A594-A5E1 / 3852-389F). Both bytes were 0 in all 47,570
        // recorded entries, and then the original skips the entry too; were either
        // non-zero, it would analyse a phantom piece off the board. Those two fields are
        // no longer read.
        if (t >= 120) continue;
        if (v.leaf_map[t] == 0 and p.pawn_attacks[H.a][t] == 0) continue;
        const gain = r.victim(v, t, i, passed_pawns[H.d]) orelse continue;
        const g: i16 = @bitCast(gain);
        if (best < g) best = g;
    }
    return best *% 25;
}
