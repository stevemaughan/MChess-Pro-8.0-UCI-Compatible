//! Playing on past move 201: the game record slid (owner decision 26, a platform
//! adaptation, AGENTS.md section 9.1 class F). Specification: docs/arch/34-game-move-
//! path.md, "Playing on past move 201: the slide".
//!
//! The original ends a game at move number 202 (38C0:1974): its game record and the
//! per-ply tables hold game plies 0..405 and move numbers 0..202 of each side, and in the
//! engine they are still the original's data segment (DGROUP) and far segment (5A7B)
//! images, where each table is followed directly by other variables. So the engine does
//! not lengthen them: when a game grows long, `slide` drops an even number of the oldest
//! plies and renumbers everything that holds a game ply or a move number, so that the
//! state is what it would be had the game begun that many plies later. Everything the
//! original reads afterwards lies within the last 101 plies (the irreversible-move scan
//! 0000:887E and the repetition scans down to DG:7464), and every test it makes on the
//! absolute game ply or move number gives the same answer before and after the slide as
//! long as the game ply stays at `min_ply` or above (`maxSlide`).
//!
//! The slide works on stores by address (`slideAt`): on the images (`slide`, the tests'
//! hand slides), or in the engine on the homes of DGROUP's variables and on the game
//! record `EngineRoot.rec` through its offsets (Stage B step 8, stage 4). It allocates nothing.

const std = @import("std");
const dgroup = @import("dgroup.zig");

pub const Image = dgroup.Image;
/// The far data segment 5A7B (`engine_root.Far`).
pub const Far = [0x10000]u8;

// ---------------------------------------------------------------------------
// What the slide renumbers
// ---------------------------------------------------------------------------

/// DG:9FC8, the game ply; DG:A84A, the move number (1 at White's first move: the game
/// ply is 2 (move number - 1) + the side to move).
pub const game_ply_addr: u16 = 0x9FC8;
pub const move_number_addr: u16 = 0xA84A;
/// DG:7464: the last irreversible ply, as the last prepare_eval left it (0000:889E).
pub const last_irreversible_addr: u16 = 0x7464;

/// Words holding a game ply at or below the current one, for which 0 is an ordinary ply:
/// moved by the slide, and 0 if that would take them below 0. The game ply itself never
/// goes below `scan_room` (`slide` refuses). The other three are written from the game
/// ply before they are read in the next search (find_last_irreversible_ply 0000:889E,
/// 88A5 inside prepare_eval; main 1420), but for DG:7464, which play_best_move's
/// repetition count (2B9F:402A) reads as the last prepare_eval left it: a slide is
/// therefore made between turns (after play_best_move or an entered move, before main
/// 0526), where 7464 is next read after prepare_eval has recomputed it.
pub const floor_plies = [_]u16{
    0x9FC8, // game ply
    0x7464, // last irreversible ply (find_last_irreversible_ply 0000:889E)
    0xA000, // the game ply at the root (0000:88A5)
    0xB4DE, // the game ply at the search's start (38C0:517F, main 1420)
};

/// The fewest plies a slide leaves: find_last_irreversible_ply (0000:888D) reads the flags
/// of plies g - 100 .. g and the repetition scans (0000:1B88, 2B9F:402A) the keys down to
/// DG:7464 >= g - 101, so below 101 a scan would read before the record.
pub const scan_room: u16 = 101;

/// Words holding the game ply of some past event, with 0 for "none" (and, for the
/// castling stamps, FFFFh for "lost before the game", set by Setup at 0EF8:6AB1): a
/// positive value is moved by the slide; one that would fall to 0 or below (the event
/// precedes the kept plies) becomes FFFFh, `before_record`. Every reader tests these for
/// zero, for equality with the game ply or the ply before, or compares them with the game
/// ply, and FFFFh answers each such test as the old value did. One reader needs more:
/// set_time_budget (0000:8E58-8ECF) treats a book-exit ply above 0 and one at or below 0
/// alike only when it lies 16 or more plies back, which a clamped one does (`min_ply`).
pub const past_plies = [_]u16{
    0xB426, 0xB428, 0x3A30, 0x3A32, // castling stamps (make_move 1E9D:0139.., prepare_eval 0000:9628..)
    0x9FBC, // the ply at which the book was left (main 076F, book_probe 4793:6D8A)
    0xA36A, // the last played ply (38C0:01E0, 554E)
    0xA6AE, // the ply at which the game ended
    0x9D92, // the ply at which the program resigned
    0xA00A, // auto-play / replay target ply (a mode word: 0 in play)
    0x7814, // replay end ply (0 in play)
    0x251E, 0x2520, // the first ply out of book, per side (play_best_move; read by learning only)
    0x2522, 0x2524, // game ply + 1 of the side's last book move (book_probe 4793:6BD2)
    0x2526, 0x2528, // learning's plies (38C0:09D8), 0 with learning off
    0x2A8E, // the book display's high-water ply (book_probe 4793:6227, 6BB1)
    0xA4C2, // the comment state's ply (1E9D:A4C6), compared in play_best_move's comment test
    0xB620, // game ply - 2 when an analysis ends (0EF8:89CD)
};

/// Words holding a move number: moved by half the slide.
pub const move_numbers = [_]u16{
    0xA84A, // move number
    0x73FA, 0x73FC, // the next time control, per side (1E9D:6E40, 6F48)
};

/// The value a past ply takes when the event it marks falls before the kept plies.
pub const before_record: u16 = 0xFFFF;

/// DG:3490 + g: the irreversible-move flags, one byte per game ply (196h).
pub const flags_addr: u16 = 0x3490;
pub const flags_len: u16 = 0x196;

/// Far tables indexed by the game ply: (offset, bytes per entry, entries).
pub const ply_tables = [_]struct { off: u16, size: u16, count: u16 }{
    .{ .off = 0x3A34, .size = 6, .count = 1997 }, // main hash keys, to 6901: 5 past the room (68E3; gamemove.key_room) into gave_check, shifted after them
    .{ .off = 0x27B0, .size = 6, .count = 485 }, // book keys, to 330D
};

/// Far tables indexed by side * 0CBh + move number (the "slot"): (offset, bytes per
/// entry). Each side has 0CBh entries (move numbers 0..202).
pub const slot_tables = [_]struct { off: u16, size: u16 }{
    .{ .off = 0x01D0, .size = 6 }, // moves (mover)
    .{ .off = 0x0B54, .size = 1 }, // check bytes (position)
    .{ .off = 0x2484, .size = 2 }, // scores (position)
    .{ .off = 0x330E, .size = 1 }, // en-passant squares (position)
    .{ .off = 0x68E6, .size = 1 }, // gave check (mover)
};
pub const side_stride: u16 = 0xCB;

/// 5A7B:22EE + side * 0CCh + move number: the captured piece, with its own stride; White
/// has 0CCh entries, Black 0CAh (its entry 0CAh would be the first score byte, 2484).
pub const captured_off: u16 = 0x22EE;
pub const captured_stride: u16 = 0xCC;
pub const captured_count = [2]u16{ 0xCC, 0xCA };

// ---------------------------------------------------------------------------
// The thresholds
// ---------------------------------------------------------------------------

/// The lowest game ply a slide may leave. The book's gate refuses at a game ply above 200
/// (4793:6238); at 201 and above the book is never consulted again, before or after a
/// slide. It also keeps every absolute test of the move number (at most 80: 0000:E428,
/// 2B9F:6BB7.., the level-0 time control's move 40 at 1E9D:6DB4) and of the game ply
/// (0000:8E44, 4793:30ED) on the side it was, and the scans of the last 101 plies within
/// the record. Even, so that the side to move keeps its parity.
pub const min_ply: u16 = 202;

/// The game ply at which the engine slides: far enough below the original's end (its
/// command loop ends the game at move number 202, ply 402) to leave room for a search's
/// plies in the game record's keys, and far enough above `min_ply` that a slide is rare.
pub const due_ply: u16 = 300;

/// DG:A274, the level; DG:B4C2 + 14 * side: the level-2 time-control records (m1, m2, m3,
/// t1, t2, t3, last), whose period boundaries are absolute move numbers.
const level_addr: u16 = 0xA274;
const tc_addr: u16 = 0xB4C2;

const word = dgroup.memWord;
const setWord = dgroup.memSetWord;
fn sword(m: anytype, a: u16) i16 {
    return @bitCast(word(m, a));
}

/// Whether a slide is due: the game ply has reached `due_ply`.
pub fn due(img: *const Image) bool {
    return dueAt(dgroup.ImageMem{ .img = @constCast(img) });
}

/// `due` on a store by address (`dgroup.ImageMem`, or the engine's homes, engine_root
/// `EngineRoot.Home`).
pub fn dueAt(m: anytype) bool {
    return sword(m, game_ply_addr) >= due_ply;
}

/// The largest even number of plies a slide may drop now and leave every decision of the
/// original unchanged: the game ply stays at `min_ply` or above, and at level 2 (time
/// controls) the move number stays on the same side of each of its record's absolute
/// boundaries (m1, m1 + m2, last + 1; with a margin of one for the adjusted move number
/// of 1E9D:6DB4). 0 if none is possible.
pub fn maxSlide(img: *const Image) u16 {
    return maxSlideAt(dgroup.ImageMem{ .img = @constCast(img) });
}

/// `maxSlide` on a store by address.
pub fn maxSlideAt(m: anytype) u16 {
    const g: i32 = sword(m, game_ply_addr);
    var d: i32 = g - min_ply;
    if (m.get(level_addr) == 2) {
        const mn: i32 = sword(m, move_number_addr);
        for (0..2) |s| {
            const r: u16 = @intCast(tc_addr + 14 * s);
            const m1: i32 = sword(m, r);
            const m2: i32 = sword(m, r + 2);
            const last: i32 = sword(m, r + 12);
            for ([_]i32{ m1, m1 + m2, last + 1 }) |t| {
                if (t <= mn) d = @min(d, 2 * (mn - t - 1));
            }
        }
    }
    if (d <= 0) return 0;
    return @intCast(d & ~@as(i32, 1));
}

pub const Error = error{ OddSlide, SlideTooFar };

/// Drop the oldest `d` plies (even) of the game: every table indexed by the game ply or
/// the move number moves down by `d` plies (`d / 2` move numbers), the entries vacated at
/// its end become 0, and every variable holding a game ply or a move number is renumbered
/// (`floor_plies`, `past_plies`, `move_numbers`). To be made between turns (see
/// `floor_plies`). Refuses an odd `d` (the side to move would change) and one that would
/// leave fewer than `scan_room` plies. `maxSlide` says how far a slide keeps the
/// original's decisions.
pub fn slide(img: *Image, far: *Far, d: u16) Error!void {
    return slideAt(dgroup.ImageMem{ .img = img }, dgroup.ImageMem{ .img = far }, d);
}

/// `slide` on stores by address: `m` DGROUP, `fm` the far segment 5A7B. In the engine
/// (Stage B step 8, stage 4) `m` is the engine's homes and `fm` the game record's
/// (engine_root `EngineRoot.RecordHome`: each offset at its field of `EngineRoot.rec`, an offset no
/// field holds at the far image), so the record slides in place, through the offsets
/// the original's tables have, and every byte moves as it moves in the far image: the
/// keys table is shifted over its 1,997 declared entries, into the first 28 bytes of
/// `gave_check`, before `gave_check` is shifted (docs/arch/60-engine-assembly.md
/// section 10.7.7, hazard 3).
pub fn slideAt(m: anytype, fm: anytype, d: u16) Error!void {
    if (d & 1 != 0) return error.OddSlide;
    if (d == 0) return;
    const dd: i32 = d;
    if (@as(i32, sword(m, game_ply_addr)) - dd < scan_room) return error.SlideTooFar;
    const h: u16 = d / 2;

    for (floor_plies) |a| {
        const v: i32 = sword(m, a);
        setWord(m, a, if (v > dd) @intCast(v - dd) else 0);
    }
    for (past_plies) |a| {
        const v = sword(m, a);
        if (v <= 0) continue;
        setWord(m, a, if (v > dd) @bitCast(@as(i16, @intCast(v - dd))) else before_record);
    }
    for (move_numbers) |a| setWord(m, a, word(m, a) -% h);

    shiftDown(m, flags_addr, flags_len, d);
    for (ply_tables) |t| shiftDown(fm, t.off, @as(usize, t.size) * t.count, @as(usize, t.size) * d);
    for (slot_tables) |t| {
        for (0..2) |s| {
            const len = @as(usize, t.size) * side_stride;
            const base: u16 = @intCast(t.off + s * len);
            shiftDown(fm, base, len, @as(usize, t.size) * h);
        }
    }
    for (0..2) |s| {
        const base: u16 = @intCast(captured_off + s * captured_stride);
        shiftDown(fm, base, captured_count[s], h);
    }
}

/// Of the `len` bytes from `base`, entry i takes entry i + n (in ascending order); the
/// last n bytes become 0.
fn shiftDown(m: anytype, base: u16, len: usize, n: usize) void {
    if (n >= len) return dgroup.memFill(m, base, len, 0);
    for (0..len - n) |k| m.set(@intCast(base + k), m.get(@intCast(base + k + n)));
    dgroup.memFill(m, @intCast(base + len - n), n, 0);
}

test "gameslide: tables move down, vacated entries are cleared, plies and move numbers are renumbered" {
    const img = try std.testing.allocator.create(Image);
    defer std.testing.allocator.destroy(img);
    const far = try std.testing.allocator.create(Far);
    defer std.testing.allocator.destroy(far);
    img.* = @splat(0);
    far.* = @splat(0);
    const mi = dgroup.ImageMem{ .img = img };
    setWord(mi, game_ply_addr, 301);
    setWord(mi, move_number_addr, 151);
    setWord(mi, last_irreversible_addr, 290);
    setWord(mi, 0xB426, 5); // a castling right lost at ply 5
    setWord(mi, 0x3A30, 0xFFFF); // lost before the game (Setup)
    setWord(mi, 0x9FBC, 0xFF9C); // -100: the book was off
    setWord(mi, 0xA36A, 301);
    for (0..flags_len) |g| img[flags_addr + g] = @truncate(g);
    for (0..1997) |g| far[0x3A34 + 6 * g] = @truncate(g);
    for (0..2) |s| {
        for (0..side_stride) |n| far[0x0B54 + s * side_stride + n] = @truncate(n);
    }
    try std.testing.expectError(error.OddSlide, slide(img, far, 99));
    try std.testing.expectError(error.SlideTooFar, slide(img, far, 202));
    try std.testing.expectEqual(@as(u16, 98), maxSlide(img));
    try slide(img, far, 98);
    try std.testing.expectEqual(@as(u16, 203), word(mi, game_ply_addr));
    try std.testing.expectEqual(@as(u16, 102), word(mi, move_number_addr));
    try std.testing.expectEqual(@as(u16, 192), word(mi, last_irreversible_addr));
    try std.testing.expectEqual(before_record, word(mi, 0xB426));
    try std.testing.expectEqual(before_record, word(mi, 0x3A30));
    try std.testing.expectEqual(@as(u16, 0xFF9C), word(mi, 0x9FBC));
    try std.testing.expectEqual(@as(u16, 203), word(mi, 0xA36A));
    try std.testing.expectEqual(@as(u8, 98), img[flags_addr]);
    try std.testing.expectEqual(@as(u8, 0), img[flags_addr + flags_len - 1]);
    try std.testing.expectEqual(@as(u8, @truncate(98 + 1000)), far[0x3A34 + 6 * 1000]);
    try std.testing.expectEqual(@as(u8, 49), far[0x0B54 + side_stride]);
    try std.testing.expectEqual(@as(u8, 0), far[0x0B54 + 2 * side_stride - 1]);
    try std.testing.expectEqual(@as(u16, 0), maxSlide(img));
}
