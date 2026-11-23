//! The main hash tables' size, index mask and index mode, as pure functions of the memory
//! on offer, the hash-table size setting and the level: `hash_setup` (0000:7180-749B, XMS
//! path), `hash_resize` (0000:6C3A-6F2D), main's request before each search
//! (0000:079F-0818) and the Settings / Hash-tables entry (38C0:4C91-4CC6); and where
//! `clear_hash_tables` (0000:88CC-89CE) leaves bytes it did not clear.
//!
//! Specification: docs/arch/35-hash-sizing.md, whose executable form is
//! tools/research/hashsize/model.py (matched the original on every call of a grid of
//! memory sizes, typed sizes and levels). Test: src/hashsize_test.zig, which replays the
//! recorded grid (tests/golden/hashsize/vectors.txt).
//!
//! The tables themselves (10-byte slots, probe, store, clear) are `searchnode.HashTable`;
//! this unit only says how many slots the index reaches and when they are cleared.
//!
//! **Integer arithmetic is the original's:** the sizes are signed dwords compared as the
//! original compares them, and the halving is the C run-time's signed long division
//! (4793:8AF0, toward zero).

const std = @import("std");

/// The XMS ladder of hash_resize (0000:6D06-6EF6): the first rung whose size the half
/// request reaches gives the table size in KB, the index mask and the 3/4 index mode.
/// The values are immediates in the code.
pub const Rung = struct { kb: i32, mask: u32, three_quarters: bool };
pub const ladder = [_]Rung{
    .{ .kb = 30720, .mask = 0x3FFFFF, .three_quarters = true },
    .{ .kb = 20480, .mask = 0x1FFFFF, .three_quarters = false },
    .{ .kb = 15360, .mask = 0x1FFFFF, .three_quarters = true },
    .{ .kb = 10240, .mask = 0x0FFFFF, .three_quarters = false },
    .{ .kb = 5120, .mask = 0x07FFFF, .three_quarters = false },
    .{ .kb = 2560, .mask = 0x03FFFF, .three_quarters = false },
    .{ .kb = 1280, .mask = 0x01FFFF, .three_quarters = false },
    .{ .kb = 640, .mask = 0x00FFFF, .three_quarters = false },
    .{ .kb = 320, .mask = 0x007FFF, .three_quarters = false },
    .{ .kb = 160, .mask = 0x003FFF, .three_quarters = false },
    .{ .kb = 80, .mask = 0x001FFF, .three_quarters = false },
    .{ .kb = 40, .mask = 0x000FFF, .three_quarters = false },
};

/// DG:00E2 as loaded from the executable: hash_setup takes the XMS path only if it is at
/// least 80 (0000:72D6). It is then replaced by the free memory.
pub const initial_avail_kb: i32 = 16000;

/// What hash_resize reads besides the requested size.
pub const Memory = struct {
    /// DG:00E2:00E4, the memory the tables may use in all, in KB: the XMS driver's
    /// largest free block at start-up (or 16000 if it was never queried).
    avail_kb: i32 = initial_avail_kb,
    /// DG:AC28: > 1 selects the conventional-memory tables (only with a command-line
    /// digit 1 or 2; never in the recorded runs).
    conv: i8 = 0,
    /// DG:9352: the XMS tables are allocated.
    xms_ready: bool = false,
};

/// What hash_resize leaves.
pub const Tables = struct {
    /// DG:12C6:12C8, the size of each table in KB (or the half request, when no rung
    /// was reached).
    size_kb: i32 = 0,
    /// DG:B624:B626, the XMS index mask; 0 when the tables are off.
    mask: u32 = 0,
    /// DG:9316, non-zero: the index is scaled by 3/4 (`i = (i + i/2) / 2`).
    mode: u8 = 0,
    /// DG:A3F8, the hash-tables-present flag the search tests; also hash_resize's AX.
    enabled: u16 = 0,
    /// DG:005A:005C, the bytes per table clear_hash_tables clears (size_kb * 1024; written
    /// only on the XMS path).
    table_bytes: i32 = 0,
    /// DG:AB9C, the conventional index mask (written only on the conventional path).
    conv_mask: u16 = 0,
};

/// Port of hash_resize (0000:6C3A-6F2D). `old` is what the previous call left: the XMS
/// mask and the byte count survive a call that does not reach the XMS path.
pub fn resize(requested_kb: i32, mem: Memory, old: Tables) Tables {
    var t = old;
    t.enabled = 0;
    t.mode = 0;
    var size = requested_kb;
    if (mem.conv > 1) {
        // UNVERIFIED: the conventional tables need a command-line digit 1 or 2, which the
        // emulator cannot pass; this branch is the reading of 6C53-6CCD only.
        // 6C53-6CCD: 60 KB or more gives two 30 KB tables (3,072 slots, mask FFFh, mode
        // 1); 30 KB or more two 20 KB tables (2,048 slots, mask 7FFh); less, none.
        t.conv_mask = 0x7FF;
        if (size >= mem.avail_kb) size = mem.avail_kb;
        if (size >= 60) {
            size = 30;
            t.conv_mask = 0xFFF;
            t.mode += 1;
        } else if (size >= 30) {
            size = 20;
        } else {
            size = 0;
        }
        if (size != 0) t.enabled += 1;
    }
    if (mem.xms_ready) {
        // 6CDC-6F2A: the request is limited to the memory on offer and halved (two
        // tables), then the first rung it reaches is taken.
        if (size >= mem.avail_kb) size = mem.avail_kb;
        t.mask = 0;
        size = @divTrunc(size, 2);
        for (ladder) |r| {
            if (size >= r.kb) {
                size = r.kb;
                t.mask = r.mask;
                if (r.three_quarters) t.mode += 1;
                break;
            }
        }
        t.table_bytes = size *% 1024;
        if (t.mask != 0) t.enabled += 1;
    }
    t.size_kb = size;
    return t;
}

/// main 0000:07C6-0806: the size requested before a search. A timed level (DG:A274 < 3)
/// whose previous budget's base (DG:8D06, ticks; stale: the budget of this search is
/// computed later) is under 91 ticks asks for 320 KB if the setting (DG:12CA) is larger.
pub fn mainRequest(level: i8, base_ticks: i32, total_kb: i32) i32 {
    if (level < 3 and base_ticks < 91 and total_kb > 320) return 320;
    return total_kb;
}

/// The state hash_setup leaves.
pub const Setup = struct {
    mem: Memory = .{},
    tables: Tables = .{},
    /// DG:12CA:12CC, the total requested before each search: twice the start-up table
    /// size, or what was typed into Settings / Hash-tables.
    total_kb: i32 = 0,
    /// The size of each XMS block allocated, in KB (0: none). Later resizes only lower the
    /// mask; the blocks are never reallocated.
    block_kb: i32 = 0,
};

/// Port of hash_setup (0000:7180-749B) on its XMS path (DG:9316 = 3, the default; a
/// command-line digit 0, 1 or 2 is not modelled). `largest_free_kb` is what XMS function
/// 08h reports (the largest free block, a word), or null when no XMS driver answers.
pub fn setup(largest_free_kb: ?u16) Setup {
    var s: Setup = .{};
    s.tables.mode = 3; // DG:9316 keeps the start-up mode until the first resize
    const free = largest_free_kb orelse return s;
    s.tables.size_kb = free; // 7329
    if (free < 80) return s; // 7337-733E: fewer than 80 KB, no tables
    s.mem.avail_kb = free;
    s.mem.xms_ready = true;
    s.tables = resize(free, s.mem, s.tables);
    s.total_kb = s.tables.size_kb * 2;
    s.block_kb = s.tables.size_kb;
    s.tables.enabled = 1;
    return s;
}

/// The Settings / Hash-tables entry (38C0:4C91-4CC6): the typed size (at most five digits,
/// negative rejected) becomes the request and the total; if the resize leaves no tables,
/// the total becomes 0. Returns whether the tables were cleared.
pub fn menu(s: *Setup, typed_kb: i32) bool {
    if (typed_kb < 0) return false;
    s.total_kb = typed_kb;
    s.tables = resize(typed_kb, s.mem, s.tables);
    if (s.tables.enabled != 0) return true;
    s.total_kb = 0;
    s.tables.size_kb = 0;
    return false;
}

/// main before a search: request, resize; returns whether the tables are cleared.
pub fn beforeSearch(s: *Setup, level: i8, base_ticks: i32) bool {
    s.tables = resize(mainRequest(level, base_ticks, s.total_kb), s.mem, s.tables);
    return s.tables.enabled != 0;
}

/// The number of 10-byte slots the XMS index reaches: mask + 1, or with the 3/4 mode
/// ((mask + mask/2) / 2) + 1. 3,145,728 for the 30,720 KB tables.
pub fn slots(t: Tables) u32 {
    if (t.mask == 0) return 0;
    const top = if (t.mode != 0) (t.mask + (t.mask >> 1)) >> 1 else t.mask;
    return top + 1;
}

/// clear_hash_tables (0000:88CC-89CE, XMS path) copies 4,096 bytes every 2,048 from a
/// buffer whose first 2,048 bytes are zero (calloc(1024, 2), 0000:7305); its last copy
/// fails when it would pass the end of the XMS block. When the size in use equals the
/// block, the last 2,048 bytes of each table therefore keep what the copy before put there:
/// the 2,048 bytes of conventional memory that follow the buffer (an uninitialised read:
/// the buffer is 2,048 bytes long). Returns that byte range of each table, or null when
/// the whole size in use is zero after a clear. Every size the ladder gives is a multiple
/// of 2,048 bytes, so the range is the last 2,048 bytes, and it exists exactly when the
/// size in use is the block's size.
pub const Range = struct { offset: u32, len: u32 };
pub fn unclearedTail(table_bytes: i32, block_kb: i32) ?Range {
    if (table_bytes <= 0 or block_kb <= 0) return null;
    const used: u64 = @intCast(table_bytes);
    const block: u64 = @as(u64, @intCast(block_kb)) * 1024;
    const last = ((used - 1) / 2048) * 2048; // the offset of the last 4,096-byte move
    if (last + 4096 <= block) return null;
    return .{ .offset = @intCast(last), .len = @intCast(@min(used, block) - last) };
}

test "hashsize: ladder rungs" {
    // The default emulator memory, 64,512 KB: two 30,720 KB tables, 3/4 index.
    const s = setup(64512);
    try std.testing.expectEqual(@as(i32, 30720), s.tables.size_kb);
    try std.testing.expectEqual(@as(u32, 0x3FFFFF), s.tables.mask);
    try std.testing.expectEqual(@as(u32, 3_145_728), slots(s.tables));
    try std.testing.expectEqual(@as(i32, 61440), s.total_kb);
    // The tail left uncleared: slot 3,145,523 from its byte 2, to the end.
    const tail = unclearedTail(s.tables.table_bytes, s.block_kb).?;
    try std.testing.expectEqual(@as(u32, 31_455_232), tail.offset);
    try std.testing.expectEqual(@as(u32, 2048), tail.len);
    // A smaller size in use is cleared whole.
    var m = s;
    try std.testing.expect(menu(&m, 5000));
    try std.testing.expectEqual(@as(i32, 1280), m.tables.size_kb);
    try std.testing.expectEqual(@as(?Range, null), unclearedTail(m.tables.table_bytes, m.block_kb));
}
