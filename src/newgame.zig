//! Program start-up, the settings, New game's tables and the turn that gives the program
//! the move, on the DGROUP image (Stage A; docs/arch/60-engine-assembly.md section 5,
//! step 12). Specification: docs/arch/34-game-move-path.md, sections "Start-up", "The
//! settings", "The turn to the program's search" and "New game, the tables".
//!
//! Only what these routines write to engine state is ported: the screen, the menus, the
//! clocks' display, the XMS driver's move structures and the far pointers to memory the
//! program allocates are not (each is listed, with its writer, in the specification).
//! The routines that need a unit's struct (the search position, the game variables, the
//! time state) are composed in src/engine_root.zig (`EngineRoot.startUp`, `EngineRoot.autoPlay`,
//! `EngineRoot.newGameCommand`); this file works on DGROUP's bytes by address, in a store the
//! caller gives (`m`: `dgroup.ImageMem` on an image, or the engine's homes, engine_root
//! `EngineRoot.Home`, where each byte is at the member that holds it; Stage B step 8, stage 4).

const std = @import("std");
const dgroup = @import("dgroup.zig");
const hashsize = @import("hashsize.zig");

const word = dgroup.memWord;
const setWord = dgroup.memSetWord;
const setDword = dgroup.memSetDword;

// ---------------------------------------------------------------------------
// The settings files (38C0:B976)
// ---------------------------------------------------------------------------

/// SETTINGS.M80 as 38C0:B976 reads it: fscanf with "%5x" 22 times and "%c" (format at
/// DG:26BA), into these words in file order. The defaults are the shipped file
/// (reference/original/M80/SETTINGS.M80, checked by src/newgame_test.zig).
pub const Settings = struct {
    /// [bp-0Ah] -> DG:A274 (byte), the level.
    level: u16 = 0,
    /// [bp-0Eh]: by level, 1 -> DG:1DFC, 3 -> DG:1E02, 4 -> DG:1DFE, else DG:A8C6 (byte).
    level_value: u16 = 2,
    /// [bp-0Ch] -> DG:AC29 (byte).
    bac29: u16 = 0,
    /// [bp-34h] -> DG:A38A (word; A38B is RootState.a38b).
    user_book_flags: u16 = 0x0A12,
    /// [bp-32h] -> DG:A3F7 (byte).
    ba3f7: u16 = 0,
    /// [bp-30h] -> DG:AB1A (byte), the thinking display.
    think_display: u16 = 1,
    /// [bp-2Eh] -> DG:A6A0 (word): learning (A6A0 bit 4) and book learning (A6A1 bit 4).
    learn_flags: u16 = 0x1073,
    /// [bp-2Ch] -> DG:22D4 (byte).
    b22d4: u16 = 1,
    /// [bp-2Ah] -> DG:A8D6 (byte), sound.
    sound: u16 = 1,
    /// [bp-28h] -> DG:1B8E (word); 26h also sets DG:1B90 = C4h.
    w1b8e: u16 = 0x26,
    /// [bp-26h]: read, not stored.
    unused: u16 = 0xC4,
    /// [bp-24h] -> DG:1DFC, game in N minutes.
    game_in: u16 = 5,
    /// [bp-22h] -> DG:1DFE, mate in N.
    mate_in: u16 = 4,
    /// [bp-20h] -> DG:1E00.
    w1e00: u16 = 1,
    /// [bp-1Eh] -> DG:1E02, the fixed depth.
    fixed_depth: u16 = 4,
    /// [bp-1Ch] -> DG:24F0.
    w24f0: u16 = 5,
    /// [bp-1Ah] -> DG:A8C6 (byte), the preset.
    preset: u16 = 2,
    /// [bp-18h] -> DG:AAF4.
    waaf4: u16 = 0,
    /// [bp-16h] -> DG:1E34.
    w1e34: u16 = 0,
    /// [bp-14h] -> DG:239C, the tablebase settings.
    tb_settings: u16 = 0x0A,
    /// [bp-12h] -> DG:19D2.
    w19d2: u16 = 0x64,
    /// [bp-10h] -> DG:19D4.
    w19d4: u16 = 0,

    /// Parses the file's text (the 22 hexadecimal numbers); null if it has fewer.
    pub fn parse(text: []const u8) ?Settings {
        var out: Settings = .{};
        var it = std.mem.tokenizeAny(u8, text, " \t\r\n");
        inline for (@typeInfo(Settings).@"struct".field_names) |name| {
            const t = it.next() orelse return null;
            @field(out, name) = std.fmt.parseInt(u16, t, 16) catch return null;
        }
        return out;
    }
};

/// UBOOKS.M80 as 38C0:BB62 reads it ("%3d%3d%c"): the M-Chess book off (DG:A5EE) and the
/// user books off (DG:A002). The shipped file holds "  0  0".
pub const UserBooks = struct { mchess_book_off: u16 = 0, user_books_off: u16 = 0 };

/// Port of the settings load (38C0:B976-BBA5) for the files as read: the stores of
/// BA15-BA95, then the level checks BAAA-BB4D. The user-book names that follow
/// (BBA8-BC86) are not read: the shipped UBOOKS.M80 has none.
pub fn loadSettings(m: anytype, s: Settings, ub: UserBooks) void {
    m.set(0xAC29, @truncate(s.bac29));
    setWord(m, 0xA38A, s.user_book_flags);
    m.set(0xA3F7, @truncate(s.ba3f7));
    m.set(0xAB1A, @truncate(s.think_display));
    setWord(m, 0xA6A0, s.learn_flags);
    m.set(0x22D4, @truncate(s.b22d4));
    m.set(0xA8D6, @truncate(s.sound));
    setWord(m, 0x1B8E, s.w1b8e);
    m.set(0xA274, @truncate(s.level));
    m.set(0xA8C6, @truncate(s.preset));
    setWord(m, 0x1DFC, s.game_in);
    setWord(m, 0x1DFE, s.mate_in);
    setWord(m, 0x1E00, s.w1e00);
    setWord(m, 0x1E02, s.fixed_depth);
    setWord(m, 0x24F0, s.w24f0);
    setWord(m, 0xAAF4, s.waaf4);
    setWord(m, 0x1E34, s.w1e34);
    setWord(m, 0x239C, s.tb_settings);
    setWord(m, 0x19D2, s.w19d2);
    setWord(m, 0x19D4, s.w19d4);
    // BAAA-BAC0: the screen layout pair.
    if (s.w1b8e == 0x26) setWord(m, 0x1B90, 0xC4) else {
        setWord(m, 0x1B8E, 0x1D);
        setWord(m, 0x1B90, 0x72);
    }
    // BAD8-BAF9: level 2 without its records, or a level outside 0..7, becomes 0.
    if (m.get(0xA274) == 2 and m.get(0x2605) == 0) m.set(0xA274, 0);
    const lv: i8 = @bitCast(m.get(0xA274));
    if (lv < 0 or lv > 7) m.set(0xA274, 0);
    // BAFE-BB37: the level's own value.
    switch (m.get(0xA274)) {
        1 => setWord(m, 0x1DFC, s.level_value),
        3 => setWord(m, 0x1E02, s.level_value),
        4 => setWord(m, 0x1DFE, s.level_value),
        else => m.set(0xA8C6, @truncate(s.level_value)),
    }
    const pr: i8 = @bitCast(m.get(0xA8C6));
    if (pr < 0 or pr > 9) m.set(0xA8C6, 2);
    // BB4D-BB60.
    m.set(0xA67C, 0);
    setWord(m, 0x1DF8, 0);
    dgroup.memFill(m, 0xA242, 9, 0);
    // BB9C-BBA5: UBOOKS.M80.
    setWord(m, 0xA5EE, ub.mchess_book_off);
    setWord(m, 0xA002, ub.user_books_off);
}

/// The menu choices of the repeatable state (AGENTS.md section 5) as the menus store
/// them [traced]: Openings / ignore the book (key K, 1E9D:8CCF: DG:A5EE = 1); Settings /
/// learning off and book learning off (2B9F:9296, 92A6: bit 4 of DG:A6A0 and of DG:A6A1
/// cleared); Levels / Fixed depth N (set_level_type 2B9F:B8CB DG:A274 = 3, 2B9F:B8EE
/// DG:1E02 = N, level_changed 2B9F:B94E-B9A4 DG:75B7 = 0 and DG:1E08 = 0). The time
/// state the level change recomputes (next_control_moves, reset_clocks) is
/// `EngineRoot.levelChanged`.
pub fn repeatableState(m: anytype, depth: u16) void {
    setWord(m, 0xA5EE, 1);
    m.set(0xA6A0, m.get(0xA6A0) & ~@as(u8, 0x10));
    m.set(0xA6A1, m.get(0xA6A1) & ~@as(u8, 0x10));
    m.set(0xA274, 3);
    setWord(m, 0x1E02, depth);
    m.set(0x75B7, 0);
    setWord(m, 0x1E08, 0);
}

// ---------------------------------------------------------------------------
// Start-up (main 0000:0036-023B and hash_setup 0000:7180-77A0)
// ---------------------------------------------------------------------------

/// What the machine gives the program at start-up: the inputs of the start-up code that
/// are not in any file.
pub const Machine = struct {
    /// XMS function 08h's largest free block in KB (hash_setup 0000:72C0..), null for no
    /// XMS driver. The oracle offers 64,512 KB.
    xms_free_kb: ?u16 = 64512,
    /// DG:7258, the speed calibration (speed_calibration_end 1E9D:55B6), a measurement
    /// of the machine: 0562h on the oracle's emulator. Read only by the timed levels'
    /// budget (src/timebudget.zig `TimeState.speed`).
    speed: u16 = 0x0562,
    /// DG:2DC8, the C library's random seed after start-up: srand(BIOS tick count)
    /// (main 0109), then one rand() (4793:89D8). 11h in the oracle's runs (its virtual
    /// clock). Read only by rand, which the search calls only with random play.
    rand_seed: u32 = 0x11,
    /// DG:A512, the segment of the hash random table that new_game_position stores
    /// (0000:94C4): an address, 694Dh at the oracle's load segment; no unit reads it as
    /// data.
    random_segment: u16 = 0x694D,
    /// The tablebase files found at start-up (tb_scan_files 2B9F:C158): with the shipped
    /// TB folder (KPK, KQK, KRK for both sides) it leaves six material signatures.
    tablebases: bool = true,
    /// The signatures the scan leaves for the TB folder the engine has: the shipped six
    /// (`shipped_tb_signatures`) or the "cd" set's 62 (`cd_tb_signatures`).
    tb_signatures: []const u16 = &shipped_tb_signatures,
};

/// DG:239A and DG:A422..A42D as tb_scan_files (2B9F:C158) leaves them with the shipped
/// TB folder [traced: the oracle's image at main 0526]: six signatures (KQK, KRK, KPK
/// for each side to move).
pub const shipped_tb_signatures = [6]u16{ 0x4000, 0x1F00, 0x1100, 0x0040, 0x001F, 0x0011 };

/// DG:239A and DG:A422 as tb_scan_files leaves them with the "cd" TB folder (the shipped
/// six and 60 of reference/tablebases/m80-cd, no KPPK or KPKP; owner decision 33)
/// [traced: tools/research/tablebase/startscan.py --tbset cd, 2026-11-20, equal to the
/// scan's model]: the *.TBW pass, then the *.TBB pass with each word byte-swapped and a
/// word already present (the five materials with equal sides) not added again, in the
/// emulator's findfirst order (names sorted). The order is never read: the probe only
/// asks whether a word is in the table (2B9F:BBD1-BBFD).
pub const cd_tb_signatures = [62]u16{
    0x1600, 0x0B00, 0x0B0B, 0x0B0A, 0x0B40, 0x1500, 0x4B00, 0x0A00, 0x0A0A, 0x0A40, 0x1400,
    0x4A00, 0x4000, 0x2A00, 0x1F00, 0x1F0B, 0x1F0A, 0x1F40, 0x1F1F, 0x1F11, 0x2900, 0x5F00,
    0x3E00, 0x3000, 0x1C00, 0x1100, 0x110B, 0x110A, 0x1140, 0x1111, 0x1B00, 0x5100, 0x2200,
    0x0016, 0x000B, 0x0A0B, 0x400B, 0x0015, 0x004B, 0x000A, 0x400A, 0x0014, 0x004A, 0x0040,
    0x002A, 0x001F, 0x0B1F, 0x0A1F, 0x401F, 0x111F, 0x0029, 0x005F, 0x003E, 0x0030, 0x001C,
    0x0011, 0x0B11, 0x0A11, 0x4011, 0x001B, 0x0051, 0x0022,
};

/// hash_setup (0000:7180) on its XMS path, as far as it writes what the search and
/// main's hash decision read: src/hashsize.zig `setup` for the sizes, mask and mode,
/// and the memory hash_resize reads later (DG:00E2 the memory on offer, DG:9352 the
/// tables allocated, DG:12CA the total requested). Also DG:9DBC = 1 (73E1, the XMS
/// tables are there; read by 0000:910E) and DG:AFC2 = 1 (7609, the conventional buffer
/// allocated; read by 0000:914C, 7626) [traced].
pub fn hashSetup(m: anytype, xms_free_kb: ?u16) void {
    const s = hashsize.setup(xms_free_kb);
    setDword(m, 0x00E2, @bitCast(s.mem.avail_kb));
    setWord(m, 0x9352, @intFromBool(s.mem.xms_ready));
    setDword(m, 0x12C6, @bitCast(s.tables.size_kb));
    setDword(m, 0xB624, s.tables.mask);
    m.set(0x9316, s.tables.mode);
    setWord(m, 0xA3F8, s.tables.enabled);
    setDword(m, 0x005A, @bitCast(s.tables.table_bytes));
    setDword(m, 0x12CA, @bitCast(s.total_kb));
    if (s.mem.xms_ready) m.set(0x9DBC, 1);
    m.set(0xAFC2, 1);
}

/// The start-up writes of engine state that come neither from a file nor from a ported
/// routine [traced: the writer of each, in the run of tools/research/newgame/trace.py]:
/// main 0000:012B [73F8] = A36C (where play_best_move finds the move); 0000:7079
/// (sub 6F7E) [90AE] = 1 (main 0598 redraws and clears it); 4793:6306 (book_probe at
/// start-up, with the book on) [9FD2] = 5 and [7449] = 1; 2B9F:A17B [A22A] = 1;
/// 38C0:755C [A254 + 2i] = 3 (i + 1), i < 8; the timer pointers of 0000:7701-770D.
pub fn startUpConstants(m: anytype, mc: Machine) void {
    setWord(m, 0x73F8, 0xA36C);
    m.set(0x90AE, 1);
    m.set(0x9FD2, 5);
    m.set(0x7449, 1);
    m.set(0xA22A, 1);
    for (0..8) |i| setWord(m, @intCast(0xA254 + 2 * i), @intCast(3 * (i + 1)));
    setWord(m, 0xA09A, 0x046C);
    setWord(m, 0xA09C, 0);
    setWord(m, 0xB4AE, 0x3A30);
    setWord(m, 0x7258, mc.speed);
    setDword(m, 0x2DC8, mc.rand_seed);
    setWord(m, 0xA512, mc.random_segment);
    if (mc.tablebases) {
        // The scan adds at most 50h words (2B9F:C2A6).
        std.debug.assert(mc.tb_signatures.len <= 0x50);
        setWord(m, 0x239A, @intCast(mc.tb_signatures.len));
        for (mc.tb_signatures, 0..) |v, i| setWord(m, @intCast(0xA422 + 2 * i), v);
    }
}

/// new_game_position's clears (0000:919C-9250) [read]: the screen board DG:7104 (120
/// bytes of 7), the reversible bytes DG:3490 (196h), DG:A28C (100 bytes of FFh), the
/// leaf map DG:8FE4, the king-ray maps DG:A09E and DG:A164, DG:A51C, the pawn attacks
/// DG:37DA and the search board DG:9EF6 (198 bytes each), and eight evaluation tables
/// of 200 bytes (DG:75CA, 76A2, AC2A, ACF4, 9182, 924A, 8DEA, 8EB8). The board, lists
/// and maps written after them are setup.newGame's; the game variables
/// gamemove.newGameVars'. 3,414 bytes, in the original's order; in the engine each at its
/// home (`EngineRoot.Home`), so a run that spans two members' variables reaches each.
pub fn newGameClears(m: anytype) void {
    dgroup.memFill(m, 0x7104, 0x78, 7);
    dgroup.memFill(m, 0x3490, 0x196, 0);
    dgroup.memFill(m, 0xA28C, 0x64, 0xFF);
    for ([_]u16{ 0x8FE4, 0xA09E, 0xA164, 0xA51C, 0x37DA, 0x9EF6 }) |a| dgroup.memFill(m, a, 0xC6, 0);
    for ([_]u16{ 0x75CA, 0x76A2, 0xAC2A, 0xACF4, 0x9182, 0x924A, 0x8DEA, 0x8EB8 }) |a| dgroup.memFill(m, a, 0xC8, 0);
}

/// maybe_reset_game_9d92 (0000:94E4) [read]: a resignation recorded at DG:9D92 is
/// forgotten (the display call 1E9D:74C8 is not ported).
pub fn maybeResetResignation(m: anytype) void {
    if (word(m, 0x9D92) != 0) setWord(m, 0x9D92, 0);
}

/// main from the top of a game (0000:013B-023B) [read], the engine state only. `first`:
/// the program's start (main 012B also sets [73F8] and clears the far byte 3968;
/// `startUpConstants`). The time state of 01E0-0203 (next_control_moves and
/// reset_clocks with the move number one higher) is `EngineRoot.mainTop`'s.
/// Returns whether 01E0's condition held (the caller then runs the time state).
pub fn mainTop(m: anytype) bool {
    m.set(0xA40F, 0);
    if (m.get(0x366F) == 0) setWord(m, 0xA8DA, 0);
    m.set(0x9EEC, m.get(0x717C));
    m.set(0x2A6A, 1);
    m.set(0x1B8C, 0);
    maybeResetResignation(m);
    m.set(0x73FE, 1);
    if (word(m, 0x153C) != 0 and word(m, 0xA00A) == 0) {
        setWord(m, 0x2ACE, 0);
        setWord(m, 0x2ACC, 0);
        setWord(m, 0x2AD2, 0);
        setWord(m, 0x9FBC, 0);
    }
    setWord(m, 0xA3FA, 0);
    m.set(0x776A, 0);
    m.set(0x9D86, 0);
    m.set(0x9FD0, 0);
    m.set(0x3676, 0);
    if (m.get(0x70E4) != 0) setWord(m, 0x9FBC, 0xFF9C);
    // (01C6-01DD: book_probe(3, 0) with [153C] and not [24EA]: a new game with the book
    // on; not bound, the book is ignored.)
    const time = m.get(0x366F) == 0 and word(m, 0xA00A) == 0 and m.get(0xA00D) == 0;
    setWord(m, 0x2508, 0);
    m.set(0x366F, 0);
    return time;
}

/// main 0000:023C-04A7 on the path auto-play and a waiting program take (no pondering:
/// [3674] or the level stops it, or [A3FA] = 0) [read; traced in auto-play], the engine
/// state: [8BAA] = [153C] = 0 (02A2); [3676] = 0 (030C, 0350); [9EEC] = [717C] (0444).
/// The control-time test of 0458-04A5 is `EngineRoot.turn`'s. (With [153C], a New game, it
/// first clears the learning score history 0000:0008.)
pub fn mainBeforeCommandLoop(m: anytype) void {
    if (word(m, 0x153C) != 0) {
        // 024D-02A0, the engine state: 0000:0008 clears the score history kept for
        // learning; [9EB8] = [A414] = [2500] = 0.
        for ([_]u16{ 0x2522, 0x251A, 0x2526, 0x251E, 0x2516, 0x2512, 0x2524, 0x251C, 0x2528, 0x2520, 0x2518, 0x2514 }) |a| setWord(m, a, 0);
        setWord(m, 0x9EB8, 0);
        setWord(m, 0xA414, 0);
        setWord(m, 0x2500, 0);
    }
    setWord(m, 0x8BAA, 0);
    setWord(m, 0x153C, 0);
    m.set(0x3676, 0);
    m.set(0x9EEC, m.get(0x717C));
}

/// The command loop's entry (38C0:174A-1974) [traced]: [8BAA] = 0 (1757, 19DF),
/// [A4FA] = 0 (18A8); with White to move ([717C] = 0, the other side White) the move
/// number goes up by one (1970). Then (1974-198C) [read], the end of the game record: at
/// move number 202 (CAh) or more the game is over, [A6AE] = the game ply, a message, and
/// the loop waits for a key (1E98), so the program neither searches nor plays again
/// (docs/arch/34-game-move-path.md, "How long a game can be"). Returns false then.
pub fn commandLoopEntry(m: anytype) bool {
    setWord(m, 0x8BAA, 0);
    m.set(0xA4FA, 0);
    if (m.get(0x717C) == 0) setWord(m, 0xA84A, word(m, 0xA84A) +% 1);
    if (@as(i16, @bitCast(word(m, 0xA84A))) >= max_move_number) {
        setWord(m, 0xA6AE, word(m, 0x9FC8));
        return false;
    }
    return true;
}

/// The move number DG:A84A at which the command loop ends the game (38C0:1974) and Ctrl-A
/// refuses (3F1C): CAh = 202, the game record's 0CBh entries per side (move numbers 0..202).
/// The move number is 1 at White's first move, so the game ends at game ply 402.
pub const max_move_number: i16 = 0xCA;

/// Ctrl-A, auto-play (38C0:3F1C-3F29) [read]: below move 202, [9FCF] = 1 and
/// [A28A] = 0; then the program takes the move (`programTakesMove`).
pub fn autoPlayKey(m: anytype) bool {
    if (@as(i16, @bitCast(word(m, 0xA84A))) >= max_move_number) return false;
    m.set(0x9FCF, 1);
    setWord(m, 0xA28A, 0);
    return true;
}

/// The program takes the side to move (38C0:3FAA-3FE1) [read; traced at Ctrl-A and at
/// every auto-play turn]: [8DDE] = [717C], [717C] = 1 - that, [A8DA] = [A3FA] = [A6AE]
/// = 0, then (by the caller, `EngineRoot`) the program's time left from its clock, [AB9E] = 2,
/// maybe_reset_game_9d92.
pub fn programTakesMove(m: anytype) void {
    const opp = m.get(0x717C);
    m.set(0x8DDE, opp);
    m.set(0x717C, 1 -% opp);
    setWord(m, 0xA8DA, 0);
    setWord(m, 0xA3FA, 0);
    setWord(m, 0xA6AE, 0);
}

/// After the program's time left: 3FDC-3FFE and the command loop's exit 517C [read].
pub fn commandLoopExit(m: anytype) void {
    m.set(0xAB9E, 2);
    maybeResetResignation(m);
    setWord(m, 0x2500, 0);
    setWord(m, 0xB4DE, word(m, 0x9FC8));
}

/// main 0000:04AD-0525 [read]: [B620] = 0 (04AD); with [A40F] = 0 the display
/// 1E9D:8ECC (which also clears [1B8A] and [776A], 8EE0-8EE3 [traced]). What main does
/// from 0526 on is rootprep's (src/rootprep.zig, `EngineRoot.search`).
pub fn mainToSearch(m: anytype) void {
    setWord(m, 0xB620, 0);
    m.set(0x1B8A, 0);
    m.set(0x776A, 0);
}
