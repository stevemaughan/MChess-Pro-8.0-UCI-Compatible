//! The game-move path: what the original does to its engine state when a move is
//! played in the game, by the program or entered for the side to move, when an
//! entered move is checked, when a ply is taken back, and the game variables of New
//! game. Specification: docs/arch/34-game-move-path.md; the proved model is
//! tools/research/gamemove/model.py.
//!
//! Ported bodies (each proved by replaying calls recorded from the original,
//! src/gamemove_test.zig):
//!
//! - play_best_move (38C0:01E0-0D21), the program's move;
//! - play_entered_move (38C0:554E-5709), a move entered for the side to move;
//! - check_entered_move (38C0:5864-5A8D), the legality test of an entered move;
//! - take_back_ply (38C0:570A-5863);
//! - the game variables of new_game_position (0000:93C0-94E3); its board, lists and maps
//!   are `setup.newGamePosition`;
//! - update_castle_stamps (38C0:0130-0181) and repetition_count (2B9F:402A-40A7), whole;
//! - set_predicted_reply (38C0:0D22-110A), which play_best_move calls in normal play (not
//!   in auto-play, the mode of the oracle's golden files): the opponent's replies scored
//!   and sorted, and the predicted reply that main ponders on;
//! - legal_move_exists (2B9F:458A-4A74) and king_attacked (2B9F:4B32-4B54), whole.
//!
//! Every other routine these call is reached through the `ctx` argument (see `Ctx`),
//! so that the replay test can answer it from the recording and the engine can bind it
//! to the ported routine (make_move, hash_from_scratch, book_key, the move
//! generators) or to nothing (the user interface).
//!
//! The game record lives in the original's far data segment 5A7B (`GameRecord`); the
//! search position is `position.Position`; the remaining DGROUP variables are
//! `GameVars`. The paths that run only with learning or book learning switched on
//! (38C0:0749-093B, 09F7-0BA5) are not ported: this project switches learning off
//! (AGENTS.md §8.2), and the port panics if it is asked to take them.

const std = @import("std");
const pos = @import("position.zig");
const Position = pos.Position;
const helpers = @import("helpers.zig");
const dgc = @import("original.zig").dgroup;

/// Entries per side in the per-move tables of the game record: move numbers 0..202.
pub const side_stride: u16 = 0xCB;
/// The captured-piece table's stride (5A7B:22EE), one more than the others.
pub const capture_stride: u16 = 0xCC;
/// Entries of the per-move tables (both sides).
pub const move_slots = 2 * side_stride;

// ---------------------------------------------------------------------------
// The game record (far segment 5A7B)
// ---------------------------------------------------------------------------

/// The game record: far data segment 5A7B (the original reaches it through the far
/// pointers DG:30CC..30EE, all equal to the segment). A "slot" is `side * 0xCB + move
/// number`, 16-bit; the per-position tables are indexed by the side to move and the
/// move number of the position *after* a move (White's move n leaves (Black, n), Black's
/// move n leaves (White, n + 1)).
pub const GameRecord = struct {
    /// 5A7B:01CA..01CF: the six bytes before the move table, which main reads as the move
    /// record of slot -1 (`rootprep` `recordMove`, 6·slot + 1CA, at slot 0). No routine
    /// writes them; 0 in every recorded far segment (Stage B step 8, stage 7).
    before_moves: [6]u8 = @splat(0),
    /// 5A7B:01D0 + 6 * slot of the mover: from, to, flag, captured piece, its piece-list
    /// slot, and a notation byte (moving piece code OR the disambiguation bits 10h/20h/30h
    /// of 38C0:D5E2). No engine routine reads the notation byte.
    moves: [move_slots][6]u8 = @splat(@splat(0)),
    /// 5A7B:0B54 + slot of the position: its check byte (8C06/8C07 after the move).
    pos_check: [move_slots]u8 = @splat(0),
    /// 5A7B:22EE + side * 0xCC + move number: the piece standing on the move's
    /// to-square before the move (0 for none; for en passant 0).
    captured: [move_slots]u8 = @splat(0),
    /// 5A7B:2484 + 2 * slot of the position: a score, as `play_best_move` and
    /// `play_entered_move` store it.
    pos_score: [move_slots]u16 = @splat(0),
    /// 5A7B:27B0 + 6 * game ply: the book key (DG:935A) after the move of that ply.
    book_keys: [485]u48 = @splat(0),
    /// 5A7B:330E + slot of the position: its en-passant square.
    pos_ep: [move_slots]u8 = @splat(0),
    /// 5A7B:3A34 + 6 * game ply: the main hash key after the move of that ply (ply 0:
    /// the start). `leaf.isRepetition` and `repetitionCount` read it; in the engine the
    /// node reads this table in place (`engine_root.EngineRoot.rec`).
    ///
    /// The original's room: 1,992 keys, up to 5A7B:68E3; `gave_check` begins two bytes
    /// later, at 68E6. (Declared 1,997 until Stage B step 8, stage 2, which made the last
    /// five keys and the first 28 `gave_check` bytes the same far memory, harmless only
    /// because the slide shifts `gave_check` after the keys.) A key of game ply 1,992 or
    /// more would write into `gave_check` in the original; the game ply stays below 340
    /// with the slide (DEV-F19) and below 450 without it, so no path reaches it, and
    /// prepare_eval's key store refuses it (`engine_root` `prepareEval`).
    keys: [key_room]u48 = @splat(0),
    /// 5A7B:68E4..68E5: the two bytes between the keys' room and `gave_check`, which the
    /// slide's shift of the 1,997 key entries the far table declares reads and writes
    /// (`gameslide`); 0 in every recorded far segment (Stage B step 8, stage 7).
    key_gap: [2]u8 = @splat(0),
    /// 5A7B:68E6 + slot of the mover: 1 if the move gave check, else 0.
    gave_check: [move_slots]u8 = @splat(0),

    /// The record's byte at offset `off` of the far segment, or null where no field is.
    pub fn byteAt(rec: *const GameRecord, off: u16) ?u8 {
        inline for (@typeInfo(@TypeOf(record_offsets)).@"struct".field_names) |name| {
            const base: u16 = @field(record_offsets, name);
            const F = @FieldType(GameRecord, name);
            if (off >= base and off < base + comptime originalSize(F)) {
                const rel = off - base;
                return elemByte(&@field(rec, name), rel);
            }
        }
        return null;
    }

    /// Writes the record's byte at offset `off`; false where no field is.
    pub fn setByteAt(rec: *GameRecord, off: u16, v: u8) bool {
        inline for (@typeInfo(@TypeOf(record_offsets)).@"struct".field_names) |name| {
            const base: u16 = @field(record_offsets, name);
            const F = @FieldType(GameRecord, name);
            if (off >= base and off < base + comptime originalSize(F)) {
                setElemByte(&@field(rec, name), off - base, v);
                return true;
            }
        }
        return false;
    }

    /// The record written into the far segment `far` at the original's offsets, every
    /// field (the keys before `gave_check`); bytes no field holds are left as they are.
    pub fn toFar(rec: *const GameRecord, far: *[0x10000]u8) void {
        inline for (@typeInfo(@TypeOf(record_offsets)).@"struct".field_names) |name| {
            const base: usize = @field(record_offsets, name);
            const v = &@field(rec, name);
            const E = @typeInfo(@TypeOf(v.*)).array.child;
            switch (@typeInfo(E)) {
                .int => |i| {
                    const n = i.bits / 8;
                    if (n == 1) @memcpy(far[base..][0..v.len], v) else for (v, 0..) |x, k| std.mem.writeInt(E, far[base + n * k ..][0..n], x, .little);
                },
                .array => @memcpy(far[base..][0 .. v.len * 6], std.mem.asBytes(v)),
                else => comptime unreachable,
            }
        }
    }

    /// The record read from the far segment `far` (every field).
    pub fn fromFar(rec: *GameRecord, far: *const [0x10000]u8) void {
        inline for (@typeInfo(@TypeOf(record_offsets)).@"struct".field_names) |name| {
            const base: usize = @field(record_offsets, name);
            const v = &@field(rec, name);
            const E = @typeInfo(@TypeOf(v.*)).array.child;
            switch (@typeInfo(E)) {
                .int => |i| {
                    const n = i.bits / 8;
                    if (n == 1) @memcpy(v, far[base..][0..v.len]) else for (v, 0..) |*x, k| {
                        x.* = std.mem.readInt(E, far[base + n * k ..][0..n], .little);
                    }
                },
                .array => @memcpy(std.mem.asBytes(v), far[base..][0 .. v.len * 6]),
                else => comptime unreachable,
            }
        }
    }
};

/// The original's room for the game record's keys (5A7B:3A34 to 68E3).
pub const key_room = (0x68E6 - 0x3A34) / 6;

fn elemByte(arr: anytype, rel: u16) u8 {
    const E = @typeInfo(@TypeOf(arr.*)).array.child;
    const n = comptime originalSize(E);
    const e = arr[rel / n];
    const k = rel % n;
    return switch (@typeInfo(E)) {
        .int => @truncate(e >> @intCast(8 * k)),
        .array => e[k],
        else => comptime unreachable,
    };
}

fn setElemByte(arr: anytype, rel: u16, v: u8) void {
    const E = @typeInfo(@TypeOf(arr.*)).array.child;
    const n = comptime originalSize(E);
    const e = &arr[rel / n];
    const k = rel % n;
    switch (@typeInfo(E)) {
        .int => {
            const shift: std.math.Log2Int(E) = @intCast(8 * k);
            e.* = (e.* & ~(@as(E, 0xFF) << shift)) | (@as(E, v) << shift);
        },
        .array => e[k] = v,
        else => comptime unreachable,
    }
}

/// The far-segment offset of each GameRecord field (for the replay test and the
/// specification).
pub const record_offsets = .{
    .before_moves = 0x01CA,
    .moves = 0x01D0,
    .pos_check = 0x0B54,
    .captured = 0x22EE,
    .pos_score = 0x2484,
    .book_keys = 0x27B0,
    .pos_ep = 0x330E,
    .keys = 0x3A34,
    .key_gap = 0x68E4,
    .gave_check = 0x68E6,
};

// ---------------------------------------------------------------------------
// The DGROUP variables of the game-move path, other than the search position
// ---------------------------------------------------------------------------

/// Every DGROUP variable the ported bodies read or write that `Position` does not hold.
/// Fields another unit also declares say so; docs/arch/34-game-move-path.md lists them.
///
/// Since Stage B step 8, stage 2 (docs/arch/60-engine-assembly.md section 10.7.10), the
/// value fields are the variables no other struct of the engine declares: `GameVars` is
/// their one home (in the engine, the persistent `engine_state.Members.gv`). Every other
/// field is a pointer to the variable's one home, bound before use: the struct of the node
/// domain that holds it (the search's state, the position, the evaluation's variables, the
/// threat evaluators' tails: `engine_state` `bindGameVars`), or, for a variable the root's
/// views, Setup mode, the time budget or prepare_eval's tables also declare, its home since
/// Stage B step 8, stage 7: `rootvars.RootVars` or `ProgramVars`. A routine run on an image
/// (the replay test) binds them to it (`bindImage`). A multi-byte pointer is `align(1)`: it
/// points at the original's bytes.
pub const GameVars = struct {
    /// DG:717C: the side the program does not play; for an entered move, the mover.
    /// (Also `setup.SetupVars.side`, `evaltables.Inputs.opponent_side`.)
    opponent_side: *u8 = undefined,
    /// DG:8DDE: the side the program plays. (Also `SetupVars.computer_side`.)
    computer_side: *u8 = undefined,
    /// DG:A84A: the move number. (Also `SetupVars.move_number`, `Inputs.move_number`.)
    move_number: *align(1) u16 = undefined,
    /// DG:A8DA: the last iteration's score. (Also `RootState.last_score`.)
    last_score: *align(1) u16 = undefined,
    /// DG:7328: game status: 0 none, 1 check, 2 check with a mate score, 3 / 4 mate
    /// scores (4: mate found), 5 third repetition, 6 bare kings drawn, 7 no legal move
    /// for the side to move. (Also `SetupVars.in_check`.)
    status: *u8 = undefined,
    /// DG:A4FA: the stop code (docs/arch/31-root-iteration-time.md §5).
    stop: *u8 = undefined,
    /// DG:38A0: the program's move as played: from, to, flag; then the captured piece
    /// and its slot, written by make_move.
    played: *[5]u8 = undefined,
    /// DG:9360: the entered move, the same five bytes.
    entered: [5]u8 = @splat(0),
    /// DG:935A: the book key (4793:5816) of the position after the move.
    book_key: u48 = 0,
    /// DG:3490 + game ply: low byte of the move's reversible word (FFh reversible, 0
    /// not); prepare_eval derives DG:7464 from it. 196h entries (New game clears
    /// 3490..3625; DG:3626 is `Position.quiet_move_by_ply`). (Also
    /// `Inputs.irreversible_by_ply`, also 196h.)
    irreversible: *[move_slots]u8 = undefined,
    /// DG:9D8A: repetition count of the position after the program's move, plus 1.
    repetitions: *u8 = undefined,
    /// DG:A36A: the game ply after the last move played (not set by a ponder move).
    last_played_ply: *align(1) u16 = undefined,
    /// DG:3676: thinking on the opponent's time.
    pondering: *u8 = undefined,
    /// DG:7464: game ply of the last irreversible move, as prepare_eval left it.
    /// (Also `leaf.LeafVars`, `EvalState`, `Tables`, `SetupVars`, `searchnode.State`.)
    last_irreversible_ply: *align(1) u16 = undefined,
    /// DG:7104: a 10x12 board for the screen (a1 at DG:7119). New game fills it with 7;
    /// play_best_move copies the 78 bytes from a1 (DG:9F0B) of the search board into it.
    board_copy: [120]u8 = @splat(7),
    /// DG:A38C: the program's material without pawns before its move.
    computer_piece_material: u16 = 0,
    /// DG:7814: the length of a game being replayed.
    replay_end_ply: u16 = 0,
    /// DG:A00A: a mode word (non-zero: replay a game from the record).
    mode_a00a: *align(1) u16 = undefined,
    /// DG:1BAC: auto-play of book moves.
    mode_1bac: *u8 = undefined,
    /// DG:A6AE: game ply at which the game ended (0: not ended).
    game_over_ply: *align(1) u16 = undefined,
    /// DG:A28A, DG:9FCF (analysis / auto-play), DG:A274 (the level).
    mode_a28a: u16 = 0,
    analysis: *u8 = undefined,
    level: *u8 = undefined,
    /// DG:A3FA: 1 after set_predicted_reply has filled the reply list DG:3A34.
    reply_list_valid: *align(1) u16 = undefined,
    /// DG:75C4: the number of legal replies in that list.
    reply_count: u16 = 0,
    /// DG:25FC: messages off. DG:1B8A: a message pending. DG:A8D6: sound.
    quiet: u16 = 0,
    message: u8 = 0,
    sound: u8 = 0,
    /// DG:251E, 2516, 251A, 2526 (per side): the program's score history kept for
    /// learning: the ply of its first move out of book, the score then, the number of
    /// drops, and (learning only) a ply.
    first_ply: [2]u16 = @splat(0),
    first_score: [2]u16 = @splat(0),
    drops: [2]u16 = @splat(0),
    learn_ply: [2]u16 = @splat(0),
    /// DG:A6A0, DG:A6A1: learning and book-learning flags (bit 10h each).
    learn_flags: *u8 = undefined,
    book_learn_flags: *u8 = undefined,
    /// DG:B622: KBN against king. DG:9D92: game ply at which the program resigned (0
    /// none; also `Inputs.reset_ply`). DG:24F2: a mode byte. DG:A8C6: the level preset.
    kbn: *u8 = undefined,
    resigned_ply: *align(1) u16 = undefined,
    mode_24f2: u8 = 0,
    preset: *u8 = undefined,
    /// DG:77EC: time left per side, dwords. (Also `RootState.time_left`.)
    time_left: *align(1) [2]u32 = undefined,
    /// DG:2504: an end-of-game message pending (1 fifty moves, 2 resignation).
    message_2504: u16 = 0,
    /// DG:1B88, DG:19D4, DG:19D2, DG:9E96..9E97, DG:A4C2: display and comment settings.
    w1b88: u16 = 0,
    w19d4: u16 = 0,
    w19d2: u16 = 0,
    w9e96: *[2]u8 = undefined,
    wa4c2: u16 = 0,
    /// DG:A414 (the predicted reply), DG:B42B (pv_length).
    predicted: *align(1) u16 = undefined,
    pv_length: *u8 = undefined,
    /// DG:9FBC: book exit ply.
    book_exit_ply: *align(1) u16 = undefined,
    /// DG:75B7: menu depth. DG:A35C depth reached, DG:744E horizon, DG:24F6, DG:A38B,
    /// DG:24F0: analysis display settings.
    menu_depth: *u8 = undefined,
    depth_reached: *u8 = undefined,
    horizon: *u8 = undefined,
    w24f6: *align(1) u16 = undefined,
    ba38b: *u8 = undefined,
    w24f0: *align(1) u16 = undefined,
    /// DG:9361 copy is `entered[1]`. Bytes New game sets to 0 and nothing here reads:
    /// DG:A2ED, A2A7, AE44, AC29, A4F3, B42A, 70E4, A4F2, 3675, and words 9EB6, 153C,
    /// A4C4, A510; DG:A512 the hash random segment.
    ba2ed: *u8 = undefined,
    ba2a7: *u8 = undefined,
    bae44: *u8 = undefined,
    bac29: u8 = 0,
    ba4f3: *u8 = undefined,
    bb42a: *u8 = undefined,
    b70e4: *u8 = undefined,
    ba4f2: *u8 = undefined,
    b3675: *u8 = undefined,
    w9eb6: *align(1) u16 = undefined,
    w153c: *align(1) u16 = undefined,
    wa4c4: u16 = 0,
    wa510: u16 = 0,
    wa512: u16 = 0,

    // ---- set_predicted_reply (38C0:0D22) ----
    /// DG:8FDE..8FE1: the predicted reply (from, to, flag, captured piece); from 0: none.
    /// main ponders on it (0000:02D3, 0318) and compares the opponent's move with it.
    predicted_reply: [4]u8 = @splat(0),
    /// DG:A366: the number of replies generated into the list DG:3A34 (`reply_count` is
    /// the number of legal ones).
    reply_total: u16 = 0,
    /// DG:8D0A + 2i: the score of reply i (the root's score array, `RootState`).
    reply_scores: *align(1) [100]u16 = undefined,
    /// DG:B59E: the check byte DG:8C07 after the predicted reply. DG:741B: a copy of its
    /// captured piece. (Read by main's display and the ponder-hit test, 1E9D:8771.)
    predicted_check: u8 = 0,
    predicted_captured: *u8 = undefined,
    /// DG:A416: the reply the search expected (from, to), DG:A414's neighbour.
    search_reply: *align(1) u16 = undefined,
    /// DG:A3F4 (iteration, a byte here), DG:A5EC, DG:9356, DG:A272 (queen_pin_depth,
    /// qs_limit2, qs_limit1), DG:A40E (a flag for the threat evaluators): search
    /// parameters the evaluators read, set for the one-ply scoring. (Also `RootState`.)
    iteration: *u8 = undefined,
    queen_pin_depth: *align(1) u16 = undefined,
    qs_limit2: *align(1) u16 = undefined,
    qs_limit1: *align(1) u16 = undefined,
    flag_a40e: *u8 = undefined,
    /// DG:AE36: a setting; with it a predicted reply scoring 150 below the best is
    /// replaced. DG:A8DE: evaluation by the first static term only. DG:A5F5:
    /// passed_threat_bits (bit 1: +200 / -1400). DG:A6C3: phase_endgame.
    bae36: *u8 = undefined,
    ba8de: *u8 = undefined,
    passed_threat_bits: *u8 = undefined,
    phase_endgame: *u8 = undefined,
    /// DG:73FE: castling_or_phase_changed (also `evaltables.Tables`, `rootprep`): set
    /// when the predicted reply is the best-scored one; with it set, main clears the
    /// hash tables before the next search (docs/arch/33-root-preparation.md step 9).
    changed_73fe: *u8 = undefined,
    /// DG:90B6, DG:369A: the pawn square sums (the search's `pawn_square_sum`), kept
    /// across each reply with DG:7182 (`Position.piece_square_sum`).
    sum_white_pawns: *align(1) u16 = undefined,
    sum_black_pawns: *align(1) u16 = undefined,
    /// DG:8FE4: the leaf attack map (198 bytes), written by 2B9F:40A8 / 42DA; only the
    /// replying king's square is read here, so only the first 120 bytes are declared
    /// (`leaf.LeafVars.leaf_map`; the rest, DG:905C, is `LeafVars.map_past`).
    leaf_map: *[0x78]u8 = undefined,

    /// Points every pointer field at its variable in the DGROUP image `img` (a routine
    /// that runs on the image, and the replay test).
    pub fn bindImage(gv: *GameVars, img: *[0x10000]u8) void {
        inline for (@typeInfo(GameVars).@"struct".field_names) |name| {
            const F = @FieldType(GameVars, name);
            if (@typeInfo(F) == .pointer) {
                const n = @sizeOf(@typeInfo(F).pointer.child);
                @field(gv, name) = @ptrCast(img[@field(var_addresses, name)..][0..n]);
            }
        }
    }
};

/// Whether `name` is a pointer field of `GameVars` (its home is another struct or the
/// image), and the number of the original's bytes a field covers.
pub fn isPointerVar(comptime name: []const u8) bool {
    return @typeInfo(@FieldType(GameVars, name)) == .pointer;
}
pub fn varBytes(comptime name: []const u8) usize {
    const F = @FieldType(GameVars, name);
    const T = if (@typeInfo(F) == .pointer) @typeInfo(F).pointer.child else F;
    return originalSize(T);
}
fn originalSize(comptime T: type) usize {
    return switch (@typeInfo(T)) {
        .int => |i| i.bits / 8,
        .array => |a| a.len * originalSize(a.child),
        else => @compileError("gamemove: unsupported field type"),
    };
}

/// DGROUP address of each GameVars field (for the replay test).
pub const var_addresses = .{
    .opponent_side = 0x717C,
    .computer_side = 0x8DDE,
    .move_number = 0xA84A,
    .last_score = 0xA8DA,
    .status = 0x7328,
    .stop = 0xA4FA,
    .played = 0x38A0,
    .entered = 0x9360,
    .book_key = 0x935A,
    .irreversible = 0x3490,
    .repetitions = 0x9D8A,
    .last_played_ply = 0xA36A,
    .pondering = 0x3676,
    .last_irreversible_ply = 0x7464,
    .board_copy = 0x7104,
    .computer_piece_material = 0xA38C,
    .replay_end_ply = 0x7814,
    .mode_a00a = 0xA00A,
    .mode_1bac = 0x1BAC,
    .game_over_ply = 0xA6AE,
    .mode_a28a = 0xA28A,
    .analysis = 0x9FCF,
    .level = 0xA274,
    .reply_list_valid = 0xA3FA,
    .reply_count = 0x75C4,
    .quiet = 0x25FC,
    .message = 0x1B8A,
    .sound = 0xA8D6,
    .first_ply = 0x251E,
    .first_score = 0x2516,
    .drops = 0x251A,
    .learn_ply = 0x2526,
    .learn_flags = 0xA6A0,
    .book_learn_flags = 0xA6A1,
    .kbn = 0xB622,
    .resigned_ply = 0x9D92,
    .mode_24f2 = 0x24F2,
    .preset = 0xA8C6,
    .time_left = 0x77EC,
    .message_2504 = 0x2504,
    .w1b88 = 0x1B88,
    .w19d4 = 0x19D4,
    .w19d2 = 0x19D2,
    .w9e96 = 0x9E96,
    .wa4c2 = 0xA4C2,
    .predicted = 0xA414,
    .pv_length = 0xB42B,
    .book_exit_ply = 0x9FBC,
    .menu_depth = 0x75B7,
    .depth_reached = 0xA35C,
    .horizon = 0x744E,
    .w24f6 = 0x24F6,
    .ba38b = 0xA38B,
    .w24f0 = 0x24F0,
    .ba2ed = 0xA2ED,
    .ba2a7 = 0xA2A7,
    .bae44 = 0xAE44,
    .bac29 = 0xAC29,
    .ba4f3 = 0xA4F3,
    .bb42a = 0xB42A,
    .b70e4 = 0x70E4,
    .ba4f2 = 0xA4F2,
    .b3675 = 0x3675,
    .w9eb6 = 0x9EB6,
    .w153c = 0x153C,
    .wa4c4 = 0xA4C4,
    .wa510 = 0xA510,
    .wa512 = 0xA512,
    .predicted_reply = 0x8FDE,
    .reply_total = 0xA366,
    .reply_scores = 0x8D0A,
    .predicted_check = 0xB59E,
    .predicted_captured = 0x741B,
    .search_reply = 0xA416,
    .iteration = 0xA3F4,
    .queen_pin_depth = 0xA5EC,
    .qs_limit2 = 0x9356,
    .qs_limit1 = 0xA272,
    .flag_a40e = 0xA40E,
    .bae36 = 0xAE36,
    .ba8de = 0xA8DE,
    .passed_threat_bits = 0xA5F5,
    .phase_endgame = 0xA6C3,
    .changed_73fe = 0x73FE,
    .sum_white_pawns = 0x90B6,
    .sum_black_pawns = 0x369A,
    .leaf_map = 0x8FE4,
};

/// The callees, for the documentation of `ctx`. Each is a method of the `ctx` the
/// routines below take:
///
/// - `notation(from: u8, to: u8, moving: u8) u8`: 38C0:D5E2, the notation bits (user
///   interface; the engine may return 0).
/// - `squareSums(move: [3]u8) void`: 0000:69DC (update_square_sums 0000:678A).
/// - `makeMove(buf: *[5]u8, side: u8, ply: u16) void`: make_move 1E9D:000C on the
///   move `buf[0..3]`, writing the captured piece and slot to `buf[3]`, `buf[4]`.
/// - `unmakeMove(move: [5]u8, side: u8) void`: unmake_move 1E9D:0960.
/// - `bookKey(side: u8) void`: book_key 4793:5816 into `GameVars.book_key`.
/// - `hashFromScratch() void`: 4793:4026 into `Position.hash_key`, `pawn_hash_key`.
/// - `legalMoveExists(side: u8) u16`: 2B9F:458A(side, 0).
/// - `predictReply(arg: u16) void`: set_predicted_reply 38C0:0D22 (the engine binds it
///   to `setPredictedReply` in normal play).
/// - `replyCall(callee: ReplyCallee, a: u16, b: u16) u16`: the evaluation routines
///   `setPredictedReply` calls (see `ReplyCallee`).
/// - `bookProbe(mode: u16, side: u8) void`: book_probe 4793:621E.
/// - `resetMoveTime() void`: reset_move_time_used 1E9D:7E8A.
/// - `genMoves(side: u8, in_check: bool) u16`: 38C0:E260 (in check) or 1E9D:3938, ply
///   0, into the list `list` (DG:3A34); the count.
/// - `kingAttacked(side: u8) u16`: 2B9F:4B32.
/// - `gameBoard(square: u8) u8`: the game board DG:7520 (`SetupVars.game_board`).
/// - `ported(site: u16, ax: u16) void`: a callee the port has just done itself
///   (update_castle_stamps, repetition_count); the engine binds it to nothing, the
///   replay test checks the state and AX against the recorded call.
/// - `ui(site: u16) void`: every user-interface callee, named by the offset of its call
///   (38C0 for the 38C0 routines, 0000 for new game); see the specification.
pub const Ctx = void;

inline fn s8(x: u8) i8 {
    return @bitCast(x);
}

inline fn s16(x: u16) i16 {
    return @bitCast(x);
}

/// `side * stride + n` as the original computes it (16-bit, side sign-extended).
inline fn slotOf(side: u8, stride: u16, n: u16) usize {
    const a: u16 = @bitCast(@as(i16, s8(side)) *% @as(i16, @intCast(stride)));
    return a +% n;
}

// ---------------------------------------------------------------------------
// Small callees, ported whole
// ---------------------------------------------------------------------------

/// Port of update_castle_stamps (38C0:0130-0181). A castling stamp still 0 is set to
/// the game ply when that side's rook of the wing (piece-list slot 4 for O-O, 5 for
/// O-O-O) has been captured (entry above 62h). make_move stamps a right lost by a king
/// or rook move; this catches the capture of a rook on its corner.
pub fn updateCastleStamps(p: *Position) void {
    const stamps = [4]*u16{ &p.oo_lost_at[0], &p.ooo_lost_at[0], &p.oo_lost_at[1], &p.ooo_lost_at[1] };
    const slots = [4]usize{ 4, 5, 16 + 4, 16 + 5 };
    for (stamps, slots) |st, sl| {
        if (st.* == 0 and p.piece_list[sl] > 0x62) st.* = p.game_ply;
    }
}

/// Port of repetition_count (2B9F:402A-40A7): the number of game plies g - 4, g - 6,
/// ... whose recorded key equals the current main key, from g = game ply down to the
/// last irreversible ply DG:7464 (as prepare_eval last left it). The loop runs
/// `((g - 4) - last + 2) >> 1` times (16-bit, unsigned shift) when g - 4 >= last
/// (signed).
pub fn repetitionCount(p: *const Position, gv: *const GameVars, rec: *const GameRecord) u16 {
    const g: i16 = s16(p.game_ply) -% 4;
    const last = s16(gv.last_irreversible_ply.*);
    if (g < last) return 0;
    var n: u16 = (@as(u16, @bitCast(g -% last)) +% 2) >> 1;
    var at: i32 = g;
    var count: u16 = 0;
    while (n != 0) : (n -= 1) {
        if (rec.keys[@intCast(at)] == p.hash_key) count += 1;
        at -= 2;
    }
    return count;
}

// ---------------------------------------------------------------------------
// king_attacked (2B9F:4B32) and legal_move_exists (2B9F:458A), ported whole
// ---------------------------------------------------------------------------

/// DG:04A2: pawn steps 9, 11, 10 (White adds them, Black subtracts). DG:04A6: rook steps.
const pawn_steps: [3]i8 = @bitCast(dgc(0x04A2, 3));
const rook_steps: [4]i8 = @bitCast(dgc(0x04A6, 4));
/// DG:1508, DG:1510: knight and king steps (the king's first four are the diagonals).
const knight_steps: [8]i8 = @bitCast(dgc(0x1508, 8));
const king_steps: [8]i8 = @bitCast(dgc(0x1510, 8));
/// By king-ray code (DG:A09E / A164: 1..8 White, 9..16 Black): DG:0490 the step away
/// from the king, DG:047E the line's bit; DG:0470 by piece code: the lines a piece moves
/// along (the bit test finds a slider pinning against that king).
const ray_step: [17]i8 = @bitCast(dgc(0x0490, 17));
const ray_bit = dgc(0x047E, 17);
const piece_bit = dgc(0x0470, 14);

/// Port of 2B9F:4B32(side): for side 0, whether Black attacks the White king's square
/// (black_attacks_square 2B9F:4AD4 at DG:A041); otherwise whether White attacks the Black
/// king's (2B9F:4A76 at DG:A051). AX 1 or 0.
pub fn kingAttacked(p: *const Position, side: u16) u16 {
    if (side == 0) return helpers.attacksSquare(p, .black, p.piece_list[7]);
    return helpers.attacksSquare(p, .white, p.piece_list[16 + 7]);
}

/// Port of legal_move_exists (2B9F:458A-4A74)(side, ply): 1 as soon as a piece of `side`
/// is found with a legal move, else 0; meant for a side not in check (play_best_move
/// calls it only then, for the stalemate status 7). By the piece code on the board at
/// each list entry (the dispatch 2B9F:45C8):
///
/// - pawn: the two captures (an enemy piece, or the en-passant square of `ply`), then the
///   push; a blocked push ends the pawn (the double push is never tried);
/// - knight: none if its king-ray byte names a line along which the first piece beyond it
///   is a slider of that line; else a step to an empty square or an enemy piece;
/// - bishop, rook: one step along each of its four lines (3 down to 0);
/// - queen: any king step to an empty or enemy square, without a pin test;
/// - king: a king step to an empty or enemy square the other side does not attack
///   (4AD4 / 4A76, with the king still on its square).
///
/// A pawn, bishop or rook on a king ray is moved on the board, the own king tested
/// (`kingAttacked`) and the board restored; the pawn taken en passant stays on the board
/// for that test. A captured piece's list entry (square + 63h, 120 or more) makes the
/// original read DG:9EF6 + entry beyond the board; the port skips the entry, which is the
/// original's behaviour while that byte is no piece code 1..13
/// (tools/port/gen_gamemove_vectors.py checks it at every recorded call).
pub fn legalMoveExists(p: *Position, side: u16, ply: u16) u16 {
    const base: usize = if (side == 0) 0 else 16;
    const ep: i16 = s8(p.ep_square_by_ply[ply]);
    for (0..16) |j| {
        const from: usize = p.piece_list[base + j];
        if (from >= 120) continue;
        const code = p.board[from];
        const found = switch (code) {
            pos.white_pawn => pawnHasMove(p, true, from, ep),
            pos.white_knight => knightHasMove(p, true, from),
            pos.white_bishop => stepperHasMove(p, true, from, king_steps[0..4], pos.white_bishop),
            pos.white_rook => stepperHasMove(p, true, from, &rook_steps, pos.white_rook),
            pos.white_queen => queenHasMove(p, true, from),
            pos.white_king => kingHasMove(p, true, from),
            pos.black_pawn => pawnHasMove(p, false, from, ep),
            pos.black_knight => knightHasMove(p, false, from),
            pos.black_bishop => stepperHasMove(p, false, from, king_steps[0..4], pos.black_bishop),
            pos.black_rook => stepperHasMove(p, false, from, &rook_steps, pos.black_rook),
            pos.black_queen => queenHasMove(p, false, from),
            pos.black_king => kingHasMove(p, false, from),
            else => false,
        };
        if (found) return 1;
    }
    return 0;
}

inline fn stepFrom(from: usize, st: i8) usize {
    return @intCast(@as(isize, @intCast(from)) + st);
}

/// An empty square or an enemy piece, as the original tests it: for White 0 or a signed
/// code above 7, for Black a signed code below 7.
inline fn isTarget(comptime white: bool, v: u8) bool {
    return if (white) v == 0 or s8(v) > 7 else s8(v) < 7;
}

/// Move the piece `code` from `from` to `to`, test its king, restore `to` to `restore`.
fn trialMove(p: *Position, comptime white: bool, from: usize, to: usize, code: u8, restore: u8) bool {
    p.board[to] = code;
    p.board[from] = pos.empty;
    const ok = kingAttacked(p, if (white) 0 else 1) == 0;
    p.board[from] = code;
    p.board[to] = restore;
    return ok;
}

fn pawnHasMove(p: *Position, comptime white: bool, from: usize, ep: i16) bool {
    const code = if (white) pos.white_pawn else pos.black_pawn;
    const pinned = p.king_rays[if (white) 0 else 1][from] != 0;
    inline for (0..2) |k| {
        const to = stepFrom(from, if (white) pawn_steps[k] else -pawn_steps[k]);
        const v = p.board[to];
        const enemy = if (white) s8(v) > 7 else (s8(v) > 0 and s8(v) < 7);
        if (enemy or ep == @as(i16, @intCast(to))) {
            if (!pinned) return true;
            if (trialMove(p, white, from, to, code, v)) return true;
        }
    }
    const to = stepFrom(from, if (white) pawn_steps[2] else -pawn_steps[2]);
    if (p.board[to] != pos.empty) return false;
    if (!pinned) return true;
    return trialMove(p, white, from, to, code, pos.empty);
}

fn knightHasMove(p: *const Position, comptime white: bool, from: usize) bool {
    const ray = p.king_rays[if (white) 0 else 1][from];
    if (ray != 0) {
        const dx = ray_step[ray];
        var s = stepFrom(from, dx);
        while (p.board[s] == pos.empty) s = stepFrom(s, dx);
        if (piece_bit[p.board[s]] & ray_bit[ray] != 0) return false;
    }
    var i: usize = 8;
    while (i > 0) {
        i -= 1;
        if (isTarget(white, p.board[stepFrom(from, knight_steps[i])])) return true;
    }
    return false;
}

fn stepperHasMove(p: *Position, comptime white: bool, from: usize, steps: *const [4]i8, code: u8) bool {
    const pinned = p.king_rays[if (white) 0 else 1][from] != 0;
    var i: usize = 4;
    while (i > 0) {
        i -= 1;
        const to = stepFrom(from, steps[i]);
        const v = p.board[to];
        if (!isTarget(white, v)) continue;
        if (!pinned) return true;
        if (trialMove(p, white, from, to, code, v)) return true;
    }
    return false;
}

fn queenHasMove(p: *const Position, comptime white: bool, from: usize) bool {
    var i: usize = 8;
    while (i > 0) {
        i -= 1;
        if (isTarget(white, p.board[stepFrom(from, king_steps[i])])) return true;
    }
    return false;
}

fn kingHasMove(p: *const Position, comptime white: bool, from: usize) bool {
    var i: usize = 8;
    while (i > 0) {
        i -= 1;
        const to = stepFrom(from, king_steps[i]);
        if (!isTarget(white, p.board[to])) continue;
        if (helpers.attacksSquare(p, if (white) .black else .white, to) == 0) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// set_predicted_reply (38C0:0D22)
// ---------------------------------------------------------------------------

/// The routines set_predicted_reply calls besides the generators and make / unmake,
/// reached through `ctx.replyCall(callee, a, b) u16`: `a` and `b` are the arguments named
/// here, AX is returned. `reply_callee_address` gives each one's address.
pub const ReplyCallee = enum {
    /// prepare_eval (0000:9582): the evaluation tables for the position after the move.
    prepare_eval,
    /// set_prescore_margins (0000:6BE4), set_search_margins (0000:6BF8).
    prescore_margins,
    search_margins,
    /// update_square_sums (0000:678A) and update_hash_key (4793:3EA2) for reply `a`
    /// (its index in the list DG:3A34).
    square_sums,
    update_key,
    /// leaf_attack_map_white (2B9F:40A8) / _black (2B9F:42DA): DG:8FE4.
    leaf_attack_map_white,
    leaf_attack_map_black,
    /// pawn_eval_wtm (0EF8:89DC) / _btm (0EF8:8F82).
    pawn_eval_wtm,
    pawn_eval_btm,
    /// static_eval (2B9F:000E)(a).
    static_eval,
    /// leaf_hanging_white_pieces (2B9F:5534) / _black (2B9F:4BFE).
    hanging_white,
    hanging_black,
    /// eval_pieces_and_kings (0EF8:0006)(a, b): (1, 1) after a White reply, (0, 1) after
    /// a Black one (the original's C argument order).
    pieces_and_kings,
    /// piece_activity_white (1E9D:16E4) / _black (1E9D:1E30).
    activity_white,
    activity_black,
    /// eval_endgame_king_white (1E9D:3416) / _black (1E9D:35FB).
    endgame_king_white,
    endgame_king_black,
    /// count_attacked_pieces_white_to_move (1E9D:CE3E) / black_to_move (1E9D:CC4E).
    count_attacked_wtm,
    count_attacked_btm,
    /// eval_threats_white (0EF8:A026) / _black (0EF8:CD20)(100, a = the count).
    threats_white,
    threats_black,
    /// sort_root_moves (0000:668E)(DG:3A34, a = the number of replies).
    sort_root_moves,
};

pub const reply_callee_address = std.enums.EnumArray(ReplyCallee, [2]u16).init(.{
    .prepare_eval = .{ 0x0000, 0x9582 },
    .prescore_margins = .{ 0x0000, 0x6BE4 },
    .search_margins = .{ 0x0000, 0x6BF8 },
    .square_sums = .{ 0x0000, 0x678A },
    .update_key = .{ 0x4793, 0x3EA2 },
    .leaf_attack_map_white = .{ 0x2B9F, 0x40A8 },
    .leaf_attack_map_black = .{ 0x2B9F, 0x42DA },
    .pawn_eval_wtm = .{ 0x0EF8, 0x89DC },
    .pawn_eval_btm = .{ 0x0EF8, 0x8F82 },
    .static_eval = .{ 0x2B9F, 0x000E },
    .hanging_white = .{ 0x2B9F, 0x5534 },
    .hanging_black = .{ 0x2B9F, 0x4BFE },
    .pieces_and_kings = .{ 0x0EF8, 0x0006 },
    .activity_white = .{ 0x1E9D, 0x16E4 },
    .activity_black = .{ 0x1E9D, 0x1E30 },
    .endgame_king_white = .{ 0x1E9D, 0x3416 },
    .endgame_king_black = .{ 0x1E9D, 0x35FB },
    .count_attacked_wtm = .{ 0x1E9D, 0xCE3E },
    .count_attacked_btm = .{ 0x1E9D, 0xCC4E },
    .threats_white = .{ 0x0EF8, 0xA026 },
    .threats_black = .{ 0x0EF8, 0xCD20 },
    .sort_root_moves = .{ 0x0000, 0x668E },
});

/// DG:00E6 + 2 * flag: a word subtracted from a reply's score by its move flag.
const flag_penalty: [7]u16 = blk: {
    const raw = dgc(0x00E6, 14);
    var t: [7]u16 = undefined;
    for (&t, 0..) |*x, k| x.* = @as(u16, raw[2 * k]) | @as(u16, raw[2 * k + 1]) << 8;
    break :blk t;
};
/// DG:03EA + 2 * n: threat_count_bonus, by the number of attacked pieces.
const threat_count_bonus: [32]u16 = blk: {
    const raw = dgc(0x03EA, 64);
    var t: [32]u16 = undefined;
    for (&t, 0..) |*x, k| x.* = @as(u16, raw[2 * k]) | @as(u16, raw[2 * k + 1]) << 8;
    break :blk t;
};

inline fn sar(x: u16, comptime n: u4) u16 {
    return @bitCast(s16(x) >> n);
}

/// Port of set_predicted_reply (38C0:0D22-110A), called by play_best_move after the
/// program's move (not in analysis or auto-play, not after a mate score of 19998 or more).
/// The opponent's replies are generated into the ply-0 list `list` (DG:3A34; the evasion
/// generator when in check); the list is marked valid (DG:A3FA, which `checkEnteredMove`
/// uses); with no reply, nothing more. Otherwise prepare_eval builds the evaluation tables
/// for the position, and each reply is made at ply 1, scored from the program's side by a
/// one-ply static evaluation (the static, pawn, piece, activity, endgame-king and threat
/// terms; a reply leaving its own king attacked is illegal: -20500 and one legal reply
/// fewer, DG:75C4), its captured piece stored in its list entry's score byte, and unmade.
/// The list is then sorted by these scores (DG:8D0A). The predicted reply (DG:8FDE) is
/// the search's own reply (DG:A416) if it was generated, is legal and is no
/// under-promotion; it is replaced by the best-scored reply when there is none, or when
/// DG:AE36 is set and the best scores at least 150 more, and then DG:73FE is set (so the
/// next search clears the hash tables). The search parameters the evaluators read are
/// set for one ply (DG:744E = DG:A3F4 = 1, DG:A5EC = DG:9356 = DG:A272 = 2); only
/// DG:A3F4 is put back.
///
/// The Black reply's first threat term adds the threat-count bonus where the White
/// reply's subtracts it (38C0:0FD0 against 0ED2, DEV-046); reproduced here, corrected in
/// `setPredictedReplyFixes`.
pub fn setPredictedReply(p: *Position, gv: *GameVars, list: *[100]pos.Move, ctx: anytype) void {
    setPredictedReplyFixes(pos.Fixes.original, p, gv, list, ctx);
}

/// `setPredictedReply` under `fixes` (DEV-046, `dev046_reply_sign`).
pub fn setPredictedReplyFixes(comptime fixes: pos.Fixes, p: *Position, gv: *GameVars, list: *[100]pos.Move, ctx: anytype) void {
    gv.reply_list_valid.* = 1;
    gv.predicted_reply[0] = 0;
    const side = gv.opponent_side.*;
    const n = ctx.genMoves(side, p.check_by_ply[0] != 0);
    gv.reply_total = n;
    gv.reply_count = n;
    if (n == 0) return;
    _ = ctx.replyCall(.prepare_eval, 0, 0);
    const sums = [3]u16{ p.piece_square_sum, gv.sum_white_pawns.*, gv.sum_black_pawns.* };
    gv.predicted_check = 0;
    gv.predicted_captured.* = 0;
    var best: i16 = -20000;
    const saved_iteration = gv.iteration.*;
    gv.horizon.* = 1;
    gv.iteration.* = 1;
    gv.queen_pin_depth.* = 2;
    gv.qs_limit2.* = 2;
    gv.qs_limit1.* = 2;
    var best_captured: u8 = 0;
    gv.flag_a40e.* = 0;
    const key = p.hash_key;
    const pawn_key = p.pawn_hash_key;
    _ = ctx.replyCall(.prescore_margins, 0, 0);
    var predicted_score: i16 = 0;
    // make_move's outputs, [bp-4] (captured piece) and [bp-15h] (its slot): locals of the
    // original that each make overwrites.
    var buf: [5]u8 = @splat(0);
    var i: u16 = 0;
    while (s16(i) < s16(gv.reply_total)) : (i += 1) {
        const e = &list[i];
        _ = ctx.replyCall(.square_sums, i, 0);
        _ = ctx.replyCall(.update_key, i, 0);
        buf[0] = e.from;
        buf[1] = e.to;
        buf[2] = e.flag;
        ctx.makeMove(&buf, side, 1);
        var legal = true;
        var score: u16 = 0;
        if (gv.computer_side.* != 0) {
            // A White reply, scored for Black.
            _ = ctx.replyCall(.leaf_attack_map_black, 0, 0);
            if (gv.leaf_map.*[p.piece_list[7]] != 0) {
                legal = false;
            } else if (p.total_material != 0) {
                const pawns = ctx.replyCall(.pawn_eval_btm, 0, 0);
                var si = ctx.replyCall(.static_eval, 1, 0);
                if (gv.passed_threat_bits.* & 2 != 0) si +%= 0xC8;
                score = si;
                if (gv.ba8de.* == 0) {
                    _ = ctx.replyCall(.static_eval, 0, 0);
                    if (gv.passed_threat_bits.* & 2 != 0) si -%= 0x578;
                    si -%= ctx.replyCall(.hanging_white, 0, 0);
                    si +%= ctx.replyCall(.pieces_and_kings, 1, 1) +% pawns;
                    si -%= ctx.replyCall(.activity_black, 0, 0);
                    si +%= sar(ctx.replyCall(.activity_white, 0, 0), 1);
                    if (gv.phase_endgame.* != 0) si +%= ctx.replyCall(.endgame_king_black, 0, 0);
                    si -%= flag_penalty[e.flag];
                    var c = ctx.replyCall(.count_attacked_btm, 0, 0);
                    si +%= sar(ctx.replyCall(.threats_black, 0x64, c) -% threat_count_bonus[c], 1);
                    c = ctx.replyCall(.count_attacked_wtm, 0, 0);
                    gv.flag_a40e.* = 1;
                    si +%= sar(ctx.replyCall(.threats_white, 0x64, c) -% threat_count_bonus[c], 2);
                    gv.flag_a40e.* = 0;
                    score = si;
                }
            }
        } else {
            // A Black reply, scored for White.
            _ = ctx.replyCall(.leaf_attack_map_white, 0, 0);
            if (gv.leaf_map.*[p.piece_list[16 + 7]] != 0) {
                legal = false;
            } else if (p.total_material != 0) {
                const pawns = ctx.replyCall(.pawn_eval_wtm, 0, 0);
                score = 0 -% ctx.replyCall(.static_eval, 0, 0);
                if (gv.passed_threat_bits.* & 2 != 0) score +%= 0xC8;
                if (gv.ba8de.* == 0) {
                    _ = ctx.replyCall(.static_eval, 1, 0);
                    if (gv.passed_threat_bits.* & 2 != 0) score -%= 0x578;
                    score -%= ctx.replyCall(.hanging_black, 0, 0);
                    score -%= ctx.replyCall(.pieces_and_kings, 0, 1) +% pawns;
                    score -%= ctx.replyCall(.activity_white, 0, 0);
                    score +%= sar(ctx.replyCall(.activity_black, 0, 0), 1);
                    if (gv.phase_endgame.* != 0) score -%= ctx.replyCall(.endgame_king_white, 0, 0);
                    score -%= flag_penalty[e.flag];
                    var c = ctx.replyCall(.count_attacked_wtm, 0, 0);
                    // 0FD0 (DEV-046): the original *adds* the threat-count bonus to
                    // eval_threats_white's result here (`add ax, [bx+si+3EA]`), where the
                    // White reply's mirror (0ED2) and both second terms (0EF7, 0FF6)
                    // subtract it: DEV-043's reversed sign in another routine.
                    // Corrected (`dev046_reply_sign`), it subtracts, as the mirror does.
                    const r = ctx.replyCall(.threats_white, 0x64, c);
                    const t = if (fixes.dev046_reply_sign) r -% threat_count_bonus[c] else r +% threat_count_bonus[c];
                    score -%= sar(t, 1);
                    c = ctx.replyCall(.count_attacked_btm, 0, 0);
                    gv.flag_a40e.* = 1;
                    score -%= sar(ctx.replyCall(.threats_black, 0x64, c) -% threat_count_bonus[c], 2);
                    gv.flag_a40e.* = 0;
                }
            }
        }
        if (!legal) {
            score = 0xAFEC; // -20500
            gv.reply_count -%= 1;
        } else {
            if (s16(score) > best) {
                best = s16(score);
                best_captured = buf[3];
            }
            const flag = s8(e.flag);
            if ((@as(u16, e.from) | @as(u16, e.to) << 8) == gv.search_reply.* and (flag <= 1 or flag >= 5)) {
                predicted_score = s16(score);
                gv.predicted_check = p.check_by_ply[1];
                gv.predicted_reply = .{ e.from, e.to, e.flag, buf[3] };
                gv.predicted_captured.* = buf[3];
            }
        }
        e.score = buf[3];
        ctx.unmakeMove(buf, side);
        // The sort key (-20500 for an illegal reply, or DEV-067's -32768: `rootListScore`).
        gv.reply_scores.*[i] = @bitCast(pos.rootListScore(fixes, legal, s16(score)));
        p.piece_square_sum = sums[0];
        gv.sum_white_pawns.* = sums[1];
        gv.sum_black_pawns.* = sums[2];
        p.hash_key = key;
        p.pawn_hash_key = pawn_key;
    }
    _ = ctx.replyCall(.search_margins, 0, 0);
    if (gv.reply_count != 0) {
        _ = ctx.replyCall(.sort_root_moves, gv.reply_total, 0);
        const replace = gv.predicted_reply[0] == 0 or
            (gv.bae36.* != 0 and predicted_score +% 0x96 <= s16(gv.reply_scores.*[0]));
        if (replace) {
            gv.predicted_reply = .{ list[0].from, list[0].to, list[0].flag, best_captured };
            gv.predicted_captured.* = best_captured;
            gv.changed_73fe.* = 1;
        }
    }
    gv.iteration.* = saved_iteration;
}

// ---------------------------------------------------------------------------
// play_entered_move (38C0:554E)
// ---------------------------------------------------------------------------

/// Port of play_entered_move (38C0:554E-5709). The side DG:717C plays the move
/// `gv.entered` (from, to, flag) on the search position (make_move at ply 1), and the
/// game record gets the move, the captured piece, the book and main keys of the new
/// position, its check byte, en-passant square and score, and the reversible byte.
/// Returns the moving piece's code (AX).
pub fn playEnteredMove(p: *Position, gv: *GameVars, rec: *GameRecord, ctx: anytype) u16 {
    gv.computer_side.* = 1 -% gv.opponent_side.*;
    const from = gv.entered[0];
    const to = gv.entered[1];
    const moving = p.board[from];
    const side = gv.opponent_side.*;
    rec.captured[slotOf(side, capture_stride, gv.move_number.*)] = p.board[to];
    const notation = ctx.notation(from, to, moving);
    ctx.makeMove(&gv.entered, side, 1);
    if (gv.pondering.* == 0) gv.last_played_ply.* = p.game_ply;
    updateCastleStamps(p);
    ctx.ported(0x55CB, 0); // 38C0:0130
    ctx.bookKey(gv.computer_side.*);
    rec.book_keys[p.game_ply] = gv.book_key;
    gv.irreversible.*[p.game_ply] = @truncate(p.reversible_by_ply[1]);
    ctx.hashFromScratch();
    rec.keys[p.game_ply] = p.hash_key;
    storePositionAfter(p, gv, rec, side, p.check_by_ply[1], p.ep_square_by_ply[1], gv.last_score.*, true);
    const at = slotOf(side, side_stride, gv.move_number.*);
    rec.gave_check[at] = @intFromBool(p.check_by_ply[1] != 0);
    @memcpy(rec.moves[at][0..5], &gv.entered);
    rec.moves[at][5] = moving | notation;
    return @bitCast(@as(i16, s8(moving)));
}

/// The record of the position after `mover`'s move (554E: 561F-567C; 01E0: 03CE-0493).
/// `entered` selects 554E's form: one score, the negated score for White's move; 01E0
/// also stores a second score two plies on.
fn storePositionAfter(p: *const Position, gv: *const GameVars, rec: *GameRecord, mover: u8, check: u8, ep: u8, score: u16, entered: bool) void {
    _ = p;
    const n = gv.move_number.*;
    const sc = s16(score);
    if (mover == 0) {
        // White moved: the position (Black, n).
        const at = side_stride + n;
        rec.pos_check[at] = check;
        rec.pos_ep[at] = ep;
        if (entered) {
            rec.pos_score[at] = 0 -% score;
        } else {
            rec.pos_score[at] = score;
            const v: u16 = if (sc > 0x4CF4) score +% 2 else if (sc < -0x4CF4) score -% 2 else score;
            rec.pos_score[n + 1] = v;
        }
    } else {
        // Black moved: the position (White, n + 1).
        const at = n + 1;
        rec.pos_check[at] = check;
        rec.pos_ep[at] = ep;
        if (entered) {
            rec.pos_score[at] = score;
        } else {
            rec.pos_score[at] = 0 -% score;
            const v: u16 = if (sc > 0x4CF4) @as(u16, 0xFFFE) -% score else if (sc < -0x4CF4) 2 -% score else 0 -% score;
            rec.pos_score[side_stride + n + 1] = v;
        }
    }
}

// ---------------------------------------------------------------------------
// check_entered_move (38C0:5864)
// ---------------------------------------------------------------------------

/// Port of check_entered_move (38C0:5864-5A8D), the original's legality test for an
/// entered move (AGENTS.md §9.3, §10.4). Returns 1 if the move `gv.entered[0..2]` is
/// legal for the side DG:717C, else 0. Sets the flag byte `gv.entered[2]` from the
/// board: 1 en passant (a pawn to the en-passant square), 5 promotion (the caller asks
/// for the piece and may change it to 2, 3 or 4), 6 castling (a king moving two files),
/// else 0. Refuses every move after the game has ended (status 4 or >= 7 at or after
/// DG:A6AE) and from move 201 on (the record's room). With a valid reply list
/// (DG:A3FA, made by set_predicted_reply after the program's move) the move must be in
/// it; otherwise the legal moves are generated and the move is made, tested for the
/// mover's king attacked, and unmade. `list` is the ply-0 move list DG:3A34
/// (`searchnode.State.move_list[0]`).
pub fn checkEnteredMove(p: *Position, gv: *GameVars, rec: *const GameRecord, list: *const [100]pos.Move, ctx: anytype) u16 {
    if (gv.game_over_ply.* != 0 and s16(gv.game_over_ply.*) <= s16(p.game_ply) and (gv.status.* == 4 or s8(gv.status.*) >= 7)) {
        if (gv.quiet == 0) ctx.ui(0x5891);
        return 0;
    }
    if (s16(gv.move_number.*) >= 0xC9 and (gv.opponent_side.* == 1 or s16(gv.move_number.*) >= 0xCA)) {
        if (gv.quiet == 0) ctx.ui(0x58BA);
        return 0;
    }
    gv.entered[2] = 0;
    const from = gv.entered[0];
    const to = gv.entered[1];
    // While pondering the search board holds the predicted move: read the game board.
    const piece = if (gv.pondering.* != 0) ctx.gameBoard(from) else p.board[from];
    if ((piece == pos.white_pawn or piece == pos.black_pawn) and to == p.ep_square_by_ply[0]) gv.entered[2] = 1;
    const d: i16 = @as(i16, s8(to)) - s8(from);
    if (gv.opponent_side.* == 0) {
        if (piece == pos.white_pawn and s8(to) > 0x5A) {
            gv.entered[2] = 5;
        } else if (piece == pos.white_king and (d == 2 or d == -2)) gv.entered[2] = 6;
    } else {
        if (piece == pos.black_pawn and s8(to) < 0x1D) {
            gv.entered[2] = 5;
        } else if (piece == pos.black_king and (d == 2 or d == -2)) gv.entered[2] = 6;
    }
    var n: i16 = undefined;
    if (gv.reply_list_valid.* != 0) {
        n = s16(gv.reply_count);
    } else {
        const at = slotOf(gv.opponent_side.*, side_stride, gv.move_number.*);
        p.ep_square_by_ply[0] = rec.pos_ep[at];
        p.check_by_ply[0] = rec.pos_check[at];
        n = s16(ctx.genMoves(gv.opponent_side.*, p.check_by_ply[0] != 0));
    }
    var found = false;
    var k: i16 = 0;
    while (k < n and !found) : (k += 1) {
        const e = list[@intCast(k)];
        found = e.from == from and e.to == to;
        if (found and gv.reply_list_valid.* != 0) gv.entered[3] = e.score;
    }
    if (found and gv.reply_list_valid.* == 0) {
        ctx.makeMove(&gv.entered, gv.opponent_side.*, 1);
        found = ctx.kingAttacked(gv.opponent_side.*) == 0;
        ctx.unmakeMove(gv.entered, gv.opponent_side.*);
    }
    if (found) {
        gv.game_over_ply.* = 0;
        return 1;
    }
    if (gv.quiet == 0) {
        gv.message = 2;
        ctx.ui(0x5A5A);
        ctx.ui(0x5A66);
        ctx.ui(0x5A71);
        if (gv.sound != 0) ctx.ui(0x5A80);
    }
    return 0;
}

// ---------------------------------------------------------------------------
// take_back_ply (38C0:570A)
// ---------------------------------------------------------------------------

/// Port of take_back_ply (38C0:570A-5863): undo the last ply on the search position
/// with unmake_move, from the move kept in the game record, and restore the side to
/// move, the move number, the score, the en-passant square and check byte of ply 0,
/// the castling stamps set at this ply and the book exit ply. A game that had ended
/// (DG:A6AE) is first rewound to the side and move number of its last position.
pub fn takeBackPly(p: *Position, gv: *GameVars, rec: *const GameRecord, ctx: anytype) void {
    if (gv.game_over_ply.* != 0 and s16(gv.game_over_ply.*) <= s16(p.game_ply)) {
        const v = s16(gv.game_over_ply.*);
        gv.opponent_side.* = @truncate(gv.game_over_ply.* & 1);
        gv.move_number.* = @bitCast(@divTrunc(v, 2) +% 1);
    }
    if (gv.opponent_side.* != 0) {
        p.ep_square_by_ply[0] = rec.pos_ep[gv.move_number.*];
        p.check_by_ply[0] = rec.pos_check[gv.move_number.*];
    }
    gv.computer_side.* = gv.opponent_side.*;
    gv.opponent_side.* = 0 -% (gv.opponent_side.* -% 1);
    var at: usize = undefined;
    if (gv.opponent_side.* == 0) {
        at = slotOf(0, side_stride, gv.move_number.*);
        gv.last_score.* = 0 -% rec.pos_score[at];
    } else {
        gv.move_number.* -%= 1;
        at = slotOf(gv.opponent_side.*, side_stride, gv.move_number.*);
        gv.last_score.* = rec.pos_score[at];
        p.ep_square_by_ply[0] = rec.pos_ep[side_stride + gv.move_number.*];
        p.check_by_ply[0] = rec.pos_check[side_stride + gv.move_number.*];
    }
    const ply = p.game_ply;
    if (p.oo_lost_at[0] == ply) p.oo_lost_at[0] = 0;
    if (p.ooo_lost_at[0] == ply) p.ooo_lost_at[0] = 0;
    if (p.oo_lost_at[1] == ply) p.oo_lost_at[1] = 0;
    if (p.ooo_lost_at[1] == ply) p.ooo_lost_at[1] = 0;
    if (s16(ply -% 1) <= s16(gv.book_exit_ply.*)) gv.book_exit_ply.* = 0;
    ctx.unmakeMove(rec.moves[at][0..5].*, gv.opponent_side.*);
    p.ep_square_by_ply[36] = gv.opponent_side.*; // DG:9EEC, the clock's side
    gv.reply_list_valid.* = 0;
}

// ---------------------------------------------------------------------------
// New game: the game variables (0000:93C0-94E3)
// ---------------------------------------------------------------------------

/// Port of new_game_position (0000:93C0-94E3), the game variables and the game
/// record's first position. Call after `setup.newGame`, which writes the search
/// position (both are one routine in the original; the Position writes of 93C8..94CA are
/// that function's). Also sets DG:9EEC (`ep_square_by_ply[36]`), which `newGame` leaves.
/// `random_segment` is the value the original stores in DG:A512 (the segment of its
/// hash random table).
pub fn newGameVars(p: *Position, gv: *GameVars, rec: *GameRecord, random_segment: u16) void {
    // 919C..91B5: the screen board, and the reversible bytes of every game ply. (The
    // other clears of 91B7..9250 are the leaf map DG:8FE4 and eight 200-byte tables of
    // the evaluation, DG:75CA, 76A2, AC2A, ACF4, 9182, 924A, 8DEA, 8EB8: see the
    // specification; their owners are other units.)
    @memset(&gv.board_copy, 7);
    @memset(&gv.irreversible.*, 0);
    gv.ba2ed.* = 0;
    gv.ba2a7.* = 0;
    gv.computer_side.* = 1;
    gv.learn_flags.* = 0;
    gv.book_learn_flags.* = 0;
    gv.w9eb6.* = 0;
    gv.bae44.* = 0;
    gv.opponent_side.* = 0;
    p.ep_square_by_ply[36] = 0; // DG:9EEC
    gv.pv_length.* = 0;
    rec.pos_check[0] = 0;
    rec.pos_ep[0] = 0;
    gv.analysis.* = 0;
    gv.status.* = 0;
    gv.ba4f2.* = 0;
    gv.b3675.* = 0;
    gv.bac29 = 0;
    gv.ba4f3.* = 0;
    gv.bb42a.* = 0;
    gv.b70e4.* = 0;
    gv.last_score.* = 0;
    rec.pos_score[0] = 0;
    gv.w153c.* = 0;
    gv.game_over_ply.* = 0;
    gv.reply_list_valid.* = 0;
    gv.book_exit_ply.* = 0;
    gv.wa4c4 = 0;
    gv.repetitions.* = 0;
    gv.last_played_ply.* = 0;
    gv.last_irreversible_ply.* = 0;
    gv.move_number.* = 0;
    gv.wa510 = 0;
    gv.wa512 = random_segment;
    rec.keys[0] = p.hash_key;
    gv.stop.* = 0;
}

// ---------------------------------------------------------------------------
// play_best_move (38C0:01E0)
// ---------------------------------------------------------------------------

/// Port of play_best_move (38C0:01E0-0D21). `arg` is the original's argument: 0 after
/// a search, 1 for a book move or a move played without a search; the routine adds 2
/// when the move is taken from the game record (a game being replayed). `best` is the
/// move the search chose (the three bytes at DG:[73F8]), read when `arg` is 0.
///
/// The program's move is made on the search position (make_move at ply 0) and the game
/// record written as for an entered move; then, unless the move came from the record,
/// the game status (DG:7328: check, mate scores, no legal move, third repetition, bare
/// kings), the scores, set_predicted_reply (not in analysis or auto-play), the score
/// history kept for learning, the resignation test, and the book's exit test.
pub fn playBestMove(p: *Position, gv: *GameVars, rec: *GameRecord, arg_in: u16, best: [3]u8, ctx: anytype) void {
    var arg = arg_in;
    var learn: u16 = 0; // [bp-8]
    var half_gain: i16 = 0; // [bp-0Ch]
    if (gv.stop.* == 3) return finish93e(p, gv, arg, learn, half_gain, ctx);
    @memcpy(gv.board_copy[21..][0..0x4E], p.board[21..][0..0x4E]);
    gv.computer_piece_material = p.piece_material[@intCast(gv.computer_side.* & 1)];
    const ply = s16(p.game_ply);
    if (ply < s16(gv.last_played_ply.*)) {
        if (s16(gv.replay_end_ply) > ply or s16(gv.mode_a00a.*) > ply or gv.stop.* == 5 or (gv.stop.* == 2 and gv.mode_1bac.* != 0)) {
            const at = slotOf(gv.computer_side.*, side_stride, gv.move_number.*);
            @memcpy(gv.played.*[0..3], rec.moves[at][0..3]);
            arg +%= 2;
        }
    }
    if (arg == 0) {
        const sc = s16(gv.last_score.*);
        if (sc > 0x4CF4) gv.status.* = if (sc >= 0x4E1E) 4 else 3;
        if (s8(gv.status.*) >= 8) {
            gv.game_over_ply.* = p.game_ply;
            p.ep_square_by_ply[36] = 1 -% gv.opponent_side.*; // DG:9EEC
            return finish955(p, gv, arg, learn, half_gain, ctx);
        }
        @memcpy(gv.played.*[0..3], &best);
    }
    const from = gv.played.*[0];
    const to = gv.played.*[1];
    const moving = p.board[from];
    gv.computer_side.* = 1 -% gv.opponent_side.*;
    const mover = gv.computer_side.*;
    rec.captured[slotOf(mover, capture_stride, gv.move_number.*)] = p.board[to];
    const notation = ctx.notation(from, to, moving);
    ctx.squareSums(gv.played.*[0..3].*);
    ctx.makeMove(&gv.played.*, mover, 0);
    updateCastleStamps(p);
    ctx.ported(0x033C, 0); // 38C0:0130
    p.ep_square_by_ply[1] = p.ep_square_by_ply[0];
    ctx.bookKey(gv.opponent_side.*);
    rec.book_keys[p.game_ply] = gv.book_key;
    gv.irreversible.*[p.game_ply] = @truncate(p.reversible_by_ply[0]);
    ctx.hashFromScratch();
    rec.keys[p.game_ply] = p.hash_key;
    const reps = repetitionCount(p, gv, rec);
    ctx.ported(0x0396, reps); // 2B9F:402A
    gv.repetitions.* = @truncate(reps +% 1);
    if (s16(arg) < 2) {
        gv.last_played_ply.* = p.game_ply;
        if (p.check_by_ply[0] == 0 and ctx.legalMoveExists(gv.opponent_side.*) == 0) gv.status.* = 7;
        storePositionAfter(p, gv, rec, mover, p.check_by_ply[0], p.ep_square_by_ply[0], gv.last_score.*, false);
        if (gv.mode_a28a == 0 and gv.analysis.* == 0 and gv.status.* != 4) ctx.predictReply(arg);
        const at = slotOf(gv.computer_side.*, side_stride, gv.move_number.*);
        @memcpy(rec.moves[at][0..5], &gv.played.*);
        rec.moves[at][5] = notation | moving;
        if (p.check_by_ply[0] != 0 and gv.status.* != 4) gv.status.* = if (gv.status.* == 3) 2 else 1;
        rec.gave_check[at] = @intFromBool(p.check_by_ply[0] != 0);
        if (s8(gv.repetitions.*) >= 3) {
            gv.status.* = 5;
        } else if (p.pawn_count == 0 and s16(gv.last_score.*) >= -1 and s16(gv.last_score.*) <= 1 and
            (s16(p.material[0]) < 0x44C or p.material[0] == 0x514) and
            (s16(p.material[1]) < 0x44C or p.material[1] == 0x514))
        {
            gv.status.* = 6;
            gv.reply_list_valid.* = 0;
        }
    }
    // 0564: the move on the screen, then the post-move work.
    ctx.ui(0x0577);
    ctx.ui(0x057D);
    if (gv.mode_a00a.* != 0) {
        ctx.ui(0x05A2);
    } else {
        if (gv.w24f6.* != 0) {
            if (gv.ba38b.* & 0x10 != 0 and arg == 0 and s8(gv.depth_reached.*) >= s8(gv.horizon.*) and s8(gv.horizon.*) > s16(gv.w24f0.*)) {
                ctx.ui(0x0648);
            } else {
                ctx.ui(0x063B);
                ctx.ui(0x0648);
            }
        }
        if (gv.mode_24f2 == 1) {
            if (s8(gv.stop.*) >= 2 and s8(gv.level.*) < 6) ctx.ui(0x0665) else ctx.ui(0x0671);
        }
        if (s16(gv.replay_end_ply) >= s16(p.game_ply)) ctx.ui(0x0682);
    }
    if (gv.w1b88 != 0 and gv.mode_a00a.* == 0) ctx.ui(0x06A6);
    if (gv.stop.* == 5 or (gv.stop.* == 2 and gv.mode_1bac.* != 0)) return finish93e(p, gv, arg, learn, half_gain, ctx);
    const n = gv.move_number.*;
    const bx: i16 = if (gv.opponent_side.* != 0) s16(rec.pos_score[n -% 1 +% side_stride]) else s16(0 -% rec.pos_score[n]);
    const sc = s16(gv.last_score.*);
    if (gv.w19d4 != 0 and sc -% bx >= s16(gv.w19d2 << 1)) half_gain = @divTrunc(sc -% bx +% 1, 2);
    if (bx -% sc > 0x3A) {
        if (sc < 0xFC or @divTrunc(sc, 5) +% sc < bx) learn = 1;
    }
    if (learn == 0 or gv.learn_flags.* & 0x10 == 0) return finish93e(p, gv, arg, learn, half_gain, ctx);
    @panic("play_best_move: learning (38C0:0749) is switched off in this project");
}

fn finish93e(p: *Position, gv: *GameVars, arg: u16, learn: u16, half_gain: i16, ctx: anytype) void {
    p.ep_square_by_ply[36] = gv.opponent_side.*; // DG:9EEC
    if (arg == 1) {
        gv.predicted.* = 0;
        gv.pv_length.* = 0;
    }
    finish955(p, gv, arg, learn, half_gain, ctx);
}

fn finish955(p: *Position, gv: *GameVars, arg: u16, learn: u16, half_gain: i16, ctx: anytype) void {
    if (arg == 0 and gv.analysis.* == 0) ctx.ui(0x0964);
    if (s8(gv.status.*) >= 8 or gv.stop.* == 3) return;
    if (arg == 0 and s8(gv.level.*) <= 2) {
        const s: usize = gv.computer_side.* & 1;
        if (gv.first_ply[s] == 0) {
            gv.first_ply[s] = p.game_ply;
            gv.first_score[s] = gv.last_score.*;
        } else if (learn == 1) {
            gv.drops[s] +%= 1;
        } else if (learn > 1) @panic("play_best_move: learning (38C0:09C6) is switched off in this project");
        if (gv.book_learn_flags.* & 0x10 != 0) @panic("play_best_move: book learning (38C0:09F7) is switched off in this project");
        const sc = s16(gv.last_score.*);
        if (sc > -19700 and sc <= -2000 and gv.analysis.* == 0 and gv.kbn.* == 0 and gv.resigned_ply.* == 0 and gv.mode_24f2 == 0) {
            var ok = true;
            if (gv.level.* != 0 or gv.preset.* != 0) {
                const t: i32 = @bitCast(gv.time_left.*[@intCast(gv.opponent_side.* & 1)]);
                if (t < 0x444) ok = false;
            }
            if (ok) {
                if (s8(gv.sound) >= 1) {
                    ctx.ui(0x0C09);
                    ctx.ui(0x0C16);
                }
                gv.resigned_ply.* = p.game_ply;
                ctx.ui(0x0C24);
                if (gv.w1b88 == 0) gv.message_2504 = 2;
            }
        }
    }
    p.ep_square_by_ply[1] = p.ep_square_by_ply[0];
    if (gv.mode_1bac.* == 0) {
        if (gv.book_exit_ply.* == 0 and gv.mode_a00a.* == 0) ctx.bookProbe(2, gv.opponent_side.*);
        if (gv.book_exit_ply.* == 0 and s8(gv.menu_depth.*) < 2) {
            if (gv.opponent_side.* == 0) gv.move_number.* +%= 1;
            ctx.ui(0x0C7B);
            if (gv.opponent_side.* == 0) gv.move_number.* -%= 1;
        }
    }
    if (gv.stop.* != 2 and (gv.mode_1bac.* != 0 or (gv.analysis.* != 0 and arg == 0))) ctx.ui(0x0CA4);
    ctx.resetMoveTime();
    if (gv.message_2504 != 0) {
        ctx.ui(0x0CB9);
        gv.message_2504 = 0;
        return;
    }
    if (half_gain != 0 and gv.analysis.* == 0 and gv.mode_24f2 == 0 and std.mem.readInt(u16, &gv.w9e96.*, .little) != 0 and
        s16(((gv.move_number.* -% 1) << 1) -% @as(u16, @bitCast(@as(i16, s8(gv.computer_side.*))))) == s16(gv.wa4c2))
    {
        if (gv.w9e96.*[1] & 0x7F != s8(gv.entered[1]) or gv.w9e96.*[0] & 0x7F != s8(gv.entered[0])) ctx.ui(0x0D18);
    }
}
