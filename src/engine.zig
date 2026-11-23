//! The joined engine behind the UCI shell (src/uci_engine.zig `Engine`): the original's own
//! search (src/engine_root.zig) on the engine's persistent structs (the node domain's
//! members, the node's `State` and the game record; since Stage B step 8, stage 6, every
//! command runs on them, each variable at its home, `EngineRoot.Home`; since stage 8 the engine
//! holds no image of the original's data segment), at the Fixed depth level, played as
//! **normal play** (the
//! original playing one side against moves entered at its command loop, pondering off),
//! as one copy of the original left running for the
//! whole game (AGENTS.md Â§10.5). The operator script, the mapping from UCI commands to the
//! original's operations, is docs/UCI.md, "The operator script"; in short:
//!
//! - Start: the original's start-up as far as it writes engine state, to its command loop
//!   (`EngineRoot.startUp`: the repeatable state of AGENTS.md section 5, book ignored, learning
//!   off, Fixed depth), computed once and kept as the start-up checkpoint (`loop_cp`: the
//!   members, the node's `State` and the game record as values, `EngineRoot.saveState`), which
//!   every rebuild restores (`EngineRoot.restoreState`).
//! - The engine holds a game: its start (`startpos`, or a FEN entered through Setup mode,
//!   src/adapt_setup.zig `enterFen`), the moves played in it, and where the original
//!   stands (`Phase`).
//! - A `position` that continues the held game by the opponent's one move, the program's
//!   own last move having been played by its search's conclusion: the move is entered as
//!   in normal play (`EngineRoot.enterMove`: check_entered_move, play_entered_move, the command
//!   loop's exit, main to 0526). The hash tables, killers and everything else the
//!   original carries stay as the original has them.
//! - Any other `position` (a new game, a different line, a take-back, a second `go` on
//!   the same position, `ucinewgame`) rebuilds the game (`rebuild`).
//! - `go`: the program searches the side to move (Fixed depth N, main from 0526), then
//!   plays its move at once as the original does (main's conclusion and play_best_move
//!   with set_predicted_reply, `EngineRoot.playMove`) and goes on to its command loop
//!   (`EngineRoot.toOpponentMove`: the ponder test, pondering off).
//!
//! `stop`: every 1024th node entry of the iteration loop reads `Signals.stop` and, once,
//! writes the original's stop flag [A4FA] = 1 (engine_root `StopCtx`); the search then ends
//! through the original's own code and plays its best move so far.
//!
//! Time management (docs/UCI_TIME.md, owner decision 20): every `go` but `go depth N`
//! searches at Fixed depth 30, and Juggernaut's time control (src/timecontrol.zig, `tc`,
//! fed by the observer in src/uci_report.zig) decides when to stop: inside an iteration
//! by the stop flag, as `stop` does (at the 1024-node test; `go nodes N` at every node);
//! after an iteration by lowering the loop's limit DG:64 to that depth + 1, which ends
//! the search exactly as the Fixed depth search of that depth ends.

const std = @import("std");
const builtin = @import("builtin");
const pos = @import("position.zig");
const fen = @import("fen.zig");
const uci_engine = @import("uci_engine.zig");
const engine_root = @import("engine_root.zig");
const mg = @import("movegen.zig");
const gamemove = @import("gamemove.zig");
const adapt_setup = @import("adapt_setup.zig");
const newgame = @import("newgame.zig");
const uci_report = @import("uci_report.zig");
const engine_data = @import("engine_data.zig");
const tb_store = @import("tb_store.zig");
const timecontrol = @import("timecontrol.zig");
const legality = @import("legality.zig");

pub const R = engine_root.EngineRoot(pos.Fixes.corrected);
const dgroup = @import("dgroup.zig");

/// Slots per main hash table: the original's 30,720 KB tables (mask 3FFFFFh, 3/4 mode), its
/// largest; a smaller `Hash` uses the first slots its mask and mode reach (`setHash`).
pub const table_slots = 3_145_728;
/// The depth of start-up's repeatable state, and of a `go` with no depth that no other
/// rule covers: the shipped settings file's Fixed depth (SETTINGS.M80: 4).
pub const default_depth: u16 = (newgame.Settings{}).fixed_depth;
/// The deepest iteration `go depth` and `go infinite` ask for (the PV holds 37 plies, and
/// the iteration's ply limits run to depth + 6).
pub const max_depth = 30;
// A `position` may list any number of moves. The original ends a game at move number
// 202 (38C0:1974; docs/arch/34-game-move-path.md, "How long a game can be"); the engine
// plays on (owner decision 26, DEV-F19): from game ply 300 the root's turn routines slide
// the game record (`EngineRoot.slideIfDue`, src/gameslide.zig), so that a long game, whether
// rebuilt move by move or continued, never reaches the original's end. The moves asked for
// and the held game's moves are kept whole (`moves`, `held`, grown as needed outside the
// search), since a new `position` is compared with the held game move for move.

/// Where the held game stands.
pub const Phase = enum {
    /// Nothing usable: the next `position` or `go` rebuilds.
    none,
    /// At the command loop after the program's own move, waiting for the opponent's.
    waiting,
    /// At main 0000:0526: the program is to search the held position.
    ready,
};

/// The engine `mchess` runs (src/uci.zig `runJoined`): every class C correction on
/// (pos.Fixes.corrected; owner decisions 25 and 27). Built with `-Dfixes=false` it is the
/// original's logic (pos.Fixes.original), as `mchess-original`, for matches between the
/// two; there is no UCI option for it (owner decision 25). The class B guards (the book's legality test,
/// DEV-049; the legality test of the move played and of the PV) and the corrections of
/// uninitialised reads are the same in both instantiations.
pub const Engine = EngineOf(if (@import("build_options").fixes) pos.Fixes.corrected else pos.Fixes.original);
/// The engine with every class C correction off: the original the golden files record,
/// and the engine the tests prove against them (AGENTS.md section 9.2).
pub const OriginalEngine = EngineOf(pos.Fixes.original);

/// The engine with the class C switches `fixes` (pos.Fixes): every one off is the original
/// the golden files record, every one on the released engine.
pub fn EngineOf(comptime fixes: pos.Fixes) type {
    return struct {
        const Self = @This();
        pub const EngineRoot = engine_root.EngineRoot(fixes);
        pub const Report = uci_report.Reporter(EngineRoot);

        gpa: std.mem.Allocator,
        root: *EngineRoot,
        /// The tablebase files the root's `TB` folder holds (`initSet`).
        tb_store: *tb_store.TbStore,
        /// The engine's state in the command loop after start-up, before Ctrl-A: where
        /// every game starts. The start-up checkpoint (Stage B step 8, stage 7: the members,
        /// the node's `State` and the record as values, `EngineRoot.Checkpoint`): taken once by
        /// `EngineRoot.saveState`, restored by every rebuild (`EngineRoot.restoreState`); the options
        /// write their variables in it by address (`EngineRoot.checkpointHome`).
        loop_cp: *EngineRoot.Checkpoint,
        io: ?std.Io = null,
        options: uci_engine.Options = .{},
        /// The `Hash` size, MB, whose dialog entry the images hold (`setHash`); start-up's
        /// tables are what 60 MB gives.
        hash_mb: u32 = 60,
        /// Whether `info` lines are printed (the tests run searches with it off and on).
        reporting: bool = true,
        /// The position asked for: its route, start and moves (`moves[0..move_count]`;
        /// the buffer grows as needed, `ensureRoom`).
        moves: []fen.UciMove = &.{},
        move_count: usize = 0,
        route: uci_engine.Route = .new_game,
        start: fen.Description,
        /// The game the root holds, every move from its start (`held[0..held_count]`).
        held: []fen.UciMove = &.{},
        held_count: usize = 0,
        held_route: uci_engine.Route = .new_game,
        held_start: fen.Description,
        phase: Phase = .none,
        /// How positions were reached: continued from the held game, or rebuilt.
        continued: u32 = 0,
        rebuilt: u32 = 0,
        reason_buf: [160]u8 = undefined,
        /// UCI time management (docs/UCI_TIME.md; owner decision 20): Juggernaut's time
        /// control, one for the engine's lifetime (its iteration history carries over from
        /// search to search, as in Juggernaut). Its margins are centipawns, and a pawn is
        /// 200 of the scores it is handed (the piece values at DG:1498): score unit 2.
        tc: timecontrol.TimeControl = .{ .score_unit = 2 },
        /// The tests' scripted clock (Âµs per node entry); null: the monotonic clock.
        scripted_us_per_node: ?u64 = null,
        /// The last search's PV after the program's move, its 2nd and 3rd moves (the
        /// reply it predicted and its answer), for the expected move of the next search.
        predicted: ?[2]u16 = null,
        /// The held position was reached by continuing the game with the opponent's move.
        by_continuation: bool = false,
        /// What the last search handed the time control and how it ended (the tests).
        time_log: Report.TimeLog = .{},
        /// The expected move and previous target square the last search was given.
        last_expected: ?timecontrol.Expected = null,
        last_previous_to: ?u8 = null,
        /// The last search was infinite with `Use Tablebases` on: bit 3 of DG:239C was
        /// cleared for it (owner decision 22).
        last_tb_off: bool = false,
        /// The PV's full legality test (AGENTS.md section 9.3 item 4; uci_report.PvCheck).
        pv_check: *uci_report.PvCheck,
        /// Lines of the last search whose PV it cut, and the first such PV (the tests).
        pv_cuts: u32 = 0,
        first_cut: @FieldType(Report, "first_cut") = null,
        /// The raw score (the evaluation's units, a pawn 200) of the last search's last
        /// `info` line with a score, if any: what the tests compare (the line shows it
        /// halved, uci_report `scoreText`).
        last_score: ?i16 = null,
        /// A game has been built (`resetToLoop`) and no `go` has run in it since: an
        /// option set now counts as set at the game's start (`applyOptions`, the seed).
        game_fresh: bool = false,
        /// Test builds only: called at the points of a `go` where one part of the original
        /// hands the state to the next (before the search, after it, after the program's
        /// move), for the test of the members' copies (src/engine_stageb_test.zig).
        probe: if (builtin.is_test) ?Probe else void = if (builtin.is_test) null else {},

        pub const Probe = struct { ctx: *anyopaque, call: *const fn (*anyopaque, []const u8) void };

        fn point(e: *Self, label: []const u8) void {
            if (builtin.is_test) if (e.probe) |p| p.call(p.ctx, label);
        }

        /// The engine with the shipped tablebase set (the six installed files): what every
        /// golden test of the original as installed runs.
        pub fn init(gpa: std.mem.Allocator) !Self {
            return initSet(gpa, .shipped);
        }

        /// The engine with the given tablebase set (src/tb_store.zig; owner decision 33):
        /// the program's `TB` folder holds those files, and start-up's scan leaves their
        /// signatures (6 or 62).
        pub fn initSet(gpa: std.mem.Allocator, set: tb_store.TbSet) !Self {
            const store = try gpa.create(tb_store.TbStore);
            errdefer gpa.destroy(store);
            store.* = .init(gpa, set);
            errdefer store.deinit();
            const loop_cp = try gpa.create(EngineRoot.Checkpoint);
            errdefer gpa.destroy(loop_cp);
            const pv_check = try gpa.create(uci_report.PvCheck);
            errdefer gpa.destroy(pv_check);
            pv_check.* = .{};
            const root = try EngineRoot.init(gpa, table_slots);
            errdefer root.deinit();
            // The TB folder, embedded (src/engine_data.zig, src/tb_store.zig): the root
            // probes it as the original does with its default tablebase setting, DG:239C =
            // 0Ah (docs/arch/41-tablebases.md).
            root.tb_files = store.files();
            root.startUp(.{ .tb_signatures = switch (set) {
                .shipped => &newgame.shipped_tb_signatures,
                .cd => &newgame.cd_tb_signatures,
            } }, .{}, .{}, default_depth);
            root.saveState(loop_cp);
            const sp = fen.parse(fen.startpos) catch unreachable;
            return .{ .gpa = gpa, .root = root, .tb_store = store, .pv_check = pv_check, .loop_cp = loop_cp, .start = sp, .held_start = sp };
        }

        pub fn deinit(e: *Self) void {
            e.tb_store.deinit();
            e.gpa.destroy(e.tb_store);
            e.root.deinit();
            e.gpa.destroy(e.pv_check);
            e.gpa.destroy(e.loop_cp);
            e.gpa.free(e.moves);
            e.gpa.free(e.held);
        }

        /// Room for `n` moves in `buf` (one of `moves`, `held`), keeping what it holds.
        fn ensureRoom(e: *Self, buf: *[]fen.UciMove, n: usize) bool {
            if (buf.len >= n) return true;
            buf.* = e.gpa.realloc(buf.*, @max(n, 2 * buf.len, 512)) catch return false;
            return true;
        }

        /// Appends the move just played to the held game.
        fn holdMove(e: *Self, m: fen.UciMove) bool {
            if (!e.ensureRoom(&e.held, e.held_count + 1)) return false;
            e.held[e.held_count] = m;
            e.held_count += 1;
            return true;
        }

        pub fn engine(e: *Self) uci_engine.Engine {
            return .{ .ctx = e, .vtable = &vtable };
        }

        const vtable: uci_engine.Engine.VTable = .{
            .applyOptions = applyOptions,
            .newGame = newGame,
            .setPosition = setPosition,
            .search = search,
        };

        fn self(ctx: *anyopaque) *Self {
            return @ptrCast(@alignCast(ctx));
        }

        fn applyOptions(ctx: *anyopaque, options: *const uci_engine.Options) void {
            const e = self(ctx);
            e.options = options.*;
            e.setBook(options.own_book);
            e.setBookKind(options.book);
            e.setTablebases(options.use_tablebases);
            // Owner decision 44: `Use Tablebases` false frees the unpacked files, true again
            // unpacks them all before this returns (src/tb_store.zig `setUse`). This runs on
            // the shell's worker, the thread that searches, between searches.
            e.tb_store.setUse(options.use_tablebases, e.io);
            if (options.hash_mb != e.hash_mb) e.setHash(options.hash_mb);
            // The book's generator is seeded at the start of every game (DEV-F13): a
            // `Seed`, `OwnBook` or `Book` set before the game's first search counts as set
            // at its start, so the seed is written again as the rebuild wrote it. Nothing
            // reads or writes DG:2DC8 between a rebuild and the first search (the rebuild's
            // replay probes the book only in modes 2 and 3, which make no draw).
            if (e.game_fresh) dgroup.memSetDword(e.root.home(), 0x2DC8, e.startSeed());
        }

        /// `Hash` (owner decision 24; docs/UCI.md, "Hash"): `mb` x 1,024 KB typed into the
        /// original's Settings / Hash-tables dialog (38C0:4C36-4CE6, engine_root
        /// `hashMenuAt`), at once, as the dialog acts: in the start-up checkpoint every game
        /// starts from, and in the game held, whose main tables the dialog clears. The total
        /// [12CA] is then what main's resize before each search (0000:079F) asks for; the
        /// original halves it and takes the ladder's size at or below the half, with its mask
        /// and 3/4 mode (docs/arch/35-hash-sizing.md section 3). The tables stay allocated
        /// at the largest size (`table_slots`), as the original's XMS blocks are never
        /// reallocated: the mask keeps the index within the size in use. Start-up's total,
        /// 2 x 30,720 KB, is what 60 MB gives, so the default types nothing.
        pub fn setHash(e: *Self, mb: u32) void {
            const kb: i32 = @intCast(@as(u32, std.math.clamp(mb, 1, 60)) * 1024);
            _ = engine_root.hashMenuAt(e.root.checkpointHome(e.loop_cp), kb);
            _ = e.root.hashMenu(kb);
            e.hash_mb = mb;
        }

        /// `Book`: the Book menu's radio group (docs/arch/40-opening-book.md section 6):
        /// DG:A6A0 bit 5 (20h) for Tournament, bit 2 (4) for Variety, both clear for
        /// Standard, with the low byte copied to DG:9EB6 as the menu does, in the start-up
        /// checkpoint and in the game held. Nothing but book_probe reads these two bits
        /// (rootprep and root_search read bits 0 and 1 of A6A0 and bit 0 of 9EB6, display).
        /// Since Stage B step 8, stage 6, in the game held at each byte's home
        /// (`EngineRoot.Home`: 9EB6 is `LeafVars`', A6A0 `RootVars`' since stage 7) and in the
        /// start-up checkpoint by address.
        pub fn setBookKind(e: *Self, kind: uci_engine.BookKind) void {
            bookKindAt(e.root.checkpointHome(e.loop_cp), kind);
            bookKindAt(e.root.home(), kind);
        }

        fn bookKindAt(m: anytype, kind: uci_engine.BookKind) void {
            var v = dgroup.memWord(m, 0xA6A0) & ~@as(u16, 0x24);
            v |= switch (kind) {
                .tournament => 0x20,
                .standard => 0,
                .variety => 0x04,
            };
            dgroup.memSetWord(m, 0xA6A0, v);
            m.set(0x9EB6, @truncate(v));
        }

        /// The tablebase settings word DG:239C (docs/arch/41-tablebases.md section 5).
        pub const tb_use_bit: u16 = 0x08;

        /// `Use Tablebases`: the Tablebases dialog's "Use tablebases" check box, bit 3 of
        /// DG:239C (as shipped 0Ah; off 02h, traced: the dialog changes nothing else that
        /// the engine reads). With bit 3 clear the root's pre-scoring takes the evaluation
        /// path (0000:0F73) and the ponder check (0389) is skipped; the search's probes
        /// need [239C] >= 0Bh and stay off either way. Written in the start-up checkpoint
        /// and in the game held (at its home, the node's `State`); the files stay bound (with
        /// bit 3 clear the root's probe asks only for the additional path, which is empty, so
        /// the unpacked files that `applyOptions` frees are never asked for).
        pub fn setTablebases(e: *Self, on: bool) void {
            setTbBit(e.root.checkpointHome(e.loop_cp), on);
            setTbBit(e.root.home(), on);
        }

        fn setTbBit(m: anytype, on: bool) void {
            var v = dgroup.memWord(m, 0x239C) & ~tb_use_bit;
            if (on) v |= tb_use_bit;
            dgroup.memSetWord(m, 0x239C, v);
        }

        /// `OwnBook`: the original's M-Chess book switch DG:A5EE (0 on, 1 off: the menu item
        /// and the key K, docs/arch/40-opening-book.md section 6), in the start-up checkpoint
        /// and in the game held, and the embedded book files bound to the root. Off is the
        /// engine as it was before the book was joined (the repeatable state's K).
        pub fn setBook(e: *Self, on: bool) void {
            const v: u16 = if (on) 0 else 1;
            dgroup.memSetWord(e.root.checkpointHome(e.loop_cp), 0xA5EE, v);
            dgroup.memSetWord(e.root.home(), 0xA5EE, v);
            e.root.book_files = if (on) &engine_data.book_files else null;
        }

        /// The value start-up gives srand (main 0000:0109: the BIOS tick count, the word at
        /// 0000:046C): `Seed` when it is set (0..65535); otherwise the portable clock read as
        /// the BIOS reads it, 18.2 ticks a second since midnight, the low word; with no clock
        /// (the tests), 17, the tick count the oracle's emulator gives.
        pub fn startSeed(e: *const Self) u16 {
            if (e.options.seed >= 0) return @intCast(e.options.seed);
            const io = e.io orelse return 17;
            const ns = std.Io.Clock.real.now(io).nanoseconds;
            const day: i96 = 86_400 * std.time.ns_per_s;
            const since_midnight: u128 = @intCast(@mod(ns, day));
            // 1,193,182 Hz / 65,536 per tick.
            return @truncate(since_midnight * 1_193_182 / (65_536 * std.time.ns_per_s));
        }

        /// `ucinewgame`: the held game is dropped; the shell's `position startpos` that
        /// follows rebuilds.
        fn newGame(ctx: *anyopaque) void {
            const e = self(ctx);
            e.move_count = 0;
            e.phase = .none;
        }

        /// The command loop after start-up, the main hash tables and the pawn hash empty:
        /// the start-up checkpoint restored (`EngineRoot.restoreState`).
        pub fn resetToLoop(e: *Self) void {
            const s = e.root;
            s.restoreState(e.loop_cp);
            s.pawn_hash.clear();
            s.dropped_plies = 0;
            for (s.tables) |*t| t.clear();
            s.failure = null;
            s.trace = false;
            // srand(the tick count) at start-up (main 0000:0109): the book's random source,
            // seeded at the start of every game (DEV-F13), whatever `OwnBook` says, so that
            // the book turned on later in the game draws from this game's seed. With the
            // book off nothing reads it (Normal style); with no clock (the tests) and the
            // default `Seed` it is 17, the start-up value.
            dgroup.memSetDword(s.home(), 0x2DC8, e.startSeed());
            e.game_fresh = true;
        }

        fn sideToMove(start: *const fen.Description, route: uci_engine.Route, n: usize) pos.Side {
            const first_white = route == .new_game or start.side_to_move == .white;
            return if (first_white == (n % 2 == 0)) .white else .black;
        }

        const Found = union(enum) { ok: pos.Move, no: []const u8 };

        /// The move of the original's generator for `m`, if it gives one and the move
        /// passes the rewrite's legality test (src/legality.zig: the generator the original
        /// uses there, gen_evasions when the game record's check byte is set, else
        /// gen_all_moves with its cap of 100; no castling out of check; the mover's king not
        /// attacked after it); else the reason. `side` is the side to move; the state must
        /// be at main 0526 (the game record's en-passant square and check byte). A promotion
        /// must carry its piece and any other move none (DEV-F22). Since Stage B step 8,
        /// stage 6, on copies of the domain's `Position`, `see.Scratch`, `SearchVars` and
        /// the node's ply-1 list, as `EngineRoot.bookMoveLegal` generates (the generator's writes,
        /// the move marks it decrements and the list, never reach the game); before, on a
        /// copy of the image.
        pub fn findLegal(e: *Self, m: fen.UciMove, side: pos.Side) Found {
            const s = e.root;
            const d = s.node.dom;
            var gp = d.p;
            // The en-passant square and the check byte of the root, as main reads them from
            // the game record before a search (0000:0677-0693).
            const r = legality.rootRecord(s, @backingInt(side));
            gp.ep_square_by_ply[1] = r.ep;
            gp.check_by_ply[1] = r.check;
            var sc = d.s;
            var sv = d.sv;
            var list = s.node_state.move_list[1];
            const n = legality.generate(fixes, &gp, &sc, &sv, &list, side, 1);
            if (n == mg.king_capture) return .{ .no = "the side not to move is in check" };
            var found: ?pos.Move = null;
            // The squares match a generated move whose piece letter does not agree.
            var needs_letter = false;
            var letter_not_wanted = false;
            for (list[0..@min(n, 100)]) |mv| {
                if (mv.from != m.from or mv.to != m.to) continue;
                const promo = isPromotion(&d.p.board, .{ mv.from, mv.to, mv.flag, 0 });
                if (promo and m.promotion == 0) needs_letter = true;
                if (!promo and m.promotion != 0) letter_not_wanted = true;
                if (promo and mv.flag != m.promotion) continue;
                if (!promo and m.promotion != 0) continue;
                found = mv;
                break;
            }
            const mv = found orelse return .{ .no = if (needs_letter)
                "a promotion needs n, b, r or q"
            else if (letter_not_wanted)
                "a piece letter on a move that is not a promotion"
            else
                "not a move of the original's move generator" };
            var p = d.p;
            // gen_all_moves (1E9D:3938) offers castling without looking at the king's own
            // square: its tests (388C, 37E0) cover the square the king passes and the one it
            // lands on. The original never asks it in check (its root and check_entered_move
            // call gen_evasions there), so `makeIfKingSafe` refuses a castling move with the
            // king attacked. Found by the perft test (src/perft_test.zig, `known_all_moves`).
            if (legality.makeIfKingSafe(&p, mv, side, 1)) |why| return .{ .no = why.text() };
            return .{ .ok = mv };
        }

        /// Plays `m` as the program's own move in auto-play (play_best_move and the
        /// turn), if `findLegal` allows it.
        fn playGiven(e: *Self, m: fen.UciMove, side: pos.Side) ?[]const u8 {
            const s = e.root;
            const mv = switch (e.findLegal(m, side)) {
                .ok => |x| x,
                .no => |why| return why,
            };
            // The best move DG:A36C, the root's own variable (its home `RootVars`).
            const h = s.home();
            h.set(0xA36C, mv.from);
            h.set(0xA36D, mv.to);
            h.set(0xA36E, mv.flag);
            s.playMove();
            s.nextTurnAutoPlay();
            if (s.failure) |f| return f;
            return null;
        }

        /// The opponent's move entered at the command loop (normal play), the program
        /// keeping its side. False, with nothing changed, when the move's piece letter does
        /// not agree with check_entered_move's own board test (38C0:5909-5936: a pawn of the
        /// side to move DG:717C reaching its last rank is a promotion, flag 5, for which the
        /// original's prompt, 38C0:30CB-30E5, asks the piece and takes no other key; any
        /// other move has no prompt): a promotion needs `n`, `b`, `r` or `q`, any other move
        /// takes none (DEV-F22). The caller then rebuilds, which refuses with the reason.
        fn enterOpponent(e: *Self, m: fen.UciMove) bool {
            const s = e.root;
            {
                const d = s.node.dom;
                const piece = squareOf(&d.p.board, m.from);
                const promotion = if (s.home().get(0x717C) == 0)
                    piece == pos.white_pawn and m.to > 0x5A
                else
                    piece == pos.black_pawn and m.to < 0x1D;
                if (promotion != (m.promotion != 0)) return false;
            }
            const promo: u8 = switch (m.promotion) {
                pos.white_knight => 'n',
                pos.white_bishop => 'b',
                pos.white_rook => 'r',
                else => 'q',
            };
            if (!s.enterMove(m.from, m.to, promo)) return false;
            return s.failure == null;
        }

        /// The program takes the side to move from the command loop: Ctrl-A (38C0:3F1C,
        /// `EngineRoot.autoPlay`), then auto-play off ([9FCF] = 0), so that the program's move is
        /// played as in normal play. [9FCF] is read by main before a search only at the
        /// timed levels and by the displays (rootprep 0000:0465, 140A).
        fn programTakesSideToMove(e: *Self) ?[]const u8 {
            if (!e.root.autoPlay()) return "the original refuses to play on from move 202";
            e.root.home().set(0x9FCF, 0);
            return null;
        }

        /// Rebuilds the held game as the position asked for (docs/UCI.md, "The operator
        /// script"): from the command loop after start-up (and Setup mode for a FEN), the
        /// key `!` (pondering off), then:
        /// - no moves: the program takes the side to move (`programTakesSideToMove`);
        /// - one move: it is entered as the opponent's (normal play: `EngineRoot.enterMove`), and
        ///   the program plays the other side;
        /// - more: the program plays every move as its own in auto-play (Ctrl-A,
        ///   play_best_move and the turn: the path of the golden corpora), then auto-play
        ///   is switched off for the search.
        fn rebuild(e: *Self) ?[]const u8 {
            e.phase = .none;
            e.rebuilt += 1;
            e.by_continuation = false;
            const s = e.root;
            const h = s.home();
            e.resetToLoop();
            if (e.route == .setup) {
                const r = adapt_setup.enterFenFixes(fixes, s, &e.start);
                if (r != .legal) return std.fmt.bufPrint(&e.reason_buf, "the original's Setup mode refuses it: {s}", .{adapt_setup.refusalText(r)}) catch adapt_setup.refusalText(r);
            }
            s.togglePondering();
            const req = e.moves[0..e.move_count];
            if (req.len == 1) {
                // Checked first on the auto-play path (Ctrl-A), where findLegal's inputs are
                // as at 0526; then the command loop is taken back (a checkpoint of the
                // state, `EngineRoot.saveState` and `restoreState`) and the move entered.
                const keep = e.gpa.create(EngineRoot.Checkpoint) catch return "out of memory";
                defer e.gpa.destroy(keep);
                s.saveState(keep);
                if (e.programTakesSideToMove()) |why| return why;
                switch (e.findLegal(req[0], sideToMove(&e.start, e.route, 0))) {
                    .ok => {},
                    .no => |why| return std.fmt.bufPrint(&e.reason_buf, "move 1: {s}", .{why}) catch why,
                }
                s.restoreState(keep);
                if (!e.enterOpponent(req[0])) return s.failure orelse "move 1: refused by check_entered_move (38C0:5864)";
            } else {
                if (e.programTakesSideToMove()) |why| return why;
                if (req.len > 0) {
                    h.set(0x9FCF, 1);
                    for (req, 0..) |m, i| {
                        if (e.playGiven(m, sideToMove(&e.start, e.route, i))) |why| {
                            return std.fmt.bufPrint(&e.reason_buf, "move {d}: {s}", .{ i + 1, why }) catch why;
                        }
                    }
                    h.set(0x9FCF, 0);
                }
                // Auto-play is now off, so the program's taking of the side to move ends as
                // the original's does with auto-play off (38C0:3FE6-3FEF): sub_38C0_1176,
                // [AE44] = [717C], the opponent's side. Ctrl-A itself skips it ([9FCF] = 1
                // at 3F24). Without it [AE44] kept the start-up 0 (White), and when the
                // program was White the opponent's next move failed check 38C0:50DB
                // ("monitor mode"), so the next position was rebuilt, not continued
                // (docs/OPEN_QUESTIONS.md question 19). Nothing the search reads.
                h.set(0xAE44, h.get(0x717C));
            }
            if (!e.ensureRoom(&e.held, req.len)) return "out of memory";
            @memcpy(e.held[0..req.len], req);
            e.held_count = req.len;
            e.held_route = e.route;
            e.held_start = e.start;
            e.phase = .ready;
            return null;
        }

        /// Brings the root to main 0526 of the position asked for: continued from the held
        /// game when it can be, rebuilt otherwise.
        fn sync(e: *Self) ?[]const u8 {
            const req = e.moves[0..e.move_count];
            const same_start = e.phase != .none and e.held_route == e.route and
                (e.route == .new_game or std.meta.eql(e.held_start, e.start));
            if (same_start and req.len >= e.held_count and movesEql(e.held[0..e.held_count], req[0..e.held_count])) {
                if (e.phase == .ready and req.len == e.held_count) return null;
                if (e.phase == .waiting and req.len == e.held_count + 1) {
                    if (e.enterOpponent(req[req.len - 1]) and e.holdMove(req[req.len - 1])) {
                        e.phase = .ready;
                        e.continued += 1;
                        e.by_continuation = true;
                        return null;
                    }
                    // Refused, or a path not ported: the rebuild names the reason (or
                    // accepts the move by another path).
                }
            }
            return e.rebuild();
        }

        fn movesEql(a: []const fen.UciMove, b: []const fen.UciMove) bool {
            if (a.len != b.len) return false;
            for (a, b) |x, y| if (!x.eql(y)) return false;
            return true;
        }

        fn setPosition(ctx: *anyopaque, start: *const fen.Description, route: uci_engine.Route, moves: []const fen.UciMove) ?[]const u8 {
            const e = self(ctx);
            if (!e.ensureRoom(&e.moves, moves.len)) return "out of memory";
            e.route = route;
            e.start = start.*;
            @memcpy(e.moves[0..moves.len], moves);
            e.move_count = moves.len;
            const why = e.sync();
            if (why != null) e.phase = .none;
            // The cd set's files the root could read from this position, decompressed now,
            // before any `go` and its clock (src/tb_store.zig `prepare`).
            if (why == null and e.options.use_tablebases) {
                e.tb_store.io = e.io;
                // The game board DG:7520 (the screen's; no member holds it).
                var board: [120]u8 = undefined;
                const h = e.root.home();
                for (&board, 0..) |*b, i| b.* = h.get(@intCast(0x7520 + i));
                e.tb_store.prepare(&board);
            }
            return why;
        }

        /// The Fixed depth of a `go` (DG:1E02): `depth N` (1 to 30); every other `go` the
        /// deepest, 30, the level `go infinite` searches at, with the time control deciding
        /// when to stop (docs/UCI_TIME.md section 1).
        pub fn depthOf(limits: *const uci_engine.Limits) u16 {
            if (limits.depth) |d| return @intCast(std.math.clamp(d, 1, max_depth));
            return max_depth;
        }

        /// The time control's limits for a `go` (docs/UCI_TIME.md section 3): `infinite`
        /// first, then `movetime`, a clock, `nodes`, `mate`, `depth`; a `go` with none of
        /// them searches as `infinite` does (without holding `bestmove`). A `depth` limit
        /// applies together with any of them, whichever comes first.
        pub fn timeLimits(limits: *const uci_engine.Limits, move_overhead: u32) timecontrol.Limits {
            const sat = struct {
                fn u32of(x: u64) u32 {
                    return @intCast(@min(x, std.math.maxInt(u32)));
                }
            }.u32of;
            var l: timecontrol.Limits = .{ .move_overhead = move_overhead };
            if (limits.depth) |d| l.depth = @intCast(std.math.clamp(d, 1, max_depth));
            if (limits.infinite) {
                l.kind = .infinite;
            } else if (limits.movetime) |t| {
                l.kind = .movetime;
                l.movetime = sat(t);
            } else if (limits.wtime != null or limits.btime != null) {
                l.kind = .clock;
                l.wtime = sat(limits.wtime orelse 0);
                l.btime = sat(limits.btime orelse 0);
                l.winc = sat(limits.winc);
                l.binc = sat(limits.binc);
                l.movestogo = @intCast(@min(limits.movestogo orelse 0, std.math.maxInt(u16)));
            } else if (limits.nodes) |n| {
                l.kind = .nodes;
                l.nodes = @max(n, 1);
            } else if (limits.mate) |m| {
                l.kind = .mate;
                l.mate = @intCast(std.math.clamp(m, 1, 255));
            } else if (limits.depth != null) {
                l.kind = .depth;
            } else {
                l.kind = .infinite;
            }
            return l;
        }

        fn search(ctx: *anyopaque, limits: *const uci_engine.Limits, signals: *uci_engine.Signals, out: uci_engine.Output) uci_engine.Result {
            const e = self(ctx);
            // Every variable read or written here before and after the search is reached at
            // its home (Stage B step 8, stage 6: `EngineRoot.Home`, the domain's members, the
            // node's `State`), with no image bracket: the search, the conclusion and the
            // turn all run on the members.
            e.last_score = null;
            if (e.sync()) |why| {
                e.phase = .none;
                out.print("info string error: {s}", .{why});
                return .{};
            }
            // The game's first search: an option set from now on waits for the next game.
            e.game_fresh = false;
            if (e.route == .setup) e.reportUnused(out);
            if (limits.searchmoves.len > 0) out.print("info string searchmoves is not supported (the original's excluded-move list is not joined): every move is searched", .{});
            const s = e.root;
            const h = s.home();
            const d = s.node.dom;
            const depth = depthOf(limits);
            h.set(0xA274, 3); // Fixed depth
            dgroup.memSetWord(h, 0x1E02, depth);
            // The time control (docs/UCI_TIME.md sections 2 and 4): the side to move is
            // the program's ([8DDE] at 0526); the opponent's last move gives the previous
            // target square; the expected move is the third move of the last search's PV
            // when the opponent played its second.
            const tl = timeLimits(limits, e.options.move_overhead_ms);
            e.tc.setLimits(tl);
            // Owner decision 22: an infinite search (`go infinite`, with or without
            // `ponder`, and a `go` with no limit, which searches as infinite does) never
            // uses the tablebases: it is the search of the original with its "Use
            // tablebases" box unticked. The setting is restored after the search.
            e.last_tb_off = tl.kind == .infinite and e.options.use_tablebases;
            if (e.last_tb_off) setTbBit(h, false);
            defer if (e.last_tb_off) setTbBit(h, e.options.use_tablebases);
            const previous_to: ?u8 = if (e.move_count > 0) e.moves[e.move_count - 1].to else null;
            var expected: ?timecontrol.Expected = null;
            if (e.by_continuation and e.move_count > 0) if (e.predicted) |p| {
                const opp = e.moves[e.move_count - 1];
                // A PV word holds no promotion piece: a predicted promotion, the reply's or
                // the answer's, is an unknown expectation.
                const a_from: u8 = @truncate(p[1] & 0x7F);
                const a_to: u8 = @truncate((p[1] >> 8) & 0x7F);
                const a_pc = squareOf(&d.p.board, a_from);
                const answer_promotes = (a_pc == 1 or a_pc == 8) and (a_to >= 91 or a_to <= 28);
                if (@as(u8, @truncate(p[0] & 0x7F)) == opp.from and @as(u8, @truncate((p[0] >> 8) & 0x7F)) == opp.to and opp.promotion == 0 and !answer_promotes)
                    expected = .{ .move = Report.moveKey(a_from, a_to), .to = a_to };
            };
            e.predicted = null;
            e.last_expected = expected;
            e.last_previous_to = previous_to;
            e.tc.start(if (h.get(0x8DDE) == 0) .white else .black, expected, previous_to, 0);
            s.node_limit = if (limits.nodes) |n| @max(n, 1) else 0;
            defer s.node_limit = 0;
            var rep: Report = .{
                .root = s,
                .out = out,
                .signals = signals,
                .io = e.io,
                .enabled = e.reporting,
                .tc = &e.tc,
                .go_ns = limits.go_ns,
                .scripted_us_per_node = e.scripted_us_per_node,
                .ponder = limits.ponder,
                .pv_check = e.pv_check,
            };
            rep.begin();
            s.observer = rep.observer();
            e.point("before the search");
            const o = s.search(.own);
            e.point("after the search");
            s.observer = null;
            e.time_log = rep.log;
            defer {
                e.pv_cuts = rep.pv_cuts;
                e.first_cut = rep.first_cut;
                if (rep.have_score) e.last_score = rep.score;
            }
            e.phase = .none;
            if (s.failure) |f| {
                out.print("info string error: {s}", .{f});
                return .{};
            }
            if (s.book_illegal) |bad| {
                var mb: [5]u8 = undefined;
                out.print("info string book miss: the book drew {s}, which is not legal here (AGENTS.md 9.3): searching", .{fen.formatMove(.{ .from = bad.from, .to = bad.to, .promotion = if (isPromotion(&d.p.board, .{ bad.from, bad.to, bad.flag, 0 })) bad.flag else 0 }, &mb)});
            }
            if (o.exit == .main_loop and s.book_played) return e.bookMove(out, &rep);
            const searched = o.exit == .iteration_loop;
            if (o.best[0] == 0) {
                out.print("info string no move: the game is over in this position", .{});
                return .{};
            }
            // AGENTS.md section 9.3 item 3 (class B): the move handed back must pass the full
            // legality test. Seen once: a continued game in which the program was
            // checkmated (no legal move) handed back [A36C] left from the search before. A
            // move that fails is never played on the held game (the next position rebuilds).
            if (e.pv_check.legalPrefix(fixes, &.{@as(u16, o.best[0] & 0x7F) | @as(u16, o.best[1] & 0x7F) << 8}, o.best[2]) == 0) {
                var mb: [5]u8 = undefined;
                const bad: fen.UciMove = .{ .from = o.best[0] & 0x7F, .to = o.best[1] & 0x7F, .promotion = 0 };
                if (e.firstLegalRootMove()) |m| {
                    var mb2: [5]u8 = undefined;
                    out.print("info string illegal move: the original's search gave {s}, which is not legal here; the first legal move of its root list, {s}, is played instead (AGENTS.md 9.3)", .{ fen.formatMove(bad, &mb), fen.formatMove(m, &mb2) });
                    return .{ .best = m };
                }
                out.print("info string no move: the game is over in this position (the original's search gave {s}, which is not legal here)", .{fen.formatMove(bad, &mb)});
                return .{};
            }
            const best: fen.UciMove = .{ .from = o.best[0] & 0x7F, .to = o.best[1] & 0x7F, .promotion = if (isPromotion(&d.p.board, o.best)) o.best[2] else 0 };
            if (!searched and o.exit == .conclude and s.tb_hits > 0) {
                // The root's pre-scoring played a move scored from the tablebases (0000:0FEA,
                // 0FB8): its score is in [A8DA], from the program's view.
                if (e.reporting) {
                    var sb: [16]u8 = undefined;
                    var mb: [5]u8 = undefined;
                    const score: i16 = @bitCast(dgroup.memWord(h, 0xA8DA));
                    e.last_score = score;
                    const ms = rep.elapsedMs();
                    out.print("info depth 1 seldepth 1 score {s} nodes {d} nps {d} time {d} hashfull {d} pv {s}", .{ uci_report.scoreText(score, &sb), s.nodes, s.nodes * 1000 / @max(ms, 1), ms, rep.hashfull(), fen.formatMove(best, &mb) });
                }
                out.print("info string tablebase move: the original's root played it from its tablebases without a search ({d} probes accepted)", .{s.tb_hits});
                return .{ .best = best };
            }
            rep.final(searched);
            if (!searched) {
                out.print("info string the original played this move without a search ({s})", .{@tagName(o.exit)});
                return .{ .best = best };
            }
            // The PV's reply and answer, for the next search's expected move: the PV row of
            // ply 1 (DG:93B0, the node's `State.pv[1]`), its length DG:B42B.
            const pv_len: i8 = @bitCast(h.get(0xB42B));
            const pv = &s.node_state.pv[1];
            if (pv_len >= 3 and pv[0] & 0x7F7F == Report.moveKey(best.from, best.to))
                e.predicted = .{ pv[1], pv[2] };
            // The original plays its move at once and goes on to its command loop.
            s.playMove();
            e.point("after play_best_move");
            var ponder: ?fen.UciMove = null;
            if (s.failure == null and s.toOpponentMove() and e.holdMove(best)) {
                e.phase = .waiting;
                // The reply set_predicted_reply chose (DG:8FDE, `GameVars.predicted_reply`),
                // legal by its own test; the list's flag DG:A3FA, its low byte.
                const p = d.gv.predicted_reply;
                if (p[0] != 0 and @as(u8, @truncate(d.gv.reply_list_valid.*)) != 0) {
                    const to = p[1] & 0x7F;
                    const pc = squareOf(&d.p.board, p[0] & 0x7F);
                    const promo = (pc == 1 or pc == 8) and (to >= 91 or to <= 28);
                    ponder = .{ .from = p[0] & 0x7F, .to = to, .promotion = if (promo) (if (p[2] >= 2 and p[2] <= 5) p[2] else pos.white_queen) else 0 };
                }
            } else e.phase = .none;
            return .{ .best = best, .ponder = ponder };
        }

        /// The first move of the root list (DG:3BC4, [7442] moves of 4 bytes, in the
        /// original's order) that passes the full legality test, if any; for the class B
        /// guard (AGENTS.md section 9.3 item 3). The state is the one after the search,
        /// before any move is played: the count at its home, the list the node's
        /// `State.move_list[1]`.
        fn firstLegalRootMove(e: *Self) ?fen.UciMove {
            const s = e.root;
            const count = @min(dgroup.memWord(s.home(), 0x7442), 100);
            const board = &s.node.dom.p.board;
            for (s.node_state.move_list[1][0..count]) |mv| {
                const m = [4]u8{ mv.from, mv.to, mv.flag, 0 };
                if (e.pv_check.legalPrefix(fixes, &.{@as(u16, m[0] & 0x7F) | @as(u16, m[1] & 0x7F) << 8}, m[2]) == 1)
                    return .{ .from = m[0] & 0x7F, .to = m[1] & 0x7F, .promotion = if (isPromotion(board, m)) m[2] else 0 };
            }
            return null;
        }

        /// main 070F: the book handed over a move and play_best_move(1) played it (DG:38A0,
        /// copied to DG:A36C); then, as after a search, main goes on to its command loop
        /// (`EngineRoot.toOpponentMove`). Reported as a line with the move and an `info string`.
        fn bookMove(e: *Self, out: uci_engine.Output, rep: *Report) uci_engine.Result {
            const s = e.root;
            const h = s.home();
            const b = [3]u8{ h.get(0x38A0), h.get(0x38A1), h.get(0x38A2) };
            // The board has the move played: a pawn now on the last rank was promoted.
            const pc = squareOf(&s.node.dom.p.board, b[1] & 0x7F);
            const promo = (pc != 1 and pc != 8) and b[2] >= 2 and b[2] <= 5;
            const best: fen.UciMove = .{ .from = b[0] & 0x7F, .to = b[1] & 0x7F, .promotion = if (promo) b[2] else 0 };
            var mb: [5]u8 = undefined;
            if (e.reporting) {
                const ms = rep.elapsedMs();
                out.print("info depth 1 seldepth 1 nodes 0 nps 0 time {d} hashfull {d} pv {s}", .{ ms, rep.hashfull(), fen.formatMove(best, &mb) });
            }
            out.print("info string book move: the original's opening book played {s} without a search", .{fen.formatMove(best, &mb)});
            if (s.failure == null and s.toOpponentMove() and e.holdMove(best)) {
                e.phase = .waiting;
            } else e.phase = .none;
            if (s.failure) |f| out.print("info string error: {s}", .{f});
            return .{ .best = best };
        }

        /// The FEN fields Setup mode cannot give, as `info string` lines: what the engine
        /// did with each (docs/UCI.md, "position fen").
        fn reportUnused(e: *const Self, out: uci_engine.Output) void {
            const u = adapt_setup.unsupported(&e.start);
            if (u.castling) out.print("info string position fen: castling rights other than the board's: the rights the FEN withholds are stamped lost as the original's position loader does (0EF8:6AAB), without a new hash key", .{});
            if (u.en_passant) out.print("info string position fen: the en-passant square is taken as the original's position loader takes it (0EF8:6AA3)", .{});
            if (u.halfmove_clock) out.print("info string position fen: halfmove clock {d} not used: the original's set-up starts the count afresh", .{e.start.halfmove_clock});
            if (u.fullmove_number) out.print("info string position fen: move number {d} not used: the original's set-up makes it 1", .{e.start.fullmove_number});
        }
    };
}

/// A pawn's move to the last rank (squares 91..98 or 21..28), whose flag is the
/// promoted piece as a White code 2..5.
/// The man on square `sq` of the 10x12 board; 0 for an index past it (a move's square is
/// always on the board where these are read: from the root list, the book, the predicted
/// reply, or a move the legality test passed).
fn squareOf(board: *const [120]u8, sq: u8) u8 {
    return if (sq < board.len) board[sq] else 0;
}

/// `board`: the search board DG:9EF6 (`Position.board`).
fn isPromotion(board: *const [120]u8, m: [4]u8) bool {
    const from = m[0] & 0x7F;
    const to = m[1] & 0x7F;
    const piece = squareOf(board, from);
    const last = (to >= 91 and to <= 98) or (to >= 21 and to <= 28);
    return (piece == 1 or piece == 8) and last and m[2] >= 2 and m[2] <= 5;
}
