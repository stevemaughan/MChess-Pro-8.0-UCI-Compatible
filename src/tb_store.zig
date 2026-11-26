//! The engine's tablebase files for either set (owner decision 33; docs/arch/41-tablebases.md,
//! "The four-man tablebases"): `shipped`, the six files the original was installed with
//! (src/engine_data.zig `tb_files`, embedded as they are), or `cd`, those six and the 60
//! further files of reference/tablebases/m80-cd that passed the checks against the rules
//! of chess (every one there but KPPK and KPKP), embedded zstd-compressed from
//! reference/extracted/tablebases/ (build.zig; the list is src/tb_names.zig).
//!
//! A further file is decompressed once and kept while `Use Tablebases` is true. The UCI engine
//! decompresses all of them at `uci`, before `uciok` (owner decision 37, 2026-11-22;
//! `preloadAll`, called from src/uci.zig on the shell's input thread, on several threads of
//! its own), so that no move pays for it (docs/ROBUSTNESS.md, finding 2). A store that is
//! never preloaded (the engine's own tests, which do not go through `uci`) decompresses a
//! file the first time it could be needed: by `prepare`, which the engine calls when it
//! takes a position (src/engine.zig `setPosition`), and, for a file `prepare` did not
//! foresee (the tests' routes that enter positions another way), by the probe's own lookup.
//! Those run on the engine's one thread. A file's slot is written once, by whichever thread
//! decompressed it first (a compare-and-swap), so a `preloadAll` that overlaps the engine's
//! thread is safe; the bytes are the same whichever thread made them.
//!
//! `Use Tablebases` false gives the memory back (owner decision 44, 2026-11-22): `setUse`
//! frees every decompressed file and the engine thread's window, and until it is set true
//! again nothing is decompressed (`load`, so `prepare` and the probe's lookup, and
//! `preloadAll`, so a second `uci`); set true again, it decompresses every file at once, as
//! at `uci`. `setUse` runs on the engine's thread, between searches (src/engine.zig
//! `applyOptions`, from the shell's queued `setoption`), so no search can be reading a file it
//! frees; the store's `lock` keeps it apart from a `preloadAll` on the shell's input thread
//! (a `uci` that arrives meanwhile). The six installed files are the executable's own bytes
//! (src/engine_data.zig) and are never freed.

const std = @import("std");
const tablebase = @import("tablebase.zig");
const os_threads = @import("threads.zig");
const engine_data = @import("engine_data.zig");
const tb_names_mod = @import("tb_names.zig");

/// Which tablebase files the program's `TB` folder holds (the oracle's scenario field `tbset`).
pub const TbSet = enum { shipped, cd };

/// The 60 further files' names, `<stem>.TBW` then `<stem>.TBB` per material.
pub const cd_names: [2 * tb_names_mod.cd_stems.len][]const u8 = blk: {
    var a: [2 * tb_names_mod.cd_stems.len][]const u8 = undefined;
    for (tb_names_mod.cd_stems, 0..) |s, i| {
        a[2 * i] = s ++ ".TBW";
        a[2 * i + 1] = s ++ ".TBB";
    }
    break :blk a;
};

/// Their contents, one zstd frame each (reference/extracted/tablebases/README.md).
pub const cd_zst: [cd_names.len][]const u8 = blk: {
    var a: [cd_names.len][]const u8 = undefined;
    for (cd_names, 0..) |n, i| a[i] = @embedFile("tbz/" ++ n);
    break :blk a;
};

/// The size of a file of this material, as the probe's index implies (22-search-helpers
/// section 6): 64 per man, the last pawn 32, or the last man of a pawnless ending 10.
pub fn fileSize(name: []const u8) usize {
    const stem = name[0 .. std.mem.indexOfScalar(u8, name, '.') orelse name.len];
    var size: usize = if (std.mem.indexOfScalar(u8, stem, 'P') != null) 32 else 10;
    for (1..stem.len) |_| size *= 64;
    return size;
}

pub fn indexOf(name: []const u8) ?usize {
    for (cd_names, 0..) |n, i| if (std.ascii.eqlIgnoreCase(n, name)) return i;
    return null;
}

/// zstd's window (8 MB plus a block): one per thread that decompresses.
const window_len = std.compress.zstd.default_window_len + std.compress.zstd.block_size_max;

/// The most threads `preloadAll` uses, the calling thread included.
pub const max_preload_threads = 8;

/// The further files in the order `preloadAll` hands them out: the largest first (the
/// four-man files with a pawn, 8 MB each; then those without, 2.6 MB; then KBK and KNK), so
/// that the threads finish together.
const preload_order: [cd_names.len]u8 = blk: {
    @setEvalBranchQuota(10_000);
    var a: [cd_names.len]u8 = undefined;
    var n: usize = 0;
    for ([_]bool{ true, false }) |pawn| for ([_]usize{ 4, 3 }) |men| for (cd_names, 0..) |name, i| {
        const stem = name[0 .. name.len - 4];
        if (stem.len == men and (std.mem.indexOfScalar(u8, stem, 'P') != null) == pawn) {
            a[n] = i;
            n += 1;
        }
    };
    if (n != cd_names.len) @compileError("preload_order misses a file");
    break :blk a;
};

/// Decompresses further file `i` into a new buffer of `fileSize` bytes, with `window`
/// (`window_len` bytes, the caller's thread's own). Null if memory ran out.
fn decompress(gpa: std.mem.Allocator, i: usize, window: []u8) ?[]u8 {
    const out = gpa.alloc(u8, fileSize(cd_names[i])) catch return null;
    var in: std.Io.Reader = .fixed(cd_zst[i]);
    // verify_checksum stays false: true panics in Zig 0.17.1 (a TODO in Decompress).
    var zd = std.compress.zstd.Decompress.init(&in, window, .{});
    zd.reader.readSliceAll(out) catch {
        gpa.free(out);
        return null;
    };
    return out;
}

pub const TbStore = struct {
    gpa: std.mem.Allocator,
    set: TbSet,
    /// Each further file once decompressed (`fileSize` bytes from this address), null
    /// until then. Written once, by a compare-and-swap from null (`publish`); read with
    /// acquire (`held`), since `preloadAll` may run on another thread than the engine's.
    slots: [cd_names.len]?[*]u8 = @splat(null),
    /// The engine thread's zstd window, allocated at its first decompression (`load`).
    window: ?[]u8 = null,
    /// Files decompressed (by any thread); of them, those decompressed inside the probe's
    /// lookup.
    loads: u32 = 0,
    loads_at_probe: u32 = 0,
    /// The longest decompression of one file and the longest `prepare`, in ns (with `io`;
    /// the engine's thread).
    max_load_ns: u64 = 0,
    max_prepare_ns: u64 = 0,
    /// The last `preloadAll` that found a file missing: its time in ns (with an `io`), the
    /// threads it used and the files it decompressed (the tests and the shell's `debug`).
    preload_ns: u64 = 0,
    preload_threads: u32 = 0,
    preload_loads: u32 = 0,
    io: ?std.Io = null,
    /// `Use Tablebases` (owner decision 44): false, no file is held or decompressed
    /// (`setUse`). Written by `setUse` only, under `lock`, on the engine's thread; read there
    /// and by `preloadAll` under `lock`.
    use: bool = true,
    /// Keeps `setUse` (the engine's thread) and `preloadAll` (the shell's input thread at
    /// `uci`, or the engine's thread) from overlapping: a release never frees a file a
    /// preload is publishing, and a preload never brings files back after a release. Held
    /// for a whole preload (about 0.2 s), so a spin with yields: the two meet only when a
    /// `uci` and a `setoption name Use Tablebases` cross.
    lock: std.atomic.Mutex = .unlocked,
    /// Times `setUse` released the files (the tests).
    releases: u32 = 0,

    pub fn init(gpa: std.mem.Allocator, set: TbSet) TbStore {
        return .{ .gpa = gpa, .set = set };
    }

    pub fn deinit(s: *TbStore) void {
        s.release();
        if (s.window) |w| s.gpa.free(w);
        s.* = undefined;
    }

    /// The probe's file supplier (`EngineRoot.tb_files`).
    pub fn files(s: *TbStore) tablebase.Files {
        return .{ .ctx = s, .lookupFn = lookup };
    }

    /// Further file `i`, if it has been decompressed.
    pub fn held(s: *const TbStore, i: usize) ?[]u8 {
        const p = @atomicLoad(?[*]u8, &s.slots[i], .acquire) orelse return null;
        return p[0..fileSize(cd_names[i])];
    }

    /// Whether every further file of the set is held (true for the shipped set, which has
    /// none).
    pub fn allHeld(s: *const TbStore) bool {
        if (s.set != .cd) return true;
        for (0..cd_names.len) |i| if (s.held(i) == null) return false;
        return true;
    }

    /// Frees every decompressed file (`setUse`, `deinit`, the tests; not while another
    /// thread may use them).
    pub fn release(s: *TbStore) void {
        for (&s.slots, 0..) |*slot, i| if (@atomicLoad(?[*]u8, slot, .acquire)) |p| {
            @atomicStore(?[*]u8, slot, null, .release);
            s.gpa.free(p[0..fileSize(cd_names[i])]);
        };
    }

    fn acquire(s: *TbStore) void {
        while (!s.lock.tryLock()) os_threads.yield();
    }

    /// `Use Tablebases` (owner decision 44, 2026-11-22). False: every decompressed file and
    /// the engine thread's zstd window are freed, and nothing is decompressed until it is
    /// true again. True after false: every file is decompressed at once (`preloadAll`'s
    /// work, on up to `max_preload_threads` threads), so that, as at `uci`, no move pays for
    /// it. No change, nothing (so the shell's first `applyOptions`, before `uci`, unpacks
    /// nothing). The engine's thread only, between searches: a search reads the files
    /// without the lock, and only this thread frees them.
    pub fn setUse(s: *TbStore, on: bool, io: ?std.Io) void {
        s.acquire();
        defer s.lock.unlock();
        if (on == s.use) return;
        s.use = on;
        if (on) {
            s.preloadLocked(io);
        } else {
            s.release();
            if (s.window) |w| s.gpa.free(w);
            s.window = null;
            s.releases += 1;
        }
    }

    /// Makes `buf` file `i`, unless another thread got there first: then `buf` is freed and
    /// the slot keeps the first one (the same bytes).
    fn publish(s: *TbStore, i: usize, buf: []u8) void {
        if (@cmpxchgStrong(?[*]u8, &s.slots[i], null, buf.ptr, .acq_rel, .acquire) != null) {
            s.gpa.free(buf);
            return;
        }
        _ = @atomicRmw(u32, &s.loads, .Add, 1, .monotonic);
    }

    fn now(s: *const TbStore) ?i96 {
        const io = s.io orelse return null;
        return std.Io.Clock.awake.now(io).nanoseconds;
    }

    /// Decompresses further file `i` (nothing if it is held). False if memory ran out, or
    /// if `Use Tablebases` is false (`use`: nothing is decompressed then).
    /// The engine's thread only (it uses the store's one `window`).
    pub fn load(s: *TbStore, i: usize) bool {
        if (s.held(i) != null) return true;
        if (!s.use) return false;
        const t0 = s.now();
        if (s.window == null) {
            s.window = s.gpa.alloc(u8, window_len) catch return false;
        }
        const out = decompress(s.gpa, i, s.window.?) orelse return false;
        s.publish(i, out);
        if (t0) |t| s.max_load_ns = @max(s.max_load_ns, @as(u64, @intCast(s.now().? - t)));
        return true;
    }

    /// Decompresses every further file of the set that is not held yet (owner decision 37:
    /// at `uci`, before `uciok`), on up to `max_preload_threads` threads (this one and the
    /// rest spawned and joined here), each with its own window, freed at the end. Each
    /// thread takes the next file of `preload_order` until none is left; the bytes of a file
    /// do not depend on the thread that made it. Nothing to do (a second `uci`, the shipped
    /// set): it returns at once. With `Use Tablebases` false (`use`) it does nothing either
    /// (owner decision 44: a `uci` then follows the option). A file whose memory could not be
    /// had stays to the lazy path (`load`). `io` times it (`preload_ns`). Under `lock`, so
    /// never at once with `setUse`.
    pub fn preloadAll(s: *TbStore, io: ?std.Io) void {
        s.acquire();
        defer s.lock.unlock();
        if (!s.use) return;
        s.preloadLocked(io);
    }

    fn preloadLocked(s: *TbStore, io: ?std.Io) void {
        if (s.allHeld()) return;
        const t0: ?i96 = if (io) |x| std.Io.Clock.awake.now(x).nanoseconds else null;
        const loads0 = @atomicLoad(u32, &s.loads, .monotonic);
        var job: PreloadJob = .{ .store = s };
        const cpus = std.Thread.getCpuCount() catch 1;
        const want = std.math.clamp(cpus, 1, max_preload_threads);
        var helpers: [max_preload_threads - 1]os_threads.Thread = undefined;
        var spawned: usize = 0;
        while (spawned + 1 < want) : (spawned += 1) {
            helpers[spawned] = os_threads.Thread.spawn(PreloadJob, PreloadJob.run, &job) catch break;
        }
        job.run();
        for (helpers[0..spawned]) |t| t.join();
        s.preload_threads = @intCast(spawned + 1);
        s.preload_loads = @atomicLoad(u32, &s.loads, .monotonic) - loads0;
        if (t0) |t| s.preload_ns = @intCast(std.Io.Clock.awake.now(io.?).nanoseconds - t);
    }

    const PreloadJob = struct {
        store: *TbStore,
        /// The next index into `preload_order` to hand out.
        next: usize = 0,

        fn run(j: *PreloadJob) void {
            const s = j.store;
            const window = s.gpa.alloc(u8, window_len) catch return;
            defer s.gpa.free(window);
            while (true) {
                const k = @atomicRmw(usize, &j.next, .Add, 1, .monotonic);
                if (k >= preload_order.len) return;
                const i = preload_order[k];
                if (s.held(i) != null) continue;
                const out = decompress(s.gpa, i, window) orelse continue;
                s.publish(i, out);
            }
        }
    };

    fn lookup(ctx: ?*const anyopaque, loc: tablebase.Location, name: []const u8) ?[]const u8 {
        const s: *TbStore = @ptrCast(@alignCast(@constCast(ctx.?)));
        if (loc != .program_tb) return null;
        if (engine_data.tb_files.lookup(loc, name)) |d| return d;
        if (s.set != .cd) return null;
        const i = indexOf(name) orelse return null;
        if (s.held(i) == null) {
            if (!s.load(i)) return null;
            s.loads_at_probe += 1;
        }
        return s.held(i);
    }

    /// Decompresses every file the root's probes could read in a search from this game
    /// position (the 10x12 board in the original's codes: 1..6 White, 8..13 Black). The
    /// root probes the position after each root move when it has five men or fewer
    /// (0000:0F73), with the other side to move: so, with five men or fewer on the board,
    /// the position's own material and each one capture, promotion or capturing promotion
    /// away, by either side (the side to move is not assumed), each with the opponent of
    /// the mover to move. Nothing with six men or more, and nothing with `Use Tablebases`
    /// false (`use`).
    pub fn prepare(s: *TbStore, board: *const [120]u8) void {
        if (s.set != .cd or !s.use) return;
        const t0 = s.now();
        defer if (t0) |t| {
            s.max_prepare_ns = @max(s.max_prepare_ns, @as(u64, @intCast(s.now().? - t)));
        };
        var c: [2][7]u8 = @splat(@splat(0));
        var men: usize = 0;
        for (21..99) |sq| {
            const b = board[sq];
            if (b >= 1 and b <= 6) {
                c[0][b] += 1;
                men += 1;
            } else if (b >= 8 and b <= 13) {
                c[1][b - 7] += 1;
                men += 1;
            }
        }
        if (men > 5) return;
        for ([2]u1{ 0, 1 }) |mover| {
            const opp = 1 - mover;
            s.prepareMaterial(c, opp);
            for (1..6) |t| {
                if (c[opp][t] == 0) continue;
                var d = c;
                d[opp][t] -= 1;
                s.prepareMaterial(d, opp);
            }
            if (c[mover][1] != 0) for (2..6) |q| {
                var d = c;
                d[mover][1] -= 1;
                d[mover][q] += 1;
                s.prepareMaterial(d, opp);
                for (2..6) |t| {
                    if (d[opp][t] == 0) continue;
                    var e = d;
                    e[opp][t] -= 1;
                    s.prepareMaterial(e, opp);
                }
            };
        }
    }

    /// Decompresses the file the probe names for this material (men per side and type,
    /// 1 P .. 6 K) with `stm` to move, if it is a further file of the set (BCF9..BDC1: the
    /// side with more men first, or with as many the side whose first differing piece is
    /// higher, White when they are the same; .TBW when the side to move is the first).
    fn prepareMaterial(s: *TbStore, c: [2][7]u8, stm: u1) void {
        var buf: [12]u8 = undefined;
        const name = fileName(c, stm, &buf) orelse return;
        if (indexOf(name)) |i| _ = s.load(i);
    }
};

/// The file name the probe forms for a material, or null when it forms none that the set
/// could hold (the bare kings, a side with no king or more than three men besides it).
pub fn fileName(c: [2][7]u8, stm: u1, buf: *[12]u8) ?[]const u8 {
    var letters: [2][4]u8 = undefined;
    var n: [2]usize = .{ 0, 0 };
    var types: [2][4]u8 = @splat(@splat(0));
    for (0..2) |side| {
        if (c[side][6] != 1) return null;
        letters[side][0] = 'K';
        n[side] = 1;
        var t: usize = 5;
        while (t >= 1) : (t -= 1) {
            for (0..c[side][t]) |_| {
                if (n[side] == 4) return null;
                letters[side][n[side]] = "?PNBRQ"[t];
                types[side][n[side]] = @intCast(t);
                n[side] += 1;
            }
        }
    }
    if (n[0] + n[1] < 3) return null;
    var first: u1 = if (n[1] > n[0]) 1 else 0;
    if (n[0] == n[1]) for (1..n[0]) |k| {
        if (types[0][k] != types[1][k]) {
            first = if (types[1][k] > types[0][k]) 1 else 0;
            break;
        }
    };
    var len: usize = 0;
    for ([2]u1{ first, 1 - first }) |side| {
        @memcpy(buf[len..][0..n[side]], letters[side][0..n[side]]);
        len += n[side];
    }
    @memcpy(buf[len..][0..4], if (stm == first) ".TBW" else ".TBB");
    return buf[0 .. len + 4];
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The hash recorded for `path` in reference/CHECKSUMS.txt (lines `<hex> *<path>`).
fn checksumOf(sums: []const u8, path: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, sums, '\n');
    while (lines.next()) |raw| {
        const l = std.mem.trimEnd(u8, raw, "\r");
        if (l.len < 66 or l[64] != ' ') continue;
        const p = if (l[65] == '*') l[66..] else l[65..];
        if (std.mem.eql(u8, p, path)) return l[0..64];
    }
    return null;
}

test "tb_store: every embedded cd-set file is its .zst in reference/CHECKSUMS.txt and decompresses to its source's SHA-256" {
    const gpa = std.testing.allocator;
    var buf: [256]u8 = undefined;
    const sums_path = try std.fmt.bufPrint(&buf, "{s}/../../reference/CHECKSUMS.txt", .{@import("build_options").golden_dir});
    const sums = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, sums_path, gpa, .limited(1 << 20));
    defer gpa.free(sums);
    var store = TbStore.init(gpa, .cd);
    defer store.deinit();
    store.io = std.testing.io;
    var compressed: usize = 0;
    var raw: usize = 0;
    for (cd_names, 0..) |n, i| {
        var path_buf: [64]u8 = undefined;
        const zlisted = checksumOf(sums, try std.fmt.bufPrint(&path_buf, "extracted/tablebases/{s}.zst", .{n})) orelse return error.NotInChecksums;
        var h: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(cd_zst[i], &h, .{});
        try std.testing.expectEqualStrings(zlisted, &std.fmt.bytesToHex(h, .lower));
        const listed = checksumOf(sums, try std.fmt.bufPrint(&path_buf, "tablebases/m80-cd/{s}", .{n})) orelse return error.NotInChecksums;
        try std.testing.expect(store.load(i));
        std.crypto.hash.sha2.Sha256.hash(store.held(i).?, &h, .{});
        try std.testing.expectEqualStrings(listed, &std.fmt.bytesToHex(h, .lower));
        compressed += cd_zst[i].len;
        raw += store.held(i).?.len;
        store.release();
    }
    std.debug.print("tb_store: {d} cd-set files, {d} bytes embedded, {d} decompressed, every one equal to its source; the longest decompression {d} ms\n", .{ cd_names.len, compressed, raw, store.max_load_ns / std.time.ns_per_ms });
    try std.testing.expectEqual(@as(usize, 60), cd_names.len);
    for (cd_names) |n| try std.testing.expect(!std.mem.startsWith(u8, n, "KPPK") and !std.mem.startsWith(u8, n, "KPKP"));
    // The lookup: KPPK and KPKP have no file; the shipped six are the shipped table's; the
    // program's folder only; a file not prepared is decompressed at the probe.
    const files = store.files();
    try std.testing.expect(files.lookup(.program_tb, "KPPK.TBW") == null);
    try std.testing.expect(files.lookup(.program_tb, "kpkp.tbb") == null);
    try std.testing.expect(files.lookup(.program_tb, "KRK.TBW").?.ptr == engine_data.tb_data[4].ptr);
    try std.testing.expect(files.lookup(.second_dir, "KQKR.TBW") == null);
    try std.testing.expectEqual(@as(usize, 2_621_440), files.lookup(.program_tb, "kqkr.tbw").?.len);
    try std.testing.expectEqual(@as(u32, 1), store.loads_at_probe);
    var shipped = TbStore.init(gpa, .shipped);
    defer shipped.deinit();
    try std.testing.expect(shipped.files().lookup(.program_tb, "KQKR.TBW") == null);
    try std.testing.expect(shipped.files().lookup(.program_tb, "KPK.TBB") != null);
}

fn emptyBoard() [120]u8 {
    var board: [120]u8 = @splat(7);
    for (0..8) |r| for (0..8) |f| {
        board[21 + 10 * r + f] = 0;
    };
    return board;
}

test "tb_store: prepare decompresses what the root can read (KRKP: itself, the pawn's promotions and their captures), nothing at six men" {
    const gpa = std.testing.allocator;
    var store = TbStore.init(gpa, .cd);
    defer store.deinit();
    var board = emptyBoard();
    board[25] = 6; // Ke1
    board[91] = 4; // Ra8
    board[95] = 13; // ke8
    board[34] = 8; // pd2
    store.prepare(&board);
    // KRKP with either side to move; Black's d1=Q, =R, =B, =N with White to move: KQKR.TBB
    // (Black named first), KRKR.TBW, KRKB.TBW, KRKN.TBW; the same taking the rook: KBK.TBB
    // and KNK.TBB (KQK, KRK and KPK are shipped).
    for ([_][]const u8{ "KRKP.TBW", "KRKP.TBB", "KQKR.TBB", "KRKR.TBW", "KRKB.TBW", "KRKN.TBW", "KBK.TBB", "KNK.TBB" }) |n| {
        if (store.held(indexOf(n).?) == null) {
            std.debug.print("tb_store: {s} not prepared\n", .{n});
            return error.TestUnexpectedResult;
        }
    }
    try std.testing.expectEqual(@as(u32, 8), store.loads);
    try std.testing.expect(store.held(indexOf("KQKR.TBW").?) == null);
    try std.testing.expect(store.held(indexOf("KQKQ.TBW").?) == null);
    try std.testing.expect(store.held(indexOf("KBNK.TBW").?) == null);
    const before = store.loads;
    board[41] = 1;
    board[42] = 1;
    store.prepare(&board);
    try std.testing.expectEqual(before, store.loads);
}

test "tb_store: preloadAll (decision 37) holds every file, each byte-equal to the lazy path's; a second call does nothing; prepare and the probe then decompress nothing" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var pre = TbStore.init(gpa, .cd);
    defer pre.deinit();
    // A position taken before `uci`: KRKP's eight files are held by the lazy path already.
    var board = emptyBoard();
    board[25] = 6; // Ke1
    board[91] = 4; // Ra8
    board[95] = 13; // ke8
    board[34] = 8; // pd2
    pre.prepare(&board);
    try std.testing.expectEqual(@as(u32, 8), pre.loads);
    const lazy_slots = pre.slots;
    pre.preloadAll(io);
    try std.testing.expect(pre.allHeld());
    try std.testing.expectEqual(@as(u32, cd_names.len), pre.loads);
    try std.testing.expectEqual(@as(u32, cd_names.len - 8), pre.preload_loads);
    try std.testing.expect(pre.preload_threads >= 1 and pre.preload_threads <= max_preload_threads);
    for (lazy_slots, pre.slots) |a, b| if (a != null) try std.testing.expect(a == b);
    const first_ms = pre.preload_ns / std.time.ns_per_ms;
    const threads = pre.preload_threads;
    // Every file byte-equal to what the lazy path (`load`, one at a time) makes.
    var lazy = TbStore.init(gpa, .cd);
    defer lazy.deinit();
    for (0..cd_names.len) |i| {
        try std.testing.expect(lazy.load(i));
        try std.testing.expectEqualSlices(u8, lazy.held(i).?, pre.held(i).?);
        lazy.release();
    }
    // A second preload (a second `uci`): nothing decompressed, nothing replaced.
    const slots = pre.slots;
    pre.preload_ns = 0;
    pre.preload_loads = 0;
    pre.preloadAll(io);
    try std.testing.expectEqual(@as(u32, cd_names.len), pre.loads);
    try std.testing.expectEqual(@as(u64, 0), pre.preload_ns);
    try std.testing.expectEqual(@as(u32, 0), pre.preload_loads);
    try std.testing.expect(std.mem.eql(?[*]u8, &slots, &pre.slots));
    // Then `prepare` and the probe's lookup find their files held.
    board[25] = 0;
    board[24] = 6; // Kd1
    board[63] = 2; // Nc5
    pre.prepare(&board);
    const files = pre.files();
    try std.testing.expect(files.lookup(.program_tb, "KQKR.TBW").?.ptr == pre.held(indexOf("KQKR.TBW").?).?.ptr);
    try std.testing.expect(files.lookup(.program_tb, "kbnk.tbb") != null);
    try std.testing.expectEqual(@as(u32, cd_names.len), pre.loads);
    try std.testing.expectEqual(@as(u32, 0), pre.loads_at_probe);
    // The shipped set has no further file: nothing to do.
    var shipped = TbStore.init(gpa, .shipped);
    defer shipped.deinit();
    shipped.preloadAll(io);
    try std.testing.expectEqual(@as(u32, 0), shipped.loads);
    try std.testing.expectEqual(@as(u32, 0), shipped.preload_threads);
    std.debug.print("tb_store: preloadAll: {d} files on {d} threads in {d} ms, every one equal to the lazy path's\n", .{ cd_names.len - 8, threads, first_ms });
}

/// An allocator that counts the bytes it has live, for the release test (the preload's
/// threads allocate at once: the counts are atomic).
const CountingAllocator = struct {
    child: std.mem.Allocator,
    live: usize = 0,
    allocs: usize = 0,

    fn allocator(c: *CountingAllocator) std.mem.Allocator {
        return .{ .ptr = c, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }

    fn alloc(ctx: *anyopaque, len: usize, a: std.mem.Alignment, ra: usize) ?[*]u8 {
        const c: *CountingAllocator = @ptrCast(@alignCast(ctx));
        const p = c.child.rawAlloc(len, a, ra) orelse return null;
        _ = @atomicRmw(usize, &c.live, .Add, len, .monotonic);
        _ = @atomicRmw(usize, &c.allocs, .Add, 1, .monotonic);
        return p;
    }

    fn resize(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, n: usize, ra: usize) bool {
        const c: *CountingAllocator = @ptrCast(@alignCast(ctx));
        if (!c.child.rawResize(m, a, n, ra)) return false;
        _ = @atomicRmw(usize, &c.live, .Add, n, .monotonic);
        _ = @atomicRmw(usize, &c.live, .Sub, m.len, .monotonic);
        return true;
    }

    fn remap(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, n: usize, ra: usize) ?[*]u8 {
        const c: *CountingAllocator = @ptrCast(@alignCast(ctx));
        const p = c.child.rawRemap(m, a, n, ra) orelse return null;
        _ = @atomicRmw(usize, &c.live, .Add, n, .monotonic);
        _ = @atomicRmw(usize, &c.live, .Sub, m.len, .monotonic);
        return p;
    }

    fn free(ctx: *anyopaque, m: []u8, a: std.mem.Alignment, ra: usize) void {
        const c: *CountingAllocator = @ptrCast(@alignCast(ctx));
        c.child.rawFree(m, a, ra);
        _ = @atomicRmw(usize, &c.live, .Sub, m.len, .monotonic);
    }
};

test "tb_store: Use Tablebases false (decision 44) frees every unpacked file and the window; nothing comes back while it is false (prepare, the probe, a second uci); true again unpacks every file, byte-equal to the first; twice, with nothing left over" {
    const io = std.testing.io;
    var counting: CountingAllocator = .{ .child = std.testing.allocator };
    const gpa = counting.allocator();
    var all: usize = 0;
    for (cd_names) |n| all += fileSize(n);
    var store = TbStore.init(gpa, .cd);
    defer store.deinit();
    // A file unpacked by the lazy path first, so that the engine thread's window is held too.
    try std.testing.expect(store.load(indexOf("KQKR.TBW").?));
    try std.testing.expect(store.window != null);
    store.preloadAll(io);
    try std.testing.expect(store.allHeld());
    try std.testing.expectEqual(all + window_len, counting.live);
    var first: [cd_names.len][32]u8 = undefined;
    for (&first, 0..) |*h, i| std.crypto.hash.sha2.Sha256.hash(store.held(i).?, h, .{});
    // An unchanged option does nothing (the shell's first applyOptions, before `uci`).
    store.setUse(true, io);
    try std.testing.expectEqual(all + window_len, counting.live);
    var board = emptyBoard();
    board[25] = 6; // Ke1
    board[91] = 4; // Ra8
    board[95] = 13; // ke8
    board[34] = 8; // pd2
    for (0..2) |round| {
        store.setUse(false, io);
        try std.testing.expectEqual(@as(usize, 0), counting.live);
        try std.testing.expectEqual(@as(u32, @intCast(round + 1)), store.releases);
        for (0..cd_names.len) |i| try std.testing.expect(store.held(i) == null);
        try std.testing.expect(store.window == null);
        // While released: `prepare` (the `position` command), the probe's lookup, `load` and
        // `preloadAll` (a second `uci`) decompress nothing; the installed six still answer.
        const loads = store.loads;
        const allocs = counting.allocs;
        store.prepare(&board);
        const files = store.files();
        try std.testing.expect(files.lookup(.program_tb, "KRKP.TBW") == null);
        try std.testing.expect(files.lookup(.program_tb, "KQKR.TBB") == null);
        try std.testing.expect(!store.load(indexOf("KBNK.TBW").?));
        store.preloadAll(io);
        try std.testing.expect(files.lookup(.program_tb, "KRK.TBW").?.ptr == engine_data.tb_data[4].ptr);
        try std.testing.expectEqual(loads, store.loads);
        try std.testing.expectEqual(@as(u32, 0), store.loads_at_probe);
        try std.testing.expectEqual(allocs, counting.allocs);
        try std.testing.expectEqual(@as(usize, 0), counting.live);
        // A second release does nothing.
        store.setUse(false, io);
        try std.testing.expectEqual(@as(u32, @intCast(round + 1)), store.releases);
        // True again: every file held at once, the same bytes; the preload's windows freed.
        store.setUse(true, io);
        try std.testing.expect(store.allHeld());
        try std.testing.expectEqual(all, counting.live);
        try std.testing.expectEqual(@as(u32, cd_names.len), store.preload_loads);
        for (first, 0..) |want, i| {
            var h: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(store.held(i).?, &h, .{});
            try std.testing.expectEqualSlices(u8, &want, &h);
        }
        // Then `prepare` finds its files held.
        const before = store.loads;
        store.prepare(&board);
        try std.testing.expectEqual(before, store.loads);
        std.debug.print("tb_store: Use Tablebases off and on, round {d}: {d} bytes freed, then {d} files unpacked again in {d} ms on {d} threads, each equal to the first\n", .{ round + 1, all, store.preload_loads, store.preload_ns / std.time.ns_per_ms, store.preload_threads });
    }
    // Released by deinit: std.testing.allocator then reports any leak.
}

test "tb_store: the file name is the probe's: the side with more men, or the higher piece, first" {
    var buf: [12]u8 = undefined;
    var c: [2][7]u8 = @splat(@splat(0));
    c[0][6] = 1;
    c[1][6] = 1;
    c[1][4] = 1; // Black rook
    c[0][1] = 1; // White pawn
    try std.testing.expectEqualStrings("KRKP.TBW", fileName(c, 1, &buf).?);
    try std.testing.expectEqualStrings("KRKP.TBB", fileName(c, 0, &buf).?);
    c[0][1] = 0;
    c[0][3] = 1;
    c[0][2] = 1; // White B + N: KBNK
    try std.testing.expectEqualStrings("KBNKR.TBW", fileName(c, 0, &buf).?);
    c[1][4] = 0;
    try std.testing.expectEqualStrings("KBNK.TBB", fileName(c, 1, &buf).?);
    c[0] = .{ 0, 0, 0, 0, 0, 0, 1 };
    try std.testing.expect(fileName(c, 0, &buf) == null); // the bare kings
}
