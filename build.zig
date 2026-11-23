const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const options = b.addOptions();
    // Relative to the build root; test runs use the build root as their cwd.
    options.addOption([]const u8, "golden_dir", "tests/golden");
    // -Dbench=true runs the timing benchmarks (tests named "bench: ...", src/bench.zig).
    const bench = b.option(bool, "bench", "Run the timing benchmarks in the test files") orelse false;
    options.addOption(bool, "bench", bench);
    // -Dtest-filter=text runs only the tests whose name contains the text.
    const test_filter = b.option([]const u8, "test-filter", "Run only tests whose name contains this text");
    // -Dfixes=false builds the engine with every class C fix off (pos.Fixes.original, the
    // original's logic) as mchess-original, to be played against the shipped engine. It is a
    // build of its own, not a UCI option (owner decision 25).
    const fixes = b.option(bool, "fixes", "Build with the class C fixes on (default) or off, as mchess-original") orelse true;
    options.addOption(bool, "fixes", fixes);

    // The engine library.
    const mod = b.addModule("mchess", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    mod.addOptions("build_options", options);
    addOriginalData(b, mod);

    const exe = b.addExecutable(.{
        .name = if (fixes) "mchess" else "mchess-original",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "mchess", .module = mod }},
        }),
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    run_cmd.addPassthruArgs();
    b.step("run", "Run the engine").dependOn(&run_cmd.step);

    // `zig build release` (owner decision 40): the builds that are shipped, each ReleaseFast,
    // stripped, with the class C fixes on, in zig-out/release/. Only the Windows 64-bit
    // build is run through the test suite; the others are cross-compiled and, but for the
    // Windows 32-bit one, have never been run (README.md, "Builds").
    const release_step = b.step("release", "Build every shipped executable into zig-out/release/");
    const release_options = b.addOptions();
    release_options.addOption([]const u8, "golden_dir", "tests/golden");
    release_options.addOption(bool, "bench", false);
    release_options.addOption(bool, "fixes", true);
    for (release_targets) |rt| {
        const query = std.Target.Query.parse(.{ .arch_os_abi = rt.triple }) catch @panic("bad release target");
        const resolved = b.resolveTargetQuery(query);
        const rmod = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = resolved,
            .optimize = .ReleaseFast,
            .strip = true,
        });
        rmod.addOptions("build_options", release_options);
        addOriginalData(b, rmod);
        const rexe = b.addExecutable(.{
            .name = rt.name,
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/main.zig"),
                .target = resolved,
                .optimize = .ReleaseFast,
                .strip = true,
                .imports = &.{.{ .name = "mchess", .module = rmod }},
            }),
        });
        const install = b.addInstallArtifact(rexe, .{ .dest_dir = .{ .override = .{ .custom = "release" } } });
        release_step.dependOn(&install.step);
    }
    // Unit tests and the differential tests against the recorded vectors
    // (tests/golden/position/*.zst, made by tools/port/gen_position_vectors.py).
    const t = b.addTest(.{
        .root_module = mod,
        .filters = if (test_filter) |f| &.{f} else &.{},
    });
    const run = b.addRunArtifact(t);
    run.setCwd(b.path("."));
    // The tests read tests/golden/ at run time, which the build cache cannot
    // see: never skip a run because the binary is cached.
    run.has_side_effects = true;
    b.step("test", "Run unit and golden-vector tests").dependOn(&run.step);

    // `zig build check-unverified` (AGENTS.md section 2, rule 7): every tag that marks ported
    // code not yet checked against the original, listed with its file and line; the step
    // fails while any remains (docs/UNVERIFIED.md is the inventory). The scanner is the small
    // program below, compiled for the host: the engine's build depends on nothing under tools/.
    const scan = b.addWriteFiles();
    const scanner = b.addExecutable(.{
        .name = "check-unverified",
        .root_module = b.createModule(.{
            .root_source_file = scan.add("check_unverified.zig", check_unverified_source),
            .target = b.graph.host,
            .optimize = .Debug,
        }),
    });
    const check = b.addRunArtifact(scanner);
    check.addDirectoryArg(b.path("src"));
    check.has_side_effects = true;
    b.step("check-unverified", "List the UNVERIFIED tags under src/; fail if there are any").dependOn(&check.step);
}

/// The shipped builds (owner decision 40). The Windows 64-bit build is the generic one:
/// the baseline x86-64, which runs on every 64-bit processor and measured within about 2%
/// of a build for the newest ones. The Linux and Android files are static. Linux for 64-bit
/// ARM (a Raspberry Pi, for instance) was added on 2026-11-22 (owner decision 44).
const ReleaseTarget = struct { name: []const u8, triple: []const u8 };
const release_targets = [_]ReleaseTarget{
    .{ .name = "mchess-windows-x64", .triple = "x86_64-windows" },
    .{ .name = "mchess-windows-x86", .triple = "x86-windows" },
    .{ .name = "mchess-windows-arm64", .triple = "aarch64-windows" },
    .{ .name = "mchess-macos-arm64", .triple = "aarch64-macos" },
    .{ .name = "mchess-linux-x64", .triple = "x86_64-linux-musl" },
    .{ .name = "mchess-linux-arm64", .triple = "aarch64-linux-musl" },
    .{ .name = "mchess-android-arm64", .triple = "aarch64-linux-android" },
};
/// The original's data, read by the engine at compile time from `reference/` (which is
/// in the project folder, not in git: AGENTS.md section 14, decision 39).
fn addOriginalData(b: *std.Build, mod: *std.Build.Module) void {
    // The decrypted original: constant tables are read from its initialised data at
    // compile time (src/original.zig), never retyped.
    mod.addAnonymousImport("mcp8_exe", .{
        .root_source_file = b.path("reference/extracted/MCP8-decrypted.exe"),
    });
    // The shipped tablebase and opening-book files, embedded in the engine
    // (src/engine_data.zig), so that the executable needs no reference folder at run time.
    for ([_][]const u8{ "KPK.TBW", "KPK.TBB", "KQK.TBW", "KQK.TBB", "KRK.TBW", "KRK.TBB" }) |name| {
        mod.addAnonymousImport(b.fmt("tb/{s}", .{name}), .{
            .root_source_file = b.path(b.fmt("reference/original/M80/TB/{s}", .{name})),
        });
    }
    // The 60 further files of the "cd" tablebase set (owner decision 33), zstd-compressed
    // (reference/extracted/tablebases/README.md); src/engine_data.zig decompresses a file
    // the first time the root could need it.
    for (@import("src/tb_names.zig").cd_stems) |stem| {
        for ([_][]const u8{ ".TBW", ".TBB" }) |ext| {
            mod.addAnonymousImport(b.fmt("tbz/{s}{s}", .{ stem, ext }), .{
                .root_source_file = b.path(b.fmt("reference/extracted/tablebases/{s}{s}.zst", .{ stem, ext })),
            });
        }
    }
    for (0..16) |i| {
        mod.addAnonymousImport(b.fmt("book/M80KEY.{X:0>3}", .{i}), .{
            .root_source_file = b.path(b.fmt("reference/original/M80/PRBOOK/M80KEY.{X:0>3}", .{i})),
        });
    }
    mod.addAnonymousImport("book/PRBOOK.M80", .{
        .root_source_file = b.path("reference/original/M80/PRBOOK/PRBOOK.M80"),
    });
}

/// The scanner of `check-unverified`: every line under the directory given that holds the
/// tag (`//` followed by a space and `UNVERIFIED:`, so `///` doc comments count too), in path
/// and line order; exit code 1 if there is one.
const check_unverified_source =
    \\const std = @import("std");
    \\
    \\const tag = "// " ++ "UNVERIFIED:";
    \\
    \\fn lessThan(_: void, a: []const u8, b: []const u8) bool {
    \\    return std.mem.lessThan(u8, a, b);
    \\}
    \\
    \\pub fn main(init: std.process.Init) !void {
    \\    const io = init.io;
    \\    const arena = init.arena.allocator();
    \\    const args = try init.minimal.args.toSlice(arena);
    \\    if (args.len != 2) {
    \\        std.debug.print("usage: check-unverified <src directory>\n", .{});
    \\        std.process.exit(2);
    \\    }
    \\    var dir = try std.Io.Dir.cwd().openDir(io, args[1], .{ .iterate = true });
    \\    defer dir.close(io);
    \\    var walker = try dir.walk(arena);
    \\    defer walker.deinit();
    \\    var files: std.ArrayList([]u8) = .empty;
    \\    while (try walker.next(io)) |e| {
    \\        if (e.kind != .file or !std.mem.endsWith(u8, e.basename, ".zig")) continue;
    \\        const p = try arena.dupe(u8, e.path);
    \\        std.mem.replaceScalar(u8, p, '\\', '/');
    \\        try files.append(arena, p);
    \\    }
    \\    std.mem.sort([]u8, files.items, {}, lessThan);
    \\    var count: usize = 0;
    \\    var tagged_files: usize = 0;
    \\    for (files.items) |rel| {
    \\        const text = try dir.readFileAlloc(io, rel, arena, .limited(64 << 20));
    \\        var line_no: usize = 0;
    \\        var here: usize = 0;
    \\        var lines = std.mem.splitScalar(u8, text, '\n');
    \\        while (lines.next()) |line| {
    \\            line_no += 1;
    \\            if (std.mem.indexOf(u8, line, tag) == null) continue;
    \\            here += 1;
    \\            std.debug.print("src/{s}:{d}: {s}\n", .{ rel, line_no, std.mem.trim(u8, line, " \t\r") });
    \\        }
    \\        count += here;
    \\        if (here != 0) tagged_files += 1;
    \\    }
    \\    if (count != 0) {
    \\        std.debug.print("check-unverified: {d} UNVERIFIED tags in {d} files under src/ (docs/UNVERIFIED.md); none may remain at release (AGENTS.md 2.7)\n", .{ count, tagged_files });
    \\        std.process.exit(1);
    \\    }
    \\    std.debug.print("check-unverified: no UNVERIFIED tags under src/\n", .{});
    \\}
    \\
;
