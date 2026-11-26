//! Entry point of the Windows 7 build (`zig build -Dwin7=true`; docs/UCI.md, "Windows 7
//! build"): the same UCI engine as src/main.zig runs, `uci.runJoined`, on the small I/O layer
//! of src/win7_io.zig, without `std.Io.Threaded`, which needs Windows 8.

const std = @import("std");
const mchess = @import("mchess");
const win7_io = mchess.win7_io;

comptime {
    if (!win7_io.enabled) @compileError("main_win7.zig is the entry point of -Dwin7=true builds only");
}

// std's panic handler, segfault handler and debug output all print through
// `std.Io.Threaded`. This build replaces the first, switches off the second and makes any use
// of the third a compile error, because win7_io's `Io` cannot lock standard error. So this
// build is ReleaseFast or ReleaseSafe: a Debug build reaches std's debug output.
pub const panic = std.debug.FullPanic(win7_io.panic);
pub const std_options: std.Options = .{ .enable_segfault_handler = false };
const no_debug_io = "the Windows 7 build cannot use std's debug output: build it ReleaseFast or ReleaseSafe";
pub const std_options_debug_io: std.Io = @compileError(no_debug_io);
pub const std_options_debug_threaded_io: ?*std.Io.Threaded = @compileError(no_debug_io);

pub fn main(_: std.process.Init.Minimal) u8 {
    // The allocator the standard build's `init.gpa` is in a ReleaseFast build.
    mchess.uci.runJoined(std.heap.smp_allocator, win7_io.io) catch |err| {
        win7_io.stderrWrite("error: ");
        win7_io.stderrWrite(@errorName(err));
        win7_io.stderrWrite("\n");
        return 1;
    };
    return 0;
}
