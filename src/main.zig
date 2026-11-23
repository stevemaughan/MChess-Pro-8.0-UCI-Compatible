const std = @import("std");
const mchess = @import("mchess");

/// `mchess` runs the UCI engine, the joined engine (src/engine.zig), on standard input
/// and output (docs/UCI.md).
///
/// The executable reaches only what `uci.runJoined` uses. The files that are the tests'
/// alone (src/state_image.zig, the tests' codec of the original's data segment; the Stage A
/// adapters src/adapt_position.zig, adapt_movegen.zig, adapt_eval.zig, adapt_staticeval.zig,
/// adapt_threats.zig, adapt_node.zig; the machine of the lifted units, src/lifted_machine.zig)
/// each fail this build at compile time if it reaches them (Stage B step 8, stage 8).
pub fn main(init: std.process.Init) !void {
    try mchess.uci.runJoined(init.gpa, init.io);
}
