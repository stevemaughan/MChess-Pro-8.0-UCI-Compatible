//! Stage A, step 7 (docs/arch/60-engine-assembly.md section 5): the machine-lifted
//! threat evaluators (src/threats.zig, 0EF8:A026 for the White node, 0EF8:CD20 for the
//! Black node) as the search node calls them (`Ctx.threats(side, ply, count, counter)`,
//! src/searchnode.zig), on the shared DGROUP image.
//!
//! The routines take three words on the 8086 stack (docs/arch/54-evaluation-threats.md,
//! "Arguments"): `[bp+6]` the ply, `[bp+8]` the count of enemy pieces attacked by cheaper
//! ones (1E9D:CE3E / CC4E), `[bp+0Ah]` a near pointer to a byte in the caller's frame
//! (`[bp-24h]` of the node), which they set to 1 and increment per serious threat. The
//! wrapper builds that frame in the image's stack area, places the byte there, pushes the
//! arguments and a far return address, runs the routine, and copies the byte back. The
//! routines read and write DGROUP directly (the board while they lift pieces, DG:8EB6,
//! the exchange work areas), so on the shared image every read is the original's and
//! every write lands where the original's does; nothing is synchronised.

const builtin = @import("builtin");

// Test-only since Stage B step 8, stage 8: the engine runs on its members (src/engine_state.zig)
// and its build never reaches this file; this block fails the build if it does.
comptime {
    if (!builtin.is_test) @compileError("src/adapt_threats.zig is a Stage A adapter, test-only since Stage B step 8, stage 8: the engine build must not reach it");
}

const std = @import("std");
const pos = @import("position.zig");
const lifted = @import("lifted_machine.zig");
const threats_mod = @import("threats.zig");
const dgroup = @import("dgroup.zig");
const ase = @import("adapt_staticeval.zig");

const Image = dgroup.Image;

/// The caller's frame pointer in the image: below the stack top the attacker routines
/// use when called alone (`adapt_staticeval.stack_top`), with room for the node's locals.
pub const frame_bp: u16 = ase.stack_top - 0x10;
/// The counter byte, `[bp-24h]` of the node.
pub const counter_addr: u16 = frame_bp - 0x24;
/// SP at the call: below the node's locals.
pub const call_sp: u16 = frame_bp - 0x40;

/// eval_threats_white (0EF8:A026, `side` white: the White node) or eval_threats_black
/// (0EF8:CD20) on the image. `counter` is the node's frame byte; returns AX.
pub fn threats(img: *Image, side: pos.Side, ply: i16, count: u16, counter: *u8) i16 {
    img[counter_addr] = counter.*;
    var m: lifted.Machine = .{ .mem = img, .sp = call_sp, .bp = frame_bp };
    m.push(counter_addr);
    m.push(count);
    m.push(@bitCast(ply));
    m.push(0x0000); // the node's segment; never read
    m.push(0x0000);
    switch (side) {
        .white => threats_mod.runA026(&m, threats_mod.entry_a026),
        .black => threats_mod.runCD20(&m, threats_mod.entry_cd20),
    }
    counter.* = img[counter_addr];
    return @bitCast(m.ax);
}
