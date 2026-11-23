//! Stage A, step 6 (docs/arch/60-engine-assembly.md section 5): static_eval
//! (src/staticeval.zig) on the DGROUP image, with `staticeval.Callees` bound to the real
//! routines:
//!
//! | Callee        | Original   | Bound to                                              |
//! | ------------- | ---------- | ----------------------------------------------------- |
//! | `see_white`   | 2B9F:C32A  | src/see.zig `see(.white)` through adapt_movegen.see   |
//! | `see_black`   | 2B9F:CAC2  | src/see.zig `see(.black)`                             |
//! | `r4793_41B6`  | 4793:41B6  | the lifted src/attackers.zig, run on the image itself; with DEV-023 corrected, src/pinexchange.zig `exchangeFixes` |
//! | `r4793_4CEC`  | 4793:4CEC  | the same, Black                                       |
//! | `r2B9F_4A76`  | 2B9F:4A76  | src/helpers.zig `attacksSquare(.white)`               |
//! | `r2B9F_4AD4`  | 2B9F:4AD4  | src/helpers.zig `attacksSquare(.black)`               |
//!
//! static_eval runs on its own `Position` and `EvalVars`, loaded from the image. Around
//! each callee the binding writes their changes back to the image (the caller has
//! emptied the pawn's square on the board, which the callee must see, as in the
//! original), runs the callee on the image, and reloads them, so the callee's effects
//! are seen by static_eval. The lifted attacker routines run on the shared image
//! directly, with their stack at `stack_top`: every byte they read beyond the board and
//! the ray maps is the original's.
//!
//! `Check` is the test mode: each real callee's result is compared with the one the
//! original returned at that call, in order (src/adapt_staticeval_test.zig).

const builtin = @import("builtin");

// Test-only since Stage B step 8, stage 8: the engine runs on its members (src/engine_state.zig)
// and its build never reaches this file; this block fails the build if it does.
comptime {
    if (!builtin.is_test) @compileError("src/adapt_staticeval.zig is a Stage A adapter, test-only since Stage B step 8, stage 8: the engine build must not reach it");
}

const std = @import("std");
const pos = @import("position.zig");
const se = @import("staticeval.zig");
const PawnHash = @import("pawnhash.zig").PawnHash;
const lifted = @import("lifted_machine.zig");
const attackers = @import("attackers.zig");
const dgroup = @import("dgroup.zig");
const adapt_movegen = @import("adapt_movegen.zig");
const adapt_eval = @import("adapt_eval.zig");
const see_mod = @import("see.zig");
const pinexchange = @import("pinexchange.zig");

const Image = dgroup.Image;
const PositionMap = adapt_eval.PositionMap;
const ScratchMap = adapt_movegen.ScratchMap;
const EvalVarsMap = adapt_eval.EvalVarsMap;

/// The top of the stack the lifted routines run on in the shared image: above every
/// variable of DGROUP (the highest declared is below DG:B700), where the original's
/// stack is.
pub const stack_top: u16 = 0xFFF0;

/// A callee's identity, for the test mode: the call sites of 2B9F the original's calls
/// were recorded at.
pub const Callee = enum { see_white, see_black, att_4cec, att_41b6, att_4a76, att_4ad4 };

pub fn sitesOf(c: Callee) []const u16 {
    return switch (c) {
        .see_white => &.{0x0C90},
        .see_black => &.{0x330C},
        .att_4cec => &.{ 0x105F, 0x1BAA },
        .att_41b6 => &.{ 0x281E, 0x36E5 },
        .att_4a76 => &.{0x19B1},
        .att_4ad4 => &.{0x262B},
    };
}

/// The test mode's interface: called after every real callee with its arguments and
/// result; returns the value static_eval is given (the real one, unless the checker
/// substitutes the recorded one after recording a disagreement).
pub const Check = struct {
    ctx: *anyopaque,
    after: *const fn (ctx: *anyopaque, callee: Callee, a0: u16, a1: ?u16, real: u16) u16,
};

/// static_eval's state during the call, and what the callees need, with the original's
/// callees.
pub const Binding = BindingOf(pos.Fixes.original);

/// The binding under the class C fixes `pfixes`. Only DEV-023 (`dev023_pinned_bishop`)
/// touches a callee here: with it on, 4793:41B6 / 4CEC are the hand-written
/// `pinexchange.exchangeFixes` on the image's position and work areas, corrected; with it
/// off they stay the lifted routines on the image, exactly as before.
pub fn BindingOf(comptime pfixes: pos.Fixes) type {
    return struct {
        const Self = @This();
        img: *Image,
        b: *adapt_eval.Buf,
        check: ?Check = null,

        fn self(ctx: *anyopaque) *Self {
            return @ptrCast(@alignCast(ctx));
        }
        /// Put static_eval's changes into the image before a callee.
        fn flush(g: *Self) void {
            _ = PositionMap.storeChanged(&g.b.p, g.img, &g.b.pb);
            _ = EvalVarsMap.storeChanged(&g.b.v, g.img, &g.b.vb);
        }
        /// Take the callee's changes back into static_eval's structs.
        fn reload(g: *Self) void {
            PositionMap.loadSnap(&g.b.p, g.img, &g.b.pb);
            EvalVarsMap.loadSnap(&g.b.v, g.img, &g.b.vb);
        }
        fn finish(g: *Self, callee: Callee, a0: u16, a1: ?u16, real: u16) u16 {
            g.reload();
            return if (g.check) |c| c.after(c.ctx, callee, a0, a1, real) else real;
        }

        fn seeWhite(ctx: *anyopaque, sq: u16, v: u16) u16 {
            const g = self(ctx);
            g.flush();
            return g.finish(.see_white, sq, v, adapt_movegen.see(g.img, .white, @truncate(sq), v));
        }
        fn seeBlack(ctx: *anyopaque, sq: u16, v: u16) u16 {
            const g = self(ctx);
            g.flush();
            return g.finish(.see_black, sq, v, adapt_movegen.see(g.img, .black, @truncate(sq), v));
        }
        fn att4CEC(ctx: *anyopaque, sq: u16, v: u16) u16 {
            const g = self(ctx);
            g.flush();
            return g.finish(.att_4cec, sq, v, exchangeCallee(g.img, .black, sq, v));
        }
        fn att41B6(ctx: *anyopaque, sq: u16, v: u16) u16 {
            const g = self(ctx);
            g.flush();
            return g.finish(.att_41b6, sq, v, exchangeCallee(g.img, .white, sq, v));
        }
        fn att4A76(ctx: *anyopaque, sq: u16) u16 {
            const g = self(ctx);
            g.flush();
            return g.finish(.att_4a76, sq, null, adapt_movegen.attacksSquare(g.img, .white, sq));
        }
        fn att4AD4(ctx: *anyopaque, sq: u16) u16 {
            const g = self(ctx);
            g.flush();
            return g.finish(.att_4ad4, sq, null, adapt_movegen.attacksSquare(g.img, .black, sq));
        }

        fn exchangeCallee(img: *Image, side: pos.Side, sq: u16, v: u16) u16 {
            if (!pfixes.dev023_pinned_bishop) return attackersOnImage(img, side, sq, v);
            return exchangeOnImage(pfixes, img, side, sq, v);
        }

        pub fn callees(g: *Self) se.Callees {
            return .{ .see_white = seeWhite, .see_black = seeBlack, .r4793_4CEC = att4CEC, .r4793_41B6 = att41B6, .r2B9F_4A76 = att4A76, .r2B9F_4AD4 = att4AD4, .ctx = g };
        }
    };
}

/// 4793:41B6 / 4CEC as the hand-written src/pinexchange.zig under `fixes`, on the image's
/// position and exchange work areas (DG:9FEC, A060, 70E5, B4E6), whose changed bytes are
/// written back, as the search node's threat evaluators call it (src/adapt_node.zig).
pub fn exchangeOnImage(comptime fixes: pos.Fixes, img: *Image, side: pos.Side, sq: u16, v: u16) u16 {
    var p: pos.Position = .{};
    var s: see_mod.Scratch = .{};
    var sb: ScratchMap.Snapshot = undefined;
    PositionMap.load(&p, img);
    ScratchMap.loadSnap(&s, img, &sb);
    const ax = pinexchange.exchangeFixes(fixes, &p, &s, side, @truncate(sq), v);
    _ = ScratchMap.storeChanged(&s, img, &sb);
    return ax;
}

/// 4793:41B6 (`side` white) or 4793:4CEC (black), the lifted routines, on the shared
/// image, called as from 0EF8 with (square, value) on the stack. Returns AX.
pub fn attackersOnImage(img: *Image, side: pos.Side, sq: u16, v: u16) u16 {
    var m: lifted.Machine = .{ .mem = img, .sp = stack_top };
    m.push(v);
    m.push(sq);
    m.push(0x0EF8); // a far return address; never read
    m.push(0);
    switch (side) {
        .white => attackers.run41B6(&m, attackers.entry_41b6),
        .black => attackers.run4CEC(&m, attackers.entry_4cec),
    }
    return m.ax;
}

/// static_eval (2B9F:000E) on the image with the real callees. `side` 0 White, 1 Black;
/// `arg2` is ply - [9356]. `stray` is DEV-015's input (unused with `Fixes.corrected`).
pub fn staticEval(b: *adapt_eval.Buf, img: *Image, h: *PawnHash, side: u16, arg2: u16, comptime fixes: se.Fixes, stray: [2]se.StrayBytes, check: ?Check) i16 {
    return staticEvalFixes(pos.Fixes.original, b, img, h, side, arg2, fixes, stray, check);
}

/// `staticEval` under the class C fixes `pfixes` (DEV-023, in the attacker callees;
/// DEV-053, in static_eval's passed-pawn prefilters, passed on as
/// `se.Fixes.dev053_line_tables_other`).
pub fn staticEvalFixes(comptime pfixes: pos.Fixes, b: *adapt_eval.Buf, img: *Image, h: *PawnHash, side: u16, arg2: u16, comptime fixes: se.Fixes, stray: [2]se.StrayBytes, check: ?Check) i16 {
    var g: BindingOf(pfixes) = .{ .img = img, .b = b, .check = check };
    PositionMap.loadSnap(&b.p, img, &b.pb);
    EvalVarsMap.loadSnap(&b.v, img, &b.vb);
    const iface = g.callees();
    const sfixes = comptime blk: {
        var f = fixes;
        f.dev053_line_tables_other = fixes.dev053_line_tables_other or pfixes.dev053_line_tables_other;
        f.dev054_unstoppable_passer_mirror = fixes.dev054_unstoppable_passer_mirror or pfixes.dev054_unstoppable_passer_mirror;
        f.dev055_passer_block_extra_test = fixes.dev055_passer_block_extra_test or pfixes.dev055_passer_block_extra_test;
        f.dev062_king_test_rank = fixes.dev062_king_test_rank or pfixes.dev062_king_test_rank;
        break :blk f;
    };
    const r = se.staticEval(&b.p, &b.v, h, &iface, side, arg2, sfixes, stray);
    g.flush();
    return r;
}
