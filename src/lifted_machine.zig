//! The machine that the machine-lifted routines run on: the 8086 registers and flags the
//! code uses, and DGROUP as a 64 KB image which also holds the stack (SS = DS = DGROUP in
//! the original). Used by src/attackers.zig (4793:41B6, 4793:4CEC) and src/threats.zig
//! (0EF8:A026, 0EF8:CD20), which tools/port/lift_zig.py transcribes from the listing
//! block by block, one statement per instruction. This is the executable form of the
//! proved model tools/research/evalthreats/model.py (`Machine`), in Zig.
//!
//! MACHINE-LIFTED CODE, AWAITING A READABLE REWRITE. The routines are proved by replay
//! (src/threats_test.zig) but are not yet written in terms of `Position`; they read and
//! write DGROUP addresses directly, and read every byte the original reads, including
//! stack words and table bytes past the end of a table (docs/arch/54-evaluation-threats.md
//! 7.1, 7.3), which is how they reproduce the original exactly.
//!
//! Far calls go through `far`: the exchange evaluators 2B9F:C32A / CAC2 to src/see.zig
//! (through a `Position` built from the image), the attacker routines 4793:41B6 / 4CEC to
//! src/attackers.zig on the same image.

const builtin = @import("builtin");

// Test-only since Stage B step 8, stage 8: the engine runs on its members (src/engine_state.zig)
// and its build never reaches this file; this block fails the build if it does.
comptime {
    if (!builtin.is_test) @compileError("src/lifted_machine.zig is the machine of the machine-lifted units (with src/threats.zig and src/attackers.zig, which run on it), test-only since Stage B step 8, stage 8: the engine build must not reach it");
}

const std = @import("std");
const pos = @import("position.zig");
const see = @import("see.zig");
const attackers = @import("attackers.zig");

/// The far routines the lifted code calls.
pub const Far = enum(u8) {
    /// 2B9F:C32A, see_capture_by_white.
    see_white = 0,
    /// 2B9F:CAC2, see_capture_by_black.
    see_black = 1,
    /// 4793:41B6, the White attacker routine.
    att_41b6 = 2,
    /// 4793:4CEC, the Black attacker routine.
    att_4cec = 3,
};

/// One far call as the caller made it: the call site, the two stack arguments, AX after.
pub const CallRecord = struct { target: Far, site: u16, sq: u16, v: u16, ax: u16 };

/// One checkpoint: a label passed, SI, DI, the nine frame words [bp-2]..[bp-12h] and the
/// byte at the flag pointer (as tools/research/evalthreats/check.py records them).
pub const Mark = struct { label: u16, si: u16, di: u16, frame: [9]u16, flag: u8 };

/// Optional recording of far calls and checkpoints, for the replay test. Fixed buffers:
/// no heap allocation.
pub const Trace = struct {
    calls: [512]CallRecord = undefined,
    ncalls: usize = 0,
    marks: [4096]Mark = undefined,
    nmarks: usize = 0,
    record_marks: bool = false,
    flagp: u16 = 0,
    /// Labels passed, over all calls (coverage), when given.
    hits: ?*std.StaticBitSet(0x10000) = null,
};

pub const Machine = struct {
    /// DGROUP, the stack included.
    mem: *[0x10000]u8,
    ax: u16 = 0,
    bx: u16 = 0,
    cx: u16 = 0,
    dx: u16 = 0,
    si: u16 = 0,
    di: u16 = 0,
    bp: u16 = 0,
    sp: u16 = 0,
    zf: bool = false,
    sf: bool = false,
    cf: bool = false,
    of: bool = false,
    trace: ?*Trace = null,

    // ---- memory -------------------------------------------------------------

    pub inline fn rb(m: *const Machine, a: u16) u8 {
        return m.mem[a];
    }
    pub inline fn rw(m: *const Machine, a: u16) u16 {
        return @as(u16, m.mem[a]) | @as(u16, m.mem[a +% 1]) << 8;
    }
    pub inline fn wb(m: *Machine, a: u16, v: u8) void {
        m.mem[a] = v;
    }
    pub inline fn ww(m: *Machine, a: u16, v: u16) void {
        m.mem[a] = @truncate(v);
        m.mem[a +% 1] = @truncate(v >> 8);
    }
    pub inline fn push(m: *Machine, v: u16) void {
        m.sp -%= 2;
        m.ww(m.sp, v);
    }
    pub inline fn pop(m: *Machine) u16 {
        const v = m.rw(m.sp);
        m.sp +%= 2;
        return v;
    }

    // ---- byte registers -----------------------------------------------------

    pub inline fn al(m: *const Machine) u8 {
        return @truncate(m.ax);
    }
    pub inline fn ah(m: *const Machine) u8 {
        return @truncate(m.ax >> 8);
    }
    pub inline fn bl(m: *const Machine) u8 {
        return @truncate(m.bx);
    }
    pub inline fn bh(m: *const Machine) u8 {
        return @truncate(m.bx >> 8);
    }
    pub inline fn cl(m: *const Machine) u8 {
        return @truncate(m.cx);
    }
    pub inline fn ch(m: *const Machine) u8 {
        return @truncate(m.cx >> 8);
    }
    pub inline fn dl(m: *const Machine) u8 {
        return @truncate(m.dx);
    }
    pub inline fn dh(m: *const Machine) u8 {
        return @truncate(m.dx >> 8);
    }
    pub inline fn setAl(m: *Machine, v: u8) void {
        m.ax = (m.ax & 0xFF00) | v;
    }
    pub inline fn setAh(m: *Machine, v: u8) void {
        m.ax = (m.ax & 0x00FF) | @as(u16, v) << 8;
    }
    pub inline fn setBl(m: *Machine, v: u8) void {
        m.bx = (m.bx & 0xFF00) | v;
    }
    pub inline fn setBh(m: *Machine, v: u8) void {
        m.bx = (m.bx & 0x00FF) | @as(u16, v) << 8;
    }
    pub inline fn setCl(m: *Machine, v: u8) void {
        m.cx = (m.cx & 0xFF00) | v;
    }
    pub inline fn setCh(m: *Machine, v: u8) void {
        m.cx = (m.cx & 0x00FF) | @as(u16, v) << 8;
    }
    pub inline fn setDl(m: *Machine, v: u8) void {
        m.dx = (m.dx & 0xFF00) | v;
    }
    pub inline fn setDh(m: *Machine, v: u8) void {
        m.dx = (m.dx & 0x00FF) | @as(u16, v) << 8;
    }

    // ---- arithmetic with the 8086 flags (ZF, SF, CF, OF; the code tests no other) ----

    inline fn szf(m: *Machine, comptime T: type, r: T) void {
        m.zf = r == 0;
        m.sf = (r >> (@bitSizeOf(T) - 1)) != 0;
    }
    inline fn subFlags(m: *Machine, comptime T: type, a: T, b: T, borrow: u1) T {
        const r1 = @subWithOverflow(a, b);
        const r2 = @subWithOverflow(r1[0], borrow);
        const r = r2[0];
        m.cf = (r1[1] | r2[1]) != 0;
        m.of = (((a ^ b) & (a ^ r)) >> (@bitSizeOf(T) - 1)) != 0;
        m.szf(T, r);
        return r;
    }
    inline fn addFlags(m: *Machine, comptime T: type, a: T, b: T) T {
        const r1 = @addWithOverflow(a, b);
        const r = r1[0];
        m.cf = r1[1] != 0;
        m.of = ((~(a ^ b) & (a ^ r)) >> (@bitSizeOf(T) - 1)) != 0;
        m.szf(T, r);
        return r;
    }
    inline fn logic(m: *Machine, comptime T: type, r: T) T {
        m.cf = false;
        m.of = false;
        m.szf(T, r);
        return r;
    }
    pub inline fn add(m: *Machine, comptime T: type, a: T, b: T) T {
        return m.addFlags(T, a, b);
    }
    pub inline fn sub(m: *Machine, comptime T: type, a: T, b: T) T {
        return m.subFlags(T, a, b, 0);
    }
    pub inline fn sbb(m: *Machine, comptime T: type, a: T, b: T) T {
        return m.subFlags(T, a, b, @intFromBool(m.cf));
    }
    pub inline fn cmp(m: *Machine, comptime T: type, a: T, b: T) void {
        _ = m.subFlags(T, a, b, 0);
    }
    pub inline fn @"and"(m: *Machine, comptime T: type, a: T, b: T) T {
        return m.logic(T, a & b);
    }
    pub inline fn @"or"(m: *Machine, comptime T: type, a: T, b: T) T {
        return m.logic(T, a | b);
    }
    pub inline fn xor(m: *Machine, comptime T: type, a: T, b: T) T {
        return m.logic(T, a ^ b);
    }
    pub inline fn @"test"(m: *Machine, comptime T: type, a: T, b: T) void {
        _ = m.logic(T, a & b);
    }
    pub inline fn inc(m: *Machine, comptime T: type, a: T) T {
        const cf = m.cf;
        const r = m.addFlags(T, a, 1);
        m.cf = cf;
        return r;
    }
    pub inline fn dec(m: *Machine, comptime T: type, a: T) T {
        const cf = m.cf;
        const r = m.subFlags(T, a, 1, 0);
        m.cf = cf;
        return r;
    }
    pub inline fn neg(m: *Machine, comptime T: type, a: T) T {
        const r = m.subFlags(T, 0, a, 0);
        m.cf = a != 0;
        return r;
    }
    pub inline fn shl(m: *Machine, comptime T: type, a: T, n: u8) T {
        var r = a;
        var k: u8 = n & 0x1F;
        while (k > 0) : (k -= 1) {
            m.cf = (r >> (@bitSizeOf(T) - 1)) != 0;
            r = r << 1;
        }
        m.of = ((r >> (@bitSizeOf(T) - 1)) != 0) != m.cf;
        m.szf(T, r);
        return r;
    }
    /// The conditional jumps, by the 8086 mnemonic without its `j`.
    pub const Cond = enum { e, ne, l, ge, le, g, b, ae, be, a, s, ns };

    /// The jump condition after `cmp a, b` or `sub a, b`, from the operands: the same
    /// answer as the flags give (signed conditions from SF != OF, unsigned from CF).
    pub inline fn subCond(comptime T: type, a: T, b: T, comptime c: Cond) bool {
        const S = if (T == u8) i8 else i16;
        const sa: S = @bitCast(a);
        const sb: S = @bitCast(b);
        return switch (c) {
            .e => a == b,
            .ne => a != b,
            .l => sa < sb,
            .ge => sa >= sb,
            .le => sa <= sb,
            .g => sa > sb,
            .b => a < b,
            .ae => a >= b,
            .be => a <= b,
            .a => a > b,
            .s => @as(S, @bitCast(a -% b)) < 0,
            .ns => @as(S, @bitCast(a -% b)) >= 0,
        };
    }

    /// The jump condition after a logical instruction (`test`, `and`, `or`, `xor`) whose
    /// result is `r`: CF and OF are clear, so the signed conditions test the sign of `r`
    /// and the unsigned ones its zero.
    pub inline fn logicCond(comptime T: type, r: T, comptime c: Cond) bool {
        const S = if (T == u8) i8 else i16;
        const s: S = @bitCast(r);
        return switch (c) {
            .e, .be => r == 0,
            .ne, .a => r != 0,
            .l, .s => s < 0,
            .ge, .ns => s >= 0,
            .le => s <= 0,
            .g => s > 0,
            .b => false,
            .ae => true,
        };
    }

    pub inline fn cbw(m: *Machine) void {
        m.ax = @bitCast(@as(i16, @as(i8, @bitCast(m.al()))));
    }

    // ---- checkpoints and far calls ------------------------------------------

    /// Called by the lifted threat routines at every label (not the entry). Without a
    /// trace it is one test of a register; the recording is out of line.
    pub inline fn mark(m: *Machine, label: u16) void {
        if (m.trace) |t| markSlow(t, m.mem, label, m.si, m.di, m.bp);
    }

    /// `lcall target` at `site`: the two arguments are on the stack ([sp] the square,
    /// [sp+2] the value); the callee is Pascal and pops them. AX is the result. BX, CX
    /// and DX are not preserved by the C convention; the attacker routines do preserve
    /// them, and the exchange evaluators' values are never used (spec 3.1).
    pub inline fn far(m: *Machine, target: Far, site: u16) void {
        const r = farCall(m.*, target, site);
        m.ax = r.ax;
        m.bx = r.bx;
        m.cx = r.cx;
        m.dx = r.dx;
        m.sp +%= 4;
    }
};

noinline fn markSlow(t: *Trace, mem: *[0x10000]u8, label: u16, si: u16, di: u16, bp: u16) void {
    if (t.hits) |h| h.set(label);
    if (t.record_marks) {
        var k: Mark = .{ .label = label, .si = si, .di = di, .frame = undefined, .flag = mem[t.flagp] };
        for (0..9) |i| {
            const a = bp -% @as(u16, @intCast(2 * (i + 1)));
            k.frame[i] = @as(u16, mem[a]) | @as(u16, mem[a +% 1]) << 8;
        }
        if (t.nmarks < t.marks.len) t.marks[t.nmarks] = k;
        t.nmarks += 1;
    }
}

const FarResult = struct { ax: u16, bx: u16, cx: u16, dx: u16 };

/// The far call of `Machine.far`, on a copy of the caller's machine: BX, CX and DX come
/// back unchanged from the exchange evaluators (their values are never used) and as the
/// attacker routines leave them.
fn farCall(c0: Machine, target: Far, site: u16) FarResult {
    const sq = c0.rw(c0.sp);
    const v = c0.rw(c0.sp +% 2);
    var r: FarResult = .{ .ax = c0.ax, .bx = c0.bx, .cx = c0.cx, .dx = c0.dx };
    switch (target) {
        .see_white => r.ax = seeOnImage(c0.mem, .white, sq, v),
        .see_black => r.ax = seeOnImage(c0.mem, .black, sq, v),
        .att_41b6, .att_4cec => {
            // the far return address: CS (relative 0EF8), then IP after the 5-byte lcall
            var c = c0;
            c.trace = null;
            c.push(0x0EF8);
            c.push(site +% 5);
            if (target == .att_41b6) attackers.run41B6(&c, attackers.entry_41b6) else attackers.run4CEC(&c, attackers.entry_4cec);
            r = .{ .ax = c.ax, .bx = c.bx, .cx = c.cx, .dx = c.dx };
        },
    }
    if (c0.trace) |t| {
        if (t.ncalls < t.calls.len) t.calls[t.ncalls] = .{ .target = target, .site = site, .sq = sq, .v = v, .ax = r.ax };
        t.ncalls += 1;
    }
    return r;
}

/// The exchange evaluator of src/see.zig on a DGROUP image: the state it reads is taken
/// from the image (board DG:9EF6, piece lists DG:A03A, pawn attacks DG:A51C / DG:37DA,
/// king rays DG:A09E / DG:A164), and its work areas (DG:9FEC, DG:A060, DG:70E5, DG:B4E6)
/// are read from and written back to it.
pub fn seeOnImage(mem: *[0x10000]u8, side: pos.Side, sq: u16, v: u16) u16 {
    var p: pos.Position = .{};
    @memcpy(&p.board, mem[0x9EF6..][0..120]);
    @memcpy(&p.piece_list, mem[0xA03A..][0..32]);
    @memcpy(&p.pawn_attacks[0], mem[0xA51C..][0..120]);
    @memcpy(&p.pawn_attacks[1], mem[0x37DA..][0..120]);
    @memcpy(&p.king_rays[0], mem[0xA09E..][0..120]);
    @memcpy(&p.king_rays[1], mem[0xA164..][0..120]);
    var s: see.Scratch = .{};
    @memcpy(&s.attackers, mem[0x9FEC..][0..116]);
    @memcpy(&s.defenders, mem[0xA060..][0..32]);
    @memcpy(&s.gain, mem[0x70E5..][0..11]);
    @memcpy(&s.net, mem[0xB4E6..][0..11]);
    const r = see.see(&p, &s, side, @truncate(sq), v);
    @memcpy(mem[0x9FEC..][0..116], &s.attackers);
    @memcpy(mem[0xA060..][0..32], &s.defenders);
    @memcpy(mem[0x70E5..][0..11], &s.gain);
    @memcpy(mem[0xB4E6..][0..11], &s.net);
    return r;
}

// ---------------------------------------------------------------------------
// The attacker routines called with a `Position` (for static_eval and the
// search), until they are rewritten: an image of DGROUP holding what they read.
// ---------------------------------------------------------------------------

/// The constant tables the attacker routines read (DG:0470, 047E, 0490, 04A6, the
/// knight and king step tables DG:0A68 and DG:0CFF at any offset 0..255 either side,
/// the exchange values DG:1A71), from the executable: DG:0000-1AFF.
const attacker_constants_len = 0x1B00;
const attacker_constants = @import("original.zig").dgroup(0, attacker_constants_len);

/// Top of the stack the routines run on in an `AttackerImage`: above every DGROUP
/// address they read (the highest is the net-value list at DG:B4E6).
const image_stack_top: u16 = 0xFFF0;

/// A DGROUP image for `attackersOnPosition`. Make it once with `init`; each call copies
/// in the state the routine reads and copies back its work areas. 64 KB: keep one per
/// thread, not on the stack of the search.
pub const AttackerImage = struct {
    mem: [0x10000]u8,

    pub fn init(img: *AttackerImage) void {
        @memset(&img.mem, 0);
        @memcpy(img.mem[0..attacker_constants_len], &attacker_constants);
    }
};

/// 4793:41B6 (`side` white: White's pawns at sq-9, sq-11, as see_capture_by_white) or
/// 4793:4CEC (black), on `p`, with the exchange work areas in `s` (the same areas as
/// src/see.zig's). Returns the original's AX. Proved on every recorded call by
/// src/threats_test.zig ("attacker routines called with a Position").
pub fn attackersOnPosition(img: *AttackerImage, p: *const pos.Position, s: *see.Scratch, side: pos.Side, sq: u8, v: u16) u16 {
    const mem = &img.mem;
    @memcpy(mem[0x9EF6..][0..120], &p.board);
    @memcpy(mem[0xA03A..][0..32], &p.piece_list);
    @memcpy(mem[0xA51C..][0..120], &p.pawn_attacks[0]);
    @memcpy(mem[0x37DA..][0..120], &p.pawn_attacks[1]);
    @memcpy(mem[0xA09E..][0..120], &p.king_rays[0]);
    @memcpy(mem[0xA164..][0..120], &p.king_rays[1]);
    @memcpy(mem[0x9FEC..][0..116], &s.attackers);
    @memcpy(mem[0xA060..][0..32], &s.defenders);
    @memcpy(mem[0x70E5..][0..11], &s.gain);
    @memcpy(mem[0xB4E6..][0..11], &s.net);
    var m: Machine = .{ .mem = mem, .sp = image_stack_top };
    m.push(v);
    m.push(sq);
    m.push(0x0EF8); // a far return address; never read
    m.push(0);
    switch (side) {
        .white => attackers.run41B6(&m, attackers.entry_41b6),
        .black => attackers.run4CEC(&m, attackers.entry_4cec),
    }
    @memcpy(&s.attackers, mem[0x9FEC..][0..116]);
    @memcpy(&s.defenders, mem[0xA060..][0..32]);
    @memcpy(&s.gain, mem[0x70E5..][0..11]);
    @memcpy(&s.net, mem[0xB4E6..][0..11]);
    return m.ax;
}
