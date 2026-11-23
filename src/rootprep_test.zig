//! Replay test of src/rootprep.zig against invocations recorded from the running original
//! (tests/golden/rootprep/*.zst, made by tools/port/gen_rootprep_vectors.py, whose
//! docstring defines the format).
//!
//! Each recorded invocation of main before the iteration loop gives the DGROUP image at its
//! entry, every direct call it made in order (site, target, stack words, the image just
//! before and just after the call, AX and DX), every value read and written outside DGROUP
//! (segment, offset, value), and the final image. The port runs on the entry state. At
//! every call it makes through the interface the test checks the site, the callee and the
//! arguments against the next recorded call, compares every field of the port's state with
//! the image the original had just before that call, and then takes the callee's effects
//! from the recording (the state is reloaded from the image after the call). The calls the
//! port does itself (memcpy, the long division, 0000:6BE4, 0000:6BF8, 1E9D:54CE) are
//! skipped in the recording; their effects are checked at the next comparison. Every
//! far access is checked for its site, segment (the DGROUP word the port names), offset
//! and, for a write, value. **Every byte the original wrote outside its stack must be a
//! byte of `PrepState`**: the test fails otherwise, so a write the port does not hold
//! cannot go unseen. At the exit the exit address and the final image are compared.
//!
//! The recorded calls of the repetition count (2B9F:402A) are replayed through
//! `repetitionCount` on their recorded inputs.

const std = @import("std");
const rp = @import("rootprep.zig");
const pos = @import("position.zig");
const PrepState = rp.PrepState;
const Callee = rp.Callee;

/// The fields of PrepState and their DGROUP addresses.
const layout = [_]struct { []const u8, u16 }{
    .{ "ply_ceiling", 0x0062 },        .{ "margin_154", 0x0154 },
    .{ "margin_168", 0x0168 },         .{ "threat_count_bonus_rest", 0x03FA },
    .{ "margin_172", 0x0172 },         .{ "margin_186", 0x0186 },
    .{ "threat_count_bonus", 0x03EA }, .{ "hash_request", 0x12C6 },
    .{ "hash_setting", 0x12CA },       .{ "single_move", 0x1480 },
    .{ "w153c", 0x153C },              .{ "style_flag", 0x1548 },
    .{ "men", 0x154A },                .{ "b1b8b", 0x1B8B },
    .{ "analysis_mode", 0x1BAC },      .{ "mate_in", 0x1DFE },
    .{ "fixed_depth", 0x1E02 },        .{ "tb_settings", 0x239C },
    .{ "w2502", 0x2502 },              .{ "exclusion_flag", 0x2508 },
    .{ "w250c", 0x250C },              .{ "w260a", 0x260A },
    .{ "w2660", 0x2660 },              .{ "random_limit", 0x291E },
    .{ "random_divisor", 0x70F2 },     .{ "pv_columns", 0x2A5E },
    .{ "reverse_move", 0x3626 },       .{ "reverse_move_opp", 0x3628 },
    .{ "reverse_mask", 0x8BC0 },       .{ "pondering", 0x3676 },
    .{ "opponent_side", 0x717C },      .{ "computer_side", 0x8DDE },
    .{ "clock_side", 0x9EEC },         .{ "game_ply", 0x9FC8 },
    .{ "book_exit_ply", 0x9FBC },      .{ "wa36a", 0xA36A },
    .{ "search_ply", 0xB4DE },         .{ "move_number", 0xA84A },
    .{ "analysis", 0x9FCF },           .{ "wa00a", 0xA00A },
    .{ "ba00d", 0xA00D },              .{ "wa00e", 0xA00E },
    .{ "wa3fa", 0xA3FA },              .{ "w8c30", 0x8C30 },
    .{ "changed_73fe", 0x73FE },       .{ "w8baa", 0x8BAA },
    .{ "result_7328", 0x7328 },        .{ "b9ec9", 0x9EC9 },
    .{ "root_in_check", 0x8C07 },      .{ "gives_check", 0x8C08 },
    .{ "ep_ply2", 0x9ECA },            .{ "level", 0xA274 },
    .{ "preset", 0xA8C6 },             .{ "mtg", 0x7102 },
    .{ "next_control", 0x73FA },       .{ "tc_last_white", 0xB4CE },
    .{ "tc_last_black", 0xB4DC },      .{ "start_clock", 0xA8E8 },
    .{ "base", 0x8D06 },               .{ "hard", 0x9DB8 },
    .{ "soft", 0xA362 },               .{ "fail_high_pending", 0xA3F5 },
    .{ "later_fail_high", 0xAE36 },    .{ "last_before_control", 0xA3F6 },
    .{ "clear_best", 0xA22C },         .{ "ext_iteration", 0xA05C },
    .{ "b90ae", 0x90AE },              .{ "stop", 0xA4FA },
    .{ "prescoring", 0x724D },         .{ "poll_requests", 0x75B6 },
    .{ "menu_depth", 0x75B7 },         .{ "white_king", 0xA041 },
    .{ "black_king", 0xA051 },         .{ "hash_key", 0x8CCC },
    .{ "pawn_hash_key", 0x8CD2 },      .{ "root_key", 0x9DC4 },
    .{ "w7182", 0x7182 },              .{ "w90b6", 0x90B6 },
    .{ "w369a", 0x369A },              .{ "material_balance", 0xA35E },
    .{ "material_total", 0xA420 },     .{ "root_balance", 0xA05A },
    .{ "root_total", 0xA35A },         .{ "white_pieces", 0x931A },
    .{ "black_pieces", 0x931B },       .{ "both_have_pieces", 0xA6C6 },
    .{ "white_nonpawn", 0xAE38 },      .{ "black_nonpawn", 0xAE3A },
    .{ "passed_threat", 0xA5F5 },      .{ "static_only", 0xA8DE },
    .{ "root_move_count", 0x7442 },    .{ "legal_count", 0xA518 },
    .{ "best_move", 0xA36C },          .{ "best_captured", 0x7186 },
    .{ "best_check", 0x77D0 },         .{ "book_move", 0x38A0 },
    .{ "current_move", 0xA038 },       .{ "pv_length", 0xB42B },
    .{ "depth_reached", 0xA35C },      .{ "predicted_reply", 0xA416 },
    .{ "ponder_bonus_move", 0xB4F6 },  .{ "wb65c", 0xB65C },
    .{ "b741e", 0x741E },              .{ "last_score", 0xA8DA },
    .{ "root_score", 0x934E },         .{ "reference_score", 0x933C },
    .{ "search_start_score", 0x7184 }, .{ "score_white_view", 0xA418 },
    .{ "score_black_view", 0x8DE8 },   .{ "tb_threshold", 0xAFC4 },
    .{ "tb_score", 0x7466 },           .{ "search_over", 0x9FD0 },
    .{ "depth", 0x744E },              .{ "iteration", 0xA3F4 },
    .{ "ply_limit2", 0xA272 },         .{ "ply_limit4", 0x9356 },
    .{ "ply_limit6", 0xA5EC },         .{ "nodes", 0x740A },
    .{ "w9312", 0x9312 },              .{ "b9d8a", 0x9D8A },
    .{ "ba40e", 0xA40E },              .{ "planning_shown", 0x9351 },
    .{ "b9eb6", 0x9EB6 },              .{ "a6a0", 0xA6A0 },
    .{ "wa5ee", 0xA5EE },              .{ "wa002", 0xA002 },
    .{ "w73f8", 0x73F8 },              .{ "bab9e", 0xAB9E },
};

/// The tables of PrepState and their DGROUP addresses: those the node domain's structs hold
/// (`rootprep.bindDomain`) and those whose home is `RootVars` or `ProgramVars`
/// (`rootprep.bindRoot`, Stage B step 8, stage 7), compared through the view's pointers like
/// its fields.
const tables = [_]struct { []const u8, u16 }{
    .{ "board", 0x9EF6 },         .{ "attack_map", 0x8FE4 },        .{ "root_moves", 0x3BC4 },
    .{ "pv", 0x93B0 },            .{ "pv_follow", 0x3790 },         .{ "low_page", 0x0000 },
    .{ "low_page_rest", 0x0064 }, .{ "irreversible_area", 0x348E }, .{ "root_copy", 0x8C57 },
    .{ "root_scores", 0x8D0A },
};

/// The type a field holds: the field's own, or what it points at (Stage B step 7: a
/// table, or a variable the node domain's structs hold).
fn Held(comptime F: type) type {
    return switch (@typeInfo(F)) {
        .pointer => |p| p.child,
        else => F,
    };
}

fn isPointer(comptime F: type) bool {
    return @typeInfo(F) == .pointer;
}

fn byteSize(comptime T: type) usize {
    return switch (@typeInfo(T)) {
        .int => |i| i.bits / 8,
        .array => |a| a.len * byteSize(a.child),
        else => @compileError("unsupported field type"),
    };
}

comptime {
    @setEvalBranchQuota(1_000_000);
    const fs = @typeInfo(PrepState).@"struct".field_names;
    if (fs.len != layout.len + tables.len) @compileError("layout does not list every PrepState field");
    for (fs) |f| {
        var found = false;
        for (layout ++ tables) |l| {
            if (std.mem.eql(u8, l[0], f)) found = true;
        }
        if (!found) @compileError("field not in layout: " ++ f);
    }
    // The layout is the one `rootprep.bindRoot` binds by.
    for (layout, rp.layout) |a, b| {
        if (!std.mem.eql(u8, a[0], b[0]) or a[1] != b[1]) @compileError("rootprep.layout differs from the test's: " ++ a[0]);
    }
    // no two fields overlap
    for (layout ++ tables, 0..) |a, i| {
        const na = byteSize(Held(@FieldType(PrepState, a[0])));
        for ((layout ++ tables)[i + 1 ..]) |b| {
            const nb = byteSize(Held(@FieldType(PrepState, b[0])));
            if (a[1] < b[1] + nb and b[1] < a[1] + na) @compileError("fields overlap: " ++ a[0] ++ ", " ++ b[0]);
        }
    }
}

fn readT(comptime T: type, img: []const u8, addr: usize) T {
    switch (@typeInfo(T)) {
        .int => return std.mem.readInt(T, img[addr..][0..comptime byteSize(T)], .little),
        .array => |a| {
            var v: T = undefined;
            for (&v, 0..) |*x, k| x.* = readT(a.child, img, addr + k * byteSize(a.child));
            return v;
        },
        else => unreachable,
    }
}

fn writeT(comptime T: type, img: []u8, addr: usize, v: T) void {
    switch (@typeInfo(T)) {
        .int => std.mem.writeInt(T, img[addr..][0..comptime byteSize(T)], v, .little),
        .array => |a| for (v, 0..) |x, k| writeT(a.child, img, addr + k * byteSize(a.child), x),
        else => unreachable,
    }
}

/// Every field, through its pointer where it is one, into the image.
fn store(st: *const PrepState, img: []u8) void {
    inline for (layout ++ tables) |l| {
        const F = @FieldType(PrepState, l[0]);
        const v = if (comptime isPointer(F)) @field(st, l[0]).* else @field(st, l[0]);
        writeT(Held(F), img, l[1], v);
    }
}

/// The DGROUP bytes PrepState holds, and the move marks the env gives (`Replay.marks`).
fn coverage(set: *std.StaticBitSet(0x10000)) void {
    set.* = .empty;
    inline for (layout ++ tables) |l| {
        const n = byteSize(Held(@FieldType(PrepState, l[0])));
        for (0..n) |k| set.set(l[1] + k);
    }
    for (0..marks_len) |k| set.set(marks_addr + k);
}

/// The move-mark table DG:781A, which main clears through the env (`env.marks()`).
const marks_addr = 0x781A;
const marks_len = @import("movegen.zig").marks_len;

/// Compare the port's fields, the ones it points at among them, with the reference image.
fn compareState(st: *const PrepState, ref: []const u8, scratch: []u8, buf: []u8) ?[]const u8 {
    @memcpy(scratch, ref);
    store(st, scratch);
    inline for (layout ++ tables) |l| {
        const n = byteSize(Held(@FieldType(PrepState, l[0])));
        for (0..n) |k| {
            const a = l[1] + k;
            if (scratch[a] != ref[a])
                return std.fmt.bufPrint(buf, "field {s} (DG:{X:0>4}), byte {d}: port {d}, original {d}", .{ l[0], l[1], k, scratch[a], ref[a] }) catch "field differs";
        }
    }
    return null;
}

// ---------------------------------------------------------------------------
// The node domain's structs main's view points at (Stage B step 7, stage 3c-1)
// ---------------------------------------------------------------------------

const dgroup = @import("dgroup.zig");
const sn = @import("searchnode.zig");
const evm = @import("evalvars.zig");
const et = @import("evalthreats.zig");
const see = @import("see.zig");
const leaf = @import("leaf.zig");

const StateMap = dgroup.Map(sn.State, &dgroup.maps.searchnode.State);
const PositionMap = dgroup.Map(pos.Position, &dgroup.maps.position.Position);
const EvalVarsMap = dgroup.Map(evm.EvalVars, &dgroup.maps.evalvars.EvalVars);
const ThreatVarsMap = dgroup.Map(et.ThreatVars, &dgroup.maps.evalthreats.ThreatVars);
const ScratchMap = dgroup.Map(see.Scratch, &dgroup.maps.see.Scratch);
const LeafVarsMap = dgroup.Map(leaf.LeafVars, &dgroup.maps.leaf.LeafVars);
const rvm = @import("rootvars.zig");
const RootVarsMap = dgroup.Map(rvm.RootVars, &dgroup.maps.rootvars.RootVars);
const ProgramVarsMap = dgroup.Map(rvm.ProgramVars, &dgroup.maps.rootvars.ProgramVars);

/// The port's `State`, `Position`, `EvalVars`, `ThreatVars`, `see.Scratch` and `LeafVars`,
/// which `rootprep.bindDomain` points the view at, as the engine points it at the domain's,
/// and its `RootVars` and `ProgramVars`, which `rootprep.bindRoot` points the rest at
/// (Stage B step 8, stage 7). Loaded from the recorded image through their generated maps
/// (every byte at its own address), so that a field pointed at the wrong byte reads another
/// variable's value.
pub const Members = struct {
    st: sn.State = .{},
    p: pos.Position = .{},
    ev: evm.EvalVars = .{},
    tv: et.ThreatVars = .{},
    s: see.Scratch = .{},
    lv: leaf.LeafVars = .{},
    rv: rvm.RootVars = .{},
    pg: rvm.ProgramVars = .{},

    fn load(m: *Members, img: []const u8) void {
        const i: *const [0x10000]u8 = img[0..0x10000];
        StateMap.load(&m.st, i);
        PositionMap.load(&m.p, i);
        EvalVarsMap.load(&m.ev, i);
        ThreatVarsMap.load(&m.tv, i);
        ScratchMap.load(&m.s, i);
        LeafVarsMap.load(&m.lv, i);
        RootVarsMap.load(&m.rv, i);
        ProgramVarsMap.load(&m.pg, i);
    }

    pub fn bind(m: *Members, st: *PrepState) void {
        rp.bindRoot(st, &m.rv, &m.pg);
        rp.bindDomain(st, &m.st, &m.p, &m.ev, &m.tv, &m.s, &m.lv);
    }
};

const Cursor = struct {
    d: []const u8,
    i: usize = 0,
    fn u8_(c: *Cursor) u8 {
        const v = c.d[c.i];
        c.i += 1;
        return v;
    }
    fn int(c: *Cursor, comptime T: type) T {
        const v = std.mem.readInt(T, c.d[c.i..][0..@sizeOf(T)], .little);
        c.i += @sizeOf(T);
        return v;
    }
    fn varint(c: *Cursor) usize {
        var n: usize = 0;
        var shift: std.math.Log2Int(usize) = 0;
        while (true) {
            const b = c.u8_();
            n |= @as(usize, b & 0x7F) << shift;
            if (b & 0x80 == 0) return n;
            shift += 7;
        }
    }
    /// Apply a change list to img (or skip it when img is null); with `changed`, mark the
    /// bytes whose value changes.
    fn changes(c: *Cursor, img: ?[]u8, changed: ?*std.StaticBitSet(0x10000)) void {
        const n = c.varint();
        var prev: isize = -1;
        for (0..n) |_| {
            const a: usize = @intCast(prev + 1 + @as(isize, @intCast(c.varint())));
            const v = c.u8_();
            if (img) |m| {
                if (changed) |ch| {
                    if (m[a] != v) ch.set(a);
                }
                m[a] = v;
            }
            prev = @intCast(a);
        }
    }
};

const Call = struct { site: u16, seg: u16, off: u16, words: [8]u16, before: usize, after: usize, ax: u16, dx: u16 };
const Far = struct { site: u16, seg: u16, off: u16, value: u32 };

fn calleeOf(seg: u16, off: u16) ?Callee {
    const t = (@as(u32, seg) << 16) | off;
    return switch (t) {
        0x38C0_8536 => .screen_8536,
        0x1E9D_7E8A => .reset_move_time_used,
        0x0000_8B7E => .moves_to_go,
        0x38C0_8454 => .display_8454,
        0x1E9D_6F48 => .add_control_time,
        0x1E9D_6AE8 => .clocks_run,
        0x1E9D_7514 => .poll,
        0x1E9D_562A => .delay,
        0x38C0_01E0 => .play_best_move,
        0x4793_621E => .book_probe,
        0x38C0_D478 => .book_exit_display_1,
        0x38C0_88C6 => .book_exit_display_2,
        0x0000_9582 => .prepare_eval,
        0x0000_6C3A => .hash_resize,
        0x0000_88CC => .hash_clear,
        0x0000_89D0 => .hash_seed_learning,
        0x38C0_E260 => .gen_evasions,
        0x1E9D_3938 => .gen_all_moves,
        0x0000_678A => .square_sums,
        0x4793_3EA2 => .hash_key,
        0x1E9D_000C => .make,
        0x1E9D_0960 => .unmake,
        0x2B9F_BB76 => .tb_probe,
        0x2B9F_40A8 => .attack_map_white,
        0x2B9F_42DA => .attack_map_black,
        0x2B9F_402A => .repetition,
        0x2B9F_458A => .has_legal_move,
        0x0000_3AC6 => .node_white,
        0x0000_5036 => .node_black,
        0x0EF8_89DC => .pawn_eval_wtm,
        0x0EF8_8F82 => .pawn_eval_btm,
        0x2B9F_000E => .static_eval,
        0x2B9F_5534 => .hanging_white,
        0x2B9F_4BFE => .hanging_black,
        0x0EF8_0006 => .pieces_and_kings,
        0x1E9D_16E4 => .activity_white,
        0x1E9D_1E30 => .activity_black,
        0x1E9D_3416 => .endgame_king_white,
        0x1E9D_35FB => .endgame_king_black,
        0x1E9D_CE3E => .count_attacked_wtm,
        0x1E9D_CC4E => .count_attacked_btm,
        0x0EF8_A026 => .threats_white,
        0x0EF8_CD20 => .threats_black,
        0x4793_89D8 => .rand,
        0x38C0_8898 => .pv_screen_line,
        0x38C0_948A => .show_move,
        0x38C0_9BEA => .show_score,
        0x0000_6F2E => .clear_excluded,
        0x0000_8C3E => .set_time_budget,
        0x38C0_570A => .game_over_display,
        0x2B9F_6614 => .end_analysis,
        0x1E9D_7144 => .display_7144,
        0x1E9D_72B4 => .display_72b4,
        0x38C0_9E7C => .positions_display,
        0x0000_668E => .sort_root_moves,
        0x38C0_A0B0 => .display_a0b0,
        // done by the port itself
        0x4793_87D4, 0x4793_8AF0, 0x0000_6BE4, 0x0000_6BF8, 0x1E9D_54CE => null,
        else => @panic("a callee the port does not know"),
    };
}

const Replay = struct {
    raw: []const u8,
    calls: []const Call,
    fars: []const Far,
    k: usize = 0,
    v: usize = 0,
    cur: []u8,
    scratch: []u8,
    st: *PrepState,
    held: *const std.StaticBitSet(0x10000),
    changed: *std.StaticBitSet(0x10000),
    stack_lo: u16,
    stack_hi: u16,
    failure: ?[]const u8 = null,
    msg: [400]u8 = undefined,
    checked: usize = 0,
    far_checked: usize = 0,
    /// main's frame pointer, and the reads of the two score words [bp-6], [bp-4] (DEV-044)
    bp: u16 = 0,
    score_word_reads: usize = 0,
    /// The port's move marks (`env.marks()`), compared with the original's like
    /// PrepState's fields.
    marks_buf: [marks_len]u8 = undefined,
    /// The structs `rootprep.bindDomain` and `bindRoot` point the view at.
    m: *Members,

    pub fn marks(r: *Replay) *[marks_len]u8 {
        return &r.marks_buf;
    }

    fn compareMarks(r: *Replay, where: []const u8) bool {
        if (std.mem.indexOfDiff(u8, &r.marks_buf, r.cur[marks_addr..][0..marks_len])) |k| {
            r.fail("{s}: move mark {d} (DG:{X:0>4}): port {d}, original {d}", .{ where, k, marks_addr + k, r.marks_buf[k], r.cur[marks_addr + k] });
            return false;
        }
        return true;
    }

    fn fail(r: *Replay, comptime fmt: []const u8, args: anytype) void {
        if (r.failure != null) return;
        r.failure = std.fmt.bufPrint(&r.msg, fmt, args) catch "failure";
    }

    fn inStack(r: *const Replay, a: usize) bool {
        return a >= r.stack_lo and a < r.stack_hi;
    }

    /// Every byte the original changed since the last check is held by PrepState (or is
    /// on the stack).
    fn checkCoverage(r: *Replay, where: []const u8) void {
        var it = r.changed.iterator(.{});
        while (it.next()) |a| {
            if (!r.held.isSet(a) and !r.inStack(a)) {
                r.fail("{s}: the original wrote DG:{X:0>4}, which PrepState does not hold", .{ where, a });
                break;
            }
        }
        r.changed.* = .empty;
    }

    fn applyChanges(r: *Replay, off: usize) void {
        var c: Cursor = .{ .d = r.raw, .i = off };
        c.changes(r.cur, r.changed);
    }

    fn skipInline(r: *Replay) void {
        while (r.k < r.calls.len and calleeOf(r.calls[r.k].seg, r.calls[r.k].off) == null) {
            r.applyChanges(r.calls[r.k].before);
            r.applyChanges(r.calls[r.k].after);
            r.k += 1;
        }
    }

    pub fn call(r: *Replay, site: u16, callee: Callee, args: []const u16) u32 {
        if (r.failure != null) return 0;
        r.skipInline();
        if (r.k >= r.calls.len) {
            r.fail("port calls {s} at {X:0>4}, the original made no more calls", .{ @tagName(callee), site });
            return 0;
        }
        const c = r.calls[r.k];
        const want = calleeOf(c.seg, c.off).?;
        if (c.site != site or want != callee) {
            r.fail("call {d}: port {s} at {X:0>4}, original {s} at {X:0>4}", .{ r.k, @tagName(callee), site, @tagName(want), c.site });
            return 0;
        }
        for (args, 0..) |a, j| {
            if (a != c.words[j]) {
                r.fail("call {d} ({s} at {X:0>4}): argument {d}: port {X:0>4}, original {X:0>4}", .{ r.k, @tagName(callee), site, j, a, c.words[j] });
                return 0;
            }
        }
        r.applyChanges(c.before);
        r.checkCoverage("before a call");
        var buf: [200]u8 = undefined;
        if (compareState(r.st, r.cur, r.scratch, &buf)) |d| {
            r.fail("before call {d} ({s} at {X:0>4}): {s}", .{ r.k, @tagName(callee), site, d });
            return 0;
        }
        if (!r.compareMarks("before a call")) return 0;
        var cc: Cursor = .{ .d = r.raw, .i = c.after };
        cc.changes(r.cur, null); // the callee's writes: not main's
        r.m.load(r.cur);
        r.marks_buf = r.cur[marks_addr..][0..marks_len].*;
        r.k += 1;
        r.checked += 1;
        return @as(u32, c.dx) << 16 | c.ax;
    }

    fn nextFar(r: *Replay, site: u16) ?Far {
        if (r.failure != null) return null;
        if (r.v >= r.fars.len) {
            r.fail("port reads or writes outside DGROUP at {X:0>4}; the original did not", .{site});
            return null;
        }
        const f = r.fars[r.v];
        r.v += 1;
        if (f.site != site) {
            r.fail("far access {d}: port at {X:0>4}, original at {X:0>4}", .{ r.v - 1, site, f.site });
            return null;
        }
        return f;
    }

    fn segOf(r: *const Replay, segvar: u16) u16 {
        return std.mem.readInt(u16, r.cur[segvar..][0..2], .little);
    }

    pub fn far(r: *Replay, site: u16, segvar: u16, off: u16) u8 {
        const f = r.nextFar(site) orelse return 0;
        if (f.seg != r.segOf(segvar) or f.off != off) {
            r.fail("far read at {X:0>4}: port [{X:0>4}]:{X:0>4}, original {X:0>4}:{X:0>4}", .{ site, segvar, off, f.seg, f.off });
            return 0;
        }
        r.far_checked += 1;
        return @truncate(f.value);
    }

    pub fn clock(r: *Replay, site: u16) u32 {
        const f = r.nextFar(site) orelse return 0;
        r.far_checked += 1;
        return f.value;
    }

    pub fn farWrite(r: *Replay, site: u16, segvar: u16, off: u16, value: u16) void {
        const f = r.nextFar(site) orelse return;
        if (f.seg != r.segOf(segvar) or f.off != off or f.value != value)
            r.fail("far write at {X:0>4}: port [{X:0>4}]:{X:0>4} = {X:0>4}, original {X:0>4}:{X:0>4} = {X:0>4}", .{ site, segvar, off, value, f.seg, f.off, f.value });
        r.far_checked += 1;
    }

    pub fn local(r: *Replay, addr: u16) u8 {
        if (addr >= r.bp -% 6 and addr < r.bp -% 2) r.score_word_reads += 1;
        return r.cur[addr];
    }

    pub fn notModelled(r: *Replay, site: u16) void {
        r.fail("branch {X:0>4} not modelled", .{site});
    }

    fn finish(r: *Replay, final_off: usize) void {
        if (r.failure != null) return;
        r.skipInline();
        if (r.k != r.calls.len) {
            const c = r.calls[r.k];
            r.fail("port returned after {d} calls, the original made {d} (next {X:0>4}:{X:0>4} at {X:0>4})", .{ r.k, r.calls.len, c.seg, c.off, c.site });
            return;
        }
        if (r.v != r.fars.len) {
            r.fail("port made {d} far accesses, the original {d}", .{ r.v, r.fars.len });
            return;
        }
        r.applyChanges(final_off);
        r.checkCoverage("at the exit");
        var buf: [200]u8 = undefined;
        if (compareState(r.st, r.cur, r.scratch, &buf)) |d| r.fail("at the exit: {s}", .{d});
        _ = r.compareMarks("at the exit");
    }
};

fn readVectors(gpa: std.mem.Allocator, name: []const u8) ![]u8 {
    var path_buf: [256]u8 = undefined;
    const dir = @import("build_options").golden_dir;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/rootprep/{s}", .{ dir, name });
    const compressed = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, path, gpa, .limited(64 << 20));
    defer gpa.free(compressed);
    var in: std.Io.Reader = .fixed(compressed);
    const window = try gpa.alloc(u8, std.compress.zstd.default_window_len + std.compress.zstd.block_size_max);
    defer gpa.free(window);
    var zd = std.compress.zstd.Decompress.init(&in, window, .{});
    return zd.reader.allocRemaining(gpa, .limited(512 << 20));
}

const Totals = struct {
    preps: u32 = 0,
    reps: u32 = 0,
    reps_nonzero: u32 = 0,
    calls: usize = 0,
    fars: usize = 0,
    failures: u32 = 0,
    quiet: bool = false,
    score_word_reads: usize = 0,
    exits: [4]u32 = .{ 0, 0, 0, 0 },
};

fn exitIndex(e: rp.Exit) usize {
    return switch (e) {
        .iteration_loop => 0,
        .conclude => 1,
        .main_loop => 2,
        .menu => 3,
    };
}

fn replayFile(comptime fixes: pos.Fixes, comptime nms: rp.NoMoveScores, gpa: std.mem.Allocator, name: []const u8, tot: *Totals) !void {
    const raw = try readVectors(gpa, name);
    defer gpa.free(raw);
    try std.testing.expectEqualSlices(u8, "MCRP", raw[0..4]);
    try std.testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, raw[4..6], .little));
    const cur = try gpa.alloc(u8, 0x10000);
    defer gpa.free(cur);
    @memset(cur, 0);
    const scratch = try gpa.alloc(u8, 0x10000);
    defer gpa.free(scratch);
    const held = try gpa.create(std.StaticBitSet(0x10000));
    defer gpa.destroy(held);
    coverage(held);
    const changed = try gpa.create(std.StaticBitSet(0x10000));
    defer gpa.destroy(changed);
    const st = try gpa.create(PrepState);
    defer gpa.destroy(st);
    const members = try gpa.create(Members);
    defer gpa.destroy(members);
    const history = try gpa.alloc([6]u8, 1024);
    defer gpa.free(history);
    var calls: std.ArrayList(Call) = .empty;
    defer calls.deinit(gpa);
    var fars: std.ArrayList(Far) = .empty;
    defer fars.deinit(gpa);
    var c: Cursor = .{ .d = raw, .i = 6 };
    var n: [2]u32 = .{ 0, 0 };
    var index: u32 = 0;
    while (true) : (index += 1) {
        const kind = c.u8_();
        if (kind == 0) {
            const want = [2]u32{ c.int(u32), c.int(u32) };
            try std.testing.expectEqual(want, n);
            break;
        }
        if (kind == 2) {
            const ply = c.int(i16);
            const last = c.int(i16);
            var key: [6]u8 = undefined;
            @memcpy(&key, c.d[c.i..][0..6]);
            c.i += 6;
            const k = c.int(u16);
            // every entry the original did not compare holds the key itself, so that a
            // port reading one more entry would count it
            @memset(history, key);
            const p0: i32 = @as(i32, ply) - 4;
            for (0..k) |j| {
                const p: usize = @intCast(p0 - 2 * @as(i32, @intCast(j)));
                @memcpy(&history[p], c.d[c.i..][0..6]);
                c.i += 6;
            }
            const ax = c.int(u16);
            const got = rp.repetitionCount(history, ply, last, key);
            if (got != ax) {
                if (tot.failures < 10) std.debug.print("rootprep {s} repetition call {d}: port {d}, original {d}\n", .{ name, index, got, ax });
                tot.failures += 1;
            }
            if (ax != 0) tot.reps_nonzero += 1;
            n[1] += 1;
            continue;
        }
        if (kind != 1) return error.BadKind;
        const entry = c.int(u16);
        const exit = c.int(u16);
        const sp = c.int(u16);
        const bp = c.int(u16);
        c.changes(cur, null);
        calls.clearRetainingCapacity();
        fars.clearRetainingCapacity();
        const ncalls = c.int(u16);
        for (0..ncalls) |_| {
            var call: Call = undefined;
            call.site = c.int(u16);
            call.seg = c.int(u16);
            call.off = c.int(u16);
            for (&call.words) |*x| x.* = c.int(u16);
            call.before = c.i;
            c.changes(null, null);
            call.after = c.i;
            c.changes(null, null);
            call.ax = c.int(u16);
            call.dx = c.int(u16);
            try calls.append(gpa, call);
        }
        const nf = c.int(u16);
        for (0..nf) |_| {
            const f: Far = .{ .site = c.int(u16), .seg = c.int(u16), .off = c.int(u16), .value = c.int(u32) };
            try fars.append(gpa, f);
        }
        const final_off = c.i;
        c.changes(null, null);

        st.* = .{};
        members.* = .{};
        members.load(cur);
        members.bind(st);
        changed.* = .empty;
        var r: Replay = .{ .raw = raw, .calls = calls.items, .fars = fars.items, .cur = cur, .scratch = scratch, .st = st, .held = held, .changed = changed, .stack_lo = sp -% 0x300, .stack_hi = bp +% 2, .bp = bp, .m = members };
        r.marks_buf = cur[marks_addr..][0..marks_len].*;
        const e = rp.rootPrepFixes(fixes, nms, st, &r, bp, @fromBackingInt(@intCast(entry)));
        if (@backingInt(e) != exit) r.fail("exit: port {X:0>4}, original {X:0>4}", .{ @backingInt(e), exit });
        r.finish(final_off);
        if (r.failure) |f| {
            if (tot.failures < 10 and !tot.quiet) std.debug.print("rootprep {s} invocation {d} (entry {X:0>4}): {s}\n", .{ name, index, entry, f });
            tot.failures += 1;
            // rebuild cur from the recording
            var k = r.k;
            while (k < calls.items.len) : (k += 1) {
                var cc: Cursor = .{ .d = raw, .i = calls.items[k].before };
                cc.changes(cur, null);
                cc.changes(cur, null);
            }
            var cf: Cursor = .{ .d = raw, .i = final_off };
            cf.changes(cur, null);
        } else {
            tot.exits[exitIndex(e)] += 1;
        }
        tot.calls += r.checked;
        tot.fars += r.far_checked;
        tot.score_word_reads += r.score_word_reads;
        n[0] += 1;
    }
    tot.preps += n[0];
    tot.reps += n[1];
}

pub const files = [_][]const u8{
    "fixed.zst",     "book.zst",    "incheck.zst", "krk.zst",            "kpk.zst",      "repeat.zst", "onemove.zst",
    "stalemate.zst", "mated.zst",   "ponder.zst",  "timed.zst",          "instant.zst",  "matein.zst", "repeat1.zst",
    "pawns5.zst",    "passers.zst", "tc5in1.zst",  "boxedstalemate.zst", "easymove.zst",
} ++ [_][]const u8{
    // 2026-11-22: add_control_time from the start of a move, at main 05FD and 061D
    "tc1in1-typed.zst",
    "preset1-monitor61-m.zst",
};

test "rootprep: every recorded preparation of the original and every repetition count" {
    const gpa = std.testing.allocator;
    var tot: Totals = .{};
    for (files) |f| try replayFile(pos.Fixes.original, .stale, gpa, f, &tot);
    std.debug.print("rootprep: {d} preparations replayed (exits: loop {d}, conclude {d}, main loop {d}, menu {d}); {d} interface calls and {d} far accesses checked; repetition count {d} calls ({d} non-zero); {d} mismatches\n", .{ tot.preps, tot.exits[0], tot.exits[1], tot.exits[2], tot.exits[3], tot.calls, tot.fars, tot.reps, tot.reps_nonzero, tot.failures });
    try std.testing.expectEqual(@as(u32, 0), tot.failures);
}

test "set_prescore_margins and set_search_margins" {
    var st: PrepState = .{};
    const m = try std.testing.allocator.create(Members);
    defer std.testing.allocator.destroy(m);
    m.* = .{};
    m.bind(&st);
    rp.setPrescoreMargins(&st);
    try std.testing.expectEqual(@as(u16, 70), st.margin_154.*);
    try std.testing.expectEqual(@as(u16, 100), st.margin_186.*);
    rp.setSearchMargins(&st);
    try std.testing.expectEqual(@as(u16, 200), st.margin_172.*);
    try std.testing.expectEqual(@as(u16, 720), st.margin_168.*);
    // The margins are the passer rank tables' entries DG:0154, 0168, 0172, 0186.
    try std.testing.expectEqual(@as(u16, 720), m.ev.passer_rank_tables[1][8]);
}

/// Replays every recorded preparation with one correction on and returns the number of
/// invocations whose replay no longer matches the original (the first difference ends an
/// invocation's replay, so this counts invocations, not bytes).
fn countChanged(comptime fixes: pos.Fixes, comptime nms: rp.NoMoveScores) !u32 {
    const gpa = std.testing.allocator;
    var tot: Totals = .{ .quiet = true };
    for (files) |f| try replayFile(fixes, nms, gpa, f, &tot);
    return tot.failures;
}

fn only(comptime name: []const u8) pos.Fixes {
    var f = pos.Fixes.original;
    @field(f, name) = true;
    return f;
}

test "DEV-043: the White-to-move pre-score's first threat term subtracts the bonus when corrected" {
    // eval_threats_white gave r = 37 with three attacked pieces (bonus [3EA + 6] = 500):
    // the original's si -= (37 + 500) >> 1 = 268; the mirror's si -= (37 - 500) >> 1 = -232.
    const bonus: i16 = 500; // [3EA + 6]
    try std.testing.expectEqual(@as(i16, 537), rp.threatTerm(pos.Fixes.original, 37, bonus));
    try std.testing.expectEqual(@as(i16, -463), rp.threatTerm(only("dev043_prescore_sign"), 37, bonus));
    // With no attacked piece the bonus is 0 and both agree.
    try std.testing.expectEqual(rp.threatTerm(pos.Fixes.original, 37, 0), rp.threatTerm(only("dev043_prescore_sign"), 37, 0));
    const n = try countChanged(only("dev043_prescore_sign"), .stale);
    std.debug.print("DEV-043: {d} of the recorded preparations change with the fix on\n", .{n});
    try std.testing.expect(n > 0);
}

test "DEV-031: the 4/5 scaling takes the product in 32 bits when corrected" {
    try std.testing.expectEqual(@as(i16, 2872), rp.fourFifthsFixes(pos.Fixes.original, 19974));
    try std.testing.expectEqual(@as(i16, 15979), rp.fourFifthsFixes(only("dev031_scaling_overflow"), 19974));
    try std.testing.expectEqual(@as(i16, -15979), rp.fourFifthsFixes(only("dev031_scaling_overflow"), -19974));
    // Below 8192 in magnitude the two agree.
    var s: i32 = -8192;
    while (s <= 8191) : (s += 1) {
        const x: i16 = @intCast(s);
        try std.testing.expectEqual(rp.fourFifthsFixes(pos.Fixes.original, x), rp.fourFifthsFixes(only("dev031_scaling_overflow"), x));
    }
    const n = try countChanged(only("dev031_scaling_overflow"), .stale);
    std.debug.print("DEV-031: {d} of the recorded preparations change with the fix on\n", .{n});
    try std.testing.expect(n > 0);
}

test "DEV-044: with no root moves the corrected preparation takes 0 for the best and second scores" {
    const gpa = std.testing.allocator;
    // mated.zst: White is checkmated, the generator gives no root move. The original reads
    // main's [bp-6] and [bp-4] (10A9, 10EB), left from the previous search; corrected, the
    // port reads neither and takes 0 for both.
    var stale: Totals = .{};
    try replayFile(pos.Fixes.original, .stale, gpa, "mated.zst", &stale);
    try std.testing.expectEqual(@as(u32, 0), stale.failures);
    try std.testing.expectEqual(@as(usize, 4), stale.score_word_reads);
    var zero: Totals = .{};
    try replayFile(pos.Fixes.original, .zero, gpa, "mated.zst", &zero);
    try std.testing.expectEqual(@as(usize, 0), zero.score_word_reads);
    // In that recording the stale words give the same [A22C] and base as 0 does.
    try std.testing.expectEqual(@as(u32, 0), zero.failures);
    const n = try countChanged(pos.Fixes.original, .zero);
    std.debug.print("DEV-044: {d} of the recorded preparations change with the stale scores taken as 0\n", .{n});
    try std.testing.expectEqual(@as(u32, 0), n);
}

test "rootprep: every recorded preparation under Fixes.corrected (counted, not required to match)" {
    const n = try countChanged(pos.Fixes.corrected, .zero);
    std.debug.print("rootprep: {d} of the recorded preparations change with every fix of this unit on\n", .{n});
}
