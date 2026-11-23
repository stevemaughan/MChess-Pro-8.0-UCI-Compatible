//! The tests' codec between the engine's state and the original's data segment (Stage B
//! step 8, stage 8; docs/arch/60-engine-assembly.md section 10.7.4, points 4 and 5).
//!
//! The engine keeps its state in its members (src/engine_state.zig `Members`: the node's
//! `searchnode.State` and the ten members with a field map) and the game record
//! (`gamemove.GameRecord`); it holds no image of DGROUP and no far segment. The oracle's
//! recordings are images, so the tests load the engine from one and compare the engine's
//! state with one through this file, which the engine build never reaches (the `comptime`
//! block below fails the build if it does):
//!
//! - `fromImage(root, img, far)` loads every member from a DGROUP image and the record from
//!   a far segment, through each member's generated map (`dgroup.Map`), exactly as the
//!   domain's `enter` loaded them until this stage; `toImage(root)` writes them back, the
//!   members in the order `exit` stored them and the node's `State` last, the record with
//!   its keys before `gave_check` (`GameRecord.toFar`), and then loads them again, as
//!   `syncImage` did. The image a root is loaded from and written to is the root's own test
//!   image (`EngineRoot.test_img`, `EngineRoot.test_far`, fields of the test build only):
//!   `toImage` stores only the bytes a member has changed since the last load
//!   (`dgroup.Map.storeChanged`, against the snapshots `Snapshots`), so that the bytes the
//!   tests compare are exactly the ones the image held before this stage.
//! - `imageBegin` / `imageEnd`: a test that writes the image itself, as the original's
//!   memory, stores the engine's state there and loads it back afterwards.
//! - `enter` / `exit`: the same for a domain `NodeEnv` alone (the node tests, the hook of
//!   the mixed tests, which reads and writes the image around each of main's callees).
//! - The image check (`checkImage`, Debug and ReleaseSafe test builds): a byte some member
//!   holds that was written in the image since the last load would be lost by the next
//!   store, or kept beside a different value; it is reported.
//!
//! The engine itself reads one image, once: the executable's initialised data
//! (`dgroup.initial`), which `engine_state` `decodeFrom` decodes into the members at
//! start-up (src/engine_root.zig `EngineRoot.init`, `startUp`). That decode is
//! `fromImage`'s, and the only part of it the engine contains.

const std = @import("std");
const builtin = @import("builtin");

comptime {
    if (!builtin.is_test) @compileError("src/state_image.zig is the tests' codec: the engine build must not reach it (Stage B step 8, stage 8)");
}

const dgroup = @import("dgroup.zig");
const est = @import("engine_state.zig");
const sn = @import("searchnode.zig");

pub const Image = dgroup.Image;
/// The far segment 5A7B as an image (src/engine_root.zig `Far`).
pub const Far = [0x10000]u8;

/// A domain `NodeEnv`'s codec state (`engine_state.NodeEnvWith`'s `codec`, a field of the
/// test build only).
pub const CtxCodec = struct {
    /// The image this `NodeEnv` is loaded from and stored to.
    img: *Image = undefined,
    /// Between `enter` and `exit`: the members hold the state, not the image. The engine
    /// is always entered; only a test leaves it (`exit`, `imageBegin`).
    in_domain: bool = false,
    /// The image check panics on a byte written in the image while the domain held it
    /// unless this is false: then it counts them, and keeps the first address.
    image_panic: bool = true,
    image_writes: u64 = 0,
    image_first: u16 = 0,
    /// The image is on pages the process may not touch (src/engine_stageb_test.zig): the
    /// image check, which reads it, is skipped.
    image_guarded: bool = false,
    /// The times the domain has been left (`exit`): the tests that the search and the
    /// engine's commands store nothing to the image read it.
    exits: u64 = 0,
    /// Open brackets (`imageBegin` without its `imageEnd`): only the outermost stores and
    /// loads.
    depth: u32 = 0,
};

/// The tests' codec state of the `Members` (`engine_state.Members.img_snap`, test builds
/// only): each member's encoding as the last load from an image left it
/// (`dgroup.Map.Snapshot`, which the codec's store compares with, so that it writes only the
/// bytes a member changed), and for the image check the bytes some member holds, as runs
/// (`a` the holder's index, `b` the first address), and the image as the last load read it.
pub const Snapshots = struct {
    pb: est.PositionMap.Snapshot = undefined,
    evb: est.EvalVarsMap.Snapshot = undefined,
    svb: est.SearchVarsMap.Snapshot = undefined,
    sb: est.ScratchMap.Snapshot = undefined,
    lvb: est.LeafVarsMap.Snapshot = undefined,
    tvb: est.ThreatVarsMap.Snapshot = undefined,
    gvb: est.GameVarsMap.Snapshot = undefined,
    tsb: est.TimeStateMap.Snapshot = undefined,
    rvb: est.RootVarsMap.Snapshot = undefined,
    pgb: est.ProgramVarsMap.Snapshot = undefined,
    held: []est.Run = &.{},
    loaded: [if (est.image_check) dgroup.size else 0]u8 = undefined,
};

/// The node's `State` into the image (every mapped range).
pub fn stateToImage(st: *const sn.State, img: *Image) void {
    const bytes = std.mem.asBytes(st);
    inline for (sn.dg_fields) |f| {
        const off = @offsetOf(sn.State, f.name);
        @memcpy(img[f.addr..][0..f.len], bytes[off..][0..f.len]);
    }
}

// ---- a domain `NodeEnv` ---------------------------------------------------------------

/// The domain entered from its image: every member and the node's `State` decoded from
/// `c.codec.img` (`decodeFrom`, which also takes the snapshots `exit` compares with).
pub fn enter(c: anytype) void {
    c.decodeFrom(c.codec.img);
}

/// The image check: while the domain is entered its members hold the bytes they hold, and
/// nothing may write those bytes in the image (a test writes the image only between `exit`
/// and `enter`, or `imageBegin` and `imageEnd`). Each held byte of the image must still be
/// what the last load read; one that is not was written outside a bracket. Run at every
/// `exit` and at the start of each search (Debug and ReleaseSafe test builds).
pub fn checkImage(c: anytype) void {
    if (!est.image_check or !c.codec.in_domain or c.codec.image_guarded) return;
    const d = c.dom;
    const img = c.codec.img;
    for (d.img_snap.held) |r| {
        const now = img[r.b..][0..r.len];
        const then = d.img_snap.loaded[r.b..][0..r.len];
        if (std.mem.eql(u8, now, then)) continue;
        for (0..r.len) |k| if (now[k] != then[k]) {
            const addr: u16 = @intCast(r.b + k);
            const m: est.Member = @fromBackingInt(@intCast(r.a));
            if (c.codec.image_panic) std.debug.panic("state_image: DG:{X:0>4}, held by {s}, was written in the image while the domain was entered (a test's write outside imageBegin / imageEnd)", .{ addr, @tagName(m) });
            if (c.codec.image_writes == 0) c.codec.image_first = addr;
            c.codec.image_writes += 1;
        };
    }
}

/// The domain left to its image: each member's changed bytes (against the snapshots of the
/// last load), the node's `State` last; the alias-write detector's pending check first.
pub fn exit(c: anytype) void {
    checkImage(c);
    if (@TypeOf(c.*).alias_detect) c.checkAliases();
    const d = c.dom;
    const img = c.codec.img;
    const sp = &d.img_snap;
    _ = est.PositionMap.storeChanged(&d.p, img, &sp.pb);
    _ = est.ScratchMap.storeChanged(&d.s, img, &sp.sb);
    _ = est.ThreatVarsMap.storeChanged(&d.tv, img, &sp.tvb);
    _ = est.LeafVarsMap.storeChanged(&d.lv, img, &sp.lvb);
    _ = est.EvalVarsMap.storeChanged(&d.ev, img, &sp.evb);
    _ = est.SearchVarsMap.storeChanged(&d.sv, img, &sp.svb);
    _ = est.GameVarsMap.storeChanged(&d.gv, img, &sp.gvb);
    _ = est.TimeStateMap.storeChanged(&d.ts, img, &sp.tsb);
    _ = est.RootVarsMap.storeChanged(&d.rv, img, &sp.rvb);
    _ = est.ProgramVarsMap.storeChanged(&d.pg, img, &sp.pgb);
    stateToImage(c.st, img);
    c.codec.in_domain = false;
    c.codec.exits += 1;
}

// ---- a root (src/engine_root.zig `EngineRoot`) ----------------------------------------

/// Before a test writes the root's image (`root.test_img`) or far segment (`root.test_far`) itself:
/// the members stored to the image (`exit`, which runs the image check) and the game record
/// to the far segment. Brackets nest: only the outermost stores.
pub fn imageBegin(s: anytype) void {
    s.image_brackets += 1;
    if (s.node.codec.depth == 0) {
        if (s.node.codec.in_domain) exit(&s.node);
        s.rec.toFar(s.test_far);
    }
    s.node.codec.depth += 1;
}

/// After it: the record loaded from the far segment and the members from the image
/// (`enter`). Exact: `exit` stored every byte the members changed, `enter` reloads every
/// byte they hold.
pub fn imageEnd(s: anytype) void {
    std.debug.assert(s.node.codec.depth > 0);
    s.node.codec.depth -= 1;
    if (s.node.codec.depth == 0) {
        s.rec.fromFar(s.test_far);
        enter(&s.node);
    }
}

/// The root's image and far segment set to `img` and `far` (null: zeros), and the members
/// and the record loaded from them (a test's start from an oracle snapshot).
pub fn fromImage(s: anytype, img: *const Image, far: ?*const Far) void {
    imageBegin(s);
    defer imageEnd(s);
    s.test_img.* = img.*;
    if (far) |f| s.test_far.* = f.* else s.test_far.* = @splat(0);
}

/// The root's image and far segment made current: the members and the record stored to
/// them (and loaded again), so that a test reading `root.test_img` or `root.test_far` sees what the
/// engine holds.
pub fn toImage(s: anytype) void {
    imageBegin(s);
    imageEnd(s);
}

/// The game record loaded from the root's far segment, for a test that has written it
/// after `fromImage` (an oracle's game record).
pub fn refreshRecord(s: anytype) void {
    std.debug.assert(s.node.codec.depth == 0);
    s.rec.fromFar(s.test_far);
}

/// main before the iteration loop (`EngineRoot.prepare`) inside a bracket (the mixed test, which
/// drives the image call by call): the record and the members loaded from the image, main,
/// and both stored back.
pub fn prepare(s: anytype, entry: anytype) @TypeOf(s.prepare(entry)) {
    std.debug.assert(s.node.codec.depth > 0 and !s.node.codec.in_domain);
    s.rec.fromFar(s.test_far);
    enter(&s.node);
    const x = s.prepare(entry);
    exit(&s.node);
    s.rec.toFar(s.test_far);
    return x;
}

/// A checkpoint (`EngineRoot.Checkpoint`) as an image and a far segment: every byte some member
/// holds written into `img` from its home's copy in the checkpoint, over the image's present
/// bytes, and the record into `far`.
pub fn checkpointToImage(s: anytype, cp: anytype, img: *Image, far: *Far) void {
    for (0..dgroup.size) |a| {
        if (s.node.dom.home_m[a] >= 0) img[a] = s.node.checkpointPtr(cp, @intCast(a)).*;
    }
    cp.rec.toFar(far);
}

/// The test image of a root about to be loaded with the C start-up's image (`EngineRoot.startUp`):
/// the image check run on the image as it is, then the image set to `dgroup.initial` and
/// the far segment to zeros, so that it is the image the members are decoded from.
pub fn startImage(s: anytype) void {
    std.debug.assert(s.node.codec.depth == 0);
    checkImage(&s.node);
    s.test_img.* = dgroup.initial;
    s.test_far.* = @splat(0);
}
