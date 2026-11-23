//! The original's initialised data, read at compile time from the pinned executable
//! (reference/extracted/MCP8-decrypted.exe, sha256 in reference/CHECKSUMS.txt), so
//! that constant tables are taken from the program and never retyped (AGENTS.md §7,
//! step 3.1).
//!
//! The decrypted file is the program's load image behind an MZ header, so DGROUP
//! (segment 61E4 relative to the load segment) starts at file offset
//! `header paragraphs * 16 + 61E4h * 16`.

const std = @import("std");

const exe = @embedFile("mcp8_exe");

/// The relative segment of DGROUP.
pub const dgroup_segment = 0x61E4;

const dgroup_file_offset: usize = blk: {
    if (!std.mem.eql(u8, exe[0..2], "MZ")) @compileError("mcp8_exe is not an MZ executable");
    const header_paragraphs = std.mem.readInt(u16, exe[8..10], .little);
    break :blk @as(usize, header_paragraphs) * 16 + dgroup_segment * 16;
};

/// `n` bytes of DGROUP's initial contents from offset `addr`.
pub fn dgroup(comptime addr: usize, comptime n: usize) [n]u8 {
    return exe[dgroup_file_offset + addr ..][0..n].*;
}

test "DGROUP is where the header says: the exchange values at DG:1A71" {
    // docs/arch/21-move-generation.md: empty 1, P 3, N 9, B 9, R 15, Q 27, K 0.
    const v = dgroup(0x1A71, 7);
    try std.testing.expectEqualSlices(u8, &.{ 1, 3, 9, 9, 15, 27, 0 }, &v);
}
