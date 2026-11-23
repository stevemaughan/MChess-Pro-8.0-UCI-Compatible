//! TEST ONLY. src/sort.zig as it was before the speed pass of 2026-11-18, kept
//! unchanged as the reference the differential tests compare the faster routines
//! with. Imported only by the test files; not part of the engine.
//!
//! sort_moves (0000:65BC): the move-list sort.
//!
//! Specification: docs/arch/21-move-generation.md §2 and
//! tools/research/movegen/model.py `sort_moves` (proved on about 924,000 calls).
//! Test: src/see_test.zig.

const std = @import("std");
const Move = @import("position.zig").Move;

/// Port of sort_moves (0000:65BC-668D). Shell sort of the first `n` moves of `list`,
/// descending by the score byte read as a signed byte. The gap starts at 1 and becomes
/// 3h+1 while n/9 >= h (signed division, truncating); after each pass it becomes 13 if
/// above 13, else 4 if above 4, else 1 if above 1, else the sort ends. Each pass is an
/// insertion sort that stops at an entry whose score is >= the key's, so equal scores
/// keep their order within a pass (not necessarily across passes). The result, ties
/// included, is the original's, which a different sort would not give.
///
/// `n` is the original's signed word; a count of 0 or less sorts nothing.
pub fn sortMoves(list: []Move, n: i16) void {
    if (n <= 1) return;
    const count: usize = @intCast(n);
    std.debug.assert(count <= list.len);
    const q: usize = @intCast(@divTrunc(n, 9));
    var h: usize = 1;
    while (q >= h) h = 3 * h + 1;
    while (true) {
        // Entries are numbered from 1 in the original: entry i is list[i - 1].
        var i = h + 1;
        while (i <= count) : (i += 1) {
            const key = list[i - 1];
            const key_score: i8 = @bitCast(key.score);
            var j = i;
            while (h < j) {
                const k = j - h;
                if (@as(i8, @bitCast(list[k - 1].score)) >= key_score) break;
                list[j - 1] = list[k - 1];
                j = k;
            }
            list[j - 1] = key;
        }
        if (h > 13) {
            h = 13;
        } else if (h > 4) {
            h = 4;
        } else if (h > 1) {
            h = 1;
        } else break;
    }
}
