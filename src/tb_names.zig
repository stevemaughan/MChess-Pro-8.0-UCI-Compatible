//! The tablebase materials of the "cd" set beyond the six shipped files (owner decision 33;
//! docs/arch/41-tablebases.md, "The four-man tablebases"): the 30 materials of
//! reference/tablebases/m80-cd whose files passed the checks against the rules of chess,
//! every one there but KPPK and KPKP. Each has a `.TBW` and a `.TBB` file, embedded
//! zstd-compressed from reference/extracted/tablebases/ (build.zig, src/engine_data.zig).
//! Read by build.zig too, so the list is in one place.

pub const cd_stems = [_][]const u8{
    "KBK",  "KNK",
    "KQQK", "KQRK",
    "KQBK", "KQNK",
    "KQPK", "KRRK",
    "KRBK", "KRNK",
    "KRPK", "KBBK",
    "KBNK", "KBPK",
    "KNNK", "KNPK",
    "KQKQ", "KQKR",
    "KQKB", "KQKN",
    "KQKP", "KRKR",
    "KRKB", "KRKN",
    "KRKP", "KBKB",
    "KBKN", "KBKP",
    "KNKN", "KNKP",
};

comptime {
    if (cd_stems.len != 30) @compileError("the cd set has 30 materials beyond the shipped three");
}
