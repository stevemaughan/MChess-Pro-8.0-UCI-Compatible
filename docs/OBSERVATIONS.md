# Observations: quirks to preserve

Behaviour of the original that looks odd, accidental or weak, and that the rewrite keeps on purpose (AGENTS.md §2.2, §9.1 class D). Each entry names the specification that holds the detail. A quirk that turns out to be a coding error with clear evidence of intent moves to `DEVIATIONS.md` as class C.

Status of every entry: **found 2026-11-17, to be confirmed when the routine is ported.**

## Position and make/unmake (`docs/arch/20-position-make-unmake.md`)

- **Stale square map after en passant.** The captured pawn's square keeps its old entry in the square-to-slot map (`DG:A28C`).
- **Castling does not update the opponent king's ray map.**
- **Unmake does not restore everything.** The per-ply records (en-passant square, check, reversible, quiet) stay as the move set them. The hash keys are restored by the search node, which copies back 12 saved bytes; unmake does not touch them.
- **Unmake writes 80h or 0 into the caller's "captured slot" byte.**

## Search (`docs/arch/30-search-node.md`)

- **The hash move can be searched twice** in one node (seen 6 times in the traced runs).
- **Stale extension bits for the hash move.** They are read from the shared entry buffer at `DG:77FE`, which the node's descendants have overwritten after a null move (559 of 732 traced cases).
- **A slot is replaced by depth alone**, comparing with the depth the probe found there, even when the slot held a different position.
- **A stopped node still stores its partial result** in the hash table.
- **The "in check" test at `0000:1C76` ignores pawns.**
- **A move that undoes this side's previous move is capped at −1.**
- **A node searches at most 100 moves** (found 2026-11-21, DEV-063). `gen_all_moves` keeps its scored moves (captures that do not lose, marked moves, some checks and threats) sorted, then the first unscored ones in the order generated, up to 100 in all (`1E9D:48D8`–`4913`); the others are never searched. It needs a position of more than 100 pseudo-legal moves: 218 is the most a legal position has, and there the original searches 100 (`tests/golden/manymoves.jsonl`). The rewrite keeps the limit and only stops the writes past the list (`docs/DEVIATIONS.md`, DEV-063).

## Evaluation (`docs/arch/50-evaluation-map.md`)

- **The piece sum drifts after castling.** `update_square_sums` does not update the rook's square value when castling, so the running sum at `DG:7182` is off by ±8 or ±20 from then on in that line.
- **The evaluation depends on the root position.** The per-square tables are rebuilt before every search from the position at the root, the castling state, the game phase, the style and which side the program plays. The same position can score differently in two searches. This is design, not a defect, and the rewrite must build the same tables at the same moments.
- **Normal and Aggressive styles appear identical in the evaluation.** Not yet explained.

## How a position was reached (`docs/arch/23-position-setup.md`)

- **The same position searches differently by route.** "New game" writes the start position with the g1 and g8 knights in piece-list slot 0. A position entered through Setup is scanned from a1 upwards, which puts the b1 and b8 knights there. Move order follows slot order, and the book flag and the move number also differ and feed the evaluation's tables. After 1.e4, a depth-5 search made 61,815 moves from New game and 131,712 from Setup; both replied 1...e5. The rewrite uses the new-game route for `position startpos moves ...` and the set-up route for `position fen ...`, even for the start position's own FEN.
- **Setup takes castling rights from the board alone.** It offers no input for castling rights, the en-passant square or the move counters. A king and rook on their home squares can castle.
- **Promoted pieces take the pawns' slots after the pawns**, in the order knight, bishop, rook, queen. Bishops are assigned to slots by the colour of their square, not by where they stand.

## When a move is played (`docs/arch/34-game-move-path.md`)

- **Auto-play and normal play leave different state.** After each of its own moves in normal play the program runs `set_predicted_reply` (`38C0:0D22`), which rebuilds the evaluation tables and writes several engine variables; in auto-play it does not. The rewrite must follow normal play.
- **The same position is searched differently in normal play and in auto-play**, because the hash tables are sometimes kept from the previous search, and that search was the program's own previous move in normal play and the other side's move in auto-play. The rewrite must follow whichever the game is; a UCI game against an opponent is normal play.
- **When a predicted reply is replaced, its captured piece comes from the first best reply in generation order.**
- **The repetition count reads the last-irreversible ply as the previous search left it** (`DG:7464`).
- **The score history is kept with learning off** (`DG:251E`, `2516`, `251A`).
- **New game clears tables that belong to other parts of the engine**: the leaf map `DG:8FE4` and eight 200-byte evaluation tables.
- **The irreversible-move flags are 406 bytes long** (`DG:3490`–`3625`), not 256.

## Before the search (`docs/arch/33-root-preparation.md`)

- **The hash tables survive some moves.** They are cleared before a search unless the flag bytes of the last two game plies (`DG:3490 + ply − 2` and `− 1`, which the evaluation specification calls the irreversible-move flags) are both set and three other conditions hold; then the tables of the previous search are used as they stand, with no ageing. This was so in 9 of 48 recorded searches. What sets those flags is specified with the game-move path.
- **The move marks are cleared twice per search**, 4,990 bytes each time (`1E9D:54CE`).
- **A root move is tested for legality through the leaf attack map**, and a legal move scores 0 in pre-scoring when no material is left or the opponent is stalemated.

## Tablebases (`docs/arch/41-tablebases.md`)

- **Tablebase endings are played without the search.** With five men or fewer the root scores each move from the tablebase. If any move wins by the tablebase, or every root move was scored from it, the program plays at once: the highest score wins and ties go to the first move in the root list. No search node runs, and make_move is called once per root move. This holds for the defending side and for drawn pawn endings too.
- **In a drawn tablebase position it plays the first move in the list, whatever that move gives away.** With White's king on e2 and pawn on e3 against a king on e5, the position is a draw, so by the root's rule every move ties and the first is played: the program played e3-e4 without searching and lost the pawn at once (`tests/golden/corpus2.jsonl`, scenario `kpk-d4`). The result of the game is the same; the play looks careless.
- **The search itself does not probe the tablebases with the default setting.** Only the root does. The search's probes need a setting the menus reach only with "Dynamic" tablebases and an additional path (DEV-032 in `DEVIATIONS.md`).
- **A move scored from the tablebase skips the legality test and the repetition count** that searched root moves get.

## The opening book (`docs/arch/40-opening-book.md`)

- **The book's choice is random**, drawn from the C library's `rand()`, seeded from the BIOS tick count at start-up and at each new game. The rewrite's generator is the same, with the seed an explicit input.
- **About 173,000 of the book's 389,947 index entries cannot be reached from the start position** by the book's own moves. Not explained.

## Not kept: the search's dependence on memory layout

- The unmodified original's fixed-depth search varies with machine speed and load address, because two routines read stack bytes they never wrote. These are bugs and are fixed (DEV-003 and DEV-015 in `DEVIATIONS.md`), by the owner's decision of 2026-11-17. They are listed here only so that nobody goes looking for the variation in the rewrite.

## Time (`docs/arch/31-root-iteration-time.md`)

- **"N seconds per move" is not a per-move limit.** It is run as a repeating control of 60 moves in 60 × N seconds (40 moves for N of 60 or more).
- **One budget term depends on machine speed.** On leaving the book the program adds 3400 divided by a start-up speed calibration (`DG:7258`) ticks.
- **The hash tables shrink to 160 KB** when the base time for a move is under 91 ticks (5 seconds).
