# MChess Pro 8 — Strength Estimate

*Tested 22 November 2026 with fastchess at 10s + 0.1s.*

## Result

**MChess plays at about 2525 Elo on the CCRL Blitz scale on this machine.**

- Combined estimate from 750 games: **2526**, 95% interval **2499–2554** (sampling error only).
- The three anchor engines individually imply 2490, 2563 and 2547, so a realistic range is roughly **2490–2565**.
- That is about 75 Elo below the ~2600 expected before the test.

## Results by opponent

Scores are from MChess's point of view. Anchor ratings are the CCRL Blitz figures in `StashStrength.md`.

| Opponent | Anchor Elo | Games | W | D | L | Score | Elo diff (95% CI) | Implied MChess Elo (95% CI) |
|---|---|---|---|---|---|---|---|---|
| Stash 20.0.1 | 2509 | 250 | 100 | 36 | 114 | 47.2% | −19 (−60 to +21) | 2490 (2449–2530) |
| Stash 21.0 | 2714 | 250 | 59 | 30 | 161 | 29.6% | −151 (−194 to −111) | 2563 (2520–2603) |
| Stash 25.0 | 2937 | 250 | 15 | 18 | 217 | 9.6% | −390 (−461 to −336) | 2547 (2476–2601) |
| **Total** | | **750** | **174** | **84** | **492** | **28.8%** | | **2526 (2499–2554)** |

The combined figure is the maximum-likelihood rating against the three fixed anchors. Confidence intervals use the variance of the paired-game scores, since each opening was played twice with colours reversed.

MChess scored 38.1% as White and 19.5% as Black. The gap is a property of the opening book, not the engine: UHO openings are deliberately unbalanced in White's favour, and the colour-reversed pairs cancel it out.

## How much to trust it

**The anchors disagree slightly.** Against Stash 20 the implied rating is 2490; against Stash 21 it is 2563. That 73-point difference is about 2.5 standard errors, so it is probably not just noise. Seen from MChess, the gap between Stash 20 and Stash 21 is about 130 Elo at this time control, not the 205 in the rating table. Stash 21 and Stash 25 agree with each other (2563 and 2547). The practical effect is that the true uncertainty is wider than the ±27 sampling interval.

**Four games were gifted to MChess on time.** Stash 20 (three times) and Stash 21 (once) overstepped by about 100 ms while living on the increment in very long games. MChess was not winning any of them: two were dead draws, in one Stash was +3.65, and in one MChess's own tablebases showed it being mated. Excluding those four games gives **2523**, so the effect is small.

**MChess itself was fully reliable.** In 790 games (pilot plus main run) it had no time forfeits, no crashes and no illegal moves, and it passed all 40 steps of fastchess's UCI compliance check.

**The time control is much faster than the one behind the anchor ratings.** CCRL Blitz is 2 minutes + 1 second; this test used 10 seconds + 0.1. MChess averaged 0.23 seconds per move and reported a median search depth of 6 (its own depth count, not comparable with Stash's 15–18). Whether MChess gains more or less than Stash from extra time was not tested, so the rating applies to fast games.

**MChess played without its own opening book.** `OwnBook` was left at its default of off and both engines started from the forced UHO positions.

## Test setup

| Item | Setting |
|---|---|
| Engine under test | `mchess.exe` — reports as "MChess Pro 8", author Marty Hirsch |
| MChess options | All defaults: Hash 60 MB (its maximum), OwnBook off, Tablebases on, Ponder off, Move Overhead 30 ms |
| Opponents | Stash 20.0.1, 21.0 and 25.0 (bmi2 builds), Hash 64 MB, one thread |
| Format | Gauntlet, 125 opening pairs per opponent, colours reversed |
| Time control | 10s + 0.1s per move |
| Openings | `UHO.pgn`, random order, seed 7919 |
| Adjudication | None — every game played to mate, draw or flag |
| Concurrency | 8 games at once; each engine uses one core |
| Tournament manager | fastchess alpha 1.8.2 (build 20260726-f618e34) |
| Machine | AMD Ryzen AI 9 HX PRO 375 (12 cores / 24 threads), 64 GB RAM, Windows 11 Pro |
| Duration | 43 minutes; games averaged 27 seconds and 68 moves |

A 40-game pilot against Stash 20 and 21 was run first to check the setup and the choice of anchors. It gave 45.0% and 32.5%, in line with the main run, and is not included in the figures above.

Game terminations in the main run: 662 mates, 84 draws (45 repetition, 20 fifty-move rule, 16 insufficient material, 3 stalemate) and the 4 time forfeits described above.

## Reproducing

All output is in `fastchess-run\`:

| File | Contents |
|---|---|
| `main.pgn` | The 750 games, with score, depth and time for every move |
| `main.out.txt`, `main.log` | fastchess console output and warning log |
| `pilot.pgn`, `pilot.out.txt`, `pilot.log` | The 40-game pilot |
| `analyse.py` | Produces the tables above: `python analyse.py main.pgn [--exclude-forfeits]` |

The command, run from `fastchess-run\` (`%R%` is the benchmark `resources` folder):

```
fastchess.exe
  -engine cmd="..\mchess.exe" name=MChess
  -engine cmd="%R%\engines\stash-20.0.1-windows-x86_64-bmi2.exe" name=Stash-20 option.Hash=64
  -engine cmd="%R%\engines\stash-21.0-windows-x86_64-bmi2.exe"   name=Stash-21 option.Hash=64
  -engine cmd="%R%\engines\stash-25.0-windows-x86_64-bmi2.exe"   name=Stash-25 option.Hash=64
  -each tc=10+0.1 proto=uci
  -tournament gauntlet -seeds 1 -rounds 125 -games 2 -repeat
  -openings file="%R%\fastchess\UHO.pgn" format=pgn order=random -srand 7919
  -concurrency 8 -recover
  -pgnout file=main.pgn -log file=main.log level=warn
```

## Getting a tighter number

- **Add an anchor below 2500.** MChess is currently bracketed only loosely: its closest opponent is Stash 20, and the other two are well above it. Stash 19 (2473) or Stash 18 (~2390) would pin down the lower side.
- **Repeat at a longer time control**, such as 60s + 0.6s, to see whether the rating holds as MChess searches deeper.
