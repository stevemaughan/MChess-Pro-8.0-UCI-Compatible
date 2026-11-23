//! Evaluation state read by eval_pieces_and_kings (src/evalpieces.zig) and the piece-
//! activity pair (src/activity.zig), other than the search position (`Position`). Since
//! Stage B step 6 its fields are declared in `evalvars.EvalVars` (the section "read by
//! evalpieces and activity"), and `EvalState` is that struct.
//!
//! Most of it is built before each search from the root position by prepare_eval
//! (0000:9582, not yet ported) or by the pawn evaluator; these routines only read it.
//! Each field names its original DGROUP address. Another unit may declare some of the
//! same variables; they are to be unified by address.
//!
//! Specification: docs/arch/53-evaluation-pieces-kings.md §3.

/// Activity tables are indexed `[piece][square]` with this order.
pub const Piece = enum(u2) { knight, bishop, rook, queen };

/// The evaluation state of evalpieces and activity is `evalvars.EvalVars` (Stage B step 6):
/// one struct for the evaluation's variables and tables, so that the style flag (1548h)
/// and the passed-pawn masks (A6C2h, 9D8Ch), which the pawn evaluation writes and these
/// routines read, have one home.
pub const EvalState = @import("evalvars.zig").EvalVars;
