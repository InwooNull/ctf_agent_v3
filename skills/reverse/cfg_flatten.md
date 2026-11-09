# Control-flow flattening

## When this fits
One function is huge and shaped like `while (1) { switch (state) { case A: ...; state =
B; break; case B: ...; } }`. There is a single **dispatcher** at the top, a **state
variable** (often `int`-sized, reassigned at the end of each block), and the real basic
blocks are scattered as `switch` cases with no natural if/else nesting. OLLVM and similar
obfuscators produce exactly this. Sometimes the state transitions are themselves computed
(a next-state array, or arithmetic on the state var) to hide the order.

## Procedure (our words)
1. **Identify the dispatcher and the state variable.** The dispatcher is the block all
   cases return to; the state var is what it switches on and what each case writes before
   jumping back. Note its initial value.
2. **Enumerate the blocks.** For each `case`/state value, record: what it computes, and
   what it sets the state var to next (the successor). Watch for conditional successors
   (the block picks next-state based on a comparison — that is a real `if`).
3. **Rebuild the real CFG.** Chain blocks by their successors starting from the initial
   state. The result is the de-obfuscated function: a normal sequence/branches. Now the
   logic (and the input check) is readable.
4. **Recover the input.** Once de-flattened the check is usually a `constraints.md`
   problem (per-byte comparisons) — solve it. If de-flattening by hand is too big, hand
   it to **angr** and let it find the path.

## angr on flattening (guarded)
Flattening is the canonical **veritesting** case: many short blocks merging back to one
dispatcher is where angr's state-merging pays off.
```
import angr
proj = angr.Project(path, auto_load_libs=False)
sm = proj.factory.simulation_manager(state)          # state with bounded symbolic input
sm.use_technique(angr.exploration_techniques.Veritesting())
sm.explore(find=WIN_ADDR, avoid=FAIL_ADDRS, n=400)   # cap; flattening needs more steps
```
- Veritesting (`veritesting=True` on the sim manager, or the technique) is what keeps the
  dispatcher loop from fanning out into thousands of states.
- Still give `avoid` (the reject block) — without it the dispatcher re-entry explodes.
- If it won't converge: de-flatten the *hot* region by hand to shrink the search, then let
  angr finish the arithmetic.

## Failure signals → what to do
- State count explodes immediately → you didn't bound the input, or no `avoid`; the
  dispatcher is looping over all states. Add both, add Veritesting.
- angr finds a path but the input is garbage → the "win" address is a decoy, or the real
  check is after it; re-read the end of the function.
- The state transitions are encrypted/arithmetic → compute the transition table manually
  first (it is small), then the order falls out.

## Not this
A normal function with ordinary if/else/loops is not flattened — don't force this frame.
Flattening is specifically the one-dispatcher, state-variable shape.
