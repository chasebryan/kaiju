# Kaiju IR

Kaiju IR is planned for a later milestone. It should be backend-independent,
explicit about side effects, and useful for data-flow analysis and eventual
decompilation.

The initial IR model will include:

- modules
- functions
- basic blocks
- instructions
- expressions
- values
- temporaries
- register references
- memory loads and stores
- branches, calls, and returns

No instruction lifting is implemented in the current foundation phase.

## Current Implementation

Phase 9 added the initial `kaiju-ir` crate. The model includes modules,
functions, basic blocks, instructions, expressions, and values. It is still a
structural IR, not a decompiler IR with SSA, type recovery, or complete flag
semantics.

The pretty printer emits a compact text form:

```text
fn sub_401000 @ 0x0000000000401000 {
block_401000:
  rbp = rsp
  ret
}
```

Phase 10 added a minimal x86-64 lifter over Kaiju's normalized instruction
model. It handles simple register moves, arithmetic and logic assignments,
placeholder flag updates for `cmp` and `test`, direct branches, conditional
branches, calls, returns, and stack-shaped `push`/`pop` placeholders. Unknown
or unsupported instructions lower to `unknown` instead of failing the lift.

Current limitations:

- no SSA construction
- no typed registers or memory spaces
- no precise x86 flags model
- no stack pointer tracking
- no memory operand lowering beyond placeholders
- no decompiler pipeline
