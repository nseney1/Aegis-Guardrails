# Aegis project rules

These rules govern development of Aegis itself. The separate `rules/` catalog ships to adopters. This project catalog uses the released rule format; it does not introduce the planned 4.6 mining/proposal workflow.

## Format and enforcement

Store one Markdown file at `<type-directory>/<id>.md`, with matching frontmatter `id` and `type`. The six directories are `invariants/`, `traps/`, `gates/`, `boundaries/`, `personas/` and `contracts/`. Set a valid domain, a concrete hypothesis/prediction and nonempty `target_paths`; the type schema and loader define required metadata. Fitness is derived from the ledger and must not be authored.

A `gate` or `invariant` is mandatory for JIT selection; declaring a tier does not create an executable code check. Supported `forbid_ast` patterns supply deterministic AST enforcement. Workflow invariants retain their review/release obligations. Prose-only traps use advisory enforcement so they do not occupy mandatory slots without a corresponding deterministic check.

Place a complete actionable instruction at the start of `## Do`, within the current 300-character Detail window. Keep source/test references in `## Evidence` after the instruction paragraphs. The current scanner projects its first eight body lines, so evidence must remain beyond that prefix; the proposed 4.6 structural projection is not assumed available.

## Delivery and coverage

Matching and selection are different checks. Default JIT selection has three total slots and at most two mandatory slots, plus a serialized token limit. Fitness, exact paths and matched-file counts participate in ranking. Do not invent rank/fitness metadata or raise budgets to make a catalog test pass.

`tests/unit/core/test_project_rule_delivery.py` copies the project-prefixed catalog into a clean, cold-start workspace and exercises the real scan API. It requires focused contracts to appear under default limits and baseline guidance for metadata/future paths. The advisory baseline targets `**`; specific rules remain responsible for subsystem guidance.

Machine-local untracked personas and configuration are not part of this committed project catalog. Validate a clean tracked export to keep those local files from changing the candidate being reviewed. Existing worktrees receive rule changes through their normal branch integration.

Binding-rule edits are still anchored to the reviewed base during a live scan. Catalog tests describe the reviewed candidate after acceptance; they do not bypass approval or claim that branch-local mandatory edits already bind an agent.

## Focused contracts

| Rule | First instruction |
| --- | --- |
| [contract-workspace-session-binding](contracts/contract-workspace-session-binding.md) | Bind scans and writes to the explicitly resolved workspace and server session; conflicting or ambiguous host, registry or file roots must hold without silently switching projects. |
| [contract-witnessed-outcome-credit](contracts/contract-witnessed-outcome-credit.md) | Derive outcome credit from witnessed checks, current content and server-owned scan exposure; caller claims, persisted exposure rows and echoed rule IDs cannot manufacture verified success. |
| [contract-ast-driver-lifecycle](contracts/contract-ast-driver-lifecycle.md) | Run only trusted AST driver plans with bounded requests, responses, diagnostics and deadlines; correlate each response, poison broken sessions and clean up owned processes on every exit path. |
| [contract-ast-semantic-fidelity](contracts/contract-ast-semantic-fidelity.md) | Preserve language meaning across normalized ASTs: distinguish unknown from false, honor source encodings and lexical binding, and never treat unsupported or failed analysis as a clean code verdict. |
| [contract-redaction-before-output](contracts/contract-redaction-before-output.md) | Apply the shared bounded redactor before persisting or exposing sensitive text; malformed, oversized or incomplete secret material must not escape through excerpts, diagnostics or truncation. |
| [contract-atomic-storage-boundaries](contracts/contract-atomic-storage-boundaries.md) | Use the established atomic/locked storage APIs with explicit symlink and permission semantics; reject unsafe destinations without overwriting valid data or exposing partial/private artifacts. |
| [contract-jit-rule-delivery](contracts/contract-jit-rule-delivery.md) | Validate rule loading, matching and actual default-budget JIT delivery separately; a rule that exists or matches is not guaranteed to be served, and prose guidance is not deterministic code enforcement. |
| [persona-check-local-performance](personas/persona-check-local-performance.md) | Reuse one coherent ledger view and check-local AST results, including failures; bound retained data and driver startup while preserving fresh evidence between separate calls. |
| [persona-change-scoped-validation](personas/persona-change-scoped-validation.md) | Match validation to the changed behavior and owner instructions: rule/docs changes need loader, JIT, metadata/link and governance checks; runtime changes need the affected behavioral suites and release gates. |
| [persona-repository-baseline](personas/persona-repository-baseline.md) | Preserve Aegis trust boundaries, evidence integrity and owner-approved workflow; read the affected public contract, verify the relevant outcome and keep unrelated work intact. |

## Repairs and approval

The 4.5 project repair keeps existing IDs and types, updates stale ledger/command/parity guidance, narrows workflow rules to their actual process surfaces, and reclassifies fourteen prose-only trap gates as advisory. Existing human merge/release restrictions and independent-review requirements remain.

Tier reductions and narrowed scopes are governance weakenings even when they improve JIT delivery. The PR must receive the existing maintainer approval for its exact final diff. Agents must not create approval signatures. The live governance check, not this README or the local catalog test, decides whether the approval requirement is satisfied.

For docs/rule changes, validate metadata, concise projection, actual JIT delivery, relevant links and the governance diff. Runtime changes additionally need behavioral/regression suites appropriate to their changed surfaces and the approved release plan.
