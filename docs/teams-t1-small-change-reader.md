# Teams T1 small-change request reader

The source-checkout command `python tools/hierarchy_lifecycle.py inspect-request
--file <absolute JSON>` inspects declarations without loading a lifecycle journal.
An optional global `--root` is ignored for inspection. Existing commands still
require it. This reader neither publishes requests nor grants execution authority.
It does not run checks, reserve capacity, or authenticate actor identities.

Input is either an unchanged lifecycle v1 `{raw, sha256}` envelope or this closed
declaration envelope. `request.raw` is the original JSON text, including whitespace;
both hashes must match those exact UTF-8 bytes. Do not reserialize a historical
request to bind a plan to it.

```json
{
  "schema": "aegis.small-change-plan/v1",
  "request": {"raw": "<original lifecycle v1 JSON text>", "sha256": "<raw hash>"},
  "plan": {
    "request_sha256": "<same raw hash>",
    "projects": ["project-id"],
    "writing_lanes": [{"lane": "lane-id", "writer": "writer-cid"}],
    "path_scopes": [["/absolute/project/approved/path"]],
    "checks": ["declared-check-id"],
    "reviewer": "reviewer-cid",
    "shared_interface_change": false,
    "migration": false,
    "governance_change": false,
    "budget_expansion": false,
    "scope_certain": true
  }
}
```

Project, lane, writer, Reviewer and check IDs use lifecycle slug syntax. Paths use
the existing absolute, traversal-free, symlink-free path contract; one path scope
may contain several paths. All declaration fields are required. Collections are
bounded at 256 entries, and each path scope must be nonempty. Duplicate projects,
checks, lane IDs, writers or paths within a scope refuse. Unknown fields,
nonboolean risk declarations, malformed JSON, unsupported schemas and hash
mismatches return a structured HOLD with exit 2 and `execution_enabled=false`.

A syntactically valid inspection exits 0 with schema `aegis.request-inspection/v1`.
One project, one writing lane, one path scope exactly matching the request's path
set, nonempty declared checks and a distinct declared Reviewer permit
`classification=declared_eligible`. This includes a declaration that the scope
has approval; the reader does not verify that claim. All other valid plans return
`classification=full_planning_required` with every applicable reason, in this order:

- `project_count`, `writing_lane_count`, `path_scope_count`, `path_scope_mismatch`
- `checks_missing`, `writer_reviewer_conflict`
- `shared_interface_change`, `migration`, `governance_change`, `budget_expansion`, `uncertain_scope`

Bare historical v1 requests return `full_planning_required` and `plan_missing`.
Approval and checks admission are always `not_evaluated`.
Reviewer independence is `not_declared`, `declared_distinct` or `conflict`;
`reviewer_authenticated` and `execution_enabled` are always false. These are
declarations, including project membership and risk flags, rather than a source
diff analysis, authority decision, recipe admission or proof of independence.

This is a reader-first contract, not the complete small-change workflow. V1
drafting, publication, admission and historical replay remain unchanged; the plan
envelope cannot be published as a lifecycle request. ROOT and Router retain their
execution refusals. Routing still targets the Orchestrator and team startup still
creates it. A later slice must bind approval and authenticated admission to the
exact plan and source, then connect deterministic dispatch through routing/jobs.
Do not omit the Orchestrator before that delivery path exists.

## Slice acceptance ledger

Base: PR #281 merge `6841e72cd9db4f4d8e4803715118e24b01a22548`, tree
`00e3a0f6b6729583861b9bcb6e20af84a2773c93`, equal to tested candidate
`6d5c36d75c032102cfb4cd39978d1c03dc9d56fc`. The PR targets
`feature/manager-workspace-prototype`; PR #259 remains open against `develop`.
Selecting this implementation base does not refresh any active runtime source pin.

| Gate | Evidence |
|---|---|
| Implementation | Reader contract above; no request writer or dispatch change |
| Independent review | Pending final source review |
| Local verification | Public RED observed: command missing; GREEN and full suite pending final snapshot |
| Prior hosted qualification | [Run 42372069458](https://github.com/nseney1/Aegis-Guardrails/actions/runs/42372069458) still running at initial reconciliation; no completion inferred |
| This candidate hosted tests | Pending publication and dispatch |
| Native behavior, installed runtime, efficiency, owner acceptance | Open; no native/provider/Stormheir/M1 exit-gate run |

The MCP registration rejected absolute isolated-worktree paths outside its
registered workspace. A relative-path scan supplied repository guidance from the
original checkout, not worktree qualification. No approval or fitness credit is
claimed. Historical corpus bytes, job identities, reservations, recovery holds,
cumulative accounting and the approved five-team capacity are unchanged.

Remaining T1: approved deterministic small-change dispatch, complete fresh-thread
composition and continuity qualification. Remaining T4: workspace/proposal
integration and compatibility qualification. T0 and T2/T3/T5 acceptance gates
remain open independently of this slice.
