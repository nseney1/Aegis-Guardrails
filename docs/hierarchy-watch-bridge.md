# Watch continuation bridge

`tools/hierarchy_watch_bridge.py` defines the external host port used by the
[watch supervisor](hierarchy-watch-supervisor.md). It keeps a native HOLD explicit
where supported authenticated execution and persistent lifetime are unavailable.
It never bootstraps raw RPC, changes permissions, starts another actor, or treats
local JSON as authenticated owner approval.

## Frozen Python contract

`observe(request_id, request_sha256)` returns `state` (`eligible` or `hold`), a
`reason`, and `native_qualified`. `continue_request(request_id, request_sha256,
operation_id)` returns `state`, `effect`, `reason` and `native_qualified`, with an
optional canonical `intent_id`. The valid result pairs are:

| State | Effect | Watch behavior |
|---|---|---|
| `completed` | `confirmed` | Retain result; never redispatch. Acceptance remains separate. |
| `refused` | `none` | May reconsider after fresh eligibility; preserve the operation ID and failed history. |
| `unknown` | `possible` | Hold for explicit canonical settlement; never retry automatically. |

An exception or invalid result after dispatch becomes unknown. A watch operation
ID is only a delivery correlation; it is not a second execution intent.

`OperatorBridge(lifecycle_root, provider, actor, generation, evidence_only=False)`
uses the canonical `Operator(lifecycle_root, provider, evidence_only=...)` and
its `execute(request_id, actor, generation)` API. Evidence-only use is explicit
at both layers. Provider observations use the frozen `qualified`, `mode`,
`source`, `gates` and `reason` contract; `mode` must be `fixture` here. Operator
repeats admission checks under the canonical lock before recording or executing
its one intent. The bridge rechecks the request hash at each call.

The operator provider's `execute(request, intent_id)` returns `outcome`,
`exit_code` and retained `evidence`. Providers are an external boundary supplied
by trusted integration code, not a user-authenticated plugin or a JSON authority
grant. The installed native path remains refused regardless of fixture claims.

## Supported-host qualification matrix

```sh
python3 -I -B tools/hierarchy_watch_bridge.py capabilities --host codex
```

| Host | Available observation evidence | Execution and lifetime verdict |
|---|---|---|
| Codex native UI | Session 1's native observer reads rollout profile provenance. The current UI exposes `read_thread`; a real read returned the existing maintenance thread's active status and recent turn. `send_message_to_thread` metadata describes a 1000 UTF-8-byte prompt limit. | HOLD: no independently qualified persistent observer/continuation executor is installed by this slice. Tool exposure does not establish an authenticated workflow decision boundary. |
| Codex CLI | Installed CLI help exposes `queue` and `exec resume`. Queue help explicitly permits success when requested resume fails. | HOLD: queue acceptance is not execution, read, or persistent executor proof. |
| Claude Code | Installed help exposes background-session controls. Those command names alone do not establish the required same-session continuation contract. | HOLD: provider admission, continuation correlation and persistent lifetime require independent qualification. |
| Other providers | No qualified adapter in this slice. | HOLD: unsupported host. |

The local help and native tool inspection are capability discovery only. The bridge does not run
those commands as a fallback. The model-free watch can poll after its OS launcher
exits, but a fake-host process test cannot establish actual native host survival
after the originating model turn. Source authoring, fixture acceptance, native
execution, recipient delivery/read and independent review remain distinct.

The remaining native work needs a supported authenticated caller/role boundary,
narrow ROOT decision service, provider-specific observation/continuation schema,
per-call source/authority/generation fences, and a separately operated executor
with independently observed lifetime. Missing any of those retains HOLD. Global
permissions and the deployed tools/daemon remain untouched.
