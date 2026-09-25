# Local workload-route assessment

Date: 2026-09-10

Status: Accepted

Structural catalog validation does not prove that an explicit workload operation has an eligible
local route. Credentials, quota authority, held usage, floors and breaker capacity may make every
candidate in a structurally valid pool unavailable. An arbitrary pool or zero-cost probe cannot
represent the configured workload.

Introduce a bounded read-only assessment for explicit canonical pool/operation requirements at
one supplied UTC time. Derive the cost and unit from the code-owned operation specification, and
use the existing planner with automatic new-work selection and no affinity or reconciliation.
Only search, scrape, map and crawl start belong to this initial contract. Existing zero-cost
resource status/cancel/reconciliation behavior is unchanged.

Return immutable eligible, ineligible or unverified results with fixed reasons. Validate all
requirements before planning. Empty requirements cannot establish eligibility. Refuse malformed
returned plans, inconsistent represented candidate facts and unknown errors without exposing raw
exceptions or credential identifiers. A catalog candidate-limit refusal is reported as a pool
refusal, not evidence of a specific missing resource. An oversized returned plan is unverified.

This helper calls only the planner. It does not reserve quota, acquire permits or leases, refresh
observations, dispatch, repair state or report health. It trusts planner enforcement of facts not
represented in the returned plan, including member/pool policy, durable authority and breakers.
Sequential observations at a supplied time are neither one coherent transaction nor a joint
capacity reservation across operations.

Health integration remains separate. It must derive operation coverage from verified client,
workspace and purpose policy; distinguish control availability from workload eligibility; and
define when expiry or other state changes trigger reassessment. Local eligibility is not policy
authorization, provider reachability, future reservation success or normal-use readiness.

Focused fake-backed and fresh synthetic SQLite tests must verify refusal/cost boundaries and the
absence of durable-state or breaker-permit changes. Native and installed/live proof remain separate.
