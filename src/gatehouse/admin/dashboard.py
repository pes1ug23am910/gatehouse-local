"""Small accessible server-rendered dashboard without secret-bearing views."""

from __future__ import annotations

from collections.abc import Sequence
from html import escape

from .models import AdminStatus, ApprovalView, RunawayQuarantineView

_FIRECRAWL_BURST_OPERATIONS = (
    "firecrawl.search",
    "firecrawl.scrape",
    "firecrawl.map",
    "firecrawl.crawl.start",
    "firecrawl.crawl.status",
    "firecrawl.crawl.cancel",
)


def render_dashboard(
    *,
    status: AdminStatus,
    approvals: Sequence[ApprovalView],
    csrf_token: str,
    runaway_quarantines: Sequence[RunawayQuarantineView] = (),
) -> str:
    rows: list[str] = []
    for approval in approvals:
        common = (
            f'<input type="hidden" name="csrf_token" value="{escape(csrf_token)}">'
            f'<input type="hidden" name="action_token" '
            f'value="{escape(approval.action_token)}">'
            f'<input type="hidden" name="request_fingerprint" '
            f'value="{escape(approval.request_fingerprint)}">'
            f'<input type="hidden" name="maximum_estimated_cost" '
            f'value="{approval.maximum_estimated_cost}">'
            '<input type="hidden" name="maximum_uses" value="1">'
        )
        approval_id = escape(approval.approval_id)
        actions = (
            f'<form method="post" action="/dashboard/approvals/{approval_id}/approve">'
            f'{common}<button type="submit">Approve once</button></form>'
            f'<form method="post" action="/dashboard/approvals/{approval_id}/deny">'
            f'{common}<button type="submit">Deny</button></form>'
        )
        rows.append(
            "<tr>"
            f'<th scope="row">{approval_id}</th>'
            f"<td>{escape(approval.client_id)}</td>"
            f"<td>{escape(approval.service)}.{escape(approval.operation)}</td>"
            f"<td>{escape(approval.target_summary)}</td>"
            f"<td>{approval.maximum_estimated_cost}</td>"
            f"<td>{actions}</td>"
            "</tr>"
        )
    approval_rows = "".join(rows) or '<tr><td colspan="6">No pending approvals.</td></tr>'
    runaway_rows: list[str] = []
    for quarantine in runaway_quarantines:
        quarantine_id = escape(quarantine.quarantine_id)
        common = (
            f'<input type="hidden" name="csrf_token" value="{escape(csrf_token)}">'
            f'<input type="hidden" name="action_token" '
            f'value="{escape(quarantine.action_token)}">'
            f'<input type="hidden" name="expected_generation" '
            f'value="{quarantine.generation}">'
        )
        known_operations = (
            _FIRECRAWL_BURST_OPERATIONS
            if quarantine.service == "firecrawl"
            else (quarantine.trigger_operation,)
        )
        operation_controls = "".join(
            '<label class="operation-choice">'
            f'<input type="checkbox" name="operations" value="{escape(operation)}"'
            f"{' checked' if operation == quarantine.trigger_operation else ''}>"
            f"{escape(operation)}</label>"
            for operation in known_operations
        )
        authorize = (
            f'<form method="post" action="/dashboard/runaway-quarantines/'
            f'{quarantine_id}/authorize">'
            f"{common}"
            '<label>Reason <input name="reason" maxlength="500" required '
            'value="Operator approved a bounded burst"></label>'
            '<label>Duration (ms) <input type="number" name="duration_ms" '
            'min="1" max="900000" value="300000" required></label>'
            '<label>Requests <input type="number" name="maximum_requests" '
            'min="1" max="25" value="10" required></label>'
            '<label>Credits <input type="number" name="maximum_credits" '
            'min="1" max="100" value="25" required></label>'
            '<label>Concurrency <input type="number" name="maximum_concurrency" '
            'min="1" max="8" value="2" required></label>'
            f"<fieldset><legend>Typed operations</legend>{operation_controls}</fieldset>"
            '<button type="submit">Authorize bounded burst</button></form>'
        )
        deny = (
            f'<form method="post" action="/dashboard/runaway-quarantines/'
            f'{quarantine_id}/deny">{common}'
            '<label>Reason <input name="reason" maxlength="500" required '
            'value="Operator denied the burst"></label>'
            '<button type="submit">Deny and keep blocked</button></form>'
        )
        recover = (
            f'<form method="post" action="/dashboard/runaway-quarantines/'
            f'{quarantine_id}/recover">{common}'
            '<input type="hidden" name="confirmation" value="RECOVER_FRESH_RUN">'
            "<p><strong>Fresh-run recovery revokes the old session and ends its root run.</strong> "
            "It succeeds only when no burst permit, ambiguous work, or live external resource "
            "remains. It does not transfer bounded burst authority.</p>"
            '<label>Reason <input name="reason" maxlength="500" required '
            'value="Operator confirmed the old run is safe to close"></label>'
            '<button type="submit">Close old run and allow a fresh run</button></form>'
        )
        if quarantine.fresh_run_recovery_id is None:
            actions = f"{authorize}{deny}{recover}"
            recovery_status = "Not recovered"
        else:
            actions = "Fresh-run recovery complete; this generation has no further actions."
            recovery_status = f"Recovered at {quarantine.fresh_run_recovered_at_ms}"
        remaining = (
            "Not authorized"
            if quarantine.remaining_requests is None or quarantine.remaining_credits is None
            else (
                f"{quarantine.remaining_requests} requests / {quarantine.remaining_credits} credits"
            )
        )
        runaway_rows.append(
            "<tr>"
            f'<th scope="row">{quarantine_id}</th>'
            f"<td>{escape(quarantine.client_id)}</td>"
            f"<td>{escape(quarantine.root_run_id)}</td>"
            f"<td>{escape(quarantine.trigger)}</td>"
            f"<td>{escape(quarantine.trigger_operation)}</td>"
            f"<td>{escape(quarantine.state)}</td>"
            f"<td>{escape(remaining)}</td>"
            f"<td>{escape(recovery_status)}</td>"
            f"<td>{actions}</td>"
            "</tr>"
        )
    runaway_body = "".join(runaway_rows) or (
        '<tr><td colspan="9">No runaway quarantines.</td></tr>'
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Gatehouse local administration</title>
  <style>
    body {{ font: 1rem system-ui, sans-serif; max-width: 80rem; margin: auto; padding: 1rem; }}
    .skip {{ position: absolute; left: -9999px; }} .skip:focus {{ left: 1rem; }}
    dl {{ display: grid; grid-template-columns: max-content 1fr; gap: .5rem 1rem; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #777; padding: .5rem; text-align: left; }}
    form {{ display: inline; margin-right: .5rem; }} button {{ min-height: 2.5rem; }}
    form label, fieldset {{ display: block; margin: .25rem 0; }}
    .operation-choice {{ white-space: nowrap; }}
  </style>
</head>
<body>
  <a class="skip" href="#main">Skip to main content</a>
  <header><h1>Gatehouse local administration</h1></header>
  <nav aria-label="Diagnostics">
    <a href="/v1/admin/audit.md">Download recent audit events (Markdown)</a>
    <a href="/v1/admin/lifecycle">View lifecycle diagnostics</a>
  </nav>
  <main id="main">
    <section aria-labelledby="status-heading">
      <h2 id="status-heading">Status</h2>
      <dl>
        <dt>Service state</dt><dd>{escape(status.service_state)}</dd>
        <dt>Active sessions</dt><dd>{status.active_sessions}</dd>
        <dt>In flight</dt><dd>{status.in_flight_requests}</dd>
        <dt>Queued</dt><dd>{status.queued_requests}</dd>
        <dt>High-severity incidents</dt><dd>{status.high_severity_incidents}</dd>
      </dl>
    </section>
    <section aria-labelledby="approvals-heading">
      <h2 id="approvals-heading">Pending approvals</h2>
      <table>
        <caption>Request-bound approvals; each approval is usable once.</caption>
        <thead><tr><th>ID</th><th>Client</th><th>Operation</th><th>Target</th>
        <th>Maximum cost</th><th>Actions</th></tr></thead>
        <tbody>{approval_rows}</tbody>
      </table>
    </section>
    <section aria-labelledby="runaway-heading">
      <h2 id="runaway-heading">Runaway quarantines</h2>
      <p>The offender is blocked at its exact session/root and new runs for the same client
      profile are also blocked. Burst authorization remains exact-root, time-, request-, credit-,
      operation-, and concurrency-bounded. A prompt cannot recover a fresh run; only this local
      authenticated administrative surface can do so after the old run is safe to close.</p>
      <table>
        <caption>
          Durable runaway quarantines, bounded burst decisions, and fenced recovery.
        </caption>
        <thead><tr><th>ID</th><th>Client</th><th>Root run</th><th>Trigger</th>
        <th>Trigger operation</th><th>State</th><th>Remaining</th><th>Recovery</th>
        <th>Actions</th></tr></thead>
        <tbody>{runaway_body}</tbody>
      </table>
    </section>
  </main>
</body>
</html>"""
