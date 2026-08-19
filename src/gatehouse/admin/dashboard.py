"""Small accessible server-rendered dashboard without secret-bearing views."""

from __future__ import annotations

from collections.abc import Sequence
from html import escape

from .models import AdminStatus, ApprovalView


def render_dashboard(
    *,
    status: AdminStatus,
    approvals: Sequence[ApprovalView],
    csrf_token: str,
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
  </style>
</head>
<body>
  <a class="skip" href="#main">Skip to main content</a>
  <header><h1>Gatehouse local administration</h1></header>
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
  </main>
</body>
</html>"""
