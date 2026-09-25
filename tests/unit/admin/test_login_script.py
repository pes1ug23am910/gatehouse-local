from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from gatehouse.admin.login import LOGIN_SCRIPT

_NODE_HARNESS = r"""
const fs = require('node:fs');
const vm = require('node:vm');
const data = JSON.parse(fs.readFileSync(0, 'utf8'));
const events = [];
const listeners = {};
let value = '';
const input = {
  get value() { return value; },
  set value(next) { events.push('input'); value = next; }
};
const button = {disabled: true};
const message = {textContent: ''};
const form = {addEventListener(name, fn) { listeners['form:' + name] = fn; }};
const nodes = {'admin-login': form, 'login-code': input,
  'login-submit': button, 'login-message': message};
const window = {
  location: {hash: data.fragment, search: data.query || ''},
  history: {replaceState(state, title, path) {
    if (data.historyFailure) throw new Error('synthetic history refusal');
    if (state !== null || title !== '' || path !== '/login') throw new Error('unsafe history');
    events.push('history'); window.location.hash = ''; window.location.search = '';
  }},
  addEventListener(name, fn) { listeners[name] = fn; }
};
const document = {getElementById(id) { return nodes[id]; }};
vm.runInNewContext(data.script, {window, document}, {timeout: 100});
let prevented = 0;
for (const event of data.events || []) {
  const handler = listeners[event];
  if (handler) handler({persisted: true, preventDefault() { prevented++; }});
}
process.stdout.write(JSON.stringify({value, disabled: button.disabled,
  fragment: window.location.hash, query: window.location.search, events, prevented}));
"""


def run_script(tmp_path: Path, **scenario: object) -> dict[str, object]:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required for the browser bootstrap behavior checks")
    completed = subprocess.run(  # noqa: S603 - fixed script with synthetic stdin, no shell
        (node, "--input-type=commonjs", "-e", _NODE_HARNESS),
        input=json.dumps({"script": LOGIN_SCRIPT, **scenario}),
        text=True,
        capture_output=True,
        timeout=5,
        check=False,
        cwd=tmp_path,
        env={"SYSTEMROOT": os.environ["SYSTEMROOT"]} if os.name == "nt" else {},
    )
    assert completed.returncode == 0, completed.stderr
    assert not completed.stderr
    result: dict[str, object] = json.loads(completed.stdout)
    return result


def test_fragment_is_removed_before_form_receives_the_code(tmp_path: Path) -> None:
    code = "a" * 43
    result = run_script(tmp_path, fragment="#code=" + code)
    assert result["value"] == code
    assert result["disabled"] is False
    assert result["fragment"] == result["query"] == ""
    assert result["events"] == ["history", "input"]


@pytest.mark.parametrize(
    "fragment",
    (
        "",
        "#",
        "#code=",
        "#code=" + "a" * 42,
        "#code=" + "a" * 44,
        "#code=" + "a" * 43 + "&code=" + "b" * 43,
        "#code=" + "a" * 43 + "&extra=x",
        "#code=" + "%61" * 43,
        "#code=" + "a" * 42 + "+",
        "#code=" + "a" * 42 + "é",
        "#CODE=" + "a" * 43,
        "#code=" + "a" * 43 + "\n",
    ),
)
def test_malformed_fragment_is_cleared_and_cannot_submit(tmp_path: Path, fragment: str) -> None:
    result = run_script(tmp_path, fragment=fragment)
    assert result["value"] == ""
    assert result["disabled"] is True
    assert result["fragment"] == ""


def test_legacy_query_is_cleared_but_never_used(tmp_path: Path) -> None:
    result = run_script(tmp_path, fragment="", query="?code=" + "a" * 43)
    assert result["query"] == ""
    assert result["value"] == ""
    assert result["disabled"] is True


def test_history_failure_never_enables_login(tmp_path: Path) -> None:
    result = run_script(tmp_path, fragment="#code=" + "a" * 43, historyFailure=True)
    assert result["value"] == ""
    assert result["disabled"] is True


@pytest.mark.parametrize("event", ("pagehide", "pageshow"))
def test_navigation_or_cached_page_restore_clears_capability(tmp_path: Path, event: str) -> None:
    result = run_script(tmp_path, fragment="#code=" + "a" * 43, events=[event])
    assert result["value"] == ""
    assert result["disabled"] is True


def test_only_first_deliberate_submission_is_allowed(tmp_path: Path) -> None:
    result = run_script(
        tmp_path,
        fragment="#code=" + "a" * 43,
        events=["form:submit", "form:submit"],
    )
    assert result["disabled"] is True
    assert result["prevented"] == 1
