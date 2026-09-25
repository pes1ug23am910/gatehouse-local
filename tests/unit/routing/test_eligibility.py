"""Pure contract checks for explicit local route assessments, without dispatch."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import FrozenInstanceError, fields
from types import SimpleNamespace
from typing import cast

import pytest

from gatehouse.core.clock import MAX_UTC_MS
from gatehouse.core.ids import CredentialId, PoolId, PrincipalId, QuotaScopeId
from gatehouse.core.provider_numbers import SQLITE_INT64_MAX
from gatehouse.core.states import CredentialState
from gatehouse.providers.base import OperationSpec
from gatehouse.providers.firecrawl.adapter import FirecrawlAdapter
from gatehouse.routing import eligibility
from gatehouse.routing.eligibility import (
    LocalRouteAssessment,
    LocalRouteReason,
    LocalRouteResult,
    LocalRouteStatus,
    WorkloadRouteRequirement,
    assess_local_routes,
)
from gatehouse.routing.models import (
    NamedPool,
    PoolMember,
    PoolSelectionStrategy,
    QuotaScopeSnapshot,
    QuotaScopeState,
    RouteCandidate,
    RoutingCredential,
    RoutingPlan,
)
from gatehouse.routing.router import (
    AffinityUnavailableError,
    NamedPoolRouter,
    NoEligibleCredentialError,
    NoEligiblePoolError,
)

_NOW = 100
_ID = "00000000000000000000000001"
_OTHER_ID = "00000000000000000000000002"
_POOL = "interactive-default"
_INVALID_INPUT = "local route assessment inputs are invalid"
_DETAIL = "untrusted-provider-detail"
_DEFAULT = object()


def _requirement(
    operation: str = "firecrawl.search", *, pool_name: str = _POOL
) -> WorkloadRouteRequirement:
    return WorkloadRouteRequirement(pool_name, operation)


def _router(pool_name: str = _POOL, *, remaining: int = SQLITE_INT64_MAX) -> NamedPoolRouter:
    principal = PrincipalId(f"prn_{_ID}")
    scope_id = QuotaScopeId(f"quota_{_ID}")
    scope = QuotaScopeSnapshot(
        quota_scope_id=scope_id,
        principal_id=principal,
        service_id="firecrawl",
        unit="credits",
        last_known_remaining_units=remaining,
    )
    credential = RoutingCredential(
        credential_id=CredentialId(f"cred_{_ID}"),
        principal_id=principal,
        quota_scope_id=scope_id,
        generation=1,
    )
    pool = NamedPool(
        pool_id=PoolId(f"pool_{_ID}"),
        name=pool_name,
        service_id="firecrawl",
        selection_strategy=PoolSelectionStrategy.CHEAPEST_FIRST,
        members=(PoolMember(scope=scope, credentials=(credential,)),),
    )
    return NamedPoolRouter((pool,))


def _valid_plan() -> RoutingPlan:
    return _router().plan(
        service_id="firecrawl",
        operation="firecrawl.search",
        pool_name=_POOL,
        estimated_cost_units=1,
        unit="credits",
        now_ms=_NOW,
    )


def _unchecked[T](record: T, **changes: object) -> T:
    """Model a malformed injected result without weakening production constructors."""
    duplicate = object.__new__(type(record))
    for field in fields(record):  # type: ignore[arg-type]
        object.__setattr__(
            duplicate, field.name, changes.get(field.name, getattr(record, field.name))
        )
    return duplicate


def _candidate_plan(candidate: RouteCandidate) -> RoutingPlan:
    return _unchecked(_valid_plan(), candidates=(candidate,))


class _Planner:
    def __init__(self, *outcomes: object, remaining: int = SQLITE_INT64_MAX) -> None:
        self.outcomes = list(outcomes)
        self.remaining = remaining
        self.calls: list[dict[str, object]] = []

    def plan(self, **kwargs: object) -> RoutingPlan:
        self.calls.append(dict(kwargs))
        outcome = self.outcomes.pop(0) if self.outcomes else _DEFAULT
        if isinstance(outcome, BaseException):
            raise outcome
        if outcome is not _DEFAULT:
            return cast(RoutingPlan, outcome)
        router = _router(cast(str, kwargs["pool_name"]), remaining=self.remaining)
        return router.plan(**kwargs)  # type: ignore[arg-type]

    def reserve(self, **kwargs: object) -> None:
        raise AssertionError("assessment must not reserve")

    def dispatch(self, **kwargs: object) -> None:
        raise AssertionError("assessment must not dispatch")

    def refresh(self, **kwargs: object) -> None:
        raise AssertionError("assessment must not refresh")

    def try_acquire(self, **kwargs: object) -> None:
        raise AssertionError("assessment must not acquire a lease or breaker permit")


def _assert_unverified(plan: object) -> None:
    planner = _Planner(plan)
    requirement = _requirement()
    assessment = assess_local_routes(planner, (requirement,), now_ms=_NOW)
    assert assessment == LocalRouteAssessment(
        _NOW,
        (
            LocalRouteResult(
                requirement,
                LocalRouteStatus.UNVERIFIED,
                LocalRouteReason.ASSESSMENT_UNVERIFIED,
            ),
        ),
    )
    assert assessment.status is LocalRouteStatus.UNVERIFIED
    assert len(planner.calls) == 1
    assert _DETAIL not in repr(assessment)


def test_records_are_immutable_and_do_not_retain_a_mutable_attribute_dictionary() -> None:
    requirement = _requirement()
    result = LocalRouteResult(
        requirement, LocalRouteStatus.ELIGIBLE, LocalRouteReason.LOCAL_ROUTE_AVAILABLE
    )
    assessment = LocalRouteAssessment(_NOW, (result,))
    for record, field, value in (
        (requirement, "pool_name", "replacement"),
        (result, "status", LocalRouteStatus.UNVERIFIED),
        (assessment, "observed_at_ms", _NOW + 1),
    ):
        with pytest.raises(FrozenInstanceError):
            setattr(record, field, value)
        assert not hasattr(record, "__dict__")


@pytest.mark.parametrize(
    "operation,cost",
    [
        ("firecrawl.search", 1),
        ("firecrawl.scrape", 1),
        ("firecrawl.map", 1),
        ("firecrawl.crawl.start", 25),
    ],
)
def test_actual_operation_cost_and_exact_named_pool_are_forwarded_without_effects(
    operation: str, cost: int
) -> None:
    planner = _Planner()
    requirement = _requirement(operation)
    assessment = assess_local_routes(planner, (requirement,), now_ms=_NOW)
    assert planner.calls == [
        {
            "service_id": "firecrawl",
            "operation": operation,
            "pool_name": _POOL,
            "estimated_cost_units": cost,
            "unit": "credits",
            "now_ms": _NOW,
            "affinity": None,
            "automatic": True,
            "reconciliation": False,
        }
    ]
    assert type(planner.calls[0]["estimated_cost_units"]) is int
    assert assessment.observed_at_ms == _NOW
    assert assessment.results == (
        LocalRouteResult(
            requirement, LocalRouteStatus.ELIGIBLE, LocalRouteReason.LOCAL_ROUTE_AVAILABLE
        ),
    )
    assert assessment.status is LocalRouteStatus.ELIGIBLE


def test_real_router_distinguishes_search_from_crawl_start_cost() -> None:
    planner = _Planner(remaining=24)
    assessment = assess_local_routes(
        planner, (_requirement(), _requirement("firecrawl.crawl.start")), now_ms=_NOW
    )
    assert [result.status for result in assessment.results] == [
        LocalRouteStatus.ELIGIBLE,
        LocalRouteStatus.INELIGIBLE,
    ]
    assert assessment.results[1].reason is LocalRouteReason.ROUTE_REFUSED
    assert assessment.status is LocalRouteStatus.INELIGIBLE


def test_batch_preserves_order_and_one_supplied_observation_time() -> None:
    planner = _Planner(_DEFAULT, NoEligiblePoolError(_DETAIL), RuntimeError(_DETAIL))
    requirements = (
        _requirement(),
        _requirement("firecrawl.scrape"),
        _requirement("firecrawl.map"),
    )
    assessment = assess_local_routes(planner, requirements, now_ms=_NOW)
    assert tuple(result.requirement for result in assessment.results) == requirements
    assert [result.status for result in assessment.results] == [
        LocalRouteStatus.ELIGIBLE,
        LocalRouteStatus.INELIGIBLE,
        LocalRouteStatus.UNVERIFIED,
    ]
    assert [call["now_ms"] for call in planner.calls] == [_NOW, _NOW, _NOW]
    assert assessment.status is LocalRouteStatus.UNVERIFIED
    assert _DETAIL not in repr(assessment)


def test_empty_requirements_are_unverified_without_consulting_planner() -> None:
    planner = _Planner()
    assessment = assess_local_routes(planner, (), now_ms=_NOW)
    assert assessment.observed_at_ms == _NOW
    assert assessment.results == ()
    assert assessment.status is LocalRouteStatus.UNVERIFIED
    assert planner.calls == []


def test_exact_requirement_limit_and_maximum_identifier_length_are_accepted() -> None:
    requirements = tuple(_requirement(pool_name=f"pool-{index}") for index in range(31))
    requirements += (_requirement(pool_name="a" * 100),)
    planner = _Planner()
    assessment = assess_local_routes(planner, requirements, now_ms=MAX_UTC_MS)
    assert len(planner.calls) == len(assessment.results) == 32
    assert assessment.status is LocalRouteStatus.ELIGIBLE
    assert all(call["now_ms"] == MAX_UTC_MS for call in planner.calls)


class _StringSubclass(str):
    pass


class _IntSubclass(int):
    pass


class _TupleSubclass(tuple[object, ...]):
    pass


@pytest.mark.parametrize(
    "pool_name",
    [
        "",
        "a" * 101,
        " interactive-default",
        "interactive-default ",
        "interactive-default\n",
        "Interactive-default",
        "interactive/default",
        "interactive--default",
        "emergency-locked",
        _StringSubclass(_POOL),
        None,
    ],
)
def test_invalid_pool_spelling_is_refused_without_normalization_or_planning(
    pool_name: object,
) -> None:
    planner = _Planner()
    requirement = WorkloadRouteRequirement(pool_name, "firecrawl.search")  # type: ignore[arg-type]
    with pytest.raises(ValueError) as caught:
        assess_local_routes(planner, (requirement,), now_ms=_NOW)
    assert str(caught.value) == _INVALID_INPUT
    assert planner.calls == []


@pytest.mark.parametrize(
    "operation",
    [
        "firecrawl.crawl.status",
        "firecrawl.crawl.cancel",
        "firecrawl.account.credit_status",
        "firecrawl.unknown",
        "a" * 81,
        " firecrawl.search",
        _StringSubclass("firecrawl.search"),
        None,
    ],
)
def test_only_explicit_new_work_operations_are_assessable(operation: object) -> None:
    planner = _Planner()
    requirement = WorkloadRouteRequirement(_POOL, operation)  # type: ignore[arg-type]
    with pytest.raises(ValueError) as caught:
        assess_local_routes(planner, (requirement,), now_ms=_NOW)
    assert str(caught.value) == _INVALID_INPUT
    assert planner.calls == []


@pytest.mark.parametrize(
    "kind",
    ["list", "generator", "tuple_subclass", "overflow", "duplicate", "foreign", "late_invalid"],
)
def test_entire_bounded_immutable_batch_is_validated_before_first_plan(kind: str) -> None:
    requirement = _requirement()
    invalid: object
    if kind == "list":
        invalid = [requirement]
    elif kind == "generator":

        def values() -> Iterator[WorkloadRouteRequirement]:
            raise AssertionError("a generator must not be consumed")
            yield requirement  # type: ignore[unreachable]  # Retain the deliberately unconsumable generator.

        invalid = values()
    elif kind == "tuple_subclass":
        invalid = _TupleSubclass((requirement,))
    elif kind == "overflow":
        invalid = tuple(_requirement(pool_name=f"pool-{index}") for index in range(33))
    elif kind == "duplicate":
        invalid = (requirement, _requirement())
    elif kind == "foreign":
        invalid = (SimpleNamespace(pool_name=_POOL, operation="firecrawl.search"),)
    else:
        invalid = (requirement, WorkloadRouteRequirement("bad/path", "firecrawl.map"))
    planner = _Planner()
    with pytest.raises(ValueError) as caught:
        assess_local_routes(planner, invalid, now_ms=_NOW)  # type: ignore[arg-type]
    assert str(caught.value) == _INVALID_INPUT
    assert planner.calls == []


@pytest.mark.parametrize("now_ms", [True, 100.0, -1, MAX_UTC_MS + 1, _IntSubclass(_NOW)])
def test_invalid_observation_time_is_refused_before_planning(now_ms: object) -> None:
    planner = _Planner()
    with pytest.raises(ValueError) as caught:
        assess_local_routes(planner, (_requirement(),), now_ms=now_ms)  # type: ignore[arg-type]
    assert str(caught.value) == _INVALID_INPUT
    assert planner.calls == []


@pytest.mark.parametrize(
    "failure,status,reason",
    [
        (NoEligiblePoolError(_DETAIL), LocalRouteStatus.INELIGIBLE, LocalRouteReason.POOL_REFUSED),
        (
            NoEligibleCredentialError(_DETAIL),
            LocalRouteStatus.INELIGIBLE,
            LocalRouteReason.ROUTE_REFUSED,
        ),
        (
            AffinityUnavailableError(_DETAIL),
            LocalRouteStatus.UNVERIFIED,
            LocalRouteReason.ASSESSMENT_UNVERIFIED,
        ),
        (
            RuntimeError(_DETAIL),
            LocalRouteStatus.UNVERIFIED,
            LocalRouteReason.ASSESSMENT_UNVERIFIED,
        ),
        (ValueError(_DETAIL), LocalRouteStatus.UNVERIFIED, LocalRouteReason.ASSESSMENT_UNVERIFIED),
    ],
)
def test_planner_failures_have_fixed_safe_classifications(
    failure: Exception, status: LocalRouteStatus, reason: LocalRouteReason
) -> None:
    assessment = assess_local_routes(_Planner(failure), (_requirement(),), now_ms=_NOW)
    assert assessment.status is status
    assert assessment.results[0].reason is reason
    assert _DETAIL not in repr(assessment)


@pytest.mark.parametrize("failure", [KeyboardInterrupt(_DETAIL), SystemExit(7)])
def test_planner_control_flow_is_propagated(failure: BaseException) -> None:
    planner = _Planner(failure)
    with pytest.raises(type(failure)) as caught:
        assess_local_routes(planner, (_requirement(),), now_ms=_NOW)
    assert caught.value is failure
    assert len(planner.calls) == 1


@pytest.mark.parametrize("cost", [25.0, SQLITE_INT64_MAX])
def test_registry_integer_cost_is_derived_without_a_second_hardcoded_cost_table(
    monkeypatch: pytest.MonkeyPatch, cost: int | float
) -> None:
    operation = "firecrawl.crawl.start"
    spec = _unchecked(FirecrawlAdapter.operation_spec(operation), default_estimated_cost=cost)
    lookups: list[str] = []

    def operation_spec(selected: str) -> OperationSpec:
        lookups.append(selected)
        return spec

    monkeypatch.setattr(
        eligibility, "FirecrawlAdapter", SimpleNamespace(operation_spec=operation_spec)
    )
    planner = _Planner()
    assessment = assess_local_routes(planner, (_requirement(operation),), now_ms=_NOW)
    assert assessment.status is LocalRouteStatus.ELIGIBLE
    assert lookups == [operation]
    assert type(planner.calls[0]["estimated_cost_units"]) is int
    assert planner.calls[0]["estimated_cost_units"] == int(cost)


@pytest.mark.parametrize(
    "kind",
    [
        "foreign",
        "name",
        "unit",
        "boolean",
        "zero",
        "negative",
        "fractional",
        "infinity",
        "nan",
        "overflow",
        "rounded_overflow",
        "subclass",
    ],
)
def test_invalid_registry_spec_is_unverified_before_planning(
    monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    spec: object = FirecrawlAdapter.operation_spec("firecrawl.search")
    values = {
        "boolean": True,
        "zero": 0,
        "negative": -1,
        "fractional": 1.5,
        "infinity": float("inf"),
        "nan": float("nan"),
        "overflow": SQLITE_INT64_MAX + 1,
        "rounded_overflow": float(SQLITE_INT64_MAX),
        "subclass": _IntSubclass(1),
    }
    if kind == "foreign":
        spec = SimpleNamespace(
            name="firecrawl.search", cost_unit="credits", default_estimated_cost=1
        )
    elif kind == "name":
        spec = _unchecked(spec, name="firecrawl.scrape")
    elif kind == "unit":
        spec = _unchecked(spec, cost_unit="requests")
    else:
        spec = _unchecked(spec, default_estimated_cost=values[kind])
    monkeypatch.setattr(
        eligibility, "FirecrawlAdapter", SimpleNamespace(operation_spec=lambda operation: spec)
    )
    planner = _Planner()
    assessment = assess_local_routes(planner, (_requirement(),), now_ms=_NOW)
    assert assessment.status is LocalRouteStatus.UNVERIFIED
    assert assessment.results[0].reason is LocalRouteReason.ASSESSMENT_UNVERIFIED
    assert planner.calls == []


@pytest.mark.parametrize(
    "failure",
    [RuntimeError(_DETAIL), NoEligiblePoolError(_DETAIL), KeyboardInterrupt(_DETAIL)],
)
def test_registry_failure_is_sanitized_or_propagates_control_flow(
    monkeypatch: pytest.MonkeyPatch, failure: BaseException
) -> None:
    def operation_spec(operation: str) -> OperationSpec:
        raise failure

    monkeypatch.setattr(
        eligibility, "FirecrawlAdapter", SimpleNamespace(operation_spec=operation_spec)
    )
    planner = _Planner()
    if isinstance(failure, Exception):
        assessment = assess_local_routes(planner, (_requirement(),), now_ms=_NOW)
        assert assessment.status is LocalRouteStatus.UNVERIFIED
        assert _DETAIL not in repr(assessment)
    else:
        with pytest.raises(type(failure)) as caught:
            assess_local_routes(planner, (_requirement(),), now_ms=_NOW)
        assert caught.value is failure
    assert planner.calls == []


@pytest.mark.parametrize(
    "kind",
    [
        "foreign",
        "tuple",
        "length",
        "request",
        "candidate",
        "identity",
        "credential",
        "quota",
        "ranking",
    ],
)
def test_malformed_successful_plan_is_unverified(kind: str) -> None:
    plan = _valid_plan()
    candidate = plan.candidates[0]
    scope = candidate.scope
    credential = candidate.credential
    malformed: list[object]
    if kind == "foreign":
        malformed = [
            None,
            True,
            SimpleNamespace(**{field.name: getattr(plan, field.name) for field in fields(plan)}),
        ]
    elif kind == "tuple":
        malformed = [
            _unchecked(plan, candidates=list(plan.candidates)),
            _unchecked(plan, candidates=_TupleSubclass(plan.candidates)),
        ]
    elif kind == "length":
        malformed = [
            _unchecked(plan, candidates=()),
            _unchecked(plan, candidates=plan.candidates * 33),
        ]
    elif kind == "request":
        malformed = [
            _unchecked(plan, **{field: value})
            for field, value in (
                ("pool_name", "other-pool"),
                ("service_id", "other"),
                ("operation", "firecrawl.map"),
                ("estimated_cost_units", 25),
                ("estimated_cost_units", True),
                ("estimated_cost_units", 1.0),
                ("unit", "requests"),
                ("automatic_failover_within_pool", 1),
            )
        ]
    elif kind == "candidate":
        malformed = [
            _unchecked(plan, candidates=(SimpleNamespace(),)),
            _candidate_plan(_unchecked(candidate, scope=SimpleNamespace())),
            _candidate_plan(_unchecked(candidate, credential=SimpleNamespace())),
            _candidate_plan(_unchecked(candidate, pool_name="other-pool")),
            _candidate_plan(_unchecked(candidate, service_id="other")),
            _unchecked(plan, candidates=(candidate, candidate)),
        ]
    elif kind == "identity":
        malformed = [
            _unchecked(plan, pool_id=str(plan.pool_id)),
            _candidate_plan(_unchecked(candidate, pool_id=PoolId(f"pool_{_OTHER_ID}"))),
            _candidate_plan(
                _unchecked(
                    candidate,
                    scope=_unchecked(scope, principal_id=PrincipalId(f"prn_{_OTHER_ID}")),
                )
            ),
            _candidate_plan(
                _unchecked(
                    candidate,
                    credential=_unchecked(
                        credential, quota_scope_id=QuotaScopeId(f"quota_{_OTHER_ID}")
                    ),
                )
            ),
            _candidate_plan(
                _unchecked(
                    candidate,
                    credential=_unchecked(credential, credential_id=str(credential.credential_id)),
                )
            ),
            _candidate_plan(_unchecked(candidate, scope=_unchecked(scope, service_id="other"))),
        ]
    elif kind == "credential":
        malformed = [
            _candidate_plan(
                _unchecked(candidate, credential=_unchecked(credential, **{field: value}))
            )
            for field, value in (
                ("state", "HEALTHY"),
                ("state", CredentialState.QUARANTINED),
                ("expires_at_ms", _NOW),
                ("expires_at_ms", True),
                ("generation", True),
                ("generation", 0),
                ("generation", SQLITE_INT64_MAX + 1),
            )
        ]
    elif kind == "quota":
        malformed = [
            _candidate_plan(_unchecked(candidate, scope=_unchecked(scope, **{field: value})))
            for field, value in (
                ("state", "HEALTHY"),
                ("state", QuotaScopeState.DISABLED),
                ("last_known_remaining_units", None),
                ("last_known_remaining_units", 0),
                ("last_known_remaining_units", True),
                ("last_known_remaining_units", SQLITE_INT64_MAX + 1),
                ("configured_floor_units", -1),
                ("active_reserved_units", 1.0),
                ("unit", "requests"),
                ("cooldown_until_ms", _NOW + 1),
                ("cooldown_until_ms", True),
            )
        ]
    else:
        malformed = [
            _candidate_plan(_unchecked(candidate, **{field: value}))
            for field in ("priority", "cost_rank")
            for value in (True, -1, SQLITE_INT64_MAX + 1)
        ]
    for returned in malformed:
        _assert_unverified(returned)


def test_every_candidate_must_be_coherent_even_when_first_candidate_is_eligible() -> None:
    plan = _valid_plan()
    candidate = plan.candidates[0]
    bad = _unchecked(
        candidate,
        credential=_unchecked(
            candidate.credential,
            credential_id=CredentialId(f"cred_{_OTHER_ID}"),
            expires_at_ms=_NOW,
        ),
    )
    _assert_unverified(_unchecked(plan, candidates=(candidate, bad)))


@pytest.mark.parametrize("contradictory", [False, True])
def test_shared_scope_credentials_require_one_coherent_scope_snapshot(
    contradictory: bool,
) -> None:
    plan = _valid_plan()
    candidate = plan.candidates[0]
    second = _unchecked(
        candidate,
        credential=_unchecked(
            candidate.credential, credential_id=CredentialId(f"cred_{_OTHER_ID}")
        ),
        scope=(
            _unchecked(candidate.scope, last_known_remaining_units=100)
            if contradictory
            else candidate.scope
        ),
    )
    returned = _unchecked(plan, candidates=(candidate, second))
    if contradictory:
        _assert_unverified(returned)
    else:
        assessment = assess_local_routes(_Planner(returned), (_requirement(),), now_ms=_NOW)
        assert assessment.status is LocalRouteStatus.ELIGIBLE


def test_represented_expiry_and_cooldown_boundaries_accept_only_current_eligibility() -> None:
    plan = _valid_plan()
    candidate = plan.candidates[0]
    candidate = _unchecked(
        candidate,
        credential=_unchecked(candidate.credential, expires_at_ms=_NOW + 1),
        scope=_unchecked(
            candidate.scope,
            last_known_remaining_units=16,
            configured_floor_units=10,
            active_reserved_units=5,
            cooldown_until_ms=_NOW,
        ),
    )
    assessment = assess_local_routes(
        _Planner(_candidate_plan(candidate)), (_requirement(),), now_ms=_NOW
    )
    assert assessment.status is LocalRouteStatus.ELIGIBLE
    _assert_unverified(
        _candidate_plan(
            _unchecked(candidate, scope=_unchecked(candidate.scope, active_reserved_units=6))
        )
    )
