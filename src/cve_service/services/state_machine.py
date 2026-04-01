from __future__ import annotations

from dataclasses import dataclass

from cve_service.models.enums import CveState

FAIL_CLOSED_STATE = CveState.SUPPRESSED

ALLOWED_TRANSITIONS: dict[CveState, set[CveState]] = {
    CveState.DISCOVERED: {CveState.CLASSIFIED, CveState.SUPPRESSED, CveState.ERROR},
    CveState.CLASSIFIED: {
        CveState.ENRICHMENT_PENDING,
        CveState.AI_REVIEW_PENDING,
        CveState.POLICY_PENDING,
        CveState.SUPPRESSED,
        CveState.ERROR,
    },
    CveState.ENRICHMENT_PENDING: {
        CveState.AI_REVIEW_PENDING,
        CveState.POLICY_PENDING,
        CveState.SUPPRESSED,
        CveState.ERROR,
    },
    CveState.AI_REVIEW_PENDING: {CveState.POLICY_PENDING, CveState.SUPPRESSED, CveState.ERROR},
    CveState.POLICY_PENDING: {CveState.PUBLISH_PENDING, CveState.SUPPRESSED, CveState.ERROR},
    CveState.PUBLISH_PENDING: {CveState.PUBLISHED, CveState.ERROR},
    CveState.PUBLISHED: {CveState.UPDATE_PENDING, CveState.ERROR},
    CveState.UPDATE_PENDING: {CveState.PUBLISH_PENDING, CveState.SUPPRESSED, CveState.ERROR},
    CveState.SUPPRESSED: set(),
    CveState.ERROR: set(),
}


class InvalidStateTransition(ValueError):
    """Raised when a requested transition is not allowed."""


@dataclass(frozen=True)
class TransitionDecision:
    current_state: CveState
    requested_state: CveState | None
    resolved_state: CveState
    fail_closed: bool


def coerce_state(requested_state: str | CveState | None) -> TransitionDecision:
    if requested_state is None:
        return TransitionDecision(
            current_state=FAIL_CLOSED_STATE,
            requested_state=None,
            resolved_state=FAIL_CLOSED_STATE,
            fail_closed=True,
        )

    if isinstance(requested_state, CveState):
        return TransitionDecision(
            current_state=requested_state,
            requested_state=requested_state,
            resolved_state=requested_state,
            fail_closed=False,
        )

    try:
        resolved_state = CveState(requested_state)
    except ValueError:
        return TransitionDecision(
            current_state=FAIL_CLOSED_STATE,
            requested_state=None,
            resolved_state=FAIL_CLOSED_STATE,
            fail_closed=True,
        )

    return TransitionDecision(
        current_state=resolved_state,
        requested_state=resolved_state,
        resolved_state=resolved_state,
        fail_closed=False,
    )


def can_transition(current_state: CveState, next_state: CveState) -> bool:
    return next_state in ALLOWED_TRANSITIONS[current_state]


def guard_transition(current_state: CveState, requested_state: str | CveState | None) -> CveState:
    decision = coerce_state(requested_state)
    next_state = decision.resolved_state

    if decision.fail_closed:
        if can_transition(current_state, FAIL_CLOSED_STATE):
            return FAIL_CLOSED_STATE
        raise InvalidStateTransition(f"{current_state} cannot fail closed to {FAIL_CLOSED_STATE}")

    if not can_transition(current_state, next_state):
        raise InvalidStateTransition(f"{current_state} cannot transition to {next_state}")

    return next_state

