from __future__ import annotations

from enum import StrEnum


class CveState(StrEnum):
    DISCOVERED = "DISCOVERED"
    CLASSIFIED = "CLASSIFIED"
    ENRICHMENT_PENDING = "ENRICHMENT_PENDING"
    AI_REVIEW_PENDING = "AI_REVIEW_PENDING"
    POLICY_PENDING = "POLICY_PENDING"
    PUBLISH_PENDING = "PUBLISH_PENDING"
    PUBLISHED = "PUBLISHED"
    UPDATE_PENDING = "UPDATE_PENDING"
    SUPPRESSED = "SUPPRESSED"
    ERROR = "ERROR"


class EvidenceSignal(StrEnum):
    POC = "POC"
    ITW = "ITW"
    OTHER = "OTHER"


class EvidenceStatus(StrEnum):
    UNKNOWN = "UNKNOWN"
    ABSENT = "ABSENT"
    PRESENT = "PRESENT"


class ClassificationOutcome(StrEnum):
    CANDIDATE = "CANDIDATE"
    DENY = "DENY"
    NEEDS_AI = "NEEDS_AI"
    DEFER = "DEFER"


class AIReviewOutcome(StrEnum):
    ADVISORY_PUBLISH = "ADVISORY_PUBLISH"
    ADVISORY_SUPPRESS = "ADVISORY_SUPPRESS"
    ADVISORY_DEFER = "ADVISORY_DEFER"
    INVALID = "INVALID"


class PolicyDecisionOutcome(StrEnum):
    PUBLISH = "PUBLISH"
    SUPPRESS = "SUPPRESS"
    DEFER = "DEFER"


class PublicationEventType(StrEnum):
    INITIAL = "INITIAL"
    UPDATE = "UPDATE"
    SUPPRESS = "SUPPRESS"


class AuditActorType(StrEnum):
    SYSTEM = "SYSTEM"
    USER = "USER"
    WORKER = "WORKER"
    AI = "AI"

