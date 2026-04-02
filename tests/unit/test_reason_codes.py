from __future__ import annotations

import pytest

from cve_service.services.reason_codes import (
    REASON_CODE_REGISTRY_VERSION,
    UnknownReasonCodeError,
    reason_code_registry_snapshot,
    validate_reason_codes,
)


def test_reason_code_registry_snapshot_includes_versioned_definitions() -> None:
    codes = validate_reason_codes(["classifier.deny.consumer_only_product"])

    snapshot = reason_code_registry_snapshot(codes)

    assert snapshot == [
        {
            "code": "classifier.deny.consumer_only_product",
            "title": "Consumer Only Product",
            "summary": "The product matches a consumer-only catalog entry and is denied by deterministic policy.",
            "registry_version": REASON_CODE_REGISTRY_VERSION,
        }
    ]


def test_reason_code_registry_rejects_unknown_codes() -> None:
    with pytest.raises(UnknownReasonCodeError):
        validate_reason_codes(["classifier.unknown.code"])
