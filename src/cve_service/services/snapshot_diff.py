from __future__ import annotations

from dataclasses import dataclass
from typing import Any

NON_MATERIAL_FIELDS = frozenset({"source_modified_at", "source_published_at", "source_labels"})


@dataclass(frozen=True, slots=True)
class SnapshotDiffResult:
    is_material: bool
    changed_fields: tuple[str, ...]
    material_fields: tuple[str, ...]
    non_material_fields: tuple[str, ...]
    summary: dict[str, Any]


def compare_snapshots(
    previous_payload: dict[str, Any] | None,
    current_payload: dict[str, Any],
) -> SnapshotDiffResult:
    previous = previous_payload or {}
    changed_fields = tuple(sorted(_diff_paths(previous, current_payload)))
    material_fields = tuple(field for field in changed_fields if field.split(".", 1)[0] not in NON_MATERIAL_FIELDS)
    non_material_fields = tuple(field for field in changed_fields if field.split(".", 1)[0] in NON_MATERIAL_FIELDS)

    return SnapshotDiffResult(
        is_material=bool(material_fields),
        changed_fields=changed_fields,
        material_fields=material_fields,
        non_material_fields=non_material_fields,
        summary={
            "changed_fields": list(changed_fields),
            "material_fields": list(material_fields),
            "non_material_fields": list(non_material_fields),
            "change_kind": "material" if material_fields else "non_material",
        },
    )


def _diff_paths(previous: Any, current: Any, prefix: str = "") -> set[str]:
    if isinstance(previous, dict) and isinstance(current, dict):
        paths: set[str] = set()
        for key in sorted(set(previous) | set(current)):
            next_prefix = f"{prefix}.{key}" if prefix else key
            if key not in previous or key not in current:
                paths.add(next_prefix)
                continue
            paths.update(_diff_paths(previous[key], current[key], next_prefix))
        return paths

    if isinstance(previous, list) and isinstance(current, list):
        return set() if previous == current else {prefix}

    return set() if previous == current else {prefix}
