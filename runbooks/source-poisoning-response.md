# Source Poisoning Response

## Trigger

Use this runbook when an upstream source appears compromised, malicious, spoofed, or systematically unreliable.

## Immediate Actions

1. Isolate the source adapter.
2. Stop new evidence from that source from increasing confidence.
3. Mark impacted evidence records for review and potential downgrade.
4. Recalculate affected candidates with the poisoned source removed.

## Containment Rules

- do not allow suspect evidence to create publishable state
- preserve original records and mark them as quarantined rather than deleting them
- log source trust changes as versioned policy or source-quality changes

## Recovery

1. Restore the source only after authenticity and integrity checks pass.
2. Replay affected CVEs with current source trust weights.
3. Issue update or suppression corrections if prior publishes materially changed.
