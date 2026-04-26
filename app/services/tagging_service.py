"""Rule-based auto-tagging service. Runs during ingestion — fast regex only, no AI."""

import re

from app.models.threat import Threat
from app.rules.tag_rules import URL_RULES, SENDER_RULES, MESSAGE_RULES, FILE_RULES


def apply_auto_tags(threat: Threat) -> list[str]:
    """Evaluate all rule sets against the threat and return deduplicated tag list."""
    tags: set[str] = set()

    # URL rules
    if threat.detected_url:
        for pattern, tag in URL_RULES:
            if re.search(pattern, threat.detected_url, re.IGNORECASE):
                tags.add(tag)

    # Sender rules
    if threat.sender_name:
        for pattern, tag in SENDER_RULES:
            if re.search(pattern, threat.sender_name):
                tags.add(tag)

    # Message rules
    if threat.message_truncated:
        for pattern, tag in MESSAGE_RULES:
            if re.search(pattern, threat.message_truncated, re.IGNORECASE):
                tags.add(tag)

    # File rules
    if threat.detected_file_name:
        ext = threat.detected_file_name.rsplit(".", 1)[-1].lower() if "." in threat.detected_file_name else ""
        for file_ext, tag in FILE_RULES:
            if ext == file_ext:
                tags.add(tag)

    return sorted(tags)
