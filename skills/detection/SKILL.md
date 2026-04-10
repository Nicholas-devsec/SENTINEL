---
version: 1.0.0
last_updated: 2026-04-08
updated_by: human
---

# Detection Skill

## Output Formats
- Sigma YAML for network_connection logsource
- CrowdStrike IOC API payloads
- KQL for Microsoft Sentinel
- SPL savedsearch definitions
- YARA rules for hash-based indicators

## Template Rules
- Generate detections only for IOCs at or above the configured rule threshold.
- Keep templates deterministic so git diffs are easy to review.

## Templates

### Sigma
```jinja
title: SENTINEL {{ indicator.type | upper }} {{ indicator.value }}
id: {{ indicator.slug }}
status: experimental
logsource:
  product: network
  category: network_connection
detection:
  selection:
    {{ indicator.sigma_field }}: "{{ indicator.value }}"
  condition: selection
fields:
  - Image
  - CommandLine
level: {{ indicator.severity }}
tags:
{% for technique in indicator.mitre_techniques %}
  - attack.{{ technique | lower }}
{% endfor %}
```

### CrowdStrike
```jinja
{
  "type": "{{ indicator.crowdstrike_type }}",
  "value": "{{ indicator.value }}",
  "action": "detect",
  "severity": "{{ indicator.severity }}",
  "platforms": ["windows", "mac", "linux"],
  "description": "SENTINEL generated IOC for {{ indicator.value }}"
}
```

### KQL
```jinja
DeviceNetworkEvents
| where RemoteUrl == "{{ indicator.value }}" or RemoteIP == "{{ indicator.value }}"
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl, RemoteIP
```

### SPL
```jinja
index=main ({{ indicator.spl_field }}="{{ indicator.value }}")
| stats count by host, {{ indicator.spl_field }}
```

### YARA
```jinja
rule sentinel_{{ indicator.slug | replace('-', '_') }} {
  meta:
    description = "SENTINEL generated hash IOC"
    severity = "{{ indicator.severity }}"
  strings:
    $hash = "{{ indicator.value }}"
  condition:
    $hash
}
```

## Git Integration
- Commit generated detection artifacts with traceable messages.
- Preserve analyst-readable filenames and metadata headers.

## Learner Updates
<!-- learner: append here -->
