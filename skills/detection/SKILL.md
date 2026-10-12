---
version: 1.0.0
last_updated: 2026-04-08
updated_by: human
---

# Detection Skill

## Output Formats
- Sigma YAML for network_connection logsource
- KQL for Microsoft Sentinel
- SPL savedsearch definitions
- YARA rules for hash-based indicators

## Template Rules
- Generate detections only for IOCs at or above the configured rule threshold.
- Keep templates deterministic so git diffs are easy to review.

## Templates

Template selection is type-aware: the generator looks for `<platform>_<type_class>`
first (type_class is one of ip, domain, url, hash) and falls back to the generic
`<platform>` template. Keep both.

### sigma_ip
```jinja
title: SENTINEL IP indicator {{ indicator.value }}
id: {{ indicator.slug }}
status: experimental
description: Outbound connection to known-bad IP (source: {{ indicator.source }})
logsource:
  category: network_connection
detection:
  selection:
    Initiated: true
    DestinationIp: "{{ indicator.value }}"
  condition: selection
fields:
  - Image
  - DestinationPort
level: {{ indicator.severity }}
tags:
{% for technique in indicator.mitre_techniques %}
  - attack.{{ technique | lower }}
{% endfor %}
```

### sigma_domain
```jinja
title: SENTINEL domain indicator {{ indicator.value }}
id: {{ indicator.slug }}
status: experimental
description: DNS resolution of known-bad domain (source: {{ indicator.source }})
logsource:
  category: dns_query
detection:
  selection:
    QueryName|endswith: "{{ indicator.value }}"
  condition: selection
fields:
  - Image
  - QueryName
level: {{ indicator.severity }}
tags:
{% for technique in indicator.mitre_techniques %}
  - attack.{{ technique | lower }}
{% endfor %}
```

### sigma_url
```jinja
title: SENTINEL URL indicator {{ indicator.value }}
id: {{ indicator.slug }}
status: experimental
description: Web request to known-bad URL (source: {{ indicator.source }})
logsource:
  category: proxy
detection:
  selection:
    c-uri|contains: "{{ indicator.value }}"
  condition: selection
fields:
  - c-uri
  - src_ip
level: {{ indicator.severity }}
tags:
{% for technique in indicator.mitre_techniques %}
  - attack.{{ technique | lower }}
{% endfor %}
```

### sigma_hash
```jinja
title: SENTINEL file hash indicator {{ indicator.value }}
id: {{ indicator.slug }}
status: experimental
description: Execution of file with known-bad {{ indicator.hash_algo | upper }} (source: {{ indicator.source }})
logsource:
  category: process_creation
detection:
  selection:
    Hashes|contains: "{{ indicator.hash_algo | upper }}={{ indicator.value }}"
  condition: selection
fields:
  - Image
  - CommandLine
  - Hashes
level: {{ indicator.severity }}
tags:
{% for technique in indicator.mitre_techniques %}
  - attack.{{ technique | lower }}
{% endfor %}
```

### sigma
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
level: {{ indicator.severity }}
tags:
{% for technique in indicator.mitre_techniques %}
  - attack.{{ technique | lower }}
{% endfor %}
```

### kql_ip
```jinja
DeviceNetworkEvents
| where RemoteIP == "{{ indicator.value }}"
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort
```

### kql_domain
```jinja
union DeviceNetworkEvents, DeviceEvents
| where RemoteUrl has "{{ indicator.value }}" or tostring(AdditionalFields) has "{{ indicator.value }}"
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl
```

### kql_url
```jinja
DeviceNetworkEvents
| where RemoteUrl startswith "{{ indicator.value }}"
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl, RemoteIP
```

### kql_hash
```jinja
DeviceFileEvents
| where {{ indicator.kql_hash_field }} == "{{ indicator.value }}"
| project Timestamp, DeviceName, FileName, FolderPath, {{ indicator.kql_hash_field }}, InitiatingProcessFileName
```

### KQL
```jinja
DeviceNetworkEvents
| where RemoteUrl == "{{ indicator.value }}" or RemoteIP == "{{ indicator.value }}"
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl, RemoteIP
```

### spl_ip
```jinja
index=* sourcetype IN ("firewall", "netflow", "pan:traffic") dest_ip="{{ indicator.value }}"
| stats count min(_time) as first_seen max(_time) as last_seen by src_ip, dest_ip, dest_port
```

### spl_domain
```jinja
index=* sourcetype IN ("dns", "stream:dns") query="*{{ indicator.value }}"
| stats count min(_time) as first_seen max(_time) as last_seen by src_ip, query
```

### spl_url
```jinja
index=* sourcetype IN ("proxy", "bluecoat", "squid") url="{{ indicator.value }}*"
| stats count min(_time) as first_seen max(_time) as last_seen by src_ip, url
```

### spl_hash
```jinja
index=* sourcetype IN ("sysmon", "xmlwineventlog") file_hash="{{ indicator.value }}"
| stats count min(_time) as first_seen max(_time) as last_seen by host, file_name, file_hash
```

### SPL
```jinja
index=main ({{ indicator.spl_field }}="{{ indicator.value }}")
| stats count by host, {{ indicator.spl_field }}
```

### yara_hash
```jinja
import "hash"

rule sentinel_{{ indicator.slug | replace('-', '_') }} {
  meta:
    description = "SENTINEL known-bad file by {{ indicator.hash_algo | upper }}"
    severity = "{{ indicator.severity }}"
    source = "{{ indicator.source }}"
  condition:
    hash.{{ indicator.hash_algo }}(0, filesize) == "{{ indicator.value }}"
}
```

### YARA
```jinja
import "hash"

rule sentinel_{{ indicator.slug | replace('-', '_') }} {
  meta:
    description = "SENTINEL known-bad file by {{ indicator.hash_algo | upper }}"
    severity = "{{ indicator.severity }}"
  condition:
    hash.{{ indicator.hash_algo }}(0, filesize) == "{{ indicator.value }}"
}
```

## Git Integration
- Commit generated detection artifacts with traceable messages.
- Preserve analyst-readable filenames and metadata headers.

## Learner Updates
<!-- learner: append here -->
