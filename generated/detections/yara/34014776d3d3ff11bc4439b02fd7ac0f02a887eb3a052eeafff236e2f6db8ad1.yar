import "hash"

rule sentinel_34014776d3d3ff11bc4439b02fd7ac0f02a887eb3a052eeafff236e2f6db8ad1 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "unit42_blog"
  condition:
    hash.sha256(0, filesize) == "34014776d3d3ff11bc4439b02fd7ac0f02a887eb3a052eeafff236e2f6db8ad1"
}
