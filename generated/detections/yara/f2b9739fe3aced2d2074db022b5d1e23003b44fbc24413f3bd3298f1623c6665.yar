import "hash"

rule sentinel_f2b9739fe3aced2d2074db022b5d1e23003b44fbc24413f3bd3298f1623c6665 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "f2b9739fe3aced2d2074db022b5d1e23003b44fbc24413f3bd3298f1623c6665"
}
