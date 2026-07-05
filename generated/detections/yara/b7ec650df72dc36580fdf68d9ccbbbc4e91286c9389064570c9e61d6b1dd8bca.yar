import "hash"

rule sentinel_b7ec650df72dc36580fdf68d9ccbbbc4e91286c9389064570c9e61d6b1dd8bca {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "b7ec650df72dc36580fdf68d9ccbbbc4e91286c9389064570c9e61d6b1dd8bca"
}
