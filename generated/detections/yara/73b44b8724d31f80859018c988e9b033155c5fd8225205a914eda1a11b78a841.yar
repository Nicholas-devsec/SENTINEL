import "hash"

rule sentinel_73b44b8724d31f80859018c988e9b033155c5fd8225205a914eda1a11b78a841 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "unit42_blog"
  condition:
    hash.sha256(0, filesize) == "73b44b8724d31f80859018c988e9b033155c5fd8225205a914eda1a11b78a841"
}
