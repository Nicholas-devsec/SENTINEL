import "hash"

rule sentinel_540028bbd229cc8ce0f531f84e11296870f9b54faa231abb6f5da8557ae3df31 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "unit42_blog"
  condition:
    hash.sha256(0, filesize) == "540028bbd229cc8ce0f531f84e11296870f9b54faa231abb6f5da8557ae3df31"
}
