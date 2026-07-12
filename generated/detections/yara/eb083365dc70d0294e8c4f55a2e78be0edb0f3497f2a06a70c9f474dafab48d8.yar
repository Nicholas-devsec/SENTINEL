import "hash"

rule sentinel_eb083365dc70d0294e8c4f55a2e78be0edb0f3497f2a06a70c9f474dafab48d8 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "gbhackers_blog"
  condition:
    hash.sha256(0, filesize) == "eb083365dc70d0294e8c4f55a2e78be0edb0f3497f2a06a70c9f474dafab48d8"
}
