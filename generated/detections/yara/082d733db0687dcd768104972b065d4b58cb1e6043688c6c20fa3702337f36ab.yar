import "hash"

rule sentinel_082d733db0687dcd768104972b065d4b58cb1e6043688c6c20fa3702337f36ab {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "discovery:www.microsoft.com"
  condition:
    hash.sha256(0, filesize) == "082d733db0687dcd768104972b065d4b58cb1e6043688c6c20fa3702337f36ab"
}
