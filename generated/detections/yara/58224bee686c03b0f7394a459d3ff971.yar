import "hash"

rule sentinel_58224bee686c03b0f7394a459d3ff971 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "58224bee686c03b0f7394a459d3ff971"
}
