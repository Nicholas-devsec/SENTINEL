import "hash"

rule sentinel_2db9b397d98c55c8a7be695d747d251c {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "2db9b397d98c55c8a7be695d747d251c"
}
