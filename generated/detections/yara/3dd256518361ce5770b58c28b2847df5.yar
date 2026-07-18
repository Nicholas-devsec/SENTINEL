import "hash"

rule sentinel_3dd256518361ce5770b58c28b2847df5 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "3dd256518361ce5770b58c28b2847df5"
}
