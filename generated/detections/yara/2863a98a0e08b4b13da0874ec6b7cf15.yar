import "hash"

rule sentinel_2863a98a0e08b4b13da0874ec6b7cf15 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "2863a98a0e08b4b13da0874ec6b7cf15"
}
