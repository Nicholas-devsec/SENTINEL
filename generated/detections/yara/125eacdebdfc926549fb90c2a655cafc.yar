import "hash"

rule sentinel_125eacdebdfc926549fb90c2a655cafc {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "125eacdebdfc926549fb90c2a655cafc"
}
