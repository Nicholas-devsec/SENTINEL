import "hash"

rule sentinel_6906e4395bc38d607d969c0699c73492 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "6906e4395bc38d607d969c0699c73492"
}
