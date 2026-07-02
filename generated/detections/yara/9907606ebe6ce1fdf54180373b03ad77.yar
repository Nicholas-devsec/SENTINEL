import "hash"

rule sentinel_9907606ebe6ce1fdf54180373b03ad77 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "9907606ebe6ce1fdf54180373b03ad77"
}
