import "hash"

rule sentinel_38b837cc5fe814ca9580f9029386aa405f8e94df {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "38b837cc5fe814ca9580f9029386aa405f8e94df"
}
