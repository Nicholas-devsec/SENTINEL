import "hash"

rule sentinel_2904768aeb8bec47852fe5b064e602dbb8bd90ac {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "2904768aeb8bec47852fe5b064e602dbb8bd90ac"
}
