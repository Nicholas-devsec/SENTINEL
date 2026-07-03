import "hash"

rule sentinel_4ca48fb14e6f26d617c77d219ae5529935bb4893 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "otx"
  condition:
    hash.sha1(0, filesize) == "4ca48fb14e6f26d617c77d219ae5529935bb4893"
}
