import "hash"

rule sentinel_86ee99f293a30720bcc898a4a8e391f93fb9be95 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "otx"
  condition:
    hash.sha1(0, filesize) == "86ee99f293a30720bcc898a4a8e391f93fb9be95"
}
