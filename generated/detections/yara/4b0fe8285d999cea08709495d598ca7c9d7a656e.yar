import "hash"

rule sentinel_4b0fe8285d999cea08709495d598ca7c9d7a656e {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "4b0fe8285d999cea08709495d598ca7c9d7a656e"
}
