import "hash"

rule sentinel_0f06d82432a719e0079783e595dcd3f8277d1bd7 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "0f06d82432a719e0079783e595dcd3f8277d1bd7"
}
