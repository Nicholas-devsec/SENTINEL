import "hash"

rule sentinel_998bd82470d28954e1882c08a5b0cc22daa5112a {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "998bd82470d28954e1882c08a5b0cc22daa5112a"
}
