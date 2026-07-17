import "hash"

rule sentinel_9890950adcbc2478e7a080234f053214adbad44e {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "unit42_blog"
  condition:
    hash.sha1(0, filesize) == "9890950adcbc2478e7a080234f053214adbad44e"
}
