import "hash"

rule sentinel_2393affaacf65a5fe1755315d581cf0a {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "2393affaacf65a5fe1755315d581cf0a"
}
