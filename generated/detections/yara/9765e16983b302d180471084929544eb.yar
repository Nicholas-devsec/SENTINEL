import "hash"

rule sentinel_9765e16983b302d180471084929544eb {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "9765e16983b302d180471084929544eb"
}
