import "hash"

rule sentinel_0542b57b67b021f877969c900214362d62eb2ba56d0645ab4e62838c8c79733a {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "otx"
  condition:
    hash.sha256(0, filesize) == "0542b57b67b021f877969c900214362d62eb2ba56d0645ab4e62838c8c79733a"
}
