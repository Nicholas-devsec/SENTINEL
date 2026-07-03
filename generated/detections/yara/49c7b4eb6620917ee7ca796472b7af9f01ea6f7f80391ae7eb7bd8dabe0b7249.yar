import "hash"

rule sentinel_49c7b4eb6620917ee7ca796472b7af9f01ea6f7f80391ae7eb7bd8dabe0b7249 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "otx"
  condition:
    hash.sha256(0, filesize) == "49c7b4eb6620917ee7ca796472b7af9f01ea6f7f80391ae7eb7bd8dabe0b7249"
}
