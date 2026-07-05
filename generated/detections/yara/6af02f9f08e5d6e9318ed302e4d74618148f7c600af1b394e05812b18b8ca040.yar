import "hash"

rule sentinel_6af02f9f08e5d6e9318ed302e4d74618148f7c600af1b394e05812b18b8ca040 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "6af02f9f08e5d6e9318ed302e4d74618148f7c600af1b394e05812b18b8ca040"
}
