import "hash"

rule sentinel_eb5ec9fca46e31da933f3a52aed3e483aec25e59c7540b89740fbe6dc19b0bc8 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "otx"
  condition:
    hash.sha256(0, filesize) == "eb5ec9fca46e31da933f3a52aed3e483aec25e59c7540b89740fbe6dc19b0bc8"
}
