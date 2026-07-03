import "hash"

rule sentinel_59a260716d05c20229c6a46fe0a2fb5b80fa30c9c73a850222d9d3454426a60a {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "otx"
  condition:
    hash.sha256(0, filesize) == "59a260716d05c20229c6a46fe0a2fb5b80fa30c9c73a850222d9d3454426a60a"
}
