import "hash"

rule sentinel_301e2aa14956cf815b865c0c2ac7de438bad6072720d180118ca777779cb0a65 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "301e2aa14956cf815b865c0c2ac7de438bad6072720d180118ca777779cb0a65"
}
