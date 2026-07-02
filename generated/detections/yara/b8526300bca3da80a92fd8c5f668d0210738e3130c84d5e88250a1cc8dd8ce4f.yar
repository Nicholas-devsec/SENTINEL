import "hash"

rule sentinel_b8526300bca3da80a92fd8c5f668d0210738e3130c84d5e88250a1cc8dd8ce4f {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "b8526300bca3da80a92fd8c5f668d0210738e3130c84d5e88250a1cc8dd8ce4f"
}
