import "hash"

rule sentinel_902f94d7819fa6a65e9ba1d491e8fc7cb3d2bcb15ae1e4a89a065223d815f9f8 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "902f94d7819fa6a65e9ba1d491e8fc7cb3d2bcb15ae1e4a89a065223d815f9f8"
}
