import "hash"

rule sentinel_62d519d2145d24a251dee3cf9b4b8cd72fb48bdb5697289e38a784e8fffe7003 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "62d519d2145d24a251dee3cf9b4b8cd72fb48bdb5697289e38a784e8fffe7003"
}
