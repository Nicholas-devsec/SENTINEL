import "hash"

rule sentinel_1ce5558cc258c2882174c3bba8de331ade2a393592d7bf90c3855131be550e72 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "1ce5558cc258c2882174c3bba8de331ade2a393592d7bf90c3855131be550e72"
}
