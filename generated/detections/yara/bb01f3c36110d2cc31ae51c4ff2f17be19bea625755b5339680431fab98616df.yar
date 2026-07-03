import "hash"

rule sentinel_bb01f3c36110d2cc31ae51c4ff2f17be19bea625755b5339680431fab98616df {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "otx"
  condition:
    hash.sha256(0, filesize) == "bb01f3c36110d2cc31ae51c4ff2f17be19bea625755b5339680431fab98616df"
}
