import "hash"

rule sentinel_20c993a491b065c511467b7e4af628781c4ef0a417d15cf5863f82f22d43e484 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "20c993a491b065c511467b7e4af628781c4ef0a417d15cf5863f82f22d43e484"
}
