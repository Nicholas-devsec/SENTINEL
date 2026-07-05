import "hash"

rule sentinel_ba37105a276d86e128bf737c1386e6cc {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "ba37105a276d86e128bf737c1386e6cc"
}
