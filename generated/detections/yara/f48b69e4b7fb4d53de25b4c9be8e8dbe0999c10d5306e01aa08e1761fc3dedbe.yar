import "hash"

rule sentinel_f48b69e4b7fb4d53de25b4c9be8e8dbe0999c10d5306e01aa08e1761fc3dedbe {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "otx"
  condition:
    hash.sha256(0, filesize) == "f48b69e4b7fb4d53de25b4c9be8e8dbe0999c10d5306e01aa08e1761fc3dedbe"
}
