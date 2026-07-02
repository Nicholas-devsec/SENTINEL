import "hash"

rule sentinel_cb998078ed0aedf3de3ee34aff231339d701b14982809df14f6b382610a835eb {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "cb998078ed0aedf3de3ee34aff231339d701b14982809df14f6b382610a835eb"
}
