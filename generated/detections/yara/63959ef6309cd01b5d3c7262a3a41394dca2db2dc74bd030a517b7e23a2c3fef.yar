import "hash"

rule sentinel_63959ef6309cd01b5d3c7262a3a41394dca2db2dc74bd030a517b7e23a2c3fef {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "medium"
    source = "discovery:gbhackers.com"
  condition:
    hash.sha256(0, filesize) == "63959ef6309cd01b5d3c7262a3a41394dca2db2dc74bd030a517b7e23a2c3fef"
}
