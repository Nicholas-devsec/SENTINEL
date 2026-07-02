import "hash"

rule sentinel_cbdc70114cac319dbe3d7455b65dbfe7eebe568d {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "cbdc70114cac319dbe3d7455b65dbfe7eebe568d"
}
