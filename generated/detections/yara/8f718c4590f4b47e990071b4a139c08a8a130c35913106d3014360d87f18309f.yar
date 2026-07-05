import "hash"

rule sentinel_8f718c4590f4b47e990071b4a139c08a8a130c35913106d3014360d87f18309f {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "8f718c4590f4b47e990071b4a139c08a8a130c35913106d3014360d87f18309f"
}
