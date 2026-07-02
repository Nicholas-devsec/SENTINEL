import "hash"

rule sentinel_fc4686a72c0387bd51e28916a20ab713eb0edac589dc8d7be28c0b1bef49694e {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "fc4686a72c0387bd51e28916a20ab713eb0edac589dc8d7be28c0b1bef49694e"
}
