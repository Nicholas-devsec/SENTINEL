import "hash"

rule sentinel_3d195ba1802309316a5a54031e76cc666136cc21e01b97daf4a21a176ea5b3d3 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "3d195ba1802309316a5a54031e76cc666136cc21e01b97daf4a21a176ea5b3d3"
}
