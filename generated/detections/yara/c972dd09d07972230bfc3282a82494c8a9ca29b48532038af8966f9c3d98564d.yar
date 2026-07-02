import "hash"

rule sentinel_c972dd09d07972230bfc3282a82494c8a9ca29b48532038af8966f9c3d98564d {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "c972dd09d07972230bfc3282a82494c8a9ca29b48532038af8966f9c3d98564d"
}
