import "hash"

rule sentinel_4ae4d4f2faf96941187abdf2d292b4ce995ecc94dc68f8e7d4e0e49747caed6d {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "4ae4d4f2faf96941187abdf2d292b4ce995ecc94dc68f8e7d4e0e49747caed6d"
}
