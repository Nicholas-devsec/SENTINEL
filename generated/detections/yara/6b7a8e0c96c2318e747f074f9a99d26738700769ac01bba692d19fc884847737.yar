import "hash"

rule sentinel_6b7a8e0c96c2318e747f074f9a99d26738700769ac01bba692d19fc884847737 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "unit42_blog"
  condition:
    hash.sha256(0, filesize) == "6b7a8e0c96c2318e747f074f9a99d26738700769ac01bba692d19fc884847737"
}
