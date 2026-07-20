import "hash"

rule sentinel_e85149704da6ee8f9bc1c55304c560d1a792180489d4859a64cf0a4e056ccf52 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "e85149704da6ee8f9bc1c55304c560d1a792180489d4859a64cf0a4e056ccf52"
}
