import "hash"

rule sentinel_4c9e9d28c5bd78e82cd874856549b18c1cfd5d0fa4b2dd63f779de90cdd27ed8 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "4c9e9d28c5bd78e82cd874856549b18c1cfd5d0fa4b2dd63f779de90cdd27ed8"
}
