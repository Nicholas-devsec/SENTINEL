import "hash"

rule sentinel_e438003e81399afda1a4801bdd3d347a757c2068c4dbbaa99d4f554972c546f0 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "e438003e81399afda1a4801bdd3d347a757c2068c4dbbaa99d4f554972c546f0"
}
