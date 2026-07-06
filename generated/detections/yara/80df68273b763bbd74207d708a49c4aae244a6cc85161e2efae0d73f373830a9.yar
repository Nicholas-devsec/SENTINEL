import "hash"

rule sentinel_80df68273b763bbd74207d708a49c4aae244a6cc85161e2efae0d73f373830a9 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "80df68273b763bbd74207d708a49c4aae244a6cc85161e2efae0d73f373830a9"
}
