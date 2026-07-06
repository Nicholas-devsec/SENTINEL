import "hash"

rule sentinel_fa23920dce139f976c8fe2cc7ce5001296429c259cc70f7f79777f69eff021be {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "fa23920dce139f976c8fe2cc7ce5001296429c259cc70f7f79777f69eff021be"
}
