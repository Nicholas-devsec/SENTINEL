import "hash"

rule sentinel_a86c023a02f1454738b39f753f50777c238b4ea296ffc76cd41c3059f216be10 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "a86c023a02f1454738b39f753f50777c238b4ea296ffc76cd41c3059f216be10"
}
