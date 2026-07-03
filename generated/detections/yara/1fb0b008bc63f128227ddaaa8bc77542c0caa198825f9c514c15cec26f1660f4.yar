import "hash"

rule sentinel_1fb0b008bc63f128227ddaaa8bc77542c0caa198825f9c514c15cec26f1660f4 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "1fb0b008bc63f128227ddaaa8bc77542c0caa198825f9c514c15cec26f1660f4"
}
