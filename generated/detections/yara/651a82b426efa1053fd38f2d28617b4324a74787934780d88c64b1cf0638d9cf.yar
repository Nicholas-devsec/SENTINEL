import "hash"

rule sentinel_651a82b426efa1053fd38f2d28617b4324a74787934780d88c64b1cf0638d9cf {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "651a82b426efa1053fd38f2d28617b4324a74787934780d88c64b1cf0638d9cf"
}
