import "hash"

rule sentinel_59521e38698120af1b5072b64894df68 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "59521e38698120af1b5072b64894df68"
}
