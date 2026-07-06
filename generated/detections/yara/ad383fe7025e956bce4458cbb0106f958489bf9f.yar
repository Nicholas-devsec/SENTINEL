import "hash"

rule sentinel_ad383fe7025e956bce4458cbb0106f958489bf9f {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "ad383fe7025e956bce4458cbb0106f958489bf9f"
}
