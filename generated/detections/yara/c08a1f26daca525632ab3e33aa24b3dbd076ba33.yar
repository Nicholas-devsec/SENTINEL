import "hash"

rule sentinel_c08a1f26daca525632ab3e33aa24b3dbd076ba33 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "c08a1f26daca525632ab3e33aa24b3dbd076ba33"
}
