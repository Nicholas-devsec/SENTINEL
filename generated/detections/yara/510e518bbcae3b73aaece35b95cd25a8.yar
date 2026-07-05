import "hash"

rule sentinel_510e518bbcae3b73aaece35b95cd25a8 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "510e518bbcae3b73aaece35b95cd25a8"
}
