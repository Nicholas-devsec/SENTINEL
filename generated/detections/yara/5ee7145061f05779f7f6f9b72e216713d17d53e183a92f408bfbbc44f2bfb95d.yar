import "hash"

rule sentinel_5ee7145061f05779f7f6f9b72e216713d17d53e183a92f408bfbbc44f2bfb95d {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "elastic_security_labs"
  condition:
    hash.sha256(0, filesize) == "5ee7145061f05779f7f6f9b72e216713d17d53e183a92f408bfbbc44f2bfb95d"
}
