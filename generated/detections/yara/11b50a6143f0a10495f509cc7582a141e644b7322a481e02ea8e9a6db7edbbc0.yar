import "hash"

rule sentinel_11b50a6143f0a10495f509cc7582a141e644b7322a481e02ea8e9a6db7edbbc0 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "11b50a6143f0a10495f509cc7582a141e644b7322a481e02ea8e9a6db7edbbc0"
}
