import "hash"

rule sentinel_6bb4372d0d02ec87b76409f69d445a93910964f8db457bafafb97a011da59e73 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "discovery:cybersecuritynews.com"
  condition:
    hash.sha256(0, filesize) == "6bb4372d0d02ec87b76409f69d445a93910964f8db457bafafb97a011da59e73"
}
