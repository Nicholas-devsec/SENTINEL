import "hash"

rule sentinel_04a8018191f2e9e76072d072a933371d9d669a42de2b2a087541cd3a653b0ba7 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "medium"
    source = "discovery:www.rapid7.com"
  condition:
    hash.sha256(0, filesize) == "04a8018191f2e9e76072d072a933371d9d669a42de2b2a087541cd3a653b0ba7"
}
