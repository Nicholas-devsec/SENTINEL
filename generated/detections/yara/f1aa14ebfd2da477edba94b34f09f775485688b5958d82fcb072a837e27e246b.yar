import "hash"

rule sentinel_f1aa14ebfd2da477edba94b34f09f775485688b5958d82fcb072a837e27e246b {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "discovery:cybersecuritynews.com"
  condition:
    hash.sha256(0, filesize) == "f1aa14ebfd2da477edba94b34f09f775485688b5958d82fcb072a837e27e246b"
}
