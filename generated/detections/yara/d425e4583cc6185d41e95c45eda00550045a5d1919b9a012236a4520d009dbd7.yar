import "hash"

rule sentinel_d425e4583cc6185d41e95c45eda00550045a5d1919b9a012236a4520d009dbd7 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "unit42_blog"
  condition:
    hash.sha256(0, filesize) == "d425e4583cc6185d41e95c45eda00550045a5d1919b9a012236a4520d009dbd7"
}
