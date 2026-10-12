import "hash"

rule sentinel_985829083f3937df6c82419216f7697afae0caac8efca6257a756066fe2c0abb {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "elastic_security_labs"
  condition:
    hash.sha256(0, filesize) == "985829083f3937df6c82419216f7697afae0caac8efca6257a756066fe2c0abb"
}
