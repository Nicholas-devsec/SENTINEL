import "hash"

rule sentinel_0cfdffc56f0fa325d0c4d24780b46597 {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "informational"
    source = "securelist_blog"
  condition:
    hash.md5(0, filesize) == "0cfdffc56f0fa325d0c4d24780b46597"
}
