import "hash"

rule sentinel_72ae58765ce3ef8777af4ca8bedeb725ccc4e55d {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "72ae58765ce3ef8777af4ca8bedeb725ccc4e55d"
}
