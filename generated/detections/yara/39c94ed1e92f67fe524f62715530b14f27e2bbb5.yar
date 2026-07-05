import "hash"

rule sentinel_39c94ed1e92f67fe524f62715530b14f27e2bbb5 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "39c94ed1e92f67fe524f62715530b14f27e2bbb5"
}
