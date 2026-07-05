import "hash"

rule sentinel_a27c95793111ec5ad8be6d3d9728d94a {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "a27c95793111ec5ad8be6d3d9728d94a"
}
