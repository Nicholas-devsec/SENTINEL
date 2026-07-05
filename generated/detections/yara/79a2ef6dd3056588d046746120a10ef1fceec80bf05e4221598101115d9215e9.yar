import "hash"

rule sentinel_79a2ef6dd3056588d046746120a10ef1fceec80bf05e4221598101115d9215e9 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "79a2ef6dd3056588d046746120a10ef1fceec80bf05e4221598101115d9215e9"
}
