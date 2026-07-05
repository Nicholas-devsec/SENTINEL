import "hash"

rule sentinel_1e3e29a85fc7fe89f3696facaa9db43c {
  meta:
    description = "SENTINEL known-bad file by MD5"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.md5(0, filesize) == "1e3e29a85fc7fe89f3696facaa9db43c"
}
