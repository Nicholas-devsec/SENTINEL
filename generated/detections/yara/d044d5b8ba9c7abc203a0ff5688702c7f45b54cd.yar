import "hash"

rule sentinel_d044d5b8ba9c7abc203a0ff5688702c7f45b54cd {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "otx"
  condition:
    hash.sha1(0, filesize) == "d044d5b8ba9c7abc203a0ff5688702c7f45b54cd"
}
