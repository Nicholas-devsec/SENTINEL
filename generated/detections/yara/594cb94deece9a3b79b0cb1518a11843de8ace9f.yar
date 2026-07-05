import "hash"

rule sentinel_594cb94deece9a3b79b0cb1518a11843de8ace9f {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "594cb94deece9a3b79b0cb1518a11843de8ace9f"
}
