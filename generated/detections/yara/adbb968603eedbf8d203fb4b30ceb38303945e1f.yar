import "hash"

rule sentinel_adbb968603eedbf8d203fb4b30ceb38303945e1f {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "adbb968603eedbf8d203fb4b30ceb38303945e1f"
}
