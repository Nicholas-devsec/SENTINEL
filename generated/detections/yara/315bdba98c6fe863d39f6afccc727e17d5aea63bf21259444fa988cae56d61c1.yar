import "hash"

rule sentinel_315bdba98c6fe863d39f6afccc727e17d5aea63bf21259444fa988cae56d61c1 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "otx"
  condition:
    hash.sha256(0, filesize) == "315bdba98c6fe863d39f6afccc727e17d5aea63bf21259444fa988cae56d61c1"
}
