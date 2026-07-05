import "hash"

rule sentinel_2603246549cd0da58081690c184ebac031b17d034552019089eedcbbfdf1db3a {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "2603246549cd0da58081690c184ebac031b17d034552019089eedcbbfdf1db3a"
}
