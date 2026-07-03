import "hash"

rule sentinel_5f94e59c132a7ed0e35b60146d973a728ab9f390c8291f9547cee26c56427738 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "5f94e59c132a7ed0e35b60146d973a728ab9f390c8291f9547cee26c56427738"
}
