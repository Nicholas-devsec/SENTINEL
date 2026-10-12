import "hash"

rule sentinel_40d253480f752805e58c21266e40afe99afc96feea0d355732af5bea459db1dd {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "discovery:cybersecuritynews.com"
  condition:
    hash.sha256(0, filesize) == "40d253480f752805e58c21266e40afe99afc96feea0d355732af5bea459db1dd"
}
