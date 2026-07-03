import "hash"

rule sentinel_fc99609172910a8fad9522b374f8bae21e5805abdf052a49029edb53620a8e8c {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "fc99609172910a8fad9522b374f8bae21e5805abdf052a49029edb53620a8e8c"
}
