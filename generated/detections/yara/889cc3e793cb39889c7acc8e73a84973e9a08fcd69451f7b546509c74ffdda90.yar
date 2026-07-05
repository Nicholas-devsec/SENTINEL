import "hash"

rule sentinel_889cc3e793cb39889c7acc8e73a84973e9a08fcd69451f7b546509c74ffdda90 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "889cc3e793cb39889c7acc8e73a84973e9a08fcd69451f7b546509c74ffdda90"
}
