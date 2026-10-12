import "hash"

rule sentinel_62ef39ec29966d71c8254f68bd5e320cf24a042d76c12dbafdcc0766861827c5 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "discovery:cybersecuritynews.com"
  condition:
    hash.sha256(0, filesize) == "62ef39ec29966d71c8254f68bd5e320cf24a042d76c12dbafdcc0766861827c5"
}
