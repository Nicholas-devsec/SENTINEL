import "hash"

rule sentinel_825aa515a905b7294efc080850e77d8962a1411c6f47468a2ce67a19770bc830 {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "825aa515a905b7294efc080850e77d8962a1411c6f47468a2ce67a19770bc830"
}
