import "hash"

rule sentinel_2ac492ce3b66a7979ceba5f26c594f0a69698d19b2ffdb56ac8b741dc30f8e5e {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "2ac492ce3b66a7979ceba5f26c594f0a69698d19b2ffdb56ac8b741dc30f8e5e"
}
