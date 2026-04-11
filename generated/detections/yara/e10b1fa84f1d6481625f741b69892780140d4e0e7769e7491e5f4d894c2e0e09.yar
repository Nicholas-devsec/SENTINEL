rule sentinel_e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09 {
  meta:
    description = "SENTINEL generated hash IOC"
    severity = "medium"
  strings:
    $hash = "e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09"
  condition:
    $hash
}
