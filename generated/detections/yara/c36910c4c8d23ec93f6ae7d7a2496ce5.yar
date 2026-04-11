rule sentinel_c36910c4c8d23ec93f6ae7d7a2496ce5 {
  meta:
    description = "SENTINEL generated hash IOC"
    severity = "informational"
  strings:
    $hash = "c36910c4c8d23ec93f6ae7d7a2496ce5"
  condition:
    $hash
}
