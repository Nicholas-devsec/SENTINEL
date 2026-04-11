rule sentinel_e4b594a18fc2a6ee164a76bdea980bc0 {
  meta:
    description = "SENTINEL generated hash IOC"
    severity = "informational"
  strings:
    $hash = "e4b594a18fc2a6ee164a76bdea980bc0"
  condition:
    $hash
}
