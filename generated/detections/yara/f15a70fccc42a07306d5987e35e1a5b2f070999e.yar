rule sentinel_f15a70fccc42a07306d5987e35e1a5b2f070999e {
  meta:
    description = "SENTINEL generated hash IOC"
    severity = "informational"
  strings:
    $hash = "f15a70fccc42a07306d5987e35e1a5b2f070999e"
  condition:
    $hash
}
