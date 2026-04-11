rule sentinel_07f95ff34fb330875d80afadca3f0d5b {
  meta:
    description = "SENTINEL generated hash IOC"
    severity = "informational"
  strings:
    $hash = "07f95ff34fb330875d80afadca3f0d5b"
  condition:
    $hash
}
