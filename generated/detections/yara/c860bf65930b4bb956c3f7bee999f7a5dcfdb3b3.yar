rule sentinel_c860bf65930b4bb956c3f7bee999f7a5dcfdb3b3 {
  meta:
    description = "SENTINEL generated hash IOC"
    severity = "informational"
  strings:
    $hash = "c860bf65930b4bb956c3f7bee999f7a5dcfdb3b3"
  condition:
    $hash
}
