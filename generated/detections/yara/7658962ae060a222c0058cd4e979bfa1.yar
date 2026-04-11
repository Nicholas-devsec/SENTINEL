rule sentinel_7658962ae060a222c0058cd4e979bfa1 {
  meta:
    description = "SENTINEL generated hash IOC"
    severity = "medium"
  strings:
    $hash = "7658962ae060a222c0058cd4e979bfa1"
  condition:
    $hash
}
