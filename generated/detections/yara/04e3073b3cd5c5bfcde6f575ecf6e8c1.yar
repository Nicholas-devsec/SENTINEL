rule sentinel_04e3073b3cd5c5bfcde6f575ecf6e8c1 {
  meta:
    description = "SENTINEL generated hash IOC"
    severity = "medium"
  strings:
    $hash = "04e3073b3cd5c5bfcde6f575ecf6e8c1"
  condition:
    $hash
}
