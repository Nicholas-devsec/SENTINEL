rule sentinel_07720d8220abc066b6fdb2c187ae58f5 {
  meta:
    description = "SENTINEL generated hash IOC"
    severity = "informational"
  strings:
    $hash = "07720d8220abc066b6fdb2c187ae58f5"
  condition:
    $hash
}
