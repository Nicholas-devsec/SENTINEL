rule sentinel_107484d66423cb601f418344cd648f12 {
  meta:
    description = "SENTINEL generated hash IOC"
    severity = "informational"
  strings:
    $hash = "107484d66423cb601f418344cd648f12"
  condition:
    $hash
}
