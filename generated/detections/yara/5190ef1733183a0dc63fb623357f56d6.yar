rule sentinel_5190ef1733183a0dc63fb623357f56d6 {
  meta:
    description = "SENTINEL generated hash IOC"
    severity = "informational"
  strings:
    $hash = "5190ef1733183a0dc63fb623357f56d6"
  condition:
    $hash
}
