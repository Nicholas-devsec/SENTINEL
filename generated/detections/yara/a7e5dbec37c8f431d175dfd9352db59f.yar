rule sentinel_a7e5dbec37c8f431d175dfd9352db59f {
  meta:
    description = "SENTINEL generated hash IOC"
    severity = "informational"
  strings:
    $hash = "a7e5dbec37c8f431d175dfd9352db59f"
  condition:
    $hash
}
