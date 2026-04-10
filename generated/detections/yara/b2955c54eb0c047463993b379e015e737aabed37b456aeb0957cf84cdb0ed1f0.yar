rule sentinel_b2955c54eb0c047463993b379e015e737aabed37b456aeb0957cf84cdb0ed1f0 {
  meta:
    description = "SENTINEL generated hash IOC"
    severity = "informational"
  strings:
    $hash = "b2955c54eb0c047463993b379e015e737aabed37b456aeb0957cf84cdb0ed1f0"
  condition:
    $hash
}
