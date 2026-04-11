rule sentinel_c02448e016b2568173de3eedadd80149 {
  meta:
    description = "SENTINEL generated hash IOC"
    severity = "informational"
  strings:
    $hash = "c02448e016b2568173de3eedadd80149"
  condition:
    $hash
}
