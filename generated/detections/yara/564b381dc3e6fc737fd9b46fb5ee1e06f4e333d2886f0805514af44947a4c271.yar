rule sentinel_564b381dc3e6fc737fd9b46fb5ee1e06f4e333d2886f0805514af44947a4c271 {
  meta:
    description = "SENTINEL generated hash IOC"
    severity = "informational"
  strings:
    $hash = "564b381dc3e6fc737fd9b46fb5ee1e06f4e333d2886f0805514af44947a4c271"
  condition:
    $hash
}
