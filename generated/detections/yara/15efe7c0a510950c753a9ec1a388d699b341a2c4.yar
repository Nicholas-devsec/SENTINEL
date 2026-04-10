rule sentinel_15efe7c0a510950c753a9ec1a388d699b341a2c4 {
  meta:
    description = "SENTINEL generated hash IOC"
    severity = "informational"
  strings:
    $hash = "15efe7c0a510950c753a9ec1a388d699b341a2c4"
  condition:
    $hash
}
