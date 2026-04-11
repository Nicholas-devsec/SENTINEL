rule sentinel_3d389886e95f00fade1eea67a6c370d1 {
  meta:
    description = "SENTINEL generated hash IOC"
    severity = "informational"
  strings:
    $hash = "3d389886e95f00fade1eea67a6c370d1"
  condition:
    $hash
}
