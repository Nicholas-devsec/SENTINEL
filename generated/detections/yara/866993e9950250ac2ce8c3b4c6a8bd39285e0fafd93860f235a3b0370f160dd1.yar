rule sentinel_866993e9950250ac2ce8c3b4c6a8bd39285e0fafd93860f235a3b0370f160dd1 {
  meta:
    description = "SENTINEL generated hash IOC"
    severity = "informational"
  strings:
    $hash = "866993e9950250ac2ce8c3b4c6a8bd39285e0fafd93860f235a3b0370f160dd1"
  condition:
    $hash
}
