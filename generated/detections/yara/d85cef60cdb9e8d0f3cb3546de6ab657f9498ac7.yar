rule sentinel_d85cef60cdb9e8d0f3cb3546de6ab657f9498ac7 {
  meta:
    description = "SENTINEL generated hash IOC"
    severity = "informational"
  strings:
    $hash = "d85cef60cdb9e8d0f3cb3546de6ab657f9498ac7"
  condition:
    $hash
}
