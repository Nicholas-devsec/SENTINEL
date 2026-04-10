rule sentinel_34a0f70ab100c47caaba7a5c85448e3d {
  meta:
    description = "SENTINEL generated hash IOC"
    severity = "informational"
  strings:
    $hash = "34a0f70ab100c47caaba7a5c85448e3d"
  condition:
    $hash
}
