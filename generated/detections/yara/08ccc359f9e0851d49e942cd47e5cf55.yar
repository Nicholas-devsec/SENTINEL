rule sentinel_08ccc359f9e0851d49e942cd47e5cf55 {
  meta:
    description = "SENTINEL generated hash IOC"
    severity = "informational"
  strings:
    $hash = "08ccc359f9e0851d49e942cd47e5cf55"
  condition:
    $hash
}
