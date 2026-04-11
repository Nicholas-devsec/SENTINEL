rule sentinel_3effadb977eddd4c48c7850c8dc03b13 {
  meta:
    description = "SENTINEL generated hash IOC"
    severity = "informational"
  strings:
    $hash = "3effadb977eddd4c48c7850c8dc03b13"
  condition:
    $hash
}
