rule sentinel_7528bf597fd7764fcb7ec06512e073e0 {
  meta:
    description = "SENTINEL generated hash IOC"
    severity = "medium"
  strings:
    $hash = "7528bf597fd7764fcb7ec06512e073e0"
  condition:
    $hash
}
