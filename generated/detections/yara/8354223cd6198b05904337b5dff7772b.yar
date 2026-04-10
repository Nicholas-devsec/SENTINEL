rule sentinel_8354223cd6198b05904337b5dff7772b {
  meta:
    description = "SENTINEL generated hash IOC"
    severity = "medium"
  strings:
    $hash = "8354223cd6198b05904337b5dff7772b"
  condition:
    $hash
}
