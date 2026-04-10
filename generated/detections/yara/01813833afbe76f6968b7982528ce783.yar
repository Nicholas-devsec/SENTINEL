rule sentinel_01813833afbe76f6968b7982528ce783 {
  meta:
    description = "SENTINEL generated hash IOC"
    severity = "informational"
  strings:
    $hash = "01813833afbe76f6968b7982528ce783"
  condition:
    $hash
}
