rule sentinel_617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101 {
  meta:
    description = "SENTINEL generated hash IOC"
    severity = "medium"
  strings:
    $hash = "617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101"
  condition:
    $hash
}
