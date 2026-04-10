rule sentinel_c94de13f548ce39911a1c55a5e0f43cddd681deb5a5a9c4de8a0dfe5b082f650 {
  meta:
    description = "SENTINEL generated hash IOC"
    severity = "informational"
  strings:
    $hash = "c94de13f548ce39911a1c55a5e0f43cddd681deb5a5a9c4de8a0dfe5b082f650"
  condition:
    $hash
}
