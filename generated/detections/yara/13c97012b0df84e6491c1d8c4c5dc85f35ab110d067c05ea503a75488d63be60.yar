rule sentinel_13c97012b0df84e6491c1d8c4c5dc85f35ab110d067c05ea503a75488d63be60 {
  meta:
    description = "SENTINEL generated hash IOC"
    severity = "informational"
  strings:
    $hash = "13c97012b0df84e6491c1d8c4c5dc85f35ab110d067c05ea503a75488d63be60"
  condition:
    $hash
}
