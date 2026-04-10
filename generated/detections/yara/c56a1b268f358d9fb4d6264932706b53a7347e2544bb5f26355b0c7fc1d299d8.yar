rule sentinel_c56a1b268f358d9fb4d6264932706b53a7347e2544bb5f26355b0c7fc1d299d8 {
  meta:
    description = "SENTINEL generated hash IOC"
    severity = "informational"
  strings:
    $hash = "c56a1b268f358d9fb4d6264932706b53a7347e2544bb5f26355b0c7fc1d299d8"
  condition:
    $hash
}
