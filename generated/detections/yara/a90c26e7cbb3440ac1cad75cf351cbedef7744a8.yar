rule sentinel_a90c26e7cbb3440ac1cad75cf351cbedef7744a8 {
  meta:
    description = "SENTINEL generated hash IOC"
    severity = "medium"
  strings:
    $hash = "a90c26e7cbb3440ac1cad75cf351cbedef7744a8"
  condition:
    $hash
}
