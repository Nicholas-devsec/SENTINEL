rule sentinel_fdae784b02b22916bf4bac1344b3e8e13f98996e3cd85f2daf171084983247e1 {
  meta:
    description = "SENTINEL generated hash IOC"
    severity = "informational"
  strings:
    $hash = "fdae784b02b22916bf4bac1344b3e8e13f98996e3cd85f2daf171084983247e1"
  condition:
    $hash
}
