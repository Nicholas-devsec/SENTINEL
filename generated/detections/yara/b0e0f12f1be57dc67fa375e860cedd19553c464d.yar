rule sentinel_b0e0f12f1be57dc67fa375e860cedd19553c464d {
  meta:
    description = "SENTINEL generated hash IOC"
    severity = "medium"
  strings:
    $hash = "b0e0f12f1be57dc67fa375e860cedd19553c464d"
  condition:
    $hash
}
