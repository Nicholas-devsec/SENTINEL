rule sentinel_f8e9a720468c89f191d8cb12d46d81ef67b87a9ef95a307835c556a0885bd181 {
  meta:
    description = "SENTINEL generated hash IOC"
    severity = "informational"
  strings:
    $hash = "f8e9a720468c89f191d8cb12d46d81ef67b87a9ef95a307835c556a0885bd181"
  condition:
    $hash
}
