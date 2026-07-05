import "hash"

rule sentinel_8cbe48fc14585b878bda6c568ae10e1c0f063034c86f868b3cc324354596d32f {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "medium"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "8cbe48fc14585b878bda6c568ae10e1c0f063034c86f868b3cc324354596d32f"
}
