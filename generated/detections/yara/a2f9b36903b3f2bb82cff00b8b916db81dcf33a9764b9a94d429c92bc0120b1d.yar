import "hash"

rule sentinel_a2f9b36903b3f2bb82cff00b8b916db81dcf33a9764b9a94d429c92bc0120b1d {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha256(0, filesize) == "a2f9b36903b3f2bb82cff00b8b916db81dcf33a9764b9a94d429c92bc0120b1d"
}
