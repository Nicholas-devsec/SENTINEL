import "hash"

rule sentinel_4b7301f02b8312ae6de614981f325dbbabee32166630618fdff74615d9a487ba {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "otx"
  condition:
    hash.sha256(0, filesize) == "4b7301f02b8312ae6de614981f325dbbabee32166630618fdff74615d9a487ba"
}
