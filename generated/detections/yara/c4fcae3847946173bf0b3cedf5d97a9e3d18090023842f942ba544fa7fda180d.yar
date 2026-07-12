import "hash"

rule sentinel_c4fcae3847946173bf0b3cedf5d97a9e3d18090023842f942ba544fa7fda180d {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "informational"
    source = "gbhackers_blog"
  condition:
    hash.sha256(0, filesize) == "c4fcae3847946173bf0b3cedf5d97a9e3d18090023842f942ba544fa7fda180d"
}
