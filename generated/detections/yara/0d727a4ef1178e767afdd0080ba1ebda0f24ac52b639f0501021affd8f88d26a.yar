import "hash"

rule sentinel_0d727a4ef1178e767afdd0080ba1ebda0f24ac52b639f0501021affd8f88d26a {
  meta:
    description = "SENTINEL known-bad file by SHA256"
    severity = "medium"
    source = "discovery:gbhackers.com"
  condition:
    hash.sha256(0, filesize) == "0d727a4ef1178e767afdd0080ba1ebda0f24ac52b639f0501021affd8f88d26a"
}
