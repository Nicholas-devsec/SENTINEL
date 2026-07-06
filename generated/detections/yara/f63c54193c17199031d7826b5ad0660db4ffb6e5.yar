import "hash"

rule sentinel_f63c54193c17199031d7826b5ad0660db4ffb6e5 {
  meta:
    description = "SENTINEL known-bad file by SHA1"
    severity = "informational"
    source = "threatfox"
  condition:
    hash.sha1(0, filesize) == "f63c54193c17199031d7826b5ad0660db4ffb6e5"
}
