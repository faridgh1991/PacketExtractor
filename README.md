# PacketExtractor

library to listen network interface and extract network packet's layers and payload. 

### install:

``` bash
go get -u github.com/faridgh1991/PacketExtractor
```

### usage:

```go
package main

import (
  "fmt"
  "log"

  packetx "github.com/faridgh1991/PacketExtractor"
)

func main() {

    extractor, error := packetx.NewExtractor("eno1", "udp", "8000")
	
    if error != nil {
		  log.Fatal("Extractor Create Failed: ", error)
	  }

    defer extractor.Close()

	  packets := extractor.Packet()

	  for p := range packets {
		  fmt.Println(string(p.Payload))
	  }
}
```
