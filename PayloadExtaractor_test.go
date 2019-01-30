package packetx

import (
	"log"
	"os/exec"
	"testing"
	"time"
)

func TestNewExtractor(t *testing.T) {

	extractor, error := NewExtractor("lo", "udp", "1813")
	defer extractor.Close()

	if error != nil {
		log.Fatal("Extractor Create Failed: ", error)
	}

	packets := extractor.Packet()

	go sendNping()

	ticker := time.NewTicker(time.Second * 2)

	select {
	case p := <-packets:
		if payloadString := string(p.Payload); payloadString != "test data" {
			t.Fatalf("Payload not equal to test data: %s\n", payloadString)
		}

		if ipString := string(p.IPLayer.SrcIP.String()); ipString != "192.168.10.10" {
			t.Fatalf("IP not equal to test ip: %s\n", ipString)
		}
	case <-ticker.C:
		t.Fatal("timedout after 500ms")
	}
}

func sendNping() {
	time.Sleep(1 * time.Second)

	err := exec.Command("bash", "-c", "nping --udp -p 1813 127.0.0.1 -c 1 -S 192.168.10.10 --data-string \"test data\" &").Run()
	if err != nil {
		log.Fatal(err)
	}

}
