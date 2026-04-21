package main

import (
	"encoding/binary"
	"fmt"
	"net"
)

type DNSResponse struct {
	Header   DNSHeader
	Question DNSQuestion
	Answer   DNSAnswer
}

func (r *DNSResponse) Serialize() []byte {
	buf := []byte{}

	buf = append(buf, r.Header.Serialize()...)
	buf = append(buf, r.Question.Serialize()...)
	buf = append(buf, r.Answer.Serialize()...)
	return buf
}

type DNSHeader struct {
	ID      int16
	QR      int8
	OPCODE  int8
	AA      int8
	TC      int8
	RD      int8
	RA      int8
	Z       int8
	RCODE   int8
	QDCOUNT int16
	ANCOUNT int16
	NSCOUNT int16
	ARCOUNT int16
}

// Serialize encodes the DNS header into exactly 12 bytes, ready to be sent over the network.
// DNS requires fields to be packed tightly in big-endian order (most significant byte first).
func (h *DNSHeader) Serialize() []byte {
	buf := make([]byte, 12)

	// Bytes 0-1: message ID — split the 16-bit value into two bytes, high byte first.
	buf[0] = byte(h.ID >> 8)
	buf[1] = byte(h.ID)

	// Byte 2: packs 5 single-bit or multi-bit flags into one byte.
	// Each field is masked to its allowed bit width, then shifted to its designated position:
	//   bit 7     — QR     (0 = query, 1 = response)
	//   bits 6–3  — OPCODE (query type, 4 bits)
	//   bit 2     — AA     (authoritative answer)
	//   bit 1     — TC     (message was truncated)
	//   bit 0     — RD     (recursion desired)
	buf[2] = byte(h.QR&0x01)<<7 | byte(h.OPCODE&0x0F)<<3 | byte(h.AA&0x01)<<2 | byte(h.TC&0x01)<<1 | byte(h.RD&0x01)

	// Byte 3: continuation of flags.
	//   bit 7     — RA    (recursion available, set by the server)
	//   bits 6–4  — Z     (reserved, must be 0)
	//   bits 3–0  — RCODE (response code: 0 = no error, 3 = name not found, etc.)
	buf[3] = byte(h.RA&0x01)<<7 | byte(h.Z&0x07)<<4 | byte(h.RCODE&0x0F)

	// Bytes 4–11: four 16-bit counters, each split into two bytes (high byte first).
	// They tell the receiver how many records follow in each section of the message.
	buf[4] = byte(h.QDCOUNT >> 8) // number of questions
	buf[5] = byte(h.QDCOUNT)
	buf[6] = byte(h.ANCOUNT >> 8) // number of answers
	buf[7] = byte(h.ANCOUNT)
	buf[8] = byte(h.NSCOUNT >> 8) // number of authority records
	buf[9] = byte(h.NSCOUNT)
	buf[10] = byte(h.ARCOUNT >> 8) // number of additional records
	buf[11] = byte(h.ARCOUNT)

	return buf
}

type DNSLabelSequence struct {
	Label string
}

func (l *DNSLabelSequence) Serialize() []byte {
	buf := make([]byte, 0, len(l.Label)+1)

	buf = append(buf, byte(len(l.Label)))
	buf = append(buf, l.Label...)
	return buf
}

type DNSQuestion struct {
	Name  []DNSLabelSequence
	Type  int16
	Class int16
}

func (q *DNSQuestion) Serialize() []byte {
	buf := []byte{}
	for _, label := range q.Name {
		buf = append(buf, label.Serialize()...)
	}
	buf = append(buf, 0x00)
	buf = append(buf, byte(q.Type>>8))
	buf = append(buf, byte(q.Type))
	buf = append(buf, byte(q.Class>>8))
	buf = append(buf, byte(q.Class))
	return buf
}

type DNSAnswer struct {
	Records []ResourceRecord
}

func (a *DNSAnswer) Serialize() []byte {
	buf := []byte{}
	for _, r := range a.Records {
		buf = append(buf, r.Serialize()...)
	}
	return buf
}

type ResourceRecord struct {
	Name  []DNSLabelSequence
	Type  int16
	Class int16
	TTL   int32
	Data  []byte
}

func (r *ResourceRecord) Serialize() []byte {
	buf := []byte{}
	for _, label := range r.Name {
		buf = append(buf, label.Serialize()...)
	}

	buf = binary.BigEndian.AppendUint16(buf, uint16(r.Type))
	buf = binary.BigEndian.AppendUint16(buf, uint16(r.Class))
	buf = binary.BigEndian.AppendUint32(buf, uint32(r.TTL))
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(r.Data)))
	buf = append(buf, r.Data...)
	return buf
}

var TestResponse = DNSResponse{
	Header: DNSHeader{
		ID: 1234,
		QR: 1,
	},
	Question: DNSQuestion{
		Name:  []DNSLabelSequence{{Label: "codecrafters"}, {Label: "io"}},
		Type:  1,
		Class: 1,
	},
	Answer: DNSAnswer{
		Records: []ResourceRecord{
			{Name: []DNSLabelSequence{{Label: "codecrafters"}, {Label: "io"}}, Type: 1, Class: 1, TTL: 60, Data: []byte{0x08, 0x08, 0x08, 0x08}},
		},
	},
}

func main() {
	// You can use print statements as follows for debugging, they'll be visible when running tests.
	fmt.Println("Logs from your program will appear here!")

	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	if err != nil {
		fmt.Println("Failed to resolve UDP address:", err)
		return
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Failed to bind to address:", err)
		return
	}
	defer udpConn.Close()

	buf := make([]byte, 512)

	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error receiving data:", err)
			break
		}

		receivedData := string(buf[:size])
		fmt.Printf("Received %d bytes from %s: %s\n", size, source, receivedData)

		// Create an empty response
		_, err = udpConn.WriteToUDP(TestResponse.Serialize(), source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
		TestResponse.Header.QDCOUNT += 1
		TestResponse.Header.ANCOUNT += 1
	}
}
