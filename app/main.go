package main

import (
	"encoding/binary"
	"fmt"
	"net"
)

type DNSResponse struct {
	Header    DNSHeader
	Questions []DNSQuestion
	Answer    DNSAnswer
}

func (r *DNSResponse) Serialize() []byte {
	buf := []byte{}

	buf = append(buf, r.Header.Serialize()...)
	for _, question := range r.Questions {
		buf = append(buf, question.Serialize()...)
	}
	buf = append(buf, answer.Serialize()...)
	return buf
}

type DNSHeader struct {
	ID      uint16
	QR      uint8
	OPCODE  uint8
	AA      uint8
	TC      uint8
	RD      uint8
	RA      uint8
	Z       uint8
	RCODE   uint8
	QDCOUNT uint16
	ANCOUNT uint16
	NSCOUNT uint16
	ARCOUNT uint16
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
	Type  uint16
	Class uint16
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

	buf = append(buf, 0x00)

	buf = binary.BigEndian.AppendUint16(buf, uint16(r.Type))
	buf = binary.BigEndian.AppendUint16(buf, uint16(r.Class))
	buf = binary.BigEndian.AppendUint32(buf, uint32(r.TTL))
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(r.Data)))
	buf = append(buf, r.Data...)
	return buf
}

func ParseDNSHeader(buf []byte) DNSHeader {
	id := binary.BigEndian.Uint16(buf[:2])

	// [qr, op, op, op, op, aa, tc, rd]
	qr := uint8((buf[2] >> 7) & 0x01)
	opCode := uint8((buf[2] >> 3) & 0x0f)
	aa := uint8((buf[2] >> 2) & 0x01)
	tc := uint8((buf[2] >> 2) & 0x01)
	rd := uint8(buf[2] & 0x01)
	ra := uint8((buf[3] >> 7) & 0x01)
	z := uint8((buf[3] >> 4) & 0x07)
	rCode := uint8((buf[3]) & 0x0f)
	qdCount := binary.BigEndian.Uint16(buf[4:6])
	anCount := binary.BigEndian.Uint16(buf[6:8])
	nsCount := binary.BigEndian.Uint16(buf[8:10])
	arCount := binary.BigEndian.Uint16(buf[10:12])
	return DNSHeader{
		ID:      id,
		QR:      qr,
		OPCODE:  opCode,
		AA:      aa,
		TC:      tc,
		RD:      rd,
		RA:      ra,
		Z:       z,
		RCODE:   rCode,
		QDCOUNT: qdCount,
		ANCOUNT: anCount,
		NSCOUNT: nsCount,
		ARCOUNT: arCount,
	}
}

func ParseDNSQuestions(buf []byte) []DNSQuestion {
	questions := []DNSQuestion{}
	// Header is 12 bytes fixed
	for i := uint(12); i <= uint(len(buf)); {
		Name := []DNSLabelSequence{}
		for buf[i] != 0x00 {
			lenByte := buf[i]

			if lenByte>>6 == 0x03 {
				labelOffset := binary.BigEndian.Uint16([]byte{(buf[i] << 2) >> 2, buf[i+1]})
				nameLen := uint8(buf[labelOffset])
				Name = append(Name, DNSLabelSequence{Label: string(buf[labelOffset+1 : labelOffset+1+uint16(nameLen)])})
				i += 2
			} else {
				nameLen := uint(lenByte)
				i += 1
				Name = append(Name, DNSLabelSequence{Label: string(buf[i : i+nameLen])})
				i += nameLen
			}
		}

		Type := binary.BigEndian.Uint16(buf[i : i+2])
		i += 2
		Class := binary.BigEndian.Uint16(buf[i : i+2])

		question := DNSQuestion{
			Name,
			Type,
			Class,
		}

		questions = append(questions, question)
	}

	return questions
}

func ParseDNSRequest(buf []byte) (DNSHeader, []DNSQuestion) {
	header := ParseDNSHeader(buf)
	questions := ParseDNSQuestions(buf)

	return header, questions
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
		receivedHeader, receivedQuestions := ParseDNSRequest([]byte(receivedData))
		responseRcode := uint8(0)
		if receivedHeader.OPCODE != 0 {
			responseRcode = 4
		}

		records := []ResourceRecord{}

		for _, question := range receivedQuestions {
			record := ResourceRecord{
				Name:  question.Name,
				Type:  1,
				Class: 1,
				TTL:   60,
				Data:  []byte{0x08, 0x08, 0x08, 0x08},
			}

			records = append(records, record)
		}
		testResponse := DNSResponse{
			Header: DNSHeader{
				ID:      receivedHeader.ID,
				QR:      1,
				OPCODE:  receivedHeader.OPCODE,
				AA:      0,
				TC:      0,
				RD:      receivedHeader.RD,
				RA:      0,
				Z:       0,
				RCODE:   responseRcode,
				QDCOUNT: 1,
				ANCOUNT: 1,
				NSCOUNT: 0,
				ARCOUNT: 0,
			},
			Questions: receivedQuestions,
			Answer: DNSAnswer{
				Records: records,
			},
		}
		fmt.Printf("Received %d bytes from %s: %s\n", size, source, receivedData)

		// Create an empty response
		_, err = udpConn.WriteToUDP(testResponse.Serialize(), source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
