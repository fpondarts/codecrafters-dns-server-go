package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
)

// --- Types and serialization ---

type DNSLabelSequence struct {
	Label string
}

func (l *DNSLabelSequence) Serialize() []byte {
	buf := make([]byte, 0, len(l.Label)+1)
	buf = append(buf, byte(len(l.Label)))
	buf = append(buf, l.Label...)
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

type ResourceRecord struct {
	Name  []DNSLabelSequence
	Type  uint16
	Class uint16
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

type DNSRequest struct {
	Header    DNSHeader
	Questions []DNSQuestion
	Answers   []DNSAnswer
}

func (r *DNSRequest) Serialize() []byte {
	buf := []byte{}
	buf = append(buf, r.Header.Serialize()...)
	for _, question := range r.Questions {
		buf = append(buf, question.Serialize()...)
	}
	for _, answer := range r.Answers {
		buf = append(buf, answer.Serialize()...)
	}
	return buf
}

// --- Parsing ---

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

func GetNames(buf []byte, start int) ([]string, int) {
	names := []string{}
	i := start
	fmt.Printf("Starting sequence at %d\n", i)
	for buf[i] != 0 {
		lenByte := buf[i]

		fmt.Printf("Looking at byte %d, with value %d\n", lenByte, buf[i])
		if lenByte>>6 == 0x03 {
			offset := binary.BigEndian.Uint16([]byte{buf[i] & 0x3f, buf[i+1]})
			fmt.Printf("Going back to offset %d\n", offset)
			compressedNames, _ := GetNames(buf, int(offset))
			names = append(names, compressedNames...)
			return names, i + 2
		} else {
			nameLen := int(lenByte)
			i += 1
			name := string(buf[i : i+nameLen])
			names = append(names, name)
			i += nameLen
			fmt.Printf("Found %s sequence starting at %d. Moving forward to %d\n", name, i-1-nameLen, i)
		}
	}

	fmt.Printf("Returning %v, ending at %d, with buf[%d] = %d \n", names, i, i, buf[i])
	return names, i + 1
}

func ParseDNSQuestions(buf []byte) []DNSQuestion {
	questions := []DNSQuestion{}
	// Header is 12 bytes fixed
	for i := 12; i < len(buf) && buf[i] != 0x00; {
		Name := []DNSLabelSequence{}
		names, end := GetNames(buf, i)
		fmt.Printf("labels: %v", names)
		for _, name := range names {
			Name = append(Name, DNSLabelSequence{Label: name})
		}
		fmt.Printf("Found name sequence: %v. Sequence ends at %d. BufLen is %d\n", names, end, len(buf))
		i = end
		Type := binary.BigEndian.Uint16(buf[i : i+2])
		i += 2
		Class := binary.BigEndian.Uint16(buf[i : i+2])
		i += 2

		questions = append(questions, DNSQuestion{Name, Type, Class})
	}

	return questions
}

func ParseDNSRequest(buf []byte) (DNSHeader, []DNSQuestion) {
	header := ParseDNSHeader(buf)
	questions := ParseDNSQuestions(buf)
	return header, questions
}

// --- Forwarding ---

func forwardRequest(req DNSRequest, resolver *net.UDPAddr) ([]byte, error) {
	conn, err := net.DialUDP("udp", nil, resolver)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_, err = conn.Write(req.Serialize())
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func ParseAnswers(buf []byte) []ResourceRecord {
	header := ParseDNSHeader(buf)

	// skip past the question section to reach the answer section
	i := 12
	for q := 0; q < int(header.QDCOUNT); q++ {
		_, end := GetNames(buf, i)
		i = end + 4 // skip type (2) + class (2)
	}

	records := []ResourceRecord{}
	for a := 0; a < int(header.ANCOUNT); a++ {
		names, end := GetNames(buf, i)
		i = end
		labels := make([]DNSLabelSequence, len(names))
		for j, n := range names {
			labels[j] = DNSLabelSequence{Label: n}
		}
		rtype := binary.BigEndian.Uint16(buf[i : i+2])
		i += 2
		class := binary.BigEndian.Uint16(buf[i : i+2])
		i += 2
		ttl := int32(binary.BigEndian.Uint32(buf[i : i+4]))
		i += 4
		rdlength := int(binary.BigEndian.Uint16(buf[i : i+2]))
		i += 2
		records = append(records, ResourceRecord{
			Name:  labels,
			Type:  rtype,
			Class: class,
			TTL:   ttl,
			Data:  buf[i : i+rdlength],
		})
		i += rdlength
	}
	return records
}

// --- Helpers ---

func NewResourceRecord(q DNSQuestion) ResourceRecord {
	return ResourceRecord{
		Name:  q.Name,
		Type:  q.Type,
		Class: q.Class,
		TTL:   60,
		Data:  []byte{0x08, 0x08, 0x08, 0x08},
	}
}

func NewDNSRequest(h DNSHeader, qs []DNSQuestion, as []DNSAnswer) DNSRequest {
	r := DNSRequest{
		Header:    h,
		Questions: qs,
		Answers:   as,
	}

	r.Header.QDCOUNT = uint16(len(qs))
	r.Header.ANCOUNT = uint16(len(as))
	return r
}

// --- Entry point ---
func parseArgs() (resolverAddr *net.UDPAddr) {
	args := os.Args[1:]
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "--resolver" {
			addr, err := net.ResolveUDPAddr("udp", args[i+1])
			if err != nil {
				fmt.Fprintf(os.Stderr, "Invalid resolver address %q: %v\n", args[i+1], err)
				os.Exit(1)
			}
			return addr
		}
	}
	return nil
}

func main() {
	fmt.Println("Logs from your program will appear here!")

	resolverAddr := parseArgs()
	if resolverAddr != nil {
		fmt.Printf("Forwarding queries to resolver: %s\n", resolverAddr)
	}

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

		answers := []DNSAnswer{}

		requestsToForward := []DNSRequest{}
		for _, question := range receivedQuestions {
			requestsToForward = append(requestsToForward, NewDNSRequest(receivedHeader, []DNSQuestion{question}, []DNSAnswer{}))
		}

		if resolverAddr != nil {
			for _, req := range requestsToForward {
				resp, err := forwardRequest(req, resolverAddr)
				if err != nil {
					fmt.Println("Failed to forward request:", err)
					continue
				}
				records := ParseAnswers(resp)
				answers = append(answers, DNSAnswer{Records: records})
			}
		} else {
			for _, question := range receivedQuestions {
				record := NewResourceRecord(question)
				answers = append(answers, DNSAnswer{Records: []ResourceRecord{record}})
			}
		}

		testResponse := NewDNSRequest(DNSHeader{
			ID:      receivedHeader.ID,
			QR:      1,
			OPCODE:  receivedHeader.OPCODE,
			AA:      0,
			TC:      0,
			RD:      receivedHeader.RD,
			RA:      0,
			Z:       0,
			RCODE:   responseRcode,
			QDCOUNT: uint16(len(receivedQuestions)),
			ANCOUNT: uint16(len(answers)),
			NSCOUNT: 0,
			ARCOUNT: 0,
		}, receivedQuestions, answers)

		response := testResponse.Serialize()
		_, err = udpConn.WriteToUDP(response, source)
		if err != nil {
			fmt.Println("Failed to send response:", err)
		}
	}
}
