package netpol

import (
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// dnsProxy is the edge's resolver for its sandboxes (spec §20.3). A query
// for an allowed name is forwarded upstream, and the IPv4 addresses in the
// answer become reachable for the asking sandbox before it gets them. Other
// names get NXDOMAIN; AAAA queries an empty answer (sandboxes have IPv4
// only). The sandbox is told by the query's source address.
type dnsProxy struct {
	m        *Manager
	upstream []string
	udp      *net.UDPConn
	tcp      *net.TCPListener
	wg       sync.WaitGroup
}

const dnsTimeout = 3 * time.Second

func startDNS(m *Manager, port int, upstream []string) (*dnsProxy, error) {
	d := &dnsProxy{m: m}
	for _, u := range upstream {
		if _, _, err := net.SplitHostPort(u); err != nil {
			u = net.JoinHostPort(u, "53")
		}
		d.upstream = append(d.upstream, u)
	}
	var err error
	if d.udp, err = net.ListenUDP("udp4", &net.UDPAddr{Port: port}); err != nil {
		return nil, err
	}
	if d.tcp, err = net.ListenTCP("tcp4", &net.TCPAddr{Port: port}); err != nil {
		d.udp.Close()
		return nil, err
	}
	d.wg.Add(2)
	go d.serveUDP()
	go d.serveTCP()
	return d, nil
}

func (d *dnsProxy) close() {
	d.udp.Close()
	d.tcp.Close()
	d.wg.Wait()
}

func (d *dnsProxy) serveUDP() {
	defer d.wg.Done()
	buf := make([]byte, 4096)
	for {
		n, src, err := d.udp.ReadFromUDP(buf)
		if err != nil {
			return
		}
		q := append([]byte(nil), buf[:n]...)
		go func() {
			if resp := d.handle(q, src.IP, false); resp != nil {
				d.udp.WriteToUDP(resp, src)
			}
		}()
	}
}

func (d *dnsProxy) serveTCP() {
	defer d.wg.Done()
	for {
		c, err := d.tcp.AcceptTCP()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			for {
				c.SetDeadline(time.Now().Add(10 * time.Second))
				q, err := readTCPMsg(c)
				if err != nil {
					return
				}
				resp := d.handle(q, c.RemoteAddr().(*net.TCPAddr).IP, true)
				if resp == nil || writeTCPMsg(c, resp) != nil {
					return
				}
			}
		}()
	}
}

func readTCPMsg(r io.Reader) ([]byte, error) {
	var l [2]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return nil, err
	}
	b := make([]byte, binary.BigEndian.Uint16(l[:]))
	_, err := io.ReadFull(r, b)
	return b, err
}

func writeTCPMsg(w io.Writer, b []byte) error {
	out := make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(out, uint16(len(b)))
	copy(out[2:], b)
	_, err := w.Write(out)
	return err
}

// handle answers query q from src; nil drops it.
func (d *dnsProxy) handle(q []byte, src net.IP, overTCP bool) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(q)
	if err != nil || h.Response {
		return nil
	}
	qs, err := p.AllQuestions()
	if err != nil || len(qs) != 1 {
		return reply(h, qs, dnsmessage.RCodeFormatError)
	}
	a := d.m.byAddr(src)
	if a == nil {
		return reply(h, qs, dnsmessage.RCodeRefused)
	}
	name := strings.TrimSuffix(strings.ToLower(qs[0].Name.String()), ".")
	if !a.current().allowsName(name) {
		return reply(h, qs, dnsmessage.RCodeNameError)
	}
	if qs[0].Type == dnsmessage.TypeAAAA {
		return reply(h, qs, dnsmessage.RCodeSuccess)
	}
	resp, err := d.forward(q, overTCP)
	if err != nil {
		return reply(h, qs, dnsmessage.RCodeServerFailure)
	}
	ips, ttl := answerA(resp)
	if len(ips) > 0 {
		if err := a.learn(name, ips, ttl); err != nil {
			d.m.log.Warn("netpol: allow resolved addresses", "lease", a.Lease, "name", name, "err", err)
			return reply(h, qs, dnsmessage.RCodeServerFailure)
		}
	}
	return resp
}

// forward asks the upstream resolvers in turn (over TCP when the UDP
// answer is truncated, or the query came over TCP).
func (d *dnsProxy) forward(q []byte, overTCP bool) ([]byte, error) {
	var lastErr error
	for _, u := range d.upstream {
		resp, err := exchange(u, q, overTCP)
		if err == nil && !overTCP && truncated(resp) {
			resp, err = exchange(u, q, true)
		}
		if err == nil {
			return resp, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func exchange(server string, q []byte, overTCP bool) ([]byte, error) {
	network := "udp"
	if overTCP {
		network = "tcp"
	}
	c, err := net.DialTimeout(network, server, dnsTimeout)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(dnsTimeout))
	if overTCP {
		if err := writeTCPMsg(c, q); err != nil {
			return nil, err
		}
		return readTCPMsg(c)
	}
	if _, err := c.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func truncated(resp []byte) bool {
	var p dnsmessage.Parser
	h, err := p.Start(resp)
	return err == nil && h.Truncated
}

// answerA returns the A records of resp (CNAME targets included, as they
// answer the same question) and their smallest TTL.
func answerA(resp []byte) ([]net.IP, time.Duration) {
	var p dnsmessage.Parser
	if _, err := p.Start(resp); err != nil {
		return nil, 0
	}
	p.SkipAllQuestions()
	var ips []net.IP
	ttl := time.Duration(-1)
	for {
		rh, err := p.AnswerHeader()
		if err != nil {
			break
		}
		if rh.Type != dnsmessage.TypeA {
			p.SkipAnswer()
			continue
		}
		r, err := p.AResource()
		if err != nil {
			break
		}
		ips = append(ips, net.IP(r.A[:]).To4())
		if t := time.Duration(rh.TTL) * time.Second; ttl < 0 || t < ttl {
			ttl = t
		}
	}
	return ips, max(ttl, 0)
}

func reply(h dnsmessage.Header, qs []dnsmessage.Question, rcode dnsmessage.RCode) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, OpCode: h.OpCode,
		RecursionDesired: h.RecursionDesired, RecursionAvailable: true, RCode: rcode})
	b.EnableCompression()
	b.StartQuestions()
	for _, q := range qs {
		b.Question(q)
	}
	out, err := b.Finish()
	if err != nil {
		return nil
	}
	return out
}
