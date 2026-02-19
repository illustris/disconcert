package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"time"
)

var privateRanges []*net.IPNet

func init() {
	for _, cidr := range []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"100.64.0.0/10",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	} {
		_, ipNet, _ := net.ParseCIDR(cidr)
		privateRanges = append(privateRanges, ipNet)
	}
}

func isPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, r := range privateRanges {
		if r.Contains(ip) {
			return false
		}
	}
	return true
}

func allPublic(addrs []string) bool {
	for _, a := range addrs {
		if !isPublicIP(net.ParseIP(a)) {
			return false
		}
	}
	return true
}

type result struct {
	IP        string `json:"ip"`
	CN        string `json:"cn"`
	DNSResult string `json:"dns_result"`
	Status    string `json:"status"`
}

func main() {
	dnsServer := flag.String("d", "", "Custom DNS server (e.g. 8.8.8.8)")
	jsonOutput := flag.Bool("j", false, "Output results as JSON")
	lax := flag.Bool("l", false, "Lax mode: treat IP mismatch as OK if both IPs are public")
	port := flag.String("p", "443", "TLS port")
	quiet := flag.Bool("q", false, "Quiet: suppress results for IPs that failed to connect")
	timeout := flag.Duration("t", 5*time.Second, "Connection timeout")
	verbose := flag.Bool("v", false, "Verbose: log each connection and DNS step to stderr")
	workers := flag.Int("w", 32, "Number of concurrent workers")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: disconcert [flags] <ip|cidr|asn> [...]\n\nFlags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	var debug *log.Logger
	if *verbose {
		debug = log.New(os.Stderr, "DEBUG: ", 0)
	} else {
		debug = log.New(io.Discard, "", 0)
	}

	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}

	// Collect all IPs from arguments
	var ips []net.IP
	for _, arg := range flag.Args() {
		if asn, ok := isASN(arg); ok {
			prefixes, err := resolveASN(asn, *timeout, debug)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error resolving %s: %v\n", asn, err)
				os.Exit(2)
			}
			for _, prefix := range prefixes {
				if strings.Contains(prefix, ":") {
					debug.Printf("%s: skipping IPv6 prefix %s", asn, prefix)
					continue
				}
				parsed, err := parseTarget(prefix)
				if err != nil {
					debug.Printf("%s: skipping prefix %s: %v", asn, prefix, err)
					continue
				}
				ips = append(ips, parsed...)
			}
			continue
		}
		parsed, err := parseTarget(arg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing %q: %v\n", arg, err)
			os.Exit(2)
		}
		ips = append(ips, parsed...)
	}

	// Set up DNS resolver
	var resolver *net.Resolver
	if *dnsServer != "" {
		server := *dnsServer
		if !strings.Contains(server, ":") {
			server = server + ":53"
		}
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: *timeout}
				return d.DialContext(ctx, "udp", server)
			},
		}
	} else {
		resolver = net.DefaultResolver
	}

	// Process IPs with worker pool
	var (
		mu        sync.Mutex
		wg        sync.WaitGroup
		results   []result
		sem       = make(chan struct{}, *workers)
		completed int
		total     = len(ips)
		showBar   = total > 1
	)

	for _, ip := range ips {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip net.IP) {
			defer wg.Done()
			defer func() { <-sem }()
			r := processIP(ip, *port, *timeout, resolver, *lax, debug)
			mu.Lock()
			results = append(results, r)
			completed++
			if showBar {
				fmt.Fprintf(os.Stderr, "\rScanning: %d/%d IPs", completed, total)
			}
			mu.Unlock()
		}(ip)
	}
	wg.Wait()
	if showBar {
		fmt.Fprintf(os.Stderr, "\r%s\r", strings.Repeat(" ", 40))
	}

	// Sort results by IP
	sort.Slice(results, func(i, j int) bool {
		a := net.ParseIP(results[i].IP)
		b := net.ParseIP(results[j].IP)
		return bytes4(a).Less(bytes4(b))
	})

	// Filter results
	var filtered []result
	for _, r := range results {
		if *quiet && strings.HasPrefix(r.Status, "ERROR") {
			continue
		}
		filtered = append(filtered, r)
	}

	// Print results
	if *jsonOutput {
		json.NewEncoder(os.Stdout).Encode(filtered)
	} else {
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "IP\tCN\tDNS Result\tStatus")
		for _, r := range filtered {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", r.IP, r.CN, r.DNSResult, r.Status)
		}
		w.Flush()
	}

	// Exit code
	for _, r := range filtered {
		if strings.HasPrefix(r.Status, "FLAGGED") || strings.HasPrefix(r.Status, "ERROR") {
			os.Exit(1)
		}
	}
}

func parseTarget(s string) ([]net.IP, error) {
	// Try CIDR first
	_, ipNet, err := net.ParseCIDR(s)
	if err == nil {
		return expandCIDR(ipNet), nil
	}

	// Try single IP
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, fmt.Errorf("invalid target: %s", s)
	}
	return []net.IP{ip}, nil
}

func expandCIDR(ipNet *net.IPNet) []net.IP {
	ones, bits := ipNet.Mask.Size()

	// /32 (or /128): just the single IP
	if ones == bits {
		return []net.IP{ipNet.IP}
	}

	// /31 (or /127): both IPs (point-to-point link)
	if ones == bits-1 {
		var ips []net.IP
		for ip := cloneIP(ipNet.IP); ipNet.Contains(ip); incIP(ip) {
			ips = append(ips, cloneIP(ip))
		}
		return ips
	}

	// Normal range: skip network and broadcast addresses
	var ips []net.IP
	ip := cloneIP(ipNet.IP)
	incIP(ip) // skip network address
	for ; ipNet.Contains(ip); incIP(ip) {
		// Check if this is the broadcast address
		next := cloneIP(ip)
		incIP(next)
		if !ipNet.Contains(next) {
			break // this is the broadcast address
		}
		ips = append(ips, cloneIP(ip))
	}
	return ips
}

func isASN(s string) (string, bool) {
	if len(s) < 3 {
		return "", false
	}
	prefix := strings.ToUpper(s[:2])
	if prefix != "AS" {
		return "", false
	}
	digits := s[2:]
	if len(digits) == 0 {
		return "", false
	}
	for _, r := range digits {
		if r < '0' || r > '9' {
			return "", false
		}
	}
	return "AS" + digits, true
}

type ripePrefix struct {
	Prefix string `json:"prefix"`
}

type ripeData struct {
	Prefixes []ripePrefix `json:"prefixes"`
}

type ripeResponse struct {
	Status string   `json:"status"`
	Data   ripeData `json:"data"`
}

func resolveASN(asn string, timeout time.Duration, debug *log.Logger) ([]string, error) {
	url := "https://stat.ripe.net/data/announced-prefixes/data.json?resource=" + asn
	debug.Printf("%s: fetching announced prefixes from RIPE", asn)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching RIPE data: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("RIPE API returned HTTP %d", resp.StatusCode)
	}

	var ripe ripeResponse
	if err := json.NewDecoder(resp.Body).Decode(&ripe); err != nil {
		return nil, fmt.Errorf("decoding RIPE response: %w", err)
	}

	if ripe.Status != "ok" {
		return nil, fmt.Errorf("RIPE API status: %s", ripe.Status)
	}

	if len(ripe.Data.Prefixes) == 0 {
		return nil, fmt.Errorf("no announced prefixes for %s", asn)
	}

	prefixes := make([]string, len(ripe.Data.Prefixes))
	for i, p := range ripe.Data.Prefixes {
		prefixes[i] = p.Prefix
	}
	debug.Printf("%s: found %d announced prefixes", asn, len(prefixes))
	return prefixes, nil
}

func cloneIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func processIP(ip net.IP, port string, timeout time.Duration, resolver *net.Resolver, lax bool, debug *log.Logger) result {
	addr := net.JoinHostPort(ip.String(), port)

	debug.Printf("%s: connecting to %s", ip, addr)
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		debug.Printf("%s: TLS failed: %s", ip, err)
		return result{
			IP:        ip.String(),
			CN:        "-",
			DNSResult: "-",
			Status:    fmt.Sprintf("ERROR: %s", tlsErrorSummary(err)),
		}
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return result{
			IP:        ip.String(),
			CN:        "-",
			DNSResult: "-",
			Status:    "ERROR: no certificates",
		}
	}

	cn := certs[0].Subject.CommonName
	if cn == "" && len(certs[0].DNSNames) > 0 {
		cn = certs[0].DNSNames[0]
	}
	debug.Printf("%s: TLS OK, CN=%s", ip, cn)
	if cn == "" {
		return result{
			IP:        ip.String(),
			CN:        "-",
			DNSResult: "-",
			Status:    "ERROR: no CN or SAN",
		}
	}

	// DNS lookup
	debug.Printf("%s: looking up %s", ip, cn)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	addrs, err := resolver.LookupHost(ctx, cn)
	if err != nil {
		debug.Printf("%s: DNS error: %s", ip, err)
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			return result{
				IP:        ip.String(),
				CN:        cn,
				DNSResult: "-",
				Status:    "FLAGGED: NXDOMAIN",
			}
		}
		return result{
			IP:        ip.String(),
			CN:        cn,
			DNSResult: "-",
			Status:    fmt.Sprintf("ERROR: DNS lookup failed: %s", err),
		}
	}
	debug.Printf("%s: %s -> %s", ip, cn, addrs)

	dnsResult := strings.Join(addrs, ",")
	ipStr := ip.String()
	for _, a := range addrs {
		if a == ipStr {
			return result{
				IP:        ipStr,
				CN:        cn,
				DNSResult: dnsResult,
				Status:    "OK",
			}
		}
	}

	if lax && isPublicIP(net.ParseIP(ipStr)) && allPublic(addrs) {
		return result{
			IP:        ipStr,
			CN:        cn,
			DNSResult: dnsResult,
			Status:    "OK (lax)",
		}
	}

	return result{
		IP:        ipStr,
		CN:        cn,
		DNSResult: dnsResult,
		Status:    "FLAGGED: IP mismatch",
	}
}

func tlsErrorSummary(err error) string {
	s := err.Error()
	// Extract the most useful part of common TLS/connection errors
	if strings.Contains(s, "connection refused") {
		return "connection refused"
	}
	if strings.Contains(s, "i/o timeout") {
		return "timeout"
	}
	if strings.Contains(s, "no route to host") {
		return "no route to host"
	}
	if strings.Contains(s, "connection reset") {
		return "connection reset"
	}
	return s
}

// bytes4 is a sortable representation of an IP address.
type ipBytes [16]byte

func bytes4(ip net.IP) ipBytes {
	var b ipBytes
	copy(b[:], ip.To16())
	return b
}

func (a ipBytes) Less(b ipBytes) bool {
	la := binary.BigEndian.Uint64(a[:8])
	lb := binary.BigEndian.Uint64(b[:8])
	if la != lb {
		return la < lb
	}
	ra := binary.BigEndian.Uint64(a[8:])
	rb := binary.BigEndian.Uint64(b[8:])
	return ra < rb
}
