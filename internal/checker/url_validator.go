package checker

import (
	"context"
	"fmt"
	"net"
	"net/url"
)

const maxURLLength = 2048

func validateURL(ctx context.Context, rawURL string) error {
	if len(rawURL) > maxURLLength {
		return &ErrInvalidURL{URL: rawURL, Reason: fmt.Sprintf("exceeds maximum length of %d characters", maxURLLength)}
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return &ErrInvalidURL{URL: rawURL, Reason: "failed to parse URL"}
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return &ErrInvalidURL{URL: rawURL, Reason: fmt.Sprintf("scheme %q not allowed, must be http or https", parsed.Scheme)}
	}

	host := parsed.Hostname()
	if host == "" {
		return &ErrInvalidURL{URL: rawURL, Reason: "missing host"}
	}

	// If the host is a literal IP, check it directly.
	// Otherwise resolve the hostname and check every returned address.
	if ip := net.ParseIP(host); ip != nil {
		return checkIP(ip, rawURL)
	}

	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return &ErrInvalidURL{URL: rawURL, Reason: fmt.Sprintf("could not resolve host: %v", err)}
	}
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		if err := checkIP(ip, rawURL); err != nil {
			return err
		}
	}

	return nil
}

func checkIP(ip net.IP, rawURL string) error {
	if ip.IsLoopback() {
		return &ErrInvalidURL{URL: rawURL, Reason: "host resolves to loopback address"}
	}
	if ip.IsPrivate() {
		return &ErrInvalidURL{URL: rawURL, Reason: "host resolves to private IP range"}
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return &ErrInvalidURL{URL: rawURL, Reason: "host resolves to link-local address"}
	}
	if ip.IsMulticast() {
		return &ErrInvalidURL{URL: rawURL, Reason: "host resolves to multicast address"}
	}
	if ip.IsUnspecified() {
		return &ErrInvalidURL{URL: rawURL, Reason: "host resolves to unspecified address"}
	}

	// Block cloud metadata addresses not covered by the above checks.
	// AWS/GCP/Azure metadata service: 169.254.169.254
	// GCP also uses 169.254.169.253 and the IPv6 fd00:ec2::254
	for _, blocked := range blockedCIDRs {
		if blocked.Contains(ip) {
			return &ErrInvalidURL{URL: rawURL, Reason: fmt.Sprintf("host resolves to blocked range %s", blocked)}
		}
	}

	return nil
}

// blockedCIDRs lists ranges that are not caught by the net.IP helper methods
// but must still be blocked for SSRF protection.
var blockedCIDRs = func() []*net.IPNet {
	ranges := []string{
		"169.254.0.0/16",  // link-local (belt-and-suspenders; also caught by IsLinkLocalUnicast)
		"100.64.0.0/10",   // IANA shared address space (RFC 6598)
		"192.0.0.0/24",    // IANA IETF protocol assignments
		"192.0.2.0/24",    // TEST-NET-1 (RFC 5737)
		"198.51.100.0/24", // TEST-NET-2 (RFC 5737)
		"203.0.113.0/24",  // TEST-NET-3 (RFC 5737)
		"240.0.0.0/4",     // reserved (RFC 1112)
		"0.0.0.0/8",       // "this" network (RFC 791)
		"fd00:ec2::/32",   // GCP internal metadata (IPv6)
	}

	nets := make([]*net.IPNet, 0, len(ranges))
	for _, r := range ranges {
		_, network, err := net.ParseCIDR(r)
		if err != nil {
			panic(fmt.Sprintf("url_validator: invalid built-in CIDR %q: %v", r, err))
		}
		nets = append(nets, network)
	}
	return nets
}()
