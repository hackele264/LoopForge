package domain

import (
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// IOC types.
const (
	IOCIPv4   = "ipv4"
	IOCDomain = "domain"
	IOCURL    = "url"
	IOCEmail  = "email"
	IOCMD5    = "md5"
	IOCSHA1   = "sha1"
	IOCSHA256 = "sha256"
	IOCCVE    = "cve"
)

// IOCTypes lists the indicator types, for validation of manual entries.
var IOCTypes = []string{IOCIPv4, IOCDomain, IOCURL, IOCEmail, IOCMD5, IOCSHA1, IOCSHA256, IOCCVE}

// MaxIOCsPerAlert bounds extraction from one payload.
const MaxIOCsPerAlert = 200

var (
	iocURLPattern    = regexp.MustCompile(`(?i)\bhttps?://[^\s"'<>()\[\]{}]+`)
	iocEmailPattern  = regexp.MustCompile(`(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,24}\b`)
	iocIPv4Pattern   = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	iocHashPattern   = regexp.MustCompile(`(?i)\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b`)
	iocCVEPattern    = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,7}\b`)
	iocDomainPattern = regexp.MustCompile(`(?i)^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$`)
)

// Suffixes that look like domains but are almost always file names.
var iocFileSuffixes = map[string]bool{"exe": true, "dll": true, "txt": true, "log": true, "json": true, "xml": true, "zip": true, "pdf": true, "doc": true, "docx": true, "xls": true, "xlsx": true, "ps1": true, "sh": true, "py": true, "js": true, "html": true, "htm": true, "png": true, "jpg": true, "gif": true, "csv": true, "tmp": true, "bat": true, "vbs": true, "jar": true, "msi": true, "lnk": true}

// ExtractIOCs walks every string in a decoded JSON payload and returns the
// indicators found, deduplicated and sorted by type then value. Domains are
// taken from URLs, email addresses and string values that are a bare
// hostname, not from free text, to keep file names out.
func ExtractIOCs(payload any) []CaseIOC {
	seen := map[string]bool{}
	var out []CaseIOC
	add := func(kind, value string) {
		value = strings.TrimSpace(value)
		if value == "" || len(out) >= MaxIOCsPerAlert {
			return
		}
		key := kind + "\x00" + strings.ToLower(value)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, CaseIOC{Type: kind, Value: value})
	}
	addDomain := func(host string) {
		host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
		if host == "" || net.ParseIP(host) != nil || !iocDomainPattern.MatchString(host) {
			return
		}
		tld := host[strings.LastIndexByte(host, '.')+1:]
		if iocFileSuffixes[tld] {
			return
		}
		add(IOCDomain, host)
	}
	var walk func(v any)
	walk = func(v any) {
		switch node := v.(type) {
		case map[string]any:
			keys := make([]string, 0, len(node))
			for k := range node {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				walk(node[k])
			}
		case []any:
			for _, item := range node {
				walk(item)
			}
		case string:
			text := node
			for _, raw := range iocURLPattern.FindAllString(text, -1) {
				raw = strings.TrimRight(raw, ".,;:!?")
				add(IOCURL, raw)
				if u, err := url.Parse(raw); err == nil {
					if ip := net.ParseIP(u.Hostname()); ip != nil && ip.To4() != nil {
						add(IOCIPv4, ip.String())
					} else {
						addDomain(u.Hostname())
					}
				}
			}
			for _, email := range iocEmailPattern.FindAllString(text, -1) {
				add(IOCEmail, strings.ToLower(email))
				addDomain(email[strings.IndexByte(email, '@')+1:])
			}
			for _, candidate := range iocIPv4Pattern.FindAllString(text, -1) {
				if ip := net.ParseIP(candidate); ip != nil && ip.To4() != nil {
					add(IOCIPv4, ip.String())
				}
			}
			for _, h := range iocHashPattern.FindAllString(text, -1) {
				switch len(h) {
				case 32:
					add(IOCMD5, strings.ToLower(h))
				case 40:
					add(IOCSHA1, strings.ToLower(h))
				case 64:
					add(IOCSHA256, strings.ToLower(h))
				}
			}
			for _, cve := range iocCVEPattern.FindAllString(text, -1) {
				add(IOCCVE, strings.ToUpper(cve))
			}
			addDomain(text)
		}
	}
	walk(payload)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].Value < out[j].Value
	})
	return out
}
