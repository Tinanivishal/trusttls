package nginx

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/trustctl/trusttls/internal/osutil"
	"github.com/trustctl/trusttls/internal/store"
)

var (
	serverNameRe = regexp.MustCompile(`(?i)^\s*server_name\s+([^;]+);`)
	rootRe       = regexp.MustCompile(`(?i)^\s*root\s+([^;]+);`)
	sslListenRe  = regexp.MustCompile(`(?i)^\s*listen\s+(\d+)\s+ssl;`)
	sslCertRe    = regexp.MustCompile(`(?i)^\s*ssl_certificate\s+([^;]+);`)
)

func Available() bool {
    if osutil.IsActiveSystemd("nginx") { return true }
    if osutil.HasProcess("nginx") { return true }
    return false
}

func DetectSSLMode(domain string) bool {
	for _, dir := range candidateConfDirs() {
		if scanServersForSSL(dir, domain) {
			return true
		}
	}
	return false
}

func scanServersForSSL(dir, domain string) bool {
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.IsDir() { continue }
		path := filepath.Join(dir, e.Name())
		f, err := os.Open(path)
		if err != nil { continue }
		s := bufio.NewScanner(f)
		var seenDomain bool
		var sslEnabled bool
		for s.Scan() {
			line := strings.TrimSpace(s.Text())
			if m := serverNameRe.FindStringSubmatch(line); len(m) == 2 {
				for _, n := range strings.Fields(m[1]) {
					if strings.EqualFold(n, domain) { seenDomain = true }
				}
			}
			if sslListenRe.MatchString(line) || sslCertRe.MatchString(line) {
				sslEnabled = true
			}
		}
		_ = f.Close()
		if seenDomain && sslEnabled { return true }
	}
	return false
}

func DetectWebroot(domain string) string {
	for _, dir := range candidateConfDirs() {
		root := scanServersForDomain(dir, domain)
		if root != "" { return root }
	}
	return ""
}

func candidateConfDirs() []string {
	return []string{
		"/etc/nginx/sites-enabled",
		"/etc/nginx/conf.d",
		"/etc/nginx/sites-available",
		"/usr/local/etc/nginx/servers",
	}
}

func scanServersForDomain(dir, domain string) string {
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.IsDir() { continue }
		path := filepath.Join(dir, e.Name())
		f, err := os.Open(path)
		if err != nil { continue }
		s := bufio.NewScanner(f)
		var seen bool
		var webroot string
		for s.Scan() {
			line := strings.TrimSpace(s.Text())
			if m := serverNameRe.FindStringSubmatch(line); len(m) == 2 {
				for _, n := range strings.Fields(m[1]) {
					if strings.EqualFold(n, domain) { seen = true }
				}
			}
			if m := rootRe.FindStringSubmatch(line); len(m) == 2 {
				webroot = strings.Trim(m[1], `"`)
			}
		}
		_ = f.Close()
		if seen && webroot != "" { return webroot }
	}
	return ""
}

type installer struct {
	storeDir  string
	assumeYes bool
}

func NewInstaller(storeDir string, assumeYes bool) *installer {
	return &installer{storeDir: storeDir, assumeYes: assumeYes}
}

func (i *installer) Webroot(domain string) string { return DetectWebroot(domain) }

func (i *installer) IsSSLEnabled(domain string) bool { return DetectSSLMode(domain) }

func (i *installer) DetectVhost(domain string) (string, string) {
	for _, dir := range candidateConfDirs() {
		if configPath := findServerForDomain(dir, domain); configPath != "" {
			return configPath, "nginx"
		}
	}
	return "", "nginx"
}

func findServerForDomain(dir, domain string) string {
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.IsDir() { continue }
		path := filepath.Join(dir, e.Name())
		f, err := os.Open(path)
		if err != nil { continue }
		s := bufio.NewScanner(f)
		for s.Scan() {
			line := strings.TrimSpace(s.Text())
			if m := serverNameRe.FindStringSubmatch(line); len(m) == 2 {
				for _, n := range strings.Fields(m[1]) {
					if strings.EqualFold(n, domain) { 
						_ = f.Close()
						return path 
					}
				}
			}
		}
		_ = f.Close()
	}
	return ""
}

func (i *installer) Install(domain string) error {
	if !i.assumeYes {
		return fmt.Errorf("confirmation required: re-run with --yes to write Nginx SSL server for %s", domain)
	}
	cert, key, _, full := store.LoadCertPaths(i.storeDir, domain)
	conf := sslServerConf(domain, cert, key, full)
	outDir := nginxServerOutDir()
	if err := os.MkdirAll(outDir, 0755); err != nil { return err }
	out := filepath.Join(outDir, domain+"-le-ssl.conf")
	if err := os.WriteFile(out, []byte(conf), 0644); err != nil { return err }
	_ = osutil.Run("nginx", "-s", "reload")
	_ = osutil.Run("service", "nginx", "reload")
	return nil
}

func nginxServerOutDir() string {
	c := []string{
		"/etc/nginx/conf.d",
		"/etc/nginx/sites-enabled",
		"/usr/local/etc/nginx/servers",
	}
	for _, d := range c { if osutil.DirExists(d) { return d } }
	return "/etc/nginx/conf.d"
}

func sslServerConf(domain, cert, key, fullchain string) string {
	return fmt.Sprintf(`server {
    listen 443 ssl;
    server_name %s;
    ssl_certificate %s;
    ssl_certificate_key %s;
    ssl_trusted_certificate %s;
}
`, domain, fullchain, key, fullchain)
}
