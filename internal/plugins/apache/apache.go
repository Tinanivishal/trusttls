package apache

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
	serverNameRe   = regexp.MustCompile(`(?i)^\s*ServerName\s+(.+)$`)
	documentRootRe = regexp.MustCompile(`(?i)^\s*DocumentRoot\s+(.+)$`)
	sslEngineRe    = regexp.MustCompile(`(?i)^\s*SSLEngine\s+(.+)$`)
	sslCertRe      = regexp.MustCompile(`(?i)^\s*SSLCertificateFile\s+(.+)$`)
)

func Available() bool {
    // Prefer checking if service is actually running
    if osutil.IsActiveSystemd("apache2") || osutil.IsActiveSystemd("httpd") {
        return true
    }
    if osutil.HasProcess("apache2", "httpd") {
        return true
    }
    return false
}

func DetectSSLMode(domain string) bool {
	for _, dir := range candidateConfDirs() {
		if scanVhostsForSSL(dir, domain) {
			return true
		}
	}
	return false
}

func scanVhostsForSSL(dir, domain string) bool {
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
				if strings.EqualFold(m[1], domain) { seenDomain = true }
			}
			if m := sslEngineRe.FindStringSubmatch(line); len(m) == 2 {
				if strings.EqualFold(strings.TrimSpace(m[1]), "on") { sslEnabled = true }
			}
		}
		_ = f.Close()
		if seenDomain && sslEnabled { return true }
	}
	return false
}

func DetectWebroot(domain string) string {
	for _, dir := range candidateConfDirs() {
		root := scanVhostsForDomain(dir, domain)
		if root != "" { return root }
	}
	return ""
}

func candidateConfDirs() []string {
	c := []string{
		"/etc/apache2/sites-enabled",
		"/etc/apache2/sites-available",
		"/etc/httpd/conf.d",
		"/etc/apache2/vhosts.d",
	}
	if osutil.IsMac() {
		c = append(c, "/etc/apache2/other", "/private/etc/apache2/other")
	}
	return c
}

func scanVhostsForDomain(dir, domain string) string {
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.IsDir() { continue }
		path := filepath.Join(dir, e.Name())
		f, err := os.Open(path)
		if err != nil { continue }
		s := bufio.NewScanner(f)
		var seen bool
		var docroot string
		for s.Scan() {
			line := strings.TrimSpace(s.Text())
			if m := serverNameRe.FindStringSubmatch(line); len(m) == 2 {
				if strings.EqualFold(m[1], domain) { seen = true }
			}
			if m := documentRootRe.FindStringSubmatch(line); len(m) == 2 {
				docroot = strings.Trim(m[1], `"`)
			}
		}
		_ = f.Close()
		if seen && docroot != "" { return docroot }
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
		if configPath := findVhostForDomain(dir, domain); configPath != "" {
			return configPath, "apache"
		}
	}
	return "", "apache"
}

func findVhostForDomain(dir, domain string) string {
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
				if strings.EqualFold(m[1], domain) { 
					_ = f.Close()
					return path 
				}
			}
		}
		_ = f.Close()
	}
	return ""
}

func (i *installer) Install(domain string) error {
	if !i.assumeYes {
		return fmt.Errorf("confirmation required: re-run with --yes to write Apache SSL vhost for %s", domain)
	}
	cert, key, _, full := store.LoadCertPaths(i.storeDir, domain)
	conf := sslVhostConf(domain, cert, key, full)
	outDir := apacheVhostOutDir()
	if err := os.MkdirAll(outDir, 0755); err != nil { return err }
	out := filepath.Join(outDir, domain+"-le-ssl.conf")
	if err := os.WriteFile(out, []byte(conf), 0644); err != nil { return err }
	// Enable site if Debian-style
	if strings.Contains(outDir, "sites-available") {
		link := filepath.Join(filepath.Dir(outDir), "sites-enabled", filepath.Base(out))
		_ = os.MkdirAll(filepath.Dir(link), 0755)
		_ = os.Symlink(out, link)
	}
	// Try to reload gracefully
	_ = osutil.Run("apache2ctl", "graceful")
	_ = osutil.Run("apachectl", "graceful")
	_ = osutil.Run("service", "apache2", "reload")
	_ = osutil.Run("service", "httpd", "reload")
	return nil
}

func apacheVhostOutDir() string {
	c := []string{
		"/etc/apache2/sites-available",
		"/etc/httpd/conf.d",
		"/etc/apache2/vhosts.d",
	}
	for _, d := range c {
		if osutil.DirExists(d) { return d }
	}
	return "/etc/apache2/sites-available"
}

func sslVhostConf(domain, cert, key, fullchain string) string {
	return fmt.Sprintf(`<IfModule mod_ssl.c>
<VirtualHost *:443>
    ServerName %s
    SSLEngine on
    SSLCertificateFile %s
    SSLCertificateKeyFile %s
    SSLCertificateChainFile %s
    # Optional: redirect from HTTP handled elsewhere
    # DocumentRoot picked from port 80 vhost
</VirtualHost>
</IfModule>
`, domain, cert, key, fullchain)
}
