package mitm

import (
	"container/list"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// CA is the user's MitM root. The private key lives only in the App Group container
// (<home>/engine/ca/ca.key, 0600); it is never bundled or committed.
type CA struct {
	Cert    *x509.Certificate
	Key     crypto.Signer
	DER     []byte
	leafKey *ecdsa.PrivateKey

	mu    sync.Mutex
	cache map[string]*list.Element
	lru   *list.List
	max   int
}

type leafEntry struct {
	host string
	cert *tls.Certificate
}

func caDir(home string) string { return filepath.Join(EngineDir(home), "ca") }

// CAInfo is shown in the app.
type CAInfo struct {
	Exists      bool   `json:"exists"`
	Subject     string `json:"subject,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"` // SHA-256
	SHA1        string `json:"sha1,omitempty"`
	NotBefore   string `json:"notBefore,omitempty"`
	NotAfter    string `json:"notAfter,omitempty"`
	Algorithm   string `json:"algorithm,omitempty"`
}

// GenerateCA creates a new ECDSA P-256 root valid for 10 years and writes it to the container.
func GenerateCA(home string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	suffix := strings.ToUpper(hex.EncodeToString(serial.Bytes()[:3]))
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Tern MitM CA " + suffix, Organization: []string{"Tern"}},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	dir := caDir(home)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := writeAtomic(filepath.Join(dir, "ca.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		return nil, err
	}
	if err := writeAtomic(filepath.Join(dir, "ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return nil, err
	}
	return LoadCA(home)
}

func writeAtomic(path string, b []byte, mode os.FileMode) error {
	// r7 P3-5: unique temp name (two engines in two processes may write the same cache / CA file).
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(b)
	if err == nil {
		err = f.Chmod(mode)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// LoadCA reads the CA from the container.
func LoadCA(home string) (*CA, error) {
	dir := caDir(home)
	cb, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil {
		return nil, err
	}
	kb, err := os.ReadFile(filepath.Join(dir, "ca.key"))
	if err != nil {
		return nil, err
	}
	cp, _ := pem.Decode(cb)
	kp, _ := pem.Decode(kb)
	if cp == nil || kp == nil {
		return nil, errors.New("CA 文件损坏")
	}
	cert, err := x509.ParseCertificate(cp.Bytes)
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(kp.Bytes)
	if err != nil {
		return nil, err
	}
	signer, ok := k.(crypto.Signer)
	if !ok {
		return nil, errors.New("CA 私钥类型不支持")
	}
	if err := checkCAPair(cert, k); err != nil {
		return nil, err
	}
	// One shared leaf key keeps per-host certificate generation cheap (a signature only).
	lk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: signer, DER: cp.Bytes, leafKey: lk, cache: map[string]*list.Element{}, lru: list.New(), max: 64}, nil
}

// Info describes the CA for the UI.
func (ca *CA) Info() CAInfo {
	sum := sha256.Sum256(ca.DER)
	s1 := sha1.Sum(ca.DER)
	alg := "ECDSA P-256"
	if _, ok := ca.Key.(*ecdsa.PrivateKey); !ok {
		alg = "RSA"
	}
	return CAInfo{Exists: true, Subject: ca.Cert.Subject.CommonName, Fingerprint: colonHex(sum[:]), SHA1: colonHex(s1[:]),
		NotBefore: ca.Cert.NotBefore.Format("2006-01-02"), NotAfter: ca.Cert.NotAfter.Format("2006-01-02"), Algorithm: alg}
}

func colonHex(b []byte) string {
	h := strings.ToUpper(hex.EncodeToString(b))
	var parts []string
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

// Leaf returns (and caches) a certificate for host.
func (ca *CA) Leaf(host string) (*tls.Certificate, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		host = "localhost"
	}
	ca.mu.Lock()
	if el, ok := ca.cache[host]; ok {
		ca.lru.MoveToFront(el)
		c := el.Value.(*leafEntry).cert
		ca.mu.Unlock()
		return c, nil
	}
	ca.mu.Unlock()

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host, Organization: []string{"Tern MitM"}},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		// iOS rejects TLS server certs valid for more than 825 days; stay well under.
		NotAfter:    time.Now().AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tpl.IPAddresses = []net.IP{ip}
	} else {
		tpl.DNSNames = []string{host}
		// Cover sibling subdomains too (a.example.com => *.example.com) to reuse the cert.
		if i := strings.IndexByte(host, '.'); i > 0 && strings.Count(host, ".") >= 2 {
			tpl.DNSNames = append(tpl.DNSNames, "*"+host[i:])
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.Cert, &ca.leafKey.PublicKey, ca.Key)
	if err != nil {
		return nil, err
	}
	c := &tls.Certificate{Certificate: [][]byte{der, ca.DER}, PrivateKey: ca.leafKey}
	ca.mu.Lock()
	ca.cache[host] = ca.lru.PushFront(&leafEntry{host: host, cert: c})
	for ca.lru.Len() > ca.max {
		el := ca.lru.Back()
		ca.lru.Remove(el)
		delete(ca.cache, el.Value.(*leafEntry).host)
	}
	ca.mu.Unlock()
	return c, nil
}

// CertPEM returns the CA certificate in PEM form.
func (ca *CA) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.DER})
}

// MobileConfig builds an unsigned configuration profile carrying the root (com.apple.security.root).
func (ca *CA) MobileConfig() []byte {
	sum := sha256.Sum256(ca.DER)
	u1 := uuidFrom(sum[:16])
	u2 := uuidFrom(sum[16:])
	b64 := base64Std(ca.DER)
	name := xmlEscape(ca.Cert.Subject.CommonName)
	return []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>PayloadCertificateFileName</key>
			<string>mihomo-ca.cer</string>
			<key>PayloadContent</key>
			<data>%s</data>
			<key>PayloadDescription</key>
			<string>Mihomo MitM 根证书</string>
			<key>PayloadDisplayName</key>
			<string>%s</string>
			<key>PayloadIdentifier</key>
			<string>com.astemo6.mihomo.ca.%s</string>
			<key>PayloadType</key>
			<string>com.apple.security.root</string>
			<key>PayloadUUID</key>
			<string>%s</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>
	</array>
	<key>PayloadDescription</key>
	<string>安装后请到 设置 → 通用 → 关于本机 → 证书信任设置 中为该证书开启完全信任。</string>
	<key>PayloadDisplayName</key>
	<string>%s</string>
	<key>PayloadIdentifier</key>
	<string>com.astemo6.mihomo.ca-profile.%s</string>
	<key>PayloadRemovalDisallowed</key>
	<false/>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>%s</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>
`, b64, name, u2[:8], u2, name, u1[:8], u1))
}

func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}

func uuidFrom(b []byte) string {
	h := strings.ToUpper(hex.EncodeToString(b[:16]))
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// ExportP12 returns a password protected PKCS#12 (cert + private key) for backup / other apps.
func (ca *CA) ExportP12(password string) ([]byte, error) {
	if password == "" {
		return nil, errors.New("请设置导出密码")
	}
	return pkcs12.Modern.Encode(ca.Key, ca.Cert, nil, password)
}

// ImportP12 replaces the CA with one from a .p12 (e.g. moved from another device).
func ImportP12(home string, data []byte, password string) error {
	key, cert, err := pkcs12.Decode(data, password)
	if err != nil {
		return fmt.Errorf("p12 解析失败：%w", err)
	}
	if !cert.IsCA {
		return errors.New("该证书不是 CA 证书")
	}
	if err := checkCAPair(cert, key); err != nil {
		return err
	}
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	dir := caDir(home)
	_ = os.MkdirAll(dir, 0o700)
	if err := writeAtomic(filepath.Join(dir, "ca.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		return err
	}
	return writeAtomic(filepath.Join(dir, "ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o644)
}

// checkCAPair verifies that key is the private key of cert and that cert may sign certificates
// (review5 P2-8: a mismatched p12 used to import "successfully" and then every leaf was invalid).
func checkCAPair(cert *x509.Certificate, key any) error {
	signer, ok := key.(crypto.Signer)
	if !ok {
		return errors.New("CA 私钥类型不支持")
	}
	pub, ok := cert.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(signer.Public()) {
		return errors.New("私钥与证书不匹配")
	}
	if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("该 CA 证书不允许签发证书（缺少 keyCertSign）")
	}
	return nil
}

// TrustTestChain returns DER leaf + CA for SecTrust evaluation in the app (trust status check).
func (ca *CA) TrustTestChain() (leaf, root []byte, host string, err error) {
	host = "mitm-trust-check.mihomo.local"
	c, err := ca.Leaf(host)
	if err != nil {
		return nil, nil, "", err
	}
	return c.Certificate[0], ca.DER, host, nil
}

// InfoJSON returns CA info as JSON ({"exists":false} when missing).
func InfoJSON(home string) string {
	ca, err := LoadCA(home)
	if err != nil {
		return `{"exists":false}`
	}
	b, _ := json.Marshal(ca.Info())
	return string(b)
}
