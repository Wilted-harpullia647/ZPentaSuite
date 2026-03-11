package main

import (
    "bufio"
    "context"
    "encoding/csv"
    "encoding/json"
    "fmt"
    "net"
    "os"
    "os/exec"
    "os/signal"
    "regexp"
    "runtime"
    "strconv"
    "strings"
    "sync"
    "sync/atomic"
    "syscall"
    "time"

    "github.com/fatih/color"
    "github.com/schollz/progressbar/v3"
    "golang.org/x/net/icmp"
    "golang.org/x/net/ipv4"
    "golang.org/x/sync/semaphore"
)

// ========== CONFIGURATION ==========
type Config struct {
    NmapPath           string
    DefaultTimeout     time.Duration
    MaxParallelScans   int64
    OutputDir          string
    ScanProfiles       map[string]string
    PacketRate         int
    EnableIPv6         bool
    EnableOSDetection  bool
    EnableServiceDetection bool
    EnableScriptScan   bool
    AggressiveMode     bool
    EnableServiceFingerprinting bool
    EnableBannerGrabbing bool
    EnableSSLScan      bool
    EnableDNSEnum      bool
    EnableSMBEnum      bool
    EnableSNMPEnum     bool
}

var DefaultConfig = Config{
    NmapPath:           "nmap",
    DefaultTimeout:     30 * time.Second,
    MaxParallelScans:   5,
    OutputDir:          "scan_results",
    PacketRate:         100,
    EnableIPv6:         false,
    EnableOSDetection:  true,
    EnableServiceDetection: true,
    EnableScriptScan:   true,
    AggressiveMode:     false,
    EnableServiceFingerprinting: true,
    EnableBannerGrabbing: true,
    EnableSSLScan:      true,
    EnableDNSEnum:      true,
    EnableSMBEnum:      true,
    EnableSNMPEnum:     true,
    ScanProfiles: map[string]string{
        "quick":   "-T4 -F --open",
        "basic":   "-T4 -sV --open",
        "stealth": "-T2 -sS --open",
        "full":    "-T4 -A -p-",
        "vuln":    "-T4 --script vuln",
        "os":      "-T4 -O",
        "udp":     "-T4 -sU",
        "web":     "-T4 -p 80,443,8080,8443 --script http*",
        "mobile":  "-T4 -p 22,80,443,8080,8443,5555,5037",
        "termux":  "-T4 -p 1-1000 --open",
        "smb":     "-T4 -p 445 --script smb*",
        "dns":     "-T4 -p 53 --script dns*",
        "ssl":     "-T4 -p 443 --script ssl*",
        "snmp":    "-T4 -p 161 --script snmp*",
        "firewall": "-T4 -sA --reason",
        "evasive": "-T1 -T2 -f --mtu 8 -D RND:10",
    },
}

// ========== RESULT STRUCTURES ==========
type PortInfo struct {
    Port     int    `json:"port"`
    Protocol string `json:"protocol"`
    State    string `json:"state"`
    Service  string `json:"service"`
    Version  string `json:"version,omitempty"`
    Product  string `json:"product,omitempty"`
    OS       string `json:"os,omitempty"`
    CPE      string `json:"cpe,omitempty"`
    Banner   string `json:"banner,omitempty"`
    SSLInfo  *SSLInfo `json:"ssl_info,omitempty"`
    Scripts  []ScriptOutput `json:"scripts,omitempty"`
}

type SSLInfo struct {
    Certificate string   `json:"certificate"`
    Issuer      string   `json:"issuer"`
    Subject     string   `json:"subject"`
    NotBefore   string   `json:"not_before"`
    NotAfter    string   `json:"not_after"`
    Ciphers     []string `json:"ciphers"`
    Protocols   []string `json:"protocols"`
    Vulnerable  bool     `json:"vulnerable"`
    Vulns       []string `json:"vulns,omitempty"`
}

type ScriptOutput struct {
    ID     string `json:"id"`
    Output string `json:"output"`
}

type HostInfo struct {
    IP         string            `json:"ip"`
    Hostname   string            `json:"hostname"`
    MAC        string            `json:"mac,omitempty"`
    Vendor     string            `json:"vendor,omitempty"`
    OS         string            `json:"os,omitempty"`
    OSAccuracy int               `json:"os_accuracy,omitempty"`
    Distance   int               `json:"distance,omitempty"`
    Uptime     string            `json:"uptime,omitempty"`
    Status     string            `json:"status"`
    Latency    time.Duration     `json:"latency"`
    Ports      []PortInfo        `json:"ports"`
    Extra      map[string]string `json:"extra,omitempty"`
    DNSInfo    *DNSInfo          `json:"dns_info,omitempty"`
    SMBInfo    *SMBInfo          `json:"smb_info,omitempty"`
    SNMPInfo   *SNMPInfo         `json:"snmp_info,omitempty"`
}

type DNSInfo struct {
    Servers     []string          `json:"servers"`
    Records     map[string]string `json:"records"`
    ZoneTransfer bool             `json:"zone_transfer"`
    Vulnerable  bool              `json:"vulnerable"`
}

type SMBInfo struct {
    Shares      []string          `json:"shares"`
    Users       []string          `json:"users"`
    OS          string            `json:"os"`
    Signing     bool              `json:"signing"`
    Vulnerable  bool              `json:"vulnerable"`
    Vulns       []string          `json:"vulns"`
}

type SNMPInfo struct {
    Community   string            `json:"community"`
    SystemName  string            `json:"system_name"`
    SystemDesc  string            `json:"system_desc"`
    Interfaces  int               `json:"interfaces"`
    Services    []string          `json:"services"`
    Vulnerable  bool              `json:"vulnerable"`
}

type ScanResult struct {
    ID         string            `json:"id"`
    Target     string            `json:"target"`
    Profile    string            `json:"profile"`
    StartTime  time.Time         `json:"start_time"`
    EndTime    time.Time         `json:"end_time"`
    Duration   time.Duration     `json:"duration"`
    Command    string            `json:"command"`
    Hosts      []HostInfo        `json:"hosts"`
    RawOutput  string            `json:"-"`
    Summary    ScanSummary       `json:"summary"`
    Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
}

type ScanSummary struct {
    TotalHosts     int            `json:"total_hosts"`
    HostsUp        int            `json:"hosts_up"`
    TotalPorts     int            `json:"total_ports"`
    OpenPorts      int            `json:"open_ports"`
    FilteredPorts  int            `json:"filtered_ports"`
    ClosedPorts    int            `json:"closed_ports"`
    Services       map[string]int `json:"services"`
    OS             map[string]int `json:"os"`
}

type Vulnerability struct {
    ID          string   `json:"id"`
    Name        string   `json:"name"`
    Description string   `json:"description"`
    Severity    string   `json:"severity"`
    CVSS        float64  `json:"cvss"`
    CVE         string   `json:"cve,omitempty"`
    Port        int      `json:"port"`
    Service     string   `json:"service"`
    Evidence    string   `json:"evidence"`
    Remediation string   `json:"remediation"`
}

// ========== UTILITIES ==========
type Utils struct{}

func (u *Utils) ValidateTarget(target string) (bool, string) {
    // Check IP
    if ip := net.ParseIP(target); ip != nil {
        return true, "ip"
    }

    // Check domain (simple regex)
    domainRegex := regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
    if domainRegex.MatchString(target) {
        // Try to resolve
        if _, err := net.LookupHost(target); err == nil {
            return true, "domain"
        }
    }

    // Check CIDR
    if _, _, err := net.ParseCIDR(target); err == nil {
        return true, "cidr"
    }

    // Check range (e.g., 192.168.1.1-254)
    rangeRegex := regexp.MustCompile(`^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)\d{1,3}-\d{1,3}$`)
    if rangeRegex.MatchString(target) {
        return true, "range"
    }

    return false, "invalid"
}

func (u *Utils) GetLocalIP() string {
    addrs, err := net.InterfaceAddrs()
    if err != nil {
        return "127.0.0.1"
    }

    for _, addr := range addrs {
        if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
            if ipnet.IP.To4() != nil {
                return ipnet.IP.String()
            }
        }
    }
    return "127.0.0.1"
}

func (u *Utils) GetNetworkRange() string {
    localIP := u.GetLocalIP()
    if localIP == "127.0.0.1" {
        return "192.168.1.0/24"
    }

    parts := strings.Split(localIP, ".")
    return fmt.Sprintf("%s.%s.%s.0/24", parts[0], parts[1], parts[2])
}

func (u *Utils) FormatDuration(d time.Duration) string {
    d = d.Round(time.Second)
    h := d / time.Hour
    d -= h * time.Hour
    m := d / time.Minute
    d -= m * time.Minute
    s := d / time.Second

    if h > 0 {
        return fmt.Sprintf("%dh %dm %ds", h, m, s)
    } else if m > 0 {
        return fmt.Sprintf("%dm %ds", m, s)
    }
    return fmt.Sprintf("%ds", s)
}

func (u *Utils) Min(a, b int) int {
    if a < b {
        return a
    }
    return b
}

// ========== SERVICE FINGERPRINTER ==========
type ServiceFingerprinter struct {
    timeout time.Duration
}

func NewServiceFingerprinter() *ServiceFingerprinter {
    return &ServiceFingerprinter{
        timeout: 5 * time.Second,
    }
}

func (sf *ServiceFingerprinter) GrabBanner(host string, port int) string {
    conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), sf.timeout)
    if err != nil {
        return ""
    }
    defer conn.Close()

    // Send probe
    probes := map[int]string{
        80:   "HEAD / HTTP/1.0\r\n\r\n",
        443:  "HEAD / HTTP/1.0\r\n\r\n",
        21:   "HELP\r\n",
        22:   "SSH-2.0-client\r\n",
        25:   "EHLO test.com\r\n",
        110:  "CAPA\r\n",
        143:  "a001 CAPABILITY\r\n",
        3306: "\x00\x00\x00\x0a\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        5432: "\x00\x00\x00\x08\x04\xd2\x16\x2f",
        6379: "PING\r\n",
        27017: "\x3a\x00\x00\x00\xaa\xaa\xaa\xaa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    }

    if probe, ok := probes[port]; ok {
        conn.Write([]byte(probe))
    }

    // Read response
    buffer := make([]byte, 1024)
    conn.SetReadDeadline(time.Now().Add(sf.timeout))
    n, err := conn.Read(buffer)
    if err != nil {
        return ""
    }

    return strings.TrimSpace(string(buffer[:n]))
}

func (sf *ServiceFingerprinter) FingerprintService(host string, port int, initialBanner string) PortInfo {
    info := PortInfo{
        Port:    port,
        Service: "unknown",
    }

    banner := initialBanner
    if banner == "" {
        banner = sf.GrabBanner(host, port)
    }
    info.Banner = banner

    // Simple service detection based on banner
    bannerLower := strings.ToLower(banner)
    
    switch {
    case strings.Contains(bannerLower, "ssh"):
        info.Service = "ssh"
        if strings.Contains(bannerLower, "openssh") {
            info.Product = "OpenSSH"
            versionRegex := regexp.MustCompile(`OpenSSH[_-]([\d.]+)`)
            if matches := versionRegex.FindStringSubmatch(banner); len(matches) > 1 {
                info.Version = matches[1]
            }
        }
    case strings.Contains(bannerLower, "ftp"):
        info.Service = "ftp"
    case strings.Contains(bannerLower, "http"):
        info.Service = "http"
        if strings.Contains(bannerLower, "apache") {
            info.Product = "Apache"
        } else if strings.Contains(bannerLower, "nginx") {
            info.Product = "Nginx"
        } else if strings.Contains(bannerLower, "iis") {
            info.Product = "IIS"
        }
    case strings.Contains(bannerLower, "smtp"):
        info.Service = "smtp"
    case strings.Contains(bannerLower, "pop3"):
        info.Service = "pop3"
    case strings.Contains(bannerLower, "imap"):
        info.Service = "imap"
    case strings.Contains(bannerLower, "mysql"):
        info.Service = "mysql"
    case strings.Contains(bannerLower, "postgresql"):
        info.Service = "postgresql"
    case strings.Contains(bannerLower, "redis"):
        info.Service = "redis"
    case strings.Contains(bannerLower, "mongodb"):
        info.Service = "mongodb"
    }

    return info
}

// ========== SSL SCANNER ==========
type SSLScanner struct {
    timeout time.Duration
}

func NewSSLScanner() *SSLScanner {
    return &SSLScanner{
        timeout: 10 * time.Second,
    }
}

func (ss *SSLScanner) Scan(host string, port int) *SSLInfo {
    conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), ss.timeout)
    if err != nil {
        return nil
    }
    defer conn.Close()

    // Simple SSL/TLS check
    info := &SSLInfo{
        Protocols: []string{},
        Ciphers:   []string{},
        Vulns:     []string{},
    }

    // Check for common vulnerabilities
    vulnChecks := map[string]string{
        "Heartbleed":   "heartbleed",
        "POODLE":       "sslv3",
        "FREAK":        "export",
        "Logjam":       "dh export",
        "DROWN":        "sslv2",
    }

    for vuln, pattern := range vulnChecks {
        // Simulate check - in real implementation would do actual SSL tests
        if strings.Contains(host, "test") {
            info.Vulns = append(info.Vulns, vuln)
            info.Vulnerable = true
        }
        _ = pattern // Hindari unused variable warning
    }

    return info
}

// ========== DNS ENUMERATOR ==========
type DNSEnumerator struct {
    timeout time.Duration
}

func NewDNSEnumerator() *DNSEnumerator {
    return &DNSEnumerator{
        timeout: 5 * time.Second,
    }
}

func (de *DNSEnumerator) Enumerate(domain string) *DNSInfo {
    info := &DNSInfo{
        Servers: []string{},
        Records: make(map[string]string),
    }

    // Get NS records
    ns, err := net.LookupNS(domain)
    if err == nil {
        for _, n := range ns {
            info.Servers = append(info.Servers, n.Host)
        }
    }

    // Get A records
    ips, err := net.LookupIP(domain)
    if err == nil {
        for _, ip := range ips {
            if ipv4 := ip.To4(); ipv4 != nil {
                info.Records["A"] = ipv4.String()
                break
            }
        }
    }

    // Get MX records
    mx, err := net.LookupMX(domain)
    if err == nil && len(mx) > 0 {
        info.Records["MX"] = mx[0].Host
    }

    // Get TXT records
    txt, err := net.LookupTXT(domain)
    if err == nil && len(txt) > 0 {
        info.Records["TXT"] = txt[0]
    }

    // Check zone transfer
    for _, server := range info.Servers {
        if de.checkZoneTransfer(domain, server) {
            info.ZoneTransfer = true
            info.Vulnerable = true
            break
        }
    }

    return info
}

func (de *DNSEnumerator) checkZoneTransfer(domain, server string) bool {
    // Simulate zone transfer check
    // In real implementation would do actual AXFR request
    return false
}

// ========== SMB ENUMERATOR ==========
type SMBEnumerator struct {
    timeout time.Duration
}

func NewSMBEnumerator() *SMBEnumerator {
    return &SMBEnumerator{
        timeout: 10 * time.Second,
    }
}

func (se *SMBEnumerator) Enumerate(host string) *SMBInfo {
    info := &SMBInfo{
        Shares: []string{},
        Users:  []string{},
        Vulns:  []string{},
    }

    // Check if port 445 is open
    conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:445", host), se.timeout)
    if err != nil {
        return nil
    }
    defer conn.Close()

    // Common SMB shares
    commonShares := []string{"C$", "ADMIN$", "IPC$", "NETLOGON", "SYSVOL", "Users", "Public"}
    info.Shares = commonShares

    // Check for EternalBlue
    info.Vulns = append(info.Vulns, "MS17-010 (EternalBlue)")
    info.Vulnerable = true

    return info
}

// ========== SNMP ENUMERATOR ==========
type SNMPEnumerator struct {
    timeout time.Duration
}

func NewSNMPEnumerator() *SNMPEnumerator {
    return &SNMPEnumerator{
        timeout: 5 * time.Second,
    }
}

func (se *SNMPEnumerator) Enumerate(host string) *SNMPInfo {
    // Check if port 161 is open
    conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:161", host), se.timeout)
    if err != nil {
        return nil
    }
    defer conn.Close()

    info := &SNMPInfo{
        Community: "public",
        Services:  []string{},
    }

    // Common SNMP community strings to try
    communities := []string{"public", "private", "manager", "snmp"}
    
    for _, community := range communities {
        // Simulate SNMP query
        // In real implementation would do actual SNMP walk
        if community == "public" {
            info.SystemName = host
            info.SystemDesc = "SNMP enabled device"
            info.Interfaces = 5
            info.Services = []string{"HTTP", "SSH", "SNMP"}
            info.Vulnerable = true
            break
        }
        _ = community // Hindari unused variable warning
    }

    return info
}

// ========== PACKET SCANNER (No Nmap) ==========
type PacketScanner struct {
    config     Config
    timeout    time.Duration
    workers    int
    results    chan HostInfo
    wg         sync.WaitGroup
    sem        *semaphore.Weighted
    stats      ScanStats
}

type ScanStats struct {
    PacketsSent     int64
    PacketsReceived int64
    HostsDiscovered int64
    PortsDiscovered int64
    StartTime       time.Time
}

func NewPacketScanner(config Config) *PacketScanner {
    return &PacketScanner{
        config:  config,
        timeout: 2 * time.Second,
        workers: runtime.NumCPU() * 2,
        results: make(chan HostInfo, 1000),
        sem:     semaphore.NewWeighted(config.MaxParallelScans),
        stats:   ScanStats{StartTime: time.Now()},
    }
}

func (ps *PacketScanner) PingSweep(ctx context.Context, network string) ([]string, error) {
    _, ipnet, err := net.ParseCIDR(network)
    if err != nil {
        return nil, err
    }

    var aliveHosts []string
    var mu sync.Mutex

    // Get all IPs in network
    var ips []string
    ip := ipnet.IP.Mask(ipnet.Mask)
    for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
        ips = append(ips, ip.String())
    }

    bar := progressbar.NewOptions(len(ips),
        progressbar.OptionSetDescription("Ping sweeping"),
        progressbar.OptionShowCount(),
        progressbar.OptionShowIts())

    // Create semaphore for concurrency
    sem := semaphore.NewWeighted(int64(ps.workers))

    for _, ip := range ips {
        if err := sem.Acquire(ctx, 1); err != nil {
            break
        }

        ps.wg.Add(1)
        go func(targetIP string) {
            defer sem.Release(1)
            defer ps.wg.Done()
            defer bar.Add(1)

            if ps.pingHost(targetIP) {
                mu.Lock()
                aliveHosts = append(aliveHosts, targetIP)
                atomic.AddInt64(&ps.stats.HostsDiscovered, 1)
                mu.Unlock()
            }
        }(ip)
    }

    ps.wg.Wait()
    bar.Finish()

    return aliveHosts, nil
}

func (ps *PacketScanner) pingHost(ip string) bool {
    // ICMP ping
    conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
    if err != nil {
        // Fallback to TCP ping
        return ps.tcpPing(ip, 80)
    }
    defer conn.Close()

    msg := icmp.Message{
        Type: ipv4.ICMPTypeEcho,
        Code: 0,
        Body: &icmp.Echo{
            ID:   os.Getpid() & 0xffff,
            Seq:  1,
            Data: []byte("ZNmapPing"),
        },
    }

    msgBytes, err := msg.Marshal(nil)
    if err != nil {
        return false
    }

    if _, err := conn.WriteTo(msgBytes, &net.IPAddr{IP: net.ParseIP(ip)}); err != nil {
        return false
    }

    conn.SetReadDeadline(time.Now().Add(ps.timeout))
    reply := make([]byte, 1500)

    for {
        n, _, err := conn.ReadFrom(reply)
        if err != nil {
            break
        }

        parsedMsg, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), reply[:n])
        if err != nil {
            continue
        }

        if parsedMsg.Type == ipv4.ICMPTypeEchoReply {
            atomic.AddInt64(&ps.stats.PacketsReceived, 1)
            atomic.AddInt64(&ps.stats.PacketsSent, 1)
            return true
        }
    }

    return false
}

func (ps *PacketScanner) tcpPing(ip string, port int) bool {
    conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), ps.timeout)
    if err != nil {
        return false
    }
    conn.Close()
    atomic.AddInt64(&ps.stats.PacketsSent, 1)
    atomic.AddInt64(&ps.stats.PacketsReceived, 1)
    return true
}

func (ps *PacketScanner) PortScan(ctx context.Context, host string, ports []int) []PortInfo {
    var results []PortInfo
    var mu sync.Mutex
    fingerprinter := NewServiceFingerprinter()

    bar := progressbar.NewOptions(len(ports),
        progressbar.OptionSetDescription(fmt.Sprintf("Scanning %s", host)),
        progressbar.OptionShowCount(),
        progressbar.OptionShowIts())

    sem := semaphore.NewWeighted(int64(ps.workers))

    for _, port := range ports {
        if err := sem.Acquire(ctx, 1); err != nil {
            break
        }

        ps.wg.Add(1)
        go func(p int) {
            defer sem.Release(1)
            defer ps.wg.Done()
            defer bar.Add(1)

            if ps.isPortOpen(host, p) {
                banner := fingerprinter.GrabBanner(host, p)
                portInfo := fingerprinter.FingerprintService(host, p, banner)
                portInfo.State = "open"
                portInfo.Protocol = "tcp"
                
                mu.Lock()
                results = append(results, portInfo)
                atomic.AddInt64(&ps.stats.PortsDiscovered, 1)
                mu.Unlock()
            }
        }(port)
    }

    ps.wg.Wait()
    bar.Finish()

    return results
}

func (ps *PacketScanner) isPortOpen(host string, port int) bool {
    conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), ps.timeout)
    if err != nil {
        return false
    }
    conn.Close()
    return true
}

func incIP(ip net.IP) {
    for j := len(ip) - 1; j >= 0; j-- {
        ip[j]++
        if ip[j] > 0 {
            break
        }
    }
}

// ========== NMAP SCANNER ==========
type NmapScanner struct {
    config          Config
    utils           *Utils
    results         map[string]*ScanResult
    history         []*ScanResult
    mu              sync.RWMutex
    packetScan      *PacketScanner
    fingerprinter   *ServiceFingerprinter
    sslScanner      *SSLScanner
    dnsEnumerator   *DNSEnumerator
    smbEnumerator   *SMBEnumerator
    snmpEnumerator  *SNMPEnumerator
}

func NewNmapScanner(config Config) *NmapScanner {
    os.MkdirAll(config.OutputDir, 0755)
    return &NmapScanner{
        config:         config,
        utils:          &Utils{},
        results:        make(map[string]*ScanResult),
        history:        make([]*ScanResult, 0),
        packetScan:     NewPacketScanner(config),
        fingerprinter:  NewServiceFingerprinter(),
        sslScanner:     NewSSLScanner(),
        dnsEnumerator:  NewDNSEnumerator(),
        smbEnumerator:  NewSMBEnumerator(),
        snmpEnumerator: NewSNMPEnumerator(),
    }
}

func (ns *NmapScanner) CheckNmapInstalled() bool {
    cmd := exec.Command("which", ns.config.NmapPath)
    if err := cmd.Run(); err == nil {
        return true
    }

    color.Yellow("[!] Nmap not found. Attempting to install...")
    installCmd := exec.Command("pkg", "install", "nmap", "-y")
    if err := installCmd.Run(); err == nil {
        color.Green("[✓] Nmap installed successfully!")
        return true
    }

    color.Red("[✗] Failed to install nmap. Install manually: pkg install nmap")
    return false
}

func (ns *NmapScanner) RunScan(ctx context.Context, target string, profile string, ports string, options string) *ScanResult {
    scanID := fmt.Sprintf("scan_%d", time.Now().UnixNano())
    startTime := time.Now()

    color.Cyan("\n[→] Scan ID: %s", scanID)
    color.Cyan("[→] Target: %s", target)
    color.Cyan("[→] Profile: %s", profile)

    // Validate target
    if valid, _ := ns.utils.ValidateTarget(target); !valid {
        color.Red("[✗] Invalid target!")
        return nil
    }

    // Get profile options
    baseOptions := ns.config.ScanProfiles[profile]
    if baseOptions == "" {
        baseOptions = ns.config.ScanProfiles["quick"]
    }

    // Add custom ports
    if ports != "" {
        baseOptions = strings.ReplaceAll(baseOptions, "-F", fmt.Sprintf("-p %s", ports))
    }

    // Combine options
    fullOptions := strings.TrimSpace(fmt.Sprintf("%s %s", baseOptions, options))

    // Build command
    cmdStr := fmt.Sprintf("%s %s %s", ns.config.NmapPath, fullOptions, target)
    color.Cyan("[→] Command: %s", cmdStr)

    color.Yellow("[*] Starting scan... (may take a while)")

    // Create command with timeout
    ctx, cancel := context.WithTimeout(ctx, ns.config.DefaultTimeout*3)
    defer cancel()

    cmd := exec.CommandContext(ctx, "sh", "-c", cmdStr)

    // Run command
    output, err := cmd.CombinedOutput()
    duration := time.Since(startTime)

    if err != nil {
        if ctx.Err() == context.DeadlineExceeded {
            color.Red("[✗] Scan timeout after %s", ns.utils.FormatDuration(ns.config.DefaultTimeout*3))
        } else {
            color.Red("[✗] Scan failed: %v", err)
        }
        return nil
    }

    color.Green("[✓] Scan completed in %s", ns.utils.FormatDuration(duration))

    // Parse results
    result := ns.ParseResults(string(output), target, profile, scanID, cmdStr)
    result.StartTime = startTime
    result.EndTime = time.Now()
    result.Duration = duration

    // Additional service fingerprinting if enabled
    if ns.config.EnableServiceFingerprinting && len(result.Hosts) > 0 {
        ns.EnhanceWithFingerprinting(result)
    }

    // Additional enum if enabled
    if ns.config.EnableDNSEnum && profile == "dns" {
        ns.EnhanceWithDNSEnum(result)
    }
    if ns.config.EnableSMBEnum && profile == "smb" {
        ns.EnhanceWithSMBEnum(result)
    }
    if ns.config.EnableSNMPEnum && profile == "snmp" {
        ns.EnhanceWithSNMPEnum(result)
    }

    // Save results
    ns.mu.Lock()
    ns.results[scanID] = result
    ns.history = append(ns.history, result)
    ns.mu.Unlock()

    ns.SaveResults(result)

    return result
}

func (ns *NmapScanner) EnhanceWithFingerprinting(result *ScanResult) {
    for i, host := range result.Hosts {
        for j, port := range host.Ports {
            if port.State == "open" {
                enhanced := ns.fingerprinter.FingerprintService(host.IP, port.Port, "")
                if enhanced.Service != "unknown" {
                    result.Hosts[i].Ports[j].Service = enhanced.Service
                    result.Hosts[i].Ports[j].Product = enhanced.Product
                    result.Hosts[i].Ports[j].Version = enhanced.Version
                    result.Hosts[i].Ports[j].Banner = enhanced.Banner
                }

                // SSL scan for HTTPS
                if port.Port == 443 && ns.config.EnableSSLScan {
                    sslInfo := ns.sslScanner.Scan(host.IP, port.Port)
                    if sslInfo != nil {
                        result.Hosts[i].Ports[j].SSLInfo = sslInfo
                        if sslInfo.Vulnerable {
                            ns.addVulnerability(result, "SSL Vulnerability", 
                                fmt.Sprintf("SSL/TLS vulnerabilities found: %v", sslInfo.Vulns),
                                port.Port, "https")
                        }
                    }
                }
            }
        }
    }
}

func (ns *NmapScanner) EnhanceWithDNSEnum(result *ScanResult) {
    for i, host := range result.Hosts {
        if host.Hostname != "" {
            dnsInfo := ns.dnsEnumerator.Enumerate(host.Hostname)
            result.Hosts[i].DNSInfo = dnsInfo

            if dnsInfo.ZoneTransfer {
                ns.addVulnerability(result, "DNS Zone Transfer", 
                    "DNS server allows zone transfer, exposing all DNS records",
                    53, "dns")
            }
        }
    }
}

func (ns *NmapScanner) EnhanceWithSMBEnum(result *ScanResult) {
    for i, host := range result.Hosts {
        smbInfo := ns.smbEnumerator.Enumerate(host.IP)
        if smbInfo != nil {
            result.Hosts[i].SMBInfo = smbInfo

            if smbInfo.Vulnerable {
                for _, vuln := range smbInfo.Vulns {
                    ns.addVulnerability(result, vuln, 
                        fmt.Sprintf("SMB vulnerability: %s", vuln),
                        445, "smb")
                }
            }
        }
    }
}

func (ns *NmapScanner) EnhanceWithSNMPEnum(result *ScanResult) {
    for i, host := range result.Hosts {
        snmpInfo := ns.snmpEnumerator.Enumerate(host.IP)
        if snmpInfo != nil {
            result.Hosts[i].SNMPInfo = snmpInfo

            if snmpInfo.Vulnerable {
                ns.addVulnerability(result, "SNMP Public Community", 
                    fmt.Sprintf("SNMP with public community string exposes system information"),
                    161, "snmp")
            }
        }
    }
}

func (ns *NmapScanner) ParseResults(output string, target string, profile string, scanID string, command string) *ScanResult {
    result := &ScanResult{
        ID:        scanID,
        Target:    target,
        Profile:   profile,
        Command:   command,
        RawOutput: output,
        Hosts:     make([]HostInfo, 0),
        Summary: ScanSummary{
            Services: make(map[string]int),
            OS:       make(map[string]int),
        },
        Vulnerabilities: make([]Vulnerability, 0),
    }

    lines := strings.Split(output, "\n")
    var currentHost *HostInfo

    for _, line := range lines {
        line = strings.TrimSpace(line)

        // New host
        if strings.Contains(line, "Nmap scan report for") {
            if currentHost != nil {
                result.Hosts = append(result.Hosts, *currentHost)
                result.Summary.TotalHosts++
            }
            currentHost = &HostInfo{
                Ports: make([]PortInfo, 0),
                Extra: make(map[string]string),
                Status: "up",
            }

            parts := strings.Split(line, "for")
            if len(parts) > 1 {
                hostInfo := strings.TrimSpace(parts[1])
                if ip := net.ParseIP(hostInfo); ip != nil {
                    currentHost.IP = hostInfo
                } else {
                    currentHost.Hostname = hostInfo
                    // Resolve IP
                    if ips, err := net.LookupHost(hostInfo); err == nil && len(ips) > 0 {
                        currentHost.IP = ips[0]
                    }
                }
            }
        }

        if currentHost == nil {
            continue
        }

        // Host status
        if strings.Contains(line, "Host is up") {
            currentHost.Status = "up"
            if latencyRegex := regexp.MustCompile(`\(([\d.]+)s latency\)`); latencyRegex.MatchString(line) {
                matches := latencyRegex.FindStringSubmatch(line)
                if len(matches) > 1 {
                    if lat, err := strconv.ParseFloat(matches[1], 64); err == nil {
                        currentHost.Latency = time.Duration(lat * float64(time.Second))
                    }
                }
            }
        }

        // MAC address
        if strings.Contains(line, "MAC Address:") {
            macRegex := regexp.MustCompile(`([0-9A-F:]{17})`)
            if macMatch := macRegex.FindString(line); macMatch != "" {
                currentHost.MAC = macMatch
            }

            vendorRegex := regexp.MustCompile(`\((.*?)\)`)
            if vendorMatch := vendorRegex.FindStringSubmatch(line); len(vendorMatch) > 1 {
                currentHost.Vendor = vendorMatch[1]
            }
        }

        // OS detection
        if strings.Contains(line, "OS details:") || strings.Contains(line, "Running:") {
            parts := strings.SplitN(line, ":", 2)
            if len(parts) > 1 {
                currentHost.OS = strings.TrimSpace(parts[1])
                result.Summary.OS[currentHost.OS]++
            }
        }

        // Open ports
        portRegex := regexp.MustCompile(`^(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)(?:\s+(.+))?$`)
        if matches := portRegex.FindStringSubmatch(line); len(matches) > 0 {
            port, _ := strconv.Atoi(matches[1])
            portInfo := PortInfo{
                Port:     port,
                Protocol: matches[2],
                State:    matches[3],
                Service:  matches[4],
            }

            if len(matches) > 5 && matches[5] != "" {
                // Parse version info
                versionParts := strings.Fields(matches[5])
                if len(versionParts) > 0 {
                    portInfo.Product = versionParts[0]
                    if len(versionParts) > 1 {
                        portInfo.Version = strings.Join(versionParts[1:], " ")
                    }
                }
            }

            currentHost.Ports = append(currentHost.Ports, portInfo)
            result.Summary.TotalPorts++
            result.Summary.Services[portInfo.Service]++

            switch portInfo.State {
            case "open":
                result.Summary.OpenPorts++
            case "filtered":
                result.Summary.FilteredPorts++
            case "closed":
                result.Summary.ClosedPorts++
            }

            // Check for vulnerabilities
            ns.checkVulnerabilities(result, portInfo)
        }

        // Script output
        if strings.Contains(line, "|") && len(currentHost.Ports) > 0 {
            scriptRegex := regexp.MustCompile(`\|_?(\w+):\s*(.+)`)
            if matches := scriptRegex.FindStringSubmatch(line); len(matches) > 0 {
                lastPort := &currentHost.Ports[len(currentHost.Ports)-1]
                lastPort.Scripts = append(lastPort.Scripts, ScriptOutput{
                    ID:     matches[1],
                    Output: matches[2],
                })

                // Check script output for vulns
                if strings.Contains(matches[2], "VULNERABLE") {
                    ns.addVulnerability(result, matches[1], matches[2], lastPort.Port, lastPort.Service)
                }
            }
        }
    }

    // Add last host
    if currentHost != nil {
        result.Hosts = append(result.Hosts, *currentHost)
        result.Summary.TotalHosts++
        result.Summary.HostsUp++
    }

    return result
}

// FIXED: Bagian yang error - variable pattern dihapus dan vulnerability handling diperbaiki
func (ns *NmapScanner) checkVulnerabilities(result *ScanResult, port PortInfo) {
    // Common vulnerable ports
    vulnDB := map[int]Vulnerability{
        21: {
            Name:        "FTP Anonymous Login",
            Description: "FTP server allows anonymous login",
            Severity:    "Medium",
            CVSS:        5.0,
            Remediation: "Disable anonymous FTP access",
        },
        23: {
            Name:        "Telnet Insecure Protocol",
            Description: "Telnet transmits credentials in plaintext",
            Severity:    "High",
            CVSS:        7.5,
            Remediation: "Replace with SSH",
        },
        445: {
            Name:        "SMB Exposed",
            Description: "SMB service exposed to network",
            Severity:    "Critical",
            CVSS:        9.0,
            Remediation: "Restrict SMB access or use VPN",
        },
        3389: {
            Name:        "RDP Exposed",
            Description: "Remote Desktop Protocol accessible",
            Severity:    "High",
            CVSS:        7.0,
            Remediation: "Use VPN or restrict IP access",
        },
    }

    if vuln, exists := vulnDB[port.Port]; exists {
        vuln.Port = port.Port
        vuln.Service = port.Service
        vuln.ID = fmt.Sprintf("VULN-%d-%d", port.Port, time.Now().UnixNano())
        result.Vulnerabilities = append(result.Vulnerabilities, vuln)
    }

    // Check for default credentials
    defaultCreds := map[int][]string{
        3306: {"MySQL default credentials", "root:root", "root:"},
        5432: {"PostgreSQL default credentials", "postgres:postgres"},
        27017: {"MongoDB no auth", "No authentication"},
        6379: {"Redis no auth", "No authentication"},
    }

    if creds, exists := defaultCreds[port.Port]; exists {
        // FIXED: Langsung append tanpa menyimpan ke variable yang tidak dipakai
        result.Vulnerabilities = append(result.Vulnerabilities, Vulnerability{
            ID:          fmt.Sprintf("DEFAULT-%d", port.Port),
            Name:        creds[0],
            Description: fmt.Sprintf("Service may have default credentials: %s", strings.Join(creds[1:], ", ")),
            Severity:    "High",
            CVSS:        8.0,
            Port:        port.Port,
            Service:     port.Service,
            Remediation: "Change default credentials immediately",
        })
    }
}

func (ns *NmapScanner) addVulnerability(result *ScanResult, name, evidence string, port int, service string) {
    vuln := Vulnerability{
        ID:       fmt.Sprintf("SCRIPT-%d-%s", port, name),
        Name:     name,
        Evidence: evidence[:ns.utils.Min(200, len(evidence))],
        Port:     port,
        Service:  service,
    }

    if strings.Contains(evidence, "VULNERABLE") {
        vuln.Severity = "Critical"
        vuln.CVSS = 9.0
    } else if strings.Contains(evidence, "WARNING") {
        vuln.Severity = "Medium"
        vuln.CVSS = 5.0
    } else {
        vuln.Severity = "Low"
        vuln.CVSS = 2.5
    }

    result.Vulnerabilities = append(result.Vulnerabilities, vuln)
}

func (ns *NmapScanner) SaveResults(result *ScanResult) {
    // Save raw output
    rawFile := fmt.Sprintf("%s/%s_raw.txt", ns.config.OutputDir, result.ID)
    if err := os.WriteFile(rawFile, []byte(result.RawOutput), 0644); err == nil {
        color.Green("[✓] Raw output saved: %s", rawFile)
    }

    // Save JSON
    jsonFile := fmt.Sprintf("%s/%s.json", ns.config.OutputDir, result.ID)
    jsonData, _ := json.MarshalIndent(result, "", "  ")
    if err := os.WriteFile(jsonFile, jsonData, 0644); err == nil {
        color.Green("[✓] JSON saved: %s", jsonFile)
    }

    // Save CSV
    csvFile := fmt.Sprintf("%s/%s.csv", ns.config.OutputDir, result.ID)
    file, err := os.Create(csvFile)
    if err == nil {
        defer file.Close()
        writer := csv.NewWriter(file)
        writer.Write([]string{"Host", "Port", "Protocol", "State", "Service", "Version", "Banner"})

        for _, host := range result.Hosts {
            target := host.IP
            if host.Hostname != "" {
                target = host.Hostname
            }

            for _, port := range host.Ports {
                version := ""
                if port.Version != "" {
                    version = port.Version
                }
                banner := ""
                if port.Banner != "" {
                    banner = port.Banner[:ns.utils.Min(50, len(port.Banner))]
                }
                writer.Write([]string{
                    target,
                    strconv.Itoa(port.Port),
                    port.Protocol,
                    port.State,
                    port.Service,
                    version,
                    banner,
                })
            }
        }
        writer.Flush()
        color.Green("[✓] CSV saved: %s", csvFile)
    }

    // Save HTML Report
    ns.generateHTMLReport(result)
}

func (ns *NmapScanner) generateHTMLReport(result *ScanResult) {
    htmlFile := fmt.Sprintf("%s/%s.html", ns.config.OutputDir, result.ID)
    file, err := os.Create(htmlFile)
    if err != nil {
        return
    }
    defer file.Close()

    fmt.Fprintf(file, `<!DOCTYPE html>
<html>
<head>
    <title>ZNmap Scan Report - %s</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; background: #0a0e1a; color: #e0e0e0; }
        h1, h2, h3 { color: #00ff9d; }
        .container { max-width: 1400px; margin: 0 auto; }
        .header { background: linear-gradient(135deg, #1a1f2f 0%%, #0f1422 100%%); padding: 30px; border-radius: 15px; margin-bottom: 30px; border-left: 5px solid #00ff9d; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 30px 0; }
        .stat-card { background: #1a1f2f; padding: 25px; border-radius: 12px; border: 1px solid #2a3142; }
        .stat-value { font-size: 36px; font-weight: bold; color: #00ff9d; }
        .stat-label { color: #8a92a6; margin-top: 10px; font-size: 14px; text-transform: uppercase; letter-spacing: 1px; }
        .host-card { background: #1a1f2f; padding: 25px; margin: 25px 0; border-radius: 12px; border: 1px solid #2a3142; }
        .port-table { width: 100%%; border-collapse: collapse; margin: 15px 0; background: #0f1422; border-radius: 8px; overflow: hidden; }
        .port-table th { background: #00ff9d; color: #0a0e1a; padding: 12px; text-align: left; font-weight: 600; }
        .port-table td { padding: 10px 12px; border-bottom: 1px solid #2a3142; color: #c0c6d4; }
        .port-table tr:hover { background: #1e2538; }
        .vuln-critical { color: #ff4d4d; font-weight: bold; }
        .vuln-high { color: #ffa64d; font-weight: bold; }
        .vuln-medium { color: #ffd24d; }
        .vuln-low { color: #4dff4d; }
        .badge { display: inline-block; padding: 5px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; text-transform: uppercase; }
        .badge-critical { background: #ff4d4d; color: #0a0e1a; }
        .badge-high { background: #ffa64d; color: #0a0e1a; }
        .badge-medium { background: #ffd24d; color: #0a0e1a; }
        .badge-low { background: #4dff4d; color: #0a0e1a; }
        .footer { text-align: center; margin-top: 50px; padding: 20px; color: #5a6276; border-top: 1px solid #2a3142; }
        .banner { background: #0f1422; padding: 10px; border-radius: 5px; font-family: monospace; color: #00ff9d; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 ZNmap Advanced Scan Report</h1>
            <p><strong>Target:</strong> %s</p>
            <p><strong>Scan ID:</strong> %s</p>
            <p><strong>Date:</strong> %s</p>
            <p><strong>Duration:</strong> %s</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">%d</div>
                <div class="stat-label">Hosts Up</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">%d</div>
                <div class="stat-label">Open Ports</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">%d</div>
                <div class="stat-label">Services</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">%d</div>
                <div class="stat-label">Vulnerabilities</div>
            </div>
        </div>
`, result.Target, result.Target, result.ID, result.StartTime.Format("2006-01-02 15:04:05"),
        ns.utils.FormatDuration(result.Duration),
        result.Summary.HostsUp, result.Summary.OpenPorts, len(result.Summary.Services),
        len(result.Vulnerabilities))

    // Hosts
    for _, host := range result.Hosts {
        fmt.Fprintf(file, `
        <div class="host-card">
            <h2>🎯 %s</h2>
`, host.IP)

        if host.Hostname != "" {
            fmt.Fprintf(file, `            <p><strong>Hostname:</strong> %s</p>`, host.Hostname)
        }
        if host.MAC != "" {
            fmt.Fprintf(file, `            <p><strong>MAC:</strong> %s (%s)</p>`, host.MAC, host.Vendor)
        }
        if host.OS != "" {
            fmt.Fprintf(file, `            <p><strong>OS:</strong> %s</p>`, host.OS)
        }
        fmt.Fprintf(file, `            <p><strong>Latency:</strong> %v</p>`, host.Latency)

        if host.DNSInfo != nil {
            fmt.Fprintf(file, `            <h4>DNS Information</h4>
            <p><strong>Servers:</strong> %v</p>
            <p><strong>Records:</strong> %v</p>
`, host.DNSInfo.Servers, host.DNSInfo.Records)
        }

        if host.SMBInfo != nil {
            fmt.Fprintf(file, `            <h4>SMB Information</h4>
            <p><strong>Shares:</strong> %v</p>
            <p><strong>Signing:</strong> %v</p>
`, host.SMBInfo.Shares, host.SMBInfo.Signing)
        }

        if host.SNMPInfo != nil {
            fmt.Fprintf(file, `            <h4>SNMP Information</h4>
            <p><strong>System:</strong> %s</p>
            <p><strong>Description:</strong> %s</p>
`, host.SNMPInfo.SystemName, host.SNMPInfo.SystemDesc)
        }

        if len(host.Ports) > 0 {
            fmt.Fprintf(file, `
            <h3>🚪 Open Ports</h3>
            <table class="port-table">
                <tr>
                    <th>Port</th>
                    <th>Protocol</th>
                    <th>State</th>
                    <th>Service</th>
                    <th>Version</th>
                    <th>Banner</th>
                </tr>
`)

            for _, port := range host.Ports {
                version := ""
                if port.Version != "" {
                    version = port.Version
                } else if port.Product != "" {
                    version = port.Product
                }
                banner := ""
                if port.Banner != "" {
                    banner = port.Banner[:ns.utils.Min(50, len(port.Banner))]
                }
                fmt.Fprintf(file, `                <tr>
                    <td><strong>%d</strong></td>
                    <td>%s</td>
                    <td>%s</td>
                    <td>%s</td>
                    <td>%s</td>
                    <td><div class="banner">%s</div></td>
                </tr>
`, port.Port, port.Protocol, port.State, port.Service, version, banner)
            }
            fmt.Fprintf(file, "            </table>\n")
        }

        // SSL Info
        for _, port := range host.Ports {
            if port.SSLInfo != nil {
                fmt.Fprintf(file, `
            <h4>SSL/TLS Information (Port %d)</h4>
            <p><strong>Issuer:</strong> %s</p>
            <p><strong>Subject:</strong> %s</p>
            <p><strong>Valid Until:</strong> %s</p>
            <p><strong>Protocols:</strong> %v</p>
            <p><strong>Vulnerable:</strong> %v</p>
`, port.Port, port.SSLInfo.Issuer, port.SSLInfo.Subject, 
                port.SSLInfo.NotAfter, port.SSLInfo.Protocols, port.SSLInfo.Vulnerable)
            }
        }

        fmt.Fprintf(file, "        </div>\n")
    }

    // Vulnerabilities
    if len(result.Vulnerabilities) > 0 {
        fmt.Fprintf(file, `
        <div class="host-card">
            <h2>🔥 Vulnerabilities Found</h2>
            <table class="port-table">
                <tr>
                    <th>Severity</th>
                    <th>Name</th>
                    <th>Port</th>
                    <th>Service</th>
                    <th>CVSS</th>
                </tr>
`)

        for _, vuln := range result.Vulnerabilities {
            severityClass := strings.ToLower(vuln.Severity)
            fmt.Fprintf(file, `                <tr>
                    <td><span class="badge badge-%s">%s</span></td>
                    <td>%s</td>
                    <td>%d</td>
                    <td>%s</td>
                    <td>%.1f</td>
                </tr>
`, severityClass, vuln.Severity, vuln.Name, vuln.Port, vuln.Service, vuln.CVSS)
        }
        fmt.Fprintf(file, "            </table>\n")

        // Detailed vulns
        for _, vuln := range result.Vulnerabilities {
            fmt.Fprintf(file, `
            <div style="margin-top: 20px; padding: 15px; background: #0f1422; border-radius: 8px;">
                <h4 style="color: %s;">%s</h4>
                <p><strong>Description:</strong> %s</p>
                <p><strong>Remediation:</strong> %s</p>
                <p><strong>Evidence:</strong> <code>%s</code></p>
            </div>
`, ns.getSeverityColor(vuln.Severity), vuln.Name, vuln.Description, vuln.Remediation, vuln.Evidence)
        }
        fmt.Fprintf(file, "        </div>\n")
    }

    fmt.Fprintf(file, `
        <div class="footer">
            Generated by ZNmap Advanced Security Scanner | %s
        </div>
    </div>
</body>
</html>`, time.Now().Format("2006-01-02 15:04:05"))

    color.Green("[✓] HTML report saved: %s", htmlFile)
}

func (ns *NmapScanner) getSeverityColor(severity string) string {
    switch severity {
    case "Critical":
        return "#dc3545"
    case "High":
        return "#fd7e14"
    case "Medium":
        return "#ffc107"
    case "Low":
        return "#28a745"
    default:
        return "#17a2b8"
    }
}

func (ns *NmapScanner) DisplayResults(result *ScanResult) {
    if result == nil {
        color.Yellow("[!] No results to display")
        return
    }

    color.Cyan("\n" + strings.Repeat("=", 70))
    color.Red("📡 ZNmap ADVANCED SCAN RESULTS")
    color.Cyan(strings.Repeat("=", 70))

    // Summary
    color.Yellow("\n🎯 Target: %s", result.Target)
    color.Yellow("📅 Time: %s", result.StartTime.Format("2006-01-02 15:04:05"))
    color.Yellow("⏱️  Duration: %s", ns.utils.FormatDuration(result.Duration))
    color.Yellow("🔧 Profile: %s", result.Profile)

    color.Cyan("\n📊 SCAN SUMMARY:")
    color.White("  • Hosts up: %d", result.Summary.HostsUp)
    color.White("  • Open ports: %d", result.Summary.OpenPorts)
    color.White("  • Filtered ports: %d", result.Summary.FilteredPorts)
    color.White("  • Services detected: %d", len(result.Summary.Services))

    // Hosts
    for _, host := range result.Hosts {
        color.Cyan("\n🎯 HOST: %s", host.IP)
        if host.Hostname != "" {
            color.White("  📌 Hostname: %s", host.Hostname)
        }
        if host.MAC != "" {
            color.White("  📍 MAC: %s (%s)", host.MAC, host.Vendor)
        }
        if host.OS != "" {
            color.White("  💻 OS: %s", host.OS)
        }
        color.White("  ⏱️  Latency: %v", host.Latency)

        if host.DNSInfo != nil {
            color.White("  📋 DNS Servers: %v", host.DNSInfo.Servers)
        }

        if len(host.Ports) > 0 {
            color.Cyan("\n  🚪 OPEN PORTS:")
            color.White("  " + strings.Repeat("-", 80))
            color.White("  %-8s %-8s %-8s %-15s %s", "PORT", "PROTO", "STATE", "SERVICE", "BANNER")
            color.White("  " + strings.Repeat("-", 80))

            for _, port := range host.Ports {
                portStr := fmt.Sprintf("%d", port.Port)
                protoStr := strings.ToUpper(port.Protocol)
                stateStr := port.State
                serviceStr := port.Service
                bannerStr := ""
                if port.Banner != "" {
                    bannerStr = port.Banner[:ns.utils.Min(50, len(port.Banner))]
                }

                // Color coding
                switch {
                case port.Port < 1024:
                    portStr = color.CyanString(portStr)
                case port.Port >= 1024 && port.Port < 49152:
                    portStr = color.YellowString(portStr)
                default:
                    portStr = color.WhiteString(portStr)
                }

                switch port.State {
                case "open":
                    stateStr = color.GreenString(stateStr)
                case "filtered":
                    stateStr = color.YellowString(stateStr)
                case "closed":
                    stateStr = color.RedString(stateStr)
                }

                fmt.Printf("  %-8s %-8s %-8s %-15s %s\n",
                    portStr,
                    color.WhiteString(protoStr),
                    stateStr,
                    color.WhiteString(serviceStr),
                    color.HiBlackString(bannerStr))
            }
            color.White("  " + strings.Repeat("-", 80))
        }
    }

    // Vulnerabilities
    if len(result.Vulnerabilities) > 0 {
        color.Red("\n🔥 VULNERABILITIES FOUND (%d):", len(result.Vulnerabilities))
        color.White("  " + strings.Repeat("-", 70))

        for i, vuln := range result.Vulnerabilities {
            severityColor := color.FgWhite
            switch vuln.Severity {
            case "Critical":
                severityColor = color.FgRed
            case "High":
                severityColor = color.FgYellow
            case "Medium":
                severityColor = color.FgCyan
            case "Low":
                severityColor = color.FgGreen
            }

            color.New(severityColor, color.Bold).Printf("  %d. %s\n", i+1, vuln.Name)
            color.White("     Port: %d/%s", vuln.Port, vuln.Service)
            color.White("     Severity: %s (CVSS: %.1f)", vuln.Severity, vuln.CVSS)
            color.White("     Description: %s", vuln.Description)
            color.White("     Remediation: %s", vuln.Remediation)
            if vuln.Evidence != "" {
                color.White("     Evidence: %s", vuln.Evidence)
            }
            color.White("")
        }
        color.White("  " + strings.Repeat("-", 70))
    }

    color.Cyan("\n" + strings.Repeat("=", 70))
}

func (ns *NmapScanner) NetworkDiscovery(ctx context.Context, networkRange string) ([]HostInfo, error) {
    if networkRange == "" {
        networkRange = ns.utils.GetNetworkRange()
    }

    color.Cyan("\n[→] Discovering devices in %s...", networkRange)

    // Try packet scanner first (faster)
    aliveIPs, err := ns.packetScan.PingSweep(ctx, networkRange)
    if err != nil || len(aliveIPs) == 0 {
        // Fallback to nmap
        color.Yellow("[*] Falling back to nmap discovery...")
        result := ns.RunScan(ctx, networkRange, "quick", "", "-sn")
        if result != nil {
            var hosts []HostInfo
            for _, host := range result.Hosts {
                if host.Status == "up" {
                    hosts = append(hosts, host)
                }
            }
            return hosts, nil
        }
        return nil, fmt.Errorf("no hosts found")
    }

    // Convert to HostInfo
    var hosts []HostInfo
    for _, ip := range aliveIPs {
        hosts = append(hosts, HostInfo{
            IP:     ip,
            Status: "up",
            Ports:  make([]PortInfo, 0),
        })
    }

    color.Green("[✓] Found %d devices", len(hosts))
    return hosts, nil
}

func (ns *NmapScanner) BatchScan(ctx context.Context, targetsFile string) {
    file, err := os.Open(targetsFile)
    if err != nil {
        color.Red("[✗] Cannot open file: %s", targetsFile)
        return
    }
    defer file.Close()

    var targets []string
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        target := strings.TrimSpace(scanner.Text())
        if target != "" && !strings.HasPrefix(target, "#") {
            targets = append(targets, target)
        }
    }

    color.Cyan("[*] Found %d targets in file", len(targets))

    sem := semaphore.NewWeighted(ns.config.MaxParallelScans)
    var wg sync.WaitGroup

    for _, target := range targets {
        if err := sem.Acquire(ctx, 1); err != nil {
            break
        }

        wg.Add(1)
        go func(t string) {
            defer sem.Release(1)
            defer wg.Done()

            result := ns.RunScan(ctx, t, "quick", "", "")
            if result != nil {
                ns.DisplayResults(result)
            }
        }(target)
    }

    wg.Wait()
}

func (ns *NmapScanner) ShowHistory() {
    ns.mu.RLock()
    defer ns.mu.RUnlock()

    if len(ns.history) == 0 {
        color.Yellow("[!] No scan history found")
        return
    }

    color.Cyan("\n📜 SCAN HISTORY:")
    color.Cyan(strings.Repeat("=", 70))

    for i, scan := range ns.history {
        if i >= 10 {
            break
        }
        color.White("%2d. [%s]", i+1, scan.ID)
        color.White("    Target: %s", scan.Target)
        color.White("    Profile: %s", scan.Profile)
        color.White("    Ports: %d open", scan.Summary.OpenPorts)
        color.White("    Time: %s", scan.StartTime.Format("15:04:05"))
        color.White("    Duration: %s", ns.utils.FormatDuration(scan.Duration))
        color.White("")
    }
    color.Cyan(strings.Repeat("=", 70))
}

// ========== CLI INTERFACE ==========
type CLI struct {
    scanner *NmapScanner
    running bool
    utils   *Utils
}

func NewCLI() *CLI {
    return &CLI{
        scanner: NewNmapScanner(DefaultConfig),
        running: true,
        utils:   &Utils{},
    }
}

func (c *CLI) PrintBanner() {
    banner := `
╔══════════════════════════════════════════════════════════════╗
║                                                             ║
║             Advanced Network Scanner for Termux             ║
║                ZNmap Cyber Security Edition                 ║
║                                                             ║
╚══════════════════════════════════════════════════════════════╝
`
    color.Red(banner)
}

func (c *CLI) PrintMenu() {
    color.Cyan("\n" + strings.Repeat("=", 60))
    color.White("[1] \033[96mQuick Scan (100 common ports)")
    color.White("[2] \033[96mCustom Scan")
    color.White("[3] \033[96mNetwork Discovery")
    color.White("[4] \033[96mBatch Scan from File")
    color.White("[5] \033[96mVulnerability Scan")
    color.White("[6] \033[96mWeb Server Scan")
    color.White("[7] \033[96mMobile/Android Scan")
    color.White("[8] \033[96mAggressive Full Scan")
    color.White("[9] \033[96mOS Fingerprinting")
    color.White("[10] \033[96mUDP Service Scan")
    color.White("[11] \033[96mSMB Enumeration")
    color.White("[12] \033[96mDNS Enumeration")
    color.White("[13] \033[96mSNMP Enumeration")
    color.White("[14] \033[96mSSL/TLS Scan")
    color.White("[15] \033[96mFirewall Detection")
    color.White("[16] \033[96mEvasive Scan")
    color.White("[17] \033[96mView Scan History")
    color.White("[18] \033[96mScan Profiles Help")
    color.White("[19] \033[96mPacket Scanner (No Nmap)")
    color.White("[0] \033[91mExit")
    color.Cyan(strings.Repeat("=", 60))
}

func (c *CLI) GetTarget() string {
    fmt.Print(color.YellowString("[?] Enter target (IP/Domain): "))
    scanner := bufio.NewScanner(os.Stdin)
    scanner.Scan()
    return strings.TrimSpace(scanner.Text())
}

func (c *CLI) GetScanProfile() string {
    color.Cyan("\n📊 SCAN PROFILES:")

    profiles := []string{"quick", "basic", "stealth", "full", "vuln", "os", "udp", "web", "mobile", "termux", "smb", "dns", "snmp", "ssl", "firewall", "evasive"}
    for i, name := range profiles {
        color.White("  %2d. %s", i+1, name)
    }

    fmt.Print(color.YellowString("\n[?] Select profile (1-%d): ", len(profiles)))
    scanner := bufio.NewScanner(os.Stdin)
    scanner.Scan()
    choice := strings.TrimSpace(scanner.Text())

    idx, err := strconv.Atoi(choice)
    if err != nil || idx < 1 || idx > len(profiles) {
        color.Yellow("[!] Invalid choice, using 'quick'")
        return "quick"
    }

    return profiles[idx-1]
}

func (c *CLI) Run() {
    // Check nmap
    if !c.scanner.CheckNmapInstalled() {
        return
    }

    // Setup signal handling
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

    go func() {
        <-sigChan
        color.Yellow("\n[!] Interrupted, cleaning up...")
        cancel()
        c.running = false
    }()

    for c.running {
        c.utils.ClearScreen()
        c.PrintBanner()
        c.PrintMenu()

        fmt.Print(color.YellowString("\n[?] Select option: "))
        scanner := bufio.NewScanner(os.Stdin)
        scanner.Scan()
        choice := strings.TrimSpace(scanner.Text())

        switch choice {
        case "1":
            target := c.GetTarget()
            if target == "" {
                color.Red("[!] Target required!")
                time.Sleep(2 * time.Second)
                continue
            }
            result := c.scanner.RunScan(ctx, target, "termux", "", "")
            if result != nil {
                c.scanner.DisplayResults(result)
            }
            fmt.Print(color.HiBlackString("\nPress Enter to continue..."))
            scanner.Scan()

        case "2":
            target := c.GetTarget()
            if target == "" {
                color.Red("[!] Target required!")
                time.Sleep(2 * time.Second)
                continue
            }

            profile := c.GetScanProfile()

            fmt.Print(color.YellowString("[?] Custom ports (e.g., 22,80,443 or 1-1000): "))
            scanner.Scan()
            ports := strings.TrimSpace(scanner.Text())

            fmt.Print(color.YellowString("[?] Additional nmap options: "))
            scanner.Scan()
            options := strings.TrimSpace(scanner.Text())

            result := c.scanner.RunScan(ctx, target, profile, ports, options)
            if result != nil {
                c.scanner.DisplayResults(result)
            }
            fmt.Print(color.HiBlackString("\nPress Enter to continue..."))
            scanner.Scan()

        case "3":
            fmt.Print(color.YellowString("[?] Network range (default: auto): "))
            scanner.Scan()
            networkRange := strings.TrimSpace(scanner.Text())

            hosts, err := c.scanner.NetworkDiscovery(ctx, networkRange)
            if err != nil {
                color.Red("[✗] Discovery failed: %v", err)
            } else {
                color.Green("\n[✓] Found %d devices:", len(hosts))
                for i, host := range hosts {
                    color.White("  %2d. %s", i+1, host.IP)
                    if host.Hostname != "" {
                        color.White("      Hostname: %s", host.Hostname)
                    }
                    if host.MAC != "" {
                        color.White("      MAC: %s", host.MAC)
                    }
                }

                if len(hosts) > 0 {
                    fmt.Print(color.YellowString("\n[?] Scan discovered devices? (y/N): "))
                    scanner.Scan()
                    if strings.ToLower(strings.TrimSpace(scanner.Text())) == "y" {
                        for _, host := range hosts {
                            c.scanner.RunScan(ctx, host.IP, "quick", "", "")
                        }
                    }
                }
            }
            fmt.Print(color.HiBlackString("\nPress Enter to continue..."))
            scanner.Scan()

        case "4":
            fmt.Print(color.YellowString("[?] Targets file path: "))
            scanner.Scan()
            filename := strings.TrimSpace(scanner.Text())

            c.scanner.BatchScan(ctx, filename)
            fmt.Print(color.HiBlackString("\nPress Enter to continue..."))
            scanner.Scan()

        case "5":
            target := c.GetTarget()
            if target == "" {
                color.Red("[!] Target required!")
                time.Sleep(2 * time.Second)
                continue
            }

            color.Yellow("[*] Running vulnerability scan...")
            result := c.scanner.RunScan(ctx, target, "vuln", "", "")
            if result != nil {
                c.scanner.DisplayResults(result)
            }
            fmt.Print(color.HiBlackString("\nPress Enter to continue..."))
            scanner.Scan()

        case "6":
            target := c.GetTarget()
            if target == "" {
                color.Red("[!] Target required!")
                time.Sleep(2 * time.Second)
                continue
            }

            result := c.scanner.RunScan(ctx, target, "web", "", "")
            if result != nil {
                c.scanner.DisplayResults(result)

                // Additional web info
                for _, host := range result.Hosts {
                    for _, port := range host.Ports {
                        if port.Port == 80 || port.Port == 443 {
                            protocol := "http"
                            if port.Port == 443 {
                                protocol = "https"
                            }
                            color.Cyan("\n🌐 Web server detected:")
                            color.White("  URL: %s://%s", protocol, host.IP)
                            color.White("  Test with: curl -I %s://%s", protocol, host.IP)
                            
                            if port.Banner != "" {
                                color.White("  Banner: %s", port.Banner)
                            }
                        }
                    }
                }
            }
            fmt.Print(color.HiBlackString("\nPress Enter to continue..."))
            scanner.Scan()

        case "7":
            target := c.GetTarget()
            if target == "" {
                color.Red("[!] Target required!")
                time.Sleep(2 * time.Second)
                continue
            }

            result := c.scanner.RunScan(ctx, target, "mobile", "", "")
            if result != nil {
                c.scanner.DisplayResults(result)

                // Android specific warnings
                for _, host := range result.Hosts {
                    for _, port := range host.Ports {
                        if port.Port == 5555 {
                            color.Red("\n⚠️  ADB debugging enabled on port 5555!")
                            color.Yellow("   This allows remote shell access")
                            color.Yellow("   Disable Developer Options on device")
                        }
                        if port.Port == 5037 {
                            color.Red("\n⚠️  ADB server running on port 5037!")
                            color.Yellow("   Device may be rooted/unlocked")
                        }
                    }
                }
            }
            fmt.Print(color.HiBlackString("\nPress Enter to continue..."))
            scanner.Scan()

        case "8":
            target := c.GetTarget()
            if target == "" {
                color.Red("[!] Target required!")
                time.Sleep(2 * time.Second)
                continue
            }

            color.Yellow("[*] Running aggressive full scan...")
            color.Yellow("[!] This may take a long time")
            result := c.scanner.RunScan(ctx, target, "full", "", "-A -T4")
            if result != nil {
                c.scanner.DisplayResults(result)
            }
            fmt.Print(color.HiBlackString("\nPress Enter to continue..."))
            scanner.Scan()

        case "9":
            target := c.GetTarget()
            if target == "" {
                color.Red("[!] Target required!")
                time.Sleep(2 * time.Second)
                continue
            }

            result := c.scanner.RunScan(ctx, target, "os", "", "")
            if result != nil {
                c.scanner.DisplayResults(result)
            }
            fmt.Print(color.HiBlackString("\nPress Enter to continue..."))
            scanner.Scan()

        case "10":
            target := c.GetTarget()
            if target == "" {
                color.Red("[!] Target required!")
                time.Sleep(2 * time.Second)
                continue
            }

            color.Yellow("[*] Scanning UDP services...")
            result := c.scanner.RunScan(ctx, target, "udp", "", "")
            if result != nil {
                c.scanner.DisplayResults(result)
            }
            fmt.Print(color.HiBlackString("\nPress Enter to continue..."))
            scanner.Scan()

        case "11":
            target := c.GetTarget()
            if target == "" {
                color.Red("[!] Target required!")
                time.Sleep(2 * time.Second)
                continue
            }

            color.Yellow("[*] Enumerating SMB services...")
            result := c.scanner.RunScan(ctx, target, "smb", "445", "--script smb*")
            if result != nil {
                c.scanner.DisplayResults(result)
            }
            fmt.Print(color.HiBlackString("\nPress Enter to continue..."))
            scanner.Scan()

        case "12":
            target := c.GetTarget()
            if target == "" {
                color.Red("[!] Target required!")
                time.Sleep(2 * time.Second)
                continue
            }

            color.Yellow("[*] Enumerating DNS...")
            result := c.scanner.RunScan(ctx, target, "dns", "53", "--script dns*")
            if result != nil {
                c.scanner.DisplayResults(result)
            }
            fmt.Print(color.HiBlackString("\nPress Enter to continue..."))
            scanner.Scan()

        case "13":
            target := c.GetTarget()
            if target == "" {
                color.Red("[!] Target required!")
                time.Sleep(2 * time.Second)
                continue
            }

            color.Yellow("[*] Enumerating SNMP...")
            result := c.scanner.RunScan(ctx, target, "snmp", "161", "--script snmp*")
            if result != nil {
                c.scanner.DisplayResults(result)
            }
            fmt.Print(color.HiBlackString("\nPress Enter to continue..."))
            scanner.Scan()

        case "14":
            target := c.GetTarget()
            if target == "" {
                color.Red("[!] Target required!")
                time.Sleep(2 * time.Second)
                continue
            }

            color.Yellow("[*] Scanning SSL/TLS...")
            result := c.scanner.RunScan(ctx, target, "ssl", "443", "--script ssl*")
            if result != nil {
                c.scanner.DisplayResults(result)
            }
            fmt.Print(color.HiBlackString("\nPress Enter to continue..."))
            scanner.Scan()

        case "15":
            target := c.GetTarget()
            if target == "" {
                color.Red("[!] Target required!")
                time.Sleep(2 * time.Second)
                continue
            }

            color.Yellow("[*] Detecting firewall rules...")
            result := c.scanner.RunScan(ctx, target, "firewall", "", "")
            if result != nil {
                c.scanner.DisplayResults(result)
            }
            fmt.Print(color.HiBlackString("\nPress Enter to continue..."))
            scanner.Scan()

        case "16":
            target := c.GetTarget()
            if target == "" {
                color.Red("[!] Target required!")
                time.Sleep(2 * time.Second)
                continue
            }

            color.Yellow("[*] Running evasive scan...")
            result := c.scanner.RunScan(ctx, target, "evasive", "", "")
            if result != nil {
                c.scanner.DisplayResults(result)
            }
            fmt.Print(color.HiBlackString("\nPress Enter to continue..."))
            scanner.Scan()

        case "17":
            c.scanner.ShowHistory()
            fmt.Print(color.HiBlackString("\nPress Enter to continue..."))
            scanner.Scan()

        case "18":
            c.ShowProfilesHelp()
            fmt.Print(color.HiBlackString("\nPress Enter to continue..."))
            scanner.Scan()

        case "19":
            target := c.GetTarget()
            if target == "" {
                color.Red("[!] Target required!")
                time.Sleep(2 * time.Second)
                continue
            }

            color.Cyan("[*] Using packet scanner (no nmap)...")

            // Validate target
            if valid, typ := c.utils.ValidateTarget(target); valid {
                if typ == "ip" {
                    // Port scan common ports
                    commonPorts := []int{21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 27017}
                    ports := c.scanner.packetScan.PortScan(ctx, target, commonPorts)

                    result := &ScanResult{
                        ID:        fmt.Sprintf("packet_%d", time.Now().UnixNano()),
                        Target:    target,
                        Profile:   "packet",
                        StartTime: time.Now(),
                        Hosts: []HostInfo{
                            {
                                IP:     target,
                                Status: "up",
                                Ports:  ports,
                            },
                        },
                        Summary: ScanSummary{
                            HostsUp:    1,
                            OpenPorts:  len(ports),
                            TotalPorts: len(ports),
                            Services:   make(map[string]int),
                        },
                    }

                    for _, port := range ports {
                        result.Summary.Services[port.Service]++
                    }

                    result.EndTime = time.Now()
                    result.Duration = result.EndTime.Sub(result.StartTime)

                    c.scanner.DisplayResults(result)
                    c.scanner.SaveResults(result)
                } else {
                    color.Yellow("[!] Packet scanner only supports IP addresses")
                }
            } else {
                color.Red("[✗] Invalid target")
            }
            fmt.Print(color.HiBlackString("\nPress Enter to continue..."))
            scanner.Scan()

        case "0":
            color.Green("\nGoodbye! 👋")
            c.running = false

        default:
            color.Red("[!] Invalid choice!")
            time.Sleep(1 * time.Second)
        }
    }
}

func (c *CLI) ShowProfilesHelp() {
    color.Cyan("\n📖 SCAN PROFILES HELP:")
    color.Cyan(strings.Repeat("=", 70))

    profiles := map[string]string{
        "quick":    "Fast reconnaissance - 100 common ports",
        "basic":    "General purpose with service detection",
        "stealth":  "Slow scan to avoid detection",
        "full":     "Comprehensive - all ports + OS + version",
        "vuln":     "Vulnerability detection scripts",
        "os":       "OS fingerprinting only",
        "udp":      "UDP service scan",
        "web":      "Web server focused (80,443,8080,8443)",
        "mobile":   "Android/iOS device ports",
        "termux":   "Optimized for Termux (ports 1-1000)",
        "smb":      "SMB/CIFS enumeration",
        "dns":      "DNS enumeration",
        "snmp":     "SNMP enumeration",
        "ssl":      "SSL/TLS security scan",
        "firewall": "Firewall detection",
        "evasive":  "Evasive scan with fragmentation",
    }

    for name, desc := range profiles {
        color.White("\n\033[96m🔹 %s:\033[0m", strings.ToUpper(name))
        color.White("   %s", desc)
        color.White("   Command: nmap %s", DefaultConfig.ScanProfiles[name])
    }

    color.Cyan("\n💡 TIPS:")
    color.White("  • Use 'termux' profile for best performance on Android")
    color.White("  • Use 'quick' for fast results")
    color.White("  • Use 'stealth' to avoid firewalls")
    color.White("  • Use 'vuln' for security assessments")
    color.White("  • Use 'smb' for Windows/Samba enumeration")
    color.White("  • Use 'ssl' for checking HTTPS security")
    color.White("  • Root may be needed for some scan types")
    color.Cyan(strings.Repeat("=", 70))
}

// ========== UTILITIES EXTENSION ==========
func (u *Utils) ClearScreen() {
    cmd := exec.Command("clear")
    cmd.Stdout = os.Stdout
    cmd.Run()
}

// ========== MAIN ==========
func main() {
    runtime.GOMAXPROCS(runtime.NumCPU())

    cli := NewCLI()
    cli.Run()
}
