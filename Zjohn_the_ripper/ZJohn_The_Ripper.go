package main

import (
    "bufio"
    "container/list"
    "context"
    "crypto/md5"
    "crypto/sha1"
    "crypto/sha256"
    "crypto/sha512"
    "encoding/csv"
    "encoding/hex"
    "fmt"
    "io"
    "os"
    "os/exec"
    "path/filepath"
    "runtime"
    "sort"
    "strconv"
    "strings"
    "sync"
    "sync/atomic"
    "time"
    "unicode"

    "golang.org/x/crypto/bcrypt"
    "golang.org/x/crypto/md4"

    "github.com/fatih/color"
    "github.com/schollz/progressbar/v3"
)

// ========== CONFIGURATION ==========
type Config struct {
    Wordlist         string
    RulesFile        string
    HashFile         string
    OutputFile       string
    Format           string
    MaxWorkers       int
    MaxMemory        int64
    Incremental      bool
    IncrementalMin   int
    IncrementalMax   int
    IncrementalChars string
    ShowCracked      bool
    Verbose          bool
    Benchmark        bool
    Timeout          time.Duration
    SessionName      string
    RestoreSession   bool
    UseGPU           bool
    ForceCPU         bool
    MaskMode         bool
    MaskPattern      string
    MarkovMode       bool
    MarkovFile       string
    PRINCEMode       bool
    PRINCEWordlist   string
    Loopback         bool
    Fork             int
    Node             int
    MPI              bool
    SkipSelfTest     bool
}

var DefaultConfig = Config{
    Wordlist:         "wordlist.txt",
    HashFile:         "hashes.txt",
    OutputFile:       "cracked.txt",
    MaxWorkers:       runtime.NumCPU(),
    MaxMemory:        4096,
    Incremental:      false,
    IncrementalMin:   1,
    IncrementalMax:   8,
    IncrementalChars: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?",
    Format:           "auto",
    ShowCracked:      true,
    Verbose:          false,
    Benchmark:        false,
    SessionName:      "zjohn",
    RestoreSession:   false,
    UseGPU:           true,
    ForceCPU:         false,
    MaskMode:         false,
    MaskPattern:      "?l?l?l?l?d?d",
    MarkovMode:       false,
    MarkovFile:       "markov.stats",
    PRINCEMode:       false,
    Loopback:         false,
    Fork:             1,
    Node:             0,
    MPI:              false,
    SkipSelfTest:     false,
}

// ========== HASH FORMATS ==========
type HashFormat struct {
    Name        string
    Prefix      string
    Length      int
    Type        string
    HashFunc    func(string) string
    VerifyFunc  func(string, string) bool
    IsValid     func(string) bool
    Complexity  int
    MinLen      int
    MaxLen      int
    Salted      bool
}

func hashMD5(s string) string {
    data := []byte(s)
    h := md5.Sum(data)
    return hex.EncodeToString(h[:])
}

func verifyMD5(password, hash string) bool {
    return hashMD5(password) == hash
}

func isValidMD5(hash string) bool {
    return len(hash) == 32 && isHex(hash)
}

func hashSHA1(s string) string {
    data := []byte(s)
    h := sha1.Sum(data)
    return hex.EncodeToString(h[:])
}

func verifySHA1(password, hash string) bool {
    return hashSHA1(password) == hash
}

func isValidSHA1(hash string) bool {
    return len(hash) == 40 && isHex(hash)
}

func hashSHA256(s string) string {
    data := []byte(s)
    h := sha256.Sum256(data)
    return hex.EncodeToString(h[:])
}

func verifySHA256(password, hash string) bool {
    return hashSHA256(password) == hash
}

func isValidSHA256(hash string) bool {
    return len(hash) == 64 && isHex(hash)
}

func hashSHA512(s string) string {
    data := []byte(s)
    h := sha512.Sum512(data)
    return hex.EncodeToString(h[:])
}

func verifySHA512(password, hash string) bool {
    return hashSHA512(password) == hash
}

func isValidSHA512(hash string) bool {
    return len(hash) == 128 && isHex(hash)
}

func hashNTLM(s string) string {
    h := md4.New()
    io.WriteString(h, s)
    return hex.EncodeToString(h.Sum(nil))
}

func verifyNTLM(password, hash string) bool {
    return hashNTLM(password) == hash
}

func isValidNTLM(hash string) bool {
    return len(hash) == 32 && isHex(hash)
}

func hashBcrypt(password string) string {
    hash, _ := bcrypt.GenerateFromPassword([]byte(password), 10)
    return string(hash)
}

func verifyBcrypt(password, hash string) bool {
    err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
    return err == nil
}

func isValidBcrypt(hash string) bool {
    return strings.HasPrefix(hash, "$2a$") || 
           strings.HasPrefix(hash, "$2b$") || 
           strings.HasPrefix(hash, "$2y$")
}

var HashFormats = []HashFormat{
    {
        Name:       "md5",
        Prefix:     "",
        Length:     32,
        Type:       "raw",
        HashFunc:   hashMD5,
        VerifyFunc: verifyMD5,
        IsValid:    isValidMD5,
        Complexity: 1,
        MinLen:     32,
        MaxLen:     32,
        Salted:     false,
    },
    {
        Name:       "sha1",
        Prefix:     "",
        Length:     40,
        Type:       "raw",
        HashFunc:   hashSHA1,
        VerifyFunc: verifySHA1,
        IsValid:    isValidSHA1,
        Complexity: 2,
        MinLen:     40,
        MaxLen:     40,
        Salted:     false,
    },
    {
        Name:       "sha256",
        Prefix:     "",
        Length:     64,
        Type:       "raw",
        HashFunc:   hashSHA256,
        VerifyFunc: verifySHA256,
        IsValid:    isValidSHA256,
        Complexity: 3,
        MinLen:     64,
        MaxLen:     64,
        Salted:     false,
    },
    {
        Name:       "sha512",
        Prefix:     "",
        Length:     128,
        Type:       "raw",
        HashFunc:   hashSHA512,
        VerifyFunc: verifySHA512,
        IsValid:    isValidSHA512,
        Complexity: 4,
        MinLen:     128,
        MaxLen:     128,
        Salted:     false,
    },
    {
        Name:       "ntlm",
        Prefix:     "",
        Length:     32,
        Type:       "raw",
        HashFunc:   hashNTLM,
        VerifyFunc: verifyNTLM,
        IsValid:    isValidNTLM,
        Complexity: 2,
        MinLen:     32,
        MaxLen:     32,
        Salted:     false,
    },
    {
        Name:       "bcrypt",
        Prefix:     "$2a$",
        Length:     60,
        Type:       "crypt",
        HashFunc:   hashBcrypt,
        VerifyFunc: verifyBcrypt,
        IsValid:    isValidBcrypt,
        Complexity: 10,
        MinLen:     60,
        MaxLen:     60,
        Salted:     true,
    },
}

// ========== MARKOV CHAIN ==========
type MarkovChain struct {
    Order        int
    Stats        map[string]map[rune]int
    Total        map[string]int
    StartChars   map[rune]int
    TotalStarts  int
    mu           sync.RWMutex
    MaxGen       int
}

func NewMarkovChain(order int) *MarkovChain {
    return &MarkovChain{
        Order:       order,
        Stats:       make(map[string]map[rune]int),
        Total:       make(map[string]int),
        StartChars:  make(map[rune]int),
        MaxGen:      1000000,
    }
}

func (mc *MarkovChain) Train(wordlist string) error {
    file, err := os.Open(wordlist)
    if err != nil {
        return err
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    
    for scanner.Scan() {
        word := strings.TrimSpace(scanner.Text())
        if len(word) < mc.Order {
            continue
        }

        mc.mu.Lock()
        firstRune := []rune(word)[0]
        mc.StartChars[firstRune]++

        runes := []rune(word)
        for i := 0; i <= len(runes)-mc.Order; i++ {
            prefix := string(runes[i : i+mc.Order-1])
            nextChar := runes[i+mc.Order-1]

            if mc.Stats[prefix] == nil {
                mc.Stats[prefix] = make(map[rune]int)
            }
            mc.Stats[prefix][nextChar]++
            mc.Total[prefix]++
        }
        mc.mu.Unlock()
    }

    mc.mu.Lock()
    for _, count := range mc.StartChars {
        mc.TotalStarts += count
    }
    mc.mu.Unlock()

    return nil
}

func (mc *MarkovChain) Generate(maxLen int) <-chan string {
    ch := make(chan string, 1000)

    go func() {
        defer close(ch)

        generated := 0
        for generated < mc.MaxGen {
            startChar := mc.pickStartChar()
            if startChar == 0 {
                continue
            }

            word := []rune{startChar}
            
            for len(word) < maxLen {
                prefix := mc.getPrefix(word)
                nextChar := mc.pickNextChar(prefix)
                if nextChar == 0 {
                    break
                }
                word = append(word, nextChar)

                if len(word) >= 4 && generated < mc.MaxGen {
                    ch <- string(word)
                    generated++
                }
            }

            if len(word) >= 4 && generated < mc.MaxGen {
                ch <- string(word)
                generated++
            }
        }
    }()

    return ch
}

func (mc *MarkovChain) pickStartChar() rune {
    mc.mu.RLock()
    defer mc.mu.RUnlock()

    if mc.TotalStarts == 0 {
        return 0
    }

    target := randInt(0, mc.TotalStarts)
    current := 0
    for char, count := range mc.StartChars {
        current += count
        if current > target {
            return char
        }
    }
    return 0
}

func (mc *MarkovChain) pickNextChar(prefix string) rune {
    mc.mu.RLock()
    defer mc.mu.RUnlock()

    stats, exists := mc.Stats[prefix]
    if !exists || mc.Total[prefix] == 0 {
        return 0
    }

    target := randInt(0, mc.Total[prefix])
    current := 0
    for char, count := range stats {
        current += count
        if current > target {
            return char
        }
    }
    return 0
}

func (mc *MarkovChain) getPrefix(word []rune) string {
    if len(word) < mc.Order-1 {
        return string(word)
    }
    return string(word[len(word)-(mc.Order-1):])
}

// ========== PRINCE ATTACK ==========
type PRINCE struct {
    words       []string
    minLen      int
    maxLen      int
    duplicates  map[string]bool
    mu          sync.Mutex
    queue       chan string
}

func NewPRINCE(wordlist string) (*PRINCE, error) {
    file, err := os.Open(wordlist)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    p := &PRINCE{
        words:      make([]string, 0),
        minLen:     1,
        maxLen:     32,
        duplicates: make(map[string]bool),
        queue:      make(chan string, 10000),
    }

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        word := strings.TrimSpace(scanner.Text())
        if len(word) >= p.minLen && len(word) <= p.maxLen {
            p.words = append(p.words, word)
        }
    }

    return p, nil
}

func (p *PRINCE) Generate() <-chan string {
    go func() {
        defer close(p.queue)
        
        for _, word := range p.words {
            p.queue <- word
        }

        for i := 0; i < len(p.words); i++ {
            for j := 0; j < len(p.words); j++ {
                if i == j {
                    continue
                }
                
                combo := p.words[i] + p.words[j]
                if len(combo) <= p.maxLen && !p.duplicates[combo] {
                    p.mu.Lock()
                    p.duplicates[combo] = true
                    p.mu.Unlock()
                    p.queue <- combo
                }

                separators := []string{"", ".", "_", "-", "@", "#"}
                for _, sep := range separators {
                    combo = p.words[i] + sep + p.words[j]
                    if len(combo) <= p.maxLen && !p.duplicates[combo] {
                        p.mu.Lock()
                        p.duplicates[combo] = true
                        p.mu.Unlock()
                        p.queue <- combo
                    }
                }
            }
        }
    }()

    return p.queue
}

// ========== MASK ATTACK ==========
type MaskAttack struct {
    pattern     string
    customChars map[byte]string
    current     []int
    done        bool
    total       int64
    generated   int64
    mu          sync.Mutex
}

func NewMaskAttack(pattern string) *MaskAttack {
    ma := &MaskAttack{
        pattern:     pattern,
        customChars: make(map[byte]string),
        current:     make([]int, len(pattern)),
        done:        false,
    }

    ma.customChars['l'] = "abcdefghijklmnopqrstuvwxyz"
    ma.customChars['u'] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    ma.customChars['d'] = "0123456789"
    ma.customChars['s'] = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    ma.customChars['a'] = ma.customChars['l'] + ma.customChars['u'] + ma.customChars['d'] + ma.customChars['s']

    ma.calculateTotal()
    return ma
}

func (ma *MaskAttack) calculateTotal() {
    ma.total = 1
    for i := 0; i < len(ma.pattern); i++ {
        if ma.pattern[i] == '?' && i+1 < len(ma.pattern) {
            charset := ma.customChars[ma.pattern[i+1]]
            ma.total *= int64(len(charset))
            i++
        }
    }
}

func (ma *MaskAttack) Next() (string, bool) {
    ma.mu.Lock()
    defer ma.mu.Unlock()

    if ma.done {
        return "", false
    }

    result := make([]byte, len(ma.pattern))
    pos := 0

    for i := 0; i < len(ma.pattern); i++ {
        if ma.pattern[i] == '?' && i+1 < len(ma.pattern) {
            charset := ma.customChars[ma.pattern[i+1]]
            result[pos] = charset[ma.current[pos]]
            pos++
            i++
        } else {
            result[pos] = ma.pattern[i]
            pos++
        }
    }

    ma.increment()
    ma.generated++

    return string(result), true
}

func (ma *MaskAttack) increment() {
    for i := 0; i < len(ma.current); i++ {
        ma.current[i]++
        
        charset := ma.getCharsetAtIndex(i)
        if ma.current[i] < len(charset) {
            return
        }
        ma.current[i] = 0
    }
    ma.done = true
}

func (ma *MaskAttack) getCharsetAtIndex(idx int) string {
    patternIdx := 0
    for i := 0; i < len(ma.pattern); i++ {
        if ma.pattern[i] == '?' && i+1 < len(ma.pattern) {
            if patternIdx == idx {
                return ma.customChars[ma.pattern[i+1]]
            }
            patternIdx++
            i++
        } else {
            if patternIdx == idx {
                return string(ma.pattern[i])
            }
            patternIdx++
        }
    }
    return ""
}

// ========== LOOPBACK ATTACK ==========
type LoopbackAttack struct {
    cracked   *list.List
    maxSize   int
    rules     *RuleEngine
    mu        sync.Mutex
    generated map[string]bool
}

func NewLoopbackAttack(maxSize int) *LoopbackAttack {
    return &LoopbackAttack{
        cracked:   list.New(),
        maxSize:   maxSize,
        generated: make(map[string]bool),
    }
}

func (la *LoopbackAttack) AddCracked(password string) {
    la.mu.Lock()
    defer la.mu.Unlock()

    la.cracked.PushBack(password)
    if la.cracked.Len() > la.maxSize {
        la.cracked.Remove(la.cracked.Front())
    }
}

func (la *LoopbackAttack) Generate(rules *RuleEngine) <-chan string {
    ch := make(chan string, 1000)

    go func() {
        defer close(ch)

        la.mu.Lock()
        passwords := make([]string, 0, la.cracked.Len())
        for e := la.cracked.Front(); e != nil; e = e.Next() {
            passwords = append(passwords, e.Value.(string))
        }
        la.mu.Unlock()

        for _, pwd := range passwords {
            if rules != nil {
                for _, variant := range rules.Apply(pwd) {
                    la.mu.Lock()
                    if !la.generated[variant] {
                        la.generated[variant] = true
                        ch <- variant
                    }
                    la.mu.Unlock()
                }
            }
            ch <- pwd
        }
    }()

    return ch
}

// ========== DISTRIBUTED NODE ==========
type DistributedNode struct {
    ID          int
    WorkQueue   chan WorkUnit
    ResultQueue chan WorkResult
    Master      bool
    Nodes       []*DistributedNode
    mu          sync.Mutex
    wg          sync.WaitGroup
    ctx         context.Context
    cancel      context.CancelFunc
}

type WorkUnit struct {
    ID       int64
    NodeID   int
    Hash     string
    Format   *HashFormat
    Wordlist []string
}

type WorkResult struct {
    UnitID   int64
    NodeID   int
    Hash     string
    Password string
    Found    bool
    Attempts int64
    Time     time.Duration
}

func NewDistributedNode(id int, master bool) *DistributedNode {
    ctx, cancel := context.WithCancel(context.Background())
    return &DistributedNode{
        ID:          id,
        Master:      master,
        WorkQueue:   make(chan WorkUnit, 1000),
        ResultQueue: make(chan WorkResult, 1000),
        Nodes:       make([]*DistributedNode, 0),
        ctx:         ctx,
        cancel:      cancel,
    }
}

func (dn *DistributedNode) AddNode(node *DistributedNode) {
    dn.mu.Lock()
    defer dn.mu.Unlock()
    dn.Nodes = append(dn.Nodes, node)
}

func (dn *DistributedNode) StartWorker() {
    dn.wg.Add(1)
    go func() {
        defer dn.wg.Done()

        for {
            select {
            case <-dn.ctx.Done():
                return
            case unit, ok := <-dn.WorkQueue:
                if !ok {
                    return
                }

                result := dn.processWork(unit)
                if dn.Master {
                    dn.ResultQueue <- result
                }
            }
        }
    }()
}

func (dn *DistributedNode) processWork(unit WorkUnit) WorkResult {
    start := time.Now()
    result := WorkResult{
        UnitID: unit.ID,
        NodeID: dn.ID,
        Hash:   unit.Hash,
        Found:  false,
    }

    for _, word := range unit.Wordlist {
        result.Attempts++
        if unit.Format.VerifyFunc(word, unit.Hash) {
            result.Found = true
            result.Password = word
            break
        }
    }

    result.Time = time.Since(start)
    return result
}

func (dn *DistributedNode) Stop() {
    dn.cancel()
    close(dn.WorkQueue)
    close(dn.ResultQueue)
    dn.wg.Wait()
}

// ========== HASH STORE ==========
type Hash struct {
    ID        int
    RawHash   string
    Format    *HashFormat
    Salt      string
    Password  string
    Cracked   bool
    CrackTime time.Duration
    Attempts  int64
    Line      int
    File      string
    Username  string
    Extra     map[string]string
}

type HashStore struct {
    Hashes      []*Hash
    FormatMap   map[string][]*Hash
    Cracked     int64
    Total       int64
    mu          sync.RWMutex
    StartTime   time.Time
    Cache       map[string]string
    CacheHits   int64
    CacheMisses int64
}

func NewHashStore() *HashStore {
    return &HashStore{
        Hashes:    make([]*Hash, 0),
        FormatMap: make(map[string][]*Hash),
        StartTime: time.Now(),
        Cache:     make(map[string]string),
    }
}

func (hs *HashStore) AddHash(hash *Hash) {
    hs.mu.Lock()
    defer hs.mu.Unlock()
    
    hash.ID = len(hs.Hashes)
    hs.Hashes = append(hs.Hashes, hash)
    hs.Total++
    
    if hash.Format != nil {
        hs.FormatMap[hash.Format.Name] = append(hs.FormatMap[hash.Format.Name], hash)
    }
}

func (hs *HashStore) MarkCracked(hash *Hash, password string, duration time.Duration) {
    hs.mu.Lock()
    defer hs.mu.Unlock()
    
    if !hash.Cracked {
        hash.Cracked = true
        hash.Password = password
        hash.CrackTime = duration
        hs.Cracked++
        hs.Cache[hash.RawHash] = password
    }
}

func (hs *HashStore) CheckCache(hash string) (string, bool) {
    hs.mu.RLock()
    defer hs.mu.RUnlock()
    
    if pwd, ok := hs.Cache[hash]; ok {
        atomic.AddInt64(&hs.CacheHits, 1)
        return pwd, true
    }
    atomic.AddInt64(&hs.CacheMisses, 1)
    return "", false
}

func (hs *HashStore) GetStats() map[string]interface{} {
    hs.mu.RLock()
    defer hs.mu.RUnlock()
    
    stats := make(map[string]interface{})
    stats["total"] = hs.Total
    stats["cracked"] = hs.Cracked
    stats["remaining"] = hs.Total - hs.Cracked
    stats["cache_hits"] = hs.CacheHits
    stats["cache_misses"] = hs.CacheMisses
    
    if hs.Total > 0 {
        stats["percentage"] = float64(hs.Cracked) / float64(hs.Total) * 100
    } else {
        stats["percentage"] = 0.0
    }
    stats["elapsed"] = time.Since(hs.StartTime).String()
    
    formatStats := make(map[string]map[string]interface{})
    for format, hashes := range hs.FormatMap {
        cracked := 0
        totalAttempts := int64(0)
        for _, h := range hashes {
            if h.Cracked {
                cracked++
            }
            totalAttempts += h.Attempts
        }
        formatStats[format] = map[string]interface{}{
            "total":     len(hashes),
            "cracked":   cracked,
            "remaining": len(hashes) - cracked,
            "attempts":  totalAttempts,
        }
    }
    stats["by_format"] = formatStats
    
    return stats
}

// ========== WORDLIST MANAGER ==========
type WordlistManager struct {
    path        string
    file        *os.File
    scanner     *bufio.Scanner
    size        int64
    lines       int64
    current     int64
    mu          sync.Mutex
    bufferSize  int
    memoryLimit int64
    useMemory   bool
    words       []string
}

func NewWordlistManager(path string, memoryLimit int64) (*WordlistManager, error) {
    file, err := os.Open(path)
    if err != nil {
        return nil, err
    }
    
    info, err := file.Stat()
    if err != nil {
        file.Close()
        return nil, err
    }
    
    wm := &WordlistManager{
        path:        path,
        file:        file,
        size:        info.Size(),
        bufferSize:  1024 * 1024,
        memoryLimit: memoryLimit * 1024 * 1024,
    }
    
    wm.countLines()
    
    if wm.size < wm.memoryLimit {
        wm.useMemory = true
        wm.loadToMemory()
    } else {
        wm.useMemory = false
        wm.scanner = bufio.NewScanner(file)
        wm.scanner.Buffer(make([]byte, wm.bufferSize), wm.bufferSize)
    }
    
    return wm, nil
}

func (wm *WordlistManager) countLines() {
    scanner := bufio.NewScanner(wm.file)
    for scanner.Scan() {
        wm.lines++
    }
    wm.file.Seek(0, 0)
}

func (wm *WordlistManager) loadToMemory() {
    wm.words = make([]string, 0, wm.lines)
    
    scanner := bufio.NewScanner(wm.file)
    scanner.Buffer(make([]byte, wm.bufferSize), wm.bufferSize)
    
    for scanner.Scan() {
        wm.words = append(wm.words, scanner.Text())
    }
    wm.file.Seek(0, 0)
}

func (wm *WordlistManager) Next() (string, error) {
    wm.mu.Lock()
    defer wm.mu.Unlock()
    
    if wm.useMemory {
        if wm.current >= int64(len(wm.words)) {
            return "", io.EOF
        }
        word := wm.words[wm.current]
        wm.current++
        return word, nil
    }
    
    if wm.scanner.Scan() {
        wm.current++
        return wm.scanner.Text(), nil
    }
    
    return "", io.EOF
}

func (wm *WordlistManager) NextBatch(size int) ([]string, error) {
    batch := make([]string, 0, size)
    
    for i := 0; i < size; i++ {
        word, err := wm.Next()
        if err != nil {
            break
        }
        batch = append(batch, word)
    }
    
    if len(batch) == 0 {
        return nil, io.EOF
    }
    
    return batch, nil
}

func (wm *WordlistManager) Reset() {
    wm.mu.Lock()
    defer wm.mu.Unlock()
    
    wm.current = 0
    if !wm.useMemory {
        wm.file.Seek(0, 0)
        wm.scanner = bufio.NewScanner(wm.file)
    }
}

func (wm *WordlistManager) Close() {
    wm.file.Close()
}

// ========== RULE ENGINE ==========
type RuleEngine struct {
    rules     []Rule
    custom    []string
    stats     RuleStats
    cache     map[string][]string
    cacheMu   sync.RWMutex
    cacheSize int
}

type Rule struct {
    Pattern    string
    Operation  string
    Apply      func(string) []string
    Complexity int
    Frequency  float64
}

type RuleStats struct {
    Applied   int64
    Generated int64
    Unique    int64
    CacheHits int64
}

var AdvancedRules = []Rule{
    {
        Pattern:    "lower",
        Operation:  "lowercase",
        Apply: func(word string) []string {
            return []string{strings.ToLower(word)}
        },
    },
    {
        Pattern:    "upper",
        Operation:  "uppercase",
        Apply: func(word string) []string {
            return []string{strings.ToUpper(word)}
        },
    },
    {
        Pattern:    "capitalize",
        Operation:  "capitalize first",
        Apply: func(word string) []string {
            if len(word) == 0 {
                return []string{word}
            }
            return []string{strings.ToUpper(word[:1]) + strings.ToLower(word[1:])}
        },
    },
    {
        Pattern:    "invert",
        Operation:  "invert case",
        Apply: func(word string) []string {
            result := make([]rune, len(word))
            for i, c := range word {
                if unicode.IsUpper(c) {
                    result[i] = unicode.ToLower(c)
                } else {
                    result[i] = unicode.ToUpper(c)
                }
            }
            return []string{string(result)}
        },
    },
    {
        Pattern:    "append_year",
        Operation:  "append year",
        Apply: func(word string) []string {
            years := []string{"2020", "2021", "2022", "2023", "2024"}
            results := make([]string, len(years))
            for i, year := range years {
                results[i] = word + year
            }
            return results
        },
    },
    {
        Pattern:    "append_common",
        Operation:  "append common",
        Apply: func(word string) []string {
            suffixes := []string{"123", "1234", "!", "@", "#"}
            results := make([]string, len(suffixes))
            for i, suf := range suffixes {
                results[i] = word + suf
            }
            return results
        },
    },
    {
        Pattern:    "prepend_common",
        Operation:  "prepend common",
        Apply: func(word string) []string {
            prefixes := []string{"!", "@", "#", "123"}
            results := make([]string, len(prefixes))
            for i, pre := range prefixes {
                results[i] = pre + word
            }
            return results
        },
    },
    {
        Pattern:    "leet_basic",
        Operation:  "basic leet",
        Apply: func(word string) []string {
            result := word
            result = strings.ReplaceAll(result, "a", "4")
            result = strings.ReplaceAll(result, "e", "3")
            result = strings.ReplaceAll(result, "i", "1")
            result = strings.ReplaceAll(result, "o", "0")
            result = strings.ReplaceAll(result, "s", "5")
            return []string{result}
        },
    },
    {
        Pattern:    "reverse",
        Operation:  "reverse word",
        Apply: func(word string) []string {
            runes := []rune(word)
            for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
                runes[i], runes[j] = runes[j], runes[i]
            }
            return []string{string(runes)}
        },
    },
}

func NewRuleEngine(rulesFile string) (*RuleEngine, error) {
    re := &RuleEngine{
        rules:     make([]Rule, len(AdvancedRules)),
        custom:    make([]string, 0),
        cache:     make(map[string][]string),
        cacheSize: 10000,
    }
    copy(re.rules, AdvancedRules)
    
    if rulesFile != "" {
        if err := re.loadCustomRules(rulesFile); err != nil {
            return nil, err
        }
    }
    
    return re, nil
}

func (re *RuleEngine) loadCustomRules(filename string) error {
    file, err := os.Open(filename)
    if err != nil {
        return err
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        rule := strings.TrimSpace(scanner.Text())
        if rule != "" && !strings.HasPrefix(rule, "#") {
            re.custom = append(re.custom, rule)
        }
    }

    return nil
}

func (re *RuleEngine) Apply(word string) []string {
    re.cacheMu.RLock()
    if cached, ok := re.cache[word]; ok {
        atomic.AddInt64(&re.stats.CacheHits, 1)
        re.cacheMu.RUnlock()
        return cached
    }
    re.cacheMu.RUnlock()

    resultsMap := make(map[string]bool)
    resultsMap[word] = true

    for _, rule := range re.rules {
        for _, result := range rule.Apply(word) {
            if result != "" && !resultsMap[result] {
                resultsMap[result] = true
                atomic.AddInt64(&re.stats.Applied, 1)
                atomic.AddInt64(&re.stats.Generated, 1)
            }
        }
    }

    for _, custom := range re.custom {
        if result := re.applyCustomRule(word, custom); result != "" && !resultsMap[result] {
            resultsMap[result] = true
            atomic.AddInt64(&re.stats.Applied, 1)
            atomic.AddInt64(&re.stats.Generated, 1)
        }
    }

    results := make([]string, 0, len(resultsMap))
    for result := range resultsMap {
        results = append(results, result)
        atomic.AddInt64(&re.stats.Unique, 1)
    }

    sort.Slice(results, func(i, j int) bool {
        return len(results[i]) < len(results[j])
    })

    re.cacheMu.Lock()
    if len(re.cache) < re.cacheSize {
        re.cache[word] = results
    }
    re.cacheMu.Unlock()

    return results
}

func (re *RuleEngine) applyCustomRule(word, rule string) string {
    parts := strings.Split(rule, ":")
    if len(parts) != 2 {
        return ""
    }

    cmd := parts[0]
    arg := parts[1]

    switch cmd {
    case "append":
        return word + arg
    case "prepend":
        return arg + word
    case "replace":
        repParts := strings.Split(arg, ",")
        if len(repParts) == 2 {
            return strings.ReplaceAll(word, repParts[0], repParts[1])
        }
    case "truncate":
        if n, err := strconv.Atoi(arg); err == nil && n < len(word) {
            return word[:n]
        }
    }

    return ""
}

// ========== INCREMENTAL GENERATOR ==========
type IncrementalGenerator struct {
    chars     []rune
    minLen    int
    maxLen    int
    current   []int
    total     int64
    generated int64
    done      bool
    mu        sync.Mutex
}

func NewIncrementalGenerator(charset string, minLen, maxLen int) *IncrementalGenerator {
    ig := &IncrementalGenerator{
        chars:   []rune(charset),
        minLen:  minLen,
        maxLen:  maxLen,
        current: make([]int, minLen),
        total:   0,
    }
    
    for l := minLen; l <= maxLen; l++ {
        ig.total += int64(pow(len(charset), l))
    }
    
    return ig
}

func (ig *IncrementalGenerator) Next() (string, bool) {
    ig.mu.Lock()
    defer ig.mu.Unlock()
    
    if ig.done {
        return "", false
    }
    
    result := make([]rune, len(ig.current))
    for i, idx := range ig.current {
        result[i] = ig.chars[idx]
    }
    
    ig.increment()
    ig.generated++
    
    return string(result), true
}

func (ig *IncrementalGenerator) increment() {
    for i := len(ig.current) - 1; i >= 0; i-- {
        ig.current[i]++
        if ig.current[i] < len(ig.chars) {
            return
        }
        ig.current[i] = 0
    }
    
    if len(ig.current) < ig.maxLen {
        ig.current = make([]int, len(ig.current)+1)
    } else {
        ig.done = true
    }
}

func pow(x, y int) int {
    result := 1
    for i := 0; i < y; i++ {
        result *= x
    }
    return result
}

// ========== GPU DETECTION ==========
type GPUInfo struct {
    Available   bool
    Vendor      string
    Name        string
    Cores       int
    Memory      int64
    ComputeCap  string
    Drivers     []string
}

type GPUKernel struct {
    Name      string
    HashType  string
    Speed     int64
    Optimized bool
}

var GPUKernels = map[string]GPUKernel{
    "md5":    {Name: "md5", Speed: 300000000, Optimized: true},
    "sha1":   {Name: "sha1", Speed: 150000000, Optimized: true},
    "sha256": {Name: "sha256", Speed: 80000000, Optimized: true},
    "sha512": {Name: "sha512", Speed: 40000000, Optimized: true},
    "ntlm":   {Name: "ntlm", Speed: 400000000, Optimized: true},
    "bcrypt": {Name: "bcrypt", Speed: 8000000, Optimized: false},
}

func DetectGPU() GPUInfo {
    gpu := GPUInfo{
        Available: false,
        Drivers:   make([]string, 0),
    }

    if output, err := exec.Command("nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader").Output(); err == nil {
        lines := strings.Split(strings.TrimSpace(string(output)), "\n")
        for _, line := range lines {
            parts := strings.Split(line, ",")
            if len(parts) >= 1 {
                gpu.Available = true
                gpu.Vendor = "NVIDIA"
                gpu.Name = strings.TrimSpace(parts[0])
                
                if len(parts) >= 2 {
                    memStr := strings.TrimSpace(parts[1])
                    memStr = strings.ReplaceAll(memStr, " MiB", "")
                    if mem, err := strconv.ParseInt(memStr, 10, 64); err == nil {
                        gpu.Memory = mem
                    }
                }
                
                gpu.Cores = 5000
            }
        }
    }

    return gpu
}

// ========== GPU CRACKER ==========
type GPUCracker struct {
    Available bool
    GPUInfo   GPUInfo
    Kernels   map[string]GPUKernel
    Queue     chan GPUTask
    Results   chan GPUResult
    workers   int
    wg        sync.WaitGroup
    ctx       context.Context
    cancel    context.CancelFunc
}

type GPUTask struct {
    ID         int64
    HashFormat *HashFormat
    Hash       string
    Wordlist   []string
}

type GPUResult struct {
    TaskID   int64
    Hash     string
    Password string
    Found    bool
    Attempts int64
    Time     time.Duration
    GPU      int
}

func NewGPUCracker(ctx context.Context) *GPUCracker {
    gpuInfo := DetectGPU()
    
    gc := &GPUCracker{
        Available: gpuInfo.Available,
        GPUInfo:   gpuInfo,
        Kernels:   make(map[string]GPUKernel),
        Queue:     make(chan GPUTask, 10000),
        Results:   make(chan GPUResult, 10000),
        workers:   2,
        ctx:       ctx,
    }
    
    for k, v := range GPUKernels {
        gc.Kernels[k] = v
    }
    
    return gc
}

func (gc *GPUCracker) Start() {
    if !gc.Available {
        return
    }
    
    for i := 0; i < gc.workers; i++ {
        gc.wg.Add(1)
        go gc.worker(i)
    }
}

func (gc *GPUCracker) worker(id int) {
    defer gc.wg.Done()
    
    for {
        select {
        case <-gc.ctx.Done():
            return
        case task, ok := <-gc.Queue:
            if !ok {
                return
            }
            
            start := time.Now()
            attempts := int64(0)
            
            for _, word := range task.Wordlist {
                attempts++
                
                if task.HashFormat.VerifyFunc(word, task.Hash) {
                    gc.Results <- GPUResult{
                        TaskID:   task.ID,
                        Hash:     task.Hash,
                        Password: word,
                        Found:    true,
                        Attempts: attempts,
                        Time:     time.Since(start),
                        GPU:      id,
                    }
                    break
                }
            }
            
            if !task.HashFormat.VerifyFunc("", task.Hash) {
                gc.Results <- GPUResult{
                    TaskID:   task.ID,
                    Hash:     task.Hash,
                    Found:    false,
                    Attempts: attempts,
                    Time:     time.Since(start),
                    GPU:      id,
                }
            }
        }
    }
}

func (gc *GPUCracker) SubmitTask(task GPUTask) {
    select {
    case gc.Queue <- task:
    default:
    }
}

func (gc *GPUCracker) Stop() {
    gc.cancel()
    close(gc.Queue)
    gc.wg.Wait()
    close(gc.Results)
}

// ========== HYBRID CRACKER ==========
type HybridCracker struct {
    config      Config
    store       *HashStore
    wordlist    *WordlistManager
    rules       *RuleEngine
    incremental *IncrementalGenerator
    mask        *MaskAttack
    prince      *PRINCE
    loopback    *LoopbackAttack
    markov      *MarkovChain
    distributed *DistributedNode
    gpu         *GPUCracker
    cpuWorkers  int
    stats       CrackerStats
    mu          sync.Mutex
    wg          sync.WaitGroup
    ctx         context.Context
    cancel      context.CancelFunc
    batchChan   chan []string
    resultChan  chan *Hash
    wordChan    chan string
}

type CrackerStats struct {
    Attempts     int64
    Cracked      int64
    Speed        float64
    StartTime    time.Time
    CacheHits    int64
    CacheMisses  int64
    RulesApplied int64
    BatchSize    int
}

func NewHybridCracker(config Config, store *HashStore) (*HybridCracker, error) {
    var wm *WordlistManager
    var err error
    
    if config.Wordlist != "" {
        wm, err = NewWordlistManager(config.Wordlist, config.MaxMemory)
        if err != nil {
            return nil, fmt.Errorf("failed to load wordlist: %v", err)
        }
    }
    
    var re *RuleEngine
    if config.RulesFile != "" {
        re, err = NewRuleEngine(config.RulesFile)
        if err != nil {
            return nil, fmt.Errorf("failed to load rules: %v", err)
        }
    } else {
        re, _ = NewRuleEngine("")
    }
    
    var ig *IncrementalGenerator
    if config.Incremental {
        ig = NewIncrementalGenerator(
            config.IncrementalChars,
            config.IncrementalMin,
            config.IncrementalMax,
        )
    }
    
    var ma *MaskAttack
    if config.MaskMode {
        ma = NewMaskAttack(config.MaskPattern)
    }
    
    var mc *MarkovChain
    if config.MarkovMode {
        mc = NewMarkovChain(3)
        if config.MarkovFile != "" && config.Wordlist != "" {
            mc.Train(config.Wordlist)
        }
    }
    
    var pr *PRINCE
    if config.PRINCEMode && config.PRINCEWordlist != "" {
        pr, err = NewPRINCE(config.PRINCEWordlist)
        if err != nil {
            return nil, fmt.Errorf("failed to load PRINCE wordlist: %v", err)
        }
    }
    
    var lb *LoopbackAttack
    if config.Loopback {
        lb = NewLoopbackAttack(1000)
    }
    
    var dn *DistributedNode
    if config.MPI || config.Fork > 1 {
        dn = NewDistributedNode(config.Node, config.Node == 0)
    }
    
    ctx, cancel := context.WithCancel(context.Background())
    
    if dn != nil {
        for i := 1; i < config.Fork; i++ {
            node := NewDistributedNode(i, false)
            dn.AddNode(node)
            node.StartWorker()
        }
        dn.StartWorker()
    }
    
    hc := &HybridCracker{
        config:      config,
        store:       store,
        wordlist:    wm,
        rules:       re,
        incremental: ig,
        mask:        ma,
        prince:      pr,
        loopback:    lb,
        markov:      mc,
        distributed: dn,
        cpuWorkers:  config.MaxWorkers,
        ctx:         ctx,
        cancel:      cancel,
        batchChan:   make(chan []string, 100),
        resultChan:  make(chan *Hash, 1000),
        wordChan:    make(chan string, 10000),
        stats: CrackerStats{
            StartTime: time.Now(),
            BatchSize: 1000,
        },
    }
    
    if config.UseGPU && !config.ForceCPU {
        gpuCtx, _ := context.WithCancel(ctx)
        hc.gpu = NewGPUCracker(gpuCtx)
    }
    
    return hc, nil
}

func (hc *HybridCracker) Start() {
    gpuAvailable := hc.gpu != nil && hc.gpu.Available
    
    color.Cyan("\n[🚀] Starting ZJohn The Ripper v2.0")
    color.Cyan("[📊] Target: %d hashes", hc.store.Total)
    
    if gpuAvailable {
        color.Green("[🎮] GPU ACCELERATED: %s", hc.gpu.GPUInfo.Name)
    } else {
        color.Yellow("[💻] CPU MODE: %d cores", runtime.NumCPU())
    }
    
    color.Cyan("\n[🔧] Attack Modes:")
    if hc.wordlist != nil {
        color.White("  • Wordlist: %s (%d words)", hc.config.Wordlist, hc.wordlist.lines)
    }
    if hc.rules != nil && len(hc.rules.rules) > 0 {
        color.White("  • Rules: %d rules", len(hc.rules.rules))
    }
    if hc.incremental != nil {
        color.White("  • Incremental: %d-%d chars", hc.config.IncrementalMin, hc.config.IncrementalMax)
    }
    if hc.mask != nil {
        color.White("  • Mask: %s", hc.config.MaskPattern)
    }
    
    totalAttempts := hc.calculateTotalAttempts()
    color.Cyan("\n[⚡] Total combinations: %s", formatNumber(totalAttempts))
    
    bar := progressbar.NewOptions64(
        totalAttempts,
        progressbar.OptionSetDescription("Cracking"),
        progressbar.OptionShowCount(),
        progressbar.OptionShowIts(),
        progressbar.OptionSetTheme(progressbar.Theme{
            Saucer:        "=",
            SaucerHead:    ">",
            SaucerPadding: " ",
            BarStart:      "[",
            BarEnd:        "]",
        }),
    )
    
    for i := 0; i < hc.cpuWorkers; i++ {
        hc.wg.Add(1)
        go hc.worker(i, bar)
    }
    
    go hc.processResults()
    go hc.monitor()
    go hc.feedGenerator()
    
    hc.wg.Wait()
    close(hc.resultChan)
    
    bar.Finish()
    hc.printFinalStats()
}

func (hc *HybridCracker) worker(id int, bar *progressbar.ProgressBar) {
    defer hc.wg.Done()
    
    for {
        select {
        case <-hc.ctx.Done():
            return
        case words, ok := <-hc.batchChan:
            if !ok {
                return
            }
            hc.processBatch(words, bar)
        }
    }
}

func (hc *HybridCracker) processBatch(words []string, bar *progressbar.ProgressBar) {
    uncracked := hc.getUncrackedHashes()
    if len(uncracked) == 0 {
        return
    }
    
    for _, hash := range uncracked {
        if hash.Cracked {
            continue
        }
        
        if pwd, ok := hc.store.CheckCache(hash.RawHash); ok {
            hc.store.MarkCracked(hash, pwd, 0)
            atomic.AddInt64(&hc.stats.CacheHits, 1)
            continue
        }
        
        start := time.Now()
        for _, word := range words {
            atomic.AddInt64(&hc.stats.Attempts, 1)
            bar.Add(1)
            
            if hash.Format.VerifyFunc(word, hash.RawHash) {
                hc.store.MarkCracked(hash, word, time.Since(start))
                hc.resultChan <- hash
                atomic.AddInt64(&hc.stats.Cracked, 1)
                break
            }
            
            if hc.rules != nil {
                for _, variant := range hc.rules.Apply(word) {
                    atomic.AddInt64(&hc.stats.Attempts, 1)
                    atomic.AddInt64(&hc.stats.RulesApplied, 1)
                    bar.Add(1)
                    
                    if hash.Format.VerifyFunc(variant, hash.RawHash) {
                        hc.store.MarkCracked(hash, variant, time.Since(start))
                        hc.resultChan <- hash
                        atomic.AddInt64(&hc.stats.Cracked, 1)
                        break
                    }
                }
            }
        }
    }
}

func (hc *HybridCracker) feedGenerator() {
    if hc.wordlist != nil {
        hc.wordlist.Reset()
        for {
            batch, err := hc.wordlist.NextBatch(hc.stats.BatchSize)
            if err != nil {
                break
            }
            select {
            case <-hc.ctx.Done():
                return
            case hc.batchChan <- batch:
            }
        }
    }
    
    if hc.prince != nil {
        for word := range hc.prince.Generate() {
            select {
            case <-hc.ctx.Done():
                return
            case hc.wordChan <- word:
            }
        }
    }
    
    if hc.mask != nil {
        for {
            word, ok := hc.mask.Next()
            if !ok {
                break
            }
            select {
            case <-hc.ctx.Done():
                return
            case hc.wordChan <- word:
            }
        }
    }
    
    if hc.loopback != nil {
        for word := range hc.loopback.Generate(hc.rules) {
            select {
            case <-hc.ctx.Done():
                return
            case hc.wordChan <- word:
            }
        }
    }
    
    if hc.markov != nil {
        for word := range hc.markov.Generate(hc.config.IncrementalMax) {
            select {
            case <-hc.ctx.Done():
                return
            case hc.wordChan <- word:
            }
        }
    }
    
    if hc.incremental != nil {
        for {
            word, ok := hc.incremental.Next()
            if !ok {
                break
            }
            select {
            case <-hc.ctx.Done():
                return
            case hc.wordChan <- word:
            }
        }
    }
    
    close(hc.batchChan)
}

func (hc *HybridCracker) processResults() {
    for hash := range hc.resultChan {
        if hc.config.ShowCracked {
            color.Green("\n[✅] CRACKED: %s -> %s", 
                truncateString(hash.RawHash, 16), 
                hash.Password)
        }
        
        if hc.loopback != nil {
            hc.loopback.AddCracked(hash.Password)
        }
        
        if hc.store.Cracked >= hc.store.Total {
            hc.Stop()
            return
        }
    }
}

func (hc *HybridCracker) monitor() {
    ticker := time.NewTicker(2 * time.Second)
    defer ticker.Stop()
    
    lastAttempts := int64(0)
    lastTime := time.Now()
    
    for {
        select {
        case <-hc.ctx.Done():
            return
        case <-ticker.C:
            now := time.Now()
            elapsed := now.Sub(lastTime).Seconds()
            attempts := atomic.LoadInt64(&hc.stats.Attempts)
            
            if elapsed > 0 {
                speed := float64(attempts-lastAttempts) / elapsed
                hc.stats.Speed = speed
            }
            
            lastAttempts = attempts
            lastTime = now
            
            hc.updateProgress()
        }
    }
}

func (hc *HybridCracker) updateProgress() {
    fmt.Print("\033[2K\r")
    
    elapsed := time.Since(hc.stats.StartTime)
    
    color.Cyan("[📊] Speed: %s/s | Time: %s | Attempts: %s | Cracked: %d/%d (%.1f%%)",
        formatNumber(int64(hc.stats.Speed)),
        formatDuration(elapsed),
        formatNumber(hc.stats.Attempts),
        hc.stats.Cracked,
        hc.store.Total,
        float64(hc.stats.Cracked)/float64(hc.store.Total)*100,
    )
}

func (hc *HybridCracker) getUncrackedHashes() []*Hash {
    hc.mu.Lock()
    defer hc.mu.Unlock()
    
    uncracked := make([]*Hash, 0)
    for _, hash := range hc.store.Hashes {
        if !hash.Cracked {
            uncracked = append(uncracked, hash)
        }
    }
    return uncracked
}

func (hc *HybridCracker) calculateTotalAttempts() int64 {
    var total int64
    
    if hc.wordlist != nil {
        total += hc.wordlist.lines
        if hc.rules != nil {
            total *= int64(len(hc.rules.rules) + 1)
        }
    }
    
    if hc.incremental != nil {
        total += hc.incremental.total
    }
    
    if hc.mask != nil {
        total += hc.mask.total
    }
    
    if hc.prince != nil {
        total += int64(len(hc.prince.words) * 50)
    }
    
    return total
}

func (hc *HybridCracker) Stop() {
    hc.cancel()
    if hc.gpu != nil {
        hc.gpu.Stop()
    }
    if hc.distributed != nil {
        hc.distributed.Stop()
    }
}

func (hc *HybridCracker) printFinalStats() {
    color.Green("\n" + strings.Repeat("=", 60))
    color.Green("🎉 CRACKING COMPLETE!")
    color.Green(strings.Repeat("=", 60))
    
    elapsed := time.Since(hc.stats.StartTime)
    color.Cyan("Time: %s", formatDuration(elapsed))
    color.Cyan("Attempts: %s", formatNumber(hc.stats.Attempts))
    color.Cyan("Speed: %s/s", formatNumber(int64(hc.stats.Speed)))
    color.Cyan("Cracked: %d/%d (%.1f%%)", 
        hc.stats.Cracked, 
        hc.store.Total, 
        float64(hc.stats.Cracked)/float64(hc.store.Total)*100)
}

// ========== HASH LOADER ==========
func LoadHashes(filename string, store *HashStore) error {
    file, err := os.Open(filename)
    if err != nil {
        return err
    }
    defer file.Close()
    
    scanner := bufio.NewScanner(file)
    lineNum := 0
    
    for scanner.Scan() {
        lineNum++
        line := strings.TrimSpace(scanner.Text())
        if line == "" || strings.HasPrefix(line, "#") {
            continue
        }
        
        hash := &Hash{
            RawHash: line,
            Line:    lineNum,
            File:    filename,
            Extra:   make(map[string]string),
        }
        
        if strings.Contains(line, ":") {
            parts := strings.SplitN(line, ":", 2)
            hash.Username = parts[0]
            hash.RawHash = parts[1]
        }
        
        for i := range HashFormats {
            if HashFormats[i].IsValid(hash.RawHash) {
                hash.Format = &HashFormats[i]
                break
            }
        }
        
        store.AddHash(hash)
    }
    
    return scanner.Err()
}

// ========== REPORT GENERATOR ==========
type ReportGenerator struct {
    outputDir string
    store     *HashStore
    config    Config
}

func NewReportGenerator(outputDir string, store *HashStore, config Config) *ReportGenerator {
    os.MkdirAll(outputDir, 0755)
    return &ReportGenerator{
        outputDir: outputDir,
        store:     store,
        config:    config,
    }
}

func (rg *ReportGenerator) Generate() error {
    timestamp := time.Now().Format("20060102_150405")
    
    csvFile := filepath.Join(rg.outputDir, fmt.Sprintf("cracked_%s.csv", timestamp))
    if err := rg.generateCSV(csvFile); err != nil {
        return err
    }
    
    crackedFile := filepath.Join(rg.outputDir, "cracked.txt")
    if err := rg.generateCracked(crackedFile); err != nil {
        return err
    }
    
    color.Green("\n[✓] Reports generated in %s", rg.outputDir)
    return nil
}

func (rg *ReportGenerator) generateCSV(filename string) error {
    file, err := os.Create(filename)
    if err != nil {
        return err
    }
    defer file.Close()
    
    writer := csv.NewWriter(file)
    defer writer.Flush()
    
    writer.Write([]string{"Hash", "Password", "Format", "Username", "Time"})
    
    for _, hash := range rg.store.Hashes {
        if hash.Cracked {
            writer.Write([]string{
                hash.RawHash,
                hash.Password,
                hash.Format.Name,
                hash.Username,
                hash.CrackTime.String(),
            })
        }
    }
    
    return nil
}

func (rg *ReportGenerator) generateCracked(filename string) error {
    file, err := os.Create(filename)
    if err != nil {
        return err
    }
    defer file.Close()
    
    for _, hash := range rg.store.Hashes {
        if hash.Cracked {
            if hash.Username != "" {
                fmt.Fprintf(file, "%s:%s\n", hash.Username, hash.Password)
            } else {
                fmt.Fprintf(file, "%s:%s\n", hash.RawHash, hash.Password)
            }
        }
    }
    
    return nil
}

// ========== CLI ==========
type CLI struct {
    config  Config
    store   *HashStore
    cracker *HybridCracker
    gpuInfo GPUInfo
    running bool
}

func NewCLI() *CLI {
    return &CLI{
        config:  DefaultConfig,
        store:   NewHashStore(),
        gpuInfo: DetectGPU(),
        running: true,
    }
}

func (c *CLI) PrintBanner() {
    banner := `
╔══════════════════════════════════════════════════════════════════════════════╗
║                    ZJohn The Ripper v1.0 - STABLE EDITION                   ║
║             Ultimate Hybrid Password Cracker - GPU/CPU/Distributed          ║
║                             Create by @GolDer409                            ║
╚══════════════════════════════════════════════════════════════════════════════╝
`
    color.Red(banner)
    
    if c.gpuInfo.Available && !c.config.ForceCPU {
        color.Green("\n[🎮] GPU DETECTED: %s", c.gpuInfo.Name)
    } else {
        color.Yellow("\n[💻] CPU MODE: %d cores", runtime.NumCPU())
    }
}

func (c *CLI) PrintMenu() {
    color.Cyan("\n" + strings.Repeat("=", 60))
    color.White("[1] Crack Hashes (Wordlist + Rules)")
    color.White("[2] Crack Hashes (Incremental/Brute Force)")
    color.White("[3] Crack Hashes (Mask Attack)")
    color.White("[4] Load Hash File")
    color.White("[5] Show Statistics")
    color.White("[6] Show Cracked Passwords")
    color.White("[7] Run Benchmark")
    color.White("[8] Generate Report")
    color.White("[9] GPU/CPU Information")
    color.White("[0] Exit")
    color.Cyan(strings.Repeat("=", 60))
}

func (c *CLI) Run() {
    scanner := bufio.NewScanner(os.Stdin)
    
    for c.running {
        c.ClearScreen()
        c.PrintBanner()
        c.PrintMenu()
        
        fmt.Print(color.YellowString("\n[?] Select: "))
        scanner.Scan()
        choice := strings.TrimSpace(scanner.Text())
        
        switch choice {
        case "1":
            c.crackWordlist(scanner)
        case "2":
            c.crackIncremental(scanner)
        case "3":
            c.crackMask(scanner)
        case "4":
            c.loadHashFile(scanner)
        case "5":
            c.showStats(scanner)
        case "6":
            c.showCracked(scanner)
        case "7":
            c.runBenchmark(scanner)
        case "8":
            c.generateReport(scanner)
        case "9":
            c.showGPUInfo(scanner)
        case "0":
            color.Green("\nGoodbye! 👋")
            c.running = false
        default:
            color.Red("[!] Invalid choice!")
            time.Sleep(1 * time.Second)
        }
    }
}

func (c *CLI) crackWordlist(scanner *bufio.Scanner) {
    color.Cyan("\n[ WORDLIST MODE ]")
    
    if c.store.Total == 0 {
        color.Yellow("[!] No hashes loaded")
        fmt.Print("\nPress Enter...")
        scanner.Scan()
        return
    }
    
    fmt.Print(color.YellowString("[?] Wordlist: "))
    scanner.Scan()
    wordlist := strings.TrimSpace(scanner.Text())
    if wordlist == "" {
        wordlist = "wordlist.txt"
    }
    
    fmt.Print(color.YellowString("[?] Rules file (optional): "))
    scanner.Scan()
    rulesFile := strings.TrimSpace(scanner.Text())
    
    c.config.Wordlist = wordlist
    c.config.RulesFile = rulesFile
    c.config.Incremental = false
    c.config.MaskMode = false
    
    var err error
    c.cracker, err = NewHybridCracker(c.config, c.store)
    if err != nil {
        color.Red("[✗] Failed: %v", err)
        return
    }
    
    c.cracker.Start()
    
    fmt.Print("\nPress Enter...")
    scanner.Scan()
}

func (c *CLI) crackIncremental(scanner *bufio.Scanner) {
    color.Cyan("\n[ INCREMENTAL MODE ]")
    
    if c.store.Total == 0 {
        color.Yellow("[!] No hashes loaded")
        fmt.Print("\nPress Enter...")
        scanner.Scan()
        return
    }
    
    fmt.Print(color.YellowString("[?] Min length [1]: "))
    scanner.Scan()
    minStr := strings.TrimSpace(scanner.Text())
    if minStr != "" {
        c.config.IncrementalMin, _ = strconv.Atoi(minStr)
    }
    
    fmt.Print(color.YellowString("[?] Max length [4]: "))
    scanner.Scan()
    maxStr := strings.TrimSpace(scanner.Text())
    if maxStr != "" {
        c.config.IncrementalMax, _ = strconv.Atoi(maxStr)
    }
    
    c.config.Incremental = true
    c.config.Wordlist = ""
    c.config.RulesFile = ""
    c.config.MaskMode = false
    
    var err error
    c.cracker, err = NewHybridCracker(c.config, c.store)
    if err != nil {
        color.Red("[✗] Failed: %v", err)
        return
    }
    
    c.cracker.Start()
    
    fmt.Print("\nPress Enter...")
    scanner.Scan()
}

func (c *CLI) crackMask(scanner *bufio.Scanner) {
    color.Cyan("\n[ MASK MODE ]")
    
    if c.store.Total == 0 {
        color.Yellow("[!] No hashes loaded")
        fmt.Print("\nPress Enter...")
        scanner.Scan()
        return
    }
    
    fmt.Print(color.YellowString("[?] Mask pattern [?l?l?l?d?d?d]: "))
    scanner.Scan()
    pattern := strings.TrimSpace(scanner.Text())
    if pattern == "" {
        pattern = "?l?l?l?d?d?d"
    }
    
    c.config.MaskMode = true
    c.config.MaskPattern = pattern
    c.config.Incremental = false
    c.config.Wordlist = ""
    
    var err error
    c.cracker, err = NewHybridCracker(c.config, c.store)
    if err != nil {
        color.Red("[✗] Failed: %v", err)
        return
    }
    
    c.cracker.Start()
    
    fmt.Print("\nPress Enter...")
    scanner.Scan()
}

func (c *CLI) loadHashFile(scanner *bufio.Scanner) {
    color.Cyan("\n[ LOAD HASH FILE ]")
    
    fmt.Print(color.YellowString("[?] Hash file: "))
    scanner.Scan()
    hashFile := strings.TrimSpace(scanner.Text())
    if hashFile == "" {
        hashFile = "hashes.txt"
    }
    
    if err := LoadHashes(hashFile, c.store); err != nil {
        color.Red("[✗] Failed: %v", err)
        return
    }
    
    color.Green("\n[✓] Loaded %d hashes", c.store.Total)
    fmt.Print("\nPress Enter...")
    scanner.Scan()
}

func (c *CLI) showStats(scanner *bufio.Scanner) {
    color.Cyan("\n[ STATISTICS ]")
    
    if c.store.Total == 0 {
        color.Yellow("[!] No hashes")
        fmt.Print("\nPress Enter...")
        scanner.Scan()
        return
    }
    
    stats := c.store.GetStats()
    
    color.White("\nTotal: %d", stats["total"])
    color.White("Cracked: %d", stats["cracked"])
    color.White("Remaining: %d", stats["remaining"])
    color.White("Success: %.1f%%", stats["percentage"])
    color.White("Cache hits: %d", stats["cache_hits"])
    
    fmt.Print("\nPress Enter...")
    scanner.Scan()
}

func (c *CLI) showCracked(scanner *bufio.Scanner) {
    color.Cyan("\n[ CRACKED ]")
    
    if c.store.Cracked == 0 {
        color.Yellow("[!] No cracked passwords")
        fmt.Print("\nPress Enter...")
        scanner.Scan()
        return
    }
    
    for _, hash := range c.store.Hashes {
        if hash.Cracked {
            color.Green("%s -> %s", truncateString(hash.RawHash, 16), hash.Password)
        }
    }
    
    fmt.Print("\nPress Enter...")
    scanner.Scan()
}

func (c *CLI) runBenchmark(scanner *bufio.Scanner) {
    color.Cyan("\n[ BENCHMARK ]")
    
    testPassword := "password123"
    iterations := 100000
    
    for _, format := range HashFormats {
        start := time.Now()
        for i := 0; i < iterations; i++ {
            format.HashFunc(testPassword)
        }
        elapsed := time.Since(start)
        speed := float64(iterations) / elapsed.Seconds()
        color.White("%-10s: %.0f/sec", format.Name, speed)
    }
    
    fmt.Print("\nPress Enter...")
    scanner.Scan()
}

func (c *CLI) generateReport(scanner *bufio.Scanner) {
    color.Cyan("\n[ GENERATE REPORT ]")
    
    if c.store.Total == 0 {
        color.Yellow("[!] No hashes")
        fmt.Print("\nPress Enter...")
        scanner.Scan()
        return
    }
    
    reporter := NewReportGenerator("reports", c.store, c.config)
    if err := reporter.Generate(); err != nil {
        color.Red("[✗] Failed: %v", err)
    }
    
    fmt.Print("\nPress Enter...")
    scanner.Scan()
}

func (c *CLI) showGPUInfo(scanner *bufio.Scanner) {
    color.Cyan("\n[ GPU/CPU INFO ]")
    
    if c.gpuInfo.Available {
        color.Green("GPU: %s %s", c.gpuInfo.Vendor, c.gpuInfo.Name)
        color.White("Memory: %d MB", c.gpuInfo.Memory)
    } else {
        color.Yellow("No GPU detected")
    }
    
    color.White("CPU Cores: %d", runtime.NumCPU())
    color.White("OS: %s/%s", runtime.GOOS, runtime.GOARCH)
    
    fmt.Print("\nPress Enter...")
    scanner.Scan()
}

func (c *CLI) ClearScreen() {
    cmd := exec.Command("clear")
    cmd.Stdout = os.Stdout
    cmd.Run()
}

// ========== UTILITY FUNCTIONS ==========
func isHex(s string) bool {
    for _, c := range s {
        if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
            return false
        }
    }
    return true
}

func formatNumber(n int64) string {
    if n < 1000 {
        return strconv.FormatInt(n, 10)
    }
    if n < 1000000 {
        return fmt.Sprintf("%.1fK", float64(n)/1000)
    }
    if n < 1000000000 {
        return fmt.Sprintf("%.1fM", float64(n)/1000000)
    }
    return fmt.Sprintf("%.1fB", float64(n)/1000000000)
}

func formatDuration(d time.Duration) string {
    if d < time.Second {
        return fmt.Sprintf("%dms", d.Milliseconds())
    }
    if d < time.Minute {
        return fmt.Sprintf("%.1fs", d.Seconds())
    }
    if d < time.Hour {
        return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
    }
    return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
}

func truncateString(s string, n int) string {
    if len(s) <= n {
        return s
    }
    return s[:n] + "..."
}

func randInt(min, max int) int {
    if max <= min {
        return min
    }
    return min + int(time.Now().UnixNano())%(max-min)
}

// ========== MAIN ==========
func main() {
    runtime.GOMAXPROCS(runtime.NumCPU())
    
    cli := NewCLI()
    cli.Run()
}
