# ============================================================
#  stun_scanner.ps1
#  Live WebRTC/STUN capture — extracts PEER IPs in real time,
#  auto-skips STUN servers and XOR-MAPPED-ADDRESS (your own
#  public IP), then queries ipinfo.io for each new peer found.
#
#  Usage:
#    .\stun_scanner.ps1 [OPTIONS]
#
#  Options:
#    -Interface  <id|name>   TShark interface index or name  (default: 1)
#    -ExclFile   <path>      Exclusion list (.txt or .json)  (optional)
#    -Duration   <sec>       Auto-stop after N seconds       (default: 0 = forever)
#    -Help                   Show this help
#
#  Exclusion file formats
#  ──────────────────────
#  TXT  — one IP or prefix per line; lines starting with # are comments
#    # Google STUN servers
#    74.125.
#    8.8.8.8
#
#  JSON — array under the key "excluded"
#    { "excluded": ["74.125.", "8.8.8.8"] }
# ============================================================

param(
    [string]$Interface = "1",
    [string]$ExclFile  = "",
    [int]   $Duration  = 0,
    [switch]$Help
)

# ── Help ─────────────────────────────────────────────────────
if ($Help) {
    Write-Host @"
stun_scanner.ps1 — Live WebRTC peer IP extractor + ipinfo lookup

if powershell blocks execution, run : 
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned

Usage:
  .\stun_scanner.ps1 [OPTIONS]

Options:
  -Interface <id|name>   TShark interface index or name   (default: 1)
  -ExclFile  <path>      Exclusion list (.txt or .json)   (optional)
  -Duration  <sec>       Auto-stop after N seconds        (default: 0 = unlimited)
  -Help                  Show this help

How exclusions work (layered):
  1. Built-in : all private/loopback/multicast ranges — always applied
  2. File     : your -ExclFile entries (prefixes or exact IPs)
  3. Auto     : XOR-MAPPED-ADDRESS = your own public IP   -> excluded
  4. Auto     : destination of your first STUN packet     -> STUN server, excluded

Exclusion file — TXT:
  # comment
  74.125.         <- prefix match (entire range)
  8.8.8.8         <- exact match

Exclusion file — JSON:
  { "excluded": ["74.125.", "8.8.8.8"] }

Tip — list your TShark interfaces:
  tshark -D
"@
    exit 0
}

# ── Colour helpers ────────────────────────────────────────────
function Write-Color {
    param([string]$Text, [ConsoleColor]$Color = [ConsoleColor]::White)
    $prev = [Console]::ForegroundColor
    [Console]::ForegroundColor = $Color
    Write-Host $Text
    [Console]::ForegroundColor = $prev
}

function Log  ($msg) { Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $msg" -ForegroundColor Cyan }
function Ok   ($msg) { Write-Host "[+] $msg" -ForegroundColor Green }
function Warn  ($msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }
function Err  ($msg) { Write-Host "[-] $msg" -ForegroundColor Red }

# ── Built-in exclusions ───────────────────────────────────────
$BuiltinExcluded = @(
    "0.0.0.0",
    "127.",
    "10.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.",
    "169.254.",
    "224.", "225.", "226.", "227.", "228.", "229.",
    "230.", "231.", "232.", "233.", "234.", "235.",
    "255.255.255.255",
    "::1"
)

# ── Load exclusion file ───────────────────────────────────────
$FileExcluded = @()

if ($ExclFile -ne "") {
    if (-not (Test-Path $ExclFile)) {
        Err "Exclusion file not found: $ExclFile"
        exit 1
    }

    if ($ExclFile -match '\.json$') {
        try {
            $json = Get-Content $ExclFile -Raw | ConvertFrom-Json
            $FileExcluded = $json.excluded
        } catch {
            Err "Failed to parse JSON exclusion file: $_"
            exit 1
        }
    } else {
        # TXT format
        Get-Content $ExclFile | ForEach-Object {
            $line = $_ -replace '#.*', ''   # strip comments
            $line = $line.Trim()
            if ($line -ne "") { $FileExcluded += $line }
        }
    }

    Log "Loaded $($FileExcluded.Count) exclusion entries from: $ExclFile"
}

# Merge all static exclusions
$AllExcluded = $BuiltinExcluded + $FileExcluded

# ── Runtime state ─────────────────────────────────────────────
$SeenPeers    = [System.Collections.Generic.List[string]]::new()
$StunServers  = [System.Collections.Generic.List[string]]::new()
$MyPublicIP   = ""

# ── Dependency check ──────────────────────────────────────────
if (-not (Get-Command tshark -ErrorAction SilentlyContinue)) {
    Err "tshark not found. Download Wireshark (includes tshark): https://www.wireshark.org/download.html"
    exit 1
}

# ── Exclusion helpers ─────────────────────────────────────────
function IsExcluded([string]$ip) {
    foreach ($excl in $AllExcluded) {
        if ($ip.StartsWith($excl)) { return $true }
    }
    if ($MyPublicIP -ne "" -and $ip -eq $MyPublicIP) { return $true }
    if ($StunServers.Contains($ip))                   { return $true }
    return $false
}

function AlreadySeen([string]$ip) {
    return $SeenPeers.Contains($ip)
}

function AlreadyStun([string]$ip) {
    return $StunServers.Contains($ip)
}

# ── IPv4 validation ───────────────────────────────────────────
function IsValidIPv4([string]$ip) {
    return $ip -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
}

# ── ipinfo.io lookup ──────────────────────────────────────────
function Invoke-IPLookup([string]$ip) {
    $SeenPeers.Add($ip)

    Write-Host ""
    Write-Host "[+] Peer found -> " -ForegroundColor Green -NoNewline
    Write-Host $ip -ForegroundColor Yellow

    try {
        # ── the curl equivalent: Invoke-RestMethod calls ipinfo.io ──
        $response = Invoke-RestMethod -Uri "https://ipinfo.io/$ip/json" `
                                      -Method Get `
                                      -TimeoutSec 6 `
                                      -ErrorAction Stop
        # ────────────────────────────────────────────────────────────

        Write-Host "  IP       : $ip"          -ForegroundColor Yellow
        if ($response.bogon -eq $true) {
            Write-Host "  !! BOGON (private/reserved — should not appear here)" -ForegroundColor Red
        }
        if ($response.hostname) { Write-Host "  Hostname : $($response.hostname)" }
        if ($response.org)      { Write-Host "  Org      : $($response.org)" }
        if ($response.city)     { Write-Host "  Location : $($response.city), $($response.region), $($response.country)" }

        Write-Host "  Raw JSON : $($response | ConvertTo-Json -Compress)"
        Write-Host "────────────────────────────────────────────────"

    } catch {
        Warn "ipinfo.io returned no data for $ip ($_)"
    }
}

# ── Banner ────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ╔═════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║   WebRTC / STUN Live Peer IP Scanner    ║" -ForegroundColor Cyan
Write-Host "  ╚═════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Log "Interface        : $Interface"
Log "Exclusion entries: $($AllExcluded.Count)  (built-in + file)"
Log "Auto-stop        : ${Duration}s  (0 = unlimited)"
Log "Waiting for STUN traffic — start your WebRTC call now..."
Write-Host "═══════════════════════════════════════════════" -ForegroundColor Cyan

# ── Build tshark arguments ────────────────────────────────────
$tsharkArgs = @(
    "-i", $Interface,
    "-l",
    "-Y",  "stun",
    "-T",  "fields",
    "-e",  "ip.src",
    "-e",  "ip.dst",
    "-e",  "stun.xor_mapped_address",
    "-e",  "stun.att.ipv4",
    "-E",  "separator=|"
)

if ($Duration -gt 0) {
    $tsharkArgs += @("-a", "duration:$Duration")
}

# ── Launch tshark as a background process ─────────────────────
$psi = [System.Diagnostics.ProcessStartInfo]::new()
$psi.FileName               = (Get-Command tshark).Source
$psi.Arguments              = $tsharkArgs -join " "
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError  = $true
$psi.UseShellExecute        = $false
$psi.CreateNoWindow         = $true

$tsharkProcess = [System.Diagnostics.Process]::Start($psi)

Log "tshark running (PID $($tsharkProcess.Id))"
Write-Host ""

# ── Cleanup on Ctrl+C ─────────────────────────────────────────
$cleanupBlock = {
    Write-Host ""
    Warn "Stopping capture..."
    try { $tsharkProcess.Kill() } catch {}

    Write-Host ""
    Write-Host "══════════════ Session summary ══════════════" -ForegroundColor Cyan
    Write-Host "  My public IP (excluded) : $MyPublicIP"
    Write-Host "  STUN servers (excluded) : $($StunServers.Count)"
    foreach ($s in $StunServers) { Write-Host "    • $s" }
    Write-Host "  Peers discovered        : $($SeenPeers.Count)"
    foreach ($p in $SeenPeers) { Write-Host "    • $p" }
    Write-Host "═════════════════════════════════════════════" -ForegroundColor Cyan
}

# Register Ctrl+C handler
[Console]::TreatControlCAsInput = $false
$null = Register-EngineEvent -SourceIdentifier ([System.Management.Automation.PsEngineEvent]::Exiting) -Action $cleanupBlock

try {
    # ── Main loop — read tshark output line by line ───────────
    while (-not $tsharkProcess.StandardOutput.EndOfStream) {

        $line = $tsharkProcess.StandardOutput.ReadLine()
        if ([string]::IsNullOrWhiteSpace($line)) { continue }

        $parts      = $line -split '\|', 4
        $src        = if ($parts.Count -gt 0) { $parts[0].Trim() } else { "" }
        $dst        = if ($parts.Count -gt 1) { $parts[1].Trim() } else { "" }
        $xorMapped  = if ($parts.Count -gt 2) { $parts[2].Trim() } else { "" }
        $stunAtt    = if ($parts.Count -gt 3) { $parts[3].Trim() } else { "" }

        # ── 1. Capture our own public IP from XOR-MAPPED-ADDRESS ──
        if ($xorMapped -ne "" -and $MyPublicIP -eq "") {
            $MyPublicIP = $xorMapped
            Log "My public IP detected (XOR-MAPPED): $MyPublicIP — excluded"
        }

        # ── 2. Auto-detect STUN server ─────────────────────────
        if ($dst -ne "" -and -not (AlreadyStun $dst)) {
            if ($src -eq $MyPublicIP) {
                $StunServers.Add($dst)
                Log "STUN server identified: $dst — excluded"
            }
        }

        # ── 3. Collect peer IP candidates ──────────────────────
        #   Priority:
        #     • stun.att.ipv4   — explicit mapped/peer-reflexive attribute
        #     • ip.src / ip.dst — actual packet endpoints
        #   xor_mapped is NOT included (= our own IP)
        $candidates = @()
        if ($stunAtt -ne "") { $candidates += $stunAtt }
        if ($src     -ne "") { $candidates += $src }
        if ($dst     -ne "") { $candidates += $dst }

        foreach ($ip in $candidates) {
            if (-not (IsValidIPv4 $ip))  { continue }
            if (IsExcluded  $ip)         { continue }
            if (AlreadySeen $ip)         { continue }

            # New public peer IP found
            Invoke-IPLookup $ip
        }
    }
} finally {
    # tshark exited naturally (duration flag) or loop ended
    try { $tsharkProcess.Kill() } catch {}

    Write-Host ""
    Write-Host "══════════════ Session summary ══════════════" -ForegroundColor Cyan
    Write-Host "  My public IP (excluded) : $MyPublicIP"
    Write-Host "  STUN servers (excluded) : $($StunServers.Count)"
    foreach ($s in $StunServers) { Write-Host "    • $s" }
    Write-Host "  Peers discovered        : $($SeenPeers.Count)"
    foreach ($p in $SeenPeers) { Write-Host "    • $p" }
    Write-Host "═════════════════════════════════════════════" -ForegroundColor Cyan
}