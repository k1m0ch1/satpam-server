// threathunting.yar — Content-based detection from ThreatHunting-Keywords dataset
// Source: https://github.com/mthcht/ThreatHunting-Keywords
//   offensive_tool_keyword.csv
//   C2_category_detection.csv
//   greyware_tool_keyword.csv
//   linux_tag_detection.csv
//
// Rules here match strings that appear INSIDE files (PHP, shell scripts, HTML, JS)
// as opposed to process command-line arguments.

// ─────────────────────────────────────────────────────────────
// Named webshell identifiers
// ─────────────────────────────────────────────────────────────

rule TH_Webshell_HoaxShell {
    meta:
        description = "HoaxShell — PowerShell reverse shell; self-identifies in script body"
        severity = "critical"
        tags = "webshell,c2,powershell"
        mitre = "T1059.001"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
    strings:
        $s1 = "[H,O,A,X,S,H,E,L,L]" nocase
        $s2 = "HOAXSHELL"            nocase
        $s3 = "HoaxShell"
        $s4 = "hoaxshell.py"         nocase
    condition:
        any of them
}

rule TH_Webshell_Godzilla {
    meta:
        description = "Godzilla webshell — Java/PHP C2 manager strings embedded in payload"
        severity = "critical"
        tags = "webshell,c2,java,php"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
    strings:
        $s1 = "Godzilla Webshell"    nocase
        $s2 = "Godzilla-Webshell"    nocase
        $s3 = "GodzillaMemShell"     nocase
        $s4 = "BehinderFilter"       nocase
    condition:
        any of them
}

rule TH_Webshell_ChinaChopper {
    meta:
        description = "China Chopper one-liner — eval(Request) in ASPX / @eval(@base64_decode in PHP"
        severity = "critical"
        tags = "webshell,c2,php,aspx"
        mitre = "T1100"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
    strings:
        $asp1 = "eval(Request.Item"                nocase
        $asp2 = "eval(Request["                    nocase
        $php1 = "@eval(@base64_decode($_POST"      nocase
        $php2 = "@eval(base64_decode($_POST"       nocase
        $php3 = "eval(stripslashes($_POST"         nocase
    condition:
        any of them
}

rule TH_Webshell_ReGeorg_Neo {
    meta:
        description = "reGeorg / Neo-reGeorg SOCKS5 tunnel webshell — status string in servlet"
        severity = "critical"
        tags = "webshell,c2,tunnel"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
    strings:
        $s1 = "Georg says, 'All seems fine'" nocase
        $s2 = "Georg sagt, 'Hier ist alles gut'" nocase
        $s3 = "reGeorg"                           nocase
        $s4 = "Neo-reGeorg"                       nocase
        $s5 = "neoregeorg"                         nocase
    condition:
        any of them
}

rule TH_Webshell_Behinder_IceScorpion {
    meta:
        description = "Behinder / IceScorpion encrypted webshell — default AES key literal"
        severity = "critical"
        tags = "webshell,c2,encrypted"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
    strings:
        $s1 = "Behinder"        nocase
        $s2 = "IceScorpion"     nocase
        $s3 = "e45e329feb5d925b"          // Behinder default AES key (hard-coded in many shells)
        $s4 = "rebeyond"        nocase
    condition:
        any of them
}

rule TH_Webshell_Antak_Nishang {
    meta:
        description = "Antak ASPX webshell from Nishang — self-identifies in source"
        severity = "critical"
        tags = "webshell,aspx,powershell"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
    strings:
        $s1 = "Antak-Webshell"  nocase
        $s2 = "ANTAK WEBSHELL"  nocase
        $s3 = "Nishang"         nocase
    condition:
        any of them
}

rule TH_Webshell_Laudanum {
    meta:
        description = "Laudanum injectable webshell collection — name embedded in payload headers"
        severity = "critical"
        tags = "webshell,multi-platform"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
    strings:
        $s1 = "laudanum"           nocase
        $s2 = "laudanum.net"       nocase
    condition:
        any of them
}

rule TH_Webshell_Weevely {
    meta:
        description = "Weevely — PHP stealth webshell; generates obfuscated stubs"
        severity = "critical"
        tags = "webshell,php"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
    strings:
        $s1 = "weevely"    nocase
        $s2 = "weevely3"   nocase
    condition:
        any of them
}

rule TH_Webshell_OffensiveNotion {
    meta:
        description = "OffensiveNotion — Notion as C2; unique scheduled task and create strings"
        severity = "critical"
        tags = "webshell,c2"
        mitre = "T1071.001"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
    strings:
        $s1 = "OffensiveNotion" nocase
        $s2 = "/tn Notion /tr"  nocase
    condition:
        any of them
}

// ─────────────────────────────────────────────────────────────
// C2 framework / beacon artifacts
// ─────────────────────────────────────────────────────────────

rule TH_C2_CobaltStrike_Artifacts {
    meta:
        description = "Cobalt Strike beacon artifacts embedded in web-accessible files"
        severity = "critical"
        tags = "c2,cobaltstrike"
        mitre = "T1071.001 T1573"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
    strings:
        $s1 = "beacon.dll"          nocase
        $s2 = "beacon64.bin"        nocase
        $s3 = "beacon_win_default"  nocase
        $s4 = ".beacon_keys"        nocase
        $s5 = "cobaltstrike"        nocase
        $s6 = "Benjamin DELPY"      nocase   // mimikatz author string in CS modules
    condition:
        any of them
}

rule TH_C2_Metasploit_Meterpreter {
    meta:
        description = "Metasploit meterpreter / payload references in web files"
        severity = "critical"
        tags = "c2,metasploit"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
    strings:
        $s1 = "msfvenom"     nocase
        $s2 = "meterpreter"  nocase
        $s3 = "MSF_PAYLOAD"  nocase
        $s4 = "4444 meter"   nocase
        $s5 = "4444 shell"   nocase
        $s6 = "payload/cmd"  nocase
        $s7 = "set LHOST"    nocase
        $s8 = "set LPORT"    nocase
    condition:
        any of them
}

// ─────────────────────────────────────────────────────────────
// Reverse shell one-liners embedded in PHP / scripts
// ─────────────────────────────────────────────────────────────

rule TH_ReverseShell_Oneliner {
    meta:
        description = "Classic reverse shell one-liners embedded in PHP or shell scripts on web servers"
        severity = "critical"
        tags = "c2,reverse-shell"
        mitre = "T1059.004"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
    strings:
        $s1 = "bash -i >& /dev/tcp"      nocase
        $s2 = "0<&196;exec 196<>/dev/tcp" nocase
        $s3 = "python -c 'import socket"  nocase
        $s4 = "python3 -c 'import socket" nocase
        $s5 = "perl -e 'use Socket"       nocase
        $s6 = "ruby -rsocket -e"          nocase
        $s7 = "php -r '$sock=fsockopen"   nocase
        $s8 = "nc -e /bin/bash"           nocase
        $s9 = "nc -e /bin/sh"             nocase
        $s10 = "/bin/sh -i >& /dev/tcp"   nocase
    condition:
        any of them
}

// ─────────────────────────────────────────────────────────────
// Python exec / encoded payloads
// ─────────────────────────────────────────────────────────────

rule TH_Python_Encoded_Exec {
    meta:
        description = "Python exec(base64.decode) dropper pattern — from ThreatHunting-Keywords greyware CSV"
        severity = "critical"
        tags = "webshell,python,obfuscation"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
    strings:
        $s1 = "exec(__import__('base64').b64decode" nocase
        $s2 = "exec(base64.b64decode("              nocase
        $s3 = "exec(compile(base64"                 nocase
        $s4 = ",exec(__import__('base64').b64decode" nocase
    condition:
        any of them
}

// ─────────────────────────────────────────────────────────────
// Linux persistence patterns (from greyware_tool_keyword.csv)
// ─────────────────────────────────────────────────────────────

rule TH_Linux_Cron_Persistence {
    meta:
        description = "Netcat reverse shell via cron — persistence backdoor pattern (ThreatHunting-Keywords)"
        severity = "critical"
        tags = "persistence,c2,linux"
        mitre = "T1053"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
    strings:
        $s1 = "crontab cron"    nocase
        $s2 = "-e /bin/bash"    nocase
        $s3 = "/bin/nc"         nocase
        $s4 = "/bin/bash -i"    nocase
    condition:
        2 of them
}

rule TH_Linux_Log_Wipe {
    meta:
        description = "Log clearing commands in uploaded scripts — from ThreatHunting-Keywords linux_tag"
        severity = "high"
        tags = "defense-evasion,linux"
        mitre = "T1070.002"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
    strings:
        $s1 = ">/var/log/syslog"                    nocase
        $s2 = "> /var/log/syslog"                   nocase
        $s3 = "/var/log -type f -exec"               nocase
        $s4 = "truncate -s 0"                        nocase
        $s5 = "echo '' > /var/log/"                  nocase
        $s6 = "history -c"                           nocase
        $s7 = "unset HISTFILE"                       nocase
        $s8 = "export HISTSIZE=0"                    nocase
    condition:
        any of them
}

// ─────────────────────────────────────────────────────────────
// Defense evasion — AMSI / AV bypass markers
// ─────────────────────────────────────────────────────────────

rule TH_AMSI_Bypass_Markers {
    meta:
        description = "AMSI bypass strings embedded in scripts — from ThreatHunting-Keywords greyware CSV"
        severity = "critical"
        tags = "evasion,amsi,powershell"
        mitre = "T1562.001"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
    strings:
        $s1 = "AMSI Bypassed"              nocase
        $s2 = "AmsiBypass"                 nocase
        $s3 = "amsi_disable"               nocase
        $s4 = "Find-AmsiSignatures"        nocase
        $s5 = "Test-ContainsAmsiSignatures" nocase
        $s6 = "am-si-bypass"               nocase
        $s7 = "[+] SUCCESS: AMSI Bypassed" nocase
        $s8 = "amsi.dll"                   nocase
    condition:
        any of them
}

rule TH_AV_Disable_Registry {
    meta:
        description = "Windows Defender / AV disable via registry — from ThreatHunting-Keywords greyware"
        severity = "critical"
        tags = "evasion,windows-defender"
        mitre = "T1562.001"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
    strings:
        $s1 = "DisableAntiSpyware"        nocase
        $s2 = "DisableAntiVirus"          nocase
        $s3 = "DisableRealtimeMonitoring" nocase
        $s4 = "DisableIOAVProtection"     nocase
        $s5 = "DisableBehaviorMonitoring" nocase
        $s6 = "MpEnablePus"               nocase
        $s7 = "sc query WinDefend"        nocase
    condition:
        any of them
}

// ─────────────────────────────────────────────────────────────
// Tunneling services referenced in scripts
// ─────────────────────────────────────────────────────────────

rule TH_Tunnel_Service_References {
    meta:
        description = "Tunneling service domains/strings in scripts — from ThreatHunting-Keywords greyware"
        severity = "high"
        tags = "c2,tunnel"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
    strings:
        $s1 = "sirtunnel"      nocase
        $s2 = "boringproxy"    nocase
        $s3 = "pinggy.io"      nocase
        $s4 = "zrok.io"        nocase
        $s5 = "expose.sh"      nocase
        $s6 = "localhost.run"  nocase
        $s7 = "serveo.net"     nocase
        $s8 = "playit.gg"      nocase
        $s9 = "cloudflared"    nocase
    condition:
        any of them
}

// ─────────────────────────────────────────────────────────────
// Credential dumping artifacts
// ─────────────────────────────────────────────────────────────

rule TH_Credential_Dump_Artifacts {
    meta:
        description = "Credential dump strings embedded in webshell command output or scripts"
        severity = "critical"
        tags = "credential-access"
        mitre = "T1003"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
    strings:
        $s1 = "\\windows\\system32\\config\\SAM"    nocase
        $s2 = "\\windows\\system32\\config\\SYSTEM" nocase
        $s3 = "aad3b435b51404eeaad3b435b51404ee"    // blank NTLM hash constant
        $s4 = "mimikatz"                             nocase
        $s5 = "lsass.exe"                            nocase
        $s6 = "sekurlsa::logonpasswords"             nocase
        $s7 = "Benjamin DELPY"                       nocase
    condition:
        any of them
}

// ─────────────────────────────────────────────────────────────
// Offensive enumeration / exploitation tool markers
// ─────────────────────────────────────────────────────────────

rule TH_Offensive_Tool_Markers {
    meta:
        description = "Offensive tool self-identifying strings found inside uploaded files"
        severity = "high"
        tags = "exploitation,enumeration"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
    strings:
        $s1  = "sqlmap"             nocase
        $s2  = "wfuzz"              nocase
        $s3  = "bettercap"          nocase
        $s4  = "BloodHound"         nocase
        $s5  = "PowerView"          nocase
        $s6  = "SharpHound"         nocase
        $s7  = "linWinPwn"          nocase
        $s8  = "linux-smart-enumeration" nocase
        $s9  = "lse_find_opts"      nocase
        $s10 = "adPEAS"             nocase
        $s11 = "ADRecon"            nocase
        $s12 = "Lazagne"            nocase
        $s13 = "LaZagne"            nocase
        $s14 = "pancake"            nocase
        $s15 = "BackHAck"           nocase
    condition:
        any of them
}

// ─────────────────────────────────────────────────────────────
// Tor / dark web references in web files
// ─────────────────────────────────────────────────────────────

rule TH_Tor_DarkWeb_References {
    meta:
        description = "Tor and dark-web onion addresses referenced in web files — exfil/C2 indicator"
        severity = "high"
        tags = "c2,tor"
        mitre = "T1090"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
    strings:
        $s1 = ".onion"      nocase
        $s2 = "tor2web"     nocase
        $s3 = "torlink"     nocase
        $s4 = "tor.keyring" nocase
        $s5 = "torproject.org" nocase
    condition:
        any of them
}
