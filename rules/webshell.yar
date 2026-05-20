// PHP Webshell & Malware Detection Rules
// Compatible with satpam-agent YARA parser

rule WebShell_PHP_Eval_Encoded {
    meta:
        description = "PHP eval with encoding functions - classic webshell obfuscation"
        severity = "critical"
    strings:
        $s1 = "eval(base64_decode" nocase
        $s2 = "eval(gzinflate" nocase
        $s3 = "eval(gzuncompress" nocase
        $s4 = "eval(str_rot13" nocase
        $s5 = "eval(rawurldecode" nocase
        $s6 = "assert(base64_decode" nocase
    condition:
        any of them
}

rule WebShell_PHP_Remote_Execution {
    meta:
        description = "PHP functions that execute OS commands - direct RCE indicators"
        severity = "critical"
    strings:
        $s1 = "shell_exec(" nocase
        $s2 = "passthru(" nocase
        $s3 = "proc_open(" nocase
        $s4 = "popen(" nocase
        $s5 = "pcntl_exec(" nocase
    condition:
        any of them
}

rule WebShell_PHP_System_UserInput {
    meta:
        description = "System calls with direct user input (GET/POST/REQUEST/COOKIE)"
        severity = "critical"
    strings:
        $s1 = "system($_" nocase
        $s2 = "exec($_" nocase
        $s3 = "passthru($_" nocase
        $s4 = "shell_exec($_" nocase
        $s5 = "assert($_" nocase
    condition:
        any of them
}

rule WebShell_PHP_Obfuscation {
    meta:
        description = "PHP code obfuscation techniques used to hide webshell logic"
        severity = "high"
    strings:
        $s1 = "create_function(" nocase
        $s2 = "call_user_func_array(" nocase
        $s3 = "ReflectionFunction" nocase
        $s4 = "preg_replace_callback(" nocase
    condition:
        any of them
}

rule WebShell_PHP_File_Operations {
    meta:
        description = "Suspicious file write + chmod patterns in PHP"
        severity = "high"
    strings:
        $s1 = "file_put_contents(" nocase
        $s2 = "fwrite(" nocase
        $s3 = "chmod(0777" nocase
        $s4 = "chmod(\"0777" nocase
    condition:
        any of them
}

rule Defacement_Keywords {
    meta:
        description = "Common defacement signature strings"
        severity = "high"
    strings:
        $s1 = "defaced by" nocase
        $s2 = "hacked by" nocase
        $s3 = "owned by" nocase
        $s4 = "pwned by" nocase
        $s5 = "r00t3d by" nocase
        $s6 = "h4ck3d by" nocase
        $s7 = "was here" nocase
        $s8 = "greetz to" nocase
    condition:
        any of them
}

rule Malware_Indonesian_Gambling {
    meta:
        description = "Indonesian gambling SEO spam malware (slot/gacor injections)"
        severity = "high"
    strings:
        $s1 = "slot gacor" nocase
        $s2 = "judi online" nocase
        $s3 = "situs slot" nocase
        $s4 = "agen slot" nocase
        $s5 = "daftar slot" nocase
        $s6 = "link slot" nocase
        $s7 = "slot online" nocase
        $s8 = "togel online" nocase
    condition:
        any of them
}

rule CryptoMiner_Indicators {
    meta:
        description = "Cryptocurrency miner deployment strings"
        severity = "critical"
    strings:
        $s1 = "stratum+tcp" nocase
        $s2 = "xmrig" nocase
        $s3 = "minerd" nocase
        $s4 = "cryptonight" nocase
        $s5 = "coinhive.min.js" nocase
        $s6 = "CoinHive.Anonymous" nocase
        $s7 = "monero" nocase
    condition:
        any of them
}

rule C2_Download_Execute {
    meta:
        description = "Download-and-execute patterns typical of dropper scripts"
        severity = "high"
    strings:
        $s1 = "wget http" nocase
        $s2 = "curl -s http" nocase
        $s3 = "curl -O http" nocase
        $s4 = "base64 -d |" nocase
        $s5 = "bash -i >& /dev/tcp" nocase
        $s6 = "python -c \"import socket" nocase
    condition:
        any of them
}

rule WebShell_Common_Names {
    meta:
        description = "Known webshell filenames/identifiers embedded in scripts"
        severity = "medium"
    strings:
        $s1 = "c99madshell" nocase
        $s2 = "c99shell" nocase
        $s3 = "r57shell" nocase
        $s4 = "WSO Shell" nocase
        $s5 = "b374k" nocase
        $s6 = "indoxploit" nocase
        $s7 = "SimAttacker" nocase
    condition:
        any of them
}

rule WebShell_Hex_Encoded_Eval {
    meta:
        description = "Hex-encoded eval - used to bypass simple string scanners"
        severity = "critical"
    strings:
        $h1 = { 65 76 61 6C 28 62 61 73 65 36 34 5F 64 65 63 6F 64 65 }
        $h2 = { 73 68 65 6C 6C 5F 65 78 65 63 }
    condition:
        any of them
}
