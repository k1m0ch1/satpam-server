// defacement.yar — Comprehensive web defacement detection
// Sources:
//   https://github.com/mthcht/ThreatHunting-Keywords (C2_category_detection.csv)
//   zone-h.org defacement archive analysis
//   Indonesia CERT observations

// ─────────────────────────────────────────────────────────────
// Generic defacement graffiti
// ─────────────────────────────────────────────────────────────

rule Defacement_Graffiti_Generic {
    meta:
        description = "Generic 'hacked/defaced/owned by' attacker signatures"
        severity = "high"
        tags = "defacement"
    strings:
        $s1  = "defaced by"         nocase
        $s2  = "hacked by"          nocase
        $s3  = "owned by"           nocase
        $s4  = "pwned by"           nocase
        $s5  = "cracked by"         nocase
        $s6  = "rooted by"          nocase
        $s7  = "r00ted by"          nocase
        $s8  = "r00t3d by"          nocase
        $s9  = "h4ck3d by"          nocase
        $s10 = "0wned by"           nocase
        $s11 = "0wn3d by"           nocase
        $s12 = "greetz to"          nocase
        $s13 = "greetingz to"       nocase
        $s14 = "shoutout to"        nocase
        $s15 = "was here"           nocase
        $s16 = "l33t hack3r"        nocase
        $s17 = "d3f4c3d"            nocase
        $s18 = "h4ck3d"             nocase
    condition:
        any of them
}

rule Defacement_HTML_Page_Structure {
    meta:
        description = "Defacement page HTML markers — title/comment injection"
        severity = "high"
        tags = "defacement,html"
    strings:
        $t1 = "<title>Hacked"    nocase
        $t2 = "<title>Defaced"   nocase
        $t3 = "<title>Owned"     nocase
        $t4 = "<title>Pwned"     nocase
        $t5 = "<title>0wned"     nocase
        $c1 = "<!-- Hacked by"   nocase
        $c2 = "<!-- Defaced by"  nocase
        $c3 = "<!-- Owned by"    nocase
        $c4 = "<!-- Pwned by"    nocase
    condition:
        any of them
}

// ─────────────────────────────────────────────────────────────
// Named defacement / webshell tools (ThreatHunting-Keywords)
// Source: C2_category_detection.csv, offensive_tool_keyword.csv
// ─────────────────────────────────────────────────────────────

rule Defacement_Tool_KingDefacer {
    meta:
        description = "KingDefacer — named defacement webshell from tennc/webshell collection"
        severity = "critical"
        tags = "defacement,webshell"
        mitre = "T1100 T1059 T1105"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
    strings:
        $s1 = "KingDefacer"  nocase
        $s2 = "King Defacer" nocase
        $s3 = "kingdefac3r"  nocase
    condition:
        any of them
}

rule Defacement_Tool_AntichatShell {
    meta:
        description = "Antichat Shell — Russian defacement webshell (tennc collection)"
        severity = "critical"
        tags = "defacement,webshell"
        mitre = "T1100 T1059 T1105"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
    strings:
        $s1 = "Antichat Shell"  nocase
        $s2 = "antichatshell"   nocase
        $s3 = "antichat.ru"     nocase
    condition:
        any of them
}

rule Defacement_Tool_FaTaLShell {
    meta:
        description = "FaTaL Shell v1.0 — webshell from tennc collection (ThreatHunting-Keywords)"
        severity = "critical"
        tags = "defacement,webshell"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
    strings:
        $s1 = "FaTaL Shell" nocase
        $s2 = "FaTaLsHell"  nocase
    condition:
        any of them
}

rule Defacement_Tool_Locus7_Storm7 {
    meta:
        description = "Locus7Shell / Storm7Shell — defacement webshells (ThreatHunting-Keywords)"
        severity = "critical"
        tags = "defacement,webshell"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
    strings:
        $s1 = "Locus7Shell" nocase
        $s2 = "Locus 7 Shell" nocase
        $s3 = "Storm7Shell"  nocase
        $s4 = "Storm 7 Shell" nocase
    condition:
        any of them
}

rule Defacement_Tool_c99_r57 {
    meta:
        description = "c99madshell / r57shell — classic PHP webshells widely used in defacement"
        severity = "critical"
        tags = "defacement,webshell,php"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
    strings:
        $s1 = "c99madshell"  nocase
        $s2 = "c99shell"     nocase
        $s3 = "c99.php"      nocase
        $s4 = "r57shell"     nocase
        $s5 = "r57.php"      nocase
        $s6 = "FilesMan"     nocase
        $s7 = "IndoXploit"   nocase
    condition:
        any of them
}

rule Defacement_Tool_WSO {
    meta:
        description = "WSO (Web Shell by Orb) — popular PHP webshell used for defacement"
        severity = "critical"
        tags = "defacement,webshell,php"
    strings:
        $s1 = "WSO Shell"    nocase
        $s2 = "wso.php"      nocase
        $s3 = "Web Shell by Orb" nocase
        $s4 = "wso2.php"     nocase
        $s5 = "b374k"        nocase
        $s6 = "b374k.php"    nocase
    condition:
        any of them
}

// ─────────────────────────────────────────────────────────────
// Indonesian hacktivist / defacement groups
// ─────────────────────────────────────────────────────────────

rule Defacement_Indonesian_Hacktivist_Groups {
    meta:
        description = "Known Indonesian hacktivist and defacement group signatures"
        severity = "critical"
        tags = "defacement,indonesian,hacktivist"
    strings:
        $s1  = "Indonesian Hacker"     nocase
        $s2  = "Garuda Defacer"        nocase
        $s3  = "Muslim Cyber Army"     nocase
        $s4  = "Cyber Army Indonesia"  nocase
        $s5  = "AnonGhost Indonesia"   nocase
        $s6  = "Team Defacer Indo"     nocase
        $s7  = "Banten Cyber"          nocase
        $s8  = "Java Security Team"    nocase
        $s9  = "BlackRose Indonesia"   nocase
        $s10 = "GanjaNisasi"           nocase
        $s11 = "Ganja Crew"            nocase
        $s12 = "Indonesia Fighter"     nocase
        $s13 = "Hackers Indonesia"     nocase
        $s14 = "Indonesian Cyber Army" nocase
        $s15 = "Team_Defacer"          nocase
        $s16 = "WayBack DEFACE"        nocase
        $s17 = "D3FACE CREW"           nocase
        $s18 = "TM-DEFACER"            nocase
        $s19 = "Phantom Crew ID"       nocase
        $s20 = "Ghost Crew Indonesia"  nocase
    condition:
        any of them
}

rule Defacement_Indonesian_Gambling_SEO {
    meta:
        description = "Indonesian gambling SEO injection (slot gacor / judi online) — mass defacement for SEO spam"
        severity = "high"
        tags = "defacement,indonesian,seo-spam,gambling"
    strings:
        $s1  = "slot gacor"     nocase
        $s2  = "judi online"    nocase
        $s3  = "situs slot"     nocase
        $s4  = "agen slot"      nocase
        $s5  = "daftar slot"    nocase
        $s6  = "link slot"      nocase
        $s7  = "slot online"    nocase
        $s8  = "togel online"   nocase
        $s9  = "bandar togel"   nocase
        $s10 = "slot terpercaya" nocase
        $s11 = "situs togel"    nocase
        $s12 = "slot88"         nocase
        $s13 = "slot777"        nocase
        $s14 = "pragmatic play"  nocase
        $s15 = "pg soft"        nocase
        $s16 = "bonus new member" nocase
        $s17 = "gacor maxwin"   nocase
        $s18 = "jp maxwin"      nocase
    condition:
        any of them
}

// ─────────────────────────────────────────────────────────────
// International hacktivist groups
// ─────────────────────────────────────────────────────────────

rule Defacement_International_Hacktivist_Groups {
    meta:
        description = "Well-known international hacktivist group signatures from zone-h archive"
        severity = "high"
        tags = "defacement,hacktivist"
    strings:
        $s1  = "AnonGhost"          nocase
        $s2  = "Anonymous #Op"      nocase
        $s3  = "#OpIsrael"          nocase
        $s4  = "#OpISIS"            nocase
        $s5  = "TiGER-M@TE"         nocase
        $s6  = "MaDLeeTs"           nocase
        $s7  = "TeaM_MaDLeeTs"      nocase
        $s8  = "Dr.SaMiR"           nocase
        $s9  = "Th3 D3fac3r"        nocase
        $s10 = "OfficialZero"        nocase
        $s11 = "Ghost Team"          nocase
        $s12 = "Shadow Crew"         nocase
        $s13 = "XtReMiSt"           nocase
        $s14 = "Albanian Hackers"    nocase
        $s15 = "MuhmadEmad"          nocase
        $s16 = "Hmei7"               nocase
        $s17 = "Morocco Black Cyber" nocase
        $s18 = "CapoO_TunisiAno"     nocase
        $s19 = "Moroccan Attacker"   nocase
        $s20 = "Pakistan Cyber Army" nocase
        $s21 = "Brazilian Cyber Army" nocase
        $s22 = "Team Digi7al"        nocase
        $s23 = "Security Geeks"      nocase
        $s24 = "D4RK-MAN"            nocase
        $s25 = "3xp1r3 Cyber Army"   nocase
    condition:
        any of them
}

// ─────────────────────────────────────────────────────────────
// Ransomware-style / extortion notes in web pages
// ─────────────────────────────────────────────────────────────

rule Defacement_Ransomware_Extortion_Note {
    meta:
        description = "Ransomware or extortion notes embedded in defaced pages"
        severity = "critical"
        tags = "defacement,ransomware"
    strings:
        $s1 = "YOUR FILES HAVE BEEN ENCRYPTED"  nocase
        $s2 = "YOUR WEBSITE HAS BEEN HACKED"    nocase
        $s3 = "ALL YOUR FILES BELONG TO US"      nocase
        $s4 = "YOUR DATA HAS BEEN STOLEN"        nocase
        $s5 = "SEND BITCOIN TO"                  nocase
        $s6 = "pay the ransom"                   nocase
        $s7 = "restore your files"               nocase
        $s8 = "contact us to recover"            nocase
        $s9 = "pay in bitcoin"                   nocase
    condition:
        any of them
}
