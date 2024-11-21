rule Misc_Suspicious_Strings {
    meta:
        description = "Misc. suspicious strings"
        version = "0.1"
    strings:
        $s1 = "backdoor" nocase ascii wide
        $s2 = "virus" nocase ascii wide fullword
        $s3 = "hack" nocase ascii wide fullword
        $s4 = "exploit" nocase ascii wide
    condition:
        any of them
}
