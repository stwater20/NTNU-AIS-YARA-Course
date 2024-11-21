rule lookupip {
    meta:
        description = "External IP lookup sites"
        version = "0.1"
    strings:
        $s1 = "checkip.dyndns.org" nocase
        $s2 = "whatsmyip.org" nocase
        $s3 = "whatsmyipaddress.com" nocase
        $s4 = "getmyip.org" nocase
    condition:
        any of them
}
