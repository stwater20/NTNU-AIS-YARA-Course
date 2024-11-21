rule DetectSuspiciousURLs {
    meta:
        description = "Detects suspicious URLs in files"
        author = "Sheng-Shan Chen"
        date = "2024-11-21"
        severity = "high"
        warning = "This rule detects URLs related to known suspicious sites"

    strings:
        $url = /https?:\/\/[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,6}(\/[^\s]*)?/ 
        $sec_web = "sectools.tw"

    condition:
        $url or $sec_web
}
