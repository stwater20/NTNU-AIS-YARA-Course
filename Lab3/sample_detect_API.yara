rule DetectSuspiciousImports {
    strings:
        $import1 = "ADVAPI32.dll"
    condition:
        $import1 
}
