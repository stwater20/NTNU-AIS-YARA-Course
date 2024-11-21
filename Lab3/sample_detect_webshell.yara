rule WebShell {
    meta:
        description = "Search for indication of shell capability"
        version = "0.1"
    strings:
        $c1 = "eval(base64_decode("
        $f1 = "cmd.exe /c"
    condition:
        $c1 or $f1
}