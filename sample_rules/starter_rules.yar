/*
    YaraForge - Sample Detection Rules
    Use these to populate your rule library and test the scanner.
    Import via the Import/Export page.
*/

rule detect_mimikatz
{
    meta:
        description = "Detects Mimikatz credential dumping tool strings"
        author = "YaraForge"
        category = "infostealer"
        date = "2025-01-01"
        severity = "critical"
        mitre = "T1003"

    strings:
        $s1 = "mimikatz" ascii nocase
        $s2 = "sekurlsa" ascii nocase
        $s3 = "kerberos::list" ascii nocase
        $s4 = "privilege::debug" ascii nocase
        $s5 = "lsadump::sam" ascii nocase

    condition:
        2 of them
}

rule detect_powershell_encoded_command
{
    meta:
        description = "Detects PowerShell encoded command execution patterns"
        author = "YaraForge"
        category = "exploit"
        date = "2025-01-01"
        severity = "high"
        mitre = "T1059.001"

    strings:
        $s1 = "powershell" ascii nocase
        $s2 = "-EncodedCommand" ascii nocase
        $s3 = "-enc " ascii nocase
        $s4 = "FromBase64String" ascii nocase
        $s5 = "[Convert]::" ascii nocase

    condition:
        $s1 and any of ($s2, $s3, $s4, $s5)
}

rule detect_ransomware_indicators
{
    meta:
        description = "Detects common ransomware behavior strings"
        author = "YaraForge"
        category = "ransomware"
        date = "2025-01-01"
        severity = "critical"
        mitre = "T1486"

    strings:
        $ransom1 = "Your files have been encrypted" ascii nocase
        $ransom2 = "bitcoin" ascii nocase
        $ransom3 = "decrypt" ascii nocase
        $ransom4 = ".onion" ascii nocase
        $shadow1 = "vssadmin delete shadows" ascii nocase
        $shadow2 = "wmic shadowcopy delete" ascii nocase
        $recov = "bcdedit /set {default} recoveryenabled no" ascii nocase

    condition:
        2 of ($ransom*) or any of ($shadow*) or $recov
}

rule detect_webshell_generic
{
    meta:
        description = "Detects common webshell patterns in PHP and ASP files"
        author = "YaraForge"
        category = "webshell"
        date = "2025-01-01"
        severity = "high"
        mitre = "T1505.003"

    strings:
        $php1 = "eval($_" ascii
        $php2 = "base64_decode($_" ascii
        $php3 = "system($_" ascii
        $php4 = "passthru(" ascii
        $php5 = "shell_exec(" ascii
        $asp1 = "eval(Request" ascii nocase
        $asp2 = "Execute(Request" ascii nocase
        $asp3 = "CreateObject(\"Wscript.Shell\")" ascii nocase

    condition:
        any of them
}

rule detect_pe_file
{
    meta:
        description = "Identifies Windows PE executable files by magic bytes"
        author = "YaraForge"
        category = "custom"
        date = "2025-01-01"
        severity = "info"

    strings:
        $mz = { 4D 5A }

    condition:
        $mz at 0
}

rule detect_reverse_shell_strings
{
    meta:
        description = "Detects common reverse shell command patterns"
        author = "YaraForge"
        category = "backdoor"
        date = "2025-01-01"
        severity = "high"
        mitre = "T1059"

    strings:
        $bash1 = "/bin/bash -i" ascii
        $bash2 = "bash -c 'bash -i" ascii
        $nc1 = "nc -e /bin" ascii
        $nc2 = "ncat -e /bin" ascii
        $python1 = "socket.socket" ascii
        $python2 = "subprocess.call" ascii
        $python3 = "pty.spawn" ascii
        $ps1 = "New-Object System.Net.Sockets.TCPClient" ascii

    condition:
        2 of them
}
