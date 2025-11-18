/*
   YARA Rule: AsyncRAT Variant Detection
   Author: Tim Forensik Kelompok 6
   Date: 2025-11-15
   Case: FOR-2025-WKS-001
   Description: Deteksi AsyncRAT variant yang ditemukan di FINANCE-WKS-07
*/

rule AsyncRAT_SecurityUpdate_Variant
{
    meta:
        description = "Deteksi AsyncRAT variant yang ditemukan di FINANCE-WKS-07"
        author = "Tim Forensik Kelompok 6"
        date = "2025-11-15"
        severity = "critical"
        reference = "FOR-2025-WKS-001"
        md5 = "a3b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6"
        sha256 = "7a3b9c2f1e8d4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
        
    strings:
        // String indicators
        $str1 = "SecurityUpdate" ascii wide
        $str2 = "WindowsSecurityService" ascii wide
        $str3 = "config.dat" ascii wide
        $str4 = "keylog.txt" ascii wide
        $str5 = "AsyncRAT" ascii wide nocase
        
        // Hex patterns
        $hex1 = { 4D 5A 90 00 03 00 00 00 }  // PE header
        $hex2 = { 89 E5 83 EC 20 }           // Function prologue
        $hex3 = { 68 74 74 70 73 3A 2F 2F }  // "https://"
        
        // API calls suspicious for RAT
        $api1 = "WSAStartup" ascii
        $api2 = "InternetOpenA" ascii
        $api3 = "GetAsyncKeyState" ascii
        $api4 = "CreateServiceA" ascii
        $api5 = "RegSetValueExA" ascii
        $api6 = "GetClipboardData" ascii
        
        // Network indicators
        $net1 = "185.220.101.47" ascii
        $net2 = ":443" ascii
        
    condition:
        uint16(0) == 0x5A4D and                    // PE file
        filesize < 10MB and
        filesize > 1MB and
        (2 of ($str*)) and
        (1 of ($hex*)) and
        (3 of ($api*))
}

rule AsyncRAT_Dropper_Variant
{
    meta:
        description = "Deteksi dropper AsyncRAT (svchost_alt.exe)"
        author = "Tim Forensik Kelompok 6"
        date = "2025-11-15"
        severity = "critical"
        
    strings:
        $str1 = "svchost_alt" ascii wide
        $str2 = "WindowsSecurity" ascii wide
        $str3 = "ProgramData" ascii wide
        
        $api1 = "CreateProcessA" ascii
        $api2 = "VirtualAlloc" ascii
        $api3 = "WriteProcessMemory" ascii
        
    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (2 of ($str*)) and
        (2 of ($api*))
}