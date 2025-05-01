rule Ransomware_Generic_Strings
{
    meta:
        description = "Detects generic ransomware ransom note strings"
        author = "Code Copilot"
        date = "2025-04-26"
    strings:
        $ransom1 = "Your files have been encrypted"
        $ransom2 = "decrypt your files"
        $ransom3 = "bitcoin address"
        $ransom4 = "ransom note"
        $ransom5 = "contact us to get the decryption key"
    condition:
        any of them
}

rule Ransomware_Suspicious_Extensions
{
    meta:
        description = "Detects files commonly dropped by ransomware"
        author = "Code Copilot"
        date = "2025-04-26"
    strings:
        $ext1 = ".locked"
        $ext2 = ".enc"
        $ext3 = ".crypted"
        $ext4 = ".ransom"
        $ext5 = ".payfast"
    condition:
        any of them
}

rule Ransomware_Known_Signatures
{
    meta:
        description = "Detects specific hardcoded ransomware signatures"
        author = "Code Copilot"
        date = "2025-04-26"
    strings:
        $sig1 = "Cerber"
        $sig2 = "Locky"
        $sig3 = "Wannacry"
        $sig4 = "Petya"
        $sig5 = "CryptoLocker"
    condition:
        any of them
}
