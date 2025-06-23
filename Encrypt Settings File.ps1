### This script encrypts a JSON file containing settings for Windows Package Manager (winget) automatic updates.
### 1: Set the input and output file paths
### 2. Generate key and IV if you dont already have them
### 3. Encrypt text from input file
### 4A. Test read the encrypted file content from url if encrypted string
### 4B. Test read the encrypted file content if saved as an encrypted file

# Function to generate a random AES key and IV, returned as a hashtable
function GenerateEncryptionKey {
    $aes = [System.Security.Cryptography.Aes]::Create()
    return @{
        Key = $aes.Key
        IV  = $aes.IV
    }
}

# Function to encrypt a file's contents and save to a new file
function EncryptFileContent {
    param (
        [string]$InputFile,
        [string]$OutputFile,
        [byte[]]$Key,
        [byte[]]$IV
    )

    $plainText = Get-Content $InputFile -Raw
    $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($plainText)

    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $Key
    $aes.IV = $IV

    $encryptor = $aes.CreateEncryptor()
    $ms = New-Object System.IO.MemoryStream
    $cs = New-Object System.Security.Cryptography.CryptoStream($ms, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)
    $cs.Write($plainBytes, 0, $plainBytes.Length)
    $cs.Close()

    [System.IO.File]::WriteAllBytes($OutputFile, $ms.ToArray())
    Write-Host "Encrypted content written to $OutputFile"
}

# Function to decrypt file contents and return plaintext
function DecryptFileContent {
    param (
        [string]$EncryptedFile,
        [byte[]]$Key,
        [byte[]]$IV
    )

    # Read the encrypted file content
    $cipherBytes = [System.IO.File]::ReadAllBytes($EncryptedFile)
    Write-Host "Cipher bytes size: $($cipherBytes.Length) bytes"

    # Create AES decryption object
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $Key
    $aes.IV = $IV

    # Decrypt the content
    try {
        $decryptor = $aes.CreateDecryptor()
        #$ms = New-Object System.IO.MemoryStream($cipherBytes)
        $ms = [System.IO.MemoryStream]::new($cipherBytes)
        $cs = New-Object System.Security.Cryptography.CryptoStream($ms, $decryptor, [System.Security.Cryptography.CryptoStreamMode]::Read)
        $sr = New-Object System.IO.StreamReader($cs, [System.Text.Encoding]::UTF8)
        $plaintext = $sr.ReadToEnd()
        $sr.Close()
        Write-Host "Decryption successful."
        return $plaintext
    }
    catch {
        Write-Host "Error during decryption: $_"
        return $null
    }
}


# Decrypt the content
function DecryptFromBytes {
    param (
        [byte[]]$CipherBytes,
        [byte[]]$Key,
        [byte[]]$IV
    )

    # Create AES decryption object
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $Key
    $aes.IV = $IV

    try {
        $decryptor = $aes.CreateDecryptor()
        $ms = [System.IO.MemoryStream]::new($CipherBytes)
        $cs = New-Object System.Security.Cryptography.CryptoStream($ms, $decryptor, [System.Security.Cryptography.CryptoStreamMode]::Read)
        $sr = New-Object System.IO.StreamReader($cs, [System.Text.Encoding]::UTF8)
        $plaintext = $sr.ReadToEnd()
        $sr.Close()
        Write-Host "Decryption successful."
        return $plaintext
    }
    catch {
        Write-Host "Error during decryption: $_"
        return $null
    }
}


### 1: Set the input and output file paths

# Path to the JSON file to be encrypted
$inputFilePath = "$((Get-Location).path)\GuiGet Update Settings.json"

# Path to save the encrypted file
$outputFilePath = "$((Get-Location).path)\GuiGet Update Settings Encyrpted.json"

### 2. Generate key and IV if you dont already have them
# If you already have a key and IV, you can skip this step and use your existing
$encryption = GenerateEncryptionKey
$key = $encryption.Key
$iv = $encryption.IV

# key = EXISTING_32_4IVBYTE_ARRAY_KEY E.g. @([byte]161, [byte]52, [byte]181, ...)
# iv = EXISTING_16_BYTE_ARRAY_IV E.g. @([byte]44, [byte]23, [byte]120, ...)

### 3. Encrypt text from input file
EncryptFileContent -InputFile $inputFilePath -OutputFile $outputFilePath -Key $key -IV $iv

### 4A. Test read the encrypted file content from url if encrypted string
# settings_url = ""

# $webClient = New-Object System.Net.WebClient
# $cipherBytes = $webClient.DownloadData($settings_url)

# $decrypted = DecryptFromBytes -CipherBytes $cipherBytes -Key $key -IV $iv
# Write-Output "Decrypted text: \n\n$decrypted"

### 4B. Test read the encrypted file content from url if encrypted file
# $decrypted = DecryptFileContent -EncryptedFile $outputFilePath -Key $key -IV $iv
# Write-Output "Decrypted text: \n\n$decrypted"
