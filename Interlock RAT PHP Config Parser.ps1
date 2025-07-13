<#
.SYNOPSIS
    Deobfuscates a given Interlock RAT PHP script and extracts embedded IP addresses and domains.

.DESCRIPTION
    This script reads a PHP file that contains strings obfuscated with hexadecimal 
    and octal escape sequences. It first decodes these strings into readable text 
    and then uses regular expressions to find and list all unique IPv4 addresses 
    and domain names found within the deobfuscated content, excluding a 
    predefined list of system-related files and domains.

.PARAMETER Path
    Specifies the path to the obfuscated PHP file. This parameter is mandatory.

.EXAMPLE
    PS C:\> .\Deobfuscate-PhpConfig.ps1 -Path "C:\path\to\your\obfuscated_script.cfg"

#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 0)]
    [string]$Path
)

# This block ensures the script processes input from the pipeline, like from Get-ChildItem.
process {
    try {
        # Check if the file exists
        if (-not (Test-Path -Path $Path -PathType Leaf)) {
            throw "File not found at path: $Path"
        }

        # Read the entire content of the file as a single string
        $content = Get-Content -Path $Path -Raw
    }
    catch {
        Write-Error $_.Exception.Message
        return
    }

    # Deobfuscate hexadecimal and octal escape sequences in a single pass for reliability.
    # The regex looks for either a hex sequence \x## OR an octal sequence \###.
    $deobfuscatedContent = [regex]::Replace($content, '\\x([0-9a-fA-F]{2})|\\([0-7]{1,3})', {
        param($match)
        # Check if the hex group (capture group 1) was matched
        if ($match.Groups[1].Success) {
            $hexValue = $match.Groups[1].Value
            return [char]([System.Convert]::ToInt32($hexValue, 16))
        }
        # Otherwise, the octal group (capture group 2) must have been matched
        else {
            $octalValue = $match.Groups[2].Value
            return [char]([System.Convert]::ToInt32($octalValue, 8))
        }
    })

    # Regex to find both IPv4 addresses and domain names
    $regex = '\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b|[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+'

    # Find all matches for IPs and domains in the deobfuscated content
    $matches = $deobfuscatedContent | Select-String -Pattern $regex -AllMatches | ForEach-Object { $_.Matches.Value }

    # Define a list of specific strings to exclude from the results
    $excludeList = @(
        'rundll32.exe',
        'nodejs.org',
        '3-win-x64.zip',
        'node.exe',
        'Security.Principal.WindowsIdentity',
        'Security.Principal.WindowsPrincipal',
        'Security.Principal.WindowsBuiltInRole',
        'powershell.exe'
    )

    # Filter the matches to exclude items in the list
    $filteredMatches = $matches | Where-Object { $_ -notin $excludeList }

    # Output the unique results in color
    if ($filteredMatches) {
        Write-Host "--- Found IPs and Domains in '$Path' ---" -ForegroundColor Cyan
        
        $uniqueMatches = $filteredMatches | Select-Object -Unique
        $ipRegex = '^\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b$'

        foreach ($match in $uniqueMatches) {
            if ($match -match $ipRegex) {
                Write-Host $match -ForegroundColor Green
            }
            else {
                Write-Host $match -ForegroundColor Magenta
            }
        }
    }
    else {
        Write-Host "No IPs or Domains found in the file: $Path" -ForegroundColor Red
    }
}
