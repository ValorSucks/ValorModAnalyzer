# Valor Mod Analyzer - PowerShell Script
# Developed by: DrValor
# Inspiration by: Hadron, TonyNoh, YarpLepstan
# Scans Minecraft mods for suspicious patterns and verifies against known databases

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# ASCII Art Banner
$asciiArt = @"
 _                _ 
   \ \              / / 
    \ \            / / 
     \ \          / / 
      \ \        / / 
       \ \______/ / 
       /          \ 
      /   _    _   \ 
     |   (.)  (.)   | 
     |      /\      | 
      \    '--'    / 
       '----------'
"@

# Display ASCII art with gradient colors
$gradientColors = @("White", "Cyan", "DarkCyan", "Blue", "DarkBlue")

$lines = $asciiArt.Split([System.Environment]::NewLine)
foreach ($line in $lines) {
    # Render the line character by character with a gradient
    if ($line.Trim().Length -gt 0) {
        $colorStep = $line.Length / $gradientColors.Count
        for ($i = 0; $i -lt $line.Length; $i++) {
            $char = $line[$i]
            $colorIndex = [math]::Min([math]::Floor($i / $colorStep), $gradientColors.Count - 1)
            $charColor = $gradientColors[$colorIndex]
            Write-Host -NoNewline $char -ForegroundColor $charColor
        }
    }
    Write-Host
}

Write-Host

# Get mods folder path
$mods = Read-Host "Enter path to the mods folder"
Write-Host

if (-not $mods) {
    $mods = "$env:USERPROFILE\AppData\Roaming\.minecraft\mods"
}

if (-not (Test-Path $mods -PathType Container)) {
    Write-Host "Invalid path: $mods" -ForegroundColor Red
    exit 1
}


# Check Minecraft uptime (silent for HTML report)
$process = Get-Process javaw -ErrorAction SilentlyContinue
if (-not $process) { $process = Get-Process java -ErrorAction SilentlyContinue }

if ($process) {
    try {
        $elapsedTime = (Get-Date) - $process.StartTime
        # Store for HTML report only
    } catch {}
}

# ==================== Fabric AddMods Detector ====================
# Find all javaw.exe processes
$javaProcesses = Get-Process -Name javaw -ErrorAction SilentlyContinue
$minecraftProcessesInfo = @()

if ($javaProcesses.Count -eq 0) {
    # No output, just continue
} else {
    $foundFabricAddMods = $false

    foreach ($proc in $javaProcesses) {
        # Get full command line
        $commandLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)").CommandLine
            
        # Store process info for HTML report
        $processInfo = [PSCustomObject]@{
            ProcessId = $proc.Id
            ProcessName = $proc.Name
            StartTime = $proc.StartTime
            CommandLine = $commandLine
            HasFabricAddMods = $commandLine -match '-Dfabric\.addMods'
            HasJavaAgent = $false
            JavaAgentPath = $null
            IsLegitimateAgent = $false
            LegitimateAgentPath = $null
        }
        $minecraftProcessesInfo += $processInfo
            
        if ($commandLine -match '-Dfabric\.addMods') {
            $foundFabricAddMods = $true
                        
            # Extract the fabric.addMods argument
            if ($commandLine -match '-Dfabric\.addMods=([^\s"]+)') {
                $rawPath = $matches[1]
                
                # Deep clean the extracted path
                $fabricAddModsValue = $rawPath.Trim('"', "'").Trim()              # Remove surrounding quotes and whitespace
                $fabricAddModsValue = $fabricAddModsValue -replace '[\x00-\x1F]', ''  # Remove control chars
                $fabricAddModsValue = $fabricAddModsValue.Trim()                       # Trim whitespace again
                $fabricAddModsValue = $fabricAddModsValue -replace '/', '\'            # Normalize slashes
                $fabricAddModsValue = [Environment]::ExpandEnvironmentVariables($fabricAddModsValue) # Expand env vars
                
                # Silent - no console output
                    
                # Validate path exists using LiteralPath to avoid interpretation issues
                if (-not (Test-Path -LiteralPath $fabricAddModsValue)) {
                    # Silent - store for HTML report only
                } else {
                    try {
                        $item = Get-Item -LiteralPath $fabricAddModsValue -Force -ErrorAction SilentlyContinue
                        
                        # Check if it's a single JAR file
                        if ($item -is [System.IO.FileInfo] -and $item.Extension -eq ".jar") {
                            # Single JAR file - process directly
                            $externalModJars += $item.FullName
                        }
                        # Check if it's a directory containing mods
                        elseif ($item -is [System.IO.DirectoryInfo] -or $item.PSIsContainer) {
                            # Directory containing JARs
                            $externalMods = Get-ChildItem -LiteralPath $fabricAddModsValue -Filter "*.jar" -Force -ErrorAction SilentlyContinue
                            if ($externalMods) {
                                foreach ($extMod in $externalMods) {
                                    $externalModJars += $extMod.FullName
                                }
                            }
                        }
                    } catch {
                        # Silent error handling
                    }
                }
            }
        }
            
        # Check for javaagent arguments
        if ($commandLine -match '-javaagent:([^\s]+)') {
            $javaAgentPath = $matches[1]
                    
            # Update process info
            $processInfo.HasJavaAgent = $true
            $processInfo.JavaAgentPath = $javaAgentPath
                    
            # Check if this is a known legitimate launcher agent
            $isLegitimateAgent = $false
            $legitimateAgentPatterns = @(
                'theseus\.jar',           # Modrinth Launcher agent
                'metadata\.jar',          # Common launcher metadata
                'NewLaunch\.jar'          # Known launcher component
            )
                    
            foreach ($pattern in $legitimateAgentPatterns) {
                if ($javaAgentPath -match $pattern) {
                    $isLegitimateAgent = $true
                    $processInfo.IsLegitimateAgent = $true
                    $processInfo.LegitimateAgentPath = $javaAgentPath
                    break
                }
            }
                    
            if (-not $isLegitimateAgent) {
                        
                # Add javaagent info to process object only for suspicious agents
                $processInfo.HasJavaAgent = $true
                $processInfo.JavaAgentPath = $javaAgentPath
            } else {
                # Mark as legitimate for HTML report
                $processInfo.HasJavaAgent = $false
                $processInfo.JavaAgentPath = $null
                $processInfo.IsLegitimateAgent = $true
                $processInfo.LegitimateAgentPath = $javaAgentPath
            }
        }
            
        # Check for argfile references and scan their contents (silent)
        if ($commandLine -match '@([\w]:\\[^\s]+\.txt|/[^\s]+\.txt)') {
            $argFilePath = $matches[1]
                
            if (Test-Path $argFilePath) {
                try {
                    $argFileContent = Get-Content -Path $argFilePath -Raw -ErrorAction SilentlyContinue
                        
                    # Check for dangerous arguments in argfile
                    if ($argFileContent -match '-Dfabric\.addMods=([^\r\n]+)') {
                        $rawArgfilePath = $matches[1]
                        
                        # Deep clean the extracted path
                        $fabricPathFromArgfile = $rawArgfilePath.Trim('"', "'").Trim()     # Remove surrounding quotes and whitespace
                        $fabricPathFromArgfile = $fabricPathFromArgfile -replace '[\x00-\x1F]', '' # Remove control chars
                        $fabricPathFromArgfile = $fabricPathFromArgfile.Trim()                      # Trim whitespace
                        $fabricPathFromArgfile = $fabricPathFromArgfile -replace '/' , '\'          # Normalize slashes
                        $fabricPathFromArgfile = [Environment]::ExpandEnvironmentVariables($fabricPathFromArgfile) # Expand env vars
                            
                        # Validate path exists using LiteralPath
                        if (-not (Test-Path -LiteralPath $fabricPathFromArgfile)) {
                            # Silent
                        } else {
                            try {
                                $item = Get-Item -LiteralPath $fabricPathFromArgfile -Force -ErrorAction SilentlyContinue
                                
                                # Check if it's a single JAR file
                                if ($item -is [System.IO.FileInfo] -and $item.Extension -eq ".jar") {
                                    # Single JAR file - process directly
                                    $externalModJars += $item.FullName
                                }
                                # Check if it's a directory containing mods
                                elseif ($item -is [System.IO.DirectoryInfo] -or $item.PSIsContainer) {
                                    # Directory containing JARs
                                    $externalMods = Get-ChildItem -LiteralPath $fabricPathFromArgfile -Filter "*.jar" -Force -ErrorAction SilentlyContinue
                                    if ($externalMods) {
                                        foreach ($extMod in $externalMods) {
                                            $externalModJars += $extMod.FullName
                                        }
                                    }
                                }
                            } catch {
                                # Silent error
                            }
                        }
                    }
                        
                    # Check for javaagent in argfile (silent)
                    if ($argFileContent -match '-javaagent:([^\r\n]+)') {
                        $javaAgentFromArgfile = $matches[1]
                    }
                        
                } catch {
                    # Silent error
                }
            } else {
                # Silent - argfile not found
            }
        }
    }

    # No console output
}

# Remove duplicates from external mod JARs (silent)
if ($externalModJars.Count -gt 0) {
    $externalModJars = $externalModJars | Select-Object -Unique
}

# ==================== File Attribute Manipulation Detector ====================
# Silent scan for HTML report

$attributeBypassDetected = $false
$suspiciousAttributeFiles = @()

# Check for files with hidden/system attributes in the mods folder
try {
    $allFiles = Get-ChildItem -Path $mods -Recurse -Force -ErrorAction SilentlyContinue
    
    foreach ($file in $allFiles) {
        $isHidden = $false
        $isSystem = $false
        $isReadOnly = $false
        
        # Check file attributes
        if ($file.Attributes -band [System.IO.FileAttributes]::Hidden) {
            $isHidden = $true
        }
        if ($file.Attributes -band [System.IO.FileAttributes]::System) {
            $isSystem = $true
        }
        if ($file.Attributes -band [System.IO.FileAttributes]::ReadOnly) {
            $isReadOnly = $true
        }
        
        # Flag suspicious attribute combinations
        if ($isHidden -or $isSystem) {
            $suspiciousAttributeFiles += [PSCustomObject]@{
                FileName = $file.Name
                FilePath = $file.FullName
                IsHidden = $isHidden
                IsSystem = $isSystem
                IsReadOnly = $isReadOnly
                Attributes = $file.Attributes.ToString()
                Extension = $file.Extension
            }
            $attributeBypassDetected = $true
        }
    }
    
    # No console output - results in HTML only
} catch {
    # Silent error
}

# Check for Prefetch file manipulation (silent)
$prefetchDir = "$env:SystemRoot\Prefetch"
$protectedPrefetchFound = $false

if (Test-Path $prefetchDir) {
    try {
        $prefetchFiles = Get-ChildItem -Path $prefetchDir -Filter "*.pf" -ErrorAction SilentlyContinue
        
        foreach ($pf in $prefetchFiles) {
            if (($pf.Attributes -band [System.IO.FileAttributes]::ReadOnly) -or 
                ($pf.Attributes -band [System.IO.FileAttributes]::Hidden) -or
                ($pf.Attributes -band [System.IO.FileAttributes]::System)) {
                
                $protectedPrefetchFound = $true
            }
        }
    } catch {
        # Silent error
    }
}

function Get-SHA1($filePath) { return (Get-FileHash -Path $filePath -Algorithm SHA1).Hash }

function Get-ZoneIdentifier($filePath) {
    try {
        if ($ads = Get-Content -Raw -Stream Zone.Identifier $filePath -ErrorAction SilentlyContinue | Where-Object { $_ -match "HostUrl=(.+)" }) {
            $url = $matches[1]
            return @{
                Source = switch -regex ($url) {
                    "modrinth\.com" { "Modrinth"; break }
                    "curseforge\.com" { "CurseForge"; break }
                    "github\.com" { "GitHub"; break }
                    "discord" { "Discord"; break }
                    "mediafire\.com" { "MediaFire"; break }
                    "dropbox\.com" { "Dropbox"; break }
                    "drive\.google\.com" { "Google Drive"; break }
                    "mega\.nz|mega\.co\.nz" { "MEGA"; break }
                    "anydesk\.com" { "AnyDesk"; break }
                    "doomsdayclient\.com" { "DoomsdayClient"; break }
                    "prestigeclient\.vip" { "PrestigeClient"; break }
                    "198macros\.com" { "198Macros"; break }
                    default { 
                        if ($url -match "https?://(?:www\.)?([^/]+)") {
                            $matches[1]
                        } else {
                            "Other"
                        }
                    }
                }
                URL = $url
                IsModrinth = $url -match "modrinth\.com"
            }
        }
    } catch {}
    return @{ Source = "Unknown"; URL = ""; IsModrinth = $false }
}

function Get-Mod-Info-From-Jar($jarPath) {
    $modInfo = @{ ModId = ""; Name = ""; Version = ""; Description = ""; Authors = @(); License = ""; Contact = @{}; Icon = ""; Environment = ""; Entrypoints = @{}; Mixins = @(); AccessWidener = ""; Depends = @{}; Suggests = @{}; Breaks = @{}; Conflicts = @{}; ModLoader = "" }
    
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = [System.IO.Compression.ZipFile]::OpenRead($jarPath)
        
        # Check for fabric.mod.json
        if ($entry = $zip.Entries | Where-Object { $_.Name -eq 'fabric.mod.json' } | Select-Object -First 1) {
            $reader = New-Object System.IO.StreamReader($entry.Open())
            $fabricData = $reader.ReadToEnd() | ConvertFrom-Json
            $reader.Close()
            
            $modInfo.ModId = $fabricData.id; $modInfo.Name = $fabricData.name; $modInfo.Version = $fabricData.version
            $modInfo.Description = $fabricData.description; $modInfo.Authors = if ($fabricData.authors -is [array]) { $fabricData.authors } else { @($fabricData.authors) }
            $modInfo.License = $fabricData.license; $modInfo.Contact = $fabricData.contact; $modInfo.Icon = $fabricData.icon
            $modInfo.Environment = $fabricData.environment; $modInfo.Entrypoints = $fabricData.entrypoints
            $modInfo.Mixins = if ($fabricData.mixins -is [array]) { $fabricData.mixins } else { @($fabricData.mixins) }
            $modInfo.AccessWidener = $fabricData.accessWidener; $modInfo.Depends = $fabricData.depends; $modInfo.Suggests = $fabricData.suggests
            $modInfo.Breaks = $fabricData.breaks; $modInfo.Conflicts = $fabricData.conflicts; $modInfo.ModLoader = "Fabric"
            
            $zip.Dispose()
            return $modInfo
        }
        
        # Check for mods.toml (Forge/NeoForge)
        if ($entry = $zip.Entries | Where-Object { $_.FullName -eq 'META-INF/mods.toml' } | Select-Object -First 1) {
            $reader = New-Object System.IO.StreamReader($entry.Open())
            $tomlContent = $reader.ReadToEnd()
            $reader.Close()
            
            if ($tomlContent -match 'modId\s*=\s*"([^"]+)"') { $modInfo.ModId = $matches[1] }
            if ($tomlContent -match 'displayName\s*=\s*"([^"]+)"') { $modInfo.Name = $matches[1] }
            if ($tomlContent -match 'version\s*=\s*"([^"]+)"') { $modInfo.Version = $matches[1] }
            if ($tomlContent -match 'description\s*=\s*"([^"]+)"') { $modInfo.Description = $matches[1] }
            if ($tomlContent -match 'authors\s*=\s*"([^"]+)"') { $modInfo.Authors = @($matches[1]) }
            
            $modInfo.ModLoader = "Forge/NeoForge"
            $zip.Dispose()
            return $modInfo
        }
        
        # Check for mixin configs
        if ($entry = $zip.Entries | Where-Object { $_.Name -match '\.mixins\.json$' } | Select-Object -First 1) {
            $reader = New-Object System.IO.StreamReader($entry.Open())
            $mixinData = $reader.ReadToEnd() | ConvertFrom-Json -ErrorAction SilentlyContinue
            $reader.Close()
            if ($mixinData.package -and -not $modInfo.ModId) {
                $packageParts = $mixinData.package -split '\.'
                if ($packageParts.Count -ge 2) { $modInfo.ModId = $packageParts[-2] }
            }
        }
        
        # Check for manifest
        if ($entry = $zip.Entries | Where-Object { $_.Name -eq 'MANIFEST.MF' } | Select-Object -First 1) {
            $reader = New-Object System.IO.StreamReader($entry.Open())
            $manifestContent = $reader.ReadToEnd()
            $reader.Close()
            
            $lines = $manifestContent -split "`n"
            foreach ($line in $lines) {
                if ($line -match 'Implementation-Title:\s*(.+)' -and -not $modInfo.Name) { $modInfo.Name = $matches[1].Trim() }
                if ($line -match 'Implementation-Version:\s*(.+)' -and -not $modInfo.Version) { $modInfo.Version = $matches[1].Trim() }
                if ($line -match 'Specification-Title:\s*(.+)' -and -not $modInfo.Name) { $modInfo.Name = $matches[1].Trim() }
            }
        }
        
        $zip.Dispose()
    } catch {}
    return $modInfo
}

function Fetch-Modrinth-By-Hash($hash) {
    try {
        $response = Invoke-RestMethod -Uri "https://api.modrinth.com/v2/version_file/$hash" -Method Get -UseBasicParsing
        if ($response.project_id) {
            $projectData = Invoke-RestMethod -Uri "https://api.modrinth.com/v2/project/$($response.project_id)" -Method Get -UseBasicParsing
            $fileInfo = $response.files[0]
            
            return @{ 
                Name = $projectData.title; Slug = $projectData.slug; ExpectedSize = $fileInfo.size
                VersionNumber = $response.version_number; FileName = $fileInfo.filename
                ModrinthUrl = "https://modrinth.com/mod/$($projectData.slug)/version/$($response.id)"
                FoundByHash = $true; ExactMatch = $true; IsLatestVersion = $false; MatchType = "Exact Hash"
                LoaderType = if ($response.loaders -contains "fabric") { "Fabric" } elseif ($response.loaders -contains "forge") { "Forge" } else { "Unknown" }
            }
        }
    } catch {}
    return @{ Name = ""; Slug = ""; ExpectedSize = 0; VersionNumber = ""; FileName = ""; FoundByHash = $false; ExactMatch = $false; IsLatestVersion = $false; LoaderType = "Unknown" }
}

function Fetch-Modrinth-By-ModId($modId, $version, $preferredLoader = "Fabric") {
    try {
        $projectData = Invoke-RestMethod -Uri "https://api.modrinth.com/v2/project/$modId" -Method Get -UseBasicParsing -ErrorAction Stop
        if ($projectData.id) {
            $versionsData = Invoke-RestMethod -Uri "https://api.modrinth.com/v2/project/$modId/version" -Method Get -UseBasicParsing
            
            foreach ($ver in $versionsData) {
                $matchesLoader = ($ver.loaders -contains $preferredLoader.ToLower())
                
                if ($matchesLoader) {
                    $file = $ver.files[0]
                    $loader = if ($ver.loaders -contains "fabric") { "Fabric" } elseif ($ver.loaders -contains "forge") { "Forge" } else { $ver.loaders[0] }
                    
                    return @{
                        Name = $projectData.title; Slug = $projectData.slug; ExpectedSize = $file.size
                        VersionNumber = $ver.version_number; FileName = $file.filename
                        ModrinthUrl = "https://modrinth.com/mod/$($projectData.slug)/version/$($ver.id)"
                        FoundByHash = $false; ExactMatch = $false; IsLatestVersion = ($versionsData[0].id -eq $ver.id)
                        MatchType = "Latest Version ($loader)"; LoaderType = $loader
                    }
                }
            }
            
            if ($versionsData.Count -gt 0) {
                $latestVersion = $versionsData[0]; $latestFile = $latestVersion.files[0]
                $loader = if ($latestVersion.loaders -contains "fabric") { "Fabric" } elseif ($latestVersion.loaders -contains "forge") { "Forge" } else { $latestVersion.loaders[0] }
                
                return @{
                    Name = $projectData.title; Slug = $projectData.slug; ExpectedSize = $latestFile.size
                    VersionNumber = $latestVersion.version_number; FileName = $latestFile.filename
                    ModrinthUrl = "https://modrinth.com/mod/$($projectData.slug)/version/$($latestVersion.id)"
                    FoundByHash = $false; ExactMatch = $false; IsLatestVersion = $true
                    MatchType = "Latest Version ($loader)"; LoaderType = $loader
                }
            }
        }
    } catch {
        try {
            $searchData = Invoke-RestMethod -Uri "https://api.modrinth.com/v2/search?query=`"$modId`"&facets=`"[[`"project_type:mod`"]]`"&limit=5" -Method Get -UseBasicParsing
            
            if ($searchData.hits -and $searchData.hits.Count -gt 0) {
                $bestMatch = $null; $bestScore = 0
                foreach ($hit in $searchData.hits) {
                    $score = 0
                    if ($hit.slug -eq $modId) { $score += 100 }
                    if ($hit.project_id -eq $modId) { $score += 100 }
                    if ($hit.title -eq $modId) { $score += 80 }
                    if ($hit.title -match $modId) { $score += 50 }
                    if ($hit.slug -match $modId) { $score += 40 }
                    
                    if ($score -gt $bestScore) { $bestScore = $score; $bestMatch = $hit }
                }
                
                if ($bestMatch) {
                    $versionsData = Invoke-RestMethod -Uri "https://api.modrinth.com/v2/project/$($bestMatch.project_id)/version" -Method Get -UseBasicParsing
                    
                    if ($versionsData.Count -gt 0) {
                        $latestVersion = $versionsData[0]; $latestFile = $latestVersion.files[0]
                        $loader = if ($latestVersion.loaders -contains "fabric") { "Fabric" } elseif ($latestVersion.loaders -contains "forge") { "Forge" } else { $latestVersion.loaders[0] }
                        
                        return @{
                            Name = $bestMatch.title; Slug = $bestMatch.slug; ExpectedSize = $latestFile.size
                            VersionNumber = $latestVersion.version_number; FileName = $latestFile.filename
                            ModrinthUrl = "https://modrinth.com/mod/$($bestMatch.slug)/version/$($latestVersion.id)"
                            FoundByHash = $false; ExactMatch = $false; IsLatestVersion = $true
                            MatchType = "Latest Version ($loader)"; LoaderType = $loader
                        }
                    }
                }
            }
        } catch {}
    }
    
    return @{ Name = ""; Slug = ""; ExpectedSize = 0; VersionNumber = ""; FileName = ""; FoundByHash = $false; ExactMatch = $false; IsLatestVersion = $false; MatchType = "No Match"; LoaderType = "Unknown" }
}

function Fetch-Modrinth-By-Filename($filename, $preferredLoader = "Fabric") {
    $cleanFilename = $filename -replace '\.temp\.jar$|\.tmp\.jar$|_1\.jar$', '.jar'
    $modNameWithoutExt = [System.IO.Path]::GetFileNameWithoutExtension($cleanFilename)
    
    if ($filename -match '(?i)fabric') { $preferredLoader = "Fabric" }
    elseif ($filename -match '(?i)forge') { $preferredLoader = "Forge" }
    
    $localVersion = ""; $baseName = $modNameWithoutExt
    if ($modNameWithoutExt -match '[-_](v?[\d\.]+(?:-[a-zA-Z0-9]+)?)$') {
        $localVersion = $matches[1]; $baseName = $modNameWithoutExt -replace '[-_](v?[\d\.]+(?:-[a-zA-Z0-9]+)?)$', ''
    }
    
    $baseName = $baseName -replace '(?i)-fabric$|-forge$', ''
    
    foreach ($slug in @($baseName.ToLower(), $modNameWithoutExt.ToLower())) {
        try {
            $projectData = Invoke-RestMethod -Uri "https://api.modrinth.com/v2/project/$slug" -Method Get -UseBasicParsing
            $versionsData = Invoke-RestMethod -Uri "https://api.modrinth.com/v2/project/$slug/version" -Method Get -UseBasicParsing
            
            foreach ($version in $versionsData) {
                foreach ($file in $version.files) {
                    if ($file.filename -eq $cleanFilename -or $file.filename -eq $filename) {
                        $loader = if ($version.loaders -contains "fabric") { "Fabric" } elseif ($version.loaders -contains "forge") { "Forge" } else { $version.loaders[0] }
                        
                        return @{
                            Name = $projectData.title; Slug = $projectData.slug; ExpectedSize = $file.size
                            VersionNumber = $version.version_number; FileName = $file.filename
                            ModrinthUrl = "https://modrinth.com/mod/$($projectData.slug)/version/$($version.id)"
                            FoundByHash = $false; ExactMatch = $true; IsLatestVersion = ($versionsData[0].id -eq $version.id)
                            MatchType = "Exact Filename"; LoaderType = $loader
                        }
                    }
                }
            }
            
            foreach ($version in $versionsData) {
                $matchesLoader = ($version.loaders -contains $preferredLoader.ToLower())
                
                if ($matchesLoader) {
                    $file = $version.files[0]
                    $loader = if ($version.loaders -contains "fabric") { "Fabric" } elseif ($version.loaders -contains "forge") { "Forge" } else { $version.loaders[0] }
                    
                    return @{
                        Name = $projectData.title; Slug = $projectData.slug; ExpectedSize = $file.size
                        VersionNumber = $version.version_number; FileName = $file.filename
                        ModrinthUrl = "https://modrinth.com/mod/$($projectData.slug)/version/$($version.id)"
                        FoundByHash = $false; ExactMatch = $false; IsLatestVersion = ($versionsData[0].id -eq $version.id)
                        MatchType = "Latest Version ($loader)"; LoaderType = $loader
                    }
                }
            }
            
            if ($versionsData.Count -gt 0) {
                $latestVersion = $versionsData[0]; $latestFile = $latestVersion.files[0]
                $loader = if ($latestVersion.loaders -contains "fabric") { "Fabric" } elseif ($latestVersion.loaders -contains "forge") { "Forge" } else { $latestVersion.loaders[0] }
                
                return @{
                    Name = $projectData.title; Slug = $projectData.slug; ExpectedSize = $latestFile.size
                    VersionNumber = $latestVersion.version_number; FileName = $latestFile.filename
                    ModrinthUrl = "https://modrinth.com/mod/$($projectData.slug)/version/$($latestVersion.id)"
                    FoundByHash = $false; ExactMatch = $false; IsLatestVersion = $true
                    MatchType = "Latest Version ($loader)"; LoaderType = $loader
                }
            }
        } catch { continue }
    }
    
    try {
        $searchData = Invoke-RestMethod -Uri "https://api.modrinth.com/v2/search?query=`"$baseName`"&facets=`"[[`"project_type:mod`"]]`"&limit=5" -Method Get -UseBasicParsing
        
        if ($searchData.hits -and $searchData.hits.Count -gt 0) {
            $hit = $searchData.hits[0]
            $versionsData = Invoke-RestMethod -Uri "https://api.modrinth.com/v2/project/$($hit.project_id)/version" -Method Get -UseBasicParsing
            
            foreach ($version in $versionsData) {
                foreach ($file in $version.files) {
                    if ($file.filename -eq $cleanFilename -or $file.filename -eq $filename) {
                        $loader = if ($version.loaders -contains "fabric") { "Fabric" } elseif ($version.loaders -contains "forge") { "Forge" } else { $version.loaders[0] }
                        
                        return @{
                            Name = $hit.title; Slug = $hit.slug; ExpectedSize = $file.size
                            VersionNumber = $version.version_number; FileName = $file.filename
                            ModrinthUrl = "https://modrinth.com/mod/$($hit.slug)/version/$($version.id)"
                            FoundByHash = $false; ExactMatch = $true; IsLatestVersion = ($versionsData[0].id -eq $version.id)
                            MatchType = "Exact Filename"; LoaderType = $loader
                        }
                    }
                }
            }
            
            if ($versionsData.Count -gt 0) {
                $latestVersion = $versionsData[0]; $latestFile = $latestVersion.files[0]
                $loader = if ($latestVersion.loaders -contains "fabric") { "Fabric" } elseif ($latestVersion.loaders -contains "forge") { "Forge" } else { $latestVersion.loaders[0] }
                
                return @{
                    Name = $hit.title; Slug = $hit.slug; ExpectedSize = $latestFile.size
                    VersionNumber = $latestVersion.version_number; FileName = $latestFile.filename
                    ModrinthUrl = "https://modrinth.com/mod/$($hit.slug)/version/$($latestVersion.id)"
                    FoundByHash = $false; ExactMatch = $false; IsLatestVersion = $true
                    MatchType = "Latest Version ($loader)"; LoaderType = $loader
                }
            }
        }
    } catch {}
    
    return @{ Name = ""; Slug = ""; ExpectedSize = 0; VersionNumber = ""; FileName = ""; FoundByHash = $false; ExactMatch = $false; IsLatestVersion = $false; MatchType = "No Match"; LoaderType = "Unknown" }
}

function Fetch-Megabase($hash) {
    try {
        $response = Invoke-RestMethod -Uri "https://megabase.vercel.app/api/query?hash=$hash" -Method Get -UseBasicParsing
        if (-not $response.error) { return $response.data }
    } catch {}
    return $null
}

# Extensive cheat/hack pattern database - compiled from known malicious mods
$suspiciousPatterns = @(
    # ===== ORIGINAL PATTERNS FROM VALOR MOD ANALYZER =====
    "AimAssist", "AnchorTweaks", "AutoAnchor", "AutoCrystal", "AutoDoubleHand",
    "AutoHitCrystal", "AutoPot", "AutoTotem", "AutoArmor", "InventoryTotem",
    "Hitboxes", "JumpReset", "LegitTotem", "PingSpoof", "SelfDestruct",
    "ShieldBreaker", "TriggerBot", "Velocity", "AxeSpam", "WebMacro",
    "FastPlace", "WalskyOptimizer", "WalksyOptimizer", "walsky.optimizer", 
    "WalksyCrystalOptimizerMod", "Donut", "Replace Mod", "Reach",
    "ShieldDisabler", "SilentAim", "Totem Hit", "Wtap", "FakeLag",
    "Friends", "NoDelay", "BlockESP", "Krypton", "krypton", "dev.krypton", "Virgin", "AntiMissClick",
    "LagReach", "PopSwitch", "SprintReset", "ChestSteal", "Antibot",
    "ElytraSwap", "FastXP", "FastExp", "Refill", "NoJumpDelay", "AirAnchor",
    "jnativehook", "FakeInv", "HoverTotem", "AutoClicker", "AutoFirework",
    "Freecam", "PackSpoof", "Antiknockback", "scrim", "catlean", "Argon",
    "Discord", "AuthBypass", "Asteria", "Prestige", "AutoEat", "AutoMine",
    "MaceSwap", "DoubleAnchor", "AutoTPA", "BaseFinder", "Xenon", "gypsy",
    "Grim", "grim",
    "org.chainlibs.module.impl.modules.Crystal.Y",
    "org.chainlibs.module.impl.modules.Crystal.bF",
    "org.chainlibs.module.impl.modules.Crystal.bM",
    "org.chainlibs.module.impl.modules.Crystal.bY",
    "org.chainlibs.module.impl.modules.Crystal.bq",
    "org.chainlibs.module.impl.modules.Crystal.cv",
    "org.chainlibs.module.impl.modules.Crystal.o",
    "org.chainlibs.module.impl.modules.Blatant.I",
    "org.chainlibs.module.impl.modules.Blatant.bR",
    "org.chainlibs.module.impl.modules.Blatant.bx",
    "org.chainlibs.module.impl.modules.Blatant.cj",
    "org.chainlibs.module.impl.modules.Blatant.dk",
    "imgui", "imgui.gl3", "imgui.glfw",
    "BowAim", "Criticals", "Flight", "Fakenick", "FakeItem",
    "invsee", "ItemExploit", "Hellion", "hellion",
    "KeyboardMixin", "ClientPlayerInteractionManagerMixin",
    "LicenseCheckMixin", "ClientPlayerInteractionManagerAccessor",
    "ClientPlayerEntityMixim", "dev.gambleclient", "obfuscatedAuth",
    "phantom-refmap.json", "xyz.greaj",
    "じ.class", "ふ.class", "ぶ.class", "ぷ.class", "た.class",
    "ね.class", "そ.class", "な.class", "ど.class", "ぐ.class",
    "ず.class", "で.class", "つ.class", "べ.class", "せ.class",
    "と.class", "み.class", "び.class", "す.class", "の.class",
    "autocrystal", "auto crystal", "cw crystal", "autohitcrystal",
    "autoanchor", "auto anchor", "anchortweaks", "anchor macro",
    "autototem", "auto totem", "legittotem", "inventorytotem", "hover totem",
    "autopot", "auto pot", "velocity",
    "autodoublehand", "auto double hand",
    "autoarmor", "auto armor",
    "automace",
    "aimassist", "aim assist",
    "triggerbot", "trigger bot",
    "shieldbreaker", "shield breaker",
    "axespam", "axe spam",
    "pingspoof", "ping spoof",
    "webmacro", "web macro",
    "selfdestruct", "self destruct",
    "hitboxes", "lvstrng",
    "swapBackToOriginalSlot",
    "attackRegisteredThisClick",
    "findKnockbackSword",
    
    # ===== ENHANCED PATTERNS=====
    # AutoCrystal variants
    "dontPlaceCrystal", "dontBreakCrystal", "AutoHitCrystal", "autohitcrystal", 
    "canPlaceCrystalServer", "healPotSlot", "endCrystalItemMixin",
    
    # AutoAnchor variants
    "hasGlowstone", "HasAnchor", "anchortweaks", "anchor macro", "safeanchor", "SafeAnchor",
    
    # AutoTotem variants
    "InventoryTotem", "inventorytotem", "HoverTotem", "hover totem", "legittotem", "LegitTotem",
    
    # AutoPot variants
    "speedPotSlot", "strengthPotSlot", "AutoPot", "autopot", "auto pot",
    
    # AutoArmor variants
    "preventSwordBlockBreaking", "preventSwordBlockAttack", "AutoArmor", "autoarmor", "auto armor",
    
    # AutoClicker/Combat
    "Failed to switch to mace after axe!", "Breaking shield with axe...", "Donut", "JumpReset", 
    "axespam", "axe spam", "shieldbreaker", "shield breaker", "EndCrystalItemMixin",
    "findKnockbackSword", "attackRegisteredThisClick", "autoCrystalPlaceClock",
    
    # AimAssist/TriggerBot
    "setBlockBreakingCooldown", "getBlockBreakingCooldown", "triggerbot", "trigger bot", 
    "onBlockBreaking", "setItemUseCooldown", "freecam", "Freecam",
    
    # Inventory/Game Manipulation
    "FakeInv", "swapBackToOriginalSlot", "setSelectedSlot", "invokeDoAttack", "pushOutOfBlocks", 
    "doItemUse", "FakeLag", "pingspoof", "ping spoof", "onTickMovement", 
    "Automatically switches to sword when hitting with totem",
    
    # Macros/Scripts
    "webmacro", "web macro", "arrayOfString", "invokeDoItemUse", "onPushOutOfBlocks", 
    "onIsGlowing", "getSelectedSlot", "lvstrng", "dqrkis", "selfdestruct", "self destruct", 
    "blockBreakingCooldown", "setItemUseCooldown", "invokeOnMouseButton", "POT_CHEATS", "BATAS",
    
    # Additional cheat client strings
    "AutoCrystal", "autocrystal", "auto crystal", "cw crystal",
    "AutoHitCrystal", "autohitcrystal", "canPlaceCrystalServer", "healPotSlot",
    "AutoAnchor", "autoanchor", "auto anchor", "DoubleAnchor", "hasGlowstone", "HasAnchor",
    "anchortweaks", "anchor macro", "safeanchor",
    "AutoTotem", "autototem", "auto totem", "InventoryTotem",
    "inventorytotem", "HoverTotem", "hover totem", "legittotem",
    "AutoPot", "autopot", "auto pot", "speedPotSlot", "strengthPotSlot",
    "AutoArmor", "autoarmor", "auto armor", "preventSwordBlockBreaking", "preventSwordBlockAttack",
    "AutoDoubleHand", "autodoublehand", "auto double hand",
    "AutoClicker", "autoclicker", "auto clicker",
    "AimAssist", "aimassist", "aim assist", "setBlockBreakingCooldown", "getBlockBreakingCooldown",
    "triggerbot", "trigger bot", "onBlockBreaking", "setItemUseCooldown", "freecam", "Freecam",
    "FakeInv", "swapBackToOriginalSlot", "setSelectedSlot", "invokeDoAttack", "pushOutOfBlocks", "doItemUse",
    "FakeLag", "pingspoof", "ping spoof", "onTickMovement", "Automatically switches to sword when hitting with totem",
    "webmacro", "web macro", "arrayOfString", "invokeDoItemUse", "onPushOutOfBlocks", "onIsGlowing", "getSelectedSlot",
    "lvstrng", "dqrkis", "selfdestruct", "self destruct", "blockBreakingCooldown", "setItemUseCooldown", "invokeOnMouseButton", "POT_CHEATS", "BATAS",
    
    # Velocity/Knockback
    "velocity", "Velocity", "VELOCITY", "antiknockback", "AntiKnockback", "ANTI_KNOCKBACK",
    
    # ESP/Wallhack
    "esp", "ESP", "wallhack", "WallHack", "WALLHACK", "boxesp", "BoxESP",
    
    # Killaura
    "killaura", "KillAura", "KILL_AURA", "autoclick", "AutoClick",
    
    # Fly/Movement
    "fly", "Fly", "FLY", "speed", "Speed", "SPEED", "step", "Step", "STEP",
    "timer", "Timer", "TIMER", "nofall", "NoFall", "NO_FALL",
    
    # Utility cheats
    "fullbright", "FullBright", "FULLBRIGHT", "nightvision", "NightVision",
    "cavefinder", "CaveFinder", "CAVE_FINDER", "xray", "Xray", "XRAY",
    
    # Reach/Hitboxes
    "reach", "Reach", "REACH", "hitboxes", "Hitboxes", "HITBOXES",
    
    # Anti-cheat bypass
    "anticheat", "AntiCheat", "bypass", "Bypass", "BYPASS"
)

# Enhanced cheat strings for deep string extraction
$cheatStrings = @(
    "AutoCrystal", "autocrystal", "auto crystal", "cw crystal",
    "dontPlaceCrystal", "dontBreakCrystal",
    "AutoHitCrystal", "autohitcrystal", "autohitcrystal", "canPlaceCrystalServer", "healPotSlot",
    "AutoAnchor", "autoanchor", "auto anchor", "DoubleAnchor",
    "hasGlowstone", "HasAnchor", "anchortweaks", "anchor macro", "safe anchor", "safeanchor",
    "AutoTotem", "autototem", "auto totem", "InventoryTotem",
    "inventorytotem", "HoverTotem", "hover totem", "legittotem",
    "AutoPot", "autopot", "auto pot", "speedPotSlot", "strengthPotSlot",
    "AutoArmor", "autoarmor", "auto armor",
    "preventSwordBlockBreaking", "preventSwordBlockAttack",
    "AutoDoubleHand", "autodoublehand", "auto double hand",
    "AutoClicker",
    "Failed to switch to mace after axe!",
    "Breaking shield with axe...",
    "Donut", "JumpReset", "axespam", "axe spam",
    "shieldbreaker", "shield breaker", "EndCrystalItemMixin",
    "findKnockbackSword", "attackRegisteredThisClick",
    "AimAssist", "aimassist", "aim assist",
    "triggerbot", "trigger bot",
    "FakeInv", "Friends", "swapBackToOriginalSlot",
    "FakeLag", "pingspoof", "ping spoof",
    "webmacro", "web macro",
    "lvstrng", "dqrkis", "selfdestruct", "self destruct",
    "AutoMace", "AutoFirework", "MaceSwap", "AirAnchor",
    "ElytraSwap", "FastXP", "FastExp", "NoJumpDelay",
    "PackSpoof", "Antiknockback", "catlean",
    "AuthBypass", "obfuscatedAuth", "LicenseCheckMixin",
    "BaseFinder", "invsee", "ItemExploit",
    "NoFall", "nofall",
    "WalksyCrystalOptimizerMod", "WalksyOptimizer", "WalskyOptimizer",
    "autoCrystalPlaceClock",
    "setBlockBreakingCooldown", "getBlockBreakingCooldown", "blockBreakingCooldown",
    "onBlockBreaking", "setItemUseCooldown",
    "setSelectedSlot", "invokeDoAttack", "invokeDoItemUse", "invokeOnMouseButton",
    "onTickMovement", "onPushOutOfBlocks", "onIsGlowing",
    "Automatically switches to sword when hitting with totem",
    "arrayOfString", "POT_CHEATS",
    "Dqrkis Client", "Entity.isGlowing"
)

function Check-Strings($filePath) {
    $stringsFound = [System.Collections.Generic.HashSet[string]]::new()
    $singleLetterClassCount = 0
    
    try {
        $possiblePaths = @(
            "C:\Program Files\Git\usr\bin\strings.exe",
            "C:\Program Files\Git\mingw64\bin\strings.exe",
            "$env:ProgramFiles\Git\usr\bin\strings.exe",
            "C:\msys64\usr\bin\strings.exe",
            "C:\cygwin64\bin\strings.exe"
        )
        
        if ($stringsPath = $possiblePaths | Where-Object { Test-Path $_ } | Select-Object -First 1) {
            $tempFile = Join-Path $env:TEMP "temp_strings_$(Get-Random).txt"
            & $stringsPath $filePath 2>$null | Out-File $tempFile
            if (Test-Path $tempFile) {
                $extractedContent = Get-Content $tempFile -Raw
                Remove-Item $tempFile -Force
                
                # Check both suspiciousPatterns and cheatStrings
                foreach ($string in $suspiciousPatterns) {
                    if ($extractedContent -match $string) { $stringsFound.Add($string) | Out-Null }
                }
                foreach ($string in $cheatStrings) {
                    if ($extractedContent -match $string) { $stringsFound.Add($string) | Out-Null }
                }
            }
        } else {
            # Also check for single-letter class files (obfuscation detection)
            try {
                Add-Type -AssemblyName System.IO.Compression.FileSystem
                $zip = [System.IO.Compression.ZipFile]::OpenRead($filePath)
                $classEntries = $zip.Entries | Where-Object { $_.Name -like '*.class' }
                foreach ($entry in $classEntries) {
                    $className = [System.IO.Path]::GetFileNameWithoutExtension($entry.Name)
                    if ($className.Length -le 2) {
                        $singleLetterClassCount++
                    }
                }
                $zip.Dispose()
            } catch {}
            
            $content = [System.Text.Encoding]::ASCII.GetString([System.IO.File]::ReadAllBytes($filePath)).ToLower()
            foreach ($string in $suspiciousPatterns) {
                if ($string -eq "velocity") {
                    if ($content -match "velocity(hack|module|cheat|bypass|packet|horizontal|vertical|amount|factor|setting)") {
                        $stringsFound.Add($string) | Out-Null
                    }
                } elseif ($content -match $string) {
                    $stringsFound.Add($string) | Out-Null
                }
            }
            # Also check cheatStrings
            foreach ($string in $cheatStrings) {
                if ($content -match $string) {
                    $stringsFound.Add($string) | Out-Null
                }
            }
        }
    } catch {}
    
    # Flag excessive single-letter class files (common in hacked clients)
    if ($singleLetterClassCount -gt 15) {
        $stringsFound.Add("SingleLetterClasses($singleLetterClassCount)") | Out-Null
    }
    
    return $stringsFound
}

# ===== BYPASS/INJECTION SCAN FUNCTION =====
function Invoke-BypassScan {
    param([string]$FilePath)

    $flags = [System.Collections.Generic.List[string]]::new()

    Add-Type -AssemblyName System.IO.Compression.FileSystem

    $mavenPrefixes = @(
        "com_","org_","net_","io_","dev_","gs_","xyz_",
        "app_","me_","tv_","uk_","be_","fr_","de_"
    )

    function Test-SuspiciousJarName {
        param([string]$JarName)
        $base = [System.IO.Path]::GetFileNameWithoutExtension($JarName)
        if ($base -match '\d')                                          { return $false }
        foreach ($pfx in $mavenPrefixes) {
            if ($base.ToLower().StartsWith($pfx))                       { return $false }
        }
        if ($base.Length -gt 20)                                        { return $false }
        return $true
    }

    try {
        $zip = [System.IO.Compression.ZipFile]::OpenRead($FilePath)

        $nestedJars   = @($zip.Entries | Where-Object { $_.FullName -match "^META-INF/jars/.+\.jar$" })
        $outerClasses = @($zip.Entries | Where-Object { $_.FullName -match "\.class$" })

        $suspiciousNestedJars = @()
        foreach ($nj in $nestedJars) {
            $njBase = [System.IO.Path]::GetFileName($nj.FullName)
            if (Test-SuspiciousJarName -JarName $njBase) {
                $suspiciousNestedJars += $njBase
            }
        }
        foreach ($sj in $suspiciousNestedJars) {
            $flags.Add("Suspicious nested JAR - no version, unknown dependency: $sj")
        }

        if ($nestedJars.Count -eq 1 -and $outerClasses.Count -lt 3) {
            $njName = [System.IO.Path]::GetFileName(($nestedJars | Select-Object -First 1).FullName)
            $flags.Add("Hollow shell - only $($outerClasses.Count) own class(es), wraps: $njName")
        }

        $outerModId = ""
        $fmje = $zip.Entries | Where-Object { $_.FullName -eq "fabric.mod.json" } | Select-Object -First 1
        if ($fmje) {
            try {
                $s = $fmje.Open()
                $r = New-Object System.IO.StreamReader($s)
                $t = $r.ReadToEnd(); $r.Close(); $s.Close()
                if ($t -match '"id"\s*:\s*"([^"]+)"') { $outerModId = $matches[1] }
            } catch { }
        }

        $allEntries = [System.Collections.Generic.List[object]]::new()
        foreach ($e in $zip.Entries) { $allEntries.Add($e) }

        $innerZips = [System.Collections.Generic.List[object]]::new()
        foreach ($nj in $nestedJars) {
            try {
                $ns = $nj.Open()
                $ms = New-Object System.IO.MemoryStream
                $ns.CopyTo($ms); $ns.Close()
                $ms.Position = 0
                $iz = [System.IO.Compression.ZipArchive]::new($ms, [System.IO.Compression.ZipArchiveMode]::Read)
                $innerZips.Add($iz)
                foreach ($ie in $iz.Entries) { $allEntries.Add($ie) }
            } catch { }
        }

        $runtimeExecFound  = $false
        $httpDownloadFound = $false
        $httpExfilFound    = $false
        $obfuscatedCount   = 0
        $numericClassCount = 0
        $unicodeClassCount = 0
        $totalClassCount   = 0


        foreach ($entry in $allEntries) {
            $name = $entry.FullName

            if ($name -match "\.class$") {
                $totalClassCount++
                $className = [System.IO.Path]::GetFileNameWithoutExtension(($name -split "/")[-1])

                # numeric-only class name: 123.class, 4567.class
                if ($className -match "^\d+$") { $numericClassCount++ }

                # unicode / non-ASCII class name
                if ($className -match "[^\x00-\x7F]") { $unicodeClassCount++ }

                # existing single-letter path obfuscation check
                $segs = ($name -replace "\.class$","") -split "/"
                $consecutiveSingle = 0
                $maxConsecutive    = 0
                foreach ($seg in $segs) {
                    if ($seg.Length -eq 1) {
                        $consecutiveSingle++
                        if ($consecutiveSingle -gt $maxConsecutive) { $maxConsecutive = $consecutiveSingle }
                    } else {
                        $consecutiveSingle = 0
                    }
                }
                if ($maxConsecutive -ge 3) { $obfuscatedCount++ }

                try {
                    $st = $entry.Open()
                    $ms2 = New-Object System.IO.MemoryStream
                    $st.CopyTo($ms2)
                    $st.Close()
                    $rawBytes = $ms2.ToArray()
                    $ms2.Dispose()
                    $ct = [System.Text.Encoding]::ASCII.GetString($rawBytes)

                    if ($ct -match "java/lang/Runtime" -and
                        $ct -match "getRuntime" -and
                        $ct -match "exec") {
                        $runtimeExecFound = $true
                    }

                    if ($ct -match "openConnection" -and
                        $ct -match "HttpURLConnection" -and
                        $ct -match "FileOutputStream") {
                        $httpDownloadFound = $true
                    }

                    if ($ct -match "openConnection" -and
                        $ct -match "setDoOutput" -and
                        $ct -match "getOutputStream" -and
                        $ct -match "getProperty") {
                        $httpExfilFound = $true
                    }

                } catch { }
            }
        }

        foreach ($iz in $innerZips) { try { $iz.Dispose() } catch { } }
        $zip.Dispose()

        $obfPct     = if ($totalClassCount -ge 10) { [math]::Round(($obfuscatedCount   / $totalClassCount) * 100) } else { 0 }
        $numPct     = if ($totalClassCount -ge 5)  { [math]::Round(($numericClassCount / $totalClassCount) * 100) } else { 0 }
        $uniPct     = if ($totalClassCount -ge 5)  { [math]::Round(($unicodeClassCount / $totalClassCount) * 100) } else { 0 }

        if ($runtimeExecFound -and $obfPct -ge 25) {
            $flags.Add("Runtime.exec() in obfuscated code - can run arbitrary OS commands")
        }

        if ($httpDownloadFound) {
            $flags.Add("HTTP file download - fetches and writes files from a remote server at runtime")
        }

        if ($httpExfilFound) {
            $flags.Add("HTTP POST exfiltration - sends system data to an external server")
        }

        if ($totalClassCount -ge 10 -and $obfPct -ge 25) {
            $flags.Add("Heavy obfuscation - $obfPct% of classes use single-letter path segments (a/b/c style)")
        }

        if ($numPct -ge 20) {
            $flags.Add("Numeric class names - $numPct% of classes have numeric-only names (e.g. 1234.class)")
        }

        if ($uniPct -ge 10) {
            $flags.Add("Unicode class names - $uniPct% of classes use non-ASCII characters")
        }


        $knownLegitModIds = @(
            "vmp-fabric","vmp","lithium","sodium","iris","fabric-api",
            "modmenu","ferrite-core","lazydfu","starlight","entityculling",
            "memoryleakfix","krypton","c2me-fabric","smoothboot-fabric",
            "immediatelyfast","noisium","threadtweak"
        )
        $dangerCount = ($flags | Where-Object {
            $_ -match "Runtime\.exec|HTTP file download|HTTP POST|Heavy obfuscation|Suspicious nested JAR"
        }).Count
        if ($outerModId -and ($knownLegitModIds -contains $outerModId) -and $dangerCount -gt 0) {
            $flags.Add("Fake mod identity - claims to be '$outerModId' but contains dangerous code")
        }

    } catch { }

    return $flags
}

# Collections for results
$verifiedMods = @(); $unknownMods = @(); $suspiciousMods = @(); $sizeMismatchMods = @(); $tamperedMods = @(); $allModsInfo = @()
$attributeManipulatedMods = @()
$bypassMods = @()  # For bypass/injection detection

# Process all mods - combine main mods folder with external JARs
$jarFiles = Get-ChildItem -Path $mods -Filter *.jar -Force

# Add external mod JARs (excluding duplicates already in main mods folder)
if ($externalModJars.Count -gt 0) {
    $mainModPaths = $jarFiles | ForEach-Object { $_.FullName }
    foreach ($extJar in $externalModJars) {
        # Skip if already in main mods folder
        if ($extJar -notin $mainModPaths) {
            try {
                $jarFile = Get-Item $extJar -Force -ErrorAction SilentlyContinue
                if ($jarFile) {
                    $jarFiles += $jarFile
                }
            } catch {
                # Silent error
            }
        }
    }
}

$totalMods = $jarFiles.Count

if ($jarFiles.Count -eq 0) {
    Write-Host "No modules found in: $mods" -ForegroundColor Red
    exit 0
}


# Process all mods
for ($i = 0; $i -lt $jarFiles.Count; $i++) {
    $file = $jarFiles[$i]
    # Simple progress indicator
    $percent = [math]::Round((($i + 1) / $totalMods) * 100)
    Write-Host "`r[$percent%]" -NoNewline
    
    # Check for attribute manipulation on mod files
    $hasHiddenAttr = $file.Attributes -band [System.IO.FileAttributes]::Hidden
    $hasSystemAttr = $file.Attributes -band [System.IO.FileAttributes]::System
    
    # Get file info
    $hash = Get-SHA1 -filePath $file.FullName
    $actualSize = $file.Length; $actualSizeKB = [math]::Round($actualSize/1KB, 2)
    $zoneInfo = Get-ZoneIdentifier $file.FullName
    $jarModInfo = Get-Mod-Info-From-Jar -jarPath $file.FullName
    
    # Determine preferred loader
    $preferredLoader = "Fabric"
    if ($file.Name -match '(?i)fabric') { $preferredLoader = "Fabric" }
    elseif ($file.Name -match '(?i)forge') { $preferredLoader = "Forge" }
    elseif ($jarModInfo.ModLoader -eq "Fabric") { $preferredLoader = "Fabric" }
    elseif ($jarModInfo.ModLoader -eq "Forge/NeoForge") { $preferredLoader = "Forge" }
    
    # Try to find mod info
    $modData = Fetch-Modrinth-By-Hash -hash $hash
    if (-not $modData.Name -and $jarModInfo.ModId) {
        $modData = Fetch-Modrinth-By-ModId -modId $jarModInfo.ModId -version $jarModInfo.Version -preferredLoader $preferredLoader
    }
    if (-not $modData.Name) {
        $modData = Fetch-Modrinth-By-Filename -filename $file.Name -preferredLoader $preferredLoader
    }
    
    # Build mod entry for analysis
    if ($modData.Name) {
        $sizeDiff = $actualSize - $modData.ExpectedSize
        $expectedSizeKB = if ($modData.ExpectedSize -gt 0) { [math]::Round($modData.ExpectedSize/1KB, 2) } else { 0 }
        
        $modEntry = [PSCustomObject]@{ 
            ModName = $modData.Name; FileName = $file.Name; Version = $modData.VersionNumber
            ExpectedSize = $modData.ExpectedSize; ExpectedSizeKB = $expectedSizeKB; ActualSize = $actualSize; ActualSizeKB = $actualSizeKB
            SizeDiff = $sizeDiff; SizeDiffKB = [math]::Round($sizeDiff/1KB, 2); DownloadSource = $zoneInfo.Source; SourceURL = $zoneInfo.URL
            IsModrinthDownload = $zoneInfo.IsModrinth; ModrinthUrl = $modData.ModrinthUrl; IsVerified = $true; MatchType = $modData.MatchType
            ExactMatch = $modData.ExactMatch; IsLatestVersion = $modData.IsLatestVersion; LoaderType = $modData.LoaderType
            PreferredLoader = $preferredLoader; FilePath = $file.FullName; JarModId = $jarModInfo.ModId; JarName = $jarModInfo.Name
            JarVersion = $jarModInfo.Version; JarModLoader = $jarModInfo.ModLoader; HasHiddenAttr = $hasHiddenAttr; HasSystemAttr = $hasSystemAttr
        }
        
        $verifiedMods += $modEntry; $allModsInfo += $modEntry
        
        if ($modData.ExpectedSize -gt 0 -and $actualSize -ne $modData.ExpectedSize) {
            $sizeMismatchMods += $modEntry
            if ([math]::Abs($sizeDiff) -gt 1024) { $tamperedMods += $modEntry }
        }
    } elseif ($megabaseData = Fetch-Megabase -hash $hash) {
        $modEntry = [PSCustomObject]@{ 
            ModName = $megabaseData.name; FileName = $file.Name; Version = "Unknown"; ExpectedSize = 0; ExpectedSizeKB = 0
            ActualSize = $actualSize; ActualSizeKB = $actualSizeKB; SizeDiff = 0; SizeDiffKB = 0; DownloadSource = $zoneInfo.Source
            SourceURL = $zoneInfo.URL; IsModrinthDownload = $zoneInfo.IsModrinth; IsVerified = $true; MatchType = "Megabase"
            ExactMatch = $false; IsLatestVersion = $false; LoaderType = "Unknown"; PreferredLoader = $preferredLoader
            FilePath = $file.FullName; JarModId = $jarModInfo.ModId; JarName = $jarModInfo.Name; JarVersion = $jarModInfo.Version
            JarModLoader = $jarModInfo.ModLoader; HasHiddenAttr = $hasHiddenAttr; HasSystemAttr = $hasSystemAttr
        }
        
        $verifiedMods += $modEntry; $allModsInfo += $modEntry
    } else {
        $unknownModEntry = [PSCustomObject]@{ 
            FileName = $file.Name; FilePath = $file.FullName; ZoneId = $zoneInfo.URL; DownloadSource = $zoneInfo.Source
            IsModrinthDownload = $zoneInfo.IsModrinth; FileSize = $actualSize; FileSizeKB = $actualSizeKB; Hash = $hash
            ExpectedSize = 0; ExpectedSizeKB = 0; SizeDiff = 0; SizeDiffKB = 0; ModrinthUrl = ""; ModName = ""; MatchType = ""
            ExactMatch = $false; IsLatestVersion = $false; LoaderType = "Unknown"; PreferredLoader = $preferredLoader
            JarModId = $jarModInfo.ModId; JarName = $jarModInfo.Name; JarVersion = $jarModInfo.Version; JarModLoader = $jarModInfo.ModLoader
            HasHiddenAttr = $hasHiddenAttr; HasSystemAttr = $hasSystemAttr
        }
        
        $unknownMods += $unknownModEntry; $allModsInfo += $unknownModEntry
    }
    
    # Track attribute manipulation separately for reporting
    if ($hasHiddenAttr -or $hasSystemAttr) {
        $attributeManipulatedMods += [PSCustomObject]@{
            ModName = if ($modData.Name) { $modData.Name } else { "Unknown" }
            FileName = $file.Name
            FilePath = $file.FullName
            Attributes = $file.Attributes.ToString()
            IsHidden = ($hasHiddenAttr -ne $null)
            IsSystem = ($hasSystemAttr -ne $null)
        }
    }
}

Write-Host "`r$(' ' * 120)`r" -NoNewline

# Try to identify unknown mods
for ($i = 0; $i -lt $unknownMods.Count; $i++) {
    $mod = $unknownMods[$i]
    $modrinthInfo = if ($mod.JarModId) { Fetch-Modrinth-By-ModId -modId $mod.JarModId -version $mod.JarVersion -preferredLoader $mod.PreferredLoader }
    if (-not $modrinthInfo -or -not $modrinthInfo.Name) { $modrinthInfo = Fetch-Modrinth-By-Filename -filename $mod.FileName -preferredLoader $mod.PreferredLoader }
    
    if ($modrinthInfo -and $modrinthInfo.Name) {
        $mod.ModName = $modrinthInfo.Name; $mod.ExpectedSize = $modrinthInfo.ExpectedSize
        $mod.ExpectedSizeKB = if ($modrinthInfo.ExpectedSize -gt 0) { [math]::Round($modrinthInfo.ExpectedSize/1KB, 2) } else { 0 }
        $mod.SizeDiff = $mod.FileSize - $modrinthInfo.ExpectedSize
        $mod.SizeDiffKB = [math]::Round(($mod.FileSize - $modrinthInfo.ExpectedSize)/1KB, 2)
        $mod.ModrinthUrl = $modrinthInfo.ModrinthUrl; $mod.ModName = $modrinthInfo.Name; $mod.MatchType = $modrinthInfo.MatchType
        $mod.ExactMatch = $modrinthInfo.ExactMatch; $mod.IsLatestVersion = $modrinthInfo.IsLatestVersion; $mod.LoaderType = $modrinthInfo.LoaderType
        
        for ($j = 0; $j -lt $allModsInfo.Count; $j++) {
            if ($allModsInfo[$j].FileName -eq $mod.FileName) {
                $allModsInfo[$j].ModName = $modrinthInfo.Name; $allModsInfo[$j].ExpectedSize = $modrinthInfo.ExpectedSize
                $allModsInfo[$j].ExpectedSizeKB = $mod.ExpectedSizeKB; $allModsInfo[$j].SizeDiff = $mod.SizeDiff
                $allModsInfo[$j].SizeDiffKB = $mod.SizeDiffKB; $allModsInfo[$j].ModrinthUrl = $modrinthInfo.ModrinthUrl
                $allModsInfo[$j].ModName = $modrinthInfo.Name; $allModsInfo[$j].MatchType = $modrinthInfo.MatchType
                $allModsInfo[$j].ExactMatch = $modrinthInfo.ExactMatch; $allModsInfo[$j].IsLatestVersion = $modrinthInfo.IsLatestVersion
                $allModsInfo[$j].LoaderType = $modrinthInfo.LoaderType
                break
            }
        }
    }
}

# Deep pattern scan on unknown mods (including those with attribute manipulation)
if ($unknownMods.Count -gt 0) {
    $idx = 0
    
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        
        $pattern = '(' + ($suspiciousPatterns -join '|') + ')'
        $regex = [regex]::new($pattern, [System.Text.RegularExpressions.RegexOptions]::Compiled)
        
        foreach ($mod in $unknownMods) {
            $idx++
            # Simple progress for deep scan
            $deepPercent = [math]::Round(($idx / $unknownMods.Count) * 100)
            Write-Host "`r[$deepPercent%]" -NoNewline
            
            $detected = [System.Collections.Generic.HashSet[string]]::new()
            
            try {
                $archive = [System.IO.Compression.ZipFile]::OpenRead($mod.FilePath)
                
                foreach ($entry in $archive.Entries) {
                    $matches = $regex.Matches($entry.FullName)
                    foreach ($m in $matches) {
                        [void]$detected.Add($m.Value)
                    }
                    
                    if ($entry.Name -like "*.jar") {
                        # ===== Nested JAR scanning =====
                        try {
                            $ms = New-Object System.IO.MemoryStream
                            $entry.Open().CopyTo($ms)
                            $ms.Position = 0
                            
                            $nestedZip = New-Object System.IO.Compression.ZipArchive($ms, [System.IO.Compression.ZipArchiveMode]::Read)
                            
                            foreach ($nestedEntry in $nestedZip.Entries) {
                                if ($nestedEntry.Name -match '\.(class|json)$') {
                                    $reader = New-Object System.IO.StreamReader($nestedEntry.Open())
                                    $nestedContent = $reader.ReadToEnd().ToLower()
                                    $reader.Close()
                                    
                                    foreach ($string in $suspiciousPatterns) {
                                        if ($nestedContent -match [regex]::Escape($string.ToLower())) {
                                            [void]$detected.Add($string)
                                        }
                                    }
                                }
                            }
                        } catch {}
                        
                        continue
                    }
                    
                    if ($entry.FullName -match '\.(class|json)$' -or $entry.FullName -match 'MANIFEST\.MF') {
                        try {
                            $stream = $entry.Open()
                            $reader = New-Object System.IO.StreamReader($stream)
                            $content = $reader.ReadToEnd()
                            $reader.Close()
                            $stream.Close()
                            
                            $contentMatches = $regex.Matches($content)
                            foreach ($m in $contentMatches) {
                                [void]$detected.Add($m.Value)
                            }
                        } catch {
                            # Entry read failed, skip
                        }
                    }
                }
                
                $archive.Dispose()
                
                if ($detected.Count -gt 0) {
                    $suspiciousMods += [PSCustomObject]@{ 
                        FileName = $mod.FileName
                        DetectedPatterns = $detected
                    }
                }
                
            } catch {
                # Archive corrupted or inaccessible
                continue
            }
        }
    } catch {
        # Silent error during deep analysis
    }
    
    Write-Host "`r$(' ' * 120)`r" -NoNewline
}

# ===== BYPASS/INJECTION SCAN - Silent with progress only =====
$idx = 0

foreach ($file in $jarFiles) {
    $idx++
    $spinner = @("⣾","⣽","⣻","⢿","⡿","⣟","⣯","⣷")[$idx % 8]
    Write-Host "`r[$spinner] Bypass scan: $idx/$totalMods - $($file.Name)" -ForegroundColor Yellow -NoNewline
    
    $bypassFlags = Invoke-BypassScan -FilePath $file.FullName
    
    if ($bypassFlags.Count -gt 0) {
        $bypassMods += [PSCustomObject]@{
            FileName = $file.Name
            FilePath = $file.FullName
            Flags    = $bypassFlags
        }
        
        # Remove from verified/unknown if bypass detected
        $verifiedMods = $verifiedMods | Where-Object { $_.FileName -ne $file.Name }
        $unknownMods = $unknownMods | Where-Object { $_.FileName -ne $file.Name }
    }
}

Write-Host "`r$(' ' * 120)`r" -NoNewline


# ==================== DISALLOWED MODS DETECTOR ====================
# List of disallowed mods with their Modrinth slugs
$disallowedMods = @{
    "xeros-minimap" = @{
        Names = @("Xero's Minimap", "Xeros Minimap", "xeros-minimap", "XerosMinimap", "Xero's Minimap Mod")
    }
    "freecam" = @{
        Names = @("Freecam", "freecam", "FreeCam", "Free Cam")
    }
    "health-indicators" = @{
        Names = @("Health Indicators", "health indicators", "HealthIndicators", "Health Indicators Mod")
    }
    "clickcrystals" = @{
        Names = @("ClickCrystals", "clickcrystals", "ClickCrystals Mod")
    }
    "mousetweaks" = @{
        Names = @("Mouse Tweaks", "mousetweaks", "MouseTweaks")
    }
    "itemscroller" = @{
        Names = @("Item Scroller", "itemscroller", "ItemScroller")
    }
    "tweakeroo" = @{
        Names = @("Tweakeroo", "tweakeroo", "Tweakeroo")
    }
}

# Scan for disallowed mods
$disallowedModsFound = @()
$jarFilesForDisallowed = Get-ChildItem -Path $mods -Filter *.jar

foreach ($file in $jarFilesForDisallowed) {
    $fileName = $file.Name.ToLower()
    $modInfo = Get-Mod-Info-From-Jar -jarPath $file.FullName
    
    # Check each disallowed mod
    foreach ($modSlug in $disallowedMods.Keys) {
        $modData = $disallowedMods[$modSlug]
        $isDisallowed = $false
        
        # Check filename
        foreach ($name in $modData.Names) {
            if ($fileName -match [regex]::Escape($name.ToLower()) -or 
                $fileName -match [regex]::Escape($modSlug.ToLower()) -or
                $fileName -match [regex]::Escape(($name -replace ' ', '').ToLower())) {
                $isDisallowed = $true
                break
            }
        }
        
        # Check mod info from jar
        if (-not $isDisallowed) {
            if ($modInfo.ModId -and $modInfo.ModId.ToLower() -match $modSlug.ToLower()) {
                $isDisallowed = $true
            }
            elseif ($modInfo.Name -and $modInfo.Name.ToLower() -match $modSlug.ToLower()) {
                $isDisallowed = $true
            }
        }
        
        if ($isDisallowed) {
            $disallowedModsFound += [PSCustomObject]@{
                FileName = $file.Name
                ModName = $modData.Names[0]
            }
            break
        }
    }
}

# Also scan verified mods for suspicious patterns (including those with attribute manipulation)
$counter = 0
foreach ($mod in $allModsInfo) {
    $counter++
    # Simple progress indicator
    $patternPercent = [math]::Round(($counter / $allModsInfo.Count) * 100)
    Write-Host "`r[$patternPercent%]" -NoNewline
    
    # Check for attribute manipulation flag
    $hasAttributeBypass = ($mod.HasHiddenAttr -or $mod.HasSystemAttr)
    
    # Only flag as suspicious if it has patterns AND is NOT a signature match (verified)
    if ($modStrings = Check-Strings $mod.FilePath) {
        # If mod is verified with exact match, don't flag as suspicious
        # Signature match takes precedence over pattern detection
        if ($mod.IsVerified -eq $true -and ($mod.MatchType -match 'Exact')) {
            # This is a verified mod with signature match, skip pattern flagging
            continue
        }
        
        $suspiciousMods += [PSCustomObject]@{ 
            FileName = $mod.FileName; DetectedPatterns = $modStrings;
            ModName = $mod.ModName; DownloadSource = $mod.DownloadSource; 
            IsVerifiedMod = ($mod.IsVerified -eq $true); HasSizeMismatch = ($mod.SizeDiffKB -ne 0 -and [math]::Abs($mod.SizeDiffKB) -gt 1)
            HasAttributeBypass = $hasAttributeBypass
        }
    }
}

# Generate HTML Report (silent)

$OutputPath = "$env:USERPROFILE\Desktop\ValorModAnalysisReport.html"

if (-not (Test-Path (Split-Path $OutputPath))) {
    New-Item -ItemType Directory -Path (Split-Path $OutputPath) -Force | Out-Null
}

$htmlReport = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Valor Mod Analyzer - Security Report</title>
    <style>
        :root {
            --primary: #2c3e50;
            --success: #27ae60;
            --warning: #f39c12;
            --danger: #e74c3c;
            --info: #3498db;
            --magenta: #9b59b6;
            --light: #ecf0f1;
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
           font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            min-height: 100vh;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        
        .header {
            background: linear-gradient(135deg, var(--primary) 0%, #1a2530 100%);
            color: white;
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 30px;
            text-align: center;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .header h1 { font-size: 2rem; margin-bottom: 10px; }
        .header p { opacity: 0.9; }
        
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            text-align: center;
            transition: transform 0.3s;
        }
        
        .card:hover { transform: translateY(-5px); }
        
        .card h3 { font-size: 0.9rem; color: var(--primary); margin-bottom: 10px; }
        .card p { font-size: 2rem; font-weight: bold; }
        
        .card.success { border-bottom: 4px solid var(--success); }
        .card.success p { color: var(--success); }
        
        .card.warning { border-bottom: 4px solid var(--warning); }
        .card.warning p { color: var(--warning); }
        
        .card.danger { border-bottom: 4px solid var(--danger); }
        .card.danger p { color: var(--danger); }
        
        .card.info { border-bottom: 4px solid var(--info); }
        .card.info p { color: var(--info); }
        
        .card.magenta { border-bottom: 4px solid var(--magenta); }
        .card.magenta p { color: var(--magenta); }
        
        .section {
            background: white;
            border-radius: 8px;
            padding: 25px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .section h2 {
            color: var(--primary);
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid var(--info);
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        
        th {
            background: linear-gradient(135deg, var(--primary) 0%, #1a2530 100%);
            color: white;
            padding: 12px;
            text-align: left;
        }
        
        td {
            padding: 12px;
            border-bottom: 1px solid #eee;
        }
        
        tr:nth-child(even) { background-color: #f8f9fa; }
        tr:hover { background-color: #e3f2fd; }
        
        .verified-row { border-left: 4px solid var(--success); }
        .suspicious-row { border-left: 4px solid var(--danger); background: linear-gradient(135deg, #fff3cd 0%, #fff8e1 100%) !important; }
        .tampered-row { border-left: 4px solid var(--magenta); background: linear-gradient(135deg, #fadbd8 0%, #f5b7b1 100%) !important; }
        .unknown-row { border-left: 4px solid var(--warning); }
        .attribute-row { border-left: 4px solid #e67e22; background: linear-gradient(135deg, #ffeaa7 0%, #fdcb6e 100%) !important; }
        
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
           font-size: 0.8rem;
           font-weight: bold;
            margin-right: 5px;
        }
        
        .badge-success { background: var(--success); color: white; }
        .badge-warning { background: var(--warning); color: white; }
        .badge-danger { background: var(--danger); color: white; }
        .badge-info { background: var(--info); color: white; }
        .badge-magenta { background: var(--magenta); color: white; }
        .badge-orange { background: #e67e22; color: white; }
        
        .footer {
            text-align: center;
            margin-top: 40px;
            padding: 20px;
            color: white;
        }
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <h1>Valor Mod Analyzer</h1>
        </header>
"@

# Summary Cards
$htmlReport += "<div class='summary-cards'>
    <div class='card info'>
        <h3>Total Analyzed</h3>
        <p>$totalMods</p>
    </div>
    <div class='card success'>
        <h3>Verified</h3>
        <p>$($verifiedMods.Count)</p>
    </div>
    <div class='card warning'>
        <h3>Unknown</h3>
        <p>$($unknownMods.Count)</p>
    </div>
    <div class='card danger'>
        <h3>Suspicious</h3>
        <p>$($suspiciousMods.Count)</p>
    </div>
    <div class='card magenta'>
        <h3>Tampered</h3>
        <p>$($tamperedMods.Count)</p>
    </div>
    <div class='card' style='border-bottom: 4px solid #e67e22;'>
        <h3>Hidden Files</h3>
        <p style='color: #e67e22;'>$($attributeManipulatedMods.Count)</p>
    </div>
    <div class='card' style='border-bottom: 4px solid var(--danger);'>
        <h3>Disallowed</h3>
        <p style='color: var(--danger);'>$($disallowedModsFound.Count)</p>
    </div>
    <div class='card' style='border-bottom: 4px solid #9b59b6;'>
        <h3>Bypass/Injection</h3>
        <p style='color: #9b59b6;'>$($bypassMods.Count)</p>
    </div>
</div>"

# Fabric AddMods Section - Scan external mods and add them to the main analysis
$fabricAddModsDetected = $javaProcesses | Where-Object { 
    try { 
        (Get-CimInstance Win32_Process -Filter "ProcessId = $($_.Id)" -ErrorAction Stop).CommandLine -match '-Dfabric\.addMods'
    } catch { $false }
}

# Check for argfiles that might contain fabric.addMods
$externalModDirectories = @()
foreach ($proc in $javaProcesses) {
    try {
        $cmdLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)").CommandLine
        # Direct fabric.addMods
        if ($cmdLine -match '-Dfabric\.addMods=([^\s]+)') {
            $externalModDirectories += $matches[1]
        }
        # Argfile-based fabric.addMods
        if ($cmdLine -match '@([\w]:\\[^\s]+\.txt|/[^\s]+\.txt)') {
            $argfilePath = $matches[1]
            if (Test-Path $argfilePath) {
                $argfileContent = Get-Content -Path $argfilePath -Raw -ErrorAction SilentlyContinue
                if ($argfileContent -match '-Dfabric\.addMods=([^\r\n]+)') {
                    $externalModDirectories += $matches[1]
                }
            }
        }
    } catch {}
}

if ($externalModDirectories.Count -gt 0) {
    $htmlReport += "<div class='section'>
        <h2>[EXTERNAL MODS] External Mod Directories Detected</h2>
        <p style='color: var(--warning); font-weight: bold;'>External mod loading detected via JVM arguments</p>"
    
    foreach ($modDir in $externalModDirectories) {
        # Check if directory is accessible
        if (-not (Test-Path $modDir)) {
            $htmlReport += "<div style='margin-bottom: 20px; padding: 15px; background: #ffe6e6; border-left: 4px solid #dc3545;'>"
            $htmlReport += "<p style='color: #dc3545; font-weight: bold;'>⚠ External mod directory not found or inaccessible: $modDir</p>"
            $htmlReport += "</div>"
            continue
        }
        
        try {
            $externalMods = Get-ChildItem -Path $modDir -Filter "*.jar" -Force -ErrorAction SilentlyContinue
            if ($externalMods) {
                $htmlReport += "<div style='margin-bottom: 20px; padding: 15px; background: #fff3cd; border-left: 4px solid #ffc107;'>"
                $htmlReport += "<p style='font-family: monospace; font-weight: bold; margin-bottom: 10px;'>Directory: $modDir</p>"
                $htmlReport += "<p style='margin-bottom: 10px;'><strong>Found $($externalMods.Count) external mod(s):</strong></p>"
                $htmlReport += "<ul style='font-family: monospace; list-style-type: none; padding-left: 20px;'>"
                foreach ($extMod in $externalMods) {
                    $htmlReport += "<li style='padding: 5px 0;'>- $($extMod.Name)</li>"
                }
                $htmlReport += "</ul>"
                $htmlReport += "</div>"
                
                # NOTE: External mods are already integrated into main scanning pipeline above
                # They will appear in the regular scan results with full analysis
            } else {
                $htmlReport += "<div style='margin-bottom: 20px; padding: 15px; background: #fff3cd; border-left: 4px solid #ffc107;'>"
                $htmlReport += "<p style='font-family: monospace; font-weight: bold;'>Directory: $modDir</p>"
                $htmlReport += "<p style='color: var(--warning);'>No .jar files found in this directory</p>"
                $htmlReport += "</div>"
            }
        } catch {
            $htmlReport += "<div style='margin-bottom: 20px; padding: 15px; background: #ffe6e6; border-left: 4px solid #dc3545;'>"
            $htmlReport += "<p style='color: #dc3545; font-weight: bold;'>⚠ Cannot access directory (Permission denied): $modDir</p>"
            $htmlReport += "<p style='font-size: 0.9rem;'>This directory appears to be protected by Windows. Run the script as Administrator to scan external mods in protected locations.</p>"
            $htmlReport += "</div>"
        }
    }
    
    $htmlReport += "<p style='margin-top: 15px; padding: 10px; background: #fff3cd; border-left: 4px solid #ffc107;'>
        <strong>INFO:</strong> External mods listed above have been fully scanned and will appear in the analysis results below.
    </p>
    </div>"
}

# JavaAgent Detection Section - Only show suspicious agents
$javaAgentDetected = $false
$suspiciousJavaAgents = @()

foreach ($proc in $javaProcesses) {
    try {
        $cmdLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)").CommandLine
        if ($cmdLine -match '-javaagent:([^\s]+)') {
            $agentPath = $matches[1]
            
            # Check if legitimate (skip these)
            $isLegitimate = $false
            $legitimatePatterns = @('theseus\.jar', 'metadata\.jar', 'NewLaunch\.jar')
            foreach ($pattern in $legitimatePatterns) {
                if ($agentPath -match $pattern) {
                    $isLegitimate = $true
                    break
                }
            }
            
            # Only track suspicious agents
            if (-not $isLegitimate) {
                $javaAgentDetected = $true
                $suspiciousJavaAgents += [PSCustomObject]@{
                    ProcessId = $proc.Id
                    AgentPath = $agentPath
                }
            }
        }
    } catch {}
}

# Show only suspicious agents
if ($javaAgentDetected) {
    $htmlReport += "<div class='section'>
        <h2 style='color: var(--danger);'>[CRITICAL] Suspicious Java Agent Detected</h2>
        <p style='color: var(--danger); font-weight: bold;'>WARNING: Java agents can inject arbitrary code and bypass all security checks!</p>"
    
    foreach ($agent in $suspiciousJavaAgents) {
        $htmlReport += "<p><strong>Process ID:</strong> $($agent.ProcessId)</p>"
        $htmlReport += "<p style='font-family: monospace; background: #ffe6e6; padding: 10px; border-radius: 4px; color: var(--danger);'>-javaagent:$($agent.AgentPath)</p>"
    }
    
    $htmlReport += "<p style='margin-top: 15px; padding: 10px; background: #fff3cd; border-left: 4px solid #e67e22;'>
        <strong>SECURITY RISK:</strong> Java agents have full access to the JVM and can modify bytecode at runtime.<br>
        This is a common method used by cheat clients to bypass anti-cheat systems.<br>
        <strong>Remediation:</strong> Remove the -javaagent argument from your launcher configuration.
    </p>
    </div>"
}

# Minecraft Process JVM Arguments Section
if ($minecraftProcessesInfo.Count -gt 0) {
    $htmlReport += "<div class='section'>
        <h2>[PROCESS INFO] Minecraft JVM Arguments ($($minecraftProcessesInfo.Count))</h2>
        <table>
            <thead>
                <tr>
                    <th>Process</th>
                    <th>PID</th>
                    <th>Start Time</th>
                    <th>User-Specified JVM Arguments</th>
                </tr>
            </thead>
            <tbody>"
    
    foreach ($procInfo in $minecraftProcessesInfo) {
        $startTimeFormatted = Get-Date $procInfo.StartTime -Format 'yyyy-MM-dd HH:mm:ss'
        
        # Build badges for security issues
        $badges = ""
        if ($procInfo.HasFabricAddMods) { 
            $badges += "<span class='badge badge-warning'>Fabric AddMods</span> " 
        }
        if ($procInfo.HasJavaAgent) {
            $badges += "<span class='badge' style='background: var(--danger); color: white;'>Java Agent</span> "
        }
        
        # Extract only user-specified arguments (filter out standard launcher args)
        $userArgs = @()
        if ($procInfo.CommandLine) {
            # Split command line into parts
            $parts = $procInfo.CommandLine -split '\s+'
            
            # Filter for user-relevant arguments
            foreach ($part in $parts) {
                # Include @argfile paths, javaagent, custom system properties, and JVM flags
                if ($part -match '^@' -or $part -match '^-javaagent:') {
                    # Include @argfile references and javaagent (these are user-modifiable)
                    $userArgs += $part
                }
                elseif ($part -match '^-D(?!java\.|jna\.|org\.lwjgl|io\.netty|minecraft\.launcher|log4j|sun\.|file\.|user\.|os\.|FabricMcEmu|modrinth\.internal\.)') {
                    # Include custom system properties but exclude standard Java/Minecraft/Launcher ones
                    $userArgs += $part
                }
                elseif ($part -match '^-X' -or $part -match '^-XX:') {
                    # Include memory and JVM flags (these are typically user-configured)
                    $userArgs += $part
                }
            }
        }
        
        $argsDisplay = if ($userArgs.Count -gt 0) {
            # Escape HTML special characters
            $escapedArgs = $userArgs | ForEach-Object { 
                $_ -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;'
            }
            $displayString = $escapedArgs -join ' '
            
            # Highlight javaagent in red
            if ($displayString -match 'javaagent') {
                $displayString = $displayString -replace '(-javaagent:[^\s]+)', '<span style="color: var(--danger); font-weight: bold;">$1</span>'
            }
            
            # Highlight argfile references in blue
            if ($displayString -match '@[^\s]+') {
                $displayString = $displayString -replace '(@[^\s]+)', '<span style="color: #0066cc; font-weight: bold;">$1</span>'
            }
            
            # Highlight fabric.addMods in orange
            if ($displayString -match '-Dfabric\.addMods') {
                $displayString = $displayString -replace '(-Dfabric\.addMods=[^\s]+)', '<span style="color: #e67e22; font-weight: bold;">$1</span>'
            }
            
            $displayString
        } else {
            "<em style='color: var(--success);'>No custom arguments</em>"
        }
        
       $htmlReport += "<tr>
            <td>${badges}$($procInfo.ProcessName)</td>
            <td>$($procInfo.ProcessId)</td>
            <td>$startTimeFormatted</td>
            <td style='font-family: monospace; font-size: 0.75rem; word-break: break-all;'>$argsDisplay</td>
        </tr>"
    }
    
   $htmlReport += "</tbody></table></div>"
}

# File Attribute Manipulation Section
if ($attributeManipulatedMods.Count -gt 0) {
    $htmlReport += "<div class='section'>
        <h2>[ATTR BYPASS] Hidden/Manipulated Files ($($attributeManipulatedMods.Count))</h2>
        <p style='color: var(--danger); font-weight: bold;'>WARNING: Files using 'attrib -h/+h' or similar attribute manipulation detected!</p>
        <table>
            <thead>
                <tr>
                    <th>File</th>
                    <th>Product</th>
                    <th>Attributes</th>
                    <th>Bypass Method</th>
                </tr>
            </thead>
            <tbody>"
    
    foreach ($mod in $attributeManipulatedMods) {
        $bypassMethods = @()
        if ($mod.IsHidden) { $bypassMethods += "attrib +h" }
        if ($mod.IsSystem) { $bypassMethods += "attrib +s" }
        
        $htmlReport += "<tr class='attribute-row'>
            <td style='font-family: monospace;'>$($mod.FileName)</td>
            <td>$($mod.ModName)</td>
            <td style='color: #e67e22; font-weight: bold;'>$($mod.Attributes)</td>
            <td style='color: var(--danger);'>$($bypassMethods -join ', ')</td>
        </tr>"
    }
    
    $htmlReport += "</tbody></table>
    </div>"
}

# Suspicious Attribute Files Section (non-mod files)
if ($suspiciousAttributeFiles.Count -gt 0) {
    $htmlReport += "<div class='section'>
        <h2>[HIDDEN FILES] Other Files with Manipulated Attributes ($($suspiciousAttributeFiles.Count))</h2>
        <table>
            <thead>
                <tr>
                    <th>File</th>
                    <th>Path</th>
                    <th>Attributes</th>
                </tr>
            </thead>
            <tbody>"
    
    foreach ($file in $suspiciousAttributeFiles) {
        $attrFlags = @()
        if ($file.IsHidden) { $attrFlags += "HIDDEN" }
        if ($file.IsSystem) { $attrFlags += "SYSTEM" }
        if ($file.IsReadOnly) { $attrFlags += "READONLY" }
        
        $htmlReport += "<tr class='attribute-row'>
            <td style='font-family: monospace;'>$($file.FileName)</td>
            <td style='font-family: monospace; font-size: 0.8rem;'>$($file.FilePath)</td>
            <td style='color: #e67e22; font-weight: bold;'>$($attrFlags -join ', ')</td>
        </tr>"
    }
    
    $htmlReport += "</tbody></table></div>"
}

# Verified Mods Section
if ($verifiedMods.Count -gt 0) {
    $htmlReport += "<div class='section'>
        <h2>[VERIFIED] Modules ($($verifiedMods.Count))</h2>
        <table>
            <thead>
                <tr>
                    <th>Module Name</th>
                    <th>File</th>
                    <th>Version</th>
                    <th>Loader</th>
                    <th>Source</th>
                    <th>Integrity</th>
                </tr>
            </thead>
            <tbody>"
    
   foreach ($mod in $verifiedMods) {
        $isSuspicious = $suspiciousMods.FileName -contains $mod.FileName
        $isTampered = $tamperedMods.FileName -contains $mod.FileName
        
        $rowClass = if ($isTampered) { "tampered-row" } elseif ($isSuspicious) { "suspicious-row" } else { "verified-row" }
        
        $statusBadge = if ($isTampered) { 
            "<span class='badge badge-magenta'>INTEGRITY FAIL</span>" 
        } elseif ($isSuspicious) { 
            "<span class='badge badge-warning'>SIGNATURE MATCH</span>" 
        } else { 
            "<span class='badge badge-success'>VERIFIED</span>" 
        }
        
        $integrityStatus = if ($mod.ExpectedSize -gt 0) {
           if ($mod.ActualSize -eq $mod.ExpectedSize) {
                "<span style='color: var(--success);'>[VERIFIED] ($($mod.ActualSizeKB) KB)</span>"
            } else {
                $sign = if ($mod.SizeDiffKB -gt 0) { "+" } else { "" }
                $color = if ($isTampered) { "var(--magenta)" } else { "var(--warning)" }
                "<span style='color: $color;'>[MODIFIED] ($($mod.ActualSizeKB) KB, Change: $sign$($mod.SizeDiffKB) KB)</span>"
            }
        } else {
            "<span style='color: var(--info);'>[?]</span>"
        }
        
        $loaderColor = if ($mod.LoaderType -eq "Fabric") { "var(--magenta)" } else { "var(--warning)" }
        
        $htmlReport += "<tr class='$rowClass'>
            <td>$statusBadge $($mod.ModName)</td>
            <td style='font-family: monospace; font-size: 0.9rem;'>$($mod.FileName)</td>
            <td>$($mod.Version)</td>
            <td style='color: $loaderColor;'>$($mod.LoaderType)</td>
            <td>$($mod.DownloadSource)</td>
            <td>$integrityStatus</td>
        </tr>"
    }
    
    $htmlReport += "</tbody></table></div>"
}

# Unknown Mods Section
if ($unknownMods.Count -gt 0) {
    $htmlReport += "<div class='section'>
        <h2>[UNKNOWN] Modules ($($unknownMods.Count))</h2>
        <table>
            <thead>
                <tr>
                    <th>File</th>
                    <th>Source</th>
                    <th>Size</th>
                </tr>
            </thead>
            <tbody>"
    
   foreach ($mod in $unknownMods) {
        $sourceText = if ($mod.DownloadSource) { $mod.DownloadSource } else { "Unknown" }
        $htmlReport += "<tr class='unknown-row'>
            <td style='font-family: monospace;'>$($mod.FileName)</td>
            <td>$sourceText</td>
            <td>$($mod.FileSizeKB) KB</td>
        </tr>"
    }
    
    $htmlReport += "</tbody></table></div>"
}

# Suspicious Mods Section
if ($suspiciousMods.Count -gt 0) {
    $htmlReport += "<div class='section'>
        <h2>[ALERT] Suspicious Patterns ($($suspiciousMods.Count))</h2>
        <table>
            <thead>
                <tr>
                    <th>File</th>
                    <th>Product</th>
                    <th>Detected Patterns</th>
                </tr>
            </thead>
            <tbody>"
    
   foreach ($mod in $suspiciousMods) {
        $patternsList = ($mod.DetectedPatterns | Sort-Object) -join ", "
        $productName = if ($mod.ModName) { $mod.ModName } else { "Unknown" }
        
        # Add attribute bypass warning if applicable
        $attributeWarning = ""
        if ($mod.HasAttributeBypass) {
            $attributeWarning = " <span class='badge badge-orange'>ATTRIB BYPASS</span>"
        }
        
        $htmlReport += "<tr class='suspicious-row'>
            <td style='font-family: monospace;'>$($mod.FileName)$attributeWarning</td>
            <td>$productName</td>
            <td style='color: var(--danger); font-weight: bold;'>$patternsList</td>
        </tr>"
    }
    
    $htmlReport += "</tbody></table></div>"
}

# Bypass/Injection Section
if ($bypassMods.Count -gt 0) {
    $htmlReport += "<div class='section'>
        <h2 style='color: #9b59b6;'>[BYPASS/INJECTION] Advanced Threat Detection ($($bypassMods.Count))</h2>
        <p style='color: #9b59b6; font-weight: bold;'>WARNING: These mods use advanced bypass techniques or code injection!</p>
        <table>
            <thead>
                <tr>
                    <th>File</th>
                    <th>Threat Flags</th>
                </tr>
            </thead>
            <tbody>"
    
    foreach ($mod in $bypassMods) {
        foreach ($flag in $mod.Flags) {
            $flagTitle = if ($flag -match "^(.+?) - (.+)$") { $matches[1] } else { $flag }
            $flagDesc = if ($flag -match "^(.+?) - (.+)$") { $matches[2] } else { "" }
            
            $flagColor = switch -regex ($flag) {
                "Runtime\.exec" { "#e74c3c"; break }  # Red - Critical
                "HTTP file download" { "#e67e22"; break }  # Orange - High
                "HTTP POST" { "#e67e22"; break }  # Orange - High
                "Heavy obfuscation" { "#f39c12"; break }  # Yellow - Medium
                "Suspicious nested JAR" { "#f39c12"; break }  # Yellow - Medium
                "Numeric class" { "#f39c12"; break }  # Yellow - Medium
                "Unicode class" { "#f39c12"; break }  # Yellow - Medium
                "Fake mod identity" { "#e74c3c"; break }  # Red - Critical
                default { "#9b59b6"; break }  # Purple - Default
            }
            
            $htmlReport += "<tr style='border-left: 4px solid $flagColor; background: linear-gradient(135deg, #f5eef8 0%, #ebdef0 100%) !important;'>
                <td style='font-family: monospace;'>$($mod.FileName)</td>
                <td>
                    <div style='margin-bottom: 8px;'>
                        <strong style='color: $flagColor;'>● $flagTitle</strong>
                    </div>"
            
            if ($flagDesc) {
                $htmlReport += "<div style='color: #7f8c8d; font-size: 0.9rem; padding-left: 20px;'>$flagDesc</div>"
            }
            
            $htmlReport += "</td></tr>"
        }
    }
    
    $htmlReport += "</tbody></table>
    <p style='margin-top: 15px; padding: 10px; background: #f5eef8; border-left: 4px solid #9b59b6;'>
        <strong>ANALYSIS:</strong> These detection methods identify sophisticated threats including:<br>
        • Runtime command execution (can run arbitrary OS commands)<br>
        • HTTP downloaders (fetches malicious payloads at runtime)<br>
        • Data exfiltration (steals system information)<br>
        • Heavy obfuscation (hides malicious code)<br>
        • Fake mod identities (impersonates legitimate mods)
    </p>
    </div>"
}

# Tampered Mods Section
if ($tamperedMods.Count -gt 0) {
    $htmlReport += "<div class='section'>
        <h2>[INTEGRITY FAIL] Modified Files ($($tamperedMods.Count))</h2>
        <table>
            <thead>
                <tr>
                    <th>File</th>
                    <th>Product</th>
                    <th>Loader</th>
                    <th>Size Change</th>
                </tr>
            </thead>
            <tbody>"
    
   foreach ($mod in $tamperedMods) {
        $sign = if ($mod.SizeDiffKB -gt 0) { "+" } else { "" }
        $loaderColor = if ($mod.LoaderType -eq "Fabric") { "var(--magenta)" } else { "var(--warning)" }
        
        $htmlReport += "<tr class='tampered-row'>
            <td style='font-family: monospace;'>$($mod.FileName)</td>
            <td>$($mod.ModName)</td>
            <td style='color: $loaderColor;'>$($mod.LoaderType)</td>
            <td style='color: var(--magenta); font-weight: bold;'>Expected: $($mod.ExpectedSizeKB) KB -&gt; Current: $($mod.ActualSizeKB) KB ($sign$($mod.SizeDiffKB) KB)</td>
        </tr>"
    }
    
    $htmlReport += "</tbody></table></div>"
}

# Disallowed Mods Section
if ($disallowedModsFound.Count -gt 0) {
    $htmlReport += "<div class='section'>
        <h2 style='color: var(--danger);'>[DISALLOWED] Server-Banned Modules ($($disallowedModsFound.Count))</h2>
        <p style='color: var(--danger); font-weight: bold;'>WARNING: These mods are commonly disallowed on servers!</p>
        <table>
            <thead>
                <tr>
                    <th>File</th>
                    <th>Module Name</th>
                </tr>
            </thead>
            <tbody>"
    
    foreach ($mod in $disallowedModsFound) {
        $htmlReport += "<tr class='suspicious-row'>
            <td style='font-family: monospace;'>$($mod.FileName)</td>
            <td style='color: var(--danger); font-weight: bold;'>$($mod.ModName)</td>
        </tr>"
    }
    
    $htmlReport += "</tbody></table>
    <p style='margin-top: 15px; padding: 10px; background: #fff3cd; border-left: 4px solid #e67e22;'>
        <strong>INFO:</strong> These modules may be allowed on some servers but are often banned. Check your server rules before using.
    </p>
    </div>"
}

$htmlReport += @"
<footer class='footer'>
    <p><strong>Valor Mod Analyzer v3.0 Enhanced</strong></p>
    <p>Developed by: DrValor</p>
</footer>
</div>
</body>
</html>
"@

try {
    $htmlReport | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
} catch {
    # Silent error
}

try {
    Start-Process $OutputPath
} catch {
    # Silently fail
}
