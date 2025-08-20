function Test-GalleryModuleUpdate
{
    param
    (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]
        [string]
        $Name,

        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]
        [version]
        $Version,

        [switch]
        $NeedUpdateOnly

    )
    
    process
    {
        $URL = "https://www.powershellgallery.com/packages/$Name" 
        $page = try {
                Invoke-WebRequest -Uri $URL -UseBasicParsing -MaximumRedirection 0 -ea SilentlyContinue -ErrorVariable b
                }
                catch {}
        [version]$latest = Split-Path -Path $b.InnerException.Response.Headers.Location -Leaf
        $needsupdate = $Latest -gt $Version

        if ($needsupdate -or (!$NeedUpdateOnly.IsPresent))
        {
            [PSCustomObject]@{
                ModuleName = $Name
                CurrentVersion = $Version
                LatestVersion = $Latest
                NeedsUpdate = $needsupdate
            }
        }
    }
}

Get-InstalledModule | Where-Object Repository -eq PSGallery | Test-GalleryModuleUpdate #-NeedUpdateOnly
  