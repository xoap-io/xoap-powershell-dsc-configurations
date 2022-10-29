# folders where PowerShell looks for modules:
$paths = $env:PSModulePath -split ';'
# finding actual module folders
$modules = Get-ChildItem -Path $paths -Depth 0 -Directory | Sort-Object -Property Name

$modules | 
  Select-Object -Property Name, @{N='Parent';E={$_.Parent.FullName}}, FullName |
  Out-GridView -Title 'Select module(s) to permanently delete' -PassThru |
  Out-GridView -Title 'Do you REALLY want to remove the modules below? CTRL+A and OK to confirm' -PassThru |
  Remove-Item -Path { $_.FullName } -Recurse -Force -WhatIf # remove -WhatIf to actually delete (as always at own risk)
  