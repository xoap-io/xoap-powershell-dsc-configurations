$output = 'C:\Example\MOF'

Configuration Example
{
    Import-DscResource -ModuleName 7ZipArchiveDsc
    Node localhost
    {
        x7ZipArchive sample1 {
            Path        = 'C:\sample.zip'
            Destination = 'C:\Destination'
            Validate    = $true
            Checksum    = 'Size'
            Clean       = $true
        }
    }
}

Example -OutputPath $output
Start-DscConfiguration -Path  $output -Verbose -wait

Remove-DscConfigurationDocument -Stage Previous, Pending, Current -Force
Remove-Item $output -Recurse -Force
