
<#
    .DESCRIPTION
        This example shows how to delete a project called 'Test Project'.
#>

Configuration Example"
{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $ApiUri,

        [Parameter(Mandatory = $true)]
        [string]
        $Pat
    )

    Import-DscResource -ModuleName 'AzureDevOpsDsc'

    node localhost
    {

        AzDevOpsProject 'DeleteProject'
        {
            Ensure               = 'Absent'  # 'Absent' ensures this will be removed/deleted

            ApiUri               = $ApiUri
            Pat                  = $Pat

            ProjectName          = 'Test Project'  # Identifies the name of the project to be deleted
        }

    }
}
