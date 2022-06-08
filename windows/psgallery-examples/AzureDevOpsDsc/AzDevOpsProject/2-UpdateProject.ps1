
<#
    .DESCRIPTION
        This example shows how to ensure that an Azure DevOps project
        with a ProjectName of 'Test Project' can have it's description
        updated to 'A Test Project with a new description'.
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
        AzDevOpsProject 'UpdateProject'
        {
            Ensure               = 'Present'

            ApiUri               = $ApiUri
            Pat                  = $Pat

            ProjectName          = 'Test Project'
            ProjectDescription   = 'A Test Project with a new description'  # Updated property


            #SourceControlType    = 'Git'  # Note: Update of this property is not supported

        }

    }
}
