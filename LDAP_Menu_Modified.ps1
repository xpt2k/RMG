<#
	.SYNOPSIS
		This is a menu driven set of script for managing RED LDAP

	.DESCRIPTION
		This is a menu driven set of script for managing RED LDAP

	.PARAMETER NoCache
		Do not cache LDAP users and groups
#>
Param
(
    [switch]$NoCache
)

########## Global Variables ##########

$Global:LDAPBasePath = "\\EPCRMG483.rmgp.royalmailgroup.net\LDAPMenu$"

$Global:LDAPLogFolder = Join-Path -Path $Global:LDAPBasePath -ChildPath Logs
$Global:LDAPLogFile = Join-Path -Path $Global:LDAPLogFolder -ChildPath ($(Get-Date -Format yyyyMMdd) + "_LDAPLogs.CSV")
$Global:LDAPLogFile_Operation = Join-Path -Path $Global:LDAPLogFolder -ChildPath ($($Env:USERNAME) + "_LDAPLogs.CSV")

$Global:LDIFFolder = Join-Path -Path $Global:LDAPBasePath -ChildPath LDIF
$Global:LDIFLogFolder = Join-Path -Path $Global:LDIFFolder -ChildPath Logs
$Global:LDIFArchive = Join-Path -Path $Global:LDIFFolder -ChildPath Archive

$Global:ADSearchBase_RED = "OU=RED,DC=red,DC=royalmailgroup,DC=net"
$Global:ADSearchBase_Groups = "OU=Groups,OU=Operations,OU=RED,DC=red,DC=royalmailgroup,DC=net"

########## Load Assemblies ##########

[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")

########## Menu Functions ##########
function DrawMenu {
    param ($menuItems, $menuPosition, $Multiselect, $selection)
    $l = $menuItems.length
    for ($i = 0; $i -le $l; $i++) {
        # if ($menuItems[$i] -ne $null){
        if ($null -ne $menuItems[$i]) {
            $item = $menuItems[$i]
            if ($Multiselect) {
                if ($selection -contains $i) {
                    $item = '[x] ' + $item
                }
                else {
                    $item = '[ ] ' + $item
                }
            }
            if ($i -eq $menuPosition) {
                Write-Host "> $($item)" -ForegroundColor Green
            }
            else {
                Write-Host "  $($item)"
            }
        }
    }
}

function Toggle-Selection {
    param ($pos, [array]$selection)
    if ($selection -contains $pos) {
        $result = $selection | Where-Object { $_ -ne $pos }
    }
    else {
        $selection += $pos
        $result = $selection
    }
    $result
}

function Menu {
    param ([array]$menuItems, [switch]$ReturnIndex = $false, [switch]$Multiselect)
    $vkeycode = 0
    $pos = 0
    $selection = @()
    $cur_pos = [System.Console]::CursorTop
    [console]::CursorVisible = $false #prevents cursor flickering
    if ($menuItems.Length -gt 0) {
        DrawMenu $menuItems $pos $Multiselect $selection
        # While ($vkeycode -ne 13 -and $vkeycode -ne 27) {
        While (($vkeycode -ne 13) -and ($vkeycode -ne 27)) {
            $press = $host.ui.rawui.readkey("NoEcho,IncludeKeyDown")
            $vkeycode = $press.virtualkeycode
            If ($vkeycode -eq 38 -or $press.Character -eq 'k') {
                $pos--
            }
            If ($vkeycode -eq 40 -or $press.Character -eq 'j') {
                $pos++
            }
            If ($press.Character -eq ' ') {
                $selection = Toggle-Selection $pos $selection
            }
            if ($pos -lt 0) {
                $pos = 0
            }
            If ($vkeycode -eq 27) {
                $pos = $null
            }
            if ($pos -ge $menuItems.length) {
                $pos = $menuItems.length - 1
            }
            if ($vkeycode -ne 27) {
                [System.Console]::SetCursorPosition(0, $cur_pos)
                DrawMenu $menuItems $pos $Multiselect $selection
            }
        }
    }
    else {
        $pos = $null
    }
    [console]::CursorVisible = $true

    # if ($ReturnIndex -eq $false -and $pos -ne $null)
    if (($ReturnIndex -eq $false) -and ($null -ne $pos)) {
        if ($Multiselect) {
            return $menuItems[$selection]
        }
        else {
            return $menuItems[$pos]
        }
    }
    else {
        if ($Multiselect) {
            return $selection
        }
        else {
            return $pos
        }
    }
}

########## GUI Configs ##########

# LDIF File Browser
$LDIFBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{
    Multiselect = $true # Multiple files can be chosen
    Filter      = 'LDIF Files (*.LDIF;*.TXT)|*.LDIF;*.TXT' # Specified file types
}

# Textbox
$Form = New-Object System.Windows.Forms.Form
# $Form.Size = New-Object System.Drawing.Size(300,250)
$Form.Size = New-Object System.Drawing.Size(800, 600)
$Form.StartPosition = "CenterScreen"
$Form.KeyPreview = $True
$Form.Topmost = $True
$Form.FormBorderStyle = 'Fixed3D'
$Form.MaximizeBox = $false
$Form.Add_KeyDown( {
        if ($_.Control -eq $True -and $_.KeyCode -eq "A") {
            $TextBox.SelectAll()
            $_.SuppressKeyPress = $True
        }
    })

$Ok = New-Object System.Windows.Forms.Button
# $Ok.Location = New-Object System.Drawing.Size(50,180)
$Ok.Location = New-Object System.Drawing.Size(50, 530)
$Ok.Size = New-Object System.Drawing.Size(75, 25)
$Ok.Text = "OK"
$Ok.DialogResult = [System.Windows.Forms.DialogResult]::OK

$Cancel = New-Object System.Windows.Forms.Button
# $Cancel.Location = New-Object System.Drawing.Size(165,180)
$Cancel.Location = New-Object System.Drawing.Size(675, 530)
$Cancel.Size = New-Object System.Drawing.Size(75, 25)
$Cancel.Text = "Cancel"
$Cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel

$TextBox = New-Object System.Windows.Forms.TextBox
$TextBox.Location = New-Object System.Drawing.Size(10, 10)
# $TextBox.Size = New-Object System.Drawing.Size(270,150)
$TextBox.Size = New-Object System.Drawing.Size(770, 500)
$TextBox.AcceptsReturn = $true
$TextBox.AcceptsTab = $false
$TextBox.Multiline = $true
$TextBox.ScrollBars = 'Both'
$TextBox.WordWrap = $False

$Form.Controls.Add($Ok)
$Form.Controls.Add($Cancel)
$Form.Controls.Add($TextBox)
$Form.AcceptButton = $Ok
$Form.CancelButton = $Cancel

########## Support Functions ##########

Function Set-Title {
    $Host.UI.RawUI.WindowTitle = $args
}

Function Out-LogFile {
    Param
    (
        [string]$Result,
        [string]$Message
    )

    # Create base log object, Result property to be added during process
    $Log = New-Object PSObject -Property @{
        "Date"  = Get-Date -Format yyyy-MM-dd
        "Time"  = Get-Date -Format HH:mm
        "RunBy" = $Env:USERNAME
    }

    # Append Result and Message property to base log object
    Add-Member -InputObject $Log -MemberType NoteProperty -Name 'Result' -Value $Result
    Add-Member -InputObject $Log -MemberType NoteProperty -Name 'Message' -Value $Message

    # Update Daily Log file
    $Log | Export-CSV -Path $Global:LDAPLogFile -Append -NoTypeInformation

    # Update Operational Log
    $Log | Export-CSV -Path $Global:LDAPLogFile_Operation -Append -NoTypeInformation
}

Function Read-HostArray {
    $Form.Text = $args
    $Form.Add_Shown( { $Form.Activate(); $TextBox.focus() })
    $DialogResult = $Form.ShowDialog()

    if ($DialogResult -eq [System.Windows.Forms.DialogResult]::OK) {
        $Output = $TextBox.Text.Split("`n") | ForEach-Object { $_.TrimEnd() } | Where-Object { $_ }
        $TextBox.Text = ""
        Return $Output
    }
}

Function Read-LDIFPaths {
    [void]$LDIFBrowser.ShowDialog()
    Return $LDIFBrowser.FileNames
}

Function Invoke-LDIF_File {

    $LDIF_Files = Read-LDIFPaths

    Foreach ($LDIF_File in $LDIF_Files) {

        # Capture Date Stamp for files
        $DateStamp = Get-Date -Format yyyyMMdd_HHmmss

        # Paths to LDIF related Files
        $LDIFOutput_err = Join-Path -Path $Global:LDIFFolder -ChildPath "ldif.err"
        $LDIFOutput_log = Join-Path -Path $Global:LDIFFolder -ChildPath "ldif.log"
        $LDIFLog_err = Join-Path -Path $Global:LDIFLogFolder -ChildPath ($DateStamp + "_LDIF.err")
        $LDIFLog_log = Join-Path -Path $Global:LDIFLogFolder -ChildPath ($DateStamp + "_LDIF.log")

        # Run LDIF Import
        Ldifde -i -f $LDIF_File -s localhost:636 -j $Global:LDIFFolder

        # Archive Logs
        Move-Item -Path $LDIF_File -Destination $Global:LDIFArchive
        Move-Item -Path $LDIFOutput_err -Destination $LDIFLog_err
        Move-Item -Path $LDIFOutput_log -Destination $LDIFLog_log

        # Sleep for 1 second to ensure no files are overwritten
        Start-Sleep -Seconds 1
    }
}

Function Invoke-LDIF_Config {

    # Capture Date Stamp for files
    $DateStamp = Get-Date -Format yyyyMMdd_HHmmss

    # Paths to LDIF related Files
    $LDIF_File = Join-Path -Path $Global:LDIFFolder -ChildPath ($DateStamp + "_LDIF.LDIF")

    $LDIFOutput_err = Join-Path -Path $Global:LDIFFolder -ChildPath "ldif.err"
    $LDIFOutput_log = Join-Path -Path $Global:LDIFFolder -ChildPath "ldif.log"
    $LDIFLog_err = Join-Path -Path $Global:LDIFLogFolder -ChildPath ($DateStamp + "_LDIF.err")
    $LDIFLog_log = Join-Path -Path $Global:LDIFLogFolder -ChildPath ($DateStamp + "_LDIF.log")

    # Create LDIF File from User Input
    Set-Content -Path $LDIF_File -Value (Read-HostArray Enter LDIF Config)

    # Run LDIF Import
    Ldifde -i -f $LDIF_File -s localhost:636 -j $Global:LDIFFolder

    # Archive Logs
    Move-Item -Path $LDIF_File -Destination $Global:LDIFArchive
    Move-Item -Path $LDIFOutput_err -Destination $LDIFLog_err
    Move-Item -Path $LDIFOutput_log -Destination $LDIFLog_log

    # View Result of Process
    (Get-Content -Path $LDIFLog_log) -NotMatch '^\s*$' | Out-GridView -Title "Results of LDIF Import"
}

Function Import-LDAPCache {


    Import-Module ActiveDirectory

    Set-Title PreLoading LDAP Users... Please wait...

    $Global:Cache_Users = (Get-ADUser -filter { ObjectClass -eq 'RMGPerson' } -Server localhost:389 -SearchBase $Global:ADSearchBase_RED).DistinguishedName

    Set-Title PreLoading LDAP Groups... Please wait...

    $Global:Cache_Groups = (Get-ADGroup -filter * -Server localhost:389 -SearchBase $Global:ADSearchBase_Groups).DistinguishedName

    [GC]::Collect()

    Set-Title LDAP Menu
}

Function Set-MenuOptions {
    If ($Global:FullMenu) {
        $Global:Menu_Main = @(
            "User Selection"
            "Group Selection"
            "Mass Updates"
            "Quick Actions"
            "LDIF Operations"
            "Exit"
        )
    }
    Else {
        $Global:Menu_Main = @(
            "Quick Actions"
            "LDIF Operations"
            "Exit"
        )
    }
}

########## Menu Structure ##########

$Menu_Selection = @(
    "Add from Search"
    "Add from Clipboard"
    "View/Filter Current Selection"
    "Clear Selection"
    "Back"
)

$Menu_MassUpdates = @(
    "Add Users to Groups"
    "Remove Users from Groups"
    "Enable User Accounts"
    "Disable User Accounts"
    "Back"
)

$Menu_Actions = @(
    "New LDAP users: Create, Enable and Modify Group Memberships"
    "Reset a User's Password"
    "Unlock a User's Account"
    "Enable a User's Account"
    "Disable a User's Account"
    "Process Group Assignments (CSV Import)"
    "Enable/Disable Full Menu"
    "Re-import LDAP Users/Groups"
    "Back"
)

$Menu_LDIF = @(
    "Process from Clipboard"
    "Process from File"
    "View Logs"
    "Back"
)

Function Show-LDAPMenu {
    Clear-Host
    ## Display Information

    If ($Global:FullMenu) {
        Write-Host Selected Users : ($Global:UserVar).Count
        Write-Host Selected Groups : ($Global:GroupVar).Count
    }

    Switch (Menu $Global:Menu_Main) {
        "User Selection" {
            Clear-Host
            Switch (Menu $Menu_Selection) {
                "Add from Search" {
                    $Global:UserVar += @($Global:Cache_Users | Out-GridView -OutPutMode Multiple -Title "Select Users to Target for Mass Updates")
                    Show-LDAPMenu
                }
                "Add from Clipboard" {
                    $Global:UserVar += Read-HostArray "Enter DNs to be added to User Selection"
                    Show-LDAPMenu
                }
                "View/Filter Current Selection" {
                    $Temp = $Global:UserVar | Out-GridView -OutPutMode Multiple -Title "Currently Targeted Users for Mass Updates"
                    If ($Temp) {
                        $Global:UserVar = $Temp
                        Clear-Variable Temp
                    }
                    Show-LDAPMenu
                }
                "Clear Selection" {
                    Clear-Variable -Scope Global -Name UserVar
                    Show-LDAPMenu
                }
                "Back" {
                    Show-LDAPMenu
                }
            }
        }
        "Group Selection" {
            Clear-Host
            Switch (Menu $Menu_Selection) {
                "Add from Search" {
                    $Global:GroupVar += @($Global:Cache_Groups | Out-GridView -OutPutMode Multiple -Title "Select Groups to Target for Mass Updates")
                    Show-LDAPMenu
                }
                "Add from Clipboard" {
                    $Global:GroupVar += Read-HostArray "Enter DNs to be added to Group Selection"
                    Show-LDAPMenu
                }
                "View/Filter Current Selection" {
                    $Temp = $Global:GroupVar | Out-GridView -OutPutMode Multiple -Title "Currently Targeted Groups for Mass Updates"
                    If ($Temp) {
                        $Global:GroupVar = $Temp
                        Clear-Variable Temp
                    }
                    Show-LDAPMenu
                }
                "Clear Selection" {
                    Clear-Variable -Scope Global -Name GroupVar
                    Show-LDAPMenu
                }
                "Back" {
                    Show-LDAPMenu
                }
            }
        }
        "Mass Updates" {
            Clear-Host
            Switch (Menu $Menu_MassUpdates) {
                "Add Users to Groups" {
                    ForEach ($Group in $Global:GroupVar) {
                        ForEach ($User in $Global:UserVar) {

                            Add-ADGroupMember -Identity $Group -members $User -Server localhost:389

                            If ((Get-ADUser -Identity $User -Properties MemberOf -Server localhost:389).MemberOf -eq $Group) {
                                Out-LogFile -Result "Success" -Message "Add $($User) to $($Group)"
                            }
                            Else {
                                Out-LogFile -Result "Failed" -Message "Add $($User) to $($Group)"
                            }
                        }
                    }
                    # Display Results
                    Import-CSV $Global:LDAPLogFile_Operation | Out-GridView -Title "Results of Adding Users to Groups"
                    Remove-Item -Path $Global:LDAPLogFile_Operation
                    Show-LDAPMenu
                }
                "Remove Users from Groups" {
                    ForEach ($Group in $Global:GroupVar) {
                        ForEach ($User in $Global:UserVar) {
                            Remove-ADGroupMember -Identity $Group -members $User -server localhost:389 -Confirm:$false

                            If ((Get-ADUser -Identity $User -Properties MemberOf -Server localhost:389).MemberOf -eq $Group) {
                                Out-LogFile -Result "Failed" -Message "Remove $($User) from $($Group)"
                            }
                            Else {
                                Out-LogFile -Result "Success" -Message "Remove $($User) from $($Group)"
                            }
                        }
                    }
                    # Display Results
                    Import-CSV $Global:LDAPLogFile_Operation | Out-GridView -Title "Results of Removing Users from Groups"
                    Remove-Item -Path $Global:LDAPLogFile_Operation
                    Show-LDAPMenu
                }
                "Enable User Accounts" {
                    ForEach ($User in $Global:UserVar) {
                        Get-ADuser $User -Server LocalHost:389 | Enable-ADAccount

                        If ((Get-ADuser $User -Server LocalHost:389).Enabled) {
                            Out-LogFile -Result "Success" -Message "Enable $($User)"
                        }
                        Else {
                            Out-LogFile -Result "Failed" -Message "Enable $($User)"
                        }
                    }
                    # Display Results
                    Import-CSV $Global:LDAPLogFile_Operation | Out-GridView -Title "Results for Enabling User Accounts"
                    Remove-Item -Path $Global:LDAPLogFile_Operation
                    Show-LDAPMenu
                }
                "Disable User Accounts" {
                    ForEach ($User in $Global:UserVar) {
                        Get-ADuser $User -Server LocalHost:389 | Disable-ADAccount

                        If ((Get-ADuser $User -Server LocalHost:389).Enabled) {
                            Out-LogFile -Result "Failed" -Message "Disable $($User)"
                        }
                        Else {
                            Out-LogFile -Result "Success" -Message "Disable $($User)"
                        }
                    }
                    # Display Results
                    Import-CSV $Global:LDAPLogFile_Operation | Out-GridView -Title "Results for Disabling User Accounts"
                    Remove-Item -Path $Global:LDAPLogFile_Operation
                    Show-LDAPMenu
                }
                "Back" {
                    Show-LDAPMenu
                }
            }
        }
        "Quick Actions" {
            Clear-Host
            Switch (Menu $Menu_Actions) {
                "New LDAP users: Create, Enable and Modify Group Memberships" {
                    # Create LDAP users from clipboard
                    Invoke-LDIF_Config

                    # Enable User Accounts in AD and add them to the specified security groups from clipboard
                    $GroupConfig = ConvertFrom-CSV (Read-HostArray Enter Group Assignment Data) -Delimiter "`t"
                    foreach ($Entry in $GroupConfig) {
                        $User = $Entry.userDN
                        $Group = $Entry.groupDN

                        Get-ADuser $User -Server LocalHost:389 | Enable-ADAccount -Server localhost:389
                        Add-ADGroupMember -Identity $Group -members $User -Server localhost:389

                        If (((Get-ADuser $User -Server LocalHost:389).Enabled) -and ((Get-ADUser -Identity $User -Properties MemberOf -Server localhost:389).MemberOf -eq $Group)) {
                            Out-LogFile -Result "Success" -Message "$($User) enabled and added to $($Group)"
                        }
                        elseif ((!(Get-ADuser $User -Server LocalHost:389).Enabled) -and ((Get-ADUser -Identity $User -Properties MemberOf -Server localhost:389).MemberOf -eq $Group)) {
                            Out-LogFile -Result "Partially Failed" -Message "$($User) not enabled, but added to $($Group)"
                        }
                        elseif (((Get-ADuser $User -Server LocalHost:389).Enabled) -and (!(Get-ADUser -Identity $User -Properties MemberOf -Server localhost:389).MemberOf -eq $Group)) {
                            Out-LogFile -Result "Partially Failed" -Message "$($User) enabled, but not added to $($Group)"
                        }
                        Else {
                            Out-LogFile -Result "Failed" -Message "$($User) not enabled and not added to $($Group)"
                        }
                    }

                    # Display Results
                    Import-CSV $Global:LDAPLogFile_Operation | Out-GridView -Title "User Enablement / Group Membership Modification Results"
                    Remove-Item -Path $Global:LDAPLogFile_Operation
                    Show-LDAPMenu
                }
                "Reset a User's Password" {
                    $User = $Global:Cache_Users | Out-GridView -OutputMode Single -Title "Select a User to Reset the Password for"
                    Set-ADAccountPassword -server localhost:389 -Identity $User -NewPassword (ConvertTo-SecureString (Read-HostArray New Password for User) -AsPlainText -Force)
                    Out-LogFile -Result "Update" -Message "Set Password for $($User)"

                    # Display Results
                    Import-CSV $Global:LDAPLogFile_Operation | Out-GridView -Title "Results of Setting the User's Password"
                    Remove-Item -Path $Global:LDAPLogFile_Operation
                    Show-LDAPMenu
                }
                "Unlock a User's Account" {
                    $User = $Global:Cache_Users | Out-GridView -OutputMode Single -Title "Select a User to Unlock"
                    Unlock-ADAccount -Identity $User -Server localhost:389

                    If ((Get-ADuser -Identity $User -Server LocalHost:389).LockedOut) {
                        Out-LogFile -Result "Failed" -Message "Unlock $($User)"
                    }
                    Else {
                        Out-LogFile -Result "Success" -Message "Unlock $($User)"
                    }

                    # Display Results
                    Import-CSV $Global:LDAPLogFile_Operation | Out-GridView -Title "Results for Unlocking a User Account"
                    Remove-Item -Path $Global:LDAPLogFile_Operation
                    Show-LDAPMenu
                }
                "Enable a User's Account" {
                    $User = $Global:Cache_Users | Out-GridView -OutputMode Single -Title "Select a User to Enable"
                    Get-ADuser $User -Server LocalHost:389 | Enable-ADAccount -Server localhost:389

                    If ((Get-ADuser $User -Server LocalHost:389).Enabled) {
                        Out-LogFile -Result "Success" -Message "Enable $($User)"
                    }
                    Else {
                        Out-LogFile -Result "Failed" -Message "Enable $($User)"
                    }
                    # Display Results
                    Import-CSV $Global:LDAPLogFile_Operation | Out-GridView -Title "Results for Enabling a User Account"
                    Remove-Item -Path $Global:LDAPLogFile_Operation
                    Show-LDAPMenu
                }
                "Disable a User's Account" {
                    $User = $Global:Cache_Users | Out-GridView -OutputMode Single -Title "Select a User to Disable"
                    Get-ADuser $User -Server LocalHost:389 | Disable-ADAccount

                    If ((Get-ADuser $User -Server LocalHost:389).Enabled) {
                        Out-LogFile -Result "Failed" -Message "Disable $($User)"
                    }
                    Else {
                        Out-LogFile -Result "Success" -Message "Disable $($User)"
                    }
                    # Display Results
                    Import-CSV $Global:LDAPLogFile_Operation | Out-GridView -Title "Results for Disabling a User Account"
                    Remove-Item -Path $Global:LDAPLogFile_Operation
                    Show-LDAPMenu
                }
                "Process Group Assignments (CSV Import)" {
                    $GroupConfig = ConvertFrom-CSV (Read-HostArray Enter Group Assignment Data) -Delimiter "`t"
                    foreach ($Entry in $GroupConfig) {
                        $User = $Entry.userDN
                        $Group = $Entry.groupDN
                        Add-ADGroupMember -Identity $Group -members $User -Server localhost:389

                        If ((Get-ADUser -Identity $User -Properties MemberOf -Server localhost:389).MemberOf -eq $Group) {
                            Out-LogFile -Result "Success" -Message "Add $($User) to $($Group)"
                        }
                        Else {
                            Out-LogFile -Result "Failed" -Message "Add $($User) to $($Group)"
                        }
                    }

                    # Display Results
                    Import-CSV $Global:LDAPLogFile_Operation | Out-GridView -Title "Results of Adding Users to Groups"
                    Remove-Item -Path $Global:LDAPLogFile_Operation
                    Show-LDAPMenu
                }
                "Enable/Disable Full Menu" {
                    If ($Global:FullMenu) {
                        $Global:FullMenu = $False
                    }
                    Else {
                        $Global:FullMenu = $True
                    }
                    Set-MenuOptions
                    Show-LDAPMenu
                }
                "Re-import LDAP Users/Groups" {
                    Import-LDAPCache
                    Show-LDAPMenu
                }
                "Back" {
                    Show-LDAPMenu
                }
            }
        }
        "LDIF Operations" {
            Clear-Host
            Switch (Menu $Menu_LDIF) {
                "Process from Clipboard" {
                    Invoke-LDIF_Config
                    Show-LDAPMenu
                }
                "Process from File" {
                    Invoke-LDIF_File
                    Show-LDAPMenu
                }
                "View Logs" {
                    Start-Process $Global:LDIFLogFolder
                    Show-LDAPMenu
                }
                "Back" {
                    Show-LDAPMenu
                }
            }
        }
        "Exit" {
            Clear-Host
            Return
        }
    }
}

### Start Script ###

Set-MenuOptions

# Allow for using the menu without a cache (run menu with -nocache switch)
If ( -Not ($NoCache)) {
    Import-LDAPCache
}

Show-LDAPMenu
