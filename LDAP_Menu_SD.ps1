<#
	.SYNOPSIS
		This is a menu driven set of script for managing RED LDAP

	.DESCRIPTION
		This is a menu driven set of script for managing RED LDAP (Service Desk Only)

	.PARAMETER NoCache
		Do not cache LDAP users and groups
#>

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

########## Menu Structure ##########

$Global:Menu_Main = @(
    "Reset a User's Password"
    "Unlock a User's Account"
    "Enable a User's Account"
    "Exit"
)

Function Show-LDAPMenu {
    Clear-Host
    Switch (Menu $Global:Menu_Main) {
        "Reset a User's Password" {

            # Prompt User for a search string
            $SearchString = '*' + (Read-Host -Prompt "User Name to Search") + '*'

            # Ensure Search string is not empty
            While ($SearchString -eq '**') {
                $SearchString = '*' + (Read-Host -Prompt "User Name to Search") + '*'
            }

            # Replace spaces with a '.'
            $SearchString = $searchstring.replace(' ', '.')

            $Global:Cache_Users = (Get-ADUser -filter { (name -like $SearchString) -and (ObjectClass -eq 'RMGPerson') } -Server localhost:389 -SearchBase $Global:ADSearchBase_RED).DistinguishedName

            $User = $Global:Cache_Users | Out-GridView -OutputMode Single -Title "Select a User to Reset the Password for"
            Set-ADAccountPassword -server localhost:389 -Identity $User -NewPassword (ConvertTo-SecureString (Read-HostArray New Password for User) -AsPlainText -Force)
            Out-LogFile -Result "Update" -Message "Set Password for $($User)"

            # Display Results
            Import-CSV $Global:LDAPLogFile_Operation | Out-GridView -Title "Results of Setting the User's Password"
            Remove-Item -Path $Global:LDAPLogFile_Operation
            Show-LDAPMenu
        }
        "Unlock a User's Account" {

            # Prompt User for a search string
            $SearchString = '*' + (Read-Host -Prompt "User Name to Search") + '*'

            # Ensure Search string is not empty
            While ($SearchString -eq '**') {
                $SearchString = '*' + (Read-Host -Prompt "User Name to Search") + '*'
            }

            # Replace spaces with a '.'
            $SearchString = $searchstring.replace(' ', '.')

            $Global:Cache_Users = (Get-ADUser -filter { (name -like $SearchString) -and (ObjectClass -eq 'RMGPerson') } -Server localhost:389 -SearchBase $Global:ADSearchBase_RED).DistinguishedName

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

            # Prompt User for a search string
            $SearchString = '*' + (Read-Host -Prompt "User Name to Search") + '*'

            # Ensure Search string is not empty
            While ($SearchString -eq '**') {
                $SearchString = '*' + (Read-Host -Prompt "User Name to Search") + '*'
            }

            # Replace spaces with a '.'
            $SearchString = $searchstring.replace(' ', '.')

            $Global:Cache_Users = (Get-ADUser -filter { (name -like $SearchString) -and (ObjectClass -eq 'RMGPerson') } -Server localhost:389 -SearchBase $Global:ADSearchBase_RED).DistinguishedName

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
        "Exit" {
            Clear-Host
            Return
        }
    }
}


### Start Script ###

Set-Title LDAP Service Desk Menu

Import-Module ActiveDirectory

Show-LDAPMenu