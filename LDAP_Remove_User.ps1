# Deleting RMG LDAP user
# Input user account displayname
$UserAcc = Read-Host -Prompt "Enter account DisplayName to delete"

# Check LDAP and delete user with error handling
try {
    if (Get-ADUser -filter { (displayName -like $UserAcc) -and (ObjectClass -eq 'RMGPerson') } -Server localhost:389 -SearchBase "OU=RED,DC=red,DC=royalmailgroup,DC=net") {
        Write-Host "User $UserAcc found attempting to delete now, please wait..."
        Get-ADUser -filter { (displayName -like $UserAcc) -and (ObjectClass -eq 'RMGPerson') } -Server localhost:389 -SearchBase "OU=RED,DC=red,DC=royalmailgroup,DC=net" | Remove-ADUser

        if (!(Get-ADUser -filter { (displayName -like $UserAcc) -and (ObjectClass -eq 'RMGPerson') } -Server localhost:389 -SearchBase "OU=RED,DC=red,DC=royalmailgroup,DC=net")) {
            write-host "User $UserAcc successfully deleted."
            else { "User $UserAcc unable to be deleted." }
        }
    }
    else {
        write-host "User $UserAcc not found."
    }
}
catch {
    write-host "User $UserAcc not found."
}