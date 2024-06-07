#Change groupname according your script >net group /domain
# Load PowerView module
powershell -ep bypass
Import-Module .\PowerView.ps1

# Define the list of groups
$groups = @(
    "Cloneable Domain Controllers",
    "Debug",
    "Development Department",
    "DnsUpdateProxy",
    "Domain Admins",
    "Domain Computers",
    "Domain Controllers",
    "Domain Guests",
    "Domain Users",
    "Enterprise Admins",
    "Enterprise Key Admins",
    "Enterprise Read-only Domain Controllers",
    "Group Policy Creator Owners",
    "Key Admins",
    "Management Department",
    "Protected Users",
    "Read-only Domain Controllers",
    "Sales Department",
    "Schema Admins"
)

# Loop through each group and get its members
foreach ($group in $groups) {
    Write-Host "Members of ${group}:"
    try {
        $members = Get-DomainGroupMember -Identity $group -ErrorAction Stop
        if ($members) {
            $members | Select-Object -ExpandProperty MemberName | ForEach-Object { Write-Host $_ }
        } else {
            Write-Host "No members found or unable to retrieve members for group: $group"
        }
    } catch {
        Write-Host "Error retrieving members for group: $group. Error: $_"
    }
    Write-Host "`n"
}
