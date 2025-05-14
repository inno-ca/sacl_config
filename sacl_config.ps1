if (($PSVersionTable.PSVersion.Major -eq 5) -or ($PSVersionTable.PSVersion.Major -eq 7)) {

	$AccountSID = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList 'S-1-1-0'
	$IdentityReference = $AccountSID.Translate([System.Security.Principal.NTAccount]).Value

	$folders_create_files = "C:\Windows\debug", "C:\Windows\Tasks", "C:\Windows\tracing", "C:\Windows\System", "C:\Windows\System32", "C:\Windows\SysWOW64", "C:\Windows\System32\wbem", "C:\Windows\System32\WindowsPowerShell\v1.0", "C:\Windows\System32\drivers", "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp", "C:\Windows", "C:\Windows\System32\Tasks"
	$folders_create_files_in_subfolders = "C:\ProgramData"
	$files_write_to_file = "C:\Windows\system32\drivers\etc\hosts"

	$FileSystemRights_create_files = "CreateFiles"
	$AuditFlags_create_files = "Success"
	$InheritanceFlags_create_files = "ObjectInherit"
	$PropagationFlags_create_files = "NoPropagateInherit,InheritOnly"

	$FileSystemRights_create_files_in_subfolders = "CreateFiles"
	$AuditFlags_create_files_in_subfolders = "Success"
	$InheritanceFlags_create_files_in_subfolders = "ContainerInherit,ObjectInherit"
	$PropagationFlags_create_files_in_subfolders = "NoPropagateInherit,InheritOnly"

	$FileSystemRights_files_write_to_file = "CreateFiles"
	$AuditFlags_files_write_to_file = "Success"
	$InheritanceFlags_files_write_to_file = "None"
	$PropagationFlags_files_write_to_file = "None"

	foreach ($folder in $folders_create_files) {
		$AccessRule = New-Object System.Security.AccessControl.FileSystemAuditRule($IdentityReference,$FileSystemRights_create_files,$InheritanceFlags_create_files,$PropagationFlags_create_files,$AuditFlags_create_files)
		$ACL = get-acl $folder -audit
		$ACL.AddAuditRule($AccessRule)
		$ACL | Set-Acl $folder
		}

	foreach ($folder in $folders_create_files_in_subfolders) {
		$AccessRule = New-Object System.Security.AccessControl.FileSystemAuditRule($IdentityReference,$FileSystemRights_create_files_in_subfolders,$InheritanceFlags_create_files_in_subfolders,$PropagationFlags_create_files_in_subfolders,$AuditFlags_create_files_in_subfolders)
		$ACL = get-acl $folder -audit
		$ACL.AddAuditRule($AccessRule)
		$ACL | Set-Acl $folder
		}

	foreach ($folder in $files_write_to_file) {
		$AccessRule = New-Object System.Security.AccessControl.FileSystemAuditRule($IdentityReference,$FileSystemRights_files_write_to_file,$InheritanceFlags_files_write_to_file,$PropagationFlags_files_write_to_file,$AuditFlags_files_write_to_file)
		$ACL = get-acl $folder -audit
		$ACL.AddAuditRule($AccessRule)
		$ACL | Set-Acl $folder
		}
	}
else {
	Write-Host ("ERROR: Required Powershell version 5.x or 7.x")
}