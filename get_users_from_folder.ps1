#Synopsis:
#This script is get ACL for folder and cleanup disabled users
#Last modification data: 2021-02-10
#Version 1.0.2

param (
    [Parameter(Mandatory=$false)]
        [string]$SMB_Path = "\\servername\ShareName"  #smb path without last symbol "\"
    ,[Parameter(Mandatory=$false)]
        [string]$Subfolder_Path = "\FolderName" #path to subfolder. Start from symbol "\" and without last symbol "\"
    ,[Parameter(Mandatory=$false)]
        [string]$FindAcess = "Read" # [Modify,Read,FullControl]
    ,[Parameter(Mandatory=$false)]
        [string]$groupname = '-' # if you want to move users to the group, provide group name via parameters or the value will be requested further
    ,[Parameter(Mandatory=$false)]
        [string]$req_action = "cleanup" # [cleanup,move_to_group]

)

$path = $MyInvocation.MyCommand.Path | Split-Path -Parent   #Folder from which started script
 
$currentdate = Get-Date -Format 'yyyy-MM-dd hh:mm:ss'
$date_for_file = Get-Date -Format 'yyyy-MM-dd'

$CheckPath = $SMB_Path + $Subfolder_Path

$namePath = ($CheckPath.Split('\')[-1]).Replace(' ','_') # this variable we will use in name of csv output file
$server = $CheckPath -split "\\" | Where {  $_ -ne ""  } | Select -first 1

$dc_server = "dc_server.domainname.local" #all operation with AD will be done with this server for except sync errors
$domainname = "domainname"

$items = (Get-Acl -Path $CheckPath).Access | ?{$_.IsInherited -eq $False} #get accounts and groups fro this path

$found = @()

$errors = @()

$acl_not_exists = @()

ForEach ($item in $items) 
{   
    $Acess = $User = $Enabled = ""
    $Access = $item.FileSystemRights
    $Flags = $item.InheritanceFlags
    $UserFind = $null
    if ($item.IdentityReference -match "S-1-5-21-49831181")
        {
            $acl_not_exists += $item   
        }
    else
        {
            try
                {
                     $User = (($item.IdentityReference).tostring().Split("\"))[1]
                     $UserFind = get-aduser -Identity $user -Server $dc_server
                     if ($UserFind.Enabled) {$Enabled = "true"}
                     else {$Enabled = "false"}  
                }
            catch
                {}
            $found += New-Object -TypeName PSObject -Property @{
                User = $User
                Name = $($userFind.name)
                Access = $Access
                Enabled = $Enabled
                Flags = $Flags 
                TimeStamp = $currentdate
              }
      }
}

#Write-Host "MODIFY"
#$found| where{$_.Access -like "*$FindAcess*" -and $_.Enabled -eq "true"}  | Select-Object -Property User 
$found|  Select-Object -Property TimeStamp, User, Name, Access, Enabled |Export-csv -Path "$path\$date_for_file $server $namePath.csv" -append

if ($req_action -eq "cleanup")
    {
        Write-Host "Starting cleanup disabled users..." -ForegroundColor Yellow
        $Error_Action = $null
        $deleteYes = Read-host "Create ACL for remove disabled users? (y/n) " 

        $count = 0
        if ($deleteYes -eq "y")
            {
                # START:   Delete not existing accounts
                if ($acl_not_exists.Count -gt 0)
                    {
                        $acl = Get-Acl $CheckPath
                        $count = 0
                        Foreach ($item in $acl_not_exists)
                            {
                                $acl.RemoveAccessRule($item) 
                                $count++
                            }
                        
                        $deleteYes = Read-host "Do you really want to remove $count not existing users? (y/n)"
                        if ($deleteYes -eq "y")
                            {
                                 try
                                    {
                                         $server = $SMB_Path -split "\\" | Where {  $_ -ne ""  } | Select -first 1
                                         $n = $server.Length + 3
                                         $smbpath = $SMB_Path.Substring($n ,$SMB_Path.Length - $n)
                                         $smbpath = $smbpath.replace('\',"") #remove " symbol

                                         $Error_Action = Invoke-Command -ComputerName $server -ScriptBlock {
                                                param($smbpath,$acl,$subfolderpath)
                                                try
                                                    {
                                                        $edit_path = (Get-SmbShare -Name $smbpath).Path + $subfolderpath
                                                        (Get-Item $edit_path).SetAccessControl($acl)
                                                        $Error_get= $false
                                                    }
                                                catch
                                                    {
                                                        $Error_get = $true
                                                    }
                                                Return $Error_get
                                                } -ArgumentList $smbpath,$acl,$Subfolder_Path
                                       #(Get-Item $CheckPath).SetAccessControl($acl) #cleanuping disabled accounts from folder
                                    }
                                 catch
                                    {
                                        Write-Host "Error with cleanup not existing users from ACL" -ForegroundColor Red
                                        $Error_Action = $true      
                                    }
                            }
                      }
                # END:   Delete not existing accounts
                    
                # START:   Delete not disabled accounts
                $acl = Get-Acl $CheckPath
                $count = 0
                foreach ($item in $found)
                    {
                        if ($item.Enabled -eq "false")
                            {
                                $username = $item.User
                                $usersid = New-Object System.Security.Principal.Ntaccount ("$domainname\$username")
                                $acl.PurgeAccessRules($usersid)    
                                $count++
                            }

                    }
                $deleteYes = Read-host "Do you really want to remove $count disabled users? (y/n)"
                if ($deleteYes -eq "y")
                    {
                        try
                            {
                                 $server = $SMB_Path -split "\\" | Where {  $_ -ne ""  } | Select -first 1
                                 $n = $server.Length + 3
                                 $smbpath = $SMB_Path.Substring($n ,$SMB_Path.Length - $n)
                                 $smbpath = $smbpath.replace('\',"") #remove " symbol

                                 $Error_Action = Invoke-Command -ComputerName $server -ScriptBlock {
                                        param($smbpath,$acl,$subfolderpath)
                                        try
                                            {
                                                $edit_path = (Get-SmbShare -Name $smbpath).Path + $subfolderpath
                                                (Get-Item $edit_path).SetAccessControl($acl)
                                                $Error_get= $false
                                            }
                                        catch
                                            {
                                                $Error_get = $true
                                            }
                                        Return $Error_get
                                        } -ArgumentList $smbpath,$acl,$Subfolder_Path
                            }
                        catch
                            {
                                Write-Host "Error with set up ACL" -ForegroundColor Red
                                $Error_Action = $true      
                            }
                    }
                else {$Error_Action = $null}
                # END:   Delete not disabled accounts
            } 
        if ($Error_Action -eq $null) {Write-Host "Cleanup not required or canceled" -ForegroundColor Green}
        elseif ($Error_Action -eq $false) {Write-Host "Cleanup $count disabled users completed" -ForegroundColor Magenta}
        else {Write-Host "Error: Cleanup disabled accounts not successfull" -ForegroundColor Red}
    }
elseif ($req_action -eq "move_to_group")
    {
        #Write-Host "SNeeds to be checked before implement"  -ForegroundColor MAGGENTA


        Write-Host "Starting move users to the group..." -ForegroundColor Yellow
        $Error_Action = $null

        if ($groupname -eq "") {$groupname = Read-host "Enter group name"}

        $groupobj = Get-ADGroup -LDAPFilter "(SAMAccountName=$groupname)" -Server $dc_server

        if ($groupobj -eq $null) {  Write-Host "Group not found in AD" -ForegroundColor Magenta }
        else
            {
                $acl = Get-Acl -Path $CheckPath # $CheckPath
                $count = 0

                $items = $found | where{$_.Access -like "*$FindAcess*" -and $_.Enabled -eq "true"} 
                foreach ($item in $items)
                    {
                        $AddingUser = Get-ADUser -Identity $item.User -server $dc_server
                        try
                            {
                                Add-ADGroupMember -Identity $groupname -Members $AddingUser -server $dc_server # add user in the group
                                Write-Host "User has been appended: $($item.User), access: $($item.access)" -ForegroundColor Green
                                
                                $username = $item.User
                                $usersid = New-Object System.Security.Principal.Ntaccount ("$domainname\$username")
                                $acl.PurgeAccessRules($usersid)    
                                $count++

                            }
                        catch
                            {
                               Write-Host "Error with append user: $($item.User)" -ForegroundColor Red
                               $Error_Action = $true
                            }
                    }
                if ($count -gt 0) 
                    {
                        $deleteYes = Read-host "Do you really want to remove $count users which has been moved to the group? (y/n)"
                        if ($deleteYes -eq "y")
                            {
                                try
                                    {
                                         $server = $SMB_Path -split "\\" | Where {  $_ -ne ""  } | Select -first 1
                                         $n = $server.Length + 3
                                         $smbpath = $SMB_Path.Substring($n ,$SMB_Path.Length - $n)
                                 
                                         $Error_Action = Invoke-Command -ComputerName $server -ScriptBlock {
                                                    param($smbpath,$acl,$subfolderpath)
                                                    try
                                                        {
                                                            $edit_path = (Get-SmbShare -Name $smbpath).Path + $subfolderpath
                                                            (Get-Item $edit_path).SetAccessControl($acl)
                                                            $Error_get= $false
                                                        }
                                                    catch
                                                        {
                                                            $Error_get = $true
                                                        }
                                                    Return $Error_get
                                                    } -ArgumentList $smbpath,$acl,$Subfolder_Path
                                    }
                                catch
                                    {
                                        Write-Host "Error with set up ACL" -ForegroundColor Red
                                        $Error_Action = $true      
                                    }
                            } 
                            else {$Error_Action = $null}
            
                        if ($Error_Action -eq $null) {Write-Host "Cleanup not required or canceled" -ForegroundColor Green}
                        elseif ($Error_Action -eq $false) {Write-Host "Cleanup $count disabled users completed" -ForegroundColor Magenta}
                        else {Write-Host "Error: Cleanup moved accounts not successfull" -ForegroundColor Red}       
                }
            }
            

    }


