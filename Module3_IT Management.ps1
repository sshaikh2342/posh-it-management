#region: Managing JEA endpoint

Get-service –name winrm                     #-> If it has not started start it       start-service –name Winrm

Get-PSSessionConfiguration | Format-Table name, PSSessionConfigurationTypeName

#Create a new JEA endpoint on a machine: 

#Create a new PS session configuration file
New-PSSessionConfigurationFile -SessionType RestrictedRemoteServer -Path .\MyJEAEndpoint.pssc 

#Register a new PS session using the just created file 
Register-PSSessionConfiguration -Path .\MyJEAEndpoint.pssc  -Name 'JEAMaintenance' -Force 

#Look at the WSMAN configuration / show some of the sub properties
Set-Location wsman:\localhost\plugin                      #->  look at some sub folders 

#Remove the endpoint again
Unregister-PSSessionConfiguration -Name 'JEAMaintenance' -Force

#endregion

#region: Session configuration


#Create a JEA session configuration file with standard options
New-PSSessionConfigurationFile -Path “c:\MyJEAEndpoint.pssc”

#Create a JEA session configuration file with all options
New-PSSessionConfigurationFile -Path “c:\MyJEAEndpointfull.pssc” –full

#Open both files and show the difference in option logged in the files

#Copy the standard options file to use as a restricted file
Copy-Item -Path "C:\MyJEAEndpoint.pssc" -Destination "C:\MyJEAEndpointrestricted.pssc"

#Open the C:\MyJEAEndpointrestricted.pssc and change the session type to Restrictedremoteserver
SessionType = 'RestrictedRemoteServer'

#Create 2 new JEA endpoint on a machine: 

#Register a new PS session using the just created file 
Register-PSSessionConfiguration -Path “c:\MyJEAEndpoint.pssc”  -Name “JEADefault”

Register-PSSessionConfiguration -Path “C:\MyJEAEndpointrestricted.pssc”  -Name “JEARestricted”

#Restart WinRM to make the configuration active
Restart-Service –name winrm

#Show the configuration on both endpoints in different

#Connect to the default session
Enter-PSSession -ComputerName localhost -ConfigurationName ”JEADefault”

#Run get command to show all available commands
Get-Command

#Disconnect from the session
Exit

#Connect to the Restricted session
Enter-PSSession -ComputerName localhost -ConfigurationName ”JEARestricted”

#Run get command to show all available commands
Get-Command              -> Only 8 cmdlets should show up

#Run a cmdlet that not available
Get-host

#Disconnect from the session
Exit

#Re-Run a cmdlet that was not available but is in normal shell
Get-host

#endregion

#region: Role capability

#Start PowerShell as an Administrator.

#Create a new AD groups used to map the role capability to group
New-Adgroup –name “Role1” –groupscope “Global” –server "dc"

#Start winRM service if this is a client machine
Start-service –name Winrm                                    # -> or start manual via services.msc

#Create a JEA session configuration file

#Create a JEA session configuration file with standard options
New-PSSessionConfigurationFile -Path “c:\Pshell\MyJEARoleEndpoint.pssc”

#Open the file and change the following role capabilities:

&"c:\Pshell\MyJEARoleEndpoint.pssc"

#Add /change the following role capability
SessionType = 'RestrictedRemoteServer'		#->> Needed to get basic command instead of a empty shell
RoleDefinitions = @{ 'CONTOSO\role1' = @{ RoleCapabilities = ‘role1’}}

#Register a new PS JEA session using the just created file 
Register-PSSessionConfiguration -Path "c:\Pshell\MyJEARoleEndpoint.pssc"  -Name "JEARoles" -Force 

#Restart WinRM to make the configuration active
Restart-Service –name winrm

#Create a new JEA role capability files: 

#File 1 – role 1
New-PSRoleCapabilityFile -Path c:\Pshell\role1.psrc

#Open the file and change the following keywords:

&"c:\Pshell\role1.psrc"

#Change the keyword Modulestoimport
Modulestoimport = ‘Activedirectory’                      #-> Don`t forget to uncomment, Might need to update quotes if you copy paste
Visiblecmdlets =  'get-ad*'                                     #   -> Don`t forget to uncomment, Might need to update quotes if you copy paste

#Copy the file to the rolecapabilityfolder in the AD module directory
New-item –path "c:\windows\system32\Windowspowershell\v1.0\modules\activedirectory\Rolecapabilities" –type "Directory"
Copy-item –path "c:\Pshell\role1.psrc" –destination "c:\windows\system32\Windowspowershell\v1.0\modules\activedirectory\Rolecapabilities\role1.psrc"

#Show the configuration is different depending on group membership

#Connect to the JEA session
Enter-PSSession -ComputerName WIN10 -ConfigurationName ”JEARoles”      	-> will fail as your not member of the AD group

#Add yourself to the group “Role1”
Add-adgroupmember –identity role1 –members power

#Re-Connect to the JEA session
Enter-PSSession -ComputerName WIN10 -ConfigurationName ”JEARoles”

#Run get command to show all available commands
Get-Command	-> AD get commands should now be there

#Disconnect from the session
Exit

#Remove your self from the group
Remove-Adgroupmember –identity role1 –members power 		

#From the same shell Re-Connect to the JEA session
Enter-PSSession -ComputerName WIN10 -ConfigurationName ”JEARoles”		-> This should work as the enter-pssession reuses its session to connect on

#From a new shell Re-Connect to the JEA session
Enter-PSSession -ComputerName WIN10 -ConfigurationName ”JEARoles”		-> This should fail as it creates a new session with new authorisation

#Disconnect from the session
Exit

#Note: there is group membership cache so removing yourself from the group and rejoining might not directly remove the permissions again.


#endregion

#region: JIT Systems

Prepare a group to use with PAM

Enable PAM on the forest level
Enable-ADOptionalFeature "Privileged Access Management Feature" -Scope ForestOrConfigurationSet -Target “Contoso.com“

Create new AD group
New-ADGroup -Name "JIT" -SamAccountName “Jit” -GroupCategory Security -GroupScope Global -DisplayName "JIT" -Path "CN=Users,DC=Contoso,DC=Com" 

Add JIT group to remote desktop users on the memberserver
Invoke-command -ComputerName ms -ScriptBlock {Add-LocalGroupMember -Name "Remote Desktop Users" -Member "contoso\JIT"}

Create new testuser
New-ADUser -Name "JIT-user1" -SamAccountName "JIT-user1" -DisplayName 'JIT-user1' -AccountPassword (Read-Host -Prompt 'pw' -AsSecureString)  -Enabled $true
 
Show its not working 

Login via RDP on the MS
mstsc /v:ms.contoso.com              -> use the Jit-user1 you just created

Show it works when member of JIT group

Add user to the group with 5 minutes TTL
Add-ADGroupMember -Identity ‘JIT’ -Members ‘JIT-user1’ -MemberTimeToLive [timespan]"00:05" 

Login via RDP on the MS
mstsc /v:ms.contoso.com              -> use the Jit-user1 you just created

Show access is revoked after 5 min

Show the countdown of the JIT setting
Get-ADGroup –Identity ‘JIT’ -Property member -ShowMemberTimeToLive | select-object -ExpandProperty member


Wait for atleast 5 minutes and try again
mstsc /v:ms.contoso.com              -> use the Jit-user1 , you should no longer be allowed to connect

Show you are no longer member of the group
Get-ADGroupMember -Identity ‘JIT’ 


#endregion

#region: Scope

#create variable in global scope
$test = "In the global scope"

#The variable $test was defined in the Global Scope
Write-Host $("[Global Scope] `$test value: " + $test)

#This creates a new variable $test in the Script Scope
$test = "In the script"
Write-Host $("[Script Scope] `$test value: " + $test)

function definition
function DemoFunctionScope {
    param ([string]$OriginalText)

    #This creates a new variable $test in the Function Scope
    $test = $OriginalText + " function"
    Write-Host $("[Function Scope] `$test value: " + $test)
}

#Invoke the function
DemoFunctionScope -OriginalText $test

Verify the value of $test after invoking the function
Write-Host $("[Script Scope] `$test value: " + $test)


# Using scope - powershell v3 and above
$s = New-PSSession -ComputerName jea1
$dt = 3

#local variable cannot be found on remote session
Invoke-Command -Session $s -ScriptBlock {Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=$dt"}

#using scope local variable can be passed to remote session
Invoke-Command -Session $s -ScriptBlock {Get-WmiObject -Class `
Win32_LogicalDisk -Filter "DriveType=$Using:dt"}




#endregion

#region: Scope modifier

#create a regular variable
$PriVar = "This is a local Variable"

#Define a new function to query the variable from a different scope
function TestFunc {"`$PriVar is $PriVar"}

#Variable's value is returned OK
Testfunc

#Create a private variable that cannot be viewed or modified from another scope
#Using the New-Variable cmdlet's -option parameter
New-Variable -Name PriVar -Value "This is a Private Variable" -Option private -Force

We can access the variable from within the scope it was defined
$PriVar

but accessing the variable from a different scope, such as a function, fails
Testfunc

#endregion

#region: Dot Source Notation

Create function in script to be dot sourced
function AddTen  {
    param($Param)
    $Param = $Param + 10
    $Param
}

Function GetServerData {
    param($computername)
    Get-CimInstance win32_OperatingSystem -ComputerName $computername
}


Save script as c:\scripts\MyFunctions.ps1

open new Powershell tab or ISE instance
run script
c:\scripts\MyFunctions.ps1

call either function
AddTen -Param 4
will get error
GetServerData -computername localhost
will get error

dot source and load into current scope
. c:\scripts\MyFunctions.ps1

call functions
AddTen -param 4
GetServerData -computername localhost
 


#endregion

#region: Profiles

view current values of $profiles
$profile | get-member -type noteproperty 
Display current user profile path
$profile
Display current user all hosts profile path 
$Profile.CurrnetUserAllHosts 
Display all users current hosts profile path 
$Profile.AllUsersCurrentHost 
Display all users all hosts profile path 
$Profile.AllUsersAllHosts 

Create a new profile file
Where would profile be?
$profile

Before we decide to create a profile, let’s check to see whether we already have one
Test-Path $profile

#Create if doesn't exist or overwrite existing one
New-Item -path $profile -type file -force

View profile in ISE
ise $profile

++++ add following code to profile

# dot source previously created script to make functions available
# upon startup
. c:\scripts\MyFunctions.ps1

# create and alias available on startup
New-Alias -Name MyAlias -Value Get-Service

# create a greeting
Write-Host "Powershell ROCKS!" -ForegroundColor Blue -BackgroundColor White

++++++ End of code for file

save and close profile

reopen new ISE 

validate MyAlias exists
Get-Alias m*

validate functions exist with Intellisense
AddTen 3
GetServerData localhost 


#endregion