#region: basic Regex 

$file = get-content C:\users\suser\Desktop\users2.txt
$regex =  "1-\d{3}-\d{3}-\d{4}" 
foreach ($line in $file)
{
    if($line -match $regex)
    {
        $matches[0]
        
    }
} 

#Output without Regex applied

$file = get-content C:\users\suser\Desktop\users.txt
$regex =  "1-\d{3}-\d{3}-\d{4}" 
foreach ($line in $file)
{
    Write-Output $line

} 


# Exact characters anywhere in the data "literALS"

“Admin@Contoso.com" -match “admin"

# Any single character, except newline "."
 
"Admin@Contoso.com" -match "A...n"

#Escape Character: add or remove special parsing "\"

# splits on each character
 "Admin@Contoso.com" -split "."

 # splits on “.”
 "Admin@Contoso.com" -split "\." 

 #Any word characted "\w"
 
 "Admin@Contoso.com" -match "\w"

 #Any white space character "\s"

 "abcd efgh" -match "\s"

 #Any decimal deigit "\d"

 12345 -match "\d" 

 #exact n matches {n}

 "Admin@Contoso.com" -match "\w{2}"

#At least n matches {n,}

"Admin@Contoso.com" -match "\w{7,}"

#At least n but not more than m matches

"Admin@Contoso.com" -match "\w{2,3}"

#Shortcut for one or more {1,} "w+"

"Admin@Contoso.com" -match "\w+"

###########################################

$a = @"
1The first line.
2The second line.
3The third of three lines.
"@ 

$a -split "\d"      #--> \d any decimal digit "1, 2, 3"

#If you want to remove the empty lines you can use:

($a -split "\d").trim()| Where-object –filterscript {$_ -ne ""}
Or 
($a -split "\d").trim() -notmatch "`n"

##########

# More Demo

#Any message that has error in it:
Get-EventLog -LogName application | where-object -FilterScript {$_.message -match "error"}

#Any message that has restart in it:
Get-EventLog -LogName application | where-object -FilterScript {$_.message -match "restart"}

#Any message that has stop in it:
Get-EventLog -LogName application | where-object -FilterScript {$_.message -match "stop"}

#Using wildcard matching with “.”:
#Any message that contains ProgramData on any driveletter:
Get-EventLog -LogName application | where-object -FilterScript {$_.message -match "...ProgramData"} | select-object -first 5

#Any message that refferances an event ID with 1 character or digit in qoutes:
Get-EventLog -LogName application | where-object -FilterScript {$_.message -match "Event ID '.’"} | select-object -first 5

#Using escape  character:
#Any message that references an exe file:
Get-EventLog -LogName application | where-object -FilterScript {$_.message -match ".\.exe"} | select-object -first 5

#Mixing regex symbols:
#Any message that contains search database related messages:
Get-EventLog -LogName application | where-object -FilterScript {$_.message -match “\(\d\d\d\d,\w,\d\d\)"} | select-object -first 5

#Any defined or undefined multiplication of a symbol:
#Anything that looks like a stop code:
Get-EventLog -LogName application | where-object -FilterScript {$_.message -match "0x\d+“} | select-object -Property Message -First 5

#Atleast 2 slashes so a fileshare or absolute path
Get-EventLog -LogName application | where-object -FilterScript {$_.message -match "\\{2,}"} | select-object -first 5

#Split takes regex as a input to act on:

#View gateway information from route command:
(route print 0*) -split "\s" -match “\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}“

#use –match ,  -replace and -split  all with regex to extract the lost packages from a ping
(ping 8.8.8.8 -n 1) -match "lost" -replace "Packets: Sent = \d+, Received = \d+," -split "\(\d+% loss\),"
(ping 8.8.8.8 -n 1) -match "lost" -split "\(\d+% loss\),"

##########
#endregion

#region: working with group and result

#Extracting data from a string with $Matches
$Signature = @"
Janine Mitchell
Property Manager | West Region
Janine.Mitchell@ContosoSuites.com
"@ 
$Signature -match "\w+\.\w+@\w+\.com" #"\w+" One or more word character # "\." Literal dot character (escaping the special dot)

$Matches[0] 

# Format () Groups regular expressions together

#Example 1

$var = "a b c"

$var -match "(\w+)(\s)(\w+)(\s)(\w+)"
$matches
$matches[3]

#Example 2

"contoso\administrator" –match "(\w+)\\(\w+)"


 #Named groups and can only begin with a letter Format ?<Name>

 "contoso\administrator" –match "(?<Domain>\w+)\\(?<UserName>\w+)"
$matches
$matches["UserName"]


#Replace Regex Examples

$str = "Henry Hunt"
$str -replace "(\w+)\s(\w+)",'$2,$1'
 

# $& --> Overall Regex Match
#$1, $2, … $n --> Individual Captures by order captured
# ${name} --> Named Capture

#PowerShell uses the $ for variables, need to be sure to pass a literal $ character in single quotes for Regex to understand

#By default $matches shows the full match as group 0 as long as the input is a single string. 
"The ip address 40.68.221.249 is also known as ??.in-addr.arpa" -match "\d+\.\d+\.\d+\.\d+"
$matches    #-> Shows just group 0 

#If we start to group this $matches will show all the capture groups
"The ip address 40.68.221.249 is also known as ??.in-addr.arpa" -match "(\d+)\.(\d+)\.(\d+)\.(\d+)"
$matches    #-> Shows all 4 octets of the IP address and the full match group 0

#Using Replace we can use this to our advantage to resequencing matches or text
"The ip address 40.68.221.249 is also known as ??.in-addr.arpa" -replace "(\d+)\.(\d+)\.(\d+)\.(\d+) is also known as \?\?.in-addr.arpa",'40.68.221.249 is also known as $4.$3.$2.$1.in-addr.arpa'

#We can also add a name to each group for reference with $matches
"The ip address 40.68.221.249 is also known as ??.in-addr.arpa" -match “(?<Octet1>\d+)\.(?<Octet2>\d+)\.(?<Octet3>\d+)\.(?<Octet4>\d+)“
$matches     #->  This will now show all named groups and group 0 showing the full match
$matches.Octet3

#Using Replace we can now create a simpler replace command
"The ip address 40.68.221.249 is also known as ??.in-addr.arpa" -replace "\?\?","$($matches.octet4).$($matches.octet3).$($matches.octet2).$($matches.octet1)"

##########
#endregion

#region: Advanced Regex

$Data = "1a2b3cd"
$Pattern = '\d'
[regex]::match($Data,$Pattern).value
1
[regex]::matches($Data,$Pattern).value

#To see all the methods and properties
[regex]::new($pattern) | Get-Member

#Additional Symbols

#Zero or more {0,} --> "*"

"abc"    -match "\w*"                            # This is always true

"baggy"  -match "b.*y" 


#Zero or one {0,1} --> "?"

"http"   -match "https?"

#Special Character Class: Ll, IsGreek, IsCyrillic, and IsBoxDrawing --> \p{name}

#http://msdn.microsoft.com/en-us/library/20bw873z(v=vs.110).aspx#SupportedUnicodeGeneralCategories
# splits on the a,b,c

 "a&b&c&" -split "\p{Ll}" 

#Alternation Logical OR --> "|"
“Contoso.com" –match "\.(com|net)"
“Consoto.net" –match "\.(com|net)"

#Beginning character(s) --> " ^ "

#Is this a UNC path?
'\\server\share\' -match '^\\\\\w+' 
'C:\folder\' -match '^\\\\\w+' 

# End character(s) --> " $ "

"book" -match "ok$"

# Demo Examples

#We can extract an IP address using .NET framework regex class System.Text.RegularExpressions.Regex with short class name is [regex]. The overload match returns the first hit
[regex]::match((ipconfig.exe),"\d+\.\d+\.\d+\.\d+")

#The overload matches will return all results found 
[regex]::matches((ipconfig.exe),"\d+\.\d+\.\d+\.\d+")

#You can view the values direct by using dotted notation
([regex]::matches((ipconfig.exe),"\d+\.\d+\.\d+\.\d+")).value

#The object returned is a regex group just like $matches system variable
$result = [regex]::matches((ipconfig.exe),"\d+\.\d+\.\d+\.\d+")
$result[0].gettype()

#You can also use the grouping with this static method
$result = [regex]::matches((ipconfig.exe),"(\d+)\.(\d+)\.(?<One>\d+)\.(?<Two>\d+)")
$result.groups | ft

#Mode Modifier
(?i) Ignore Case
(?m) Multi-line: ^ and $ apply to each line
(?s) Single-line: match newlines with . char

#As ipconfig is an array of strings trying to match multiple lines with ^ and $ won`t work 
[regex]::Matches((ipconfig.exe),"(?m)^\s+IPv.*")

#We need to convert the output of Ipconfig from array to a string with line formatting
[string]$ipconfigstring = ipconfig.exe | foreach-object –process {"$_`n"}
[regex]::Matches(($ipconfigstring),"(?m)^\s+IPv.*")       # 	-> start with IPv ignore white space show whole line
[regex]::Matches(($ipconfigstring),"(?m).*(\.0)$")		#-> ending ip on 0  show whole line
[regex]::Matches(($ipconfigstring),"(?m)^\s+IPv.*|.*(\.0)$")	#-> start with IPv or ending ip on 0 ignore white space show whole line

##########
#endregion

#region: Select String cmdlet

Get-ChildItem –recurse –Filter *.ps1 | Select-String “CONTOSO\OldAdminAccount” #– Find all your scripts where you referenced an out of date admin account.  

$Data = "1a2b3c4d5e"
$Pattern = ‘\d’

(select-string -InputObject $Data -Pattern $Pattern -AllMatches).Matches.Value

#Demo Examples
#Finding all set commands from a configuration file:
netsh dump | Select-String -Pattern "^set"

#Show all interfaces using netsh
netsh trace show interfaces | Select-String -Pattern "^\s+Description“

#Show all interfaces using netsh and use alternation to add the index
netsh trace show interfaces | Select-String -Pattern "^\s+Description|index“

#Mixing it all together: replace the description using capture groups
(netsh trace show interfaces | Select-String -Pattern "^\s+Description|index") 
(netsh trace show interfaces | Select-String -Pattern "^\s+Description|index") -replace "(\sDescription):\s+(Microsoft)(.*)",' My $2 device$1 is $3'

##########

#Optional webscrapping
$HTML = Invoke-RestMethod 'http://quotes.toscrape.com/'

$HTML -match '<span class="text" itemprop="text">.*</span>'

$HTML -match '<span class="text" itemprop="text">(?<quote>.*)</span>'    #----> named match

$Matches.quote

$pattern = '<span class="text" itemprop="text">(?<quote>.*)<\/span>'

$allmatches = ($HTML | Select-String $pattern -AllMatches).Matches

($allmatches.groups.where{$_.name -like 'Quote'}).value

$allmatches.groups | Where-Object name -like 'quote' | Select-Object value

#endregion

#region: Background Job:
Start-Job {Get-Service Spooler} | Out-Null

#WmiJob :
Get-WMiObject –Class Win32_Service –Filter "Name='Spooler'" –AsJob | Out-Null 

#RemoteJob: 
Invoke-Command -ScriptBlock {Get-Service Spooler} -AsJob -Session (New-PSSession) | Out-Null

#Workflow Job:
Workflow Test {}; Test –AsJob | Out-Null

#Scheduled Jobs:
Register-ScheduledJob -ScriptBlock {Get-ChildItem} -Name Test -RunNow

#List the Jobs:
Get-Job

##########
# Starting a job with -ScriptBlock parameter
Start-Job –ScriptBlock { Get-ChildItem –Recurse –Path C:\ }

# Jobs can be also started using scripts but are converted to ScriptBlocks
Start-Job –FilePath .\Scripts\Get_Network_info.ps1

# It is possible to start a script before the job starts
Start-Job -Name GetMapFiles -InitializationScript {Import-Module MapFunctions}`
 -ScriptBlock {Get-Map 0 -Name * | Set-Content D:\Maps.tif} -RunAs32 

Start-job –ScriptBlock {Get-ChildItem -Path C:\windows }

#endregion

#region: Working with Job object
#Start a background job which will fail;
 $myJob4 = Start-Job –ScriptBlock {Get-ChildItem HKLM:\SAM}

#Review the properties of the job object
$myJob4 | format-list

#List the ChildJobs
Get-Job  -ID $myJob4.Id –IncludeChildJob

#Run Each of the following to review the error details :
  (Get-Job -Id $myJob4.Id -IncludeChildJob).Error | Get-Member
  (Get-Job -Id $myJob4.Id -IncludeChildJob).Error.Exception
  (Get-Job -Id $myJob4.Id -IncludeChildJob).Error.Targetobject
  (Get-Job -Id $myJob4.Id -IncludeChildJob).Error.FullyQualifiedErrorId 
  (Get-Job -Id $myJob4.Id -IncludeChildJob).Error.Exception.SerializedRemoteInvocationInfo

##########
#endregion

#region: Managing background Jobs
Start-Job { Get-ChildItem –Recurse –Filter *.ps1}


Start-Job { Get-ChildItem –Recurse –Filter *.ps1} 

Get-Job | Receive-Job -Keep


#Demo examples

#Start a background job and wait for the job to finish. ;
Start-Job –Name MyWaitingJob –ScriptBlock {Get-WinEvent –LogName Application –MaxEvents 1000} | wait-job

#Receive the results:
Get-job –Name MyWaitingJob | Receive-Job

#Try to receive again; 
Get-job –Name MyWaitingJob | Receive-Job

#Start a background job but don’t wait it to finish:
Start-Job –Name MyWaitingJob –ScriptBlock {Get-WinEvent –LogName Application –MaxEvents 5000}

#Run the following line multiple times over and over:
(Get-job –Name MyWaitingJob | Receive-Job –Keep).Count

##########
#endregion

#region: Remote Background Job 

#Start a remote interactive PowerShell session
Enter-PSSession -ComputerName jea1

#In the Remote Session start the job and review the properties.
$job = start-job -ScriptBlock {get-eventlog "Windows PowerShell"} 
$job

#Receive the results in the remote interactive session:
Receive-Job $job

#Run Remote Background job on multiple computers
$Jobs = Invoke-Command –ComputerName jea1,jea2 –ScriptBlock {Get-WinEvent –LogName System –MaxEvents 1000} -AsJob

#List the Remote Background Jobs and review the states.
$Jobs | Get-Job –IncludeChildJob

##########
#endregion

#region: scheduledJobs

#Start a remote interactive PowerShell session
Register-ScheduledJob -Name myTestJob5 -Trigger (New-JobTrigger -Daily -At 1:00AM) -ScriptBlock {restart service }

#Review the scheduled job in task scheduler gui (taskschd.msc)
taskschd.msc
#Run MyTestJob5 in Task scheduled gui multiple times

#Also you can run task using start-job or by adding runNow parameter to your Register-ScheduledJob command
Start-Job -Type PSScheduledJob –DefinitionName "task name"


#Receive the results in the remote interactive session:
Receive-Job myTestJob5
#Review the output folder:
Get-ChildItem C:\Users\suser\AppData\Local\Microsoft\Windows\PowerShell\ScheduledJobs\myTestJob5\Output

#Close and restart a new ISE and receive;
Receive-Job myTestJob5

#unregister scheduled job

Get-ScheduledJob | Unregister-ScheduledJob

#You might need to import SchduledJobModule if the above don’t work and then run again

Import-Module PSScheduledJob 

##########
#endregion

#region: Create a scheduled task and review in Task Scheduler.

#Create the command line action:
$Action = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument "-ExecutionPolicy Bypass -File " "C:\Pshell\Get-JobEvent.ps1"

#Use localystem as the username:
$UserName = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

#Create a basic trigger:
$Trigger  = New-ScheduledTaskTrigger –AtStartup

#Bring together and create the task object:
$Task = New-ScheduledTask -Action $Action -Principal $UserName -Trigger $Trigger -Settings (New-ScheduledTaskSettingsSet -WakeToRun)

#Register the task in task scheduler and then review:
Register-ScheduledTask DemoTask -InputObject $Task –Force

##########
#endregion

#region: Package management and providers

#Show the default installed providers
Get-PackageProvider

#Show providers that can be added via Find-PackageProvider
Find-PackageProvider


#Introduction to repositories
#Show some of the main repositories and brows some content
https://www.nuget.org/
https://chocolatey.org
https://www.powershellgallery.com

Find-Package -Name psreadline -AllVersions

Get-Package -Provider programs -IncludeWindowsInstaller
##########
#endregion

#region: Providers and Repository
#Show all needed cmdlets are in the packagemanagement module:
Get-Command -Module PackageManagement
Get-Command -Module PowerShellGet
#Install additional package providers
#Show the default installed providers and what is available if it is not open in your session anymore

#Update the Nuget provider
Install-PackageProvider -name nuget
#Install the chocolatey provider
Install-PackageProvider -name chocolatey

#Show the providers have been installed
Get-PackageProvider         		#-> Note the version numbers
Get-PackageProvider –ListAvailable   	#-> Will show all providers and their versions if multiple are available

#Show the repositories that are now available:
Get-packagesource

#Show that Psget has his own cmdlet for this:
Get-PSRepository

#Rename chocolatey and set it trusted
Set-packagesource -name chocolatey -NewName "Puurchocolate" -Trusted

#Show it is now trusted a -nd has the new name
Get-packagesource 

#Show All properties
Get-packagesource  | fl

#endregion

#region: Package cmdlets

#######Packager Cmdlets###

#Find zoomit in chocolatey
Find-Package -Source chocolatey -Name zoomit  	#-> Won`t work because we renamed chocolatey into puurchocolate last demo
Find-Package -Source Puurchocolate -Name zoomit

#Save the package for inspection before you install it
Save-Package –name zoomit –Source chocolatey  –path c:\temp	 #-> Won`t work because we renamed chocolatey into puurchocolate last demo
Save-Package –name zoomit –Source Puurchocolate   –path c:\temp

#Install a package from your save location
Install-Package –InputObject c:\temp\zoomit.4.50.0.20160210.nupkg	#-> note there is no message saying that the repository is untrusted as we set puurchocolate repo to a trusted repo

#Install a package direct from the repository
Install-Package -Source chocolatey -Name zoomit  	#-> Won`t work because we renamed chocolatey into puurchocolate last demo
Install-Package -Source Puurchocolate -Name zoomit	#-> note there is no message saying that the repository is untrusted as we set puurchocolate repo to a trusted repo


#Install from a GUI
Find-Package -ProviderName Puurchocolate | Out-GridView -PassThru | Install-Package

#Not all content is OK especially older content has its source broken:
Install-Package snake-jave 	#-> Zip File aint downloaded due to redirect on soundforce
Install-Package mspacman	#-> download does not exist

#Inspect all the installed packages 

#Look at packages that have been installed anywhere within the scope of packagemanger
$all = Get-Package

#Inspect the output:
$all | group-object –property ProviderName
$all | where-object -FilterScript {$_.Providername -eq "msu"}
$all | where-object -FilterScript {$_.Providername -eq "msi"}
$all | where-object -FilterScript {$_.Providername -eq "Chocolatey"}

#If you have a MSI program that can be uninstalled show uninstall from a msi program works
Uninstall-Package -name "Google Talk Plugin"

#remove package provider
(Get-PackageProvider -Name Chocolatey).providerpath # find the path and delete
##########
#endregion

#region: PowershellGet
#In previeus demos we installed the PowerShellGet repository so the module should be available
#Validate the module is loaded
Get-module	#-> you should see the powershellget module if not you could old fasion load it     import-module –name powershellget   

#Show all commands in the module
Get-command -module powershellget

#Show the difference between the package management commands and PowerShellGet commands:
#Package management 
Get-PackageSource
#VS
#PowerShellGet
Get-PSRepository		#-> Only shows Psget resources


#Package management 
Find-Package –Name AZ	
#VS
#PowerShellGet
Find-Module –Name AZ 	#-> Note Repository VS Source

#You can mostly combine the commands in the Pipe
Find-Package -Name az | Install-Module

#Install-module uses install package under the hood
find-package -Name ACMESharp | Install-Module 		#- Will trow an error that the package name is not found while running install-package

#Uninstall the module again:
Uninstall-Module –name ACMESharp		#-> Will trow a error as you have the module actively loaded need to remove first

#Unload the module
Remove-Module –name ACMESharp

#Uninstall the module again:
Uninstall-Module –name ACMESharp

#Install a module in the local user scope
Install-Module –name ACMESharp –scope "currentuser"


##########
#endregion

#region: publish packages
#Show the creation of a local file share repository
#Create the repository on your local pc
New-Item –Type directory –Path C:\MyRepo
New-SmbShare -Path C:\MyRepo -FullAccess Everyone -Name MyRepo
Register-PSRepository `
-Name MyRepo `
-PackageManagementProvider NuGet `
-SourceLocation \\localhost\MyRepo `
-PublishLocation \\localhost\MyRepo `
-InstallationPolicy Trusted 

#View the new repository is created
Get-PSRepository

#Publish a script into the new created repository
New-ScriptFileInfo `
-Path C:\Users\suser.SHADAB\Desktop\scripts\testscipt1.ps1 `
-Version 1.0 `
-Author "Joe Scripter" `
-Description "My Script" `
-ReleaseNotes @'
Version history 1.0 - Initial release
'@

Test-ScriptFileInfo -Path C:\Users\suser.SHADAB\Desktop\scripts\testscipt1.ps1

Publish-Script `
-Path C:\Users\suser.SHADAB\Desktop\scripts\testscipt1.ps1 `
-Repository MyRepo 

#List all packages in the repository
#Using packagemanagement
Find-Package -ProviderName Powershellget -Type script -Source myrepo

#Using PSGet:
Find-script -Repository myrepo		#->  You can use –verbose –debug to display the parameter binding that is used on find package it is about 35 lines from the bottum

##########
#endregion
