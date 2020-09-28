#region:What is Powershell remoting

Get-Command | Where-Object -FilterScript {$_.Parameters.Keys -contains 'ComputerName' -and $_.Parameters.Keys -notcontains 'Session'} 

Get-Command -ParameterName ComputerName 

#This is valid only for loaded modules. Loaded initially: Microsoft.PowerShell.Core and Microsoft.PowerShell.Utility

#Execute Remote Commands: 

#Run to local computer. You may replace $env:Computername with the name of the computer or use dot. 

Invoke-Command –ComputerName $env:ComputerName –ScriptBlock {“$env:ComputerName”} 	#Works. PowerShell Remoting enabled, WinRM Service running
Stop-Service –name WinRM  
Invoke-Command –ComputerName $env:ComputerName –ScriptBlock {“$env:ComputerName”} 	#Does not work, as WinRM service stopped
Get-Process –Name System –ComputerName $env:ComputerName	 	                        # Still, this option works, as it uses NativeOS Remoting and does not rely on PowerShell Remoting
Start-Service –name WinRM

##########

#endregion

#region:Enable PowerShell Remoting

#Check WinRM Service status: 
Get-Service -Name WinRM | Select-Object -Property Name, DisplayName, Status, StartType                                                      # WinRM must be with Status: Running and StartType: Automatic

#Check Firewall: 
Get-NetFirewallRule –Name "WINRM-HTTP-In-TCP*" | Select-Object -Property Name, Enabled, Profile, Description	 #Enabled: False for Public Network profile, True for Private and Domain

#Demonstrate Endpoints: 
Get-PSSessionConfiguration                                                                                                                                                                    # Comment on purpose and permissions

##########
#endregion

#region:Interactive remoting with local credentials: 

Enter-PSSession –ComputerName DC #by default uses logon user credential

#Run with current credentials: 

$Env:COMPUTERNAME 				# Confirm logged to remote computer
whoami.exe  				# Confirm using current user credentials
Get-WindowsFeature -Name AD-Domain-Services    		# confirm that you have ADDS installed (obviously DC) 
Exit-PSSession


#Run with alternative credentials:

Enter-PSSession –ComputerName DC –Credentials shadab\suser3 	# Password same as for current user
$Env:COMPUTERNAME 					# Confirm logged to remote computer
whoami.exe  					# Confirm using alternative user credentials
Exit-PSSession


##########
#endregion

#region:Execute command remotely 

Invoke-Command -ComputerName DC -ScriptBlock {$env:COMPUTERNAME} 				 # confirm executing command remotely
Invoke-Command -ComputerName DC -ScriptBlock {Get-WindowsFeature -Name AD-Domain-Services}  		# Confirm installed ADDS on DC computer

#Execute multiple times, to demonstrate that command is not executing sequentially in the order specified, but parallel – order in property PSComputername will be different
Invoke-Command -ComputerName Win10, DC, MS -ScriptBlock {Get-Service –Name BITS }
Invoke-Command -ComputerName DC, MS -ScriptBlock {Get-Service –Name BITS} -Credential CONTOSO\Administrator 	# Confirm Alternative Credentials being executed remotely


##########

#endregion

#region: Object Serialization

#Result displayed as expected, comment on the property PSComputerName
Invoke-Command -ComputerName $env:COMPUTERNAME -ScriptBlock {Get-Service -Name BITS}

#If you check the members, you’ll notice that you are working with Deserialized object (Deserialized.System.ServiceProcess.ServiceController), as it was transferred trough the network and methods are missing. 
#Similar to Export-CliXML, Import-CliXMl 

Invoke-Command -ComputerName $env:COMPUTERNAME -ScriptBlock {Get-Service -Name BITS} | Get-Member}

#Still if you check the object on the remote session it would be the original object - System.ServiceProcess.ServiceController, with access to methods.
Invoke-Command -ComputerName $env:COMPUTERNAME -ScriptBlock {Get-Service -Name BITS  | Get-Member}


##########

#endregion

#region: Object Basics
#reate a variable storing a string object, and check its members and datatype
$var= "Hello World"
$var | Get-Member
$var.GetType()

#Due to everything being a object makes it possible to use the pipeline.  PowerShell can uses its binding logic to positionally bind the objects properties to the next cmdlet parameters.
$var | Out-File –path c:\temp\helloworld.txt

#Check the dataTypes available by default
Get-TypeData | Sort-Object -Property typename

#Inspect a type
[datetime] | fl

#more examples

'simple string' | get-member | Select-Object -ExpandProperty typename -Unique
Get-Process | Get-Member | Select-Object -ExpandProperty typename -Unique
Get-ChildItem | Get-Member | Select-Object -ExpandProperty typename -Unique



#Show some properties and methods of an object
$today = get-date
$today | get-member

#Display Properties:
$today.month
$today.Ticks
$today.DayOfYear

#DisplMethods:
$today.adddays(-$today.DayOfYear)
$today.IsDaylightSavingTime()
$today.tostring("yyyy-MM-dd,yy-dd-MM")

#Inspect static members and demo some

Get-Member -InputObject ([System.DateTime])  -Static
[System.DateTime]::Today
[System.DateTime]::IsLeapYear(2068)
[System.Net.IPAddress]::Loopback
[System.Guid]::NewGuid()

##########
#endregion

#region: Custom Objects
$obj = New-Object -TypeName pscustomobject
$obj | Add-Member -MemberType Noteproperty -Name cpu -Value "Xeon"
$obj | Add-Member -Membertype Scriptmethod -Name Proc1 –Value {(get-WMIobject win32_processor).name }

$obj.cpu
$obj.proc1()
$obj | Get-Member

#Create custom object using hash table

$myHashtable = @{
    Name     = $env:USERNAME
    Language = 'Powershell'
    version  = $PSVersionTable.PSVersion.Major
} 

$myObject = New-Object -TypeName PSObject -Property $myHashtable

# Using type casting you can directly create the PSCustomObject:

[pscustomobject]@{name=$env:USERNAME; language='PowerShell'; version=$PSVersionTable.PSVersion.Major} 

#Working with a custom object
#Create a custom object

$customobject = new-object -TypeName PSCustomObject		#-> Note it is empty by default 

#Validate it is empty

$customobject

#Show that Custom Object is a empty template that you can use to add types to.
#Use the custom object to restructure the data  about the c:\windows location.
$Result = @()
foreach ( $file in Get-ChildItem -Path c:\windows -file )
{
    $temp = new-object -TypeName PSCustomObject
    $temp | Add-Member -MemberType NoteProperty -Name filename -Value $file.name
    $temp | Add-Member -MemberType NoteProperty -Name path -Value $file.fullname
    $temp | Add-Member -MemberType NoteProperty -Name "size(Mb)" -Value ($file.length /1mb)
    $Result += $temp
}
$Result

#Same code adding hash tables via Select-Object

$Result2 = Get-ChildItem -Path c:\windows -file | Select-Object -Property `
@{name="Filename";Expression={$_.name}}, `
@{name="Path";Expression={$_.fullname}}, `
@{name="Size(MB)";Expression={$_.length /1mb}} 
$Result2 

#Or using single hash table to add onto the array		->  Note the output is no longer a nice table
$Result3 = @()
foreach ( $file in Get-ChildItem -Path c:\windows -file )
{
    $temp = `
    @{
        "Filename" = $file.name
        "Path" = $file.fullname
        "Size(MB)" = $file.length /1mb
     }
     $Result3 += $temp
}
$Result3 

#Using type casting to add a hashtable as pscustomobject to the array		->  Note the output is a nice table again
$Result4 = @()
foreach ( $file in Get-ChildItem -Path c:\windows -file )
{
    $temp = `
    [pscustomobject]@{
        "Filename" = $file.name
        "Path" = $file.fullname
        "Size(MB)" = $file.length /1mb
     }
     $Result4 += $temp
}
$Result4 


#* Lesson here is the add-member gives the most control and flexibility
##########
#endregion

#region: COM Object 

#View the list of all COM objects and show some of them:
$allcom =  Get-ChildItem -path HKLM:\Software\Classes | Where-Object -FilterScript `
{
    $_.PSChildName -match '^\w+\.\w+$' -and (Test-Path -Path "$($_.PSPath)\CLSID")
}

$allcom | More

#Or look for parameter values by finding namespace Get-CimClass -Namespace  using intellisense. 

$a = New-Object -comobject Excel.Application

$a.Visible = $True
$b = $a.Workbooks.Add()

$c = $b.Worksheets.Item(1)
$c.Cells.Item(1,1) = “A value in cell A1.”

$b.SaveAs(“C:\Scripts\Test.xls”)
$a.Quit()

#COM Object for automating Word document

$filePath = "C:\lit\PaperTemplate.docx"

$HeaderFooterIndex = "microsoft.office.interop.word.WdHeaderFooterIndex" -as [type]

$alignmentTab = "microsoft.office.interop.word.WdAlignmentTabAlignment" -as [type]

$word = New-Object -comobject word.application

$word.visible = $true

$doc = $word.documents.open($filePath)

$section = $doc.sections.item(1)

$header = $section.headers.item($HeaderFooterIndex::wdHeaderFooterFirstPage)

 

$header.range.InsertAlignmentTab($alignmentTab::wdRight)

$header.range.InsertAfter("First Page Header")

$doc.save()

$doc.close()

$word.quit()


Working with Wscript
Create a new COM object:
$wscript = new-object -ComObject wscript.shell

View the object 
$wscript | select *

Get objects members
$wscript | get-member

Start a application via the COM object
$wscript.run("utilman")

#Send a message
$wscript.popup("Hello From Windows PowerShell and COM") 


#Explorer the Shell.Application com object. Shell.Application is used to perform tasks like navigate the file system using Windows Explorer, launch control panel items and cascade and tile windows on the desktop
#Look at the members
$winshell = new-object -ComObject Shell.Application
$winshell | get-member

#Use a methode of Shell.Application
$winshell.minimizeAll()


Office automation
Even these powerpoints for the lab are being generated from about 50 individual PPTs via COM automation of powerpoint

Look at running word processes
get-process winword

Open a word document in PowerShell
$Word = New-Object -ComObject Word.Application	->   Note the application is running but bot yet visible	

Look at running word processes
get-process winword				-> Should be 1 more now while it is not visible on screen

Make word visible
$Word.Visible = $True

Add a new blank document
$Document = $Word.Documents.Add()

Add some text 
$Selection = $Word.Selection
$Selection.TypeText("My username is $($Env:USERNAME) and the date is $(Get-Date)")
$Selection.TypeParagraph()
$Selection.Font.Bold = 1
$Selection.TypeText("This is on a new line and bold!")

Save the document to file and exit
$Report = "C:\temp\MyFirstDocument.docx" 
$Document.SaveAs([ref]$Report,[ref]$SaveFormat::wdFormatDocument)
$word.Quit() 

# Look at $word again everything is empty and clean due to common language runtime (CLR) garbage collector. Memory will be cleaned up no need to call dispose or GC.Collect()

#Look at $word
$word

#Recreate a new word document this time use strict switch to see it is using the .NET COM Interop
$Word2 = New-Object -ComObject Word.Application -strict


#Uing Excel ComObject

$a = New-Object -comobject Excel.Application
$a.visible = $false 
Add-Type -AssemblyName Microsoft.Office.Interop.Excel
$xlFixedFormat = [Microsoft.Office.Interop.Excel.XlFileFormat]::xlWorkbookDefault

$b = $a.Workbooks.Add()
$c = $b.Worksheets.Item(1)

$c.Cells.Item(1,1) = "Server Name"
$c.Cells.Item(1,2) = "Drive"
$c.Cells.Item(1,3) = "Total Size (GB)"
$c.Cells.Item(1,4) = "Free Space (GB)"
$c.Cells.Item(1,5) = "Free Space (%)"

$d = $c.UsedRange
$d.Interior.ColorIndex = 19
$d.Font.ColorIndex = 11
$d.Font.Bold = $True

$intRow = 2

$colComputers = get-content "c:\servers.txt"
foreach ($strComputer in $colComputers)
{
    $colDisks = get-wmiobject Win32_LogicalDisk -computername $strComputer -Filter "DriveType = 3" 
    foreach ($objdisk in $colDisks)
    {
        $c.Cells.Item($intRow, 1) = $strComputer.ToUpper()
        $c.Cells.Item($intRow, 2) = $objDisk.DeviceID
        $c.Cells.Item($intRow, 3) = "{0:N0}" -f ($objDisk.Size/1GB)
        $c.Cells.Item($intRow, 4) = "{0:N0}" -f ($objDisk.FreeSpace/1GB)
        $c.Cells.Item($intRow, 5) = "{0:P0}" -f ([double]$objDisk.FreeSpace/[double]$objDisk.Size)
        $intRow = $intRow + 1
    }
}
$a.workbooks.OpenText($file,437,1,1,1,$True,$True,$False,$False,$True,$False)
$a.ActiveWorkbook.SaveAs("$home\Desktop\myfile.xls", $xlFixedFormat)

$a.Workbooks.Close()
$a.Quit() 


##########
#endregion

#region: Common Information Model (CIM)

Get-CimClass -ClassName *disk* 
#wmiv1
Get-Command -Noun *wmi* 

#wmiv2 (CIM)
Get-Command -noun *cim* 

##########
#endregion

#region: WMI and CIM Piecing it Together
Get-WmiObject –Query 'SELECT * FROM Win32_Share WHERE name like "%$" '
Get-CimInstance –Query 'SELECT * FROM Win32_Share WHERE name like  "%$" ' 

$folder = Get-WmiObject -Query 'Select * From Win32_Directory Where Name ="C:\\Test " ' 
$folder | Remove-WmiObject

$var = Get-CimInstance –Query 'Select * from Win32_Process where name LIKE "calc%" '
Remove-CimInstance –InputObject $var

Register-WmiEvent –Class 'Win32_ProcessStartTrace' `
-SourceIdentifier "ProcessStarted"
Get-Event -SourceIdentifier "ProcessStarted"  


Register-CimIndicationEvent –ClassName ` 'Win32_ProcessStartTrace' -SourceIdentifier "ProcessStarted"
Get-Event -SourceIdentifier "ProcessStarted"

#WMI Query Language
#https://docs.microsoft.com/en-us/windows/desktop/WmiSdk/wql-sql-for-wmi 



#Type Accelerator
# The String must evaluate to a WMI Path with Namespace and Filter using Key property.

[wmi]”root\cimv2:Win32_Service.Name='spooler'” 


# This method can also be used to invoke Static Methods of the WMI Class.

([wmiclass]”Win32_Process”).Create(“Notepad.exe”) 


# [wmisearcher] uses WQL to create WMI Queries

$query = [wmisearcher]"Select * FROM Win32_Service WHERE State='Running'"
$query.Get()

#Speed comparison between WMI and CIM

#http://maikkoster.com/cim-vs-wmi-cmdlets-speed-comparison/ 



#Demo WMI and CIM 

#Show WMI commands:
Get-Command -Noun *wmi*

#Show Cim commands:
Get-Command -Noun *cim*

#List objects:

#List WMI objects: 
Get-WMIObject -List 
(Get-WMIObject –List).count			#-> Should be the same as CIM

#List CIM objects
Get-CIMClass
(Get-CIMClass).count			#-> Should be the same as WMI

#Show some classes
Get-WMIObject –Class Win32_Operatingsystem
Get-CIMInstance –Class Win32_bios

#The prefix CIM or WIN32 don’t matter
Get-WMIObject –Class CIM_PhysicalMemory
Get-CIMInstance –Class Win32_PhysicalMemory



#Using WQL:
Get-CIMInstance -Query 'SELECT * FROM Win32_process WHERE PageFileUsage < 50000' 

#Removing a folder
New-Item -Type Directory -Path c:\cimtest
get-item -Path c:\cimtest
$folder = Get-WMIObject -Query 'Select * From Win32_Directory Where Name ="C:\\cimtest "'
Remove-WMIObject -InputObject $folder
get-item -Path c:\cimtest


##########
#endregion

#region: PSSEssions
# PowerShell Remoting creates a temporary runspace in which it is being executed. 
# When exit or command execution is completed. The runspace is not available any more - all variables, functions, aliases and modules loaded are gone. 

# This is why you cannot access the variables defined
Invoke-Command -ComputerName JEA1 -ScriptBlock {$a = 123; $b = 'abc'; $a; $b}
Invoke-Command -ComputerName JEA1 -ScriptBlock {$a; $b}

# Whenever you are connecting to another machine, a process is being launched on the remote side: wsmprovhost, containing the runspace
# Run multiple times to demonstrate that the process ID is different. This means new process is launched every time
Invoke-Command -ComputerName JEA1 -ScriptBlock {Get-Process -Name wsmprovhost | Format-Table -Property Name, Id}

# To create a persistent session we need to use New-PSSession
# you may specify alternative credentials as well (not required) -Credential Contoso\Administrator
New-PSSession -ComputerName JEA2 -OutVariable sess

# Process id is the same, as it is a persistant session. 
# Run multiple times, to demonstrate consistent Process ID
Invoke-Command -Session $sess -ScriptBlock {Get-Process -Name wsmprovhost | Format-Table -Property Name, Id}

# Because it is persistent all of the variables, aliases, functions and modules will be there each and every time when connected. 

# Declare variables
Invoke-Command -Session $sess -ScriptBlock {$a = 123; $b = 'abc'; $a; $b}

# Call variables multiple times, to demonstrate, that they are available 
Invoke-Command -Session $sess -ScriptBlock {$a; $b}

# If we run again with ComputerName parameter, it creates again a temporary session, where the variables have not been declared and not available
Invoke-Command -ComputerName JEA2 -ScriptBlock {$a; $b}   # returns NULL

# If we check the process, we'll see two results - one for the persistent session and one for the temporary
Invoke-Command -ComputerName JEA2 -ScriptBlock {Get-Process -Name wsmprovhost | Format-Table -Property Name, Id}

#Run multiple times, to demonstrate that one process ID is constant (the persistent session), the other is changing (temporary session)

##########
#endregion

#region: Disconnected session
# Invoke in disconnected session
Invoke-Command -ComputerName JEA2 -ScriptBlock {Get-Service} -InDisconnectedSession

# Show Session locally
Get-PSSession  

# show session on the remote computer
Get-PSSession -ComputerName JEA2

# Store session into variable
$sess = Get-PSSession -ComputerName JEA2

# Demo Connect and Disconnect
# Comment on state and availability
Connect-PSSession -ComputerName JEA2
Disconnect-PSSession -Session $sess

# Connect and Receive the output
# Receive also connects
Receive-PSSession -Session $sess

# Close the session
Get-PSSession | Remove-PSSession
Get-PSSession -ComputerName JEA2 | Remove-PSSession
Exit-PSSession

##########
#endregion

#region: Implicit remoting
# Create a persistent session
 $sess = New-PSSession -ComputerName JEA2

# Import a single CmdLet into the session
Import-PSSession -Session $sess -CommandName Get-WindowsFeature -Prefix Remote 

# Compare the commands
get-command -Verb Get -Noun *WindowsFeature
 
# Execute the commandlet
Get-WindowsFeature -Name AD-Domain-Services

# Execute the remote cmdlet. Feature installed on the remote computer. 
Get-RemoteWindowsFeature -Name AD-Domain-Services

# Close session
Remove-PSSession -Session $sess

#... and re-create
$sess = New-PSSession -ComputerName JEA2

# Import module into the session
Import-Module -Name NetTCPIP -PSSession $sess -Prefix Remote

# List Remote Commands
Get-Command -Noun Remote* -Module NetTCPIP

# Execute original command on the local computer 
Get-NetIPConfiguration

# Execute implicit remoting commnad on DC and compare IP Addresses
Get-RemoteNetIPConfiguration

#endregion

#region: Robust Session 

Invoke-Command -ComputerName JEA2 -ScriptBlock{ 1..300 | foreach {Write-Host "." -NoNewline ; sleep -Seconds 100}}

Get-PSSession | Select-Object -Property State, IdleTimeout, DisconnectedOn, ExpiresOn, ComputerType, ComputerName, ConfigurationName, Id, Name, Availability 

##########
#endregion

#region: security
#Walk trough WSMan provider
#Client – how we are connecting to remote machines

# Default ports
Get-ChildItem -Path WSMan:\localhost\Client\DefaultPorts\

# Authentication methods
    Get-ChildItem -Path WSMan:\localhost\Client\Auth\
     
#Service – how remote machines are connecting to us

# Explain endpoints authentication – Permissions, RunAs
Get-PSSessionConfiguration

# Explain how to change permissions 

Set-PSSessionConfiguration -Name microsoft.powershell –ShowSecurityDescriptorUI  #Only comment on permissions, do not change!! 
Set-PSSessionConfiguration –SecurityDescriptorSddl # Comment: Bind existing SDDL with –SecurityDescriptorSddl parameter
Set-PSSessionConfiguration –RunAsCredential    # Comment: Bind alternate credential with –RunAsCredential parameter



#Details on custom endpoints will be discussed in module 06 JEA JIT

#endregion

#region: Trusted Hosts

Get-ChildItem WSMan:\localhost\Client\TrustedHosts

# Using Kerberos - works
Invoke-Command -ComputerName JEA2.shadab.int -ScriptBlock {"Testing Trustedhosts"} -Credential Shadab\suser

# Using NTLM – does not work
Invoke-Command -ComputerName  10.10.10.6 -ScriptBlock {"Testing Trustedhosts"} -Credential Shadab\suser

# TruestedHosts is empty by default
Get-Item -Path WSMan:\localhost\Client\TrustedHosts

# Add IP to TrustedHosts for MS.contoso.local
Set-Item -Path WSMan:\localhost\Client\TrustedHosts -value 10.10.10.4 –Force	# apply settings
Get-Item -Path WSMan:\localhost\Client\TrustedHosts			# confirm settings

# Using NTLM – Now works
Invoke-Command -ComputerName 10.10.10.6 -ScriptBlock {"Testing Trustedhosts"} -Credential Shadab\suser


# Remove TrustedHosts
Set-Item -Path WSMan:\localhost\Client\TrustedHosts –value ’’ –Force				# Back to default
Invoke-Command -ComputerName 10.10.10.6 -ScriptBlock {"Testing Trustedhosts"} -Credential shadab\suser	# Does not work again


##########
#endregion

#region: create SSL endpoint
#  Execute on computer JEA2, as remoting is not enabled on Win10 computer

# We need to have a Server Auth Certificate with Private Key
# Creating a self-signed for the demo

Get-ChildItem Cert:\LocalMachine\my -SSLServerAuthentication # No Server Auth certs at the moment

# Createing the cert and store it into a variable
$cert = New-SelfSignedCertificate -Type SSLServerAuthentication -Subject 'DC1.shadab.int' -CertStoreLocation Cert:\LocalMachine\My

# Confirming the existence 
Get-ChildItem Cert:\LocalMachine\my -SSLServerAuthentication

#Verify if any existing certificate can be used 

Get-ChildItem Cert:\LocalMachine\My | 
    Where {$_.hasprivatekey -and $_.EnhancedKeyUsageList.FriendlyName `
	-contains 'Server Authentication'} |
        Format-List thumbprint,EnhancedKeyUsageList,DNSNameList,Issuer  


# Export the cert and import it as Trusted Root CA
Export-Certificate -Cert $cert -FilePath .\DC1_Cert.cer
Import-Certificate -FilePath .\DC1_Cert.cer -CertStoreLocation Cert:\LocalMachine\Root



# For the moment using SSL still does not work. We need to create HTTPS listener with this certificate
Invoke-Command -ComputerName DC1.shadab.int -ScriptBlock {"Testing SSL"} -UseSSL

# Currently only HTTP Listener is available
Get-ChildItem -Path WSMan:\localhost\Listener

# ... and computer listens only on port HTTP = 5985
Get-NetTCPConnection | Where-Object -Property LocalPort -like 598*

# Creating HTTPS Listener with the certificate thumbprint 
#$cert was created in above steps and we can use $cert.thumbprint
#or $cert.pschildname to retrieve thumprint of our certificate
New-Item -Path WSMan:\localhost\Listener -ItemType Listener -Address * -Transport HTTPS -CertificateThumbPrint $cert.PSChildName  -Force

# Confirming that we have HTTPS listener created
Get-ChildItem -Path WSMan:\localhost\Listener

# ... and that the computer listnens on port HTTPS = 5986 as well
Get-NetTCPConnection | Where-Object -Property LocalPort -like 598*

# No existing connections on HTTPS = 5986
Get-NetTCPConnection -RemotePort 5986 # Result in an error

# Now the using UseSSL parameter works 

#The exported certificate needs to be imported on connecting machine

Invoke-Command -ComputerName JEA2.shadab.int -ScriptBlock {"Testing SSL"} -UseSSL

# Confirming the established connection in TimeWait state
Get-NetTCPConnection -RemotePort 5986

# Remove all

# Remove Listener
Get-ChildItem WSMan:\localhost\Listener\Listener | Where-Object -Property Keys -Like '*HTTPS*' | remove-item -Recurse -Force

# Confirm HTTPS Listener removal
Get-ChildItem -Path WSMan:\localhost\Listener

# Confirm Computer does not listen on port HTTPS = 5986 anymore
Get-NetTCPConnection | Where-Object -Property LocalPort -like 598*

# Remove the certificates from the personal and Root store

Get-ChildItem Cert:\LocalMachine\My\$($cert.PSChildName) | Remove-Item -Force
Get-ChildItem Cert:\LocalMachine\Root\$($cert.PSChildName) | Remove-Item -Force 


##########
#endregion

#region: Working with passwords
# Create credentials object
$UserName = 'Shadab\test'
$secureString = ConvertTo-SecureString -String 'password' -AsPlainText -Force

# Result
$secureString

$plaintext = ConvertFrom-SecureString -SecureString $secureString -
$plaintext


#ExportCliXMl can also store securestring in a file

$secureString | Export-Clixml .\securestring.txt

# Create PSCredential object
$cred = New-Object -TypeName PSCredential -ArgumentList $UserName, $secureString
# Result
$cred

$cred1 = Get-Credential
$cred1
# Demo that it works with the created credentials
Invoke-Command -ComputerName JEA2 -ScriptBlock {whoami} -Credential $cred

# Convert secure string as  encrypted string. 
$encryptedString = ConvertFrom-SecureString -SecureString $secureString

# Result
$encryptedString

# Convert back to Secure string
$convertedString = ConvertTo-SecureString -String $encryptedString

# Result
$convertedString

# Create PSCredential object with the converted secure string
$convertedCred = New-Object -TypeName PSCredential -ArgumentList $UserName, $convertedString

# Result
$convertedCred
$ConvertedCred.GetNetworkCredential().Password

# Demo that it works again
Invoke-Command -ComputerName JEA2 -ScriptBlock {whoami} -Credential $convertedCred

# Cannot construct secure string from encrypted string, as it is encrypted twice : User and Computer
# Demo: When try to reconstruct secure string from encrypted string on another machine - it fails! 
Invoke-Command -ComputerName JEA2 -ScriptBlock {$using:encryptedString}  # sending the credentials
Invoke-Command -ComputerName JEA2 -ScriptBlock {ConvertTo-SecureString -String $using:encryptedString} # try to re-construct - fails!
# Result: Key not valid for use in specified state. 


##########


####Since the encryption is based on DPAPI based on the user’s context 
#and the machine the SecureString was created on, 
#it can be handy to know where that happened. 
#You can add a NoteProperty as an FYI before you export it as XML.

$PSCredential | Add-Member -NotePropertyName Origin -NotePropertyValue $env:COMPUTERNAME

#endregion

#region: revision

$service = Invoke-Command -ComputerName jea2 -ScriptBlock {Get-Service bits}

#Why this method invocation fails?
$service.stop()

#endregion