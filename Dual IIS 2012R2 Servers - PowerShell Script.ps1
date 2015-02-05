#region Deployment of IIS, FTP and ASP .Net Site\n
                         Function Deploy-AspdotNet(){\n
                             [CmdletBinding()]\n
                                Param(\n
                                        [String]$DomainName = \"example.com\",\n
                                        [String]$FtpUserName = \"ftpuser01\",\n 
                                        [String]$FtpPassword = \"Passw0rd\",\n
                                        [String]$Logfile = \"C:undefinedWindowsundefinedTempundefinedDeploy-AspdotNet.log\"\n
                                        )\n
                                Set-Content .undefinedsuper.txt $FtpPassword\n
                         #region Create Log File\n
                                if (!( Test-Path $Logfile)){\n
                                    New-Item -Path \"C:undefinedWindowsundefinedTempundefinedDeploy-AspdotNet.log\" -ItemType file\n
                                    }\n
                         #endregion\n
                         #region Write Log file\n
                            Function WriteLog{\n
                                Param ([string]$logstring)\n
                                    Add-content $Logfile -value $logstring\n
                                    }\n    
                         #endregion\n
                         #region Variables\n
                            $webRoot = \"$env:systemdriveundefinedinetpubundefinedwwwrootundefined\"\n
                            $webFolder = $webRoot + $DomainName\n
                            $appPoolName = $DomainName\n
                            $siteName = $DomainName\n
                            $ftpName = \"ftp_\" + $DomainName\n
                            $appPoolIdentity = \"IIS AppPoolundefined$appPoolName\"\n
                         #endregion\n
                         #region Create Automation Login\n
                            Function Create-User($User,$Password) {\n
                                try{\n
                                    if($Password -match $null){\n
                                        Write-Host \"[$(Get-Date)] Error: wffadmin is set with the password $Password\"\n
                                    }\n
                                $hostname = $env:ComputerName\n
                                $objComputer = [ADSI](\"WinNT://$hostname,computer\")\n
                                $colUsers = ($objComputer.psbase.children |\n
                                    Where-Object {$_.psBase.schemaClassName -eq \"User\"} |\n
                                    Select-Object -expand Name)\n
                                    if($colUsers -contains $User){\n
                                        ([ADSI](\"WinNT://$hostname/$User\")).SetPassword($Password)\n
                                        WMIC USERACCOUNT WHERE \"Name='$User'\" SET PasswordExpires=FALSE >$null\n
                                        Write-Host \"[$(Get-Date)] Status: Completed $user update with password $Password\"\n
                                    }\n
                                    else {\n
                                        net user /add $User $Password /expires:never /passwordchg:no /comment:\"Automation\" > $null\n
                                        WMIC USERACCOUNT WHERE \"Name='$User'\" SET PasswordExpires=FALSE > $null\n
                                        net localgroup administrators $User /add > $null\n
                                        Write-Host \"[$(Get-Date)] Status: Completed $user creation with password $Password\"\n
                                        #return $Password\n
                                        }\n
                                    }\n
                                    catch [Exception] {\n
                                        Write-Host \"[$(Get-Date)] Error: $_\"\n
                                        return\n
                                        }\n
                                    }\n
                         #endregion\n
                         #region Install IIS and ASP\n
                            Function Install-AspWebServer (){\n
                                Write-Host \"[$(Get-Date)] Installing IIS and ASP .Net\"\n
                                Import-Module servermanager\n
                                    Add-WindowsFeature Web-Server,Web-WebServer,Web-Common-Http,Web-Default-Doc,Web-Dir-Browsing,Web-Http-Errors,Web-Static-Content,Web-Http-Redirect,Web-Health,Web-Http-Logging,Web-Custom-Logging,Web-Log-Libraries,Web-ODBC-Logging,Web-Request-Monitor,Web-Http-Tracing,Web-Performance,Web-Stat-Compression,Web-Dyn-Compression,Web-Security,Web-Filtering,Web-Basic-Auth,Web-CertProvider,Web-Client-Auth,Web-Digest-Auth,Web-Cert-Auth,Web-IP-Security,Web-Url-Auth,Web-Windows-Auth,Web-App-Dev,Web-Net-Ext,Web-Net-Ext45,Web-AppInit,Web-ASP,Web-Asp-Net,Web-Asp-Net45,Web-CGI,Web-ISAPI-Ext,Web-ISAPI-Filter,Web-Includes,Web-WebSockets,Web-Mgmt-Tools,Web-Mgmt-Console,Web-Mgmt-Compat,Web-Metabase,Web-Lgcy-Mgmt-Console,Web-Scripting-Tools > $null\n
                            }\n
                         #endregion\n
                         #region Install FTP\n
                            Function Install-FTPserver () {\n
                                Import-Module ServerManager\n
                                $out = Add-WindowsFeature -Name Web-Ftp-Server -IncludeAllSubFeature\n
                                if ($out.ExitCode -eq \"NoChangeNeeded\"){\n
                                    Write-Host \"[$(Get-Date)] FTP server is already installed\"\n
                                }\n
                                else {\n
                                    Write-Host \"[$(Get-Date)] FTP Server and dependencies have been installed\"\n
                                }\n
                            }\n
                         #endregion\n
                         #region Create A Website in IIS\n
                            Function Create-Website ($webSiteName, $webSiteFolder, $webAppPoolName){\n
                               try{\n
                                  Write-Host \"[$(Get-Date)] Creating the $webSiteName\"\n 
                                  New-Item $webSiteFolder -type directory -Force >$null\n
                                  Stop-Website -Name 'Default Web Site'\n
                                  New-WebAppPool $webAppPoolName > $null\n
                                  New-Website -Name $webSiteName -Port 80 -IPAddress \"*\" -HostHeader $webSiteName -PhysicalPath $webSiteFolder -ApplicationPool $webAppPoolName -Force > $null\n
                                }\n
                               catch{\n
                                  throw \"Error : $_\"\n
                               }\n
                            }\n
                        #endregion\n
                        #region Remove a Website in IIS\n
                            Function Remove-Website($webAppPoolName, $webSiteFolder, $webSiteName){\n
                                try{\n
                                    if($webSiteFolder -ne $null){\n
                                        if((Test-Path -PathType Container -path $webSiteFolder)){\n
                                            $siteStatus = get-website -Name $webSiteName\n
                                            $siteAppPoolStatus = Get-Item \"IIS:undefinedAppPoolsundefined$webSiteName\"\n
                                            if((Get-WebsiteState -Name \"$webSiteName\").Value -ne \"Stopped\") {\n
                                                $siteStatus.Stop()\n
                                            }\n
                                            if((Get-WebAppPoolState -Name $webAppPoolName).Value -ne \"Stopped\") {\n
                                                $siteAppPoolStatus.Stop()\n
                                            }\n 
                                            Write-Host \"[$(Get-Date)] Removing the Web site $webSiteName\"\n
                                            Remove-Website -Name $webSiteName\n
                                            Write-Host \"[$(Get-Date)] Removing the Application pool $webAppPoolName\"\n
                                            Remove-WebAppPool -Name $webAppPoolName\n
                                            Write-Host \"[$(Get-Date)] Removing the Site Directory if $webAppPoolName\"\n
                                            Remove-Item $webSiteFolder -Recurse -Force\n
                                            }\n
                                            else{\n
                                            Write-Host \"[$(Get-Date)] The site $webSiteName is not present\"\n
                                            }\n 
                                        }\n
                                }\n
                                catch{\n
                                    throw \"Error : $_\"\n
                                }\n 
                            }\n 
                         #endregion\n    
                         #region Create a FTP site\n
                             Function Create-FtpSite($DefaultFtpSiteName,$DefaultFtpUser,$DefaultFtpPassword){\n
                                 function New-SelfSignedCert{\n
                                    [CmdletBinding()]\n
                                    [OutputType([int])]\n
                                    Param\n
                                    (\n
                                       [Parameter(Mandatory=$true,\n
                                       ValueFromPipeLine=$true,\n
                                       Position=0)]\n
                                    [string[]]$Subject = \"demo.demo.com\"\n
                                    ,\n
                                    [Parameter(Mandatory=$true,\n
                                      ValueFromPipelineByPropertyName=$true,\n
                                      Position=1)]\n
                                     [ValidateSet(\"User\",\"Computer\")]\n
                                     [string]$CertStore = \"Computer\"\n
                                     ,\n
                                    [ValidateSet(\"Y\",\"N\")]\n
                                    [string]$EKU_ServerAuth =  \"Y\"\n
                                    ,\n
                                    [ValidateSet(\"Y\",\"N\")]\n
                                    [string]$EKU_ClientAuth =  \"Y\"\n
                                    ,\n
                                    [ValidateSet(\"Y\",\"N\")]\n
                                    [string]$EKU_SmartCardAuth =  \"Y\"\n
                                    ,\n
                                    [ValidateSet(\"Y\",\"N\")]\n
                                    [string]$EKU_EncryptFileSystem =  \"Y\"\n
                                    ,\n
                                   [ValidateSet(\"Y\",\"N\")]\n
                                    [string]$EKU_CodeSigning =  \"Y\"\n
                                    ,\n 
                                   [ValidateSet(\"Y\",\"N\")]\n 
                                   [string]$AsTrustedRootCert =  \"N\"\n
                                    )\n
                                    Begin{\n
                                       $ErrorActionPreference = \"SilentlyContinue\"\n
                                        If ($CertStore -eq \"User\"){\n
                                            $machineContext = 0\n
                                            $initContext = 1\n
                                        }\n
                                        ElseIF ($CertStore -eq \"Computer\"){\n
                                            $machineContext = 1\n 
                                            $initContext = 2\n
                                        }\n
                                        Else{\n
                                            Write-Error \"Invalid selection\"\n
                                            Exit\n
                                        }\n
                                    }\n 
                                   Process{\n 
                                       $OS = (Get-WmiObject Win32_OperatingSystem).Version\n
                                            if ($OS[0] -ge 6) {\n
                                               foreach ($sub in $Subject){\n                    
                            #Generate cert in local computer My store\n
                             $name = new-object -com \"X509Enrollment.CX500DistinguishedName.1\"\n
                             $name.Encode(\"CN=$sub\", 0)\n
                             $key = new-object -com \"X509Enrollment.CX509PrivateKey.1\"\n
                             $key.ProviderName = \"Microsoft RSA SChannel Cryptographic Provider\"\n
                             $key.KeySpec = 1\n
                             $key.Length = 2048\n
                             $key.SecurityDescriptor = \"D:PAI(A;;0xd01f01ff;;;SY)(A;;0xd01f01ff;;;BA)(A;;0x80120089;;;NS)\"\n
                             $key.MachineContext = $machineContext\n
                             $key.ExportPolicy = 1\n
                             $key.Create()\n 
                             $ekuoids = new-object -com \"X509Enrollment.CObjectIds.1\"\n                    
                            #Enhanced Key Usage `(EKU`) by answering Y/N\n
                             If ($EKU_ServerAuth -eq \"Y\"){\n
                                $serverauthoid = new-object -com \"X509Enrollment.CObjectId.1\"\n
                                $serverauthoid.InitializeFromValue(\"1.3.6.1.5.5.7.3.1\")\n
                                $ekuoids.add($serverauthoid)\n
                             }\n    
                             If ($EKU_ClientAuth -eq \"Y\"){\n
                                $clientauthoid = new-object -com \"X509Enrollment.CObjectId.1\"\n
                                $clientauthoid.InitializeFromValue(\"1.3.6.1.5.5.7.3.2\")\n 
                                $ekuoids.add($clientauthoid)\n 
                             }\n
                             If ($EKU_SmartCardAuth -eq \"Y\"){\n
                                $smartcardoid = new-object -com \"X509Enrollment.CObjectId.1\"\n
                                $smartcardoid.InitializeFromValue(\"1.3.6.1.4.1.311.20.2.2\")\n
                                $ekuoids.add($smartcardoid)\n
                             }\n          
                             If ($EKU_EncryptFileSystem -eq \"Y\"){\n
                                $efsoid = new-object -com \"X509Enrollment.CObjectId.1\"\n
                                $efsoid.InitializeFromValue(\"1.3.6.1.4.1.311.10.3.4\")\n
                                $ekuoids.add($efsoid)\n
                             }\n
                             If ($EKU_CodeSigning -eq \"Y\"){\n
                                $codesigningoid = new-object -com \"X509Enrollment.CObjectId.1\"\n
                                $codesigningoid.InitializeFromValue(\"1.3.6.1.5.5.7.3.3\")\n
                                $ekuoids.add($codesigningoid)\n
                             }\n
                                $ekuext = new-object -com \"X509Enrollment.CX509ExtensionEnhancedKeyUsage.1\"\n
                                $ekuext.InitializeEncode($ekuoids)\n 
                                $cert = new-object -com \"X509Enrollment.CX509CertificateRequestCertificate.1\"\n
                                $cert.InitializeFromPrivateKey($initContext, $key, \"\")\n    
                                $cert.Subject = $name\n   
                                $cert.Issuer = $cert.Subject\n 
                                $cert.NotBefore = get-date\n 
                                $cert.NotAfter = $cert.NotBefore.AddDays(3650)\n 
                                $cert.X509Extensions.Add($ekuext)\n  
                                $cert.Encode()\n    
                                $enrollment = new-object -com \"X509Enrollment.CX509Enrollment.1\"\n
                                $enrollment.InitializeFromRequest($cert)\n  
                                $certdata = $enrollment.CreateRequest(1)\n  
                                $enrollment.InstallResponse(2, $certdata, 1, \"\")\n 
                                Write-Verbose \"$($sub) has been added the Certificate to the Store $($CertStore)\"\n
                        #Install the certificate to Trusted Root Certification Authorities\n
                            if ($AsTrustedRootCert -eq \"Y\") {\n
                               [Byte[]]$bytes = [System.Convert]::FromBase64String($certdata)\n 
                               foreach ($Store in \"Root\", \"TrustedPublisher\") {\n
                                    $x509store = New-Object Security.Cryptography.X509Certificates.X509Store $Store, \"LocalMachine\"\n
                                    $x509store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)\n
                                    $x509store.Add([Security.Cryptography.X509Certificates.X509Certificate2]$bytes)\n
                                    $x509store.Close()\n
                                }\n
                            }\n
                                Write-Verbose \"$($sub) has been added the Certificate to the Store $($Store)\"\n
                                }\n
                            }\n 
                            else{\n  
                              Write-Warning \"The Operating System must be at LEAST Windows Server 2008\"\n
                              }\n
                            }\n
                            End{\n
                                Write-Host \"Completed :: New Certificate(s) Created and Installed\" -ForegroundColor Green\n
                                Write-Verbose \"Execution finished...\"\n
                            }\n
                            }\n
                                Import-Module WebAdministration\n
                                $DefaultFtpPath = \"C:undefinedinetpubundefinedwwwrootundefined\"\n
                                $DefaultNonSecureFtpPort = 21\n    

                        # Create FTP user Account\n
                            net user /add $DefaultFtpUser $DefaultFtpPassword > $null\n
                            Write-Host \"[$(Get-Date)] Completed '$DefaultFtpUser' creation\"\n
                            New-WebFtpSite -Name $DefaultFtpSiteName -PhysicalPath $DefaultFtpPath -Port $DefaultNonSecureFtpPort -IPAddress * > $null \n

                        # Apply permissions to wwwroot Folder\n
                            $acl = (Get-Item $DefaultFtpPath).GetAccessControl(\"Access\")\n
                            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($DefaultFtpUser,\"Modify\",\"ContainerInherit, ObjectInherit\",\"None\",\"Allow\")\n
                            $acl.AddAccessRule($rule)\n
                            Set-Acl $DefaultFtpPath $acl\n    
                        # Configure IIS Site Properties\n
                                Set-ItemProperty IIS:undefinedSitesundefined$DefaultFtpSiteName -Name ftpServer.security.ssl.controlChannelPolicy -Value 0\n
                                Set-ItemProperty IIS:undefinedSitesundefined$DefaultFtpSiteName -Name ftpServer.security.ssl.dataChannelPolicy -Value 0\n
                                Set-ItemProperty IIS:undefinedSitesundefined$DefaultFtpSiteName -Name ftpServer.security.ssl.ssl128 -Value $true\n
                                Set-ItemProperty IIS:undefinedSitesundefined$DefaultFtpSiteName -Name ftpServer.security.authentication.basicAuthentication.enabled -Value $true\n

                        # Alter FTPServer Configuration\n
                            # Add Allow rule for our ftpGroup (Permission=3 ==> Read+Write)\n
                                Add-WebConfiguration \"/system.ftpServer/security/authorization\" -value @{accessType=\"Allow\"; users=$DefaultFtpUser; permissions=3} -PSPath IIS:undefined -location $DefaultFtpSiteName\n 
                            # Change the lower and upper dataChannel ports\n
                                            $firewallSupport = Get-WebConfiguration system.ftpServer/firewallSupport\n
                                            $firewallSupport.lowDataChannelPort = 5001\n
                                            $firewallSupport.highDataChannelPort = 5050\n
                                            $firewallSupport | Set-WebConfiguration system.ftpServer/firewallSupport\n
                                            New-SelfSignedCert -Subject $DefaultFtpSiteName -CertStore Computer -EKU_ServerAuth Y -EKU_ClientAuth Y -EKU_SmartCardAuth Y -EKU_EncryptFileSystem Y -EKU_CodeSigning Y -AsTrustedRootCert Y > $null\n
                                            cd Microsoft.PowerShell.SecurityundefinedCertificate::localmachineundefinedmy\n
                                            $cert = Get-ChildItem | Where-Object {$_.subject -match $DefaultFtpSiteName } | select thumbprint | foreach { $_.thumbprint }\n
                                            Set-ItemProperty IIS:undefinedSitesundefined$DefaultFtpSiteName -Name ftpServer.security.ssl.serverCertHash -Value $cert\n
                                            Write-Host \"[$(Get-Date)] FTP Certificate $cert\"\n
                                            Write-Host \"[$(Get-Date)] Completed $DefaultFtpSiteName creation\"\n
                                            netsh advfirewall set global StatefulFTP disable > $null\n
                                            Write-Host \"[$(Get-Date)] Stateful FTP is disabled\"\n
                                            Write-Host \"[$(Get-Date)] Restart FTP service\"\n
                                            Restart-Service ftpsvc > $null\n
                                            cd c:undefined\n}\n 
                        #endregion\n
                        #region Enable HTTP and HTTPS ports\n
                            Function Enable-WebServerFirewall(){\n
                                write-host \"[$(Get-Date)] Enabling port 80\"\n
                                netsh advfirewall firewall set rule group=\"World Wide Web Services (HTTP)\" new enable=yes > $null\n 
                                write-host \"[$(Get-Date)] Enabling port 443\"\n
                                netsh advfirewall firewall set rule group=\"Secure World Wide Web Services (HTTPS)\" new enable=yes > $null\n
                            }\n    
                        #endregion\n  
                        #region Clean Deployment\n
                            Function Clean-Deployment{\n
                        #region Remove Automation initial firewall rule opener\n
                                if((Test-Path -Path 'C:undefinedCloud-Automation')){\n
                                    Remove-Item -Path 'C:undefinedCloud-Automation' -Recurse > $null\n
                                }\n
                        #endregion\n
                        #region Schedule Task to remove the Psexec firewall rule\n
                            $DeletePsexec = {\n
                            Remove-Item $MyINvocation.InvocationName\n 
                            $find_rule = netsh advfirewall firewall show rule \"PSexec Port\"\n
                                if ($find_rule -notcontains 'No rules match the specified criteria.') {\n
                                    Write-Host \"Deleting firewall rule\"\n
                                    netsh advfirewall firewall delete rule name=\"PSexec Port\" > $null\n
                                }\n
                            }\n
                            $Cleaner = \"C:undefinedWindowsundefinedTempundefinedcleanup.ps1\"\n
                                Set-Content $Cleaner $DeletePsexec\n
                                $ST_Username = \"autoadmin\"\n
                                net user /add $ST_Username $FtpPassword\n
                                net localgroup administrators $ST_Username /add\n
                                $ST_Exec = \"C:undefinedWindowsundefinedSystem32undefinedWindowsPowerShellundefinedv1.0undefinedpowershell.exe\"\n
                                $ST_Arg = \"-NoLogo -NonInteractive -WindowStyle Hidden -ExecutionPolicy ByPass C:undefinedWindowsundefinedTempundefinedcleanup.ps1\"\n
                                $ST_A_Deploy_Cleaner = New-ScheduledTaskAction -Execute $ST_Exec -Argument $ST_Arg\n
                                $ST_T_Deploy_Cleaner = New-ScheduledTaskTrigger -Once -At ((Get-date).AddMinutes(2))\n
                                $ST_S_Deploy_Cleaner = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -WakeToRun -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances Parallel\n
                      #$ST_ST_Deploy_Cleaner = New-ScheduledTask -Action $ST_A_Deploy_Cleaner -Trigger $ST_T_Deploy_Cleaner -Settings $ST_S_Deploy_Cleaner\n
                                Register-ScheduledTask -TaskName \"Clean Automation\" -TaskPath undefined -RunLevel Highest -Action $ST_A_Deploy_Cleaner -Trigger $ST_T_Deploy_Cleaner -Settings $ST_S_Deploy_Cleaner -User $ST_Username -Password $FtpPassword *>> $Logfile\n
                        #endregion\n
                            }\n
                        #endregion\n
                        #region MAIN\n 
                            Install-AspWebServer\n
                            Install-FTPserver\n
                            Create-Website -webSiteName $siteName -webSiteFolder $webFolder -webAppPoolName $appPoolName\n
                            Set-Content .undefinedsuper.txt \"$FtpPassword\"\n
                            Create-FtpSite -DefaultFtpSiteName $ftpName -DefaultFtpUser $FtpUserName -DefaultFtpPassword $FtpPassword\n
                            Enable-WebServerFirewall\n
                            Clean-Deployment\n
                        #endregion\n
                                       }\n
                        #endregion\n
                        #region MAIN : Deploy ASP .Net site with FTP\n
                        #region Delete myself from the filesystem during execution\n
                        #Remove-Item $MyINvocation.InvocationName\n
                        #endregion\n
                            New-Item -ItemType file -Name super.txt\n
                            Deploy-AspdotNet -DomainName \"%%sitedomain2\" -FtpUserName \"%%ftpusername2\" -FtpPassword \"%%ftppassword2\"\n
                        #endregion\n"