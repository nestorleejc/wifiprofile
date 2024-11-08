<# WLAN_profile schema: 
https://learn.microsoft.com/en-us/windows/win32/nativewifi/wlan-profileschema-elements
Based on the 'WPA2-Personal profile sample':
https://learn.microsoft.com/en-us/windows/win32/nativewifi/wpa2-personal-profile-sample

### Wi-Fi-EAP-TTLS-PAP-with-JumpCloud ###

Please define the parameters below according to your environment.
#>

### Start of configuration ###
# Please specify the name of your network here:
$Name = 'Micah Corporate WiFi'
# Please specify your PreShareKey (or other type of credentials) here:
#not-in-use $PSK = 'MyPreSharedKey' # https://learn.microsoft.com/en-us/windows/win32/nativewifi/wlan-profileschema-elements
# Please specify the name of the SSID here:
$SSID = 'Micah Corporate WiFi'
# Please specify the Connection Type (IBSS for AdHoc; ESS for Infrastructure) here:
$ConnectionType = 'ESS' 
# Please specify the Connection Mode (Auto or Manual) here:
#not-in-use $ConnectionMode = 'Auto' 
### End of configuration ###

# Generate random Guid for the profile
$guid = New-Guid
# 'hexing' the SSID
$HexArray = $SSID.ToCharArray() | foreach-object { [System.String]::Format("{0:X}", [System.Convert]::ToUInt32($_)) }
$HexSSID = $HexArray -join ""

# Generate the XML-Profile
@"
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
	<name>$Name</name>
	<SSIDConfig>
		<SSID>
			<hex>$HexSSID</hex>
			<name>$SSID</name>
		</SSID>
		<nonBroadcast>true</nonBroadcast>
	</SSIDConfig>
	<connectionType>$ConnectionType</connectionType>
	<connectionMode>auto</connectionMode>
	<autoSwitch>false</autoSwitch>
	<MSM>
		<security>
			<authEncryption>
				<authentication>WPA2</authentication>
				<encryption>AES</encryption>
				<useOneX>true</useOneX>
			</authEncryption>
			<OneX xmlns="http://www.microsoft.com/networking/OneX/v1">
				<cacheUserData>true</cacheUserData>
				<authMode>user</authMode>
				<EAPConfig><EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig"><EapMethod><Type xmlns="http://www.microsoft.com/provisioning/EapCommon">21</Type><VendorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorId><VendorType xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorType><AuthorId xmlns="http://www.microsoft.com/provisioning/EapCommon">311</AuthorId></EapMethod><Config xmlns="http://www.microsoft.com/provisioning/EapHostConfig"><EapTtls xmlns="http://www.microsoft.com/provisioning/EapTtlsConnectionPropertiesV1"><ServerValidation><ServerNames></ServerNames><TrustedRootCAHash>19 72 95 8A 0D 85 B2 63 A0 78 B4 19 18 DA 0D 72 A7 1E D0 DE</TrustedRootCAHash><DisablePrompt>false</DisablePrompt></ServerValidation><Phase2Authentication><PAPAuthentication/></Phase2Authentication><Phase1Identity><IdentityPrivacy>true</IdentityPrivacy><AnonymousIdentity>anonymous</AnonymousIdentity></Phase1Identity></EapTtls></Config></EapHostConfig></EAPConfig>
			</OneX>
		</security>
	</MSM>
</WLANProfile>

"@ | out-file "C:\Windows\Temp\$guid.xml" 

# Apply Wifi-Profile
netsh wlan add profile filename="C:\Windows\Temp\$guid.xml" user=all

function DownloadFile()
{
    param(
        [Parameter(Mandatory)]
        [string]$DownloadFileURI,
        [Parameter(Mandatory)]
        [string]$OutFilePath
    )

    try
    {
        Invoke-WebRequest -URI $DownloadFileURI -OutFile $OutFilePath
    }
    catch
    {
        Write-Error -Message "Failed to download $DownloadFileURI"
        Write-Host $_
        exit 1
    }
}

function ValidateHash()
{
    param(
        [Parameter(Mandatory)]
        [string]$CertFilePath,
        [Parameter(Mandatory)]
        [string]$CertHashFilePath
    )

    try
    {
        $HashToValidate = certutil -hashfile $CertFilePath MD5 | Out-String | % { ($_ -split '\r?\n')[1] };
        $HashPattern = "[a-fA-F0-9]{32}";
        $KnownHash = Select-String -Path $CertHashFilePath -Pattern $HashPattern | % { $_.matches.Groups[0] } | % { $_.Value }
        return ($HashToValidate -eq $KnownHash)
    }
    catch
    {
        Write-Error -Message "Failed to validate MD5 hash of RADIUS certificate"
        Write-Host $_
        exit 1
    }
}

function InstallCertificate()
{
    param(
        [Parameter(Mandatory)]
        [string]$CertFileURI,

        [Parameter(Mandatory)]
        [string]$CertFileOutPath,
        [Parameter(Mandatory)]
        [string]$CertHashFileURI,
        [Parameter(Mandatory)]
        [string]$CertHashFileOutPath
    )


    try
    {
        DownloadFile -DownloadFileURI $CertFileURI -OutFilePath $CertFileOutPath
        DownloadFile -DownloadFileURI $CertHashFileURI -OutFilePath $CertHashFileOutPath

        $HashMatches = ValidateHash -CertFilePath $CertFileOutPath -CertHashFilePath $CertHashFileOutPath
        if ($HashMatches -ne 1)
        {
            Write-Error -Message "Failed to validate MD5 hash of RADIUS certificate"
            Write-Host $_
            exit 1
        }
        Remove-Item -Path $CertHashFileOutPath -Force
        Import-Certificate -FilePath $CertFileOutPath -CertStoreLocation Cert:\LocalMachine\Root
    }
    catch
    {
        Write-Error -Message "Failed to install RADIUS certificate"
        Write-Host $_
        exit 1   
    }
}

$Radius2024CertURI = "https://jumpcloud-kb.s3.amazonaws.com/radius.jumpcloud.com-2024.crt"
$Radius2024CertOutFilePath = "C:\Windows\Temp\radius.jumpcloud.com-2024.crt"
$Radius2024CertHashURI = "https://jumpcloud-kb.s3.amazonaws.com/radius.jumpcloud.com-2024.crt.md5"
$Radius2024CertHashOutFilePath = "C:\Windows\Temp\radius.jumpcloud.com-2024.crt.md5"

InstallCertificate -CertFileURI $Radius2024CertURI -CertFileOutPath $Radius2024CertOutFilePath -CertHashFileURI $Radius2024CertHashURI -CertHashFileOutPath $Radius2024CertHashOutFilePath