$domain_name = (Get-WmiObject Win32_ComputerSystem).Domain
$host_name = "$((Get-WmiObject Win32_ComputerSystem).Name).$domain_name"


$share_parent_folder = "\\srv.$domain_name\"

$bitlocker_keys_folder = "$share_parent_folder\bitlocker_keys\"
$bitlocker_log_folder = "$share_parent_folder\bitlocker_keys\logs\"
$bitlocker_log_file = "$bitlocker_log_folder$host_name.log"
$bitlocker_key_file = "$bitlocker_keys_folder$host_name.txt"

$bitlocker_mountpoint = "C:"
#errorcodes / info codes

$evn_error = 1

$tpm_error_not_availabel = 10
$tpm_error_not_supported = 11
$tpm_error_not_reset = 12

$bitlocker_invalid_key = 20
$bitlocker_activation_failed = 21

#By default, error action preference is set to continue
$ErrorPreference = "Stop"

#Helper function to log events
function Write-Log([string]$logtext, [int]$level = 0) {
	$logdate = get-date -format "yyyy-MM-dd HH:mm:ss"

	if ($level -eq 0) {
		$logtext = "[INFO] " + $logtext
		$text = "[" + $logdate + "] - " + $logtext
	}
	if ($level -eq 1) {
		$logtext = "[WARNING] " + $logtext
		$text = "[" + $logdate + "] - " + $logtext
	}
	if ($level -eq 2) {
		$logtext = "[ERROR] " + $logtext
		$text = "[" + $logdate + "] - " + $logtext
	}
 
	$text >> $bitlocker_log_file
}#end:Write-Log

#Creates bitlocker key and log folders
function prepare_enviroment {

	If (!(test-path $share_parent_folder)) {
		Write-Log "Failed accessing parent share: $share_parent_folder"
		return $evn_error
	}

	If (!(test-path $bitlocker_keys_folder)) {
		New-Item -ItemType Directory -Force -Path $bitlocker_keys_folder
	}

	If (!(test-path $bitlocker_log_folder)) {
		New-Item -ItemType Directory -Force -Path $bitlocker_log_folder
	}

	If (!(test-path $bitlocker_log_file)) {
		New-Item -ItemType file -Force -Path $bitlocker_log_file
		Write-Log("Log file created $bitlocker_log_file")
	}

	return 0

}#end:prepare_enviroment

#Saves the Bitlocker key to the specified path in '$bitlocker_key_file'
function save_bitlocker_key {

	#For each bitlocker volume we have in our set up a object for the recovery key (KeyProtectorType=RecoveryPassword)
	#and the Tpm (KeyProtectorType = Tpm). Here we handle onyle the bitlocker object ('RecoveryPassword')
	$bitlocker_volume_keyprotector = ""
	$bitlocker_key = ""
	$bitlocker_id = ""
	$return_code = -1

	Write-Log "Fetching Bitlocker recovery key and ID..."
	$bitlocker_volume_keyprotector = Get-BitLockerVolume -MountPoint C | Select-Object -ExpandProperty KeyProtector | Where-Object KeyProtectorType -eq 'RecoveryPassword' 
        
	$bitlocker_key = $bitlocker_volume_keyprotector | Select-Object -ExpandProperty RecoveryPassword
	$bitlocker_id = $bitlocker_volume_keyprotector | Select-Object -ExpandProperty KeyProtectorId 
	$bitlocker_key_pattern = "\d{6}[-]\d{6}[-]\d{6}[-]\d{6}[-]\d{6}[-]\d{6}[-]\d{6}[-]\d{6}"
	
	if ($bitlocker_key -match $bitlocker_key_pattern) {
		"Bitlocker ID and recovery key for $host_name" > $bitlocker_key_file
		"Bitlocker ID: $bitlocker_id" >> $bitlocker_key_file
		"Bitlocker recovery key: $bitlocker_key" >> $bitlocker_key_file
		Write-Log("Fateched and saved Bitlocker recovery key and ID to $bitlocker_key_file")
		$return_code = 0
	}
	else {
		Write-Log "Bitlocker recovery key has an unexpected format, key is >>$bitlocker_key<<" 2
		$return_code = $bitlocker_invalid_key
	}

	return $return_code
}#end: save_bitlocker_key

#Checks if the TPM has the status 'ready' and tries to set it to this status by clearing it - if required.
function check_tpm() {
	$tpm_properties = Get-Tpm
	$tpm_present = $tpm_properties |  Select-Object -ExpandProperty TpmPresent
	$tpm_ready = $tpm_properties |  Select-Object -ExpandProperty TpmReady
	$tpm_specification = Get-WmiObject -class Win32_Tpm -namespace root\CIMV2\Security\MicrosoftTpm |  Select-Object -ExpandProperty SpecVersion
	$return_code = -1

	if ($tpm_present -match "False") {
		Write-Log "TPM is NOT present or disabled in BIOS " 2
		return $tpm_error_not_availabel
	}
	
	if ($tpm_specification -notmatch "2[.]0") {
		Write-Log "TPM does NOT support the TPM 2.0 specification" 2
		return $tpm_error_not_supported
	}
	
	if ($tpm_ready -match "False") {

		Write-Log "TPM is NOT ready... trying to initialize / set to ready"

		#If the TPM is not ready, we try to make it by clearing it.
		#We do not use the parameter 'AllowPhysicalPresence' as we are performing the task without a guaranteed onsite support. 
		$tpm_initialization_result = Initialize-Tpm -AllowClear 
		$tpm_initialization_sucessfull = $tpm_initialization_result | Select-Object -ExpandProperty TpmReady
		
		if ($tpm_initialization_sucessfull -match "False") {
			$tpm_initialization_restart_required = $tpm_initialization_result | Select-Object -ExpandProperty RestartRequired
			$tpm_initialization_shutdown_required = $tpm_initialization_result | Select-Object -ExpandProperty ShutdownRequired
			$tpm_initialization_clear_required = $tpm_initialization_result | Select-Object -ExpandProperty ClearRequired

			Write-Log "TPM clearing / initializing failed ... clearing requires physical presence" 1	
			Write-Log "TPM clearing / initializing requires: reboot($tpm_initialization_restart_required) shutdown($tpm_initialization_shutdown_required) reset_in_BIOS_required($tpm_initialization_clear_required)" 1		
			return $tpm_error_not_reset
		}
		else {
			Write-Log "TPM is ready ... (TPM clearing / initializing was sucessfull)" 0
			$return_code = 0
		}
	}
	else {
		Write-Log "TPM is ready"
		$return_code = 0
	}
	return $return_code
}#end:check_tpm

#Activates Bitlocker by adding to '$bitlocker_mountpoint' TPM and RecoveryPasswordProtector as protectors.
#If Bitlocker is already activated it will just fatch and save the recovery key.
function activate_bitlocker {	
	#alternative:  Get-BitLockerVolume -MountPoint C: | Select-Object -ExpandProperty ProtectionStatus	
	$status_bitlocker = manage-bde.exe -status $bitlocker_mountpoint
	
	#to ensure we have tpm and recovery key as protectors
	$bitlocker_key_protector = Get-BitLockerVolume -MountPoint $bitlocker_mountpoint | Select-Object -ExpandProperty KeyProtector | Where-Object KeyProtectorType -eq 'RecoveryPassword'     
	$bitlocker_key_id = $bitlocker_key_protector | Select-Object -ExpandProperty "KeyProtectorId"
	
	$bitlocker_tpm_protector = Get-BitLockerVolume -MountPoint C | Select-Object -ExpandProperty KeyProtector | Where-Object KeyProtectorType -eq 'Tpm'     
	$bitlocker_tpm_id = $bitlocker_tpm_protector | Select-Object -ExpandProperty "KeyProtectorId"
	
	#Note: 
	#When checking the status via manage-bde.exe -status c: , the status is shown in the windows display language
	#=> queries like match "Off" / "In Progress" will fail on non English display language systems!
	#No PowerShell environment variable or other safe option was found to fix this. (logging off and in can be considered in next options)
	#Status of Bitlocker (shown when executing manage-bde.exe -status c:) and key protectors presence:
	#Protection off => no protectors present
	#Suspended => protectors present
	#Encrytion in progress => protectors are present
	#Decrytion in progress => protectors are present

	Write-Log("Activating \ Checking if required protectors (TPM, and recovery key) are availabel...")

	Try {
			
		if (!($bitlocker_tpm_id)) {
			Write-Log("Adding TPM protector ...")
			#Remove-BitLockerKeyProtector -MountPoint c: -KeyProtectorId $bitlocker_tpm_id -ErrorAction Stop | Out-Null
			# '-SkipHardwareTest', is not used to avoid a restart of the system
			Enable-BitLocker -MountPoint "C:" -TpmProtector -EncryptionMethod Aes256 -SkipHardwareTest | Out-Null
		}
		else {
        
			#Note: After an OS installation / enabling TPM in BIOS the TPM status is set to 'not ready'
			# i.e. required a clearing (this clears all protectors)
			#And thus the "Enable-BitLocker -MountPoint "C:" -TpmProtector..." will be execute.
			#Therefore it is safe to just check if the protectors is present
			Write-Log("TPM protector is already present ...")
		}
			
		if (!($bitlocker_key_id)) {			
			Write-Log("Adding recovery key protector ...")
			#Optionly, we could also remove the existing RecoveryPasswordProtector
			#Remove-BitlockerKeyProtector -MountPoint "C:" -KeyProtectorId $bitlocker_key_id
			Add-BitLockerKeyProtector -MountPoint "C:" -RecoveryPasswordProtector -WarningAction SilentlyContinue | Out-Null			
		}
		else {
		
			Write-Log("Recovery key protector is already present ...")
		}
		
	}#end: try
		
	Catch {
		Write-Log "Activating Bitlocker failed error: >>$_<<,  " 2	
		Write-Log("Bitlocker status is >>$status_bitlocker<<")
		return $bitlocker_activation_failed
	}
	
	save_bitlocker_key
	Write-Log("Activating Bitlocker (adding TPM and Key protector) was sucessfull")
	Write-Log("Bitlocker status is >>$status_bitlocker<<")

	return 0	
}#end:activate_bitlocker

$a = prepare_enviroment


if ($a -eq 0) {
	prepare_enviroment
}
else {
	return "ERROR in prepare_enviroment, ERROR code $a"
}

$b = check_tpm

if ($b -eq 0) {
	check_tpm
}
else {
	return "ERROR in check_tpm, ERROR code $b"
}

$c = activate_bitlocker

if ($c -eq 0) {
	activate_bitlocker
}
else {
	return "ERROR in activate_bitlocker, ERROR code $c"
}
