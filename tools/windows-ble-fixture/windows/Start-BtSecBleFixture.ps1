[CmdletBinding()]
param(
  [switch]$Capabilities,
  [switch]$Advertise,
  [ValidateRange(1, 3600)][int]$DurationSeconds = 120
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Runtime.WindowsRuntime

function Get-WinRtType([string]$TypeName, [string]$AssemblyName) {
  return [Type]::GetType("$TypeName, $AssemblyName, ContentType=WindowsRuntime", $true)
}

function Await-WinRt([object]$Operation, [Type]$ResultType) {
  $method = [System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
    $_.Name -eq 'AsTask' -and $_.IsGenericMethodDefinition -and $_.GetGenericArguments().Count -eq 1 -and $_.GetParameters().Count -eq 1
  } | Select-Object -First 1
  if ($null -eq $method) { throw 'System.WindowsRuntimeSystemExtensions.AsTask<T> was not available.' }
  return $method.MakeGenericMethod($ResultType).Invoke($null, @($Operation)).GetAwaiter().GetResult()
}

$adapterType = Get-WinRtType 'Windows.Devices.Bluetooth.BluetoothAdapter' 'Windows.Devices.Bluetooth'
$adapter = Await-WinRt ($adapterType::GetDefaultAsync()) $adapterType
if ($null -eq $adapter) {
  [Console]::WriteLine('status=UNAVAILABLE reason=No default Windows Bluetooth adapter.')
  exit 2
}

if ($Capabilities -or -not $Advertise) {
  [Console]::WriteLine('status=AVAILABLE')
  [Console]::WriteLine("adapterId=$($adapter.DeviceId)")
  [Console]::WriteLine("lowEnergySupported=$($adapter.IsLowEnergySupported)")
  [Console]::WriteLine("peripheralRoleSupported=$($adapter.IsPeripheralRoleSupported)")
  [Console]::WriteLine('boundary=BLE GATT fixture only; no raw HCI, key extraction, BR/EDR L2CAP, or over-the-air capture.')
  if (-not $Advertise) { exit 0 }
}

if (-not $adapter.IsLowEnergySupported -or -not $adapter.IsPeripheralRoleSupported) {
  throw 'The default Windows adapter cannot host a BLE GATT peripheral.'
}

$gattAssembly = 'Windows.Devices.Bluetooth'
$providerType = Get-WinRtType 'Windows.Devices.Bluetooth.GenericAttributeProfile.GattServiceProvider' $gattAssembly
$providerResultType = Get-WinRtType 'Windows.Devices.Bluetooth.GenericAttributeProfile.GattServiceProviderResult' $gattAssembly
$characteristicResultType = Get-WinRtType 'Windows.Devices.Bluetooth.GenericAttributeProfile.GattLocalCharacteristicResult' $gattAssembly
$characteristicParametersType = Get-WinRtType 'Windows.Devices.Bluetooth.GenericAttributeProfile.GattLocalCharacteristicParameters' $gattAssembly
$characteristicPropertiesType = Get-WinRtType 'Windows.Devices.Bluetooth.GenericAttributeProfile.GattCharacteristicProperties' $gattAssembly
$protectionLevelType = Get-WinRtType 'Windows.Devices.Bluetooth.GenericAttributeProfile.GattProtectionLevel' $gattAssembly
$advertisingParametersType = Get-WinRtType 'Windows.Devices.Bluetooth.GenericAttributeProfile.GattServiceProviderAdvertisingParameters' $gattAssembly

$serviceUuid = [Guid]'b7ec0001-6e7f-4a55-95d1-4e1e6d4f0001'
$readUuid = [Guid]'b7ec0002-6e7f-4a55-95d1-4e1e6d4f0001'
$writeUuid = [Guid]'b7ec0003-6e7f-4a55-95d1-4e1e6d4f0001'

$providerResult = Await-WinRt ($providerType::CreateAsync($serviceUuid)) $providerResultType
if ($providerResult.Error.ToString() -ne 'Success') { throw "GattServiceProvider creation failed: $($providerResult.Error)." }
$provider = $providerResult.ServiceProvider
$service = $provider.Service

function Add-FixtureCharacteristic([Guid]$Uuid, [object]$Properties) {
  $parameters = [Activator]::CreateInstance($characteristicParametersType)
  $parameters.CharacteristicProperties = $Properties
  $parameters.ReadProtectionLevel = [Enum]::Parse($protectionLevelType, 'Plain')
  $parameters.WriteProtectionLevel = [Enum]::Parse($protectionLevelType, 'Plain')
  $result = Await-WinRt ($service.CreateCharacteristicAsync($Uuid, $parameters)) $characteristicResultType
  if ($result.Error.ToString() -ne 'Success') { throw "Characteristic $Uuid creation failed: $($result.Error)." }
  return $result.Characteristic
}

$readCharacteristic = Add-FixtureCharacteristic $readUuid ([Enum]::Parse($characteristicPropertiesType, 'Read'))
$writeCharacteristic = Add-FixtureCharacteristic $writeUuid ([Enum]::Parse($characteristicPropertiesType, 'Write'))

$advertisingParameters = [Activator]::CreateInstance($advertisingParametersType)
$advertisingParameters.IsConnectable = $true
$advertisingParameters.IsDiscoverable = $true
$advertisingStarted = $false
try {
  $provider.StartAdvertising($advertisingParameters)
  $advertisingStarted = $true
  [Console]::WriteLine("status=ADVERTISING service=$serviceUuid read=$readUuid write=$writeUuid")
  [Console]::WriteLine('evidenceBoundary=Advertisement confirms the fixture started; use a physical Android device running BTSec to collect discovery/connection evidence.')
  Start-Sleep -Seconds $DurationSeconds
}
finally {
  if ($advertisingStarted) {
    $provider.StopAdvertising()
    [Console]::WriteLine('status=STOPPED')
  }
}
