# BTSec Windows BLE Test Fixture

**Testing infrastructure only.** This is not an Android app feature and BTSec does not communicate with the PC at runtime.

The fixture turns the PC's Windows BLE peripheral-capable adapter into a deterministic physical **discovery target**. A **physical Android device** running BTSec can discover the fixture and verify the Android app's real BLE scan path. The Android emulator cannot see this PC radio.

This initial stage advertises the service and reserves read/write characteristic UUIDs for a later interaction-fixture stage; it does not yet claim GATT read, write, or notification coverage.

## Prerequisites

- Windows 11 with Bluetooth enabled
- Default adapter must report `lowEnergySupported=True` and `peripheralRoleSupported=True`
- A physical Android phone running the BTSec dev build, with Bluetooth and Nearby Devices permission enabled

No USB Bluetooth dongle is required for this BLE-fixture stage.

## Commands

From Windows PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\Start-BtSecBleFixture.ps1 -Capabilities
powershell -ExecutionPolicy Bypass -File .\Start-BtSecBleFixture.ps1 -Advertise -DurationSeconds 120
```

The advertising command defaults to 120 seconds (and accepts 1–3600 seconds) and always stops advertising on exit. It exposes a test-only service UUID:

- Service: `b7ec0001-6e7f-4a55-95d1-4e1e6d4f0001`
- Read characteristic: `b7ec0002-6e7f-4a55-95d1-4e1e6d4f0001`
- Write characteristic: `b7ec0003-6e7f-4a55-95d1-4e1e6d4f0001`

## Evidence boundary

Record the fixture command output, BTSec scan output, Android logcat, and the real device model/API level. Report only whether BTSec discovered or interacted with this fixture.

This fixture does **not** validate raw HCI, Bluetooth key extraction, LMP/KNOB parameters, BR/EDR L2CAP, HFP/PBAP/MAP/SAP/AVRCP interoperability, or over-the-air packet capture.
