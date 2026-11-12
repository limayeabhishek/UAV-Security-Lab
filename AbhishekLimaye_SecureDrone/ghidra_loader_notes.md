# Ghidra Static Reverse Engineering Guide: ArduPilot Pixhawk 4 (STM32F767)

## 1. Artifact Verification & Provenance
- **Source Target**: ArduPilot Copter Official Stable Release (`arducopter.apj`)
- **Target Platform**: Holybro Pixhawk 4 (FMUv5)
- **Container SHA-256**: `5e2a0ef273e26e2c30f76e94781a695ee00285e653aa84122bea36903a886c63`
- **Extracted Binary**: `arducopter_pixhawk4.bin` (1,564,244 bytes)
- **Binary SHA-256**: Calculated and recorded in `firmware-analysis/manifests/firmware_manifest.json`

---

## 2. Ghidra Import Configuration

When importing `arducopter_pixhawk4.bin` into Ghidra as a raw binary (`Raw Binary` format):

| Parameter | Configuration Value | Technical Rationale |
| :--- | :--- | :--- |
| **Language / Architecture** | `ARM:LE:32:Cortex (default)` | STM32F767 utilizes an ARM Cortex-M7 core with ARMv7E-M instruction set |
| **Base Address** | `0x08008000` | Pixhawk FMUv5 reserves 32 KB (`0x08000000` - `0x08007FFF`) for the bootloader; firmware image starts at offset `0x8000` |
| **Block Name** | `FLASH` | Internal Flash memory region |
| **Block Size** | `0x17DE74` (1,564,244 bytes) | Extracted binary length |
| **Permissions** | `Read / Execute` (R-X) | Executable firmware code |

### Memory Map Configuration (Add via `Window -> Memory Map`)
1. **FLASH**:
   - Start: `0x08008000`
   - Length: `0x00180000`
   - Permissions: `R-X`
2. **DTCM-RAM (Data Tightly-Coupled Memory)**:
   - Start: `0x20000000`
   - Length: `0x00020000` (128 KB)
   - Permissions: `RW-`
3. **SRAM1 / SRAM2**:
   - Start: `0x20020000`
   - Length: `0x00060000` (384 KB)
   - Permissions: `RW-`
4. **Peripherals**:
   - Start: `0x40000000`
   - Length: `0x20000000`
   - Permissions: `RW-`

---

## 3. Disassembly & Vector Table Setup

1. **Navigate to `0x08008000`**:
   - Byte `0x08008000`: `0x20020600` -> Define as Pointer (`Initial_SP`). Points to top of DTCM/SRAM.
   - Byte `0x08008004`: `0x08008CED` -> Define as Pointer (`Reset_Handler`).
2. **Mark Reset Handler as 16-bit Thumb Mode**:
   - In Ghidra, go to address `0x08008CEC` (clear bit 0).
   - Press `G` to goto `0x08008CEC`.
   - Set register `T = 1` (Thumb mode flag).
   - Press `D` to disassemble.
3. **Auto-Analyze**:
   - Select `Analysis -> Auto Analyze 'arducopter_pixhawk4.bin'`.
   - Enable `ARM Constant Reference Analyzer`, `Subroutine References`, and `Decompiler Parameter ID`.

---

## 4. Key Security Disassembly Audit Targets

### A. MAVLink Message Dispatch Table
- Search for strings: `"COMMAND_LONG"`, `"PARAM_SET"`, `"HEARTBEAT"`.
- Locate the message handler jump table mapping 24-bit MAVLink message IDs to handler functions:
  - `handle_command_long`: Inspect permission checks before executing `MAV_CMD_DO_SET_SERVO`, `MAV_CMD_DO_FLIGHTTERMINATION`, and `MAV_CMD_COMPONENT_ARM_DISARM`.
  - Notice that without signing, commands matching `target_system == g.sysid_this_mav` are dispatched directly without caller authentication.

### B. Parameter Validation Logic
- Locate `AP_Param` parameter storage and write callback handlers.
- Search for `"BRD_SAFETYENABLE"`, `"ARMING_CHECK"`, `"FS_THR_ENABLE"`.
- Observe that parameter write constraints validate numeric ranges (min/max), but do not authenticate the transport link identity.
