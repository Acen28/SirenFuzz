# Root Cause Analysis of Discovered Zero-Day Vulnerabilities

## Vulnerability Overview

| # | Target | Vulnerability Type | Root Cause Keywords |
|---|---|---|---|
| 1 | PLC | Out-of-Bounds Write | Function Code 16, unvalidated length, unbounded copy to holding register array |
| 2 | PLC | Out-of-Bounds Write | Function Code 1, `Modbus::process_FC1`, missing `au8Buffer` boundary check |
| 3 | Gateway | Out-of-Bounds Write| Pointer to local variable stored in global context, dangling pointer dereference after return |
| 4 | Heat Press | Heap Metadata Corruption | `Modbus::getRxBuffer`, `bBuffOverflow` without `break`, `au8Buffer` OOB, `u8BufferIndex` overwrite  |
| 5 | Soldering Iron | State Underflow | `LIS2DH12::getAxisReadings` I2C overflow, corrupts `startMOVTask` stack/TCB, executes `FONT_6x8` after `PendSV` |
| 6 | Zephyr SocketCan | Uninitialized Stack Variable leading to vTable Hijack | `can_sock_setsockopt_vmeth`, uninitialized `api`, indirect branch via `api->setsockopt` |
| 7 | RIOT-CCN-Lite-Relay | Resource Exhaustion leading to NULL Pointer Dereference | `ble_hs_enqueue_hci_event`, missing NULL check, `STR R3, [ev]` writes `0x00000000` |
| 8 | RT-Thread FatFS | Architectural Interrupt Context Violation | `console i2c2` binds I2C, Mutex in ISR, recursive `rt_kprintf` |
| 9 | RT-Thread Paho-MQTT | Heap Out-of-Bounds Write | `msh_auto_complete_path`, path concatenation lacks bounds, corrupts RTOS heap metadata |

---

## 1. PLC — Out-of-Bounds Copy

**Vulnerability Type:** Out-of-Bounds Copy

**Trigger Point:** Handling Modbus Write Multiple Registers requests, Function Code 16; `Modbus::process_FC1`.

**Root Cause:** The underlying protocol parser extracts the payload length directly from the attacker-controlled packet and does not verify whether that length exceeds the physical bounds of the internal holding register array. It then copies the payload into that array. This unbounded memory copy silently corrupts adjacent RAM structures, leading to deterministic HardFaults or potential RCE upon subsequent variable dereferencing.

---

## 2. PLC — Out-of-Bounds Write

**Vulnerability Type:** Out-of-Bounds Write

**Trigger Point:** Handling read-coil requests, Function Code 1; `Modbus::process_FC1`.

**Root Cause:** `Modbus::process_FC1` iterates over the requested coil bits and assembles the response into a local buffer. The loop increments the buffer index (`u8BufferSize++`) whenever 8 bits are written, but the loop condition lacks a strict boundary check against the maximum allocated size of `au8Buffer`. This oversight allows a maliciously crafted request with an inflated coil count to write sequentially past the end of the buffer, corrupting the stack layout.

---

## 3. Gateway — Use-After-Return

**Vulnerability Type:** Use-After-Return

**Note:** CVE assigned (CVE-2026-26399).

**Root Cause:** The vulnerability arises from improper memory lifecycle management. A pointer to a local variable allocated on the stack frame of a specific subroutine is erroneously returned or stored in a global context. Once the subroutine returns, the stack frame is invalidated and subsequently reused. When the global context later dereferences this dangling pointer, it accesses corrupted or attacker-controlled stack data, leading to a catastrophic control-flow hijack.

---

## 4. Heat Press — Out-of-Bounds Write

**Vulnerability Type:** Out-of-Bounds Write 

**Root Cause:** The firmware uses the official CONTROLLINO_Library Modbus RTU Slave example. In `examples/MAXI/DemoModbusRTUSlave/ModbusRtu.h`, `Modbus::getRxBuffer()` reads incoming serial data into `au8Buffer`. When `u8BufferIndex` exceeds the buffer size (typically 64 bytes), the function sets `bBuffOverflow = true` but does not break out of the read loop. It then continues executing `au8Buffer[u8BufferIndex] = u8Byte; u8BufferIndex++;`, writing past the buffer boundary.

If the underlying serial RX buffer is configured larger than 64 bytes, an attacker can send a malformed long packet to trigger the overflow. The 65th byte overwrites `u8BufferIndex` itself, enabling relative write-what-where corruption. Dynamic emulation confirmed the overflow and eventual control-structure corruption, leading to DoS and potential RCE.

---

## 5. Soldering Iron — State Underflow

**Vulnerability Type:** State Underflow

**Root Cause:** While polling accelerometer data (`LIS2DH12::getAxisReadings`), a lack of bounds checking on the incoming I2C data stream allows a silent buffer overflow. This overflow perfectly overwrites the saved stack pointer or Task Control Block (TCB) of `startMOVTask`.

During a FreeRTOS context switch (`PendSV`), the scheduler restores the corrupted stack frame, inadvertently loading the unallocated stack watermark (`0xA5A5A5A5`) into general-purpose registers (`R5-R12`). This extreme context destruction causes the Program Counter (PC) to execute wildly, eventually landing in the `.rodata` font array (`FONT_6x8`), where the CPU attempts to execute display pixel data as ARM instructions.

---

## 6. Zephyr SocketCan — Uninitialized Stack Variable leading to vTable Hijack

**Vulnerability Type:** Uninitialized Stack Variable leading to vTable Hijack

**Root Cause:** In the network socket abstraction layer (`can_sock_setsockopt_vmeth`), the code fails to validate the initialization state of the socket context when handling `CAN_RAW_FILTER` requests. If a socket is unbound, `net_context_get_iface(obj)` returns an invalid or uninitialized structure.

Consequently, the local device API pointer (`api`) is not initialized and picks up a residual return address (`0x08002DA3`) left on the stack by a previous function call. Execution bypasses the null check (`if (!api)`) because the stale code address is non-zero. The program then dereferences an offset from this code address (`api->setsockopt`), fetches arbitrary machine code (`0xb6f00808`), and executes an indirect branch (`BLX R7`), granting the attacker full control over the execution flow.

---

## 7. RIOT-CCN-Lite-Relay — Resource Exhaustion leading to NULL Pointer Dereference

**Vulnerability Type:** Resource Exhaustion leading to NULL Pointer Dereference

**Root Cause:** When flooded with high-frequency, malformed BLE events, the RTOS memory pool becomes exhausted, causing the event allocation function to return a `NULL` pointer. The `ble_hs_enqueue_hci_event` function completely omits a `NULL` check on the returned pointer. It immediately proceeds to write initialization data (`STR R3, [ev]`), attempting to write to the physical address `0x00000000` (the Flash region in Cortex-M). This triggers an instantaneous HardFault, presenting as a highly reliable Denial of Service (DoS) attack via packet flooding.

---

## 8. RT-Thread FatFS — Architectural Interrupt Context Violation

**Vulnerability Type:** Architectural Interrupt Context Violation

**Root Cause:** The FinSH console component contains a configuration vulnerability: the `console` command allows dynamic redirection of the standard output device without verifying whether the target device is asynchronous-safe.

A fuzzer successfully injected a command (`console i2c2`) to bind the console to an I2C device, which uses blocking Mutexes. Subsequently, the fuzzer saturated the UART RX buffer, triggering a warning macro (`LOG_W`) from within the Hardware Interrupt Service Routine (ISR). Attempting to acquire an I2C Mutex inside an ISR triggered a kernel panic assertion (`scheduler is not available`). The assertion handler then attempted to print the error using `rt_kprintf`, recursively triggering the same Mutex violation. This formed an infinite recursive loop that exhausted the ISR stack in milliseconds.

---

## 9. RT-Thread Paho-MQTT — Heap Out-of-Bounds Write

**Vulnerability Type:** Heap Out-of-Bounds Write 

**Root Cause:** An Out-of-Bounds write exists within the RT-Thread FinSH shell component, specifically in the `msh_auto_complete_path` function. When processing a user-supplied path string for auto-completion (triggered via the `<Tab>` key), the function allocates a fixed-size heap buffer (typically 256 bytes) to hold the concatenated path.

However, the string concatenation loop fails to enforce boundary checks against the buffer's capacity. By injecting an oversized directory path string, an attacker causes the loop to write past the heap chunk boundaries, silently corrupting adjacent RTOS heap metadata. This payload eventually triggers a catastrophic crash during subsequent `rt_malloc` or `rt_free` operations. Our Oracle successfully intercepted the exact instruction writing beyond the heap boundary.
