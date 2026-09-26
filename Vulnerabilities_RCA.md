# Root Cause Analysis (RCA) of Discovered Zero-Day Vulnerabilities

---

## 1. Programmable Logic Controller (PLC)
**Vulnerability Type:** Out-of-Bounds Copy (RX Buffer / FC16)
**Root Cause Summary:**
When handling Modbus Write Multiple Registers (e.g., Function Code 16) requests, the underlying protocol parser extracts the payload length directly from the unverified attacker-controlled packet. It proceeds to copy the payload into the internal holding register array without asserting if the requested length exceeds the physical bounds of the destination buffer. This unbounded memory copy silently corrupts adjacent RAM structures, leading to deterministic HardFaults or potential RCE upon subsequent variable dereferencing.

## 2. Programmable Logic Controller (PLC)
**Vulnerability Type:** Out-of-Bounds Write (Cmd Handler / FC1)
**Root Cause Summary:**
In the command handler for reading coils (e.g., Function Code 1), the `Modbus::process_FC1` function iterates over the requested coil bits and assembles the response into a local buffer. The loop increments the buffer index (`u8BufferSize++`) whenever 8 bits are written. However, the loop condition lacks a strict boundary check against the maximum allocated size of `au8Buffer`. This oversight permits a maliciously crafted request (with an inflated coil count) to sequentially write past the buffer's end, corrupting the stack layout.

## 3. IoT Gateway
**Vulnerability Type:** Use-After-Return (UAR)
**Root Cause Summary:**
*(Note: CVE Assigned)*. The vulnerability arises due to improper memory lifecycle management. A pointer to a local variable (allocated on the stack frame of a specific subroutine) is erroneously returned or stored in a global context. Once the subroutine returns, the stack frame is invalidated and subsequently reused. When the global context later dereferences this dangling pointer, it accesses corrupted or attacker-controlled stack data, leading to a catastrophic control-flow hijack.

## 4. Heat Press
**Vulnerability Type:** Heap Metadata Corruption (OOB Write -> Unlink Hijack)
**Root Cause Summary:**
Sharing the vulnerable Controllino Modbus library with the PLC target, this firmware exhibits the same OOB write flaw. However, due to its specific memory layout, the out-of-bounds write silently obliterates the metadata (specifically the `FD` and `BK` pointers) of an adjacent free heap chunk. 
The corruption remains dormant until the firmware subsequently invokes `realloc()`. During the chunk consolidation phase (Unlink macro), the standard C library attempts to execute `FD->bk = BK`. Because the pointers are tainted by the Fuzzer payload, this transforms into a classic **Arbitrary Write-What-Where primitive**, intercepted instantly by our symbolic memory hooks.

## 5. Soldering Iron (IronOS)
**Vulnerability Type:** State Underflow / Stack Pivot via I2C Sensor Parsing
**Root Cause Summary:**
While polling accelerometer data (`LIS2DH12::getAxisReadings`), a lack of bounds checking on the incoming I2C data stream allows a silent buffer overflow. This overflow perfectly overwrites the saved stack pointer or Task Control Block (TCB) of the `startMOVTask`. 
During a FreeRTOS context switch (`PendSV`), the scheduler restores the corrupted stack frame, inadvertently loading the unallocated stack watermark (`0xA5A5A5A5`) into general-purpose registers (`R5-R12`). This extreme context destruction causes the Program Counter (PC) to execute wildly, eventually landing in the `.rodata` font array (`FONT_6x8`), where the CPU attempts to execute display pixel data as ARM instructions.

## 6. Zephyr SocketCan
**Vulnerability Type:** Uninitialized Stack Variable leading to vTable Hijack
**Root Cause Summary:**
In the network socket abstraction layer (`can_sock_setsockopt_vmeth`), the code fails to validate the initialization state of the socket context when handling `CAN_RAW_FILTER` requests. If a socket is unbound, `net_context_get_iface(obj)` returns an invalid or uninitialized structure.
Consequently, the local device API pointer (`api`) is not initialized and picks up a residual return address (e.g., `0x08002DA3`) left on the stack by a previous function call. The execution bypasses the null-check (`if (!api)`) because the stale code address is non-zero. The program then dereferences an offset from this code address (`api->setsockopt`), fetches arbitrary machine code (e.g., `0xb6f00808`), and executes an indirect branch (`BLX R7`), granting the attacker full control over the execution flow.

## 7. RIOT-CCN-Lite Relay
**Vulnerability Type:** Resource Exhaustion leading to NULL Pointer Dereference
**Root Cause Summary:**
When flooded with high-frequency, malformed BLE events, the RTOS memory pool becomes exhausted, causing the event allocation function to return a `NULL` pointer. The `ble_hs_enqueue_hci_event` function completely omits a `NULL` check on the returned pointer. It immediately proceeds to write initialization data (`STR R3, [ev]`), attempting to write to the physical address `0x00000000` (the Flash region in Cortex-M). This triggers an instantaneous HardFault, presenting as a highly reliable Denial of Service (DoS) attack via packet flooding.

## 8. RT-Thread FatFS (FinSH Console)
**Vulnerability Type:** Architectural Interrupt Context Violation (Uncontrolled Recursion)
**Root Cause Summary:**
The FinSH console component contains a configuration vulnerability: the `console` command allows dynamic redirection of the standard output device without verifying if the target device is asynchronous-safe. 
A fuzzer successfully injected a command (`console i2c2`) to bind the console to an I2C device (which utilizes blocking Mutexes). Subsequently, the fuzzer saturated the UART RX buffer, triggering a warning macro (`LOG_W`) from within the Hardware Interrupt Service Routine (ISR). Attempting to acquire an I2C Mutex inside an ISR triggered a kernel panic assertion (`scheduler is not available`). The assertion handler then attempted to print the error using `rt_kprintf`, recursively triggering the same Mutex violation. This formed an infinite recursive loop that exhausted the ISR stack in milliseconds.

## 9. RT-Thread Paho-MQTT (FinSH)
**Vulnerability Type:** Heap Out-of-Bounds Write (Path Autocomplete)
**Root Cause Summary:**
An Out-of-Bounds write (CWE-122) exists within the RT-Thread FinSH shell component, specifically in the `msh_auto_complete_path` function. When processing a user-supplied path string for auto-completion (triggered via the `<Tab>` key), the function allocates a fixed-size heap buffer (typically 256 bytes) to hold the concatenated path. 
However, the string concatenation loop fails to enforce boundary checks against the buffer's capacity. By injecting an oversized directory path string, an attacker causes the loop to write past the heap chunk boundaries, silently corrupting adjacent RTOS heap metadata. This payload eventually triggers a catastrophic crash during subsequent `rt_malloc` or `rt_free` operations. Our Oracle successfully intercepted the exact instruction writing beyond the heap boundary.