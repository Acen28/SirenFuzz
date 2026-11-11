# RT-Thread targets

Two of the 25 fuzzing targets are RT-Thread firmware built for the STM32F407 ATK
Explorer board, from the `stm32f407-atk-explorer` BSP in the RT-Thread tree.

- `firmware/rt-thread_fatfs.bin` — FatFS target
- `firmware/rt-thread_paho_mqtt.bin` — Paho-MQTT target

## 1. Toolchain

```bash
sudo apt install gcc-arm-none-eabi scons python3
```

Built with `gcc-arm-none-eabi` **15:10.3-2021.07-4** (GCC 10.3.1) on Ubuntu 22.04.

## 2. RT-Thread

```bash
git clone https://github.com/RT-Thread/rt-thread.git
cd rt-thread
git checkout cda0a63        # v5.3.0
```

Both targets are built from the same BSP directory:

```bash
cd bsp/stm32/stm32f407-atk-explorer
```

## 3. FatFS target

```bash
scons --menuconfig
```

Starting from the default configuration:

| Menu | Option | Setting |
|---|---|---|
| RT-Thread Components → Network | Light weight TCP/IP stack (LwIP) | **off** |
| RT-Thread Components → IoT | Paho MQTT | **off** |
| RT-Thread Components → Device virtual file system | Enable FatFS (elm-chan) | **on** |
| Hardware Drivers Config → On-chip Peripheral Drivers | Enable I2C1 | **on** (software I2C, default pins) |

Save and exit, then:

```bash
scons -j8
```

## 4. Paho-MQTT target

```bash
scons --menuconfig
```

| Menu | Option | Setting |
|---|---|---|
| RT-Thread Components → Network | Light weight TCP/IP stack (LwIP) | **on** |
| RT-Thread Components → Network → Network device | Enable ifconfig command | **on** |
| RT-Thread Components → Network → Network device | Enable netstat command | **on** |
| RT-Thread Components → IoT | Paho MQTT | **on** |
| Hardware Drivers Config → On-chip Peripheral Drivers | Enable I2C1 | **on** (software I2C, default pins) |

Save and exit, then:

```bash
scons -j8
```

## 5. Output

`scons` produces `rt-thread.elf`; the raw image is exported with:

```bash
arm-none-eabi-objcopy -O binary rt-thread.elf rt-thread.bin
```
