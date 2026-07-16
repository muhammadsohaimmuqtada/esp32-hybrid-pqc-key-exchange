# Reproduction Steps

## Prerequisites

### Software
- **ESP-IDF v5.2.1** — [Installation guide](https://docs.espressif.com/projects/esp-idf/en/v5.2.1/esp32/get-started/)
- **Python 3.10+** with `flask` (`pip install flask`)
- **GCC cross-compiler** for Xtensa (included with ESP-IDF)

### Hardware
- ESP32-WROOM-32E development board
- USB cable (Micro-USB or USB-C depending on board revision)
- Wi-Fi router (2.4 GHz, WPA2-PSK)
- (Optional) Kenwood regulated bench power supply + digital multimeter for power measurements

## Step 1: Clone the Repository

```bash
git clone https://github.com/muhammadsohaimmuqtada/esp32-hybrid-pqc-key-exchange.git
cd esp32-hybrid-pqc-key-exchange
```

## Step 2: Configure Wi-Fi Credentials

Edit the firmware Wi-Fi configuration:

```bash
cd firmware
cp sdkconfig.defaults sdkconfig
```

Open `sdkconfig` and set your Wi-Fi SSID and password:
```
CONFIG_ESP_WIFI_SSID="YOUR_WIFI_SSID"
CONFIG_ESP_WIFI_PASSWORD="YOUR_WIFI_PASSWORD"
```

Also update the server IP address in `main/main.c` to match your server machine's local IP.

## Step 3: Build and Flash the Firmware

```bash
source ~/esp/esp-idf/export.sh    # Activate ESP-IDF environment
idf.py set-target esp32
idf.py build
idf.py -p /dev/ttyUSB0 flash monitor
```

The serial monitor will display boot logs, Wi-Fi connection status, and benchmark output.

## Step 4: Start the Server

In a separate terminal on your server machine:

```bash
cd server
pip install -r requirements.txt
python3 server.py
```

The server listens on `0.0.0.0:5000` and will print handshake details and telemetry data as the ESP32 connects.

## Step 5: Verify the Handshake

Once the ESP32 connects to Wi-Fi and reaches the server, the serial monitor will output:

```
I (xxxx) CRYPTO_HYBRID: === Hybrid Handshake Starting ===
I (xxxx) CRYPTO_HYBRID: BENCHMARK [X25519 Keygen]: 274xxx us, 43xxxxxx cycles
I (xxxx) CRYPTO_HYBRID: BENCHMARK [ML-KEM-512 Keypair]: 9xxx us, 1xxxxxx cycles
...
I (xxxx) CRYPTO_HYBRID: Session key derived successfully
I (xxxx) CRYPTO_HYBRID: Telemetry POST: 200 OK
```

The server terminal will show:
```
[HANDSHAKE] Mode: HYBRID (0x02)
[HANDSHAKE] HMAC verified ✓
[HANDSHAKE] Session ID: <hex>
[TELEMETRY] Decrypted: {"temperature": 24.5, "humidity": 61.2, ...}
```

## Step 6: Run Benchmark Analysis

After collecting serial output logs (copy from the monitor to a file):

```bash
cd benchmarks
python3 cpu_cycles_parser.py --input ../data/raw_logs/esp_bench_full_real.log --output ../data/processed_results/parsed_cycles.csv
python3 latency_benchmark.py --input ../data/processed_results/parsed_cycles.csv
python3 energy_calculation.py --input ../data/processed_results/parsed_cycles.csv
python3 memory_benchmark.py
```

## Step 7: Capture Network Traffic (Optional)

To generate sanitized PCAP captures for verification:

```bash
cd server
python3 generate_pcap_captures.py
```

Pre-captured sanitized PCAPs are available in `data/sanitized_pcaps/`.

## Step 8: Power Measurement (Optional)

For electrical verification as described in the paper:

1. Disconnect the USB power path (use bench supply on VIN/GND pins — see `docs/hardware_setup.md`).
2. Modify firmware to run handshakes in an infinite loop (uncomment the `while(1)` block in `main.c`).
3. Measure sustained current with the multimeter in series on the +5V line.
4. Expected readings: 30–70 mA during cryptographic processing, 110 mA peak during Wi-Fi boot.

## Expected Results

| Metric | Expected Value |
|---|---|
| Hybrid handshake latency | 635.88 ms (mean, n=100) |
| SRAM peak usage | 13.8 KB |
| CPU cycles (total) | 103.38M |
| Energy per handshake | 122.34 mJ |
| TLS 1.3 baseline latency | 776.40 ms |
| TLS 1.3 baseline CPU cycles | 372.66M |
