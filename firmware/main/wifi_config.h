/*
 * Wi-Fi Configuration for ESP32 Hybrid PQC
 * Edit these values for your network
 */
#ifndef WIFI_CONFIG_H
#define WIFI_CONFIG_H

#define WIFI_SSID      "YOUR_SSID_HERE"
#define WIFI_PASS      "YOUR_WIFI_PASSWORD_HERE"

/* Server configuration - set to your Python server's LAN IP */
#define SERVER_HOST    "192.168.x.x" // Change this to your Server's IP
#define SERVER_PORT    8443

/* Benchmark configuration */
#define BENCHMARK_ITERATIONS  10
#define TELEMETRY_INTERVAL_MS 5000

#endif /* WIFI_CONFIG_H */
