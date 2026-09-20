/*
 * Wi-Fi Configuration for ESP32 Hybrid PQC
 * Edit these values for your network or provide a wifi_config.local.h (ignored by git)
 */
#ifndef WIFI_CONFIG_H
#define WIFI_CONFIG_H

#if __has_include("wifi_config.local.h")
#include "wifi_config.local.h"
#endif

#ifndef WIFI_SSID
#define WIFI_SSID      "YOUR_SSID_HERE"
#endif

#ifndef WIFI_PASS
#define WIFI_PASS      "YOUR_WIFI_PASSWORD_HERE"
#endif

/* Server configuration - set to your Python server's LAN IP */
#ifndef SERVER_HOST
#define SERVER_HOST    "192.168.1.100" // Change this to your Server's IP
#endif

#ifndef SERVER_PORT
#define SERVER_PORT    8443
#endif

/* Benchmark configuration */
#define BENCHMARK_ITERATIONS  10
#define TELEMETRY_INTERVAL_MS 5000

#endif /* WIFI_CONFIG_H */
