/*
 * ESP32 Hybrid PQC — Main Firmware
 * X25519 + ML-KEM-512 Hybrid Post-Quantum Key Exchange
 *
 * Protocol: session_key = HKDF-SHA256(X25519_ss || ML-KEM_ss)
 * Target: ESP32-D0WD-V3 (240 MHz, 520 KB SRAM, 4 MB Flash)
 *
 * Based on: "Hybrid Post-Quantum Cryptography on ESP32 Edge Devices"
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_task_wdt.h"

#include "esp_system.h"
#include "esp_random.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "esp_chip_info.h"
#include "nvs_flash.h"

#include "crypto_hybrid.h"
#include "benchmark.h"
#include "wifi_config.h"
#include "esp_http_client.h"

static const char *TAG = "PQC_MAIN";

/* Wi-Fi event group */
static EventGroupHandle_t wifi_event_group;
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1

static int wifi_retry_count = 0;
#define MAX_WIFI_RETRIES 10

/* Server IP - will be set to gateway or configured address */
static char server_ip[16] = SERVER_HOST;

/*
 * Wi-Fi event handler
 */
static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                                int32_t event_id, void *event_data) {
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        ESP_LOGI(TAG, "Skipping Wi-Fi connection for local benchmarking");
        /*
        // int retry_count = 0;
        // const int max_retries = 10;
        // while (retry_count < max_retries) {
        //     if (wifi_connected) {
        //         break;
        //     }
        //     ESP_LOGI(TAG, "Retrying Wi-Fi connection (%d/%d)...", retry_count + 1, max_retries);
        //     vTaskDelay(pdMS_TO_TICKS(2000));
        //     retry_count++;
        // }

        // if (!wifi_connected) {
        //     ESP_LOGW(TAG, "Failed to connect to Wi-Fi. Benchmark will run in local-only mode.");
        // } else {
        //     ESP_LOGI(TAG, "Wi-Fi connected successfully");
        // }
        */
        if (wifi_retry_count < MAX_WIFI_RETRIES) {
            esp_wifi_connect();
            wifi_retry_count++;
            ESP_LOGI(TAG, "Retrying Wi-Fi connection (%d/%d)...", wifi_retry_count, MAX_WIFI_RETRIES);
        } else {
            xEventGroupSetBits(wifi_event_group, WIFI_FAIL_BIT);
            ESP_LOGE(TAG, "Wi-Fi connection failed after %d retries", MAX_WIFI_RETRIES);
        }
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        ESP_LOGI(TAG, "Connected! IP: " IPSTR, IP2STR(&event->ip_info.ip));

        /* If server_host is 0.0.0.0, use the gateway as server */
        if (strcmp(server_ip, "0.0.0.0") == 0) {
            snprintf(server_ip, sizeof(server_ip), IPSTR, IP2STR(&event->ip_info.gw));
            ESP_LOGI(TAG, "Auto-detected server IP (gateway): %s", server_ip);
        }

        wifi_retry_count = 0;
        xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

/*
 * Initialize Wi-Fi in STA mode
 */
static void wifi_init_sta(void) {
    wifi_event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                    &wifi_event_handler, NULL, &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                    &wifi_event_handler, NULL, &instance_got_ip));

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = WIFI_SSID,
            .password = WIFI_PASS,
            .threshold.authmode = WIFI_AUTH_WPA_PSK,
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "Connecting to Wi-Fi SSID: %s", WIFI_SSID);

    /* Wait for connection */
    EventBits_t bits = xEventGroupWaitBits(wifi_event_group,
                                           WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
                                           pdFALSE, pdFALSE, portMAX_DELAY);

    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "Wi-Fi connected successfully");
    } else {
        ESP_LOGE(TAG, "Wi-Fi connection failed");
    }
}

/*
 * Print system information
 */
static void print_system_info(void) {
    esp_chip_info_t chip_info;
    esp_chip_info(&chip_info);

    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "╔══════════════════════════════════════════════════════════╗");
    ESP_LOGI(TAG, "║    HYBRID POST-QUANTUM CRYPTOGRAPHY — ESP32 EDGE       ║");
    ESP_LOGI(TAG, "║    X25519 + ML-KEM-512 (FIPS 203) + HKDF-SHA256        ║");
    ESP_LOGI(TAG, "╠══════════════════════════════════════════════════════════╣");
    ESP_LOGI(TAG, "║  Chip:    ESP32 rev %d, %d cores @ 240 MHz             ║",
             chip_info.revision, chip_info.cores);
    ESP_LOGI(TAG, "║  SRAM:    520 KB                                        ║");
    ESP_LOGI(TAG, "║  Flash:   4 MB                                          ║");
    ESP_LOGI(TAG, "║  Free heap: %lu bytes                                   ║",
             (unsigned long)esp_get_free_heap_size());
    ESP_LOGI(TAG, "╚══════════════════════════════════════════════════════════╝");
    ESP_LOGI(TAG, "");
}

/*
 * Simulated sensor telemetry data
 */
typedef struct {
    float temperature;
    float humidity;
    uint32_t timestamp;
    uint32_t sequence;
} telemetry_data_t;

static uint32_t telemetry_seq = 0;

static void generate_telemetry(telemetry_data_t *data) {
    /* Use internal temperature sensor approximation + random jitter */
    uint32_t rand_val = esp_random();
    data->temperature = 22.0f + (float)(rand_val % 100) / 10.0f;
    data->humidity = 45.0f + (float)((rand_val >> 8) % 200) / 10.0f;
    data->timestamp = (uint32_t)(esp_timer_get_time() / 1000000);
    data->sequence = telemetry_seq++;
}

/*
 * HTTP helper: perform POST requests
 */
static int send_http_post(const char *url, const uint8_t *payload, size_t payload_len,
                          uint8_t *response_buf, size_t *response_len) {
    esp_http_client_config_t config = {
        .url = url,
        .method = HTTP_METHOD_POST,
        .timeout_ms = 5000,
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (client == NULL) {
        ESP_LOGE(TAG, "Failed to initialize HTTP client");
        return -1;
    }

    esp_http_client_set_header(client, "Content-Type", "application/octet-stream");
    esp_http_client_set_post_field(client, (const char *)payload, payload_len);

    esp_err_t err = esp_http_client_open(client, payload_len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "HTTP request failed: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        return -1;
    }

    esp_http_client_write(client, (const char *)payload, payload_len);
    int content_length = esp_http_client_fetch_headers(client);

    int status = esp_http_client_get_status_code(client);
    if (status != 200) {
        ESP_LOGE(TAG, "Server returned status code %d", status);
        esp_http_client_cleanup(client);
        return -1;
    }

    int target_len = (content_length > 0) ? content_length : *response_len;
    if (target_len > *response_len) {
        target_len = *response_len;
    }

    int read_len = 0;
    while (read_len < target_len) {
        int r = esp_http_client_read(client, (char *)response_buf + read_len, target_len - read_len);
        if (r <= 0) break;
        read_len += r;
    }

    *response_len = read_len;
    esp_http_client_cleanup(client);
    return 0;
}

/*
 * Test public internet connection to Google
 */
static void test_google_connection(void) {
    ESP_LOGI(TAG, "Testing public internet connectivity: connecting to http://www.google.com...");
    esp_http_client_config_t config = {
        .url = "http://www.google.com",
        .method = HTTP_METHOD_GET,
        .timeout_ms = 5000,
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (client == NULL) {
        ESP_LOGE(TAG, "Failed to initialize HTTP client for Google");
        return;
    }

    esp_err_t err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        int status = esp_http_client_get_status_code(client);
        int len = esp_http_client_get_content_length(client);
        ESP_LOGI(TAG, "Google connection successful! Status: %d, Length: %d", status, len);
    } else {
        ESP_LOGE(TAG, "Google connection failed: %s", esp_err_to_name(err));
    }

    esp_http_client_cleanup(client);
}

/*
 * Main PQC task — runs the full protocol
 */
static void pqc_task(void *pvParameters) {
    ESP_LOGI(TAG, "Starting Hybrid PQC task...");

    /* Run internet connection test to Google first */
    test_google_connection();

    /* Execute full Q1 journal benchmark suite (Classical vs PQC vs Hybrid) */
    ESP_LOGI(TAG, "=== Executing 100-Iteration Q1 Journal Benchmark Suite ===");
    benchmark_stats_t stats[3];
    int iterations = BENCHMARK_ITERATIONS;
    benchmark_run_suite(iterations, server_ip, SERVER_PORT, stats);
    benchmark_print_comparison(stats);
    benchmark_send_results(stats, server_ip, SERVER_PORT);

    /* Execute Standard mbedTLS (TLS 1.3) baseline comparison benchmark */
    benchmark_run_mbedtls_baseline();

    /* Now run continuous hybrid handshake + telemetry */
    ESP_LOGI(TAG, "");
    ESP_LOGI(TAG, "=== Starting continuous hybrid telemetry ===");

    int ret;
    while (1) {
        hybrid_ctx_t ctx;
        hybrid_init(&ctx, MODE_HYBRID);

        esp_task_wdt_reset(); /* Feed TWDT without yielding context */
        /* Keygen */
        ret = hybrid_keygen(&ctx);
        if (ret != 0) {
            ESP_LOGE(TAG, "Hybrid keygen failed, retrying...");
            vTaskDelay(pdMS_TO_TICKS(5000));
            continue;
        }

        /* Network handshake */
        uint8_t pubkey_buf[1 + X25519_KEY_SIZE + KYBER_PUBLICKEYBYTES + 32];
        int pubkey_len = hybrid_pack_pubkeys(&ctx, pubkey_buf, sizeof(pubkey_buf));
        if (pubkey_len < 0) {
            ESP_LOGE(TAG, "Failed to pack public keys");
            hybrid_cleanup(&ctx);
            vTaskDelay(pdMS_TO_TICKS(5000));
            continue;
        }

        char handshake_url[128];
        snprintf(handshake_url, sizeof(handshake_url), "http://%s:%d/handshake", server_ip, SERVER_PORT);

        uint8_t response_buf[16 + X25519_KEY_SIZE + KYBER_CIPHERTEXTBYTES + 64];
        size_t response_len = sizeof(response_buf);

        ESP_LOGI(TAG, "Sending handshake to %s (%d bytes)...", handshake_url, pubkey_len);
        ret = send_http_post(handshake_url, pubkey_buf, pubkey_len, response_buf, &response_len);
        if (ret != 0 || response_len < 16) {
            ESP_LOGE(TAG, "Handshake network request failed or response too short (%d bytes)", (int)response_len);
            hybrid_cleanup(&ctx);
            vTaskDelay(pdMS_TO_TICKS(5000));
            continue;
        }

        /* Extract 16-byte Session ID */
        uint8_t session_id[16];
        memcpy(session_id, response_buf, 16);
        ESP_LOGI(TAG, "Handshake successful! Session ID: %02x%02x%02x%02x%02x%02x%02x%02x...",
                 session_id[0], session_id[1], session_id[2], session_id[3],
                 session_id[4], session_id[5], session_id[6], session_id[7]);

        /* Derive session key using the full response (Session ID + pubkeys/CT + HMAC) */
        ret = hybrid_process_server_response(&ctx, response_buf, response_len);
        if (ret != 0) {
            ESP_LOGE(TAG, "Failed to process server response / derive session key");
            hybrid_cleanup(&ctx);
            vTaskDelay(pdMS_TO_TICKS(5000));
            continue;
        }

        /* Telemetry Loop with Key Rotation after 50 packets */
        int telemetry_errors = 0;
        int packets_sent = 0;
        char telemetry_url[128];
        snprintf(telemetry_url, sizeof(telemetry_url), "http://%s:%d/api/telemetry", server_ip, SERVER_PORT);

        while (telemetry_errors < 3) {
            if (packets_sent >= 50) {
                ESP_LOGI(TAG, "Key rotation threshold reached (50 packets). Rotating keys...");
                break;
            }

            vTaskDelay(pdMS_TO_TICKS(TELEMETRY_INTERVAL_MS));

            telemetry_data_t telemetry;
            generate_telemetry(&telemetry);

            ESP_LOGI(TAG, "Preparing telemetry #%u: temp=%.1f C, humidity=%.1f%%, ts=%u",
                     (unsigned int)telemetry.sequence, telemetry.temperature,
                     telemetry.humidity, (unsigned int)telemetry.timestamp);

            /* Format JSON */
            char json_payload[256];
            snprintf(json_payload, sizeof(json_payload),
                     "{\"temperature\":%.2f,\"humidity\":%.2f,\"timestamp\":%u,\"sequence\":%u,\"device_id\":\"ESP32-Edge\"}",
                     telemetry.temperature, telemetry.humidity,
                     (unsigned int)telemetry.timestamp, (unsigned int)telemetry.sequence);

            /* Encrypt telemetry */
            size_t json_len = strlen(json_payload);
            uint8_t encrypt_buf[12 + 256 + 16];
            size_t ciphertext_len = 0;

            ret = hybrid_encrypt_telemetry(&ctx, (const uint8_t *)json_payload, json_len, encrypt_buf, &ciphertext_len);
            if (ret != 0) {
                ESP_LOGE(TAG, "Failed to encrypt telemetry");
                telemetry_errors++;
                continue;
            }

            /* Prepend Session ID (16 bytes) to the encrypted payload */
            uint8_t post_buf[16 + 12 + 256 + 16];
            memcpy(post_buf, session_id, 16);
            memcpy(post_buf + 16, encrypt_buf, ciphertext_len);
            size_t post_len = 16 + ciphertext_len;

            /* POST telemetry */
            uint8_t response_telemetry[256];
            size_t response_telemetry_len = sizeof(response_telemetry);

            ESP_LOGI(TAG, "Posting encrypted telemetry to %s (%d bytes)...", telemetry_url, (int)post_len);
            ret = send_http_post(telemetry_url, post_buf, post_len, response_telemetry, &response_telemetry_len);
            if (ret != 0) {
                ESP_LOGE(TAG, "Failed to post encrypted telemetry");
                telemetry_errors++;
                continue;
            }

            /* Decrypt response from server */
            uint8_t decrypted_response[256];
            size_t decrypted_response_len = 0;
            ret = hybrid_decrypt_response(&ctx, response_telemetry, response_telemetry_len, decrypted_response, &decrypted_response_len);
            if (ret != 0) {
                ESP_LOGE(TAG, "Failed to decrypt server response");
                telemetry_errors++;
                continue;
            }

            ESP_LOGI(TAG, "Successfully decrypted server response: %.*s", (int)decrypted_response_len, (char *)decrypted_response);
            telemetry_errors = 0; // Reset consecutive errors count
            packets_sent++;
        }

        /* Clean up context and trigger re-handshake */
        if (packets_sent >= 50) {
            ESP_LOGI(TAG, "Session key successfully rotated after 50 telemetry packets.");
        } else {
            ESP_LOGW(TAG, "Too many telemetry errors or session expired. Initiating re-handshake...");
        }
        hybrid_cleanup(&ctx);
    }
}

/*
 * Application entry point
 */
void app_main(void) {
    /* Initialize NVS (required for Wi-Fi) */
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    /* Print banner */
    print_system_info();

    /* Connect to Wi-Fi */
    wifi_init_sta();

    /* Launch PQC task on core 1 (core 0 handles Wi-Fi) */
    xTaskCreatePinnedToCore(pqc_task, "pqc_task", 32768, NULL, 5, NULL, 1);
}
