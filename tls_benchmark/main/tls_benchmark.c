#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "esp_cpu.h"

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"
#include "lwip/dns.h"

#include "mbedtls/platform.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/esp_debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"

#define WIFI_SSID      "SHAHID-JUTT-4G"
#define WIFI_PASS      "wanbhachran"
#define WEB_SERVER     "example.com"
#define WEB_PORT       "443"

static const char *TAG = "tls_bench";
static EventGroupHandle_t s_wifi_event_group;
#define WIFI_CONNECTED_BIT BIT0

static void event_handler(void* arg, esp_event_base_t event_base,
                                int32_t event_id, void* event_data) {
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        esp_wifi_connect();
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

static void wifi_init_sta(void) {
    s_wifi_event_group = xEventGroupCreate();
    esp_netif_init();
    esp_event_loop_create_default();
    esp_netif_create_default_wifi_sta();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL, NULL);
    esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, NULL, NULL);
    wifi_config_t wifi_config = {
        .sta = {
            .ssid = WIFI_SSID,
            .password = WIFI_PASS,
        },
    };
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_set_config(WIFI_IF_STA, &wifi_config);
    esp_wifi_start();
    xEventGroupWaitBits(s_wifi_event_group, WIFI_CONNECTED_BIT, pdFALSE, pdFALSE, portMAX_DELAY);
    ESP_LOGI(TAG, "Connected to WiFi");
}

void tls_benchmark_task(void *pvParameters) {
    int ret;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_net_context server_fd;

    mbedtls_ssl_init(&ssl);
    mbedtls_net_init(&server_fd);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    ESP_LOGI(TAG, "Seeding the random number generator");
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);

    ESP_LOGI(TAG, "Setting up the SSL/TLS structure...");
    mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE); // Skip cert verification strictly to measure baseline handshake
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_setup(&ssl, &conf);
    mbedtls_ssl_set_hostname(&ssl, WEB_SERVER);

    ESP_LOGI(TAG, "Connecting to %s:%s...", WEB_SERVER, WEB_PORT);
    ret = mbedtls_net_connect(&server_fd, WEB_SERVER, WEB_PORT, MBEDTLS_NET_PROTO_TCP);
    if(ret != 0) {
        ESP_LOGE(TAG, "mbedtls_net_connect returned -%x", -ret);
        goto exit;
    }

    ESP_LOGI(TAG, "Connected. Setting up BIOS...");
    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    ESP_LOGI(TAG, "Performing the SSL/TLS handshake...");
    
    // Start Measurement
    uint32_t min_mem_before = heap_caps_get_minimum_free_size(MALLOC_CAP_8BIT);
    
    int64_t start_time = esp_timer_get_time();
    uint32_t start_cycles = esp_cpu_get_cycle_count();
    
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            ESP_LOGE(TAG, "mbedtls_ssl_handshake returned -0x%x", -ret);
            goto exit;
        }
    }
    
    uint32_t end_cycles = esp_cpu_get_cycle_count();
    int64_t end_time = esp_timer_get_time();
    
    uint32_t min_mem_after = heap_caps_get_minimum_free_size(MALLOC_CAP_8BIT);
    uint32_t mem_used = min_mem_before - min_mem_after;

    float latency_ms = (end_time - start_time) / 1000.0;
    uint32_t cycles = end_cycles - start_cycles;
    
    ESP_LOGI(TAG, "===============================================");
    ESP_LOGI(TAG, "       MBEDTLS (TLS) HANDSHAKE BENCHMARK       ");
    ESP_LOGI(TAG, "===============================================");
    ESP_LOGI(TAG, "Latency:        %.2f ms", latency_ms);
    ESP_LOGI(TAG, "CPU Cycles:     %lu", cycles);
    ESP_LOGI(TAG, "Peak RAM Usage: %lu bytes (%.2f KB)", mem_used, mem_used / 1024.0);
    ESP_LOGI(TAG, "===============================================");

exit:
    mbedtls_ssl_close_notify(&ssl);
    mbedtls_ssl_session_reset(&ssl);
    mbedtls_net_free(&server_fd);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    vTaskDelete(NULL);
}

void app_main(void) {
    ESP_ERROR_CHECK(nvs_flash_init());
    wifi_init_sta();
    xTaskCreate(&tls_benchmark_task, "tls_bench", 16384, NULL, 5, NULL);
}
