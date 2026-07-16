#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "wifi_config.h"
#include "esp_tls.h"
#include "esp_http_client.h"

static const char *TAG = "TLS_MAIN";

/* Embed the server certificate */
extern const uint8_t server_cert_pem_start[] asm("_binary_server_crt_start");
extern const uint8_t server_cert_pem_end[]   asm("_binary_server_crt_end");

/* Global Wi-Fi event handler */
static void wifi_event_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data) {
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        esp_wifi_connect();
        ESP_LOGI(TAG, "Retry to connect to the AP");
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        ESP_LOGI(TAG, "Got IP: " IPSTR, IP2STR(&event->ip_info.ip));
    }
}

void wifi_init_sta(void) {
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, &instance_got_ip));

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = WIFI_SSID,
            .password = WIFI_PASS,
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());
}

void tls_task(void *pvParameters) {
    vTaskDelay(pdMS_TO_TICKS(5000)); // Wait for Wi-Fi

    char url[128];
    snprintf(url, sizeof(url), "https://%s:%d/api/telemetry", SERVER_HOST, SERVER_PORT);

    while (1) {
        ESP_LOGI(TAG, "Establishing new TLS 1.3 connection to %s", url);
        
        esp_http_client_config_t config = {
            .url = url,
            .cert_pem = (const char *)server_cert_pem_start,
            .transport_type = HTTP_TRANSPORT_OVER_SSL,
            .keep_alive_enable = true
        };
        
        esp_http_client_handle_t client = esp_http_client_init(&config);
        
        if (client == NULL) {
            ESP_LOGE(TAG, "Failed to initialize HTTP client");
            vTaskDelay(pdMS_TO_TICKS(5000));
            continue;
        }

        // Send 50 telemetry packets over the same TLS connection (simulating our Hybrid loop)
        for (int i = 0; i < 50; i++) {
            vTaskDelay(pdMS_TO_TICKS(TELEMETRY_INTERVAL_MS));
            
            char post_data[256];
            snprintf(post_data, sizeof(post_data), "{\"temperature\":25.0,\"humidity\":50.0,\"timestamp\":0,\"sequence\":%d,\"device_id\":\"ESP32-TLS\"}", i);
            
            esp_http_client_set_method(client, HTTP_METHOD_POST);
            esp_http_client_set_post_field(client, post_data, strlen(post_data));
            
            esp_err_t err = esp_http_client_perform(client);
            if (err == ESP_OK) {
                ESP_LOGI(TAG, "HTTPS POST Status = %d, content_length = %d",
                         (int)esp_http_client_get_status_code(client),
                         (int)esp_http_client_get_content_length(client));
            } else {
                ESP_LOGE(TAG, "HTTPS POST request failed: %s", esp_err_to_name(err));
                break; // Break loop on error to re-handshake
            }
        }
        
        esp_http_client_cleanup(client);
        ESP_LOGI(TAG, "TLS session closed, rotating session...");
    }
}

void app_main(void) {
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    wifi_init_sta();

    xTaskCreatePinnedToCore(tls_task, "tls_task", 32768, NULL, 5, NULL, 1);
}
