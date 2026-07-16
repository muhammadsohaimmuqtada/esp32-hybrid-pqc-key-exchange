idf_component_register(SRCS "tls_benchmark.c"
                    INCLUDE_DIRS "."
                    REQUIRES mbedtls nvs_flash esp_wifi esp_timer esp_netif lwip)
