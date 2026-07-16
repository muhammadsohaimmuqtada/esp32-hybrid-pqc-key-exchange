idf_component_register(
    SRCS "main.c" "crypto_hybrid.c" "benchmark.c"
    INCLUDE_DIRS "."
    REQUIRES mlkem512 mbedtls nvs_flash esp_wifi esp_netif esp_event esp_http_client esp_timer esp-tls
    EMBED_TXTFILES "server.crt"
)

target_compile_options(${COMPONENT_LIB} PRIVATE -O2 -Wall)
