#include <stdio.h>
#include "esp_log.h"
#include "esp_wifi.h"
#include "sniff.h"


char *TAG = "main";

//connect to a wifi network
void wifi_connect()
{
    //wifi configuration
    wifi_config_t wifi_config = {
        .sta = {
            .ssid = "SSID",
            .password = "PASSWORD",
        },
    };

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();

    //initialize the tcp/ip adapter
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config));

    //start the wifi connection
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_LOGI(TAG, "Connecting to %s", wifi_config.sta.ssid);

}


void app_main(void)
{
    ESP_LOGI(TAG, "Hello world!");
    wifi_connect();
    wifi_sniffer_init();

}
