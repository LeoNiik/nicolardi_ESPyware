#include "freertos/FreeRTOS.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include "driver/gpio.h"
#include <arpa/inet.h>
#include <stdbool.h>
#include "sniff.h"

#define TAG "DEBUG"
#define IMP "IMPORTANT"

uint8_t level = 0, channel = 2;

bool is_message_1(const eapol_key_packet_t *pkt);
bool is_message_2(const eapol_key_packet_t *pkt);
bool is_message_3(const eapol_key_packet_t *pkt);
bool is_message_4(const eapol_key_packet_t *pkt);
void process_eapol_packet(const eapol_key_packet_t *pkt);
void print_key_information(const eapol_key_packet_t *pkt);

//set the if in promiscuous mode and assign the packet handler
void wifi_sniffer_init(void)
{
  ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
  esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler1);
}

void wifi_sniffer_set_channel(uint8_t channel)
{
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}
//1° filter eapol packets ->ETHER_TYPE_EAPOL 
eapol_packet_t *parse_eapol_packet(data_frame_t *frame) {
    uint8_t *frame_buffer = frame->body;

    if(frame->mac_header.frame_control.protected_frame == 1) {
        //ESP_LOGI(TAG, "Protected frame, skipping...");
        return NULL;
    }

    if(frame->mac_header.frame_control.subtype > 7) {
        //ESP_LOGI(TAG, "QoS data frame");
        // Skipping QoS field (2 bytes)

        frame_buffer += 2;
    }

    // Skipping LLC SNAP header (6 bytes)
    frame_buffer += sizeof(llc_snap_header_t);

    // Check if frame is type of EAPoL
    if(ntohs(*(uint16_t *) frame_buffer) == ETHER_TYPE_EAPOL) {
        //ESP_LOGI(IMP, "EAPOL packet");
        frame_buffer += 2;
        return (eapol_packet_t *) frame_buffer; 
    }
    return NULL;
}

//2° filter eapol key packets 
eapol_key_packet_t *parse_eapol_key_packet(eapol_packet_t *eapol_packet){
    if(eapol_packet->header.packet_type != EAPOL_KEY){
        // ESP_LOGD(TAG, "Not an EAPoL-Key packet.");
        return NULL;
    }
    return (eapol_key_packet_t *) eapol_packet->packet_body;
}
void eapol_packet_info(eapol_packet_t *eapol_packet, int i){
    switch(eapol_packet->header.packet_type){
        case EAPOL_START:
            ESP_LOGI(TAG, "EAPOL packet %d, type: EAPOL_START", i);
            break;
        case EAPOL_LOGOFF:
            ESP_LOGI(TAG, "EAPOL packet %d, type: EAPOL_LOGOFF", i);
            break;
        case EAPOL_KEY:
            ESP_LOGI(TAG, "EAPOL packet %d, type: EAPOL_KEY", i);
            break;
        case EAPOL_ENCAPSULATED_ASF_ALERT:
            ESP_LOGI(TAG, "EAPOL packet %d, type: EAPOL_ENCAPSULATED_ASF_ALERT", i);
            break;
        case EAPOL_MKA: 
            ESP_LOGI(TAG, "EAPOL packet %d, type: EAPOL_MKA", i);
            break;
        case EAPOL_ANNOUNCEMENT_GENERIC:
            ESP_LOGI(TAG, "EAPOL packet %d, type: EAPOL_ANNOUNCEMENT_GENERIC", i);
            break;
        case EAPOL_ANNOUNCEMENT_SPECIFIC:
            ESP_LOGI(TAG, "EAPOL packet %d, type: EAPOL_ANNOUNCEMENT_SPECIFIC", i);
            break;
        case EAPOL_ANNOUNCEMENT_REQ:
            ESP_LOGI(TAG, "EAPOL packet %d, type: EAPOL_ANNOUNCEMENT_REQ", i);
            break;
        default:
            ESP_LOGI(TAG, "EAPOL packet, type: %d", eapol_packet->header.packet_type);
            break;
    }
}

// bool check_handshake(eapol_key_packet_t *eapol_key_packet, uint8_t *addr1, uint8_t *addr2){
//     if(eapol_key_packet->key_information.key_ack == 1 && eapol_key_packet->key_information.key_mic == 1){
//         ESP_LOGI(IMP, "Full handshake caught!");
//         return true;
//     }
//     else{
//         ESP_LOGI(IMP, "Half handshake caught!");
//         return false;
//     }
// }
#define KEY_ACK_MASK      (1 << 7)
#define KEY_MIC_MASK      (1 << 8)

void process_eapol_packet(const eapol_key_packet_t *pkt) {

    print_key_information(pkt);
    return;
    // ESP_LOGI(TAG, "Received EAPOL Key Message, key_ack: %d, key_mic: %d", pkt->key_information.key_ack & KEY_ACK_MASK, pkt->key_information.key_mic & KEY_MIC_MASK);
    if (is_message_1(pkt)) {
        ESP_LOGI(TAG,"Received EAPOL Key Message 1\n");
    } else if (is_message_2(pkt)) {
        ESP_LOGI(TAG,"Received EAPOL Key Message 2\n");
    } else if (is_message_3(pkt)) {
        ESP_LOGI(TAG,"Received EAPOL Key Message 3\n");
    } else if (is_message_4(pkt)) {
        ESP_LOGI(TAG,"Received EAPOL Key Message 4\n");
    } else {
        ESP_LOGI(TAG,"Unknown or malformed EAPOL Key message\n");
    }
}

void printBits(size_t const size, void const * const ptr)
{
    unsigned char *b = (unsigned char*) ptr;
    unsigned char byte;
    int i, j;
    
    for (i = size-1; i >= 0; i--) {
        for (j = 7; j >= 0; j--) {
            byte = (b[i] >> j) & 1;
            ESP_LOGI(TAG, "%u", byte);
        }
    }
}

void print_key_information(const eapol_key_packet_t *pkt) {
    ESP_LOGI(TAG, "Key Information: %04X, size: %zu", pkt->key_information.full_value, sizeof(key_information_t));
    //print every bit of the key information
    //pritn the bit from the left to the right no loop with masking of the full value
    printBits(sizeof(key_information_t), &pkt->key_information);

}

bool is_message_1(const eapol_key_packet_t *pkt) {
    return (pkt->key_information.key_ack == 0 &&
            pkt->key_information.key_mic == 1);
}

bool is_message_2(const eapol_key_packet_t *pkt) {
    return (pkt->key_information.key_ack == 0 &&
            pkt->key_information.key_mic == 1);
}

bool is_message_3(const eapol_key_packet_t *pkt) {
    return (pkt->key_information.key_ack == 1 &&
            pkt->key_information.key_mic == 1);
}


bool is_message_4(const eapol_key_packet_t *pkt) {
    return (pkt->key_information.key_ack == 0 &&
            pkt->key_information.key_mic == 1);
}


void wifi_sniffer_packet_handler1(void* buff, wifi_promiscuous_pkt_type_t type)
{
    static int i = 0;
    if(type != WIFI_PKT_DATA)
    {
        return;
    }

    wifi_promiscuous_pkt_t *frame = (wifi_promiscuous_pkt_t *) buff;
    data_frame_t *data = (data_frame_t *) frame->payload;

    eapol_packet_t *eapol_packet = parse_eapol_packet((data_frame_t *) frame->payload);
    if(eapol_packet == NULL){
        return;
    }

    eapol_key_packet_t *eapol_key_packet = parse_eapol_key_packet(eapol_packet);
    if(eapol_key_packet == NULL){
        return;
    }
  
    uint8_t *addr1 = data->mac_header.addr1;
    uint8_t *addr2 = data->mac_header.addr2;
    //pritn the mac addresses of the packet
    // eapol_packet_info(eapol_packet, i);
    // ESP_LOGI(TAG, "SOURCE %02X:%02X:%02X:%02X:%02X:%02X\n", addr1[0], addr1[1], addr1[2], addr1[3], addr1[4], addr1[5]);
    // ESP_LOGI(TAG, "DEST %02X:%02X:%02X:%02X:%02X:%02X\n", addr2[0], addr2[1], addr2[2], addr2[3], addr2[4], addr2[5]);
    
    // //identyfy if a full handshake is caught
    process_eapol_packet(eapol_key_packet);
    // check_handshake(eapol_key_packet, addr1, addr2);
    // for (int i = 0; i < 6; i++) {
    // }
  
    
    // pcap_serializer_append_frame(frame->payload, frame->rx_ctrl.sig_len, frame->rx_ctrl.timestamp);
    i++;
}