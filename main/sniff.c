#include "freertos/FreeRTOS.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include <arpa/inet.h>
#include "sniff.h"

#define TAG "sniffer"
#define IMP "IMPORTANT"

// static wifi_country_t wifi_country = {.cc="CN", .schan = 1, .nchan = 13}; //Most recent esp32 library struct
uint8_t level = 0, channel = 2;

//set the if in promiscuous mode and assign the packet handler
void wifi_sniffer_init(void)
{
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
    esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);
}

void wifi_sniffer_set_channel(uint8_t channel)
{
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}



void wifi_sniffer_packet_handler(void* buff, wifi_promiscuous_pkt_type_t type)
{

    if(type != WIFI_PKT_DATA)
    {
        return;
    }

    wifi_promiscuous_pkt_t *frame = (wifi_promiscuous_pkt_t *) buff;
    data_frame_t *data = (data_frame_t *) frame->payload;

    //filter for IPV4 packets
    if(data->mac_header.frame_control.type != ETHER_TYPE_IPV4)
    {
        return;
    }
    //
    ipv4_packet_t *ipv4 = (ipv4_packet_t *) data->body;

    //filter for UDP and TCP packets
    if(ipv4->header.protocol != UDP_PROTOCOL || ipv4->header.protocol != TCP_PROTOCOL)
    {
        return;
    }
    

    // Interpret the packet as a UDP or TCP packet and access its ports
    udp_packet_t *udp_tcp = (udp_packet_t *) ipv4->data ;  // Move past the IPv4 header
    ESP_LOGI(TAG, "%d , %d", ntohs(udp_tcp->header.src_port), ntohs(udp_tcp->header.dst_port));

    // Check for DNS port (53)
    if (ntohs(udp_tcp->header.src_port) != DNS_PORT && ntohs(udp_tcp->header.dst_port) != DNS_PORT) {
        return;
    }
    
    ESP_LOGI(IMP, "got an DNS-packet");

    parse_dns_packet(udp_tcp->data, ntohs(udp_tcp->header.length));

    // pcap_serializer_append_frame(frame->payload, frame->rx_ctrl.sig_len, frame->rx_ctrl.timestamp);
  
}


void parse_dns_packet(uint8_t *data, uint16_t length)
{
    dns_packet_t *dns = (dns_packet_t *) data;
    dns_header_t *header = &(dns->header);
    dns_question_t *question = dns->questions;
    dns_rr_t *answer = dns->answers;


    ESP_LOGI(TAG, "DNS packet");
    ESP_LOGI(TAG, "ID: %d", ntohs(header->id));
    ESP_LOGI(TAG, "Questions: %d", ntohs(header->nquestions));
    ESP_LOGI(TAG, "Answers: %d", ntohs(header->nanswers));
    ESP_LOGI(TAG, "Authority: %d", ntohs(header->nauthRR));
    ESP_LOGI(TAG, "Additional: %d", ntohs(header->naddRR));

    for(int i = 0; i < ntohs(header->nquestions); i++)
    {
        ESP_LOGI(TAG, "Question %d", i);
        ESP_LOGI(TAG, "QNAME: %s", question->name);
        ESP_LOGI(TAG, "QTYPE: %d", ntohs(question->type));
        ESP_LOGI(TAG, "QCLASS: %d", ntohs(question->class));
        question++;
    }

    for(int i = 0; i < ntohs(header->nanswers); i++)
    {
        ESP_LOGI(TAG, "Answer %d", i);
        ESP_LOGI(TAG, "NAME: %s", answer->name);
        ESP_LOGI(TAG, "TYPE: %d", ntohs(answer->type));
        ESP_LOGI(TAG, "CLASS: %d", ntohs(answer->class));
        ESP_LOGI(TAG, "TTL: %lu", ntohl(answer->ttl));
        ESP_LOGI(TAG, "RDLENGTH: %d", ntohs(answer->rdlength));
        ESP_LOGI(TAG, "RDATA: %s", answer->rdata);
        answer++;
    }
}