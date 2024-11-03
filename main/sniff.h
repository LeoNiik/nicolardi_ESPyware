#include <stdint.h>
#define LED_GPIO_PIN                     5
#define WIFI_CHANNEL_SWITCH_INTERVAL  (500)
#define WIFI_CHANNEL_MAX               (13)



#define ETHER_TYPE_IPV4   0x0800
#define TCP_PROTOCOL      6
#define UDP_PROTOCOL      17
#define DNS_PORT          53


typedef struct
{
    uint8_t version:4;           // 4-bit version
    uint8_t header_length:4;      // 4-bit header length
    uint8_t tos;                  // Type of Service
    uint16_t total_length;        // Total length
    uint16_t identification;      // Identification
    uint16_t flags:3;             // Flags (3 bits)
    uint16_t fragment_offset:13;  // Fragment offset (13 bits)
    uint8_t ttl;                  // Time to Live
    uint8_t protocol;             // Protocol
    uint16_t checksum;            // Header checksum
    uint8_t src_ip[4];            // Source IP address
    uint8_t dst_ip[4];            // Destination IP address
    uint8_t options[];            // Options (variable length, if header_length > 5)
} ipv4_header_t;

typedef struct {
    ipv4_header_t header;
    uint8_t data[];  // Data (variable length)
} ipv4_packet_t;



/* UDP Packet structure*/

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} udp_header_t;

typedef struct {
    udp_header_t header;
    uint8_t data[];  // Data (variable length)
} udp_packet_t;



/* DNS Packet structure */

typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t nquestions;
    uint16_t nanswers;
    uint16_t nauthRR;
    uint16_t naddRR;
} dns_header_t;

typedef struct {
    uint8_t *name;
    uint16_t type;
    uint16_t class;
} dns_question_t;

typedef struct {
    uint8_t *name;
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;
    uint8_t *rdata;
} dns_rr_t;

typedef struct {
    dns_header_t header;
    dns_question_t *questions;
    dns_rr_t *answers;
    dns_rr_t *authRR;
    dns_rr_t *addRR;
} dns_packet_t;



typedef struct {
    uint8_t protocol_version:2;
    uint8_t type:2;
    uint8_t subtype:4;
    uint8_t to_ds:1;
    uint8_t from_ds:1;
    uint8_t more_fragments:1;
    uint8_t retry:1;
    uint8_t power_management:1;
    uint8_t more_data:1;
    uint8_t protected_frame:1;
    uint8_t htc_order:1;
} frame_control_t;

//mac header
typedef struct {
    frame_control_t frame_control;
    uint16_t duration;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint16_t sequence_control;
} data_frame_mac_header_t;

//logical link control header 
typedef struct {
    uint8_t snap_dsap;
    uint8_t snap_ssap;
    uint8_t control;
    uint8_t encapsulation[3];
} llc_snap_header_t;

//generic data frame
typedef struct {
    data_frame_mac_header_t mac_header;
    uint8_t body[];
} data_frame_t;


void parse_dns_packet(uint8_t *data, uint16_t length);
void wifi_sniffer_init(void);
void wifi_sniffer_set_channel(uint8_t channel);
static void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type);
