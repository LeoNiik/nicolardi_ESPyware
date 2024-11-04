# nicolardi_ESPyware
DNS resolutions Sniffing via ESP-32

## Install 

Follow the guide on the esp idf website to install the espressif framework.
Once you have the idf.py command execute this:

```bash
git clone https://github.com/LeoNiik/nicolardi_ESPyware.git\
cd ./nicolardi_ESPyware
idf.py build
idf.py -p /dev/ttyUSB0 flash
```

## Project workflow

The Esp32 is supposed to capture the 4 way handshakes of a specific device and the respective traffic. Then serialize the packets captured and only then stream the files
to a PC with wireshark, that given the PSK (pre-shared key) and the handshake will decrypt the traffic.

### Deauthentication Attack:

Send Deauth Packets: You can send deauthentication packets to connected devices to force them to reconnect. This is typically done to capture the 4-way handshake as devices reconnect to the network.
Capture Device MACs: When sending deauth packets, make sure to target devices connected to the network by using their MAC addresses. This will prompt those devices to re-authenticate, allowing you to capture the handshake.

### Capture the 4-Way Handshake:

Capture All 4 Packets: Yes, it’s crucial to capture all four packets of the 4-way handshake. These packets contain important information necessary to derive the Pairwise Transient Key (PTK) for decryption.
You’ll want to filter for packets with a specific frame type corresponding to the handshake (e.g., EAPOL packets).
Store these packets in a buffer or log them for later analysis.

### Capture Additional Packets:

After capturing the handshake, continue capturing all data packets exchanged between devices and the AP. This includes both unicast and broadcast/multicast packets.
Ensure your ESP32 is configured to operate in promiscuous mode to receive all packets in the air.
You may need to format the captured packets into a format that Wireshark can interpret (like PCAP).

### Streaming to a PC:

Stream the captured packets in real time or save them to flash memory or an SD card.
Use a serial connection (UART), Wi-Fi, or any other suitable method to send the captured packets to a PC.