# nicolardi_ESPyware
DNS resolutions Sniffing via ESP-32

## Install 

follow the guide on the esp idf website to install the espressif framework.
Once you have the idf.py command execute this:

```bash
git clone https://github.com/LeoNiik/nicolardi_ESPyware.git\
cd ./nicolardi_ESPyware
idf.py build
idf.py -p /dev/ttyUSB0 flash
```