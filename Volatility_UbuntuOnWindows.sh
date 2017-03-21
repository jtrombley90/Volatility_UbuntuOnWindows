cd ~
#Update Ubuntu 16.04 Server
sudo apt-get update && sudo apt-get upgrade -y && sudo apt-get dist-upgrade -y
sudo apt-get install automake libtool make gcc unzip libmagic-dev pcregrep libssl-dev bison flex build-essential libpcre++-dev python-yara python-urllib3 python-dev python-pip libjpeg8 libjpeg8-dev python-socksipy python-lxml -y
sudo -H pip install --upgrade pip

#Install Yara
wget https://github.com/VirusTotal/yara/archive/v3.5.0.tar.gz
tar xvfz v3.5.0.tar.gz
cd yara-3.5.0
./bootstrap.sh
./configure --with-crypto --enable-magic
make
sudo make install
sudo make check
cd ..
sudo rm -rf yara-3.5.0

#Volatility Install
sudo -H pip install distorm3 pycrypto pillow ujson pyinstrument haystack pycoin simplejson pefile dpapick pysocks requests construct==2.5.5-reupload
wget http://downloads.volatilityfoundation.org/releases/2.5/volatility-2.5.zip
unzip volatility-2.5.zip
sudo mv volatility-2.5 /opt/
sudo ln -s /opt/volatility-2.5/vol.py /usr/local/bin/
sudo chmod +x /usr/local/bin/vol.py
