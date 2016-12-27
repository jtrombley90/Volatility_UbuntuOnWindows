cd ~
#Update Ubuntu 16.04 Server
sudo apt-get update && sudo apt-get upgrade -y && sudo apt-get dist-upgrade -y
sudo apt-get install automake libtool make gcc unzip libmagic-dev pcregrep libssl-dev bison flex build-essential libpcre++-dev python-yara python-urllib3 python-dev python-pip libjpeg8 libjpeg8-dev python-socksipy python-lxml -y
sudo pip install --upgrade pip

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

#Install Yara Rules
git clone https://github.com/jtrombley90/Yara_Rules

#Volatility Install
sudo pip install distorm3 pycrypto pillow ujson pyinstrument haystack pycoin simplejson pefile dpapick pysocks requests construct==2.5.5-reupload
git clone https://github.com/volatilityfoundation/volatility
cd volatility
sudo python setup.py install
cd ..

#Install Community Plugins
git clone https://github.com/jtrombley90/Volatility_Plugins
sudo cp -r Volatility_Plugins/* /usr/local/lib/python2.7/dist-packages/volatility-2.6-py2.7.egg/volatility/plugins/
cd /usr/local/lib/python2.7/dist-packages/volatility-2.6-py2.7.egg/volatility/plugins/
sudo mv callstacks.py malware/callstacks.py

echo ""
echo "Please add your VirusTotal API key to the following files:"
echo ""
echo "/usr/local/lib/python2.7/dist-packages/volatility-2.6-py2.7.egg/volatility/plugins/findevilinfo.py"
echo "/usr/local/lib/python2.7/dist-packages/volatility-2.6-py2.7.egg/volatility/plugins/OSINT/osint.conf"
echo ""
