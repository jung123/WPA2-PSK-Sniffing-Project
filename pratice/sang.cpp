#include <iostream>
#include <set>
#include <string>
#include <unistd.h>
#include <tins/tins.h>
#include <pcap.h>
#include <vector>
#include <signal.h>
#include <thread>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>
#include <algorithm>
using namespace Tins;
using namespace std;
#define ON 1
#define OFF 0


//int ApScannerStatus = ON;
//int ChannelHopperStatus = ON;

struct ApInfo{
	Dot11::address_type bssid;
	string ssid;
	string psk;
	unsigned channel;
}typedef ApInfo;

struct KEY{
	Dot11::address_type device;
	unsigned char Anonce[32];
	unsigned char Snonce[32];
	unsigned char PMK[32];
	unsigned char TK[16];
	int is_activated;
}typedef KEY;
/*
void ApScanner::signal_handler(int signal){
	if(signal == SIGINT){
		ApScannerStatus = OFF;
		ChannelHopperStatus = OFF;
	}
}
*/
class Interface {
	public :
		string name;
		void find_interface();
};

void Interface::find_interface(){
        system("clear");
	char* dev;
        char* errbuf;
        pcap_if_t *alldevs;
        pcap_t *device_handle;
        if(pcap_findalldevs(&alldevs, errbuf) == -1){
                cout << errbuf << endl;
                return ;
        }
        int i=0;
        vector<string> v;
        cout << "[*] Select network interface"<< endl << endl;
        while( alldevs->next != NULL){
                if(alldevs -> flags ==0){
                        alldevs = alldevs->next;
                        continue;
                }
                if(alldevs->name !=NULL) cout<< i << ". "<< alldevs->name << endl;
                v.push_back(string(alldevs->name));
                alldevs = alldevs->next;
                i++;
        }
	cout << endl <<"Select Device : ";
        int select_device;
        cin >> select_device;
	this->name = v[select_device];
	system("clear");
}


class ApScanner {
	public:
		ApScanner(string InterfaceName);
		ApInfo run();
		string iface;
		static void signal_handler(int signo);
		static int ApScannerStatus;
	private:
    		set<Dot11::address_type> bssid_list;
		unsigned int count;
		vector<ApInfo> ap_list;
   		bool callback(PDU& pdu);
		void channel_hopper();

};

int ApScanner::ApScannerStatus = ON;

void ApScanner::signal_handler(int signal){
        if(signal == SIGINT){
                ApScanner::ApScannerStatus = OFF;
        }
}

ApScanner::ApScanner(string InterfaceName){
	this->iface = InterfaceName;
	this->count = 0;
}
void ApScanner::channel_hopper(){
	srand(time(NULL));
	int channel;
	char command[30];
	while(1){
		if (ApScanner::ApScannerStatus == OFF) break;
		channel = rand() % 14 +1;
		sprintf(command, "iwconfig %s channel %d", this->iface.c_str(), channel);
		sleep(1);
		system(command);
	}
}

ApInfo ApScanner::run() {
	cout << "[*] Start Ap Scanning.." << endl <<endl;
	SnifferConfiguration config;
	config.set_promisc_mode(true);
	config.set_filter("type mgt subtype beacon");
	config.set_rfmon(true);
	Sniffer sniffer(this->iface, config);

	signal(SIGINT, ApScanner::signal_handler);	//?????

	thread hopper(&ApScanner::channel_hopper, this);	//??? ??????????
	sniffer.sniff_loop(make_sniffer_handler(this, &ApScanner::callback));
	hopper.join();	// ??? ??? ???.
	cout << endl <<"Select AP : " ;
	int select;
	cin >> select;
	string psk;
	cout << "Input Ap's PSK(password) : ";
	cin >> psk;
	ap_list[select].psk = psk;
        char command[100];
        sprintf(command, "iw dev %s set channel %d ht40+", this->iface.c_str(), ap_list[select].channel);
        system(command);
	system("clear");
	return ap_list[select];
}

bool ApScanner::callback(PDU& pdu) {
	const Dot11Beacon beacon = pdu.rfind_pdu<Dot11Beacon>();
	// All beacons must have from_ds == to_ds == 0
	ApInfo AP;
	if (ApScanner::ApScannerStatus == OFF)
		return false;
	if (!beacon.from_ds() && !beacon.to_ds()) {
		Dot11::address_type bssid = beacon.addr2();	// AP's bssid
        	set<Dot11::address_type>::iterator it = bssid_list.find(bssid);
		if (it == bssid_list.end()) {
			 try {
				AP.ssid = beacon.ssid();
				AP.bssid = bssid;
				AP.channel = beacon.ds_parameter_set();
				bssid_list.insert(bssid);
				ap_list.push_back(AP);
				cout << this->count <<". " << AP.bssid << " - " << AP.ssid << " - " << AP.channel << " - "<<  endl;
				this->count ++;
			}catch (runtime_error&) {}
		}
	}
	return true;
}

const HWAddress<6>& min(const HWAddress<6>& lhs, const HWAddress<6>& rhs) {
    return lhs < rhs ? lhs : rhs;
}

const HWAddress<6>& max(const HWAddress<6>& lhs, const HWAddress<6>& rhs) {
    return lhs < rhs ? rhs : lhs;
}

class EAPOLSniffer{
	public:
		EAPOLSniffer(ApInfo Ap, string IfaceName);
		KEY CaptureEAPOL();
		ApInfo Ap;
		string IfaceName;
		KEY key;
	private:
		bool callback(PDU &pdu);
		void Generate_PMK();
		void Generate_PTK();
};

EAPOLSniffer::EAPOLSniffer(ApInfo Ap, string IfaceName){
	this->Ap = Ap;
	this->IfaceName = IfaceName;
	this->key.is_activated = OFF;
	memset(this->key.Snonce, 0x00, 32);
	memset(this->key.Anonce, 0x00, 32);
	memset(this->key.PMK, 0x00, 32);
	memset(this->key.TK, 0x00, 16);
}

void EAPOLSniffer::Generate_PTK(){
	unsigned char buf[100];
        memset(buf, 0x00, 100);
        unsigned char str[23] = "Pairwise key expansion";
        memcpy(buf, str, 23);   // 0 ~ 22
        min(this->Ap.bssid, this->key.device).copy(buf+23); // 23 ~ 28
		std::cout << "min : " << min(this->Ap.bssid, this->key.device).to_string() << std::endl;
        max(this->Ap.bssid, this->key.device).copy(buf+29); // 29 ~ 34
		std::cout << "max : " << max(this->Ap.bssid, this->key.device).to_string() << std::endl;
		if(lexicographical_compare (this->key.Anonce, this->key.Anonce+32, this->key.Snonce, this->key.Snonce+32)){
                memcpy(buf+35, this->key.Anonce, 32);   // 35 ~ 66
                memcpy(buf+67, this->key.Snonce, 32);   // 67 ~ 99
        }else{
                memcpy(buf+35, this->key.Snonce, 32);
                memcpy(buf+67, this->key.Anonce, 32);
        }
        unsigned char value[80];
        for(int i=0; i < 4; i++) {
                buf[99] = i;
                HMAC(EVP_sha1(), this->key.PMK, 32, buf, 100, value+(i * 20), 0);
        }
        memcpy(this->key.TK, value+32, 16);
        cout << "[+] Generate PTK!" << endl;
}

void EAPOLSniffer::Generate_PMK(){
	unsigned char buf[32];
	std::cout << "psk : " << this->Ap.psk << " size : " << this->Ap.psk.size() << std::endl;
	std::cout << "ssid : " << this->Ap.ssid << " size : " << this->Ap.ssid.size() << std::endl;

        PKCS5_PBKDF2_HMAC_SHA1(this->Ap.psk.c_str(), this->Ap.psk.size(), (unsigned char*)this->Ap.ssid.c_str(), this->Ap.ssid.size(), 4096, 32, buf);
        memcpy(this->key.PMK, buf, 32);
	cout << "[+] Generate PMK!"<< endl;
}

KEY EAPOLSniffer::CaptureEAPOL(){
	cout << "[*] Capture EAPOL" <<" / " <<Ap.ssid << " / "<< Ap.channel << endl;
	cout << "[+] Start EAPSniffer " << endl;
	char command[1000];
	SnifferConfiguration config;
        config.set_promisc_mode(true);
        sprintf(command, "type data subtype qos-data and (wlan addr1 %s or wlan addr2 %s or wlan addr3 %s or wlan addr4 %s)",Ap.bssid.to_string().c_str() ,Ap.bssid.to_string().c_str(),Ap.bssid.to_string().c_str(),Ap.bssid.to_string().c_str());
        config.set_filter(command);
        config.set_rfmon(true);
	Sniffer sniffer(this->IfaceName, config);
	sniffer.sniff_loop(make_sniffer_handler(this, &EAPOLSniffer::callback));
	cout << endl << "[+] All EAPOL KEY Captured! / " << key.device << endl;
	cout << "[-] Stop EAPSniffer.." << endl;

	Generate_PMK();
	Generate_PTK();
	return this->key;
}

bool EAPOLSniffer::callback(PDU& pdu) {
	if(key.Anonce[0] != 0x00 && key.Snonce[0] != 0x00)
		return false;
	const RSNEAPOL eapol = pdu.rfind_pdu<RSNEAPOL>();
    const Dot11Data data = pdu.rfind_pdu<Dot11Data>();
	if(this->key.is_activated == OFF){
		if(data.src_addr() == Ap.bssid){
			this->key.device = data.dst_addr();
		}
		else{
            this->key.device = data.src_addr();
		}
		this->key.is_activated = ON;
	}
	if(eapol.nonce()[0] != 0x00){
		if(data.src_addr() == Ap.bssid)
			memcpy(this->key.Anonce, eapol.nonce(), 32);
        	else
			memcpy(this->key.Snonce, eapol.nonce() ,32);
	}
	return true;
}

template<typename InputIterator1, typename InputIterator2, typename OutputIterator>
void xor_range(InputIterator1 src1, InputIterator2 src2, OutputIterator dst, size_t sz) {
    for (size_t i = 0; i < sz; ++i) {
        *dst++ = *src1++ ^ *src2++;
    }
}


class WEPSniffer{
	public:
		WEPSniffer(string InterfaceName, ApInfo Ap, KEY key);
		ApInfo Ap;
		KEY key;
		string iface;
		void run();
	private:
		bool callback(PDU &pdu);
};

WEPSniffer::WEPSniffer(string InterfaceName, ApInfo Ap, KEY key){
	this->iface = InterfaceName;
	this->Ap = Ap;
	this->key = key;
}

void WEPSniffer::run(){
	cout << "[*] Start WEP Data.." <<endl << endl;
	char command[1000];
    SnifferConfiguration config;
    config.set_promisc_mode(true);

	string ap_mac = this->Ap.bssid.to_string();
	string sta_mac = this->key.device.to_string();

	sprintf(command, "type data subtype qos-data and ((wlan addr1 %s or wlan addr2 %s or wlan addr3 %s or wlan addr4 %s) or (wlan addr1 %s or wlan addr2 %s or wlan addr3 %s or wlan addr4 %s))", ap_mac.c_str(), ap_mac.c_str(), ap_mac.c_str(), ap_mac.c_str(), sta_mac.c_str(), sta_mac.c_str(), sta_mac.c_str(), sta_mac.c_str());

	config.set_filter(command);
	config.set_rfmon(true);
	Sniffer sniffer(this->iface, config);
	sniffer.sniff_loop(make_sniffer_handler(this, &WEPSniffer::callback));
}

bool WEPSniffer::callback(PDU& pdu){
	const Dot11QoSData qos = pdu.rfind_pdu<Dot11QoSData>();
	//?????? ?????? ????????
	if(!qos.wep()) return true;
	const RawPDU raw = pdu.rfind_pdu<RawPDU>();
	RawPDU::payload_type pload = raw.payload();
	// PN
	unsigned char PN[6] = {pload[7], pload[6], pload[5], pload[4], pload[1], pload[0]};
	// Counter
	unsigned char counter[16] = {0,};
	counter[0] = 0x01;
	counter[1] = 0x00;
	qos.addr2().copy(counter+2);
	memcpy(counter+8, PN, 6);

	unsigned char cipher_text[16];
	AES_KEY ctx;
	AES_set_encrypt_key(this->key.TK, 128, &ctx);
	//
	size_t total_sz = raw.payload_size() - 16, offset = 8, blocks = (total_sz + 15) / 16;

	for (size_t i = 1; i <= blocks; ++i) {
        	size_t block_sz = (i == blocks) ? (total_sz % 16) : 16;
        	if (block_sz == 0) {
            		block_sz = 16;
        	}
       		counter[14] = (i >> 8) & 0xff;
       		counter[15] = i & 0xff;
        	AES_encrypt(counter, cipher_text, &ctx );
        	xor_range(cipher_text, &pload[offset], &pload[(i - 1) * 16], block_sz);
        	offset += block_sz;
    	}

	SNAP snap(&pload[0], total_sz);
	IP ip = snap.rfind_pdu<IP>();
	TCP tcp = snap.rfind_pdu<TCP>();
	RawPDU data = snap.rfind_pdu<RawPDU>();
	cout << "Src :" <<ip.src_addr() <<":" << tcp.sport()<<" / " <<"Dst :" <<ip.dst_addr() << ":"<< tcp.dport() <<endl;
	RawPDU::payload_type p = data.payload();
	for(int i=0; i<data.payload_size(); i++){
		printf("%c",p[i]);
	}
	cout << endl;
	return true;
}

void get_info(ApInfo* Ap, KEY* key){


        cout << "device " << key->device << endl;
        cout << "ap " << Ap->bssid << endl;
        cout << "Anonce : ";
        for(int i=0; i<32; i++){
                printf("\\x%.2x",key->Anonce[i]);
        }
        cout << endl << "Snonce : ";
        for(int i=0; i<32; i++){
                printf("\\x%.2x",key->Snonce[i]);
        }
        cout << endl << "PMK : ";
        for(int i=0; i<32; i++)
                printf("%.2x ",key->PMK[i]);
		cout << endl << "TK : ";
		for(int i=0; i<16; i++){
                printf("%.2X ", key->TK[i]);
        }
        cout << endl;

        printf("\n");

}

int main(){
	Interface iface;
	iface.find_interface();
	ApScanner scanner(iface.name);
	ApInfo Ap;
	Ap = scanner.run();
	EAPOLSniffer Esniffer(Ap, iface.name);
	KEY key;
	key = Esniffer.CaptureEAPOL();

	get_info(&Ap, &key);
	WEPSniffer w(iface.name, Ap, key);
	w.run();

}
