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
// for ptk
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>
// my code
#include "/home/kim/project_sniffing/real_code/code/apscanner.h"
#include "/home/kim/project_sniffing/real_code/code/interfaceC.h"

using namespace std;

namespace project {
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
		// insert and dequeing Queue
		bool insertQueue(std::shared_ptr<Tins::RawPDU>& shared_ptr);
		bool dequeQueue(std::shared_ptr<Tins::RawPDU>& shared_ptr);
		// generate ptk
		void clearPTK();
		bool generatePmk();
		bool generatePTK();
		// decrypt !!
//		bool decryptDATA(std::shared_ptr<Tins::RawPDU>& shared_ptr);
		bool decryptDATA(std::shared_ptr<Tins::RawPDU>& shared_ptr, Tins::RawPDU::payload_type& pload);
		template<typename InputIterator1, typename InputIterator2, typename OutputIterator>
		void xor_range(InputIterator1 src1, InputIterator2 src2, OutputIterator dst, size_t sz) {
		    for (size_t i = 0; i < sz; ++i) {
		        *dst++ = *src1++ ^ *src2++;
		    }
		}
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
		std::mutex kDecryptedPacketQue;
		std::queue<std::shared_ptr<Tins::RawPDU>> decryptedPacketQue;
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
	// O
	void sig_handler(int signo);
	void set_sig(bool a);
	bool get_sig();
	// init sharing signal variable ;
	// sniffing, distribute, outing thread check this signal
	std::atomic<bool> sigon(false);
	std::mutex ksig;
}
// init All Thread Number;
std::atomic<int> project::Radio_Sniffer::nThread(0);
// exception ; when : all thread throw exception input Exception to this Vector
std::mutex project::Radio_Sniffer::kExceptionVec;
std::vector<std::exception_ptr> project::Radio_Sniffer::exVec;

int main(){
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
	std::cout << "susccess" << '\n';
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
	std::cout << "[Radio_Sniffer] : Terminate Work !" << std::endl;
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
		std::cout << "[Radio_Sniffer]<on> : Not yet setting NetworkInterface" << std::endl;
		return;
	}
	// set Signal !!
	signal(SIGINT, project::sig_handler);
	//
	std::thread t{&project::Radio_Sniffer::setSniffThread,this};
	std::thread t1{&project::Radio_Sniffer::distribute_callback, this};
//	outing_result();
	// Exit Check acquired !!
	std::this_thread::sleep_for(std::chrono::milliseconds(500));
	t.join();
	t1.join();
// last
	std::cout << "program is end" << std::endl;
	signal(SIGINT, SIG_DFL);
}
			/* Sniffing */
void project::Radio_Sniffer::setSniffThread(){
	// get thread's Id and thread's plus self Exception index !!
	int id = project::Radio_Sniffer::plusExcptionNum();
	std::cout << "[Radio_Sniffer::setSniffThread] : id : " << id << std::endl;
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
		std::cerr << "Sniffing Thread Throw Error !! " << std::endl;
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
			std::cout << "packetQue is empty" <<std::endl;
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
						std::cout << "sleep thread wake up !!" << std::endl;
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
						std::cout << "[Authentification] sleep thread wake up !!" << std::endl;
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
			std::cout << "[StartWoring] Throw Exception : " << e.what() << std::endl;
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
		// TEST
		try{
			std::ofstream ofs("./sta/" + this->staMac + ".txt",std::ofstream::app | std::ofstream::out);
			std::stringstream ss;
			ss << "========================================================================\n";
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
			ss << "\n========================================================================\n";
			ofs << ss.str();
			ofs.close();
			std::cout << ss.str() << std::endl;
			//
		}catch(std::exception& e){
			std::cout << "ofs Exception : " << e.what() << std::endl;
		}
		//

	}
}
//*********************************************************************/

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
