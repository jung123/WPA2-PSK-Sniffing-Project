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
		// destructor
		// getter or setter
		std::string getSSid();
		std::string getPsk();
		uint32_t getThreadId();
		void setPsk(std::string& str_);
		void setSSid(std::string& str_);
		// member function
		void settedThread();
		void startWorking();
		bool join();
		// insert and dequeing Queue
		bool insertQueue(std::shared_ptr<Tins::RawPDU>& shared_ptr);
		bool dequeQueue(std::shared_ptr<Tins::RawPDU>& shared_ptr);

		private :
		uint32_t id;
		std::string ssid;
		std::string psk;
		bool checkPMK;
		//
		thread t;
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
		std::string compileSyntax;
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
	//std::cout << "[TEST] packet queue insert !!" << std::endl;
	std::unique_lock<std::mutex> lck(this->kPacketQue);
	this->packetQue.push(std::shared_ptr<Tins::RawPDU>(new Tins::RawPDU(vec.cbegin(),vec.cend())));
}
bool project::Radio_Sniffer::packetQueDeque(std::shared_ptr<Tins::RawPDU>& lptmp){
	std::unique_lock<std::mutex> lck(this->kPacketQue);
	if(this->packetQue.size() == 0) return false;
	lptmp = this->packetQue.front();
	this->packetQue.pop();
	return true;
}
// contructor
project::Radio_Sniffer::Radio_Sniffer(){}
project::Radio_Sniffer::Radio_Sniffer(project::Interface& inte){
	this->mInterface = inte;
}
project::Radio_Sniffer::Radio_Sniffer(project::Interface& inte, project::Ap& targetAp_){
	this->mInterface = inte;
	this->targetAp = targetAp_;
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
		if(this->compileSyntax.length() != 0){
			syntax << " and " << this->compileSyntax;
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
	// TEST
	std::cout << "Sniffing Thread is Over !!" << endl;
}
// lootins !!
bool project::Radio_Sniffer::mySniffingCallback(Tins::PDU& myPdu){
	// signal
	if(project::get_sig() == true) return false;
	// raw pdu for copy
	Tins::RawPDU raw = myPdu.rfind_pdu<Tins::RawPDU>();
	int packetSize = raw.size();
	std::vector<uint8_t>& tmpVec = raw.payload();
	// Create RadioTap
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
	Tins::PDU::PDUType typeData = Tins::Dot11Data::pdu_flag;
	Tins::PDU::PDUType typeManage = Tins::Dot11ManagementFrame::pdu_flag;
	Tins::PDU::PDUType typeControl = Tins::Dot11Control::pdu_flag;
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
		Tins::RawPDU *lpRawPdu = tmpPtr.get();
		Tins::Dot11 *lpDot11 = lpRawPdu->to<Tins::RadioTap>().find_pdu<Tins::Dot11>();
		std::string targetStr = this->targetAp.getBssid().to_string();
		std::string staStr;
		// get Sta Addr
		Tins::Dot11Data *lpDotData = 0;
		Tins::Dot11ManagementFrame *lpDotManage = 0;
		Tins::Dot11Control *lpDotControl = 0;
		lpDotData = lpRawPdu->to<Tins::RadioTap>().find_pdu<Tins::Dot11Data>();
		lpDotManage = lpRawPdu->to<Tins::RadioTap>().find_pdu<Tins::Dot11ManagementFrame>();
		lpDotControl = lpRawPdu->to<Tins::RadioTap>().find_pdu<Tins::Dot11Control>();

		if(!(lpDotData == 0)){
			std::string add1str = lpDotData->addr1().to_string();
			std::string add2str = lpDotData->addr2().to_string();
			std::string add3str = lpDotData->addr3().to_string();
			std::string add4str = lpDotData->addr4().to_string();

			std::string eodeod = "00:00:00:00:00:00";
			if((add1str != targetStr)and(add1str != eodeod)) staStr = add1str;
			else if((add2str != targetStr)and(add2str != eodeod)) staStr = add2str;
			else if((add3str != targetStr)and(add3str != eodeod)) staStr = add3str;
			else if((add4str != targetStr)and(add4str != eodeod)) staStr = add4str;
		}
		else if(!(lpDotManage == 0)){
			std::string add1str = lpDotManage->addr1().to_string();
			std::string add2str = lpDotManage->addr2().to_string();
			std::string add3str = lpDotManage->addr3().to_string();
			std::string add4str = lpDotManage->addr4().to_string();

			std::string eodeod = "00:00:00:00:00:00";
			if((add1str != targetStr)and(add1str != eodeod)) staStr = add1str;
			else if((add2str != targetStr)and(add2str != eodeod)) staStr = add2str;
			else if((add3str != targetStr)and(add3str != eodeod)) staStr = add3str;
			else if((add4str != targetStr)and(add4str != eodeod)) staStr = add4str;
		}else if(!(lpDotControl == 0)) continue;
		//
		std::cout << "STA SSid : " << staStr << std::endl;
		check = false;
		std::shared_ptr<project::Sta> tmpSta;
		uint32_t i = 0;
		for(i=0;i<this->mStaVec.size();i++){
			if(this->mStaVec[i].get()->getSSid() == staStr){
				tmpSta = this->mStaVec[i];
				check = true;
				break;
			}
		}
		// STA Create !!
		if(check == false){
			this->mStaVec.push_back(std::shared_ptr<project::Sta>(new project::Sta()));
			tmpSta = this->mStaVec[this->mStaVec.size()-1];
			std::string tmptmp = this->targetAp.getPsk();
			tmpSta->setPsk(tmptmp);
			tmpSta->setSSid(staStr);
			tmpSta->settedThread(); // Thread Start !!
		}
		// work copy
		tmpSta->insertQueue(tmpPtr);
	}
	// STA Thread Exit Waiting !!
	for(auto& t : this->mStaVec){
		t.get()->join();
		std::cout << "Thread Id : " << t->getThreadId() << " is End" << std::endl;
	}
}
// setter or getter
void project::Radio_Sniffer::set_NetworkInterface(project::Interface& inte){
	this->mInterface = inte;
}
std::string project::Radio_Sniffer::get_deviceName(){
	return this->mInterface.getInterfaceName();
}

//*********************************************************************/

//************************** Sta *************************************
// contructor
project::Sta::Sta(){
	this->ssid = "";
	this-> psk = "";
	this->id = 0;
	this->checkPMK =false;
}
// setter or gettter
void project::Sta::setSSid(std::string& str_){
	this->ssid = str_;
}
void project::Sta::setPsk(std::string& str_){
	this->psk = str_;
}
std::string project::Sta::getSSid(){
	return this->ssid;
}
std::string project::Sta::getPsk(){
	return this->psk;
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
	if(this->encryptedPacketQue.empty()) return false;
	shared_ptr_ = this->encryptedPacketQue.front();
	this->encryptedPacketQue.pop();
	return true;
}
// member function
void project::Sta::settedThread(){
	std::cout << "settedThread Start !! " << std::endl;
	this->t = std::thread(&project::Sta::startWorking,this);
}
bool project::Sta::join(){
	this->t.join();
	return true;
}
void project::Sta::startWorking(){
	// thread ID create
	this->id = project::Radio_Sniffer::plusExcptionNum();
	std::cout << "[project::Sta::startWorking]<" << this->ssid << "> : id : " << this->id << " psk : " << this->getPsk() << std::endl;
	// Start Work !!
	while(true){
		// check signal !!
		if(project::get_sig() == true) break;;
		// Encrypted Data Get !!
		std::shared_ptr<Tins::RawPDU> tmpPtr;
		if(!this->dequeQueue(tmpPtr)){
			std::cout << "[" << this->ssid << ", id : " << this->id << "] Encrypted Data Queue is empty" << std::endl;
			std::this_thread::sleep_for(std::chrono::milliseconds(10000));
			continue;
		}
		Tins::RawPDU *lpRaw = tmpPtr.get();
		std::vector<uint8_t> tmpVec = lpRaw->payload();
		// TEST
		std::ofstream ofs(this->ssid + ".txt",std::ofstream::app | std::ofstream::out);
		std::stringstream ss;
		ss << "\n-----------------------------------" << std::endl;
		ss << "ssid : " << this->ssid << std::endl;
		for(auto& t : tmpVec){
			ss << (char)t;
		}
		ss << "\n-----------------------------------" << std::endl;
		ofs << ss.str();
		ofs.close();
		//
	}
}
//*********************************************************************/
