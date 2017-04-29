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
		std::string getMAC();
		std::string getPsk();
		uint32_t getThreadId();
		uint8_t getThreadState();
		void setPsk(std::string& str_);
		void setMAC(std::string& str_);
		// member function
		void settedThread();
		void startWorking();
		bool join();
		// insert and dequeing Queue
		bool insertQueue(std::shared_ptr<Tins::RawPDU>& shared_ptr);
		bool dequeQueue(std::shared_ptr<Tins::RawPDU>& shared_ptr);

		private :
		uint32_t id;
		std::string mac;
		std::string psk;
		bool checkPTK;
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
		std::string targetStr = this->targetAp.getBssid().to_string();
		std::string staStr = "";
		std::shared_ptr<project::Sta> tmpSta;
		// get Sta Addr
		Tins::Dot11Data *lpDotData = 0;
		Tins::Dot11ManagementFrame *lpDotManage = 0;
		Tins::Dot11QoSData *lpDotQos = 0;
		Tins::Dot11Control *lpDotControl = 0;
		try{
			lpDotControl = tmpPtr->to<Tins::RadioTap>().find_pdu<Tins::Dot11Control>();
			lpDotData = tmpPtr->to<Tins::RadioTap>().find_pdu<Tins::Dot11Data>();
			lpDotManage = tmpPtr->to<Tins::RadioTap>().find_pdu<Tins::Dot11ManagementFrame>();
			lpDotQos = tmpPtr->to<Tins::RadioTap>().find_pdu<Tins::Dot11QoSData>();
		}catch(std::exception& e){
			std::cout << "[Radio_Sniffer::distribute_callback] : find_pdu<>() throw Exception !!" << std::endl;
			std::cout << e.what() << std::endl;
		}

		if(!(lpDotQos == 0)){
			std::cout << "QOS !!" << std::endl;
			// Qos Only create Sta
			// get Sta MAC
			std::string add1str = lpDotData->dst_addr().to_string();
			std::string add2str = lpDotData->src_addr().to_string();
			// ipv4 multicast mac handle
			if((add1str.substr(0, 9) == ipv4mcastStr1)
			 || (add1str.substr(0,6) == ipv4mcastStr2)) continue;
			//	str Mac Detect !!
			if(add1str == targetStr) staStr = add2str;
			else staStr = add1str;
			//
			check = false;
			// existing STA finding
			for(uint32_t i=0;i<this->mStaVec.size();i++){
				if(this->mStaVec[i]->getMAC() == staStr){
					tmpSta = this->mStaVec[i];
					uint8_t threadState = tmpSta->getThreadState();
					if(threadState == 2){
						std::cout << "sleep thread wake up !!" << std::endl;
						tmpSta->settedThread();
					}
					check = true;
					break;
				}
			}
			// STA Create !!
			if(check == false){
				this->mStaVec.push_back(std::shared_ptr<project::Sta>(new project::Sta()));
				tmpSta = this->mStaVec[this->mStaVec.size()-1];
				std::string tmptmp = this->targetAp.getPsk();
				std::cout << tmptmp << std::endl;
				tmpSta->setPsk(tmptmp);
				tmpSta->setMAC(staStr);
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
			std::cout << "Manage STA : " << staStr << std::endl;
			//
			for(uint32_t i=0;i<this->mStaVec.size();i++){
				if(this->mStaVec[i]->getMAC() == staStr){
					tmpSta = this->mStaVec[i];
					uint8_t threadState = tmpSta->getThreadState();
					if(threadState == 2) tmpSta->settedThread();
					check = true;
					break;
				}
			}

		}
		else if(!(lpDotData == 0)){
			std::cout << "Data packet Get !!" << std::endl;
			continue;
		}
		else if(!(lpDotControl == 0)){
			std::cout << "control pacekt !!" << std::endl;
			continue;
		}
		else continue;
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
void project::Radio_Sniffer::setTargetMacAddress(std::string& str_){
	this->targetMacAddress = str_;
}

//*********************************************************************/

//************************** Sta *************************************
// contructor
project::Sta::Sta(){
	this->mac = "";
	this-> psk = "";
	this->countSleep = 0;
	this->threadState = 0;
	this->id = 0;
	this->checkPTK =false;
}
// setter or gettter
void project::Sta::setMAC(std::string& str_){
	this->mac = str_;
}
void project::Sta::setPsk(std::string& str_){
	this->psk = str_;
}
std::string project::Sta::getMAC(){
	return this->mac;
}
std::string project::Sta::getPsk(){
	return this->psk;
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
	if(this->encryptedPacketQue.empty()) return false;
	shared_ptr_ = this->encryptedPacketQue.front();
	this->encryptedPacketQue.pop();
	return true;
}
// member function
void project::Sta::settedThread(){
	std::cout << "["<<this->mac <<"]settedThread Start !! " << std::endl;
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
	if(this->id == 0) this->id = project::Radio_Sniffer::plusExcptionNum();
	std::cout << "[project::Sta::startWorking]<" << this->mac << "> : id : " << this->id << " psk : " << this->psk << std::endl;
	// Start Work !!
	while(true){
		// check signal !!
		if(project::get_sig() == true) break;;
		// Encrypted Data Get !!
		std::shared_ptr<Tins::RawPDU> tmpPtr;
		if(!this->dequeQueue(tmpPtr)){
			this->countSleep = this->countSleep + 1;
			if(this->countSleep == 10){
				this->threadState = 2;
				return;
			}
			std::cout << "[" << this->mac << ", id : " << this->id << "] Encrypted Data Queue is empty" << std::endl;
			std::this_thread::sleep_for(std::chrono::milliseconds(5000));
			continue;
		}
		Tins::RawPDU *lpRaw = tmpPtr.get();
		std::vector<uint8_t> tmpVec = lpRaw->payload();
		// TEST

		try{
			std::ofstream ofs(this->mac + ".txt",std::ofstream::app | std::ofstream::out);
			std::stringstream ss;
			ss << "\n-----------------------------------" << std::endl;
			ss << "MAC : " << this->mac << std::endl;
			for(auto& t : tmpVec){
				ss << (char)t;
			}
			ss << "\n-----------------------------------" << std::endl;
			ofs << ss.str();
			ofs.close();
			//
		}catch(std::exception& e){
			std::cout << "ofs Exception : " << e.what() << std::endl;
		}

	}
}
//*********************************************************************/
