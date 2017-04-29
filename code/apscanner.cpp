#include <iostream>
#include <iomanip>
#include <string>
#include <tins/tins.h>
#include <vector>
#include <unistd.h>
#include <pthread.h>
#include <thread>
#include <mutex>
#include <sstream>
#include <sys/types.h>
#include <csignal>
//
#include "apscanner.h"
#include "interfaceC.h"
//
project::Ap::Ap(std::string& ssid_, Tins::Dot11::address_type bssid_, uint32_t channel_, std::string& psk_){
  this->ssid = ssid_;
  this->bssid = bssid_;
  this->channel = channel_;
  this->psk = psk_;
};
project::Ap::Ap(std::string& ssid_, Tins::Dot11::address_type bssid_, uint32_t channel_){
  this->ssid = ssid_;
  this->bssid = bssid_;
  this->channel = channel_;
};
project::Ap::Ap(const Ap& rhs){
  this->ssid = rhs.ssid;
  this->bssid = rhs.bssid;
  this->channel = rhs.channel;
  this->psk = rhs.psk;
}
project::Ap::~Ap(){};
bool project::Ap::operator==(const Ap& rhs){
  if((this->bssid == rhs.bssid)
  &&(this->ssid == rhs.ssid)
&&(this->channel == rhs.channel)
&&(this->psk == rhs.psk)){
	return true;
  }
  return false;
}
std::string project::Ap::getPsk(){
	return this->psk;
}
project::Ap& project::Ap::operator=(project::Ap rhs){
	this->ssid = rhs.ssid;
    this->bssid = rhs.bssid;
    this->channel = rhs.channel;
	this->psk = rhs.psk;
}
void project::Ap::print(){
  std::stringstream ss;
  ss.setf(std::ios::left);
  ss  << "AP : " << std::setw(20)  << ssid;
  ss << " | bssid : " << bssid;
  ss << " | channel : " << channel;
  std::cout << ss.str() << std::endl;
}
uint32_t project::Ap::get_channel(){
  return this->channel;
}
std::string project::Ap::getSSid(){
	return this->ssid;
}
Tins::Dot11::address_type project::Ap::getBssid(){
	return this->bssid;
}
void project::Ap::setPsk(std::string& str_){
	this->psk = str_;
}
//
project::Apscanner::Apscanner()
{
}
//
bool project::Apscanner::apsigon = false;
void project::Apscanner::set_sig(bool arg){
  project::Apscanner::apsigon = arg;
}
//
project::Apscanner::~Apscanner(){
  try{

  }
  catch(...){

  }
}
//
void project::Apscanner::search_networkInterface()
{
  std::vector<Tins::NetworkInterface> netinterfaces = Tins::NetworkInterface::all();
  Tins::NetworkInterface::Info deviceInfo;
  std::vector<Tins::NetworkInterface>::iterator vIterator;
  int i = 0;
  std::cout << "<< select Network Interface >>" << '\n';
  for(vIterator = netinterfaces.begin(); vIterator != netinterfaces.end(); vIterator++){
    deviceInfo = vIterator->info();
    std::cout << "-------------" << ++i << "-------------" << std::endl;
    std::cout << " Device : " << vIterator->name() << '\n';
    std::cout << "Address : " << deviceInfo.ip_addr.to_string() << std::endl;
    std::cout << "NetMask : " << deviceInfo.netmask.to_string() << std::endl;
    std::cout << "HW Addr : " << deviceInfo.hw_addr.to_string() << std::endl;
  }
  //
  int j;
  while(1){
    std::cout << "your Interface Number : ";
    std::cin >> j;
    if(!(j <= 0 || j > i+1)) break;
    std::cout << "Wrong Input !!" << std::endl;
  }
  //
  this->selectedInterface.set(netinterfaces[j-1]);
  //
}
//
void project::Apscanner::sniffing(){
  Tins::SnifferConfiguration config;
  config.set_rfmon(true);
  config.set_promisc_mode(true);
  Tins::Sniffer mySniffer(this->selectedInterface.getInterfaceName(),config);
  mySniffer.sniff_loop(Tins::make_sniffer_handler(this, &project::Apscanner::scanner_handler));
  if(project::Apscanner::apsigon == true) return;
  // Tests

}
//
bool project::Apscanner::scanner_handler(Tins::PDU& myPdu){
  try{
    // SIGNAL HANDLER
      if(project::Apscanner::apsigon == true) return false;
    //
      Tins::Dot11Beacon& beacon = myPdu.rfind_pdu<Tins::Dot11Beacon>();

      std::string ssid = beacon.ssid();
	  if(ssid.empty()) return true;
      Tins::Dot11::address_type bssid = beacon.addr3();
      uint32_t channel = (uint32_t)beacon.ds_parameter_set();
      project::Ap myAp(ssid,bssid,channel);
      //
      std::vector<project::Ap>::iterator vi;
      bool check = false;
      for(vi = this->apVec.begin(); vi != this->apVec.end(); vi++){
        if(*vi == myAp) return true;
      }
      //
      std::cout << "------------------------------------" << '\n';
      std::cout << "AP : " << ssid << std::endl;
      std::cout << "bssid : " << bssid << std::endl;
      std::cout << "------------------------------------" << '\n';
      this->apVec.push_back(myAp);
  }
  catch(Tins::pdu_not_found& exPduNF){
    //std::cout << "[Exception]<Apscanner>.scanner_handler : pdu not found" << std::endl;
    //std::cout << exPduNF.what() << '\n';
  }
  return true;
}
//
void project::Apscanner::on(){
  //
  this->search_networkInterface();
  //
  signal(SIGINT, Apscanner::sig_handler);
  std::thread th1 = std::thread([&](){this->sniffing();});
  // channel change and wait signal 'ctrl-l'
  std::stringstream os1;
  int i = 0;;
  system("clear");
  while(1){
    os1.str(std::string(""));
	i++;
	if(i < 9 && i > 0){
		os1 << "iw dev " << this->selectedInterface.getInterfaceName() << " set channel " << i << " ht40+";
	}else if(i < 14 && i > 8){
		os1 << "iw dev " << this->selectedInterface.getInterfaceName() << " set channel " << i << " ht40-";
	}
    system(os1.str().c_str());
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    if(project::Apscanner::apsigon == true) break;
    i = ((i = i%14) == 0 ? 0 : i);
  }
  //
  th1.join();
  signal(SIGINT, SIG_DFL);
  //
  i=1;
  std::vector<project::Ap>::iterator itA;
  system("clear");
  for(itA = this->apVec.begin(); itA != this->apVec.end(); itA++){
      std::cout << std::setw(2)<< i++ << " | ";
      itA->print();
  }
}
//
void project::Apscanner::sig_handler(int signo){
  std::cout << "accept ctrl-l signal !!" << std::endl;
  project::Apscanner::set_sig(true);
}
//
project::Ap project::Apscanner::select_ap(){
  // insert !!
  int i;
  uint32_t channel;
  std::stringstream ss;
  std::cout << "\n---------------------------------------------" << std::endl;
  while(1){
    std::cout << "AP를 선택해주세요 : ";
    std::cin >> i;
    if((i > this->apVec.size())||(i<1)){
        std::cout << "입력이 잘못되었습니다. !" << std::endl;
    }else {
        channel = this->apVec[i-1].get_channel();
        this->apVec[i-1].print();
		if(channel > 0 && channel < 10){
			ss << "iw dev " << this->selectedInterface.getInterfaceName() << " set channel " << channel << " ht40+";
		}else if(channel > 9 && channel < 14){
			ss << "iw dev " << this->selectedInterface.getInterfaceName() << " set channel " << channel << " ht40-";
		}
        std::cout << ss.str() << std::endl;

		/////////////////////////////////////////////////////////////////////////////////////////////
		std::stringstream setMode;
		setMode << "ifconfig " << this->selectedInterface.getInterfaceName() << " down";
		system(setMode.str().c_str());
		setMode.str(std::string());
		setMode << "iwconfig " << this->selectedInterface.getInterfaceName() << " mode monitor";
		try{
			system(setMode.str().c_str());
		}catch(std::exception& e){
			std::cout << "[Apscanner::select_ap] throw exception : " << e.what() <<std::endl;
		}
		setMode.str(std::string());
		setMode << "ifconfig " << this->selectedInterface.getInterfaceName() << " up";
		system(setMode.str().c_str());
		setMode.str(std::string());
		///////////////////////////////////////////////
		system(ss.str().c_str());
        std::cout << "성공적으로 AP를 선택하였습니다. !!" << std::endl;
		///////////////////////////////////////////////
		setMode << "ifconfig " << this->selectedInterface.getInterfaceName() << " down";
		system(setMode.str().c_str());
		setMode.str(std::string());
		setMode << "iwconfig " << this->selectedInterface.getInterfaceName() << " mode managed";
		try{
			system(setMode.str().c_str());
		}catch(std::exception& e){
			std::cout << "[Apscanner::select_ap] throw exception : " << e.what() <<std::endl;
		}
		setMode.str(std::string());
		setMode << "ifconfig " << this->selectedInterface.getInterfaceName() << " up";
		system(setMode.str().c_str());
		/////////////////////////////////////////////////////////////////////////////////////////////

        this->channelInfo = channel;
		this->selectedAp = this->apVec[i-1];
		{
			// input psk
			std::string tmp;
			bool check = true;
			uint32_t check1 = 0;
			while(check){
				std::cout << "input password !\n password : ";
				std::cin >> tmp;
				std::cout << "password is " << tmp << std::endl;
				std::cout << "yes : 0 no : 1" << std::endl;
				std::cin >> check1;
				check = (check1 == 0 ? false : true);
			}
			std::cout << "psk : " << tmp << std::endl;
			this->selectedAp.setPsk(tmp);
		}
		std::cout << "---------------------------------------------\n" << std::endl;
        return this->selectedAp;
    }
  }
}
 project::Interface project::Apscanner::getInterface(){
	 return this->selectedInterface;
 }
