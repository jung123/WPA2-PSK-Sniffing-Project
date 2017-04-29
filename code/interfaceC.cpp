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
//
#include "interfaceC.h"
//
//************************** Interface *************************************
//
project::Interface::Interface()
:flag(false){}
project::Interface::Interface(std::string& name){
	try{
		this->itf = Tins::NetworkInterface(name);
	}catch(std::exception& e){
		std::cout << "[Interface()] : " << e.what() << std::endl;
	}
	this->deviceinfo = this->itf.info();
	this->flag = true;
}
//
std::vector<Tins::NetworkInterface> project::Interface::search_networkInterface(){
	std::vector<Tins::NetworkInterface> netV;
	netV = Tins::NetworkInterface::all();
	/* print
	for(auto& t : netV){
		cout << t.name() << endl;
	}
	*/
	return netV;
}
bool project::Interface::setInterface(std::string& name){
	std::vector<Tins::NetworkInterface> netV;
	netV = this->search_networkInterface();
	for(auto& t : netV){
		if(name == t.name()){
			this->itf = Tins::NetworkInterface(name);
			this->deviceinfo = this->itf.info();
			this->flag = true;
			return true;
		}
	}
	return false;
}
std::string project::Interface::getInterfaceName(){
	if(!this->flag) return std::string("Not yet NetworkInterface");
	return this->interfaceName;
}
bool project::Interface::checkFlag(){
	if(this->flag) return true;
	else return false;
}
void project::Interface::set(Tins::NetworkInterface& rhs){
	this->itf = rhs;
	this->deviceinfo = rhs.info();
	this->flag = true;
	this->interfaceName = rhs.name();
	//
}
Tins::NetworkInterface project::Interface::getInterface(){
	return this->itf;
}
project::Interface& project::Interface::operator=(project::Interface rhs){
	this->itf = rhs.itf;
	this->deviceinfo = rhs.deviceinfo;
	this->flag = rhs.flag;
	this->interfaceName = this->itf.name();
}
//*************************************************************************/
