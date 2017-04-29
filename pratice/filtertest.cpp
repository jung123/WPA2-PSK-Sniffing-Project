#include <iostream>
#include <iomanip>
#include <thread>
#include <functional>
#include <condition_variable>
#include <mutex>
#include <string>
#include <sstream>
//
#include <unistd.h>
#include <csignal>
#include <sys/types.h>
#include <tins/tins.h>
//
#include "../code/apscanner.h"

using namespace std;

bool sniffing_callback(Tins::PDU& myPdu);

int main(){
	string interface;
	stringstream ss;

	// Ap Select
	{
		Apscanner myAp;
		myAp.on();
		myAp.select_ap();
		interface = myAp.get_interface();
	}
	cout << interface << endl;

	//
	vector<Tins::NetworkInterface> ifVec;
	int i = 0;
	Tins::NetworkInterface myInterface;
	ifVec = myInterface.all();
	for(auto& t : ifVec){
		++i;
		cout << t.name() << endl;
	}
	cout << "your interface ?" << endl;
	cin >> i;
	interface = ifVec[i].name();
	// configuration
	Tins::SnifferConfiguration config;
	config.set_filter("icmp");
	config.set_rfmon(true);
	//
	Tins::Sniffer sniffer(interface, config);
	sniffer.sniff_loop(sniffing_callback, 0);
 	return 0;
}
bool sniffing_callback(Tins::PDU& myPdu){
	Tins::ICMP myIcmp = myPdu.rfind_pdu<Tins::ICMP>();

	return true;
}
