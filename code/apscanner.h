#ifndef _APSCANNER_
#define _APSCANNER_
//
#include "interfaceC.h"
namespace project {
	class Ap{
	  public :
	    Ap(){};
	    Ap(std::string& ssid_, Tins::Dot11::address_type bssid_, uint32_t channel_, std::string& psk_);
		Ap(std::string& ssid_, Tins::Dot11::address_type bssid_, uint32_t channel_);
	    Ap(const Ap& rhs);
	    ~Ap();
	    bool operator==(const Ap& rhs);
		project::Ap& operator=(project::Ap rhs);
	    void print();
		std::string getSSid();
		std::string getPsk();
		void setPsk(std::string& str_);
	    uint32_t get_channel();
		Tins::Dot11::address_type getBssid();
	  private :
	    std::string ssid;
	    Tins::Dot11::address_type bssid;
		std::string psk;
		uint32_t channel;
	};
	//
	class Apscanner {
	  public :
	  static bool apsigon;
	  // constructor
	  Apscanner();
	  // destructor
	  ~Apscanner();
	  //  accessor

	  // member funtion
	  void on(); 		// ap스캔을 시작하는 멤버함수 !!
	  void search_networkInterface();	// ap스캔을 시작하기 전에 적절한 네트워크 인터페이스를 찾는 멤버함수이다.
	  bool scanner_handler(Tins::PDU& myPdu);		// ap 스캔을 할 때 callback함수이다 !!
	  project::Ap select_ap();
	  void sniffing();
	  static void sig_handler(int signo);
	  static void set_sig(bool arg);
	  project::Interface getInterface();

	  private :
	  std::vector<project::Ap> apVec;
	  int channelInfo;
	  project::Ap selectedAp;
	  project::Interface selectedInterface;
	};
}
#endif
