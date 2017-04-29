//
#include "apscanner.h"
//
Ap(std::string& ssid_, Tins::Dot11::address_type& src_hw_, Tins::Dot11::address_type bssid_, uint8_t channel_){
  this->ssid = ssid_;
  this->src_hw = src_hw_;
  this->bssid = bssid_;
  this->channel = channel_;
};
Ap(const Ap& rhs){
  this->ssid = rhs.ssid;
  this->src_hw = rhs.src_hw;
  this->bssid = rhs.bssid;
  this->channel = rhs.channel;
}
Ap::~Ap(){};
bool Ap::operator==(const Ap& rhs){
  if((this->bssid == rhs.bssid)
  &&(this->ssid == rhs.ssid)
  &&(this->src_hw == rhs.src_hw)
&&(this->channel == rhs.channel)){
	return true;
  }
  return false;
}
void Ap::print(){
  std::stringstream ss;
  ss.setf(std::ios::left);
  ss  << "AP : " << std::setw(20)  << ssid;
  ss << " | src Hw : " << src_hw;
  ss << " | bssid : " << bssid;
  std::cout << ss.str() << std::endl;
}
uint8_t Ap::get_channel(){
  return this->channel;
}
//
bool Apscanner::sigon = false;
void Apscanner::set_sig(bool arg){
  Apscanner::sigon = arg;
}
//
Apscanner::Apscanner()
{

}
//
Apscanner::~Apscanner(){
  try{

  }
  catch(...){

  }
}
//
void Apscanner::search_networkInterface()
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
  this->apInterface = netinterfaces[i-1];
  //
}
//
void Apscanner::sniffing(){
  Tins::SnifferConfiguration config;
  config.set_rfmon(true);
  config.set_promisc_mode(true);
  Tins::Sniffer mySniffer(this->apInterface.name(),config);
  mySniffer.sniff_loop(Tins::make_sniffer_handler(this, &Apscanner::scanner_handler));
  if(Apscanner::sigon == true) return;
  // Tests

}
//
bool Apscanner::scanner_handler(Tins::PDU& myPdu){
  try{
    // SIGNAL HANDLER
      if(Apscanner::sigon == true) return false;
    //
      Tins::Dot11Beacon& beacon = myPdu.rfind_pdu<Tins::Dot11Beacon>();
      std::string ssid = beacon.ssid();
      Tins::Dot11::address_type src_hw = beacon.addr2();
      Tins::Dot11::address_type bssid = beacon.addr3();
      uint8_t channal = beacon.ds_parameter_set();
      Ap myAp(ssid,src_hw,bssid,channal);
      //
      std::vector<Ap>::iterator vi;
      bool check = false;
      for(vi = this->apVec.begin(); vi != this->apVec.end(); vi++){
        if(*vi == myAp) return true;
      }
      //
      std::cout << "------------------------------------" << '\n';
      std::cout << "AP : " << ssid << std::endl;
      std::cout << "src Hw : " << src_hw << std::endl;
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
void Apscanner::on(){
  //
  this->serach_networkInterface();
  //
  signal(SIGINT, Apscanner::sig_handler);
  std::thread th1 = std::thread([&](){this->sniffing();});
  // channel change and wait signal 'ctrl-l'
  std::stringstream os1;
  int i = 1;;
  while(1){
    os1.str(std::string(""));
    os1 << "iwconfig " << this->apInterface.name() << " channel " << i++;
    system(os1.str().c_str());
    std::cout << "<<< channel changed !! >>>" << '\n';
    sleep(3);
    if(Apscanner::sigon == true) break;
    i = ((i = i%14) == 0 ? 1 : i);
  }
  //
  th1.join();
  signal(SIGINT, SIG_DFL);
  //
  i=1;
  std::vector<Ap>::iterator itA;
  system("clear");
  for(itA = this->apVec.begin(); itA != this->apVec.end(); itA++){
      std::cout << std::setw(2)<< i++ << " | ";
      itA->print();
  }
}
//
void Apscanner::sig_handler(int signo){
  std::cout << "accept ctrl-l signal !!" << std::endl;
  Apscanner::set_sig(true);
}
//
void Apscanner::select_ap(){
  // insert !!
  int i;
  uint8_t channel;
  std::stringstream ss;
  while(1){
    std::cout << "채널을 선택해주세요 : ";
    std::cin >> i;
    if((i > this->apVec.size())||(i<1)){
        std::cout << "잘못된 채널을 입력하셨습니다. 다시 입력하세요. !" << std::endl;
    }else {
        channel = this->apVec[i-1].get_channel();
        this->apVec[i-1].print();
        ss << "iwconfig " << this->apInterface.name() << " channel " << (unsigned int)channel;
        std::cout << ss.str() << std::endl;
        system(ss.str().c_str());
        std::cout << "성공적으로 AP를 선택하였습니다. !!";
        this->channelInfo = channel;
        return;
    }
  }
  //

}
