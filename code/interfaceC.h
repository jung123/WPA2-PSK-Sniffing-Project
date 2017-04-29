#ifndef PROJECT_INTERFACE_CLASS
#define PROJECT_INTERFACE_CLASS
namespace project{
	class Interface {
		public :
		//
			Interface();
			Interface(std::string& name);
			project::Interface& operator=(project::Interface rhs);
		//
			std::vector<Tins::NetworkInterface> search_networkInterface();
			bool setInterface(std::string& name);
			std::string getInterfaceName();
			bool checkFlag();
			void set(Tins::NetworkInterface& rhs);
			//getter
			Tins::NetworkInterface getInterface();
		private :
			Tins::NetworkInterface itf;
			Tins::NetworkInterface::Info deviceinfo;
			bool flag;
			std::string interfaceName;
	};
}
#endif
