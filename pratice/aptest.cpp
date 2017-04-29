#include <iostream>
#include <string>
#include <tins/tins.h>
#include <csignal>
#include "../code/apscanner.h"

int main(){
	project::Apscanner test;
	test.on();
	project::Ap myAp = test.select_ap();
	std::cout << "sadasd " << std::endl;
	myAp.print();
	return 0;
}
