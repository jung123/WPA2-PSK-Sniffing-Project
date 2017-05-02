#include <iostream>
#include <string>

using namespace std;

int main(){
	string test = string("qweqweqwe");
	int loc = test.find('a');
	if(loc == std::string::npos) std::cout << "???\n";
	cout << "loc : " << loc << std::endl;
	cout << "TEST : " << std::string::npos << std::endl;
	return 0;
}
