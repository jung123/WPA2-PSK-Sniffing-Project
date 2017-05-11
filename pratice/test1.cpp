#include <iostream>
#include <iomanip>
#include <thread>
#include <mutex>
#include <string>
#include <condition_variable>
#include <cstdarg>
#include <atomic>
#include <chrono>
#include <vector>
#include <fstream>

#define NUM 10
using namespace std;

mutex mu;
atomic<int> threadNum;
vector<uint32_t> myVector;
condition_variable cv;

void thread1(uint32_t id);
void thread2(uint32_t id);

int main(){
	cout << "test1 program !!" << endl;
	thread t[NUM];
	uint32_t i = 0;
	threadNum = 0;
	//
	for(i=0;i<NUM;i++) t[i] = thread(thread1, i);
	thread t2(thread2, i);
	//
	for(i=0;i<NUM;i++) t[i].join();
	t2.join();

	return 0;
}
void thread1(uint32_t id){
	cout << "thread "<< id <<" start !!" << endl;
	//
	uint32_t val = id*1000, i=0;
	unique_lock<std::mutex> lck(mu, defer_lock_t());
	while(true){
		cout << id << ". thread " << i+1 << "번째 시도입니다." << endl;
		lck.try_lock();
		if(!lck.owns_lock()){
			i++;
			std::this_thread::sleep_for(chrono::milliseconds(1000));
			continue;
		}
		cout << id << ". thread get Mutex !!" << endl;
		threadNum++;
		for(uint32_t val = id * 100; val < (id*100)+100; val++){
			myVector.push_back(val);
		}
		//
		lck.unlock();
		cv.notify_one();
		break;
	}
	//
	cout << "thread " << id << " end !!" << endl;
	return;
}
void thread2(uint32_t id){
	cout << "Output Thread start !!" << endl;
	//
	ofstream ofs("test1_file");
	unique_lock<std::mutex> lck(mu);
	//
	uint32_t i =0;
	while(true){
		cv.wait(lck,[&lck](){
			if(lck.owns_lock() == true || threadNum == NUM) return true;
			cout << "Output Thread wake up predkit !!" << endl;
			return false;
		});
		cout << "Output Thread Get Mutex !! " << endl;
		//
		if(threadNum == NUM) break;
		ofs << "\n------------------------------------------" << endl;
		i = 0;
		for(auto&t : myVector){
			ofs << " " << t;
			if(++i % 10 == 0) ofs << endl;
		}
		ofs << "\n------------------------------------------" << endl;
		lck.unlock();
		cv.notify_one();
	}
	//
	cout << "Output Thread end !!" << endl;
	return;
}












