
/**
* Basic example of creating a stand alone program linked against Connector/C++
*
* This example is not integrated into the Connector/C++ build environment.
* You must run "make install" prior to following the build instructions
* given here.
*
* To compile the standalone example on Linux try something like:
*
* /usr/bin/c++
*   -o standalone
*   -I/usr/local/include/cppconn/
*   -Wl,-Bdynamic -lmysqlcppconn
*    examples/standalone_example.cpp
*
* To run the example on Linux try something similar to:
*
*  LD_LIBRARY_PATH=/usr/local/lib/ ./standalone
*
* or:
*
*  LD_LIBRARY_PATH=/usr/local/lib/ ./standalone host user password database
*
*/


/* Standard C++ includes */
#include <stdlib.h>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <chrono>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <string>

#include <boost/scoped_ptr.hpp>


/*
  Include directly the different
  headers from cppconn/ and mysql_driver.h + mysql_util.h
  (and mysql_connection.h). This will reduce your build time!
*/
#include "mysql_connection.h"
#include "mysql_driver.h"

#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/prepared_statement.h>

class DB_connection {
	private :
	sql::Driver *driver;
	boost::scoped_ptr< sql::Connection > con;
	boost::scoped_ptr< sql::PreparedStatement > prep_stmt;
	//
	std::string url;
	std::string user;
	std::string password;
	std::string database;
	std::string table;
	//
	public :
	//
	DB_connection(std::string& url_,
					std::string& user_,
					std::string& password_,
					std::string& database_,
					std::string& table_) {
		this->url = url_;
		this->user = user_;
		this->password = password_;
		this->database = database_;
		this->table = table_;
	}
	//
	bool get_driver_instance();
	//
	bool setConnection(std::string& url_, std::string& user_, std::string& pw, std::string& table_);
	bool setConnection();
	//
	bool executeQuery(std::string& ApMac,
		 			std::string& ApSsid,
					std::string& StaMac,
					std::string& HttpRequestHeader,
					std::string& NetIp,
					std::string& NetPort);
	// setter and getter
	bool setUrl(std::string& url_);
	std::string setUrl();
	bool setUser(std::string& user_);
	std::string setUser();
	bool setPassWord(std::string& pw);
	std::string setPassWord();
	bool setDB(std::string& database_);
	std::string setDB();
	bool setTable(std::string& table_);
	std::string setTable();

};

using namespace std;

/**
* Usage example for Driver, Connection, (simple) Statement, ResultSet
*/
int main(int argc, const char **argv)
{
	std::string url("localhost");
	std::string user("capston");
	std::string password("password");
	std::string database("capston_DB");
	std::string table("WSniffer_wsniffer");
	//
	DB_connection dbcon(url, user, password, database, table);
	cout << "db con instance !!\n";
	dbcon.get_driver_instance();
	cout << "dbcon get driver instance !!" << endl;
	if(dbcon.setConnection() == false) {
		cout << "dbcon setConnection() return false !!" << endl;
		return 0;
	}
	cout << "dbcon setConnection()" << endl;
	std::string apmac = "ac:5a:14:07:49:82";
	std::string apssid = "wndgus";
	std::string stamac = "e4:f8:9c:c0:6f:98";
	std::string http = "get http qwjkdqwbnjkdqwnjd qnjkwdnqwjkdnqwjkndqwjkndjkqwd";
	std::string netip = "192.168.0.1";
	std::string netport = "8562";
	if(dbcon.executeQuery(apmac, apssid, stamac, http, netip, netport) == false) {
		cout << "dbcon executeQuery() return false !!" << endl;
		return 0;
	}
	cout << "dbcon executeQuery() !!" << endl;
}


DB_connection::DB_connection(std::string& url_,
				std::string& user_,
				std::string& password_,
				std::string& database_,
				std::string& table_) {
	this->url = url_;
	this->user = user_;
	this->password = password_;
	this->database = database_;
	this->table = table_;
}
//
bool DB_connection::get_driver_instance(){
	try {
		this->driver = sql::mysql::get_driver_instance();
	}catch(sql::SQLException &e) {
		std::cout << "[DB_connection]<DB_connection> Throw Exception : " << e.what() << " (MySQL error code : " << e.getErrorCode() << ", SQLState : " << e.getSQLState() << " )" << std::endl;
		return false;
	}
	return true;
}
//
bool DB_connection::setConnection(std::string& url_, std::string& user_, std::string& pw, std::string& table_) {
	this->url = url_;
	this->user = user_;
	this->password = pw;
	this->table = table_;
	if(setConnection()) return true;
	return false;
}
bool DB_connection::setConnection() {
	try {
		this->con.reset(this->driver->connect(this->url, this->user, this->password));
		if(this->con->isValid() == false) {
			std::cout << "[DB_connection]<setConnection> fail connecting !!" << std::endl;
			return false;
		}
		// set database !!
		this->con->setSchema(this->database);
	}catch(sql::SQLException& e) {
		std::cout << "[DB_connection]<setConnetion> Throw Exception : " << e.what() << " (MySQL error code : " << e.getErrorCode() << ", SQLState : " << e.getSQLState() << " )" << std::endl;
		return false;
	}
	return true;
}
//
bool DB_connection::executeQuery(std::string& ApMac,
	 			std::string& ApSsid,
				std::string& StaMac,
				std::string& HttpRequestHeader,
				std::string& NetIp,
				std::string& NetPort) {
	try{
		this->prep_stmt.reset(this->con->prepareStatement("INSERT INTO " + this->table + "(ApMac, ApSsid, StaMac, Date, HttpRequestHeader, NetIp, NetPort) VALUES (?, ?, ?, ?, ?, ?, ?)"));
	}catch(sql::SQLException& e) {
		std::cout << "[DB_connection]<executeQuery 1> Throw Exception : " << e.what() << " (MySQL error code : " << e.getErrorCode() << ", SQLState : " << e.getSQLState() << " )" << std::endl;
		return false;
	}

	try {

		this->prep_stmt->setString(1, ApMac); //
		this->prep_stmt->setString(2, ApSsid); //
		this->prep_stmt->setString(3, StaMac); //
		//
		std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
		std::time_t now_c = std::chrono::system_clock::to_time_t(now - std::chrono::hours(24));
		std::stringstream tmp;
		tmp << std::put_time(std::localtime(&now_c), "%F %T");
		std::cout << "24 hours ago, the time was " << tmp.str() << '\n';
		//
		this->prep_stmt->setDateTime(4, tmp.str()); //
		this->prep_stmt->setString(5, HttpRequestHeader); //
		this->prep_stmt->setString(6, NetIp); //
		this->prep_stmt->setString(7, NetPort); //
		this->prep_stmt->execute();
	}catch(sql::SQLException& e) {
		std::cout << "[DB_connection]<executeQuery 2> Throw Exception : " << e.what() << " (MySQL error code : " << e.getErrorCode() << ", SQLState : " << e.getSQLState() << " )" << std::endl;
		return false;
	}
	return true;
}
// setter and getter
bool DB_connection::setUrl(std::string& url_) {
	this->url = url_;
	return true;
}
std::string DB_connection::setUrl() {
	return this->url;
}
bool DB_connection::setUser(std::string& user_) {
	this->user = user_;
	return true;
}
std::string DB_connection::setUser() {
	return this->user;
}
bool DB_connection::setPassWord(std::string& pw) {
	this->password = pw;
	return true;
}
std::string DB_connection::setPassWord() {
	return this->password;
}
bool DB_connection::setDB(std::string& database_) {
	this->database = database_;
	return true;
}
std::string DB_connection::setDB() {
	return this->database;
}
bool DB_connection::setTable(std::string& table_) {
	this->table = table_;
	return true;
}
std::string DB_connection::setTable() {
	return this->table;
}
