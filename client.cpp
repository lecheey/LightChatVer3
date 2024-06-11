#include <iostream>
#include <unistd.h> // вызовы linux/bsd
#include <string.h>
#include <cstring>
#include <sys/socket.h> // сокет
#include <netinet/in.h> // IP
#include <arpa/inet.h>
#include <sys/time.h>
#include <algorithm>
#include <fstream>
#include <filesystem>
#include "client.h"

#define CODE_LENGTH 3
#define COMMAND_LENGTH 6
#define SUCCESS "801"
#define ERROR_AUTH "802"
#define ERROR_NOTFOUND "803"
#define ERROR_OCCUPIED "804"
#define ERROR_SYMBOLS "805"
#define ERROR_MESSAGE "Ошибка"
#define END "END"
#define RETURN "000"
#define QUIT "000"

#define MESSAGE_LENGTH 1024
#define PORT 7777
#define SERVER_IP "127.0.0.1"

int sockd, bind_stat, connection_stat, connection;
struct sockaddr_in serveraddress, clientaddress;
socklen_t length;
char message[MESSAGE_LENGTH];
int _receiver;

namespace fs = std::filesystem; 

void Client::clientRuntime(){
	clientConnect();

	if(connection == -1){
		serverStartup();
		_clienttype = "serv";
		_receiver = connection;
	}
	else{
		_clienttype = "cli";
		_receiver = sockd;
	}
 	while(true){
		std::cout << "Главное меню\n1 - регистрация 2 - вход q - выход: ";
		char choice;
		std::cin >> choice;
		
		if(choice == 'q'){
			break;
		}		
		
		switch(choice){
			case '1':
				userCreate();
				break;
			case '2':
				if(userLogin()){
					if(_clienttype == "cli"){
						getUserList(_username);
						bzero(message, sizeof(message));
						recv(_receiver, message, MESSAGE_LENGTH, 0);
						sendUserList(sockd, message);
					}
					else if(_clienttype == "serv"){
						bzero(message, sizeof(message));
						recv(_receiver, message, MESSAGE_LENGTH, 0);
						sendUserList(_receiver, message);
						getUserList(_username);
					}
					userRuntime(_username);
				}
				break;
			default:
				std::cout << "Неверное значение\n";
				break;
		}
	}
	close(sockd);
}

void Client::serverStartup(){
	std::cout << "Переход в режим ожидания подключений...";

	sockd = socket(AF_INET, SOCK_STREAM, 0);
	if(sockd == -1){
		std::cout << ERROR_MESSAGE << "\nСокет не был создан" << std::endl;
		exit(1);
	}
	
	serveraddress.sin_addr.s_addr = INADDR_ANY;
	serveraddress.sin_port = htons(PORT);
	serveraddress.sin_family = AF_INET;
	bind_stat = bind(sockd, (struct sockaddr*)&serveraddress, sizeof(serveraddress));
	if(bind_stat == -1){
		std::cout << ERROR_MESSAGE << ": Socket binding failed!" << std::endl;
		exit(1);
	}

	connection_stat = listen(sockd, 5);
	if(connection_stat == -1){
		std::cout << ERROR_MESSAGE << ": Socket is unable to listen for connection!" << std::endl;
		exit(1);
	}
	else{
		std::cout << "успешно\nОжидание подключения..." << std::endl;
	}
	
	length = sizeof(clientaddress);
	connection = accept(sockd, (struct sockaddr*)&clientaddress, &length);
	if(connection == -1)  {
		cout << "Server is unable to accept the data from client.!" << endl;
		exit(1);
	}
	else{
		cout << "новое соединение" << endl;
	}
}

void Client::clientConnect(){
	std::cout << "Поиск сервера...";

	sockd = socket(AF_INET, SOCK_STREAM, 0);
	if(sockd == -1){
		std::cout << ERROR_MESSAGE << "\nСокет не был создан" << std::endl;
		exit(1);
	}

	serveraddress.sin_addr.s_addr = inet_addr(SERVER_IP);
	serveraddress.sin_port = htons(PORT);
	serveraddress.sin_family = AF_INET;

	connection = connect(sockd, (struct sockaddr*)&serveraddress, sizeof(serveraddress));
	if(connection == -1){
		std::cout << ERROR_MESSAGE << "\nНет доступных серверов" << std::endl;
	}
	else{
		std::cout << "успешно" << std::endl;
	}
}

void Client::userCreate(){
	systemClear();
	std::cout << "Создание нового пользователя..." << std::endl;
	std::cin.ignore(256, '\n');
	
	while(true){
		std::string login;
		std::cout << "Придумайте логин: ";	
		std::getline(std::cin, login, '\n');
		
		if(login == "q") { break; }
		
		if(loginCheck(login) == 5){
			std::cout << "Недопустимые символы ( ; или : или / )" << std::endl; 
			continue;
		}
		if(loginCheck(login) == 4){
			std::cout << "Пользователь с таким логином уже есть вашей системе" << std::endl; 
			continue;
		}

		char pass[16];
		std::cout << "Придумайте пароль: ";
		std::cin.getline(pass, 16, '\n');
		uint* h = sha1(pass, std::strlen(pass));
		std::string p = to_string(*h);

		userAdd(login, p);
		delete[] h;
		break;
	}
}

bool Client::userLogin(){
	systemClear();
	std::cout << "Вход в систему" << std::endl;
	std::cin.ignore(256, '\n');
	
	int a = 3;
	std::string b;
	bool result{false};

	while(a >= 0){
		if(a == 0) {
			std::cout << "Превышен лимит попыток!" << std::endl;
			return result;
		}
		if(a == 1) { b = "a"; }
			  else { b = "и"; }

		std::cout << "Осталось " << a << " попытк" << b << std::endl;
		
		std::string login;
		std::cout << "Введите логин: ";	
		std::getline(std::cin, login, '\n');
		
		if(login == "q") { break; }
		
		if(findLogin(login) < 0){
			std::cout << "Неверный логин" << std::endl; 
			--a;
			continue;
		}
		if(loginCheck(login) == 5){
			std::cout << "Недопустимые символы ( ; или : или / )" << std::endl; 
			--a;
			continue;
		}
		
		char pass[16];
		std::cout << "Введите пароль: ";
		std::cin.getline(pass, 16, '\n');
		uint* h = sha1(pass, std::strlen(pass));
		
		std::cout << "Проверка данных пользователя...";
		std::string p = to_string(*h);
	
		if(_users[findLogin(login)]._pass != p){
			std::cout << ERROR_MESSAGE << "Неверный пароль" << std::endl;
			--a;
			continue;
		}	
		
		_users[findLogin(login)].switchStatus();
		_username = login;
		std::cout << "Успешно!\nДобро пожаловать " << login << std::endl;
		result = true;
		break;
	}
	return result;
}

bool Client::userLogout(std::string &l){
	_users[findLogin(l)].switchStatus();
	_messages.clear();
	systemClear();
	std::cout << "Пользователь " << l <<  " вышел из чата!" << std::endl;
	return true; 
}

void Client::userAdd(std::string &l, std::string &p){
	std::cout << "Создание аккаунта пользователя...";

	User newUser(l, p);
	_users.push_back(newUser);
	++_usercount;
	
	writeUser(l, p);

	std::cout << "успешно" << std::endl;
}

void Client::userRuntime(std::string &_from){
	std::string _to;
	while(true){
		systemClear();
		std::cout << "Друзья в чате (введите имя)\n-----" << std::endl; 
		showUsers();
		std::cout << "-----" << std::endl;
		std::cout << _from << ": ";

		bzero(message, sizeof(message));
		std::cin >> message;

		if((strncmp(message, "q", 1)) == 0){
			userLogout(_from);
			break;
		}
		
		_to = message;
		if(findContact(_to) < 0){
			std::cout << "Неверный логин собеседника" << std::endl;
			continue;
		}

		getMsgList(_from, _to);
		systemClear();
		std::cout << "---------- Собеседник  " << _to << " ----------" << std::endl; 
				
		showMsgs(_from, _to);
		userTyping(_from, _to);
	}
}

void Client::userTyping(std::string &_from, std::string &_to){
	std::cin.ignore(256, '\n');
	
	std::string msg, _time, msgPkg;	
	_time = getTime();
	_rcvrname = _to;
	
	if(_clienttype == "cli"){
		msgPkg = makeReq("HNDSHK", "в сети", _time);
		bzero(message, sizeof(message));
		strcpy(message, msgPkg.data());
		send(_receiver, message, sizeof(message), 0);
	}

	while(true){
		bzero(message, sizeof(message));
		recv(_receiver, message, MESSAGE_LENGTH, 0);	
		splitReq(message, msg, _time);
		std::cout << _to << " (" <<  _time << "): " << msg << std::endl;

		if(msg != "q"){
			saveMsg(_to, _from, msg, _time);
		}

		std::cout << _from << ": ";
		std::getline(std::cin, msg, '\n');
		_time = getTime();

		msgPkg = makeReq("USRTYP", msg, _time);
		bzero(message, sizeof(message));
		strcpy(message, msgPkg.data());
		send(_receiver, message, sizeof(message), 0);
		
		if(msg == "q"){
			break;
		}

		saveMsg(_from, _to, msg, _time);
	}
}


void Client::readUser(){
	fs::path filepath{"accounts.txt"};
	std::ifstream file(filepath, std::ios::in);
	
	std::string l, p, n, temp;
	if(file.is_open()){
		getline(file, temp, '\n');
		_usercount = stoi(temp);
		for(int i = 0; i < _usercount; i++){
			getline(file, l, ':');
			getline(file, p, ':');
			getline(file, n, ';');
			
			User user(l,p,n);
			_users.push_back(user);
		}	
		file.close();
	}
}

void Client::makeUsrDir(){
	fs::path dir("userdata/");
	if(!fs::exists(dir)){
		create_directory(dir);
	}
}

void Client::writeUser(std::string &l, std::string &p){
	fs::path filepath{"accounts.txt"};
	std::ofstream file(filepath, std::ios::out);
    if(file.is_open()){
		file << _usercount << '\n';
		for(int i = 0; i < _usercount; i++){
			file << _users[i]._login << ':' << _users[i]._pass << ':' << _users[i]._name <<';';
		}
		file.close();
    }
	
	fs::path dir("userdata/" + l);
	if(!fs::exists(dir)){
		create_directory(dir);
	}
}

void Client::getUserList(std::string &l){
	std::cout << "Обновление списка контактов...";
	
	std::string req = makeReq("GETLST", l, "0");	
	bzero(message, MESSAGE_LENGTH);
	strcpy(message,req.data());
	send(_receiver, message, sizeof(message), 0);
		
	bzero(message, sizeof(message));
	read(_receiver, message, MESSAGE_LENGTH);

	if(strncmp(message, ERROR_NOTFOUND, CODE_LENGTH) == 0 ){
		std::cout << ERROR_MESSAGE << "\nСписок не найден" << std::endl;
	}
	else{
		std::string m = message;
		splitUserList(m);
		std::cout << "успешно" << std::endl;
	}
}

void Client::sendUserList(int index, std::string m){
	std::cout << "Передача списка контактов...";
	std::string login_temp, dummy;
	splitReq(m, login_temp, dummy);
	
	std::string pkg = pkgUserList();
	bzero(message, MESSAGE_LENGTH);
	strcpy(message, pkg.data());
	if(sizeof(message) <= MESSAGE_LENGTH){
		send(index, message, sizeof(message), 0);
		std::cout << "успешно" << std::endl;
	}
	else{
		send(index, ERROR_NOTFOUND, CODE_LENGTH, 0);
		std::cout << ERROR_MESSAGE << std::endl;
	}
}

void Client::saveMsg(std::string &_from, std::string &_to, std::string &_msg, std::string &_time){
	fs::path p = "userdata/" + _username;
	fs::path dir(p);
	if(!fs::exists(dir)){
		create_directory(dir);
	}

	if(_to != "all"){
		fs::path filepath1{dir / (_rcvrname + ".txt")};
		std::ofstream file1(filepath1, std::ios::app);
		if(file1.is_open()){
    	   file1 << _time << ';' << _from << ';' << _to << ';' << _msg <<'\n';
    	   file1.close();
		}
	}
	else{
		fs::path filepath2{dir / "group.txt"};
		std::ofstream file2(filepath2, std::ios::app);
    	if(file2.is_open()){
    	   file2 << _time << ';' << _from << ';' << _to << ';' << _msg <<'\n';
    	   file2.close();
    	}
	}
}

void Client::getMsgList(std::string &_from, std::string &_to){
	fs::path p = "userdata/" + _from;
	fs::path dir(p);
	if(fs::exists(dir)){
		std::string d, f, t, m, paths;

		paths = _to != "all" ?  (_to + ".txt") : "group.txt";
		
		fs::path filepath{dir / paths};
		std::ifstream file(filepath, std::ios::in);
		
		if(file.is_open()){
			while(getline(file, d, ';')){
				getline(file, f, ';');
				getline(file, t, ';');
				getline(file, m, '\n');

				Message msg(d, f, t,m);
				_messages.push_back(msg);
			}
			file.close();
		}
	}
}

void Client::showMsgs(std::string &_from, std::string &_to){
	for(int i = 0; i < _messages.size(); i++){
		if(_to == "all" && _to == _messages[i]._receiver){
			std::cout << _messages[i]._sender << " (" << _messages[i]._time <<  "): " <<  _messages[i]._msg << std::endl;
		}
		else if(_from == _messages[i]._sender && _to == _messages[i]._receiver){
			std::cout << _messages[i]._sender << " (" << _messages[i]._time <<  "): " <<  _messages[i]._msg << std::endl;
		}
		else if(_from == _messages[i]._receiver && _to == _messages[i]._sender){
			std::cout << _messages[i]._sender << " (" << _messages[i]._time <<  "): " <<  _messages[i]._msg << std::endl;
		}
	}
}

int Client::findLogin(std::string &user){
	for(int i = 0; i < _usercount; i++){
		if(user == _users[i]._login){
			return i;
		}
	}
	return -3;
}

int Client::findContact(std::string &user){
	for(int i = 0; i < _contacts.size(); i++){
		if(user == _contacts[i]){
			return i;
		}
	}
	return -3;
}

int Client::loginCheck(std::string &l){
	for(int i = 0; i < l.size(); i++){
		if(l[i] == ';' || l [i] == '/' || l [i] == ':' ) { return 5; }
	}
	for(int i = 0; i < _users.size(); i++){
		if(l == _users[i]._login) { return 4; }
	}
	return 1;
}

void Client::showUsers(){
	for(int i = 0; i < _contacts.size(); i++){
		std::cout << _contacts[i] << std::endl;
	}
}

void Client::User::switchStatus(){
	if(this->_status == 1){
		this->_status = userstatus::online;
	}
	else{
		this->_status = userstatus::offline;
	}
}

void Client::splitUserList(std::string &m){
	size_t pos{0};
	int i{0};
	while((pos = m.find(";")) != std::string::npos){
		_contacts.push_back(m.substr(0, pos));
		m.erase(0, pos + 1);
	}
}

std::string Client::makeReq(std::string rtype, std::string v1, std::string v2){
	std::string result;
		result.append(rtype);
		result.append(";");
		result.append(v1);
		result.append(";");
		result.append(v2);
		result.append(";");
	return result;
}

void Client::splitReq(std::string m, std::string &v1, std::string &v2){
	std::string temparr[3];
	size_t pos{0};
	int i{0};
	while((pos = m.find(";")) != std::string::npos){
		temparr[i++] = m.substr(0, pos); 
		m.erase(0, pos + 1);
	}
	v1 = temparr[1];
	v2 = temparr[2];
}

std::string Client::pkgUserList(){
	std::string result;
	for(int i = 0; i < _users.size(); i++){
		result.append(_users[i]._login);
		result.append(";");
	}
	return result;
}
