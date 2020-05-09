#include "auth.h"
#include "lw_http.hpp"
#include "md5wrapper.h"
#include "print.h"
#include "hwid.h"
#include "xor.h"
#include "crypto.h"

c_crypto crypto;

bool replace(std::string& str, const std::string& from, const std::string& to)
{
	size_t start_pos = str.find(from);
	if (start_pos == std::string::npos)
		return false;
	str.replace(start_pos, from.length(), to);
	return true;
}

void auth::set_license_key(const std::string serial, const std::string id)
{
	c_lw_http	lw_http;
	c_lw_httpd	lw_http_d;
	auto md5 = new md5wrapper();
	if (!lw_http.open_session())
	{
		return;
	}
	std::string s_reply;
	lw_http_d.add_field(xor_a("a"), md5->getHashFromString(Serial::GetHardwareId(id)).c_str());
	lw_http_d.add_field(xor_a("b"), crypto.key.c_str());
	lw_http_d.add_field(xor_a("c"), crypto.iv.c_str());
	lw_http_d.add_field(xor_a("d"), id.c_str());
	lw_http_d.add_field(xor_a("e"), serial.c_str());
	const auto b_lw_http = lw_http.post(L"https://peckcapsalot.com/api/action", s_reply, lw_http_d);
	lw_http.close_session();
	if (!b_lw_http)
	{
		return;
	}
	if (!strcmp(c_crypto::decrypt(s_reply, crypto.key, crypto.iv).c_str(), "201"))
	{
		//print::set_error(xor_a("INFO : Sorry, look wrong application id.\n"));
	}
	if (!strcmp(c_crypto::decrypt(s_reply, crypto.key, crypto.iv).c_str(), "202"))
	{
		//print::set_warning(xor_a("INFO : Application is paused cheat is update.\n"));
	}
	if (!strcmp(c_crypto::decrypt(s_reply, crypto.key, crypto.iv).c_str(), "203"))
	{
		//print::set_error(xor_a("INFO : Sorry, Hardware id is invalid please reset it.\n"));
	}
	if (!strcmp(c_crypto::decrypt(s_reply, crypto.key, crypto.iv).c_str(), "100"))
	{
		MessageBoxA(0, "invalid token", "Atlas", 0);
	}
	if (!strcmp(c_crypto::decrypt(s_reply, crypto.key, crypto.iv).c_str(), "101"))
	{
		//print::set_error(xor_a("INFO : Sorry, serial key already used by other.\n"));
	}
	if (!strcmp(c_crypto::decrypt(s_reply, crypto.key, crypto.iv).c_str(), "102"))
	{
		//print::set_error(xor_a("INFO : Sorry, you enter invalid serial key.\n"));
	}
	if (!strcmp(c_crypto::decrypt(s_reply, crypto.key, crypto.iv).c_str(), "103"))
	{
		//print::set_error(xor_a("INFO : Sorry, serial key has been expired.\n"));
	}
	if (!strcmp(c_crypto::decrypt(s_reply, crypto.key, crypto.iv).c_str(), "104"))
	{
		//print::set_error(xor_a("INFO : Sorry, user already unsed.\n"));
	}
	if (!strcmp(c_crypto::decrypt(s_reply, crypto.key, crypto.iv).c_str(), ("200")))
	{
		MessageBoxA(0, "success", "restart client", 0);
	}
}

int auth::get_valid_user(const std::string& id)
{
	c_lw_http	lw_http;
	c_lw_httpd	lw_http_d;
	auto md5 = new md5wrapper();
	if (!lw_http.open_session())
	{
		return 0;
	}
	std::string s_reply;
	lw_http_d.add_field(xor_a("a"), md5->getHashFromString(Serial::GetHardwareId(id)).c_str());
	lw_http_d.add_field(xor_a("b"), crypto.key.c_str());
	lw_http_d.add_field(xor_a("c"), crypto.iv.c_str());
	lw_http_d.add_field(xor_a("d"), id.c_str());
	lw_http_d.add_field(xor_a("e"), xor_a(""));
	const auto b_lw_http = lw_http.post(xor_w(L"https://peckcapsalot.com/api/info"), s_reply, lw_http_d);
	lw_http.close_session();

	if (!b_lw_http)
	{
		return 0;
	}

	if (!strcmp(c_crypto::decrypt(s_reply, crypto.key, crypto.iv).c_str(), "201"))
	{
		//print::set_error(xor_a("INFO : Sorry, look wrong application id.\n"));
		return 0;
	}
	if (!strcmp(c_crypto::decrypt(s_reply, crypto.key, crypto.iv).c_str(), "202"))
	{
		//print::set_error(xor_a("INFO : Application is paused cheat is update.\n"));
		return 0;
	}
	if (!strcmp(c_crypto::decrypt(s_reply, crypto.key, crypto.iv).c_str(), "203"))
	{
		//print::set_error(xor_a("INFO : Sorry, Your PC is not registered or HWID is not match.\n"));
		return 0;
	}
	if (!strcmp(c_crypto::decrypt(s_reply, crypto.key, crypto.iv).c_str(), "100"))
	{
		MessageBoxA(0, "invalid token", "Failure", 0);
		return 0;
	}
	if (!strcmp(c_crypto::decrypt(s_reply, crypto.key, crypto.iv).c_str(), "101"))
	{
		//print::set_error(xor_a("INFO : Sorry, serial key already used by other.\n"));
		return 0;
	}
	if (!strcmp(c_crypto::decrypt(s_reply, crypto.key, crypto.iv).c_str(), "102"))
	{
		//printf(xor_a("INFO : Sorry, you enter invalid serial key.\n"));
		return 0;
	}
	if (!strcmp(c_crypto::decrypt(s_reply, crypto.key, crypto.iv).c_str(), "103"))
	{
		//print::set_error(xor_a("INFO : Sorry, serial key has been expired.\n"));
		return 0;
	}
	if (!strcmp(c_crypto::decrypt(s_reply, crypto.key, crypto.iv).c_str(), "200"))
	{
		return 0x100;
	}

	return 0;
};

std::string auth::get_sub_info(const std::string id)
{
	c_lw_http	lw_http;
	c_lw_httpd	lw_http_d;
	auto md5 = new md5wrapper();
	if (!lw_http.open_session())
	{
		return{};
	}
	std::string s_reply;
	lw_http_d.add_field(xor_a("a"), md5->getHashFromString(Serial::GetHardwareId(id)).c_str());
	lw_http_d.add_field(xor_a("b"), crypto.key.c_str());
	lw_http_d.add_field(xor_a("c"), crypto.iv.c_str());
	lw_http_d.add_field(xor_a("d"), id.c_str());
	lw_http_d.add_field(xor_a("e"), xor_a("info"));
	const auto b_lw_http = lw_http.post(L"https://peckcapsalot.com/api/info", s_reply, lw_http_d);
	if (!b_lw_http)
	{
		return{};
	}
	lw_http.close_session();
	std::string sstring(crypto.decrypt(s_reply.c_str(), crypto.key.c_str(), crypto.iv.c_str()).c_str());
	replace(sstring, "\"", "");
	replace(sstring, "\"", "");
	char data[256];
	sprintf(data, xor_a("%s"), sstring.c_str());
	return std::string(data);
}

/*#include "auth.h"
#include "lw_http.hpp"
#include "md5wrapper.h"
#include "print.h"
#include "hwid.h"
#include "xor.h"
#include "crypto.h"

c_crypto crypto;

bool replace(std::string& str, const std::string& from, const std::string& to)
{
	size_t start_pos = str.find(from);
	if (start_pos == std::string::npos)
		return false;
	str.replace(start_pos, from.length(), to);
	return true;
}

void auth::set_license_key(const std::string serial, const std::string id)
{
	c_lw_http	lw_http;
	c_lw_httpd	lw_http_d;
	auto md5 = new md5wrapper();
	if (!lw_http.open_session())
	{
		return;
	}
	std::string s_reply;
	lw_http_d.add_field(xor_a("a"), md5->getHashFromString(Serial::GetHardwareId(id)).c_str());
	lw_http_d.add_field(xor_a("b"), crypto.key.c_str());
	lw_http_d.add_field(xor_a("c"), crypto.iv.c_str());
	lw_http_d.add_field(xor_a("d"), id.c_str());
	lw_http_d.add_field(xor_a("e"), serial.c_str());
	const auto b_lw_http = lw_http.post(L"http://www.artemis.wtf/api/action", s_reply, lw_http_d);
	lw_http.close_session();
	if (!b_lw_http)
	{
		return;
	}
	if (!strcmp(c_crypto::decrypt(s_reply, crypto.key, crypto.iv).c_str(), "201"))
	{
		//print::set_error(xor_a("INFO : Sorry, look wrong application id.\n"));
	}
	if (!strcmp(c_crypto::decrypt(s_reply, crypto.key, crypto.iv).c_str(), "202"))
	{
		//print::set_warning(xor_a("INFO : Application is paused cheat is update.\n"));
	}
	if (!strcmp(c_crypto::decrypt(s_reply, crypto.key, crypto.iv).c_str(), "203"))
	{
		//print::set_error(xor_a("INFO : Sorry, Hardware id is invalid please reset it.\n"));
	}
	if (!strcmp(c_crypto::decrypt(s_reply, crypto.key, crypto.iv).c_str(), "100"))
	{
		MessageBoxA(0, "token = invalid", "BackFire", 0);
		//print::set_error(xor_a("INFO : You enter wrong serial key.\n"));
	}
	if (!strcmp(c_crypto::decrypt(s_reply, crypto.key, crypto.iv).c_str(), "101"))
	{
		//print::set_error(xor_a("INFO : Sorry, serial key already used by other.\n"));
	}
	if (!strcmp(c_crypto::decrypt(s_reply, crypto.key, crypto.iv).c_str(), "102"))
	{
		MessageBox(0, "invalid token", "BackFire", 0);
		//print::set_error(xor_a("INFO : Sorry, you enter invalid serial key.\n"));
	}
	if (!strcmp(c_crypto::decrypt(s_reply, crypto.key, crypto.iv).c_str(), "103"))
	{
		//print::set_error(xor_a("INFO : Sorry, serial key has been expired.\n"));
	}
	if (!strcmp(c_crypto::decrypt(s_reply, crypto.key, crypto.iv).c_str(), "104"))
	{
		//print::set_error(xor_a("INFO : Sorry, user already unsed.\n"));
	}
	if (!strcmp(c_crypto::decrypt(s_reply, crypto.key, crypto.iv).c_str(), ("200")))
	{
		AllocConsole();
		print::set_ok(xor_a("SUCCESS: Please re-open loader! (closing in 10 seconds)\n"));
		Sleep(10000);
		exit(0);
		//system("pause");
	}
}

int auth::get_valid_user(const std::string& id)
{
	c_lw_http	lw_http;
	c_lw_httpd	lw_http_d;
	auto md5 = new md5wrapper();
	if (!lw_http.open_session())
	{
		return 0;
	}
	std::string s_reply;
	lw_http_d.add_field(xor_a("a"), md5->getHashFromString(Serial::GetHardwareId(id)).c_str());
	lw_http_d.add_field(xor_a("b"), crypto.key.c_str());
	lw_http_d.add_field(xor_a("c"), crypto.iv.c_str());
	lw_http_d.add_field(xor_a("d"), id.c_str());
	lw_http_d.add_field(xor_a("e"), xor_a(""));
	const auto b_lw_http = lw_http.post(xor_w(L"http://www.artemis.wtf/api/info"), s_reply, lw_http_d);
	lw_http.close_session();

	if (!b_lw_http)
	{
		return 0;
	}

	if (!strcmp(c_crypto::decrypt(s_reply, crypto.key, crypto.iv).c_str(), "201"))
	{
		//print::set_error(xor_a("INFO : Sorry, look wrong application id.\n"));
		return 0;
	}
	if (!strcmp(c_crypto::decrypt(s_reply, crypto.key, crypto.iv).c_str(), "202"))
	{
		MessageBoxA(0, "cheat is updating!", "client offline", 0);
		//print::set_error(xor_a("INFO : Application is paused cheat is update.\n"));
		return 0;
	}
	if (!strcmp(c_crypto::decrypt(s_reply, crypto.key, crypto.iv).c_str(), "203"))
	{
		return 0;
	}
	if (!strcmp(c_crypto::decrypt(s_reply, crypto.key, crypto.iv).c_str(), "100"))
	{
		MessageBoxA(0, "incorret token", "BackFire", 0);
		//print::set_error(xor_a("INFO : You enter wrong serial key.\n"));
		return 0;
	}
	if (!strcmp(c_crypto::decrypt(s_reply, crypto.key, crypto.iv).c_str(), "101"))
	{
		//print::set_error(xor_a("INFO : Sorry, serial key already used by other.\n"));
		return 0;
	}
	if (!strcmp(c_crypto::decrypt(s_reply, crypto.key, crypto.iv).c_str(), "102"))
	{
		MessageBoxA(0, "invalid token", "BackFire", 0);
	    //printf(xor_a("INFO : Sorry, you enter invalid serial key.\n"));
		return 0;
	}
	if (!strcmp(c_crypto::decrypt(s_reply, crypto.key, crypto.iv).c_str(), "103"))
	{
		//print::set_error(xor_a("INFO : Sorry, serial key has been expired.\n"));
		return 0;
	}
	if (!strcmp(c_crypto::decrypt(s_reply, crypto.key, crypto.iv).c_str(), "200"))
	{
		return 0x100;
	}

	return 0;
};

std::string auth::get_sub_info(const std::string id)
{
	c_lw_http	lw_http;
	c_lw_httpd	lw_http_d;
	auto md5 = new md5wrapper();
	if (!lw_http.open_session())
	{
		return{};
	}
	std::string s_reply;
	lw_http_d.add_field(xor_a("a"), md5->getHashFromString(Serial::GetHardwareId(id)).c_str());
	lw_http_d.add_field(xor_a("b"), crypto.key.c_str());
	lw_http_d.add_field(xor_a("c"), crypto.iv.c_str());
	lw_http_d.add_field(xor_a("d"), id.c_str());
	lw_http_d.add_field(xor_a("e"), xor_a("info"));
	const auto b_lw_http = lw_http.post(L"http://www.artemis.wtf/api/info", s_reply, lw_http_d);
	if (!b_lw_http)
	{
		return{};
	}
	lw_http.close_session();
	std::string sstring(crypto.decrypt(s_reply.c_str(), crypto.key.c_str(), crypto.iv.c_str()).c_str());
	replace(sstring, "\"", "");
	replace(sstring, "\"", "");
	char data[256];
	sprintf(data, xor_a("%s"), sstring.c_str());
	return std::string(data);
}*/