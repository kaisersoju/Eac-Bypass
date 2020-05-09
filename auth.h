#pragma once
#include <string.h>
#include <string>

class auth
{
public:
	static void set_license_key(const std::string serial, const std::string id);
	static int get_valid_user(const std::string& id);
	static std::string get_sub_info(const std::string id);
};