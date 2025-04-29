#pragma once
#include <string>
#include <windows.h>

std::string read_registry_value(HKEY root, const std::string& subKey, const std::string& valueName);
