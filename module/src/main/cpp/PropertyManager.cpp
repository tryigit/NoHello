
#include "PropertyManager.h"
#include <fstream>
#include <sstream>
#include <utility>

PropertyManager::PropertyManager(std::string path) : filePath(std::move(path)) {
	load();
}

void PropertyManager::load() {
	props.clear();
	std::ifstream file(filePath);
	std::string line;
	while (std::getline(file, line)) {
		auto pos = line.find('=');
		if (pos == std::string::npos) continue;

		std::string key = line.substr(0, pos);
		std::string val = line.substr(pos + 1);
		props[key] = val;
	}
}

void PropertyManager::save() {
	std::ofstream file(filePath, std::ios::trunc);
	for (const auto& [key, value] : props) {
		file << key << "=" << value << '\n';
	}
}

std::string PropertyManager::getProp(const std::string& key) {
	load();
	auto it = props.find(key);
	return it != props.end() ? it->second : "";
}

void PropertyManager::setProp(const std::string& key, const std::string& value) {
	load();
	props[key] = value;
	save();
}
