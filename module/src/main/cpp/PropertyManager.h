
#ifndef NOHELLO_PROPERTYMANAGER_H
#define NOHELLO_PROPERTYMANAGER_H

#include <string>
#include <unordered_map>

class PropertyManager {
public:
	explicit PropertyManager(const std::string& path);

	std::string getProp(const std::string& key);
	void setProp(const std::string& key, const std::string& value);

private:
	std::string filePath;
	std::unordered_map<std::string, std::string> props;

	void load();
	void save();
};

#endif //NOHELLO_PROPERTYMANAGER_H
