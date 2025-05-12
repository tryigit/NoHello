#ifndef NOHELLO_PROPERTYMANAGER_H
#define NOHELLO_PROPERTYMANAGER_H

#include <string>
#include <unordered_map>

class PropertyManager {
public:
	explicit PropertyManager(std::string  path);

	std::string getProp(const std::string& key, const std::string& defaultValue = "");
	void setProp(const std::string& key, const std::string& value);
  // bool hasProp(const std::string& key) const;
  // void removeProp(const std::string& key);

private:
	std::string filePath;
	std::unordered_map<std::string, std::string> props;

	bool loadFromFile();
	bool saveToFile();
};

#endif //NOHELLO_PROPERTYMANAGER_H
