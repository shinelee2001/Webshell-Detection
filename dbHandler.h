#ifndef DB_HANDLER_H
#define DB_HANDLER_H

#include <sqlite3.h>
#include <iostream>
#include <string>

class DBHandler {
public:
    DBHandler(const std::string& db_file);
    ~DBHandler();

    bool openDatabase();
    bool createDetectedTable(); // Creates DETECTED_WEBSHELLS DB
    bool insertDetectedData(const std::string& file_path, const std::string& hash);

    bool createdSignatureTable(); // Creates SIGNATURE_WEBSHELLS DB

private:
    sqlite3* db;
    std::string db_file;
};

#endif