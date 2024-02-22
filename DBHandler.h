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

    // Handling DETECTED_WEBSHELLS TABLE
    bool createDetectedTable(); // Creates DETECTED_WEBSHELLS TABLE
    bool insertDetectedData(const std::string& file_path, const std::string& hash); // Stores the detected data

    // Handling SIGNATURE_WEBSHELLS TABLE
    bool createdSignatureTable(); // Creates SIGNATURE_WEBSHELLS TABLE
    bool insertSignatrues(); // Stores the signatures

  private:
    sqlite3* db;
    std::string db_file;
};

#endif