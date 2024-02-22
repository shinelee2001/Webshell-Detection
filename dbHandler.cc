#include "dbHandler.h"
#include <fstream>
#include <string>

DBHandler::DBHandler(const std::string& db_file):
    db{nullptr}, db_file{db_file} {}

DBHandler::~DBHandler() {
    // If db is set, free it.
    if (db) {
        sqlite3_close(db);
    }
}

bool DBHandler::openDatabase() {
    // Check the return code for sqlite3_open()
    int ret = sqlite3_open(db_file.c_str(), &db);
    if (ret != SQLITE_OK) {
        std::cerr << "Failed to open database" << std::endl;
    }
    return ret == SQLITE_OK;
}

bool DBHandler::createDetectedTable() {
    const char* create_table_sql = 
        "CREATE TABLE IF NOT EXISTS DETECTED_WEBSHELLS ("
        "id INTEGER PRIMARY KEY,"
        "file_path TEXT NOT NULL,"
        "hash TEXT NOT NULL);";

    int ret = sqlite3_exec(db, create_table_sql, nullptr, nullptr, nullptr);
    bool isOk = (ret == SQLITE_OK);
    if (!isOk) {
        std::cerr << "Error creating table" << std::endl;
        return !isOk;
    }
    return isOk;
}

bool DBHandler::insertDetectedData(const std::string& file_path, const std::string& hash) {
    const char* insert_sql = "INSERT INTO DETECTED_WEBSHELLS (file_path, hash) VALUES (?, ?);";
    sqlite3_stmt* stmt;
    
    // Prepare the exeecute statement
    int ret = sqlite3_prepare_v2(db, insert_sql, -1, &stmt, nullptr);
    if (ret != SQLITE_OK) {
        std::cerr << "Insert Statement cannot be resolved" << std::endl;
        return false;
    }
    sqlite3_bind_text(stmt, 1, file_path.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, hash.c_str(), -1, SQLITE_STATIC);

    // Execute Insert Statement
    sqlite3_step(stmt);

    sqlite3_finalize(stmt);

    return true;
}


bool DBHandler::createdSignatureTable() {
    const char* create_table_sql = 
        "CREATE TABLE IF NOT EXISTS SIGNATURE_WEBSHELLS ("
        "id INTEGER PRIMARY KEY,"
        "hash TEXT NOT NULL);";
    
    int ret = sqlite3_exec(db,create_table_sql, nullptr, nullptr, nullptr);
    bool isOk = (ret == SQLITE_OK);
    if (!isOk) {
        std::cerr << "Error creating table" << std::endl;
        return !isOk;
    }
    return isOk;
}

bool DBHandler::insertSignatrues() {
    const char* insert_sql = "INSERT INTO SIGNATURE_WEBSHELLS (hash) VALUES (?);";
    sqlite3_stmt* stmt;

    // Prepare the executet statement
    int ret = sqlite3_prepare_v2(db, insert_sql, -1, &stmt, nullptr);
    if (ret != SQLITE_OK) {
        std::cerr << "Insert Statement cannot be resolved" << std::endl;
        return false;
    }

    // Read hashes from output.txt file
    std::ifstream file {"./malwares/output.txt"};
    std::string hash;
    while (file >> hash) {
        // Execute insert statement
        sqlite3_bind_text(stmt, 1, hash.c_str(), -1, SQLITE_STATIC);
        sqlite3_step(stmt);
    }
    sqlite3_finalize(stmt);
    return true;
}