#include "dbHandler.h"

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

bool DBHandler::createTable() {
    const char* create_table_sql = 
        "CREATE TABLE IF NOT EXISTS DETECTED_WEBSHELLS ("
        "id INTEGER PRIMARY KEY,"
        "file_path TEXT NOT NULL,"
        "hash TEXT NOT NULL);";

    int ret = sqlite3_exec(db, create_table_sql, nullptr, nullptr, nullptr);
    bool isOk = (ret == SQLITE_OK);
    if (!isOk) {
        std::cerr << "Error creating table" << std::endl;
    }
    return isOk;
}

bool DBHandler::insertData(const std::string& file_path, const std::string& hash) {
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