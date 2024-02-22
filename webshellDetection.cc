#include <iostream>
#include <fstream>
#include <filesystem>
#include <regex>
#include <unordered_map>
#include <sqlite3.h>
#include "md5.h"
#include "dbHandler.h"

namespace fs = std::filesystem;

// Hashes for known signatures.
// Later, will store them in a database
std::unordered_map<std::string, std::string> websell_signature = {
        {"hashforsomephp", "PHP webshell"},
        {"hashforsomeasp", "ASP webshell"},
        {"hashforsomejsp", "JSP webshell"}
};

bool detect_signature(const std::string& file_path){
    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }

    std::string file_contents((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    MD5 hasher;
    std::string md5_hash = hasher.hash(file_contents);

    if (websell_signature.find(md5_hash) != websell_signature.end()) {
        return true;
    }
    return false;
}

bool detect_webshell(const std::string &file_path) {
    std::ifstream file(file_path);
    if (!file.is_open()) {
        return false;
    }

    std::string file_contents((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    if (std::regex_search(file_contents, std::regex("(system|eval|base64_decode)"))) {
        return true;
    }
    if (std::regex_search(file_contents, std::regex("(shell_exec|exec|passthru|proc_open|popen)"))) {
        return true;
    }
    return false;
}

// check the hash code in the database

void check_directory(const std::string &directory, DBHandler &db) {
    for (const auto &entry : fs::recursive_directory_iterator(directory)) {
        if (entry.is_regular_file() && (entry.path().extension() == ".php" || entry.path().extension() == ".php3" || entry.path().extension() == ".phtml")) {
            std::string file_path = entry.path().string();
            
            if (detect_webshell(file_path) || detect_signature(file_path)) {
                std::cout << "Webshell detected in file: " << file_path << std::endl;

                // Store detected webshell in DB
                std::ifstream file(file_path, std::ios::binary);
                std::string file_contents((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                MD5 hasher;
                std::string md5_hash = hasher.hash(file_contents);

                if (!db.insertDetectedData(file_path, md5_hash)) {
                    std::cerr << "Failed to store data" << std::endl;
                }
            }
        }
    }
    std::cout << "Finished checking directory: " << directory << std::endl;
}

int main() {
	//std::string directory;
    //std::cout << "Write a path to directory you want to check:" << std::endl;
    //std::cin >> directory; 

    std::string directory = "C:\\Users\\LG\\Desktop\\1_4_7_14\\uploads";
    // Create DB
    DBHandler dbHandler("WEBSHELLS.db");
    dbHandler.openDatabase();
    dbHandler.createDetectedTable();
    
    dbHandler.createdSignatureTable();
    dbHandler.insertSignatrues();

	check_directory(directory, dbHandler);
}