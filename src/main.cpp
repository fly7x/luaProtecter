#include "transformer.hpp"
#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sstream>
#include <filesystem>

namespace fs = std::filesystem;

constexpr int PORT = 10000;
constexpr int BACKLOG = 32;
const std::string WEB_ROOT = "web/";

// Helper to read a file into a string
std::string readFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return "";
    std::string content((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());
    return content;
}

// MIME type from extension
std::string mimeType(const std::string& path) {
    if (path.ends_with(".html")) return "text/html";
    if (path.ends_with(".css")) return "text/css";
    if (path.ends_with(".js")) return "application/javascript";
    if (path.ends_with(".png")) return "image/png";
    if (path.ends_with(".svg")) return "image/svg+xml";
    return "text/plain";
}

// JSON escape
std::string jsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default: out += c; break;
        }
    }
    return out;
}

void handleClient(int clientFd) {
    char buffer[65536];
    ssize_t n = read(clientFd, buffer, sizeof(buffer) - 1);
    if (n <= 0) { close(clientFd); return; }
    buffer[n] = '\0';
    
    std::string request(buffer);
    std::string method = request.substr(0, request.find(' '));
    std::string path = request.substr(request.find(' ') + 1);
    path = path.substr(0, path.find(' '));
    
    std::string response;
    int status = 200;
    std::string contentType = "text/html";
    
    try {
        if (path == "/" || path == "/index.html") {
            std::string content = readFile(WEB_ROOT + "index.html");
            if (content.empty()) throw std::runtime_error("index.html not found");
            response = content;
            contentType = "text/html";
        } else if (path == "/app.js") {
            std::string content = readFile(WEB_ROOT + "app.js");
            if (content.empty()) throw std::runtime_error("app.js not found");
            response = content;
            contentType = "application/javascript";
        } else if (path == "/api/obfuscate" && method == "POST") {
            size_t bodyStart = request.find("\r\n\r\n");
            if (bodyStart == std::string::npos) throw std::runtime_error("Malformed request");
            std::string body = request.substr(bodyStart + 4);
            
            // Extract JSON source
            std::string key = "\"code\"";
            size_t keyPos = body.find(key);
            if (keyPos == std::string::npos) throw std::runtime_error("Missing 'code' field");
            size_t colon = body.find(':', keyPos + key.size());
            if (colon == std::string::npos) throw std::runtime_error("Invalid JSON");
            size_t start = colon + 1;
            while (start < body.size() && (body[start] == ' ' || body[start] == '\t' || body[start] == '\r' || body[start] == '\n')) start++;
            if (start >= body.size() || body[start] != '"') throw std::runtime_error("Code must be a string");
            start++;
            std::string code;
            bool escaped = false;
            while (start < body.size()) {
                char c = body[start++];
                if (escaped) {
                    if (c == 'n') code += '\n';
                    else if (c == 'r') code += '\r';
                    else if (c == 't') code += '\t';
                    else if (c == '\\') code += '\\';
                    else if (c == '"') code += '"';
                    else code += c;
                    escaped = false;
                    continue;
                }
                if (c == '\\') { escaped = true; continue; }
                if (c == '"') break;
                code += c;
            }
            
            // Obfuscate
            Transformer transformer;
            Transformer::Options opts;
            opts.virtualize = true;
            opts.polymorphic = true;
            std::string protectedCode = transformer.protect(code, opts);
            
            std::stringstream ss;
            ss << "{\"success\":true,\"code\":\"" << jsonEscape(protectedCode) << "\"}";
            response = ss.str();
            contentType = "application/json";
        } else {
            status = 404;
            response = "404 Not Found";
            contentType = "text/plain";
        }
    } catch (const std::exception& e) {
        status = 500;
        std::stringstream ss;
        ss << "{\"success\":false,\"error\":\"" << jsonEscape(e.what()) << "\"}";
        response = ss.str();
        contentType = "application/json";
    }
    
    std::stringstream resp;
    resp << "HTTP/1.1 " << status << " OK\r\n";
    resp << "Content-Type: " << contentType << "\r\n";
    resp << "Content-Length: " << response.size() << "\r\n";
    resp << "Connection: close\r\n\r\n";
    resp << response;
    std::string full = resp.str();
    write(clientFd, full.c_str(), full.size());
    close(clientFd);
}

int main(int argc, char* argv[]) {
    // If command line arguments, process file
    if (argc >= 2) {
        std::string inputFile = argv[1];
        std::string outputFile = (argc >= 3) ? argv[2] : "output/protected.lua";
        std::ifstream in(inputFile);
        if (!in.is_open()) {
            std::cerr << "Cannot open input: " << inputFile << std::endl;
            return 1;
        }
        std::string source((std::istreambuf_iterator<char>(in)),
                           std::istreambuf_iterator<char>());
        in.close();
        try {
            Transformer transformer;
            std::string protectedCode = transformer.protect(source);
            std::ofstream out(outputFile);
            if (!out.is_open()) {
                std::cerr << "Cannot write output: " << outputFile << std::endl;
                return 1;
            }
            out << protectedCode;
            out.close();
            std::cout << "✅ Protected: " << inputFile << " → " << outputFile << std::endl;
            std::cout << "   Original: " << source.size() << " bytes" << std::endl;
            std::cout << "   Protected: " << protectedCode.size() << " bytes" << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "❌ Error: " << e.what() << std::endl;
            return 1;
        }
        return 0;
    }
    
    // Serve web interface
    std::cout << "🔒 LuaProtecter Server starting on port " << PORT << std::endl;
    std::cout << "   Web root: " << WEB_ROOT << std::endl;
    std::cout << "   Open http://localhost:" << PORT << std::endl;
    
    int serverFd = socket(AF_INET, SOCK_STREAM, 0);
    if (serverFd < 0) { std::cerr << "Socket error\n"; return 1; }
    int opt = 1;
    setsockopt(serverFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);
    if (bind(serverFd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "Bind failed\n"; close(serverFd); return 1;
    }
    if (listen(serverFd, BACKLOG) < 0) {
        std::cerr << "Listen failed\n"; close(serverFd); return 1;
    }
    
    while (true) {
        struct sockaddr_in clientAddr;
        socklen_t len = sizeof(clientAddr);
        int clientFd = accept(serverFd, (struct sockaddr*)&clientAddr, &len);
        if (clientFd < 0) continue;
        handleClient(clientFd);
    }
    close(serverFd);
    return 0;
}