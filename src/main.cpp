#include "transformer.hpp"
#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sstream>
#include <algorithm>
#include <cctype>

constexpr int PORT = 10000;
constexpr int BACKLOG = 32;
const std::string WEB_ROOT = "web/";

static bool hasSuffix(const std::string& str, const std::string& suffix) {
    if (str.size() < suffix.size()) return false;
    return str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::string readFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return "";
    return std::string((std::istreambuf_iterator<char>(file)),
                       std::istreambuf_iterator<char>());
}

std::string mimeType(const std::string& path) {
    if (hasSuffix(path, ".html")) return "text/html";
    if (hasSuffix(path, ".css"))  return "text/css";
    if (hasSuffix(path, ".js"))   return "application/javascript";
    return "text/plain";
}

std::string jsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += char(c);
                }
        }
    }
    return out;
}

static std::string toLower(std::string s) {
    for (char& c : s) c = char(std::tolower((unsigned char)c));
    return s;
}

static size_t headerEnd(const std::string& req) {
    size_t p = req.find("\r\n\r\n");
    if (p != std::string::npos) return p;
    return req.find("\n\n");
}

static int contentLengthOf(const std::string& headers) {
    std::string h = toLower(headers);
    size_t p = h.find("content-length:");
    if (p == std::string::npos) return 0;
    p += 15;
    while (p < h.size() && (h[p] == ' ' || h[p] == '\t')) ++p;
    return std::atoi(h.c_str() + p);
}

static std::string readRequest(int fd) {
    std::string req;
    char buf[4096];
    while (headerEnd(req) == std::string::npos) {
        ssize_t n = ::read(fd, buf, sizeof(buf));
        if (n <= 0) break;
        req.append(buf, size_t(n));
        if (req.size() > 8 * 1024 * 1024) break;
    }
    size_t he = headerEnd(req);
    if (he == std::string::npos) return req;

    std::string sep = (req.find("\r\n\r\n") != std::string::npos) ? "\r\n\r\n" : "\n\n";
    std::string headers = req.substr(0, he);
    int need = contentLengthOf(headers);
    size_t bodyStart = he + sep.size();
    int have = int(req.size() - bodyStart);
    while (have < need) {
        ssize_t n = ::read(fd, buf, sizeof(buf));
        if (n <= 0) break;
        req.append(buf, size_t(n));
        have += int(n);
        if (req.size() > 8 * 1024 * 1024) break;
    }
    return req;
}

static std::string extractJsonString(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\"";
    size_t keyPos = json.find(search);
    if (keyPos == std::string::npos) return "";
    size_t colon = json.find(':', keyPos + search.size());
    if (colon == std::string::npos) return "";
    size_t start = colon + 1;
    while (start < json.size() && std::isspace((unsigned char)json[start])) start++;
    if (start >= json.size() || json[start] != '"') return "";
    start++;
    std::string result;
    bool escaped = false;
    for (size_t i = start; i < json.size(); ++i) {
        char c = json[i];
        if (escaped) {
            switch (c) {
                case 'n': result += '\n'; break;
                case 'r': result += '\r'; break;
                case 't': result += '\t'; break;
                case '"': result += '"'; break;
                case '\\': result += '\\'; break;
                case '/': result += '/'; break;
                case 'u': {
                    if (i + 4 < json.size()) i += 4;
                    result += '?';
                    break;
                }
                default: result += c; break;
            }
            escaped = false;
            continue;
        }
        if (c == '\\') { escaped = true; continue; }
        if (c == '"') break;
        result += c;
    }
    return result;
}

static std::string extractCode(const std::string& body) {
    std::string code = extractJsonString(body, "code");
    if (code.empty()) code = extractJsonString(body, "source");
    if (code.empty()) code = extractJsonString(body, "script");
    if (code.empty()) {
        std::string t = body;
        while (!t.empty() && std::isspace((unsigned char)t.front())) t.erase(t.begin());
        if (!t.empty() && t.front() != '{' && t.front() != '[')
            code = t;
    }
    return code;
}

void sendAll(int fd, const std::string& s) {
    const char* p = s.data();
    size_t left = s.size();
    while (left) {
        ssize_t n = ::write(fd, p, left);
        if (n <= 0) break;
        p += n;
        left -= size_t(n);
    }
}

void handleClient(int clientFd) {
    std::string request = readRequest(clientFd);
    if (request.empty()) { close(clientFd); return; }

    std::string method = request.substr(0, request.find(' '));
    std::string path;
    size_t sp1 = request.find(' ');
    if (sp1 != std::string::npos) {
        size_t sp2 = request.find(' ', sp1 + 1);
        path = request.substr(sp1 + 1, sp2 - sp1 - 1);
    }
    size_t q = path.find('?');
    if (q != std::string::npos) path = path.substr(0, q);

    std::string response;
    int status = 200;
    std::string contentType = "text/html";

    try {
        if (path == "/" || path == "/index.html") {
            response = readFile(WEB_ROOT + "index.html");
            if (response.empty()) throw std::runtime_error("index.html not found");
        } else if (path == "/style.css") {
            response = readFile(WEB_ROOT + "style.css");
            contentType = "text/css";
        } else if (path == "/app.js") {
            response = readFile(WEB_ROOT + "app.js");
            contentType = "application/javascript";
        } else if (path == "/api/obfuscate" && (method == "POST" || method == "post")) {
            size_t he = headerEnd(request);
            std::string sep = (request.find("\r\n\r\n") != std::string::npos) ? "\r\n\r\n" : "\n\n";
            std::string body = (he == std::string::npos) ? "" : request.substr(he + sep.size());

            std::string code = extractCode(body);
            if (code.empty())
                throw std::runtime_error("Missing or empty 'code' field");

            bool vmMode = true, polymorphic = true;
            std::string vmStr = extractJsonString(body, "vm");
            if (vmStr == "false" || vmStr == "0") vmMode = false;
            std::string polyStr = extractJsonString(body, "polymorphic");
            if (polyStr == "false" || polyStr == "0") polymorphic = false;

            Transformer transformer;
            Transformer::Options opts;
            opts.virtualize = vmMode;
            opts.polymorphic = polymorphic;
            opts.renameIdentifiers = true;
            opts.encodeStrings = true;
            opts.encodeNumbers = true;
            opts.removeComments = true;
            opts.decoys = false;
            opts.antiDebug = false;

            std::string protectedCode = transformer.protect(code, opts);
            response = std::string("{\"success\":true,\"code\":\"") + jsonEscape(protectedCode) + "\"}";
            contentType = "application/json";
        } else if (method == "OPTIONS" || method == "options") {
            response = "";
            contentType = "text/plain";
        } else {
            status = 404;
            response = "404 Not Found";
            contentType = "text/plain";
        }
    } catch (const std::exception& e) {
        status = 500;
        response = std::string("{\"success\":false,\"error\":\"") + jsonEscape(e.what()) + "\"}";
        contentType = "application/json";
    }

    std::stringstream resp;
    resp << "HTTP/1.1 " << status << (status == 200 ? " OK" : " Error") << "\r\n";
    resp << "Content-Type: " << contentType << "\r\n";
    resp << "Content-Length: " << response.size() << "\r\n";
    resp << "Access-Control-Allow-Origin: *\r\n";
    resp << "Access-Control-Allow-Headers: Content-Type\r\n";
    resp << "Access-Control-Allow-Methods: POST, GET, OPTIONS\r\n";
    resp << "Connection: close\r\n\r\n";
    resp << response;
    sendAll(clientFd, resp.str());
    close(clientFd);
}

int main(int argc, char* argv[]) {
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
        try {
            Transformer transformer;
            Transformer::Options opts;
            opts.virtualize = true;
            opts.polymorphic = true;
            opts.antiDebug = false;
            std::string protectedCode = transformer.protect(source, opts);
            std::ofstream out(outputFile);
            out << protectedCode;
            std::cout << "Protected: " << inputFile << " -> " << outputFile << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return 1;
        }
        return 0;
    }

    std::cout << "FLY Obfuscator on port " << PORT << std::endl;
    int serverFd = socket(AF_INET, SOCK_STREAM, 0);
    if (serverFd < 0) return 1;
    int opt = 1;
    setsockopt(serverFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);
    if (bind(serverFd, (sockaddr*)&addr, sizeof(addr)) < 0) { close(serverFd); return 1; }
    if (listen(serverFd, BACKLOG) < 0) { close(serverFd); return 1; }
    for (;;) {
        sockaddr_in clientAddr{};
        socklen_t len = sizeof(clientAddr);
        int clientFd = accept(serverFd, (sockaddr*)&clientAddr, &len);
        if (clientFd < 0) continue;
        handleClient(clientFd);
    }
}