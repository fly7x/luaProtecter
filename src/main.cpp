#include "transformer.hpp"
#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sstream>

namespace {
    constexpr int PORT = 10000;
    constexpr int BACKLOG = 32;
    
    std::string jsonEscape(const std::string& value) {
        std::string result;
        result.reserve(value.size() + 16);
        for (unsigned char c : value) {
            switch (c) {
                case '"': result += "\\\""; break;
                case '\\': result += "\\\\"; break;
                case '\n': result += "\\n"; break;
                case '\r': result += "\\r"; break;
                case '\t': result += "\\t"; break;
                case '\b': result += "\\b"; break;
                case '\f': result += "\\f"; break;
                default:
                    if (c < 32) {
                        result += ' ';
                    } else {
                        result += static_cast<char>(c);
                    }
                    break;
            }
        }
        return result;
    }
    
    std::string html() {
        return R"HTML(<!DOCTYPE html>
<html>
<head>
    <title>LuaProtecter</title>
    <style>
        body { font-family: monospace; max-width: 900px; margin: 40px auto; padding: 20px; background: #0d1117; color: #c9d1d9; }
        h1 { color: #58a6ff; }
        textarea { width: 100%; padding: 12px; font-family: monospace; font-size: 14px; background: #161b22; color: #c9d1d9; border: 1px solid #30363d; border-radius: 6px; resize: vertical; }
        textarea:focus { outline: none; border-color: #58a6ff; }
        .row { display: flex; gap: 20px; margin: 20px 0; flex-wrap: wrap; }
        .col { flex: 1; min-width: 300px; }
        .controls { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; margin: 10px 0; }
        .controls label { display: flex; align-items: center; gap: 5px; font-size: 13px; }
        button { padding: 10px 24px; font-size: 14px; font-weight: bold; border: none; border-radius: 6px; cursor: pointer; background: #238636; color: white; transition: 0.2s; }
        button:hover { background: #2ea043; }
        button:disabled { opacity: 0.5; cursor: not-allowed; }
        button.secondary { background: #21262d; color: #c9d1d9; }
        button.secondary:hover { background: #30363d; }
        .status { font-size: 13px; color: #8b949e; margin-top: 8px; }
        .hidden { display: none; }
        .spinner { display: inline-block; width: 16px; height: 16px; border: 2px solid #30363d; border-top-color: #58a6ff; border-radius: 50%; animation: spin 0.6s linear infinite; }
        @keyframes spin { to { transform: rotate(360deg); } }
        .flex { display: flex; align-items: center; gap: 12px; }
    </style>
</head>
<body>
    <h1>🔒 LuaProtecter</h1>
    <p>Luau source transformer with VM-level obfuscation</p>
    
    <div class="row">
        <div class="col">
            <h3>Input</h3>
            <textarea id="source" rows="12" placeholder="Paste your Luau source code here...">local function greet(name) print("Hello, " .. name .. "!") end greet("World")</textarea>
        </div>
        <div class="col">
            <h3>Output</h3>
            <textarea id="output" rows="12" readonly placeholder="Protected code will appear here..."></textarea>
        </div>
    </div>
    
    <div class="controls">
        <label><input type="checkbox" id="rename" checked> Rename</label>
        <label><input type="checkbox" id="strings" checked> Strings</label>
        <label><input type="checkbox" id="constants" checked> Constants</label>
        <label><input type="checkbox" id="controlFlow" checked> Control Flow</label>
        <label><input type="checkbox" id="deadCode" checked> Dead Code</label>
        <label><input type="checkbox" id="vmMode" checked> VM Mode</label>
    </div>
    
    <div class="flex">
        <button id="protectButton"><span id="buttonText">⚡ Obfuscate</span><span id="spinner" class="spinner hidden"></span></button>
        <button id="clearButton" class="secondary">Clear</button>
        <button id="copyButton" class="secondary">Copy</button>
        <span id="outputStatus" class="status">Nothing generated yet</span>
    </div>
    
    <script src="/app.js"></script>
</body>
</html>)HTML";
    }
    
    std::string findHeader(const std::string& request, const std::string& name) {
        std::string needle = name + ":";
        size_t pos = request.find(needle);
        if (pos == std::string::npos) return {};
        
        size_t start = pos + needle.size();
        size_t end = request.find("\r\n", start);
        if (end == std::string::npos) end = request.size();
        
        std::string value = request.substr(start, end - start);
        while (!value.empty() && value.front() == ' ') {
            value.erase(value.begin());
        }
        return value;
    }
    
    std::string extractJsonSource(const std::string& body) {
        std::string key = "\"source\"";
        size_t keyPos = body.find(key);
        if (keyPos == std::string::npos) {
            throw std::runtime_error("Missing source field");
        }
        
        size_t colon = body.find(':', keyPos + key.size());
        if (colon == std::string::npos) {
            throw std::runtime_error("Invalid JSON");
        }
        
        size_t pos = colon + 1;
        while (pos < body.size() && (body[pos] == ' ' || body[pos] == '\t' || 
               body[pos] == '\r' || body[pos] == '\n')) {
            ++pos;
        }
        
        if (pos >= body.size() || body[pos] != '"') {
            throw std::runtime_error("source must be a JSON string");
        }
        
        ++pos;
        std::string result;
        bool escaped = false;
        
        while (pos < body.size()) {
            char c = body[pos++];
            if (escaped) {
                switch (c) {
                    case '"': result += '"'; break;
                    case '\\': result += '\\'; break;
                    case '/': result += '/'; break;
                    case 'n': result += '\n'; break;
                    case 'r': result += '\r'; break;
                    case 't': result += '\t'; break;
                    case 'b': result += '\b'; break;
                    case 'f': result += '\f'; break;
                    default: result += c; break;
                }
                escaped = false;
                continue;
            }
            if (c == '\\') {
                escaped = true;
                continue;
            }
            if (c == '"') {
                break;
            }
            result += c;
        }
        
        return result;
    }
    
    void handleClient(int clientFd) {
        char buffer[65536];
        ssize_t n = read(clientFd, buffer, sizeof(buffer) - 1);
        if (n <= 0) {
            close(clientFd);
            return;
        }
        buffer[n] = '\0';
        
        std::string request(buffer);
        std::string method = request.substr(0, request.find(' '));
        std::string path = request.substr(request.find(' ') + 1);
        path = path.substr(0, path.find(' '));
        
        std::string response;
        std::string contentType = "text/html";
        int statusCode = 200;
        
        try {
            if (path == "/" || path == "/index.html") {
                response = html();
                contentType = "text/html";
            } else if (path == "/app.js") {
                // Serve app.js from embedded string or file
                response = R"(const source = document.getElementById("source");
const output = document.getElementById("output");
const protectButton = document.getElementById("protectButton");
const clearButton = document.getElementById("clearButton");
const copyButton = document.getElementById("copyButton");
const buttonText = document.getElementById("buttonText");
const spinner = document.getElementById("spinner");
const outputStatus = document.getElementById("outputStatus");
const rename = document.getElementById("rename");
const strings = document.getElementById("strings");
const constants = document.getElementById("constants");
const controlFlow = document.getElementById("controlFlow");
const deadCode = document.getElementById("deadCode");
const vmMode = document.getElementById("vmMode");

clearButton.addEventListener("click", () => {
    source.value = "";
    output.value = "";
    outputStatus.textContent = "Nothing generated yet";
});

copyButton.addEventListener("click", async () => {
    if (!output.value) return;
    try {
        await navigator.clipboard.writeText(output.value);
        copyButton.textContent = "Copied";
        setTimeout(() => { copyButton.textContent = "Copy"; }, 1200);
    } catch {
        output.select();
        document.execCommand("copy");
        copyButton.textContent = "Copied";
        setTimeout(() => { copyButton.textContent = "Copy"; }, 1200);
    }
});

protectButton.addEventListener("click", async () => {
    const code = source.value;
    if (!code.trim()) {
        outputStatus.textContent = "Paste Luau code first";
        source.focus();
        return;
    }
    
    protectButton.disabled = true;
    buttonText.classList.add("hidden");
    spinner.classList.remove("hidden");
    outputStatus.textContent = "Protecting source...";
    
    try {
        const response = await fetch("/api/obfuscate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                code: code,
                options: {
                    rename: rename.checked,
                    strings: strings.checked,
                    constants: constants.checked,
                    controlFlow: controlFlow.checked,
                    deadCode: deadCode.checked,
                    vm: vmMode.checked
                }
            })
        });
        
        const data = await response.json();
        if (!response.ok || !data.success) {
            throw new Error(data.error || "Obfuscation failed");
        }
        output.value = data.code || "";
        outputStatus.textContent = "Protection complete";
    } catch (error) {
        output.value = "";
        outputStatus.textContent = error.message || "Request failed";
    } finally {
        protectButton.disabled = false;
        buttonText.classList.remove("hidden");
        spinner.classList.add("hidden");
    }
});)";
                contentType = "application/javascript";
            } else if (path == "/api/obfuscate" && method == "POST") {
                size_t bodyStart = request.find("\r\n\r\n");
                if (bodyStart == std::string::npos) {
                    throw std::runtime_error("Malformed request");
                }
                std::string body = request.substr(bodyStart + 4);
                
                std::string sourceCode = extractJsonSource(body);
                
                Transformer transformer;
                Transformer::Options opts;
                opts.renameIdentifiers = true;
                opts.encodeStrings = true;
                opts.encodeNumbers = true;
                opts.removeComments = true;
                opts.virtualize = true;
                opts.polymorphic = true;
                opts.decoys = true;
                
                std::string protectedCode = transformer.protect(sourceCode, opts);
                
                std::stringstream ss;
                ss << "{\"success\":true,\"code\":\"" << jsonEscape(protectedCode) << "\"}";
                response = ss.str();
                contentType = "application/json";
            } else {
                statusCode = 404;
                response = "404 Not Found";
                contentType = "text/plain";
            }
        } catch (const std::exception& e) {
            statusCode = 500;
            std::stringstream ss;
            ss << "{\"success\":false,\"error\":\"" << jsonEscape(e.what()) << "\"}";
            response = ss.str();
            contentType = "application/json";
        }
        
        std::stringstream responseStream;
        responseStream << "HTTP/1.1 " << statusCode << " OK\r\n";
        responseStream << "Content-Type: " << contentType << "\r\n";
        responseStream << "Content-Length: " << response.size() << "\r\n";
        responseStream << "Connection: close\r\n";
        responseStream << "\r\n";
        responseStream << response;
        
        std::string fullResponse = responseStream.str();
        write(clientFd, fullResponse.c_str(), fullResponse.size());
        close(clientFd);
    }
}

int main(int argc, char* argv[]) {
    // If command line arguments provided, process file
    if (argc >= 2) {
        std::string inputFile = argv[1];
        std::string outputFile = (argc >= 3) ? argv[2] : "output/protected.lua";
        
        std::ifstream in(inputFile);
        if (!in.is_open()) {
            std::cerr << "Failed to open input file: " << inputFile << std::endl;
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
                std::cerr << "Failed to open output file: " << outputFile << std::endl;
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
    
    // Otherwise run web server
    std::cout << "🔒 LuaProtecter Server starting on port " << PORT << "..." << std::endl;
    
    int serverFd = socket(AF_INET, SOCK_STREAM, 0);
    if (serverFd < 0) {
        std::cerr << "Failed to create socket" << std::endl;
        return 1;
    }
    
    int opt = 1;
    setsockopt(serverFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);
    
    if (bind(serverFd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "Failed to bind to port " << PORT << std::endl;
        close(serverFd);
        return 1;
    }
    
    if (listen(serverFd, BACKLOG) < 0) {
        std::cerr << "Failed to listen" << std::endl;
        close(serverFd);
        return 1;
    }
    
    std::cout << "🌐 Web interface: http://localhost:" << PORT << std::endl;
    std::cout << "Press Ctrl+C to stop" << std::endl;
    
    while (true) {
        struct sockaddr_in clientAddr;
        socklen_t clientLen = sizeof(clientAddr);
        int clientFd = accept(serverFd, (struct sockaddr*)&clientAddr, &clientLen);
        if (clientFd < 0) continue;
        handleClient(clientFd);
    }
    
    close(serverFd);
    return 0;
}