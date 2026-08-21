#include "compiler.hpp"
#include "transformer.hpp"
#include "bytecode.hpp"
#include <arpa/inet.h>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
namespace
{
    constexpr int PORT = 10000;
    constexpr int BACKLOG = 32;
    // ------------------------------------------------------------
    // JSON
    // ------------------------------------------------------------
    std::string jsonEscape(
        const std::string& value
    )
    {
        std::string result;
        result.reserve(
            value.size() + 16
        );
        for (unsigned char c : value)
        {
            switch (c)
            {
                case '"':
                    result += "\\\"";
                    break;
                case '\\':
                    result += "\\\\";
                    break;
                case '\n':
                    result += "\\n";
                    break;
                case '\r':
                    result += "\\r";
                    break;
                case '\t':
                    result += "\\t";
                    break;
                case '\b':
                    result += "\\b";
                    break;
                case '\f':
                    result += "\\f";
                    break;
                default:
                {
                    if (c < 32)
                    {
                        result += ' ';
                    }
                    else
                    {
                        result +=
                            static_cast<char>(c);
                    }
                    break;
                }
            }
        }
        return result;
    }
    // ------------------------------------------------------------
    // HTML
    // ------------------------------------------------------------
    std::string html()
    {
        return R"HTML(
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta
    name="viewport"
    content="width=device-width,initial-scale=1"
>
<title>LuaProtecter</title>
<style>
* {
    box-sizing: border-box;
}
body {
    margin: 0;
    min-height: 100vh;
    background: #0b0d10;
    color: #f5f7fa;
    font-family: Arial, sans-serif;
}
.container {
    width: min(1100px, 94%);
    margin: 50px auto;
}
h1 {
    margin-bottom: 8px;
}
.subtitle {
    color: #9ca3af;
    margin-bottom: 30px;
}
.editor {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 18px;
}
.panel {
    background: #12161b;
    border: 1px solid #272d35;
    border-radius: 12px;
    overflow: hidden;
}
.panel-title {
    padding: 13px 16px;
    border-bottom: 1px solid #272d35;
    color: #cbd5e1;
}
textarea {
    width: 100%;
    min-height: 500px;
    resize: vertical;
    border: 0;
    outline: 0;
    padding: 18px;
    background: #0f1317;
    color: #e5e7eb;
    font-family: monospace;
    font-size: 14px;
}
pre {
    margin: 0;
    min-height: 500px;
    padding: 18px;
    overflow: auto;
    white-space: pre-wrap;
    word-break: break-word;
    color: #dbeafe;
    font-family: monospace;
    font-size: 14px;
}
.controls {
    margin-top: 18px;
}
button {
    border: 0;
    border-radius: 8px;
    padding: 12px 20px;
    cursor: pointer;
    background: #6366f1;
    color: white;
    font-weight: 700;
}
button:disabled {
    opacity: .5;
    cursor: wait;
}
.status {
    margin-top: 12px;
    color: #9ca3af;
}
@media (max-width: 800px)
{
    .editor {
        grid-template-columns: 1fr;
    }
}
</style>
</head>
<body>
<div class="container">
    <h1>LuaProtecter</h1>
    <div class="subtitle">
        Luau source transformer
    </div>
    <div class="editor">
        <div class="panel">
            <div class="panel-title">
                Input
            </div>
            <textarea
                id="source"
                placeholder="Paste Luau here..."
            ></textarea>
        </div>
        <div class="panel">
            <div class="panel-title">
                Output
            </div>
            <pre id="output"></pre>
        </div>
    </div>
    <div class="controls">
        <button
            id="protect"
            onclick="protectSource()"
        >
            Obfuscate
        </button>
        <div
            class="status"
            id="status"
        ></div>
    </div>
</div>
<script>
async function protectSource()
{
    const source =
        document.getElementById(
            "source"
        ).value;
    const output =
        document.getElementById(
            "output"
        );
    const status =
        document.getElementById(
            "status"
        );
    const button =
        document.getElementById(
            "protect"
        );
    if (!source.trim())
    {
        status.textContent =
            "Enter Luau source first.";
        return;
    }
    button.disabled = true;
    status.textContent =
        "Compiling and protecting...";
    output.textContent = "";
    try
    {
        const response =
            await fetch(
                "/protect",
                {
                    method: "POST",
                    headers:
                    {
                        "Content-Type":
                            "application/json"
                    },
                    body:
                        JSON.stringify(
                            {
                                source: source
                            }
                        )
                }
            );
        const data =
            await response.json();
        if (
            !response.ok ||
            !data.success
        )
        {
            throw new Error(
                data.error ||
                "Protection failed"
            );
        }
        output.textContent =
            data.output;
        status.textContent =
            "Successfully protected.";
    }
    catch (error)
    {
        status.textContent =
            error.message;
        output.textContent = "";
    }
    finally
    {
        button.disabled = false;
    }
}
</script>
</body>
</html>
)HTML";
    }
    // ------------------------------------------------------------
    // HTTP header helper
    // ------------------------------------------------------------
    std::string findHeader(
        const std::string& request,
        const std::string& name
    )
    {
        const std::string needle =
            name + ":";
        const std::size_t position =
            request.find(
                needle
            );
        if (
            position ==
            std::string::npos
        )
        {
            return {};
        }
        const std::size_t start =
            position +
            needle.size();
        std::size_t end =
            request.find(
                "\r\n",
                start
            );
        if (
            end ==
            std::string::npos
        )
        {
            end =
                request.size();
        }
        std::string value =
            request.substr(
                start,
                end - start
            );
        while (
            !value.empty() &&
            value.front() == ' '
        )
        {
            value.erase(
                value.begin()
            );
        }
        return value;
    }
    // ------------------------------------------------------------
    // JSON source extraction
    // ------------------------------------------------------------
    std::string extractJsonSource(
        const std::string& body
    )
    {
        const std::string key =
            "\"source\"";
        const std::size_t keyPos =
            body.find(
                key
            );
        if (
            keyPos ==
            std::string::npos
        )
        {
            throw std::runtime_error(
                "Missing source field"
            );
        }
        const std::size_t colon =
            body.find(
                ':',
                keyPos + key.size()
            );
        if (
            colon ==
            std::string::npos
        )
        {
            throw std::runtime_error(
                "Invalid JSON"
            );
        }
        std::size_t position =
            colon + 1;
        while (
            position < body.size() &&
            (
                body[position] == ' ' ||
                body[position] == '\t' ||
                body[position] == '\r' ||
                body[position] == '\n'
            )
        )
        {
            ++position;
        }
        if (
            position >= body.size() ||
            body[position] != '"'
        )
        {
            throw std::runtime_error(
                "source must be a JSON string"
            );
        }
        ++position;
        std::string result;
        bool escaped = false;
        while (
            position < body.size()
        )
        {
            const char c =
                body[position++];
            if (escaped)
            {
                switch (c)
                {
                    case '"':
                        result += '"';
                        break;
                    case '\\':
                        result += '\\';
                        break;
                    case '/':
                        result += '/';
                        break;
                    case 'n':
                        result += '\n';
                        break;
                    case 'r':
                        result += '\r';
                        break;
                    case 't':
                        result += '\t';
                        break;
                    case 'b':
                        result += '\b';
                        break;
                    case 'f':
                        result += '\f';
                        break;
                    default:
                        result += c;
                        break;
                }
                escaped = false;
                continue;
            }
            if (c == '\\')
            {
                escaped = true;
                continue;
            }
            if (c == '"')
            {
                return result;
            }
            result += c;
        }
        throw std::runtime_error(
            "Unterminated JSON string"
        );
    }
    // ------------------------------------------------------------
    // Protected bytecode → readable-safe textual representation
    //
    // This is deliberately NOT Base64.
    //
    // It produces Lua decimal byte values:
    //
    // {76,80,82,...}
    //
    // The actual executable wrapper/decryption stage belongs in
    // Transformer. main.cpp should not duplicate that logic.
    // ------------------------------------------------------------
    std::string bytesAsDecimal(
        const Bytecode& bytecode
    )
    {
        const auto& bytes =
            bytecode.data();
        std::ostringstream result;
        result
            << "{";
        for (
            std::size_t i = 0;
            i < bytes.size();
            ++i
        )
        {
            if (i != 0)
                result << ",";
            result
                << static_cast<unsigned int>(
                    bytes[i]
                );
        }
        result
            << "}";
        return result.str();
    }
    // ------------------------------------------------------------
    // HTTP response
    // ------------------------------------------------------------
    void sendResponse(
        int client,
        int status,
        const std::string& contentType,
        const std::string& body
    )
    {
        std::ostringstream response;
        response
            << "HTTP/1.1 "
            << status
            << (
                status == 200
                    ? " OK"
                    : " Bad Request"
            )
            << "\r\n";
        response
            << "Content-Type: "
            << contentType
            << "\r\n";
        response
            << "Content-Length: "
            << body.size()
            << "\r\n";
        response
            << "Access-Control-Allow-Origin: *\r\n";
        response
            << "Access-Control-Allow-Headers: Content-Type\r\n";
        response
            << "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n";
        response
            << "Connection: close\r\n";
        response
            << "\r\n";
        response
            << body;
        const std::string data =
            response.str();
        std::size_t sent = 0;
        while (
            sent < data.size()
        )
        {
            const ssize_t count =
                send(
                    client,
                    data.data() + sent,
                    data.size() - sent,
                    0
                );
            if (count <= 0)
                break;
            sent +=
                static_cast<std::size_t>(
                    count
                );
        }
    }
    // ------------------------------------------------------------
    // Client
    // ------------------------------------------------------------
    void handleClient(
        int client,
        const Compiler& compiler,
        const Transformer& transformer
    )
    {
        std::string request;
        char buffer[8192];
        while (true)
        {
            const ssize_t count =
                recv(
                    client,
                    buffer,
                    sizeof(buffer),
                    0
                );
            if (count <= 0)
                break;
            request.append(
                buffer,
                static_cast<std::size_t>(
                    count
                )
            );
            /*
             * Once we have the HTTP headers we can inspect
             * Content-Length and continue receiving the body.
             */
            if (
                request.find(
                    "\r\n\r\n"
                ) != std::string::npos
            )
            {
                break;
            }
            if (
                request.size() >
                1024 * 1024
            )
            {
                break;
            }
        }
        const std::size_t headerEnd =
            request.find(
                "\r\n\r\n"
            );
        if (
            headerEnd ==
            std::string::npos
        )
        {
            sendResponse(
                client,
                400,
                "application/json",
                R"({"success":false,"error":"Invalid HTTP request"})"
            );
            return;
        }
        const std::string headers =
            request.substr(
                0,
                headerEnd
            );
        std::string body =
            request.substr(
                headerEnd + 4
            );
        std::istringstream requestLine(
            headers
        );
        std::string method;
        std::string path;
        std::string version;
        requestLine
            >> method
            >> path
            >> version;
        const std::string contentLengthHeader =
            findHeader(
                headers,
                "Content-Length"
            );
        std::size_t contentLength = 0;
        if (
            !contentLengthHeader.empty()
        )
        {
            try
            {
                contentLength =
                    static_cast<std::size_t>(
                        std::stoull(
                            contentLengthHeader
                        )
                    );
            }
            catch (...)
            {
                sendResponse(
                    client,
                    400,
                    "application/json",
                    R"({"success":false,"error":"Invalid Content-Length"})"
                );
                return;
            }
        }
        /*
         * Limit incoming request bodies.
         */
        constexpr std::size_t MAX_BODY =
            4 * 1024 * 1024;
        if (
            contentLength >
            MAX_BODY
        )
        {
            sendResponse(
                client,
                400,
                "application/json",
                R"({"success":false,"error":"Request body too large"})"
            );
            return;
        }
        while (
            body.size() <
            contentLength
        )
        {
            const ssize_t count =
                recv(
                    client,
                    buffer,
                    sizeof(buffer),
                    0
                );
            if (count <= 0)
                break;
            body.append(
                buffer,
                static_cast<std::size_t>(
                    count
                )
            );
        }
        // --------------------------------------------------------
        // GET /
        // --------------------------------------------------------
        if (
            method == "GET" &&
            path == "/"
        )
        {
            sendResponse(
                client,
                200,
                "text/html; charset=utf-8",
                html()
            );
            return;
        }
        // --------------------------------------------------------
        // GET /health
        // --------------------------------------------------------
        if (
            method == "GET" &&
            path == "/health"
        )
        {
            sendResponse(
                client,
                200,
                "application/json",
                R"({"success":true,"service":"luaProtecter","luau":true})"
            );
            return;
        }
        // --------------------------------------------------------
        // OPTIONS
        // --------------------------------------------------------
        if (
            method == "OPTIONS"
        )
        {
            sendResponse(
                client,
                200,
                "text/plain",
                ""
            );
            return;
        }
        // --------------------------------------------------------
        // POST /protect
        // --------------------------------------------------------
        if (
            method == "POST" &&
            path == "/protect"
        )
        {
            try
            {
                const std::string source =
                    extractJsonSource(
                        body
                    );
                if (
                    source.empty()
                )
                {
                    throw std::runtime_error(
                        "Source cannot be empty"
                    );
                }
                /*
                 * ------------------------------------------------
                 * STEP 1
                 *
                 * Compile the user's Luau using the real Luau
                 * compiler already stored in third_party/luau.
                 * ------------------------------------------------
                 */
                const Bytecode compiled =
                    compiler.compile(
                        source
                    );
                if (
                    compiled.empty()
                )
                {
                    throw std::runtime_error(
                        "Luau compiler produced empty bytecode"
                    );
                }
                /*
                 * ------------------------------------------------
                 * STEP 2
                 *
                 * Pass REAL Luau bytecode into Transformer.
                 * ------------------------------------------------
                 */
                const Bytecode protectedBytecode =
                    transformer.protect(
                        compiled
                    );
                if (
                    protectedBytecode.empty()
                )
                {
                    throw std::runtime_error(
                        "Transformer produced empty output"
                    );
                }
                /*
                 * ------------------------------------------------
                 * STEP 3
                 *
                 * For now return the protected binary as decimal
                 * byte values rather than Base64.
                 *
                 * IMPORTANT:
                 *
                 * This is a representation of the protected
                 * package. It is not itself a valid Luau program.
                 *
                 * The next Transformer layer should generate the
                 * executable Lua wrapper around these bytes.
                 * ------------------------------------------------
                 */
                const std::string output =
                    bytesAsDecimal(
                        protectedBytecode
                    );
                const std::string json =
                    std::string(
                        R"({"success":true,"output":")"
                    )
                    +
                    jsonEscape(
                        output
                    )
                    +
                    "\"}";
                sendResponse(
                    client,
                    200,
                    "application/json",
                    json
                );
                return;
            }
            catch (
                const std::exception& error
            )
            {
                const std::string json =
                    std::string(
                        R"({"success":false,"error":")"
                    )
                    +
                    jsonEscape(
                        error.what()
                    )
                    +
                    "\"}";
                sendResponse(
                    client,
                    400,
                    "application/json",
                    json
                );
                return;
            }
        }
        // --------------------------------------------------------
        // 404
        // --------------------------------------------------------
        sendResponse(
            client,
            404,
            "application/json",
            R"({"success":false,"error":"Not found"})"
        );
    }
}
// ================================================================
// MAIN
// ================================================================
int main()
{
    std::signal(
        SIGPIPE,
        SIG_IGN
    );
    const int server =
        socket(
            AF_INET,
            SOCK_STREAM,
            0
        );
    if (
        server < 0
    )
    {
        std::cerr
            << "socket() failed: "
            << std::strerror(errno)
            << '\n';
        return 1;
    }
    int reuse = 1;
    setsockopt(
        server,
        SOL_SOCKET,
        SO_REUSEADDR,
        &reuse,
        sizeof(reuse)
    );
    sockaddr_in address{};
    address.sin_family =
        AF_INET;
    address.sin_addr.s_addr =
        htonl(
            INADDR_ANY
        );
    address.sin_port =
        htons(
            PORT
        );
    if (
        bind(
            server,
            reinterpret_cast<sockaddr*>(
                &address
            ),
            sizeof(address)
        ) < 0
    )
    {
        std::cerr
            << "bind() failed: "
            << std::strerror(errno)
            << '\n';
        close(server);
        return 1;
    }
    if (
        listen(
            server,
            BACKLOG
        ) < 0
    )
    {
        std::cerr
            << "listen() failed: "
            << std::strerror(errno)
            << '\n';
        close(server);
        return 1;
    }
    std::cout
        << "LuaProtecter listening on port "
        << PORT
        << '\n';
    Compiler compiler;
    Transformer transformer;
    while (true)
    {
        sockaddr_in clientAddress{};
        socklen_t clientLength =
            sizeof(clientAddress);
        const int client =
            accept(
                server,
                reinterpret_cast<sockaddr*>(
                    &clientAddress
                ),
                &clientLength
            );
        if (
            client < 0
        )
        {
            if (
                errno == EINTR
            )
            {
                continue;
            }
            std::cerr
                << "accept() failed: "
                << std::strerror(errno)
                << '\n';
            continue;
        }
        handleClient(
            client,
            compiler,
            transformer
        );
        close(client);
    }
    close(server);
    return 0;
}