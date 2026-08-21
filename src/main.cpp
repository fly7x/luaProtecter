#include "bytecode.hpp"
#include "compiler.hpp"
#include "transformer.hpp"
#include "vm.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <limits>
#include <netinet/in.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

namespace
{
    constexpr std::size_t MAX_REQUEST_SIZE =
        4 * 1024 * 1024;

    constexpr int DEFAULT_PORT = 10000;

    // ---------------------------------------------------------
    // File helpers
    // ---------------------------------------------------------

    std::string readFile(
        const std::string& path
    )
    {
        std::ifstream file(
            path,
            std::ios::binary
        );

        if (!file)
            return {};

        std::ostringstream buffer;

        buffer << file.rdbuf();

        return buffer.str();
    }

    // ---------------------------------------------------------
    // JSON escaping
    // ---------------------------------------------------------

    std::string jsonEscape(
        const std::string& value
    )
    {
        std::string result;

        result.reserve(
            value.size() + 32
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

                case '\b':
                    result += "\\b";
                    break;

                case '\f':
                    result += "\\f";
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

                default:
                {
                    if (c < 0x20)
                    {
                        constexpr char hex[] =
                            "0123456789abcdef";

                        result += "\\u00";

                        result +=
                            hex[(c >> 4) & 0x0F];

                        result +=
                            hex[c & 0x0F];
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

    // ---------------------------------------------------------
    // JSON string extraction
    // ---------------------------------------------------------

    bool extractJsonString(
        const std::string& json,
        const std::string& key,
        std::string& output
    )
    {
        const std::string search =
            "\"" + key + "\"";

        const std::size_t keyPosition =
            json.find(search);

        if (
            keyPosition ==
            std::string::npos
        )
        {
            return false;
        }

        const std::size_t colon =
            json.find(
                ':',
                keyPosition + search.size()
            );

        if (
            colon ==
            std::string::npos
        )
        {
            return false;
        }

        std::size_t start =
            colon + 1;

        while (
            start < json.size() &&
            std::isspace(
                static_cast<unsigned char>(
                    json[start]
                )
            )
        )
        {
            ++start;
        }

        if (
            start >= json.size() ||
            json[start] != '"'
        )
        {
            return false;
        }

        ++start;

        std::string result;

        bool escaped = false;

        for (
            std::size_t i = start;
            i < json.size();
            ++i
        )
        {
            const char c =
                json[i];

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

                    case 'b':
                        result += '\b';
                        break;

                    case 'f':
                        result += '\f';
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

                    case 'u':
                    {
                        if (
                            i + 4 >=
                            json.size()
                        )
                        {
                            return false;
                        }

                        unsigned int value = 0;

                        for (
                            int j = 1;
                            j <= 4;
                            ++j
                        )
                        {
                            const char h =
                                json[i + j];

                            value <<= 4;

                            if (
                                h >= '0' &&
                                h <= '9'
                            )
                            {
                                value +=
                                    h - '0';
                            }
                            else if (
                                h >= 'a' &&
                                h <= 'f'
                            )
                            {
                                value +=
                                    h - 'a' + 10;
                            }
                            else if (
                                h >= 'A' &&
                                h <= 'F'
                            )
                            {
                                value +=
                                    h - 'A' + 10;
                            }
                            else
                            {
                                return false;
                            }
                        }

                        if (value <= 0x7F)
                        {
                            result +=
                                static_cast<char>(
                                    value
                                );
                        }
                        else if (
                            value <= 0x7FF
                        )
                        {
                            result +=
                                static_cast<char>(
                                    0xC0 |
                                    (value >> 6)
                                );

                            result +=
                                static_cast<char>(
                                    0x80 |
                                    (value & 0x3F)
                                );
                        }
                        else
                        {
                            result +=
                                static_cast<char>(
                                    0xE0 |
                                    (value >> 12)
                                );

                            result +=
                                static_cast<char>(
                                    0x80 |
                                    ((value >> 6) &
                                     0x3F)
                                );

                            result +=
                                static_cast<char>(
                                    0x80 |
                                    (value & 0x3F)
                                );
                        }

                        i += 4;

                        break;
                    }

                    default:
                        result += '\\';
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
                output = result;

                return true;
            }

            result += c;
        }

        return false;
    }

    // ---------------------------------------------------------
    // HTTP helpers
    // ---------------------------------------------------------

    void sendAll(
        int client,
        const std::string& data
    )
    {
        std::size_t sent = 0;

        while (sent < data.size())
        {
            const ssize_t count =
                send(
                    client,
                    data.data() + sent,
                    data.size() - sent,
                    0
                );

            if (count <= 0)
                return;

            sent +=
                static_cast<std::size_t>(
                    count
                );
        }
    }

    void sendResponse(
        int client,
        int status,
        const std::string& contentType,
        const std::string& body
    )
    {
        const char* statusText =
            "Unknown";

        switch (status)
        {
            case 200:
                statusText = "OK";
                break;

            case 400:
                statusText = "Bad Request";
                break;

            case 404:
                statusText = "Not Found";
                break;

            case 405:
                statusText = "Method Not Allowed";
                break;

            case 413:
                statusText = "Payload Too Large";
                break;

            case 422:
                statusText = "Unprocessable Entity";
                break;

            case 500:
                statusText = "Internal Server Error";
                break;
        }

        std::ostringstream response;

        response
            << "HTTP/1.1 "
            << status
            << " "
            << statusText
            << "\r\n"

            << "Content-Type: "
            << contentType
            << "\r\n"

            << "Content-Length: "
            << body.size()
            << "\r\n"

            << "Access-Control-Allow-Origin: *\r\n"
            << "Access-Control-Allow-Headers: Content-Type\r\n"
            << "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"

            << "Cache-Control: no-store\r\n"

            << "Connection: close\r\n"

            << "\r\n"

            << body;

        sendAll(
            client,
            response.str()
        );
    }

    bool parseContentLength(
        const std::string& headers,
        std::size_t& length
    )
    {
        const std::string key =
            "Content-Length:";

        const std::size_t position =
            headers.find(key);

        if (
            position ==
            std::string::npos
        )
        {
            length = 0;

            return true;
        }

        std::size_t start =
            position + key.size();

        while (
            start < headers.size() &&
            std::isspace(
                static_cast<unsigned char>(
                    headers[start]
                )
            )
        )
        {
            ++start;
        }

        std::size_t end = start;

        while (
            end < headers.size() &&
            std::isdigit(
                static_cast<unsigned char>(
                    headers[end]
                )
            )
        )
        {
            ++end;
        }

        if (end == start)
            return false;

        try
        {
            length =
                std::stoull(
                    headers.substr(
                        start,
                        end - start
                    )
                );
        }
        catch (...)
        {
            return false;
        }

        return true;
    }

    bool receiveRequest(
        int client,
        std::string& request
    )
    {
        char buffer[16384];

        while (
            request.find("\r\n\r\n") ==
            std::string::npos
        )
        {
            const ssize_t received =
                recv(
                    client,
                    buffer,
                    sizeof(buffer),
                    0
                );

            if (received <= 0)
                return false;

            request.append(
                buffer,
                static_cast<std::size_t>(
                    received
                )
            );

            if (
                request.size() >
                MAX_REQUEST_SIZE
            )
            {
                return false;
            }
        }

        return true;
    }

    // ---------------------------------------------------------
    // Client handler
    // ---------------------------------------------------------

    void handleClient(
        int client
    )
    {
        std::string request;

        if (
            !receiveRequest(
                client,
                request
            )
        )
        {
            sendResponse(
                client,
                413,
                "application/json; charset=utf-8",
                "{\"success\":false,\"error\":\"Request too large\"}"
            );

            close(client);

            return;
        }

        const std::size_t headerEnd =
            request.find("\r\n\r\n");

        if (
            headerEnd ==
            std::string::npos
        )
        {
            sendResponse(
                client,
                400,
                "application/json; charset=utf-8",
                "{\"success\":false,\"error\":\"Malformed HTTP request\"}"
            );

            close(client);

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

        std::istringstream headerStream(
            headers
        );

        std::string method;
        std::string path;
        std::string version;

        headerStream
            >> method
            >> path
            >> version;

        if (
            method.empty() ||
            path.empty()
        )
        {
            sendResponse(
                client,
                400,
                "application/json; charset=utf-8",
                "{\"success\":false,\"error\":\"Invalid HTTP request\"}"
            );

            close(client);

            return;
        }

        // -----------------------------------------------------
        // CORS preflight
        // -----------------------------------------------------

        if (method == "OPTIONS")
        {
            sendResponse(
                client,
                200,
                "text/plain; charset=utf-8",
                ""
            );

            close(client);

            return;
        }

        // -----------------------------------------------------
        // Content length
        // -----------------------------------------------------

        std::size_t contentLength = 0;

        if (
            !parseContentLength(
                headers,
                contentLength
            )
        )
        {
            sendResponse(
                client,
                400,
                "application/json; charset=utf-8",
                "{\"success\":false,\"error\":\"Invalid Content-Length\"}"
            );

            close(client);

            return;
        }

        if (
            contentLength >
            MAX_REQUEST_SIZE
        )
        {
            sendResponse(
                client,
                413,
                "application/json; charset=utf-8",
                "{\"success\":false,\"error\":\"Payload too large\"}"
            );

            close(client);

            return;
        }

        // -----------------------------------------------------
        // Receive remaining body
        // -----------------------------------------------------

        char buffer[16384];

        while (
            body.size() <
            contentLength
        )
        {
            const ssize_t received =
                recv(
                    client,
                    buffer,
                    sizeof(buffer),
                    0
                );

            if (received <= 0)
                break;

            body.append(
                buffer,
                static_cast<std::size_t>(
                    received
                )
            );

            if (
                body.size() >
                MAX_REQUEST_SIZE
            )
            {
                sendResponse(
                    client,
                    413,
                    "application/json; charset=utf-8",
                    "{\"success\":false,\"error\":\"Payload too large\"}"
                );

                close(client);

                return;
            }
        }

        if (
            contentLength > 0 &&
            body.size() < contentLength
        )
        {
            sendResponse(
                client,
                400,
                "application/json; charset=utf-8",
                "{\"success\":false,\"error\":\"Incomplete request body\"}"
            );

            close(client);

            return;
        }

        if (
            contentLength > 0 &&
            body.size() > contentLength
        )
        {
            body.resize(
                contentLength
            );
        }

        // -----------------------------------------------------
        // GET /
        // -----------------------------------------------------

        if (
            method == "GET" &&
            path == "/"
        )
        {
            const std::string html =
                readFile(
                    "web/index.html"
                );

            if (html.empty())
            {
                sendResponse(
                    client,
                    500,
                    "text/plain; charset=utf-8",
                    "web/index.html not found"
                );
            }
            else
            {
                sendResponse(
                    client,
                    200,
                    "text/html; charset=utf-8",
                    html
                );
            }

            close(client);

            return;
        }

        // -----------------------------------------------------
        // GET /style.css
        // -----------------------------------------------------

        if (
            method == "GET" &&
            path == "/style.css"
        )
        {
            const std::string css =
                readFile(
                    "web/style.css"
                );

            if (css.empty())
            {
                sendResponse(
                    client,
                    404,
                    "text/plain; charset=utf-8",
                    "style.css not found"
                );
            }
            else
            {
                sendResponse(
                    client,
                    200,
                    "text/css; charset=utf-8",
                    css
                );
            }

            close(client);

            return;
        }

        // -----------------------------------------------------
        // GET /app.js
        // -----------------------------------------------------

        if (
            method == "GET" &&
            path == "/app.js"
        )
        {
            const std::string js =
                readFile(
                    "web/app.js"
                );

            if (js.empty())
            {
                sendResponse(
                    client,
                    404,
                    "text/plain; charset=utf-8",
                    "app.js not found"
                );
            }
            else
            {
                sendResponse(
                    client,
                    200,
                    "application/javascript; charset=utf-8",
                    js
                );
            }

            close(client);

            return;
        }

        // -----------------------------------------------------
        // GET /health
        // -----------------------------------------------------

        if (
            method == "GET" &&
            path == "/health"
        )
        {
            sendResponse(
                client,
                200,
                "application/json; charset=utf-8",
                "{\"status\":\"ok\"}"
            );

            close(client);

            return;
        }

        // -----------------------------------------------------
        // POST /api/compile
        //
        // Luau source
        //      ↓
        // Compiler
        //      ↓
        // custom Bytecode
        //      ↓
        // Base64
        // -----------------------------------------------------

        if (
            method == "POST" &&
            path == "/api/compile"
        )
        {
            std::string source;

            if (
                !extractJsonString(
                    body,
                    "code",
                    source
                )
            )
            {
                sendResponse(
                    client,
                    400,
                    "application/json; charset=utf-8",
                    "{\"success\":false,\"error\":\"Missing code field\"}"
                );

                close(client);

                return;
            }

            if (source.empty())
            {
                sendResponse(
                    client,
                    400,
                    "application/json; charset=utf-8",
                    "{\"success\":false,\"error\":\"Code cannot be empty\"}"
                );

                close(client);

                return;
            }

            try
            {
                Compiler compiler;

                const Bytecode bytecode =
                    compiler.compile(
                        source
                    );

                if (bytecode.empty())
                {
                    throw std::runtime_error(
                        "Compiler produced empty bytecode"
                    );
                }

                const std::string encoded =
                    bytecode.toBase64();

                const std::string response =
                    "{\"success\":true,"
                    "\"bytecode\":\"" +
                    jsonEscape(encoded) +
                    "\","
                    "\"size\":" +
                    std::to_string(
                        bytecode.size()
                    ) +
                    "}";

                sendResponse(
                    client,
                    200,
                    "application/json; charset=utf-8",
                    response
                );
            }
            catch (
                const std::exception& exception
            )
            {
                const std::string response =
                    "{\"success\":false,"
                    "\"error\":\"" +
                    jsonEscape(
                        exception.what()
                    ) +
                    "\"}";

                sendResponse(
                    client,
                    422,
                    "application/json; charset=utf-8",
                    response
                );
            }
            catch (...)
            {
                sendResponse(
                    client,
                    500,
                    "application/json; charset=utf-8",
                    "{\"success\":false,\"error\":\"Unknown compiler failure\"}"
                );
            }

            close(client);

            return;
        }

        // -----------------------------------------------------
        // POST /api/obfuscate
        //
        // Luau source
        //      ↓
        // Compiler
        //      ↓
        // Bytecode
        //      ↓
        // Transformer::protect(Bytecode)
        //      ↓
        // Protected Bytecode
        //      ↓
        // Base64
        // -----------------------------------------------------

        if (
            method == "POST" &&
            path == "/api/obfuscate"
        )
        {
            std::string source;

            if (
                !extractJsonString(
                    body,
                    "code",
                    source
                )
            )
            {
                sendResponse(
                    client,
                    400,
                    "application/json; charset=utf-8",
                    "{\"success\":false,\"error\":\"Missing code field\"}"
                );

                close(client);

                return;
            }

            if (source.empty())
            {
                sendResponse(
                    client,
                    400,
                    "application/json; charset=utf-8",
                    "{\"success\":false,\"error\":\"Code cannot be empty\"}"
                );

                close(client);

                return;
            }

            try
            {
                // ---------------------------------------------
                // Compile source
                // ---------------------------------------------

                Compiler compiler;

                const Bytecode bytecode =
                    compiler.compile(
                        source
                    );

                if (bytecode.empty())
                {
                    throw std::runtime_error(
                        "Compiler produced empty bytecode"
                    );
                }

                // ---------------------------------------------
                // Protect custom bytecode
                // ---------------------------------------------

                Transformer transformer;

                const Bytecode protectedBytecode =
                    transformer.protect(
                        bytecode
                    );

                if (
                    protectedBytecode.empty()
                )
                {
                    throw std::runtime_error(
                        "Transformer produced empty package"
                    );
                }

                // ---------------------------------------------
                // Base64 for JSON transport
                // ---------------------------------------------

                const std::string encoded =
                    protectedBytecode.toBase64();

                const std::string response =
                    "{\"success\":true,"
                    "\"code\":\"" +
                    jsonEscape(encoded) +
                    "\","
                    "\"size\":" +
                    std::to_string(
                        protectedBytecode.size()
                    ) +
                    ","
                    "\"original_size\":" +
                    std::to_string(
                        bytecode.size()
                    ) +
                    "}";

                sendResponse(
                    client,
                    200,
                    "application/json; charset=utf-8",
                    response
                );
            }
            catch (
                const std::exception& exception
            )
            {
                const std::string response =
                    "{\"success\":false,"
                    "\"error\":\"" +
                    jsonEscape(
                        exception.what()
                    ) +
                    "\"}";

                sendResponse(
                    client,
                    422,
                    "application/json; charset=utf-8",
                    response
                );
            }
            catch (...)
            {
                sendResponse(
                    client,
                    500,
                    "application/json; charset=utf-8",
                    "{\"success\":false,\"error\":\"Unknown obfuscation failure\"}"
                );
            }

            close(client);

            return;
        }

        // -----------------------------------------------------
        // POST /api/execute
        //
        // This endpoint is kept separate from compilation.
        //
        // The exact VM::execute() signature determines how the
        // final execution call is wired.
        // -----------------------------------------------------

        if (
            method == "POST" &&
            path == "/api/execute"
        )
        {
            std::string source;

            if (
                !extractJsonString(
                    body,
                    "code",
                    source
                )
            )
            {
                sendResponse(
                    client,
                    400,
                    "application/json; charset=utf-8",
                    "{\"success\":false,\"error\":\"Missing code field\"}"
                );

                close(client);

                return;
            }

            if (source.empty())
            {
                sendResponse(
                    client,
                    400,
                    "application/json; charset=utf-8",
                    "{\"success\":false,\"error\":\"Code cannot be empty\"}"
                );

                close(client);

                return;
            }

            try
            {
                /*
                 * Compile the source into our custom VM format.
                 */
                Compiler compiler;

                const Bytecode bytecode =
                    compiler.compile(
                        source
                    );

                if (bytecode.empty())
                {
                    throw std::runtime_error(
                        "Compiler produced empty bytecode"
                    );
                }

                /*
                 * VM execution is intentionally kept behind
                 * VM::execute(). The implementation must match
                 * your current vm.hpp API.
                 *
                 * This endpoint can therefore be wired directly
                 * once that API is fixed.
                 */

                sendResponse(
                    client,
                    200,
                    "application/json; charset=utf-8",
                    "{\"success\":true,\"output\":\"Compiled successfully\"}"
                );
            }
            catch (
                const std::exception& exception
            )
            {
                const std::string response =
                    "{\"success\":false,"
                    "\"error\":\"" +
                    jsonEscape(
                        exception.what()
                    ) +
                    "\"}";

                sendResponse(
                    client,
                    422,
                    "application/json; charset=utf-8",
                    response
                );
            }
            catch (...)
            {
                sendResponse(
                    client,
                    500,
                    "application/json; charset=utf-8",
                    "{\"success\":false,\"error\":\"Unknown VM failure\"}"
                );
            }

            close(client);

            return;
        }

        // -----------------------------------------------------
        // Unsupported method
        // -----------------------------------------------------

        if (
            method != "GET" &&
            method != "POST"
        )
        {
            sendResponse(
                client,
                405,
                "application/json; charset=utf-8",
                "{\"success\":false,\"error\":\"Method not allowed\"}"
            );

            close(client);

            return;
        }

        // -----------------------------------------------------
        // 404
        // -----------------------------------------------------

        sendResponse(
            client,
            404,
            "application/json; charset=utf-8",
            "{\"success\":false,\"error\":\"Not found\"}"
        );

        close(client);
    }
}

// -------------------------------------------------------------
// Main
// -------------------------------------------------------------

int main()
{
    const char* portEnvironment =
        std::getenv("PORT");

    int port =
        DEFAULT_PORT;

    if (portEnvironment)
    {
        try
        {
            const int parsed =
                std::stoi(
                    portEnvironment
                );

            if (
                parsed > 0 &&
                parsed <= 65535
            )
            {
                port = parsed;
            }
        }
        catch (...)
        {
            port = DEFAULT_PORT;
        }
    }

    // ---------------------------------------------------------
    // Create socket
    // ---------------------------------------------------------

    const int server =
        socket(
            AF_INET,
            SOCK_STREAM,
            0
        );

    if (server < 0)
    {
        std::cerr
            << "Failed to create socket: "
            << strerror(errno)
            << '\n';

        return 1;
    }

    // ---------------------------------------------------------
    // Reuse address
    // ---------------------------------------------------------

    int reuse = 1;

    if (
        setsockopt(
            server,
            SOL_SOCKET,
            SO_REUSEADDR,
            &reuse,
            sizeof(reuse)
        ) < 0
    )
    {
        std::cerr
            << "Warning: SO_REUSEADDR failed: "
            << strerror(errno)
            << '\n';
    }

    // ---------------------------------------------------------
    // Bind
    // ---------------------------------------------------------

    sockaddr_in address{};

    address.sin_family =
        AF_INET;

    address.sin_addr.s_addr =
        htonl(INADDR_ANY);

    address.sin_port =
        htons(
            static_cast<std::uint16_t>(
                port
            )
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
            << "Failed to bind port "
            << port
            << ": "
            << strerror(errno)
            << '\n';

        close(server);

        return 1;
    }

    // ---------------------------------------------------------
    // Listen
    // ---------------------------------------------------------

    if (
        listen(
            server,
            64
        ) < 0
    )
    {
        std::cerr
            << "Failed to listen: "
            << strerror(errno)
            << '\n';

        close(server);

        return 1;
    }

    std::cout
        << "luaProtecter listening on port "
        << port
        << '\n';

    // ---------------------------------------------------------
    // Accept loop
    // ---------------------------------------------------------

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

        if (client < 0)
        {
            if (errno == EINTR)
                continue;

            std::cerr
                << "accept() failed: "
                << strerror(errno)
                << '\n';

            continue;
        }

        handleClient(
            client
        );
    }

    close(server);

    return 0;
}