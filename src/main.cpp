#include "bytecode.hpp"
#include "transformer.hpp"
#include "vm.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <cctype>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <netinet/in.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

namespace
{
    constexpr std::size_t MAX_REQUEST_SIZE =
        4 * 1024 * 1024;

    constexpr int DEFAULT_PORT = 10000;

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

        std::ostringstream stream;
        stream << file.rdbuf();

        return stream.str();
    }

    std::string jsonEscape(
        const std::string& value
    )
    {
        std::string result;
        result.reserve(value.size() + 32);

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
                    if (c < 0x20)
                    {
                        static constexpr char hex[] =
                            "0123456789abcdef";

                        result += "\\u00";
                        result += hex[(c >> 4) & 0x0F];
                        result += hex[c & 0x0F];
                    }
                    else
                    {
                        result += static_cast<char>(c);
                    }
                    break;
            }
        }

        return result;
    }

    bool extractJsonString(
        const std::string& json,
        const std::string& key,
        std::string& output
    )
    {
        const std::string target =
            "\"" + key + "\"";

        const std::size_t keyPos =
            json.find(target);

        if (keyPos == std::string::npos)
            return false;

        const std::size_t colon =
            json.find(
                ':',
                keyPos + target.size()
            );

        if (colon == std::string::npos)
            return false;

        std::size_t start = colon + 1;

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
            const char c = json[i];

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
                        if (i + 4 >= json.size())
                            return false;

                        unsigned int value = 0;

                        for (int j = 1; j <= 4; ++j)
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
                                    static_cast<unsigned>(
                                        h - '0'
                                    );
                            }
                            else if (
                                h >= 'a' &&
                                h <= 'f'
                            )
                            {
                                value +=
                                    static_cast<unsigned>(
                                        h - 'a' + 10
                                    );
                            }
                            else if (
                                h >= 'A' &&
                                h <= 'F'
                            )
                            {
                                value +=
                                    static_cast<unsigned>(
                                        h - 'A' + 10
                                    );
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
                        else if (value <= 0x7FF)
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
                                    ((value >> 6) & 0x3F)
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
                        return false;
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

    void sendAll(
        int client,
        const std::string& data
    )
    {
        std::size_t offset = 0;

        while (offset < data.size())
        {
            const ssize_t sent =
                send(
                    client,
                    data.data() + offset,
                    data.size() - offset,
                    0
                );

            if (sent <= 0)
                return;

            offset +=
                static_cast<std::size_t>(
                    sent
                );
        }
    }

    void sendResponse(
        int client,
        int status,
        const std::string& type,
        const std::string& body
    )
    {
        const char* text = "Unknown";

        switch (status)
        {
            case 200:
                text = "OK";
                break;

            case 400:
                text = "Bad Request";
                break;

            case 404:
                text = "Not Found";
                break;

            case 405:
                text = "Method Not Allowed";
                break;

            case 413:
                text = "Payload Too Large";
                break;

            case 422:
                text = "Unprocessable Entity";
                break;

            case 500:
                text = "Internal Server Error";
                break;
        }

        std::ostringstream response;

        response
            << "HTTP/1.1 "
            << status
            << " "
            << text
            << "\r\n"
            << "Content-Type: "
            << type
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

    void handleClient(int client)
    {
        std::string request;

        if (!receiveRequest(client, request))
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

        if (headerEnd == std::string::npos)
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

        std::istringstream stream(headers);

        std::string method;
        std::string path;
        std::string version;

        stream >>
            method >>
            path >>
            version;

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

        if (
            method == "GET" &&
            path == "/health"
        )
        {
            sendResponse(
                client,
                200,
                "application/json; charset=utf-8",
                "{\"status\":\"ok\",\"compiler\":\"luau\"}"
            );

            close(client);
            return;
        }

        if (
            method == "GET" &&
            path == "/"
        )
        {
            const std::string html =
                readFile("web/index.html");

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

        if (
            method == "GET" &&
            path == "/style.css"
        )
        {
            const std::string css =
                readFile("web/style.css");

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

        if (
            method == "GET" &&
            path == "/app.js"
        )
        {
            const std::string js =
                readFile("web/app.js");

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

        if (
            method != "POST" ||
            path != "/api/obfuscate"
        )
        {
            sendResponse(
                client,
                404,
                "application/json; charset=utf-8",
                "{\"success\":false,\"error\":\"Not found\"}"
            );

            close(client);
            return;
        }

        /*
         * Extract Content-Length.
         */
        std::size_t contentLength = 0;

        const std::string lengthKey =
            "Content-Length:";

        const std::size_t lengthPos =
            headers.find(lengthKey);

        if (lengthPos != std::string::npos)
        {
            std::size_t start =
                lengthPos + lengthKey.size();

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

            try
            {
                contentLength =
                    std::stoull(
                        headers.substr(
                            start,
                            end - start
                        )
                    );
            }
            catch (...)
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
        }

        if (
            body.size() <
            contentLength
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
            body.size() >
            contentLength
        )
        {
            body.resize(contentLength);
        }

        /*
         * Extract source.
         */
        std::string source;

        if (!extractJsonString(
                body,
                "code",
                source
            ))
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
             * 1. Real Luau compiler.
             */
            Transformer transformer;

            const std::string compiled =
                transformer.transform(source);

            /*
             * 2. Store the binary compiler output.
             */
            Bytecode bytecode(compiled);

            /*
             * 3. Validate/package it.
             */
            VM vm;

            std::string validationError;

            if (
                !vm.validate(
                    bytecode,
                    validationError
                )
            )
            {
                sendResponse(
                    client,
                    422,
                    "application/json; charset=utf-8",
                    "{\"success\":false,\"error\":\"" +
                    jsonEscape(validationError) +
                    "\"}"
                );

                close(client);
                return;
            }

            /*
             * 4. Base64 makes the binary safe for JSON.
             */
            const std::string encoded =
                vm.package(bytecode);

            const std::string response =
                "{\"success\":true,"
                "\"format\":\"luau-bytecode-base64\","
                "\"code\":\"" +
                jsonEscape(encoded) +
                "\","
                "\"size\":" +
                std::to_string(bytecode.size()) +
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
                "{\"success\":false,\"error\":\"" +
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
                "{\"success\":false,\"error\":\"Unknown compiler error\"}"
            );
        }

        close(client);
    }
}

int main()
{
    int port = DEFAULT_PORT;

    const char* environment =
        std::getenv("PORT");

    if (environment)
    {
        try
        {
            const int parsed =
                std::stoi(environment);

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
        }
    }

    const int server =
        socket(
            AF_INET,
            SOCK_STREAM,
            0
        );

    if (server < 0)
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
            << "bind() failed: "
            << std::strerror(errno)
            << '\n';

        close(server);
        return 1;
    }

    if (
        listen(
            server,
            64
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
        << port
        << '\n';

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
                << std::strerror(errno)
                << '\n';

            continue;
        }

        handleClient(client);
    }

    close(server);
    return 0;
}