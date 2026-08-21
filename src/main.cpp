#include "transformer.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <netinet/in.h>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

namespace
{
    constexpr std::size_t MAX_REQUEST_SIZE = 4 * 1024 * 1024;
    constexpr int DEFAULT_PORT = 10000;

    std::string readFile(const std::string& path)
    {
        std::ifstream file(path, std::ios::binary);

        if (!file)
            return {};

        std::ostringstream buffer;
        buffer << file.rdbuf();

        return buffer.str();
    }

    std::string jsonEscape(const std::string& value)
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
                {
                    if (c < 0x20)
                    {
                        static constexpr char hex[] =
                            "0123456789abcdef";

                        result += "\\u00";
                        result += hex[(c >> 4) & 0xF];
                        result += hex[c & 0xF];
                    }
                    else
                    {
                        result += static_cast<char>(c);
                    }

                    break;
                }
            }
        }

        return result;
    }

    bool extractJsonString(
        const std::string& json,
        const std::string& key,
        std::string& output)
    {
        const std::string search = "\"" + key + "\"";

        const std::size_t keyPosition =
            json.find(search);

        if (keyPosition == std::string::npos)
            return false;

        const std::size_t colon =
            json.find(':', keyPosition + search.size());

        if (colon == std::string::npos)
            return false;

        std::size_t start = colon + 1;

        while (
            start < json.size() &&
            std::isspace(
                static_cast<unsigned char>(json[start])))
        {
            ++start;
        }

        if (
            start >= json.size() ||
            json[start] != '"')
        {
            return false;
        }

        ++start;

        std::string result;
        bool escaped = false;

        for (std::size_t i = start; i < json.size(); ++i)
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
                            const char h = json[i + j];

                            value <<= 4;

                            if (h >= '0' && h <= '9')
                            {
                                value += h - '0';
                            }
                            else if (h >= 'a' && h <= 'f')
                            {
                                value += h - 'a' + 10;
                            }
                            else if (h >= 'A' && h <= 'F')
                            {
                                value += h - 'A' + 10;
                            }
                            else
                            {
                                return false;
                            }
                        }

                        if (value <= 0x7F)
                        {
                            result += static_cast<char>(value);
                        }
                        else if (value <= 0x7FF)
                        {
                            result += static_cast<char>(
                                0xC0 | (value >> 6));

                            result += static_cast<char>(
                                0x80 | (value & 0x3F));
                        }
                        else
                        {
                            result += static_cast<char>(
                                0xE0 | (value >> 12));

                            result += static_cast<char>(
                                0x80 |
                                ((value >> 6) & 0x3F));

                            result += static_cast<char>(
                                0x80 |
                                (value & 0x3F));
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

    void sendAll(
        int client,
        const std::string& data)
    {
        std::size_t sent = 0;

        while (sent < data.size())
        {
            const ssize_t count =
                send(
                    client,
                    data.data() + sent,
                    data.size() - sent,
                    0);

            if (count <= 0)
                return;

            sent += static_cast<std::size_t>(count);
        }
    }

    void sendResponse(
        int client,
        int status,
        const std::string& contentType,
        const std::string& body)
    {
        const char* statusText = "Unknown";

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

        sendAll(client, response.str());
    }

    bool parseContentLength(
        const std::string& headers,
        std::size_t& length)
    {
        std::size_t position =
            headers.find("Content-Length:");

        if (position == std::string::npos)
        {
            length = 0;
            return true;
        }

        position +=
            std::string("Content-Length:").size();

        while (
            position < headers.size() &&
            std::isspace(
                static_cast<unsigned char>(
                    headers[position])))
        {
            ++position;
        }

        const std::size_t start = position;

        while (
            position < headers.size() &&
            std::isdigit(
                static_cast<unsigned char>(
                    headers[position])))
        {
            ++position;
        }

        if (position == start)
            return false;

        try
        {
            length = std::stoull(
                headers.substr(
                    start,
                    position - start));
        }
        catch (...)
        {
            return false;
        }

        return true;
    }

    bool receiveRequest(
        int client,
        std::string& request)
    {
        char buffer[16384];

        while (
            request.find("\r\n\r\n") ==
            std::string::npos)
        {
            const ssize_t received =
                recv(
                    client,
                    buffer,
                    sizeof(buffer),
                    0);

            if (received <= 0)
                return false;

            request.append(
                buffer,
                static_cast<std::size_t>(received));

            if (request.size() > MAX_REQUEST_SIZE)
                return false;
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
                "{\"success\":false,\"error\":\"Request too large\"}");

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
                "{\"success\":false,\"error\":\"Malformed HTTP request\"}");

            close(client);
            return;
        }

        const std::string headers =
            request.substr(0, headerEnd);

        std::string body =
            request.substr(headerEnd + 4);

        std::istringstream headerStream(headers);

        std::string method;
        std::string path;
        std::string version;

        headerStream >> method >> path >> version;

        if (method.empty() || path.empty())
        {
            sendResponse(
                client,
                400,
                "application/json; charset=utf-8",
                "{\"success\":false,\"error\":\"Invalid HTTP request\"}");

            close(client);
            return;
        }

        if (method == "OPTIONS")
        {
            sendResponse(
                client,
                200,
                "text/plain; charset=utf-8",
                "");

            close(client);
            return;
        }

        std::size_t contentLength = 0;

        if (!parseContentLength(
                headers,
                contentLength))
        {
            sendResponse(
                client,
                400,
                "application/json; charset=utf-8",
                "{\"success\":false,\"error\":\"Invalid Content-Length\"}");

            close(client);
            return;
        }

        if (contentLength > MAX_REQUEST_SIZE)
        {
            sendResponse(
                client,
                413,
                "application/json; charset=utf-8",
                "{\"success\":false,\"error\":\"Payload too large\"}");

            close(client);
            return;
        }

        char buffer[16384];

        while (body.size() < contentLength)
        {
            const ssize_t received =
                recv(
                    client,
                    buffer,
                    sizeof(buffer),
                    0);

            if (received <= 0)
                break;

            body.append(
                buffer,
                static_cast<std::size_t>(received));

            if (body.size() > MAX_REQUEST_SIZE)
            {
                sendResponse(
                    client,
                    413,
                    "application/json; charset=utf-8",
                    "{\"success\":false,\"error\":\"Payload too large\"}");

                close(client);
                return;
            }
        }

        if (
            contentLength > 0 &&
            body.size() < contentLength)
        {
            sendResponse(
                client,
                400,
                "application/json; charset=utf-8",
                "{\"success\":false,\"error\":\"Incomplete request body\"}");

            close(client);
            return;
        }

        if (
            contentLength > 0 &&
            body.size() > contentLength)
        {
            body.resize(contentLength);
        }

        /*
         * ----------------------------------------------------
         * Website
         * ----------------------------------------------------
         */

        if (method == "GET" && path == "/")
        {
            const std::string html =
                readFile("web/index.html");

            if (html.empty())
            {
                sendResponse(
                    client,
                    500,
                    "text/plain; charset=utf-8",
                    "web/index.html not found");
            }
            else
            {
                sendResponse(
                    client,
                    200,
                    "text/html; charset=utf-8",
                    html);
            }

            close(client);
            return;
        }

        if (method == "GET" && path == "/style.css")
        {
            const std::string css =
                readFile("web/style.css");

            if (css.empty())
            {
                sendResponse(
                    client,
                    404,
                    "text/plain; charset=utf-8",
                    "style.css not found");
            }
            else
            {
                sendResponse(
                    client,
                    200,
                    "text/css; charset=utf-8",
                    css);
            }

            close(client);
            return;
        }

        if (method == "GET" && path == "/app.js")
        {
            const std::string js =
                readFile("web/app.js");

            if (js.empty())
            {
                sendResponse(
                    client,
                    404,
                    "text/plain; charset=utf-8",
                    "app.js not found");
            }
            else
            {
                sendResponse(
                    client,
                    200,
                    "application/javascript; charset=utf-8",
                    js);
            }

            close(client);
            return;
        }

        if (method == "GET" && path == "/health")
        {
            sendResponse(
                client,
                200,
                "application/json; charset=utf-8",
                "{\"status\":\"ok\"}");

            close(client);
            return;
        }

        /*
         * ----------------------------------------------------
         * Obfuscation API
         * ----------------------------------------------------
         */

        if (
            method == "POST" &&
            path == "/api/obfuscate")
        {
            std::string source;

            if (!extractJsonString(
                    body,
                    "code",
                    source))
            {
                sendResponse(
                    client,
                    400,
                    "application/json; charset=utf-8",
                    "{\"success\":false,\"error\":\"Missing code field\"}");

                close(client);
                return;
            }

            if (source.empty())
            {
                sendResponse(
                    client,
                    400,
                    "application/json; charset=utf-8",
                    "{\"success\":false,\"error\":\"Code cannot be empty\"}");

                close(client);
                return;
            }

            try
            {
                Transformer transformer;

                const std::string protectedCode =
                    transformer.transform(source);

                if (protectedCode.empty())
                {
                    sendResponse(
                        client,
                        422,
                        "application/json; charset=utf-8",
                        "{\"success\":false,\"error\":\"Transformation produced no output\"}");

                    close(client);
                    return;
                }

                const std::string response =
                    "{\"success\":true,\"code\":\"" +
                    jsonEscape(protectedCode) +
                    "\"}";

                sendResponse(
                    client,
                    200,
                    "application/json; charset=utf-8",
                    response);
            }
            catch (const std::exception& exception)
            {
                const std::string response =
                    "{\"success\":false,\"error\":\"" +
                    jsonEscape(exception.what()) +
                    "\"}";

                sendResponse(
                    client,
                    500,
                    "application/json; charset=utf-8",
                    response);
            }
            catch (...)
            {
                sendResponse(
                    client,
                    500,
                    "application/json; charset=utf-8",
                    "{\"success\":false,\"error\":\"Unknown obfuscation failure\"}");
            }

            close(client);
            return;
        }

        if (
            method != "GET" &&
            method != "POST")
        {
            sendResponse(
                client,
                405,
                "application/json; charset=utf-8",
                "{\"success\":false,\"error\":\"Method not allowed\"}");

            close(client);
            return;
        }

        sendResponse(
            client,
            404,
            "application/json; charset=utf-8",
            "{\"success\":false,\"error\":\"Not found\"}");

        close(client);
    }
}

int main()
{
    const char* portEnvironment =
        std::getenv("PORT");

    int port = DEFAULT_PORT;

    if (portEnvironment)
    {
        try
        {
            const int parsed =
                std::stoi(portEnvironment);

            if (parsed > 0 && parsed <= 65535)
                port = parsed;
        }
        catch (...)
        {
            port = DEFAULT_PORT;
        }
    }

    const int server =
        socket(
            AF_INET,
            SOCK_STREAM,
            0);

    if (server < 0)
    {
        std::cerr
            << "Failed to create socket: "
            << strerror(errno)
            << '\n';

        return 1;
    }

    int reuse = 1;

    setsockopt(
        server,
        SOL_SOCKET,
        SO_REUSEADDR,
        &reuse,
        sizeof(reuse));

    sockaddr_in address{};

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port =
        htons(
            static_cast<std::uint16_t>(port));

    if (
        bind(
            server,
            reinterpret_cast<sockaddr*>(&address),
            sizeof(address)) < 0)
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

    if (listen(server, 64) < 0)
    {
        std::cerr
            << "Failed to listen: "
            << strerror(errno)
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
                reinterpret_cast<sockaddr*>(&clientAddress),
                &clientLength);

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

        handleClient(client);
    }

    close(server);
    return 0;
}