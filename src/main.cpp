#include "transformer.hpp"

#include <arpa/inet.h>
#include <cerrno>
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
constexpr int BUFFER_SIZE = 8192;

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

    for (unsigned char c : value)
    {
        switch (c)
        {
        case '\"':
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
                const char hex[] = "0123456789abcdef";

                result += "\\u00";
                result += hex[(c >> 4) & 0xF];
                result += hex[c & 0xF];
            }
            else
            {
                result += static_cast<char>(c);
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
    std::string search = "\"" + key + "\"";

    size_t keyPosition = json.find(search);

    if (keyPosition == std::string::npos)
        return false;

    size_t colon = json.find(':', keyPosition + search.length());

    if (colon == std::string::npos)
        return false;

    size_t start = colon + 1;

    while (start < json.length() &&
           (json[start] == ' ' ||
            json[start] == '\t' ||
            json[start] == '\r' ||
            json[start] == '\n'))
    {
        ++start;
    }

    if (start >= json.length() || json[start] != '"')
        return false;

    ++start;

    std::string result;

    bool escaped = false;

    for (size_t i = start; i < json.length(); ++i)
    {
        char c = json[i];

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
                if (i + 4 >= json.length())
                    return false;

                unsigned int value = 0;

                for (int j = 1; j <= 4; ++j)
                {
                    char h = json[i + j];

                    value <<= 4;

                    if (h >= '0' && h <= '9')
                        value += h - '0';
                    else if (h >= 'a' && h <= 'f')
                        value += h - 'a' + 10;
                    else if (h >= 'A' && h <= 'F')
                        value += h - 'A' + 10;
                    else
                        return false;
                }

                if (value <= 0x7F)
                {
                    result += static_cast<char>(value);
                }
                else if (value <= 0x7FF)
                {
                    result += static_cast<char>(0xC0 | (value >> 6));
                    result += static_cast<char>(0x80 | (value & 0x3F));
                }
                else
                {
                    result += static_cast<char>(0xE0 | (value >> 12));
                    result += static_cast<char>(0x80 | ((value >> 6) & 0x3F));
                    result += static_cast<char>(0x80 | (value & 0x3F));
                }

                i += 4;
                break;
            }

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
            output = result;
            return true;
        }

        result += c;
    }

    return false;
}

void sendResponse(
    int client,
    int status,
    const std::string& contentType,
    const std::string& body)
{
    std::string statusText;

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

    case 500:
        statusText = "Internal Server Error";
        break;

    default:
        statusText = "Unknown";
        break;
    }

    std::ostringstream response;

    response
        << "HTTP/1.1 " << status << " " << statusText << "\r\n"
        << "Content-Type: " << contentType << "\r\n"
        << "Content-Length: " << body.size() << "\r\n"
        << "Access-Control-Allow-Origin: *\r\n"
        << "Access-Control-Allow-Headers: Content-Type\r\n"
        << "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
        << "Connection: close\r\n"
        << "\r\n"
        << body;

    std::string data = response.str();

    size_t sent = 0;

    while (sent < data.size())
    {
        ssize_t n = send(
            client,
            data.data() + sent,
            data.size() - sent,
            0);

        if (n <= 0)
            break;

        sent += static_cast<size_t>(n);
    }
}

void handleClient(int client)
{
    std::string request;

    char buffer[BUFFER_SIZE];

    while (request.find("\r\n\r\n") == std::string::npos)
    {
        ssize_t received = recv(
            client,
            buffer,
            sizeof(buffer),
            0);

        if (received <= 0)
        {
            close(client);
            return;
        }

        request.append(buffer, static_cast<size_t>(received));

        if (request.size() > 1024 * 1024)
        {
            sendResponse(
                client,
                400,
                "application/json",
                "{\"error\":\"Request too large\"}");

            close(client);
            return;
        }
    }

    size_t headerEnd = request.find("\r\n\r\n");

    std::string headers = request.substr(0, headerEnd);
    std::string body = request.substr(headerEnd + 4);

    std::istringstream headerStream(headers);

    std::string method;
    std::string path;
    std::string version;

    headerStream >> method >> path >> version;

    if (method == "OPTIONS")
    {
        sendResponse(client, 200, "text/plain", "");
        close(client);
        return;
    }

    size_t contentLengthPosition =
        headers.find("Content-Length:");

    if (contentLengthPosition != std::string::npos)
    {
        size_t valueStart =
            contentLengthPosition + strlen("Content-Length:");

        while (
            valueStart < headers.size() &&
            (headers[valueStart] == ' ' ||
             headers[valueStart] == '\t'))
        {
            ++valueStart;
        }

        size_t valueEnd =
            headers.find("\r\n", valueStart);

        std::string lengthString =
            headers.substr(
                valueStart,
                valueEnd == std::string::npos
                    ? std::string::npos
                    : valueEnd - valueStart);

        size_t contentLength =
            std::stoull(lengthString);

        while (body.size() < contentLength)
        {
            ssize_t received = recv(
                client,
                buffer,
                sizeof(buffer),
                0);

            if (received <= 0)
                break;

            body.append(
                buffer,
                static_cast<size_t>(received));
        }

        if (body.size() > contentLength)
            body.resize(contentLength);
    }

    if (method == "GET" && path == "/")
    {
        std::string html = readFile("web/index.html");

        if (html.empty())
        {
            sendResponse(
                client,
                500,
                "text/plain",
                "index.html not found");

            close(client);
            return;
        }

        sendResponse(
            client,
            200,
            "text/html; charset=utf-8",
            html);

        close(client);
        return;
    }

    if (method == "GET" && path == "/style.css")
    {
        std::string css = readFile("web/style.css");

        sendResponse(
            client,
            200,
            "text/css; charset=utf-8",
            css);

        close(client);
        return;
    }

    if (method == "GET" && path == "/app.js")
    {
        std::string js = readFile("web/app.js");

        sendResponse(
            client,
            200,
            "application/javascript; charset=utf-8",
            js);

        close(client);
        return;
    }

    if (method == "GET" && path == "/health")
    {
        sendResponse(
            client,
            200,
            "application/json",
            "{\"status\":\"ok\"}");

        close(client);
        return;
    }

    if (method == "POST" && path == "/api/obfuscate")
    {
        std::string source;

        if (!extractJsonString(body, "code", source))
        {
            sendResponse(
                client,
                400,
                "application/json",
                "{\"error\":\"Missing code field\"}");

            close(client);
            return;
        }

        if (source.empty())
        {
            sendResponse(
                client,
                400,
                "application/json",
                "{\"error\":\"Code cannot be empty\"}");

            close(client);
            return;
        }

        try
        {
            Transformer transformer;

            std::string protectedCode =
                transformer.transform(source);

            std::string response =
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
            std::string response =
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
                "{\"success\":false,\"error\":\"Obfuscation failed\"}");
        }

        close(client);
        return;
    }

    sendResponse(
        client,
        404,
        "application/json",
        "{\"error\":\"Not found\"}");

    close(client);
}

} // namespace

int main()
{
    const char* portEnvironment =
        std::getenv("PORT");

    int port = 10000;

    if (portEnvironment)
    {
        try
        {
            port = std::stoi(portEnvironment);
        }
        catch (...)
        {
            port = 10000;
        }
    }

    int server =
        socket(AF_INET, SOCK_STREAM, 0);

    if (server < 0)
    {
        std::cerr << "Failed to create socket\n";
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
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(
        static_cast<uint16_t>(port));

    if (bind(
            server,
            reinterpret_cast<sockaddr*>(&address),
            sizeof(address)) < 0)
    {
        std::cerr << "Failed to bind port "
                  << port
                  << ": "
                  << strerror(errno)
                  << "\n";

        close(server);
        return 1;
    }

    if (listen(server, 32) < 0)
    {
        std::cerr << "Failed to listen\n";
        close(server);
        return 1;
    }

    std::cout
        << "LuaProtecter web server listening on port "
        << port
        << "\n";

    while (true)
    {
        sockaddr_in clientAddress{};
        socklen_t clientLength =
            sizeof(clientAddress);

        int client = accept(
            server,
            reinterpret_cast<sockaddr*>(&clientAddress),
            &clientLength);

        if (client < 0)
        {
            if (errno == EINTR)
                continue;

            std::cerr << "accept() failed\n";
            continue;
        }

        handleClient(client);
    }

    close(server);

    return 0;
}