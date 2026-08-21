#include "transformer.hpp"

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

namespace
{
std::string read_all(int fd)
{
    std::string result;
    char buffer[8192];

    for (;;)
    {
        ssize_t n = recv(fd, buffer, sizeof(buffer), 0);

        if (n <= 0)
            break;

        result.append(buffer, static_cast<size_t>(n));

        // Prevent accidentally accepting enormous requests.
        if (result.size() > 4 * 1024 * 1024)
            break;
    }

    return result;
}

std::string extract_body(const std::string& request)
{
    const std::string separator = "\r\n\r\n";
    const size_t pos = request.find(separator);

    if (pos == std::string::npos)
        return {};

    return request.substr(pos + separator.size());
}

std::string json_escape(const std::string& value)
{
    std::string out;
    out.reserve(value.size() + 32);

    for (char c : value)
    {
        switch (c)
        {
        case '\\': out += "\\\\"; break;
        case '"':  out += "\\\""; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            out += c;
            break;
        }
    }

    return out;
}

std::string extract_json_string(const std::string& body, const std::string& key)
{
    const std::string needle = "\"" + key + "\"";

    size_t p = body.find(needle);

    if (p == std::string::npos)
        return {};

    p = body.find(':', p);

    if (p == std::string::npos)
        return {};

    ++p;

    while (p < body.size() && (body[p] == ' ' || body[p] == '\t'))
        ++p;

    if (p >= body.size() || body[p] != '"')
        return {};

    ++p;

    std::string result;

    bool escaped = false;

    for (; p < body.size(); ++p)
    {
        char c = body[p];

        if (escaped)
        {
            switch (c)
            {
            case 'n': result += '\n'; break;
            case 'r': result += '\r'; break;
            case 't': result += '\t'; break;
            case '"': result += '"'; break;
            case '\\': result += '\\'; break;
            default: result += c; break;
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
            break;

        result += c;
    }

    return result;
}

void send_response(int fd, int status, const std::string& content_type,
                   const std::string& body)
{
    std::string status_text =
        status == 200 ? "OK" :
        status == 400 ? "Bad Request" :
        status == 404 ? "Not Found" :
        "Internal Server Error";

    std::ostringstream response;

    response
        << "HTTP/1.1 " << status << " " << status_text << "\r\n"
        << "Content-Type: " << content_type << "\r\n"
        << "Content-Length: " << body.size() << "\r\n"
        << "Access-Control-Allow-Origin: *\r\n"
        << "Access-Control-Allow-Headers: Content-Type\r\n"
        << "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
        << "Connection: close\r\n"
        << "\r\n"
        << body;

    const std::string data = response.str();

    send(fd, data.data(), data.size(), 0);
}

void handle_client(int fd)
{
    const std::string request = read_all(fd);

    if (request.rfind("OPTIONS ", 0) == 0)
    {
        send_response(fd, 200, "text/plain", "");
        close(fd);
        return;
    }

    if (request.rfind("GET /health", 0) == 0)
    {
        send_response(
            fd,
            200,
            "application/json",
            "{\"status\":\"ok\",\"service\":\"luaProtecter\"}"
        );

        close(fd);
        return;
    }

    if (request.rfind("POST /api/protect", 0) == 0)
    {
        const std::string body = extract_body(request);
        const std::string source = extract_json_string(body, "source");

        if (source.empty())
        {
            send_response(
                fd,
                400,
                "application/json",
                "{\"error\":\"Missing source\"}"
            );

            close(fd);
            return;
        }

        try
        {
            Transformer transformer;
            const std::string output = transformer.transform(source);

            const std::string response =
                "{\"success\":true,\"output\":\"" +
                json_escape(output) +
                "\"}";

            send_response(fd, 200, "application/json", response);
        }
        catch (const std::exception& e)
        {
            const std::string response =
                "{\"success\":false,\"error\":\"" +
                json_escape(e.what()) +
                "\"}";

            send_response(fd, 400, "application/json", response);
        }

        close(fd);
        return;
    }

    send_response(
        fd,
        404,
        "application/json",
        "{\"error\":\"Not found\"}"
    );

    close(fd);
}

int main()
{
    int port = 10000;

    if (const char* env = std::getenv("PORT"))
    {
        try
        {
            port = std::stoi(env);
        }
        catch (...)
        {
            port = 10000;
        }
    }

    const int server_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (server_fd < 0)
    {
        std::cerr << "Failed to create socket\n";
        return 1;
    }

    int reuse = 1;

    setsockopt(
        server_fd,
        SOL_SOCKET,
        SO_REUSEADDR,
        &reuse,
        sizeof(reuse)
    );

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(static_cast<uint16_t>(port));

    if (bind(
            server_fd,
            reinterpret_cast<sockaddr*>(&address),
            sizeof(address)) < 0)
    {
        std::cerr << "Failed to bind port " << port << "\n";
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 32) < 0)
    {
        std::cerr << "Failed to listen\n";
        close(server_fd);
        return 1;
    }

    std::cout
        << "luaProtecter web server listening on 0.0.0.0:"
        << port
        << "\n";

    for (;;)
    {
        sockaddr_in client{};
        socklen_t client_len = sizeof(client);

        const int client_fd = accept(
            server_fd,
            reinterpret_cast<sockaddr*>(&client),
            &client_len
        );

        if (client_fd < 0)
            continue;

        std::thread(handle_client, client_fd).detach();
    }

    close(server_fd);
    return 0;
}