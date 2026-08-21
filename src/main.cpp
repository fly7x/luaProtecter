#include "bytecode.hpp"
#include "compiler.hpp"
#include "transformer.hpp"
#include "vm.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace
{
    constexpr int PORT = 10000;
    constexpr int BACKLOG = 32;
    constexpr std::size_t MAX_REQUEST_SIZE = 8 * 1024 * 1024;

    std::string jsonEscape(
        const std::string& value
    )
    {
        std::string result;
        result.reserve(value.size() + 16);

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
                        const char hex[] = "0123456789abcdef";

                        result += "\\u00";
                        result += hex[(c >> 4) & 0x0F];
                        result += hex[c & 0x0F];
                    }
                    else
                    {
                        result.push_back(
                            static_cast<char>(c)
                        );
                    }

                    break;
            }
        }

        return result;
    }

    std::string makeResponse(
        int status,
        const std::string& body,
        const std::string& contentType =
            "application/json"
    )
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

            case 413:
                statusText = "Payload Too Large";
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
            << "HTTP/1.1 "
            << status
            << ' '
            << statusText
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
            << "Connection: close\r\n";

        response
            << "Access-Control-Allow-Origin: *\r\n";

        response
            << "Access-Control-Allow-Headers: "
               "Content-Type\r\n";

        response
            << "Access-Control-Allow-Methods: "
               "POST, GET, OPTIONS\r\n";

        response
            << "\r\n";

        response << body;

        return response.str();
    }

    bool sendAll(
        int socket,
        const std::string& data
    )
    {
        std::size_t sent = 0;

        while (sent < data.size())
        {
            const ssize_t result =
                ::send(
                    socket,
                    data.data() + sent,
                    data.size() - sent,
                    0
                );

            if (result <= 0)
            {
                if (
                    errno == EINTR
                )
                {
                    continue;
                }

                return false;
            }

            sent +=
                static_cast<std::size_t>(
                    result
                );
        }

        return true;
    }

    std::string receiveRequest(
        int socket
    )
    {
        std::string request;

        request.reserve(8192);

        char buffer[8192];

        while (
            request.size() <
            MAX_REQUEST_SIZE
        )
        {
            const ssize_t received =
                ::recv(
                    socket,
                    buffer,
                    sizeof(buffer),
                    0
                );

            if (received == 0)
                break;

            if (received < 0)
            {
                if (
                    errno == EINTR
                )
                {
                    continue;
                }

                throw std::runtime_error(
                    "recv() failed"
                );
            }

            request.append(
                buffer,
                static_cast<std::size_t>(
                    received
                )
            );

            /*
             * Once the headers have arrived, determine whether
             * we already have the complete body.
             */
            const std::size_t headerEnd =
                request.find(
                    "\r\n\r\n"
                );

            if (
                headerEnd !=
                std::string::npos
            )
            {
                const std::size_t bodyStart =
                    headerEnd + 4;

                std::size_t contentLength = 0;

                std::istringstream headers(
                    request.substr(
                        0,
                        headerEnd
                    )
                );

                std::string line;

                while (
                    std::getline(
                        headers,
                        line
                    )
                )
                {
                    if (
                        line.size() >= 15 &&
                        std::equal(
                            line.begin(),
                            line.begin() + 15,
                            "Content-Length:",
                            [](char a, char b)
                            {
                                return
                                    std::tolower(
                                        static_cast<unsigned char>(a)
                                    ) ==
                                    std::tolower(
                                        static_cast<unsigned char>(b)
                                    );
                            }
                        )
                    )
                    {
                        const std::string value =
                            line.substr(15);

                        try
                        {
                            contentLength =
                                static_cast<std::size_t>(
                                    std::stoull(
                                        value
                                    )
                                );
                        }
                        catch (...)
                        {
                            throw std::runtime_error(
                                "Invalid Content-Length"
                            );
                        }

                        break;
                    }
                }

                if (
                    contentLength >
                    MAX_REQUEST_SIZE
                )
                {
                    throw std::runtime_error(
                        "Request body too large"
                    );
                }

                if (
                    request.size() >=
                    bodyStart + contentLength
                )
                {
                    break;
                }
            }
        }

        if (
            request.size() >=
            MAX_REQUEST_SIZE
        )
        {
            throw std::runtime_error(
                "Request too large"
            );
        }

        return request;
    }

    struct HttpRequest
    {
        std::string method;
        std::string path;
        std::string body;
    };

    HttpRequest parseRequest(
        const std::string& request
    )
    {
        const std::size_t headerEnd =
            request.find(
                "\r\n\r\n"
            );

        if (
            headerEnd ==
            std::string::npos
        )
        {
            throw std::runtime_error(
                "Malformed HTTP request"
            );
        }

        const std::string headers =
            request.substr(
                0,
                headerEnd
            );

        const std::size_t bodyStart =
            headerEnd + 4;

        std::istringstream stream(
            headers
        );

        std::string requestLine;

        if (
            !std::getline(
                stream,
                requestLine
            )
        )
        {
            throw std::runtime_error(
                "Missing HTTP request line"
            );
        }

        if (
            !requestLine.empty() &&
            requestLine.back() == '\r'
        )
        {
            requestLine.pop_back();
        }

        std::istringstream requestLineStream(
            requestLine
        );

        HttpRequest result;

        std::string version;

        if (
            !(requestLineStream
                >> result.method
                >> result.path
                >> version)
        )
        {
            throw std::runtime_error(
                "Invalid HTTP request line"
            );
        }

        std::size_t contentLength = 0;

        std::string line;

        while (
            std::getline(
                stream,
                line
            )
        )
        {
            if (
                !line.empty() &&
                line.back() == '\r'
            )
            {
                line.pop_back();
            }

            const std::string prefix =
                "Content-Length:";

            if (
                line.size() >= prefix.size()
            )
            {
                bool matches = true;

                for (
                    std::size_t i = 0;
                    i < prefix.size();
                    ++i
                )
                {
                    if (
                        std::tolower(
                            static_cast<unsigned char>(
                                line[i]
                            )
                        ) !=
                        std::tolower(
                            static_cast<unsigned char>(
                                prefix[i]
                            )
                        )
                    )
                    {
                        matches = false;
                        break;
                    }
                }

                if (matches)
                {
                    try
                    {
                        contentLength =
                            static_cast<std::size_t>(
                                std::stoull(
                                    line.substr(
                                        prefix.size()
                                    )
                                )
                            );
                    }
                    catch (...)
                    {
                        throw std::runtime_error(
                            "Invalid Content-Length"
                        );
                    }
                }
            }
        }

        if (
            contentLength >
            MAX_REQUEST_SIZE
        )
        {
            throw std::runtime_error(
                "Request body too large"
            );
        }

        if (
            request.size() <
            bodyStart + contentLength
        )
        {
            throw std::runtime_error(
                "Incomplete HTTP body"
            );
        }

        result.body =
            request.substr(
                bodyStart,
                contentLength
            );

        return result;
    }

    /*
     * Extract a simple JSON string field:
     *
     * {
     *   "source": "print(\"flyx\")"
     * }
     *
     * This intentionally avoids pulling another JSON library
     * into the project. It handles normal JSON string escapes.
     */
    std::string extractJsonString(
        const std::string& json,
        const std::string& field
    )
    {
        const std::string key =
            "\"" + field + "\"";

        const std::size_t keyPosition =
            json.find(key);

        if (
            keyPosition ==
            std::string::npos
        )
        {
            throw std::runtime_error(
                "Missing JSON field: " +
                field
            );
        }

        std::size_t position =
            keyPosition + key.size();

        while (
            position < json.size() &&
            std::isspace(
                static_cast<unsigned char>(
                    json[position]
                )
            )
        )
        {
            ++position;
        }

        if (
            position >= json.size() ||
            json[position] != ':'
        )
        {
            throw std::runtime_error(
                "Invalid JSON field: " +
                field
            );
        }

        ++position;

        while (
            position < json.size() &&
            std::isspace(
                static_cast<unsigned char>(
                    json[position]
                )
            )
        )
        {
            ++position;
        }

        if (
            position >= json.size() ||
            json[position] != '"'
        )
        {
            throw std::runtime_error(
                "JSON field must be a string: " +
                field
            );
        }

        ++position;

        std::string result;

        while (
            position < json.size()
        )
        {
            const char c =
                json[position++];

            if (c == '"')
                return result;

            if (c != '\\')
            {
                result.push_back(c);
                continue;
            }

            if (
                position >= json.size()
            )
            {
                throw std::runtime_error(
                    "Invalid JSON escape"
                );
            }

            const char escaped =
                json[position++];

            switch (escaped)
            {
                case '"':
                    result.push_back('"');
                    break;

                case '\\':
                    result.push_back('\\');
                    break;

                case '/':
                    result.push_back('/');
                    break;

                case 'b':
                    result.push_back('\b');
                    break;

                case 'f':
                    result.push_back('\f');
                    break;

                case 'n':
                    result.push_back('\n');
                    break;

                case 'r':
                    result.push_back('\r');
                    break;

                case 't':
                    result.push_back('\t');
                    break;

                default:
                    throw std::runtime_error(
                        "Unsupported JSON escape"
                    );
            }
        }

        throw std::runtime_error(
            "Unterminated JSON string"
        );
    }

    std::string handleCompile(
        const std::string& source,
        bool execute
    )
    {
        Compiler compiler;
        Transformer transformer;

        /*
         * REAL Luau compilation.
         *
         * This is no longer the old custom print()
         * parser.
         */
        const Bytecode compiled =
            compiler.compile(
                source
            );

        /*
         * Protect the REAL Luau bytecode.
         */
        const Bytecode protectedBytecode =
            transformer.protect(
                compiled
            );

        std::string executionOutput;

        if (execute)
        {
            VM vm;

            if (
                !vm.execute(
                    compiled,
                    executionOutput
                )
            )
            {
                throw std::runtime_error(
                    executionOutput.empty()
                        ? "Luau execution failed"
                        : executionOutput
                );
            }
        }

        std::ostringstream json;

        json
            << "{"
            << "\"success\":true,"
            << "\"bytecodeSize\":"
            << compiled.size()
            << ","
            << "\"protectedSize\":"
            << protectedBytecode.size()
            << ","
            << "\"protected\":\""
            << jsonEscape(
                protectedBytecode.toBase64()
            )
            << "\"";

        if (execute)
        {
            json
                << ","
                << "\"output\":\""
                << jsonEscape(
                    executionOutput
                )
                << "\"";
        }

        json << "}";

        return json.str();
    }

    void handleClient(
        int client
    )
    {
        try
        {
            const std::string request =
                receiveRequest(
                    client
                );

            const HttpRequest parsed =
                parseRequest(
                    request
                );

            /*
             * CORS preflight.
             */
            if (
                parsed.method ==
                "OPTIONS"
            )
            {
                const std::string response =
                    makeResponse(
                        200,
                        ""
                    );

                sendAll(
                    client,
                    response
                );

                return;
            }

            /*
             * Health endpoint.
             */
            if (
                parsed.method == "GET" &&
                parsed.path == "/"
            )
            {
                const std::string body =
                    R"({"success":true,"service":"luaProtecter","luau":true})";

                const std::string response =
                    makeResponse(
                        200,
                        body
                    );

                sendAll(
                    client,
                    response
                );

                return;
            }

            /*
             * Compile + protect.
             *
             * POST /compile
             *
             * Body:
             *
             * {
             *   "source":"print(\"flyx\")"
             * }
             */
            if (
                parsed.method == "POST" &&
                parsed.path == "/compile"
            )
            {
                const std::string source =
                    extractJsonString(
                        parsed.body,
                        "source"
                    );

                const std::string body =
                    handleCompile(
                        source,
                        false
                    );

                const std::string response =
                    makeResponse(
                        200,
                        body
                    );

                sendAll(
                    client,
                    response
                );

                return;
            }

            /*
             * Compile + protect + execute.
             *
             * POST /execute
             */
            if (
                parsed.method == "POST" &&
                parsed.path == "/execute"
            )
            {
                const std::string source =
                    extractJsonString(
                        parsed.body,
                        "source"
                    );

                const std::string body =
                    handleCompile(
                        source,
                        true
                    );

                const std::string response =
                    makeResponse(
                        200,
                        body
                    );

                sendAll(
                    client,
                    response
                );

                return;
            }

            /*
             * Wrong method/path.
             */
            const std::string body =
                R"({"success":false,"error":"Not found"})";

            const std::string response =
                makeResponse(
                    404,
                    body
                );

            sendAll(
                client,
                response
            );
        }
        catch (
            const std::exception& error
        )
        {
            const std::string body =
                std::string(
                    "{\"success\":false,\"error\":\""
                )
                +
                jsonEscape(
                    error.what()
                )
                +
                "\"}";

            const std::string response =
                makeResponse(
                    400,
                    body
                );

            sendAll(
                client,
                response
            );
        }

        ::close(client);
    }

    int createServer()
    {
        const int server =
            ::socket(
                AF_INET,
                SOCK_STREAM,
                0
            );

        if (server < 0)
        {
            throw std::runtime_error(
                std::string(
                    "socket() failed: "
                )
                +
                std::strerror(errno)
            );
        }

        int reuse = 1;

        if (
            ::setsockopt(
                server,
                SOL_SOCKET,
                SO_REUSEADDR,
                &reuse,
                sizeof(reuse)
            ) < 0
        )
        {
            ::close(server);

            throw std::runtime_error(
                std::string(
                    "setsockopt() failed: "
                )
                +
                std::strerror(errno)
            );
        }

        sockaddr_in address{};

        address.sin_family =
            AF_INET;

        address.sin_addr.s_addr =
            htonl(
                INADDR_ANY
            );

        address.sin_port =
            htons(
                static_cast<std::uint16_t>(
                    PORT
                )
            );

        if (
            ::bind(
                server,
                reinterpret_cast<
                    const sockaddr*
                >(&address),
                sizeof(address)
            ) < 0
        )
        {
            ::close(server);

            throw std::runtime_error(
                std::string(
                    "bind() failed: "
                )
                +
                std::strerror(errno)
            );
        }

        if (
            ::listen(
                server,
                BACKLOG
            ) < 0
        )
        {
            ::close(server);

            throw std::runtime_error(
                std::string(
                    "listen() failed: "
                )
                +
                std::strerror(errno)
            );
        }

        return server;
    }
}

int main()
{
    try
    {
        const int server =
            createServer();

        std::cout
            << "luaProtecter listening on port "
            << PORT
            << '\n';

        std::cout
            << "POST /compile  -> compile + protect\n";

        std::cout
            << "POST /execute  -> compile + protect + execute\n";

        std::cout
            << "GET  /         -> health check\n";

        while (true)
        {
            sockaddr_in clientAddress{};

            socklen_t clientLength =
                sizeof(clientAddress);

            const int client =
                ::accept(
                    server,
                    reinterpret_cast<
                        sockaddr*
                    >(&clientAddress),
                    &clientLength
                );

            if (client < 0)
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

            std::thread(
                handleClient,
                client
            ).detach();
        }

        ::close(server);
    }
    catch (
        const std::exception& error
    )
    {
        std::cerr
            << "Fatal error: "
            << error.what()
            << '\n';

        return 1;
    }

    return 0;
}