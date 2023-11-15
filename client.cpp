#include <iostream>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <cstring>
#include <unistd.h>
#include "json.hpp"
#include "buffer.hpp"

bool is_number(const std::string &s)
{
    return !s.empty() && std::find_if(s.begin(),
                                      s.end(), [](unsigned char c) { return !std::isdigit(c); }) == s.end();
}

bool string_contains(std::string s1, std::string s2)
{
    if (s1.find(s2) != std::string::npos)
        return true;
    return false;
}

class Request
{
private:
    std::string request_body;

public:
    std::string post_credentials(std::string username, std::string password, std::string url, std::string host)
    {
        this->request_body.clear();
        nlohmann::json json;
        json["username"] = username;
        json["password"] = password;
        std::string content = json.dump();

        this->request_body.append("POST " + url + " HTTP/1.1\r\n");
        this->request_body.append("Host: " + host + "\r\n");
        this->request_body.append("Content-Type: application/json\r\n");
        this->request_body.append("Content-Length: " + std::to_string(content.size()) + "\r\n");
        this->request_body.append("\r\n");
        this->request_body.append(content + "\r\n");

        return this->request_body;
    }

    std::string get_cookie(std::string url, std::string host, std::string cookie)
    {
        this->request_body.clear();
        this->request_body.append("GET " + url + " HTTP/1.1\r\n");
        this->request_body.append("Host: " + host + "\r\n");
        this->request_body.append("Cookie: " + cookie + "\r\n\r\n");

        return this->request_body;
    }

    std::string get_token(std::string url, std::string host, std::string cookie, std::string token)
    {
        this->request_body.clear();
        this->request_body.append("GET " + url + " HTTP/1.1\r\n");
        this->request_body.append("Host: " + host + "\r\n");
        this->request_body.append("Cookie: " + cookie + "\r\n");
        this->request_body.append("Authorization: Bearer " + token + "\r\n\r\n");

        return this->request_body;
    }

    std::string delete_req(std::string url, std::string host, std::string cookie, std::string token)
    {
        this->request_body.clear();
        this->request_body.append("DELETE " + url + " HTTP/1.1\r\n");
        this->request_body.append("Host: " + host + "\r\n");
        this->request_body.append("Cookie: " + cookie + "\r\n");
        this->request_body.append("Authorization: Bearer " + token + "\r\n\r\n");

        return this->request_body;
    }

    std::string post_token(std::string title, std::string author, std::string genre, std::string publisher, std::string page_count, std::string url, std::string host, std::string cookie, std::string token)
    {
        this->request_body.clear();
        nlohmann::json json;
        json["title"] = title;
        json["author"] = author;
        json["genre"] = genre;
        json["publisher"] = publisher;
        json["page_count"] = page_count;
        std::string content = json.dump();

        this->request_body.append("POST " + url + " HTTP/1.1\r\n");
        this->request_body.append("Host: " + host + "\r\n");
        this->request_body.append("Content-Type: application/json\r\n");
        this->request_body.append("Content-Length: " + std::to_string(content.size()) + "\r\n");
        this->request_body.append("Cookie: " + cookie + "\r\n");
        this->request_body.append("Authorization: Bearer " + token + "\r\n");
        this->request_body.append("\r\n");
        this->request_body.append(content + "\r\n");

        return this->request_body;
    }
};

class Client
{
private:
    std::string server_ip, username, password, token, cookie;
    int port, server_sock;
    bool logged_in = false, inside_library = false;

public:
    Client(const std::string server_ip, int port);
    void run();
    void open_connection();
    void close_connection();
    std::string send_and_recv(std::string request_body, int sockfd);
    void send_to_server(std::string request_body, int sockfd);
    std::string receive_from_server(int sockfd);
};

Client::Client(const std::string server_ip, int port)
{
    this->server_ip = server_ip;
    this->port = port;
}

std::string Client::receive_from_server(int sockfd)
{
    char response[BUFLEN];
    buffer buffer = buffer_init();
    int header_end = 0;
    int content_length = 0;

    do
    {
        int bytes = read(sockfd, response, BUFLEN);

        if (bytes < 0)
        {
            std::cerr << "ERROR reading response from socket\n";
        }

        if (bytes == 0)
        {
            break;
        }

        buffer_add(&buffer, response, (size_t)bytes);

        header_end = buffer_find(&buffer, HEADER_TERMINATOR, HEADER_TERMINATOR_SIZE);

        if (header_end >= 0)
        {
            header_end += HEADER_TERMINATOR_SIZE;

            int content_length_start = buffer_find_insensitive(&buffer, CONTENT_LENGTH, CONTENT_LENGTH_SIZE);

            if (content_length_start < 0)
            {
                continue;
            }

            content_length_start += CONTENT_LENGTH_SIZE;
            content_length = strtol(buffer.data + content_length_start, NULL, 10);
            break;
        }
    } while (1);
    size_t total = content_length + (size_t)header_end;

    while (buffer.size < total)
    {
        int bytes = read(sockfd, response, BUFLEN);

        if (bytes < 0)
        {
            std::cerr << "ERROR reading response from socket\n";
        }

        if (bytes == 0)
        {
            break;
        }

        buffer_add(&buffer, response, (size_t)bytes);
    }
    buffer_add(&buffer, "", 1);
    return std::string(buffer.data);
}

void Client::send_to_server(std::string request_body, int sockfd)
{
    int bytes, sent = 0;
    int total = request_body.size();
    auto message = request_body.c_str();

    do
    {
        bytes = write(sockfd, message + sent, total - sent);
        if (bytes < 0)
        {
            std::cerr << "ERROR writing message to socket\n";
        }

        if (bytes == 0)
        {
            break;
        }

        sent += bytes;
    } while (sent < total);
}

std::string Client::send_and_recv(std::string request_body, int sockfd)
{
    send_to_server(request_body, sockfd);
    return receive_from_server(sockfd);
}

void Client::run()
{
    std::string command;
    while (true)
    {
        std::cin >> command;

        if (string_contains(command, "register"))
        {
            if (this->logged_in)
            {
                std::cout << "Log out before registering a new user\n";
                continue;
            }

            std::string username, password;
            std::cout << "username=";
            std::cin >> username;
            std::cout << "password=";
            std::cin >> password;

            Request request;

            this->open_connection();
            std::string response = this->send_and_recv(request.post_credentials(username, password, "/api/v1/tema/auth/register", this->server_ip), this->server_sock);
            this->close_connection();

            if (!string_contains(response, "201 Created"))
            {
                std::cerr << "Registration failed\n";
                continue;
            }

            std::cout << "Registration successful\n";
        }
        else if (string_contains(command, "login"))
        {
            if (this->logged_in)
            {
                std::cout << "You are already logged in\n";
                continue;
            }
            std::string username, password;
            std::cout << "username=";
            std::cin >> username;
            std::cout << "password=";
            std::cin >> password;

            Request request;
            this->open_connection();
            std::string response = this->send_and_recv(request.post_credentials(username, password, "/api/v1/tema/auth/login", this->server_ip), this->server_sock);
            this->close_connection();

            if (!string_contains(response, "200 OK"))
            {
                std::cerr << "Authentification failed\n";
                continue;
            }

            const std::string cookie_start = "Set-Cookie: ";
            const std::string cookie_end = "; Path";
            size_t start_index = response.find(cookie_start);
            if (start_index != std::string::npos)
            {
                size_t end_index = response.find(cookie_end);
                this->cookie = response.substr(start_index + cookie_start.size(), end_index - start_index - cookie_end.size());
                this->logged_in = true;

                std::cout << "Logged in succesfully\n";
            }
        }
        else if (string_contains(command, "enter_library"))
        {
            if (!this->logged_in)
            {
                std::cout << "You need to login first\n";
                continue;
            }

            if (this->inside_library)
            {
                std::cout << "You already have access to the library\n";
                continue;
            }

            Request request;
            this->open_connection();
            std::string response = this->send_and_recv(request.get_cookie("/api/v1/tema/library/access", this->server_ip, this->cookie), this->server_sock);
            this->close_connection();

            if (!string_contains(response, "200 OK"))
            {
                std::cerr << "Your session has expired or is invalid\n";
                continue;
            }

            const std::string token_start = ":\"";
            const std::string token__end = "\"}";
            size_t start_index = response.find(token_start);
            size_t end_index = response.find(token__end);
            this->token = response.substr(start_index + token_start.size(), end_index - start_index - token__end.size());
            this->inside_library = true;

            std::cout << "Access to the library has been granted\n";
        }
        else if (string_contains(command, "get_books"))
        {
            if (!this->inside_library)
            {
                std::cout << "You do not have library access\n";
                continue;
            }

            Request request;
            this->open_connection();
            std::string response = this->send_and_recv(request.get_token("/api/v1/tema/library/books", this->server_ip, this->cookie, this->token), this->server_sock);
            this->close_connection();

            size_t start_index = response.find("[{\"");
            if (start_index != std::string::npos)
            {
                std::string payload = response.substr(start_index, response.size() - start_index);

                nlohmann::json json;
                json = nlohmann::json::parse(payload);
                std::cout << json.dump() << std::endl;
            }
        }
        else if (string_contains(command, "add_book"))
        {
            std::string title, author, genre, publisher, page_count;
            std::cout << "title=";
            std::getline(std::cin >> std::ws, title);
            std::cout << "author=";
            std::getline(std::cin, author);
            std::cout << "genre=";
            std::getline(std::cin, genre);
            std::cout << "publisher=";
            std::getline(std::cin, publisher);
            std::cout << "page_count=";
            std::getline(std::cin, page_count);

            while (!is_number(page_count))
            {
                std::cout << "Invalid value for page count!" << std::endl;
                std::cout << "page_count=";
                std::getline(std::cin, page_count);
            }

            Request request;
            this->open_connection();
            std::string response = this->send_and_recv(request.post_token(title, author, genre, publisher, page_count, "/api/v1/tema/library/books", this->server_ip, this->cookie, this->token), this->server_sock);
            this->close_connection();
            if (!string_contains(response, "200 OK"))
            {
                std::cout << "Failed to add book\n";
                continue;
            }

            std::cout << "Book has been added succesfully\n";
        }
        else if (string_contains(command, "get_book"))
        {
            if (!this->inside_library)
            {
                std::cout << "You do not have library access\n";
                continue;
            }

            std::string id;
            std::cout << "id=";
            std::cin >> id;

            Request request;
            this->open_connection();
            std::string response = this->send_and_recv(request.get_token("/api/v1/tema/library/books/" + id, this->server_ip, this->cookie, this->token), this->server_sock);
            this->close_connection();

            if (!string_contains(response, "200 OK"))
            {
                std::cout << "Book with id " + id + " doesn't exist\n";
                continue;
            }

            size_t start_index = response.find("{\"");
            std::string payload = response.substr(start_index, response.size() - start_index);

            nlohmann::json json;
            json = nlohmann::json::parse(payload);

            std::cout << json.dump() << std::endl;
        }
        else if (string_contains(command, "delete_book"))
        {
            if (!this->inside_library)
            {
                std::cout << "You do not have library access\n";
                continue;
            }

            std::string id;
            std::cout << "id=";
            std::cin >> id;

            Request request;
            this->open_connection();
            std::string response = this->send_and_recv(request.delete_req("/api/v1/tema/library/books/" + id, this->server_ip, this->cookie, this->token), this->server_sock);
            this->close_connection();

            if (!string_contains(response, "200 OK"))
            {
                std::cout << "Book with id " + id + " doesn't exist\n";
                continue;
            }

            std::cout << "Book has been removed succesfully\n";
        }
        else if (string_contains(command, "logout"))
        {
            if (!this->logged_in)
            {
                std::cout << "You need to login first\n";
                continue;
            }
            Request request;
            this->open_connection();
            std::string response = this->send_and_recv(request.get_cookie("/api/v1/tema/auth/logout", this->server_ip, this->cookie), this->server_sock);
            this->close_connection();

            if (!string_contains(response, "200 OK"))
            {
                std::cerr << "Failed to log out\n";
                continue;
            }

            std::cout << "Logged out succesfully\n";
            this->logged_in = false;
        }
        else if (string_contains(command, "exit"))
        {
            std::cout << "Exiting\n";
            exit(0);
        }
    }
}

void Client::open_connection()
{
    sockaddr_in server_addr;
    this->server_sock = socket(AF_INET, SOCK_STREAM, 0);
    std::memset(&server_addr, 0, sizeof(sockaddr_in));
    server_addr.sin_family = AF_INET;
    inet_aton(this->server_ip.c_str(), &server_addr.sin_addr);
    server_addr.sin_port = htons(this->port);

    if (connect(this->server_sock, (struct sockaddr *)&server_addr, sizeof(sockaddr_in)) < 0)
    {
        std::cerr << "Failed to initialize a connection to the server\n";
        close(this->server_sock);
        std::exit(-1);
    }
}

void Client::close_connection()
{
    close(this->server_sock);
}

int main(void)
{
    const std::string server_ip = "34.254.242.81";
    const int port = 8080;
    Client client(server_ip, port);
    client.run();
    return 0;
}