#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <http_parser.h>

void die()
{
    exit(1);
}

struct http_header
{
    char *name, *value;
    struct http_header *next;
};

struct http_headers
{
    struct http_header *first, *last;
};

char * clone_http_string(const char *data, size_t len)
{
    char *addr = NULL;
    addr = malloc(len+1);
    if(addr == NULL)
    {
        die();
    }

    memcpy(addr, data, len);
    addr[len] = '\0';
    return addr;
}

void append_header_name(struct http_headers *headers, const char *name, int len)
{
    struct http_header *header = NULL;
    header = malloc(sizeof(struct http_header));
    if(header == NULL)
    {
        die();
    }

    header->name = clone_http_string(name, len);
    header->value = NULL;
    header->next = NULL;

    if(headers->last == NULL)
    {
        headers->first = headers->last = header;
    }
    else
    {
        headers->last->next = header;
        headers->last = header;
    }
}

void fill_last_header_value(struct http_headers *headers, const char *value, int len)
{
    headers->last->value = clone_http_string(value, len);
}

struct http_chunk {
    char *data;
    size_t length;
    struct http_chunk *next;
};

struct http_body {
    struct http_chunk *first, *last;
};

void append_chunk(struct http_body *body, const char *data, size_t len)
{
    struct http_chunk *chunk = NULL;
    chunk = (struct http_chunk *)malloc(sizeof(struct http_chunk));
    if(chunk == NULL)
    {
        die();
    }

    memset(chunk, 0, sizeof(struct http_chunk));
    chunk->data = malloc(len);
    if(chunk->data == NULL)
    {
        die();
    }
    memcpy(chunk->data, data, len);
    chunk->length = len;

    if(body->first == NULL)
    {
        body->first = body->last = chunk;
    }
    else
    {
        body->last->next = chunk;
        body->last = chunk;
    }
}

struct http_request
{
    unsigned int method, http_major, http_minor, status_code;
    char *status, *url;
    struct http_headers headers;
    struct http_body body;

    int upgrade;
};

#define FREE(ptr)\
    if(ptr != NULL)\
    {\
        free(ptr);\
    }

void request_clear(struct http_request *request)
{
    FREE(request->status);
    FREE(request->url);

    struct http_header *header = NULL;
    if(request->headers.first != NULL)
    {
        header = request->headers.first;
    }
    while(header != NULL)
    {
        struct http_header *next = NULL;
        next = header->next;

        FREE(header->name);
        FREE(header->value);
        FREE(header);

        header = next;
    }

    struct http_chunk *chunk = NULL;
    if(request->body.first != NULL)
    {
        chunk = request->body.first;
    }
    while(chunk != NULL)
    {
        struct http_chunk *next = NULL;
        next = chunk->next;

        FREE(chunk->data);
        FREE(chunk);

        chunk = next;
    }


    memset(request, 0, sizeof(struct http_request));
}

int message_begin_handler(http_parser *parser)
{
//    printf("Message begin\r\n");

    return 0;
}

int headers_complete_handler(http_parser *parser)
{
    struct http_request *request = NULL;
    request = (struct http_request *)parser->data;

//    printf("Headers complete\r\n");

    request->method = parser->method;
    request->http_major = parser->http_major;
    request->http_minor = parser->http_minor;

    return 0;
}

int message_complete_handler(http_parser *parser)
{
//    printf("Message complete\r\n");

    struct http_request *request = NULL;
    request = (struct http_request *)parser->data;

    request->upgrade = parser->upgrade;

    return 0;
}

int chunk_header_handler(http_parser *parser)
{
    return 0;
}

int chunk_complete_handler(http_parser *parser)
{
    return 0;
}

int url_handler(http_parser *parser, const char *at, size_t length)
{
    struct http_request *request = NULL;
    request = (struct http_request *)parser->data;

    request->url = clone_http_string(at, length);

    return 0;
}

int status_handler(http_parser *parser, const char *at, size_t length)
{
    struct http_request *request = NULL;
    request = (struct http_request *)parser->data;

    request->status_code = parser->status_code;
    request->status = clone_http_string(at, length);

    return 0;
}

int header_field_handler(http_parser *parser, const char *at, size_t length)
{
    struct http_request *request = NULL;
    request = (struct http_request *)parser->data;

    append_header_name(&(request->headers), at, length);

    return 0;
}

int header_value_handler(http_parser *parser, const char *at, size_t length)
{
    struct http_request *request = NULL;
    request = (struct http_request *)parser->data;

    fill_last_header_value(&(request->headers), at, length);

    return 0;
}

int body_handler(http_parser *parser, const char *at, size_t length)
{
    struct http_request *request = NULL;
    request = (struct http_request *)parser->data;

    append_chunk(&request->body, at, length);

    return 0;
}

void parse_example_request(const http_parser_settings *settings)
{
    const char *headers = "GET / HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0\r\n"
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
            "Accept-Language: zh-CN,en-US;q=0.7,en;q=0.3\r\n"
            "Accept-Encoding: gzip, deflate\r\n"
            "DNT: 1\r\n"
            "Connection: keep-alive\r\n"
            "Upgrade-Insecure-Requests: 1\r\n"
            "If-Modified-Since: Fri, 09 Aug 2013 23:54:35 GMT\r\n"
            "If-None-Match: \"359670651+gzip\"\r\n"
            "Cache-Control: max-age=0\r\n"
            "\r\n";

    struct http_parser parser;
    memset(&parser, 0, sizeof(struct http_parser));
    http_parser_init(&parser, HTTP_REQUEST);

    struct http_request request;
    memset(&request, 0, sizeof(struct http_request));
    parser.data = &request;

    int nparsed = 0;
    nparsed = http_parser_execute(&parser, settings, headers, strlen(headers));
    printf("parsed: %d\r\nerr: %s\r\n\r\n", nparsed, http_errno_description(parser.http_errno));

    printf("%s %s %d.%d\r\n", http_method_str(request.method), request.url, request.http_major, request.http_minor);
    struct http_header *header = NULL;
    header = request.headers.first;
    while(header != NULL)
    {
        printf("%s: %s\r\n", header->name, header->value);
        header = header->next;
    }
    printf("\r\n");

    request_clear(&request);
}

void parse_example_response(const http_parser_settings *settings)
{
    const char *headers = "HTTP/1.1 200 OK\r\n"
            "Content-Encoding: gzip\r\n"
            "Accept-Ranges: bytes\r\n"
            "Cache-Control: max-age=604800\r\n"
            "Content-Type: text/html\r\n"
            "Date: Wed, 06 Sep 2017 09:23:41 GMT\r\n"
            "Etag: \"359670651+gzip\"\r\n"
            "Expires: Wed, 13 Sep 2017 09:23:41 GMT\r\n"
            "Last-Modified: Fri, 09 Aug 2013 23:54:35 GMT\r\n"
            "Server: ECS (cpm/F9D5)\r\n"
            "Vary: Accept-Encoding\r\n"
            "X-Cache: HIT\r\n"
            "Content-Length: 596\r\n"
            "\r\n";
    const char *body1 = "<!doctype html>\r\n"
            "<html>\r\n"
            "<head>\r\n"
            "    <title>Example Domain</title>\r\n"
            "    <meta charset=\"utf-8\" />\r\n"
            "    <meta http-equiv=\"Content-type\" content=\"text/html; charset=utf-8\" />\r\n"
            "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />  \r\n"
            "</head>\r\n";
    const char *body2 = "<body>\r\n"
            "<div>\r\n"
            "    <h1>Example Domain</h1>\r\n"
            "    <p>This domain is established to be used for illustrative examples in documents. You may use this\r\n"
            "    domain in examples without prior coordination or asking for permission.</p>\r\n"
            "    <p><a href=\"http://www.iana.org/domains/example\">More information...</a></p>\r\n"
            "</div>\r\n"
            "</body>\r\n"
            "</html>\r\n";

    struct http_parser parser;
    memset(&parser, 0, sizeof(struct http_parser));
    http_parser_init(&parser, HTTP_RESPONSE);

    struct http_request request;
    memset(&request, 0, sizeof(struct http_request));
    parser.data = &request;

    int nparsed = 0;
    nparsed += http_parser_execute(&parser, settings, headers, strlen(headers));
    nparsed += http_parser_execute(&parser, settings, body1, strlen(body1));
    nparsed += http_parser_execute(&parser, settings, body2, strlen(body2));
    printf("parsed: %d\r\nerr: %s\r\n\r\n", nparsed, http_errno_description(parser.http_errno));

    if(parser.http_errno != 0)
    {
        return;
    }

    printf("%d.%d %d %s\r\n", request.http_major, request.http_minor, request.status_code, request.status);
    struct http_header *header = NULL;
    header = request.headers.first;
    while(header != NULL)
    {
        printf("%s: %s\r\n", header->name, header->value);
        header = header->next;
    }
    printf("\r\n");
    if(request.body.first != NULL)
    {
        struct http_chunk *chunk = NULL;
        chunk = request.body.first;

        while(chunk != NULL)
        {
            printf("%.*s", chunk->length, chunk->data);

            chunk = chunk->next;
        }
    }
    printf("\r\n");

    request_clear(&request);
}

void parse_chunked_response(const http_parser_settings *settings)
{
    const char *headers = "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n";
    const char *chunk1 = "25\r\n"
            "This is the data in the first chunk\r\n\r\n";
    const char *chunk2 = "1C\r\n"
            "and this is the second one\r\n\r\n";
    const char *chunk3 = "3\r\n"
            "con\r\n";
    const char *chunk4 = "8\r\n"
            "sequence\r\n";
    const char *chunk5 = "0\r\n"
            "\r\n";

    struct http_parser parser;
    memset(&parser, 0, sizeof(struct http_parser));
    http_parser_init(&parser, HTTP_RESPONSE);

    struct http_request request;
    memset(&request, 0, sizeof(struct http_request));
    parser.data = &request;

    int nparsed = 0;
    nparsed += http_parser_execute(&parser, settings, headers, strlen(headers));
    nparsed += http_parser_execute(&parser, settings, chunk1, strlen(chunk1));
    nparsed += http_parser_execute(&parser, settings, chunk2, strlen(chunk2));
    nparsed += http_parser_execute(&parser, settings, chunk3, strlen(chunk3));
    nparsed += http_parser_execute(&parser, settings, chunk4, strlen(chunk4));
    nparsed += http_parser_execute(&parser, settings, chunk5, strlen(chunk5));
    printf("parsed: %d\r\nerr: %s\r\n\r\n", nparsed, http_errno_description(parser.http_errno));

    if(parser.http_errno != 0)
    {
        return;
    }

    printf("%d.%d %d %s\r\n", request.http_major, request.http_minor, request.status_code, request.status);
    struct http_header *header = NULL;
    header = request.headers.first;
    while(header != NULL)
    {
        printf("%s: %s\r\n", header->name, header->value);
        header = header->next;
    }
    printf("\r\n");
    if(request.body.first != NULL)
    {
        struct http_chunk *chunk = NULL;
        chunk = request.body.first;

        while(chunk != NULL)
        {
            printf("%.*s", chunk->length, chunk->data);

            chunk = chunk->next;
        }
    }

    request_clear(&request);
}

int main(int argc, char *argv[])
{
    struct http_parser_settings settings;
    memset(&settings, 0, sizeof(struct http_parser));
    settings.on_message_begin = message_begin_handler;
    settings.on_headers_complete = headers_complete_handler;
    settings.on_message_complete = message_complete_handler;
    settings.on_chunk_header = chunk_header_handler;
    settings.on_chunk_complete = chunk_complete_handler;
    settings.on_url = url_handler;
    settings.on_status = status_handler;
    settings.on_header_field = header_field_handler;
    settings.on_header_value = header_value_handler;
    settings.on_body = body_handler;

    parse_example_request(&settings);

    parse_example_response(&settings);

    parse_chunked_response(&settings);

    return 0;
}
