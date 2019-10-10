# mbedtls examples

```
static int get_bing();
static char *get_filename(const char *path);
static char *get_header(const char *host, const char *path);
static char *get_upload_header();
static char *header(size_t buf_length,
                    const char *headers,
                    const char *method,
                    const char *path,
                    const char *host,
                    const char *content_type,
                    const char *user_agent,
                    const char *body);
static void header_content_length(char *buf, size_t len);
static char *header_upload(size_t buf_len,
                           size_t file_length,
                           const char *path,
                           const char *host,
                           const char *boundary,
                           const char *user_agent,
                           const char *filename_field,
                           const char *filename,
                           const char *mime_type

);
static int post_json();
int ssl_certificates(https *h);
int ssl_close(https *h);
int ssl_connect(https *h, const char *host, const char *port);
int ssl_handshake(https *h);
int ssl_init(https *h);
char *ssl_read_fully(https *h);
int ssl_setup(https *h, const char *host);
int ssl_write(https *h, const unsigned char *buf, size_t buf_len);
int ssl_write_file(https *h, const char *file_path, size_t buf_size);
```

```
POST /api/upload HTTP/1.1
Host: localhost:5000
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Cache-Control: max-age=0
Connection: keep-alive
Content-Length: 53315
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryTjlkgpnCWY9MNBrA
Cookie: _ga=GA1.1.1819275317.1565499913; _gid=GA1.1.497015746.1570667806
Origin: http://localhost:5000
Referer: http://localhost:5000/upload
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3724.8 Safari/537.36

------WebKitFormBoundaryTjlkgpnCWY9MNBrA
Content-Disposition: form-data; name="q"


------WebKitFormBoundaryTjlkgpnCWY9MNBrA
Content-Disposition: form-data; name="file"; filename="00001_Cover_00001.jpg"
Content-Type: image/jpeg

{file_content}
------WebKitFormBoundaryTjlkgpnCWY9MNBrA--
```




- https://github.com/ARMmbed/mbedtls