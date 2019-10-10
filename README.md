# mbedtls examples

    typedef struct {
      mbedtls_net_context fd;
      mbedtls_entropy_context entropy;
      mbedtls_ctr_drbg_context ctr_drbg;
      mbedtls_ssl_context ssl;
      mbedtls_ssl_config conf;
      mbedtls_x509_crt crt;
    } https;

    int ssl_certificates(https *h);
    int ssl_close(https *h);
    int ssl_connect(https *h, const char *host, const char *port);
    int ssl_handshake(https *h);
    int ssl_init(https *h);
    int ssl_setup(https *h, const char *host);
    char *ssl_read_fully(https *h);

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

```
GET /api/test HTTP/1.1
Host: localhost:5000
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Connection: keep-alive
Cookie: _ga=GA1.1.1819275317.1565499913; _gid=GA1.1.497015746.1570667806
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3724.8 Safari/537.36


```



- https://github.com/ARMmbed/mbedtls