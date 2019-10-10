#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/certs.h>
#include <errno.h>
#include <sys/stat.h>
#include "ca_cert.h"

#define LOGE(fmt, ...) printf(fmt, ##__VA_ARGS__)

typedef struct {
  mbedtls_net_context fd;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config conf;
  mbedtls_x509_crt crt;
} https;

// ---------------------------------------------------------------
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

// ---------------------------------------------------------------

static int get_bing() {
  const char *host = "cn.bing.com";
  const char *port = "443";
  const char *path = "/";

  https *h = malloc(sizeof(https));

//  int ret = ssl_init(h);
//  ret = ssl_certificates(h);
//  ret = ssl_connect(h, host, "443");
//  ret = ssl_setup(h, host);
//  ret = ssl_handshake(h);

  int ret = ssl_init(h);

  if (ret != 0) {
    LOGE("%s:%d\n", "ssl_init", ret);
    goto exit;
  }
  ret = ssl_certificates(h);

  if (ret != 0) {
    LOGE("%s:%d\n", "ssl_certificates", ret);
    goto exit;
  }
  ret = ssl_connect(h, host, port);

  if (ret != 0) {
    LOGE("%s:%d\n", "ssl_connect", ret);
    goto exit;
  }
  ret = ssl_setup(h, host);

  if (ret != 0) {
    LOGE("%s:%d\n", "ssl_setup", ret);
    goto exit;
  }
  ret = ssl_handshake(h);

  if (ret != 0) {
    LOGE("%s:%d\n", "ssl_handshake", ret);
    goto exit;
  }

  char *buf_header = get_header(host, path);
  if (buf_header == NULL) {
    LOGE("Fail at get_header.\n");
    goto exit;
  }
  ret = ssl_write(h, (const unsigned char *) buf_header, strlen(buf_header));
  free(buf_header);
  if (ret != 0) {
    LOGE("%s:%d\n", "ssl_write", ret);
    goto exit;
  }

  char *buf = ssl_read_fully(h);
  mbedtls_ssl_close_notify(&h->ssl);

  if (buf != NULL) {
    LOGE("buf length %lld\n %s", strlen(buf), buf);
    free(buf);
  }

  // --------------------------
  exit:
  ssl_close(h);
  return ret;
}

static char *get_filename(const char *path) {
  const char *s = path + strlen(path);
  while (*--s && (*s != '\\' && *s != '/'));
  if (*s)++s;
  return s;
}

static char *get_header(const char *host, const char *path) {
  const char *method = "GET";
  const char *user_agent = "Mozilla/5.0";
  size_t
      buf_header_length = (strlen(method) + strlen(path) + strlen(host) + strlen(user_agent));
  char *buf_header =
      header(buf_header_length + 50, NULL, method, path, host, NULL, user_agent, NULL);
  return buf_header;
}

static char *get_upload_header() {
  const char *file_path = "C:\\Users\\psycho\\CLionProjects\\mbedtls\\1.jpg";

  struct stat stat_buf;
  if (stat(file_path, &stat_buf) != 0) {

  }
  size_t file_length = stat_buf.st_size;

  const char *port = "5000";
  const char *method = "POST";
  const char *path = "/api/upload";
  const char *host = "localhost";
  const char *content_type = "application/json";
  const char *user_agent = "Mozilla/5.0";

  const char *boundary = "----WebKitFormBoundaryTjlkgpnCWY9MNBrA";
  const char *filename_field = "file";
  const char *filename = get_filename(file_path);
  const char *mime_type = "image/jpeg";

  size_t buf_header_len =
      strlen(path) + strlen(host) + strlen(boundary) + strlen(user_agent)
          + strlen(boundary) + strlen(filename_field) + strlen(filename) + strlen(mime_type);

  char *buf_header = header_upload(buf_header_len << 2,
                                   file_length,
                                   path,
                                   host,
                                   boundary,
                                   user_agent,
                                   filename_field,
                                   filename,
                                   mime_type);
}

static char *header(size_t buf_length,
                    const char *headers,
                    const char *method,
                    const char *path,
                    const char *host,
                    const char *content_type,
                    const char *user_agent,
                    const char *body) {
  size_t len = buf_length;
  char *buf = malloc(len);
  if (buf == NULL)
    return NULL;
  memset(buf, 0, len);
/*
 * application/json
{method} {path} HTTP/1.1
Host: {host}
Content-Length: {content_length}
Content-Type: {content_type}
User-Agent: {user_agent}

{body}

  Connection: keep-alive <crlf>
  Accept: text/html,application/xhtml+xml,application/xml;q=0.9... <crlf>
  User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_4)... <crlf>
  Accept-Encoding: gzip, deflate, sdch <crlf>
  Accept-Language: en-US,en;q=0.8 <crlf>
  Cookie: pfy_cbc_lb=p-browse-w; customerZipCode=99912|N; ltc=%20;... <crlf>
  <crlf>

 */
  strcat(buf, method);
  strcat(buf, " ");
  strcat(buf, path);
  strcat(buf, " HTTP/1.1");
  strcat(buf, "\r\n");
  strcat(buf, "Host: ");
  strcat(buf, host);
  strcat(buf, "\r\n");

  if (body != NULL) {
    strcat(buf, "Content-Length: ");
    header_content_length(buf, strlen(body));
    strcat(buf, "\r\n");

  }
  if (content_type != NULL) {
    strcat(buf, "Content-Type: ");
    strcat(buf, content_type);
    strcat(buf, "\r\n");
  }

  strcat(buf, "User-Agent: ");
  strcat(buf, user_agent);
  strcat(buf, "\r\n");

  if (headers != NULL) {
    strcat(buf, headers);
  }
  strcat(buf, "\r\n");

  if (body != NULL)
    strcat(buf, body);

// const char *method,const char *path,const char *host,const char *content_length,const char *content_type,const char *user_agent,const char *body
// const char *method="";const char *path="";const char *host="";const char *content_length="";const char *content_type="";const char *user_agent="";const char *body=""
// method,path,host,content_length,content_type,user_agent,body
// strlen(method)+strlen(path)+strlen(host)+strlen(content_length)+strlen(content_type)+strlen(user_agent)+strlen(body)

  return
      buf;
}

static void header_content_length(char *buf, size_t len) {
  size_t buf_body_len = 0;
  size_t body_len = len, tmp_len = body_len;
  while ((tmp_len /= 10) > 0) {

    buf_body_len++;
  }
  buf_body_len++;

  char buf_content_len[buf_body_len];
  itoa(body_len, buf_content_len, 10);
  strcat(buf, buf_content_len);
}

static char *header_upload(size_t buf_len,
                           size_t file_length,
                           const char *path,
                           const char *host,
                           const char *boundary,
                           const char *user_agent,
                           const char *filename_field,
                           const char *filename,
                           const char *mime_type

) {
  /*
   * image/jpeg
POST {path} HTTP/1.1
Host: {host}
Content-Length: {file_length}
Content-Type: multipart/form-data; boundary={boundary}
User-Agent: {user_agent}

--{boundary}
Content-Disposition: form-data; name=\\u0022{filename_field}\\u0022; filename=\\u0022{filename}\\u0022
Content-Type: {mime_type}

{file_content}
--{boundary}--
   */

  char header_file[256];
  memset(header_file, 0, 256);
  strcat(header_file, "--");
  strcat(header_file, boundary);
  strcat(header_file, "\r\n");
  strcat(header_file, "Content-Disposition: form-data; name=\"");
  strcat(header_file, filename_field);
  strcat(header_file, "\"; filename=\"");
  strcat(header_file, filename);
  strcat(header_file, "\"");
  strcat(header_file, "\r\n");
  strcat(header_file, "Content-Type: ");
  strcat(header_file, mime_type);
  strcat(header_file, "\r\n");
  strcat(header_file, "\r\n");

  char *buf = malloc(buf_len);
  if (buf == NULL) {
    return NULL;
  }
  memset(buf, 0, buf_len);

  strcat(buf, "POST ");
  strcat(buf, path);
  strcat(buf, " HTTP/1.1");
  strcat(buf, "\r\n");
  strcat(buf, "Host: ");
  strcat(buf, host);
  strcat(buf, "\r\n");
  strcat(buf, "Content-Length: ");
  header_content_length(buf, file_length + strlen(header_file));
  strcat(buf, "\r\n");
  strcat(buf, "Content-Type: multipart/form-data; boundary=");
  strcat(buf, boundary);

  strcat(buf, "\r\n");
  strcat(buf, "User-Agent: ");
  strcat(buf, user_agent);
  strcat(buf, "\r\n");
  strcat(buf, "\r\n");
  strcat(buf, header_file);

// const char *path,const char *host,const char *file_length,const char *boundary,const char *user_agent,const char *boundary,const char *filename_field,const char *filename,const char *mime_type
// const char *path="";const char *host="";const char *file_length="";const char *boundary="";const char *user_agent="";const char *boundary="";const char *filename_field="";const char *filename="";const char *mime_type=""
// path,host,file_length,boundary,user_agent,boundary,filename_field,filename,mime_type
// strlen(path)+strlen(host)+strlen(file_length)+strlen(boundary)+strlen(user_agent)+strlen(boundary)+strlen(filename_field)+strlen(filename)+strlen(mime_type)

  return buf;
}

static int post_json() {
  const char *port = "5000";
  const char *method = "POST";
  const char *path = "/api/commands";
  const char *host = "localhost";
  const char *content_type = "application/json";
  const char *user_agent = "Mozilla/5.0";
  const char *body = "select id from note limit 5";

  https *h = malloc(sizeof(https));

  int ret = ssl_init(h);

  if (ret != 0) {
    LOGE("%s:%d\n", "ssl_init", ret);
    goto exit;
  }
  ret = ssl_certificates(h);

  if (ret != 0) {
    LOGE("%s:%d\n", "ssl_certificates", ret);
    goto exit;
  }
  ret = ssl_connect(h, host, port);

  if (ret != 0) {
    LOGE("%s:%d\n", "ssl_connect", ret);
    goto exit;
  }
  ret = ssl_setup(h, host);

  if (ret != 0) {
    LOGE("%s:%d\n", "ssl_setup", ret);
    goto exit;
  }
  ret = ssl_handshake(h);

  if (ret != 0) {
    LOGE("%s:%d\n", "ssl_handshake", ret);
    goto exit;
  }
  const char *headers = "Authorization: Bearer test\r\n";
  size_t buf_header_len =
      strlen(method) + strlen(path) + strlen(host)
          + strlen(content_type) + strlen(user_agent) + strlen(body);
  char *buf_header =
      header(buf_header_len << 1, headers, method, path, host, content_type, user_agent, body);
  if (buf_header == NULL) {
    LOGE("Fail at get_header.\n");
    goto exit;
  }
  ret = ssl_write(h, (const unsigned char *) buf_header, strlen(buf_header));
  free(buf_header);
  if (ret != 0) {
    LOGE("%s:%d\n", "ssl_write", ret);
    goto exit;
  }

  char *buf = ssl_read_fully(h);
  mbedtls_ssl_close_notify(&h->ssl);

  if (buf != NULL) {
    LOGE("buf length %lld\n %s", strlen(buf), buf);
    free(buf);
  }

  // --------------------------
  exit:
  ssl_close(h);
  return ret;
}

int ssl_certificates(https *h) {
  ca_crt_rsa[ca_crt_rsa_size - 1] = 0;

  int ret = mbedtls_x509_crt_parse(&h->crt, (const unsigned char *) ca_crt_rsa,
                                   ca_crt_rsa_size);
  if (ret < 0) {
    LOGE(" failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n", -ret);
    return ret;
  }
  return 0;
}

int ssl_close(https *h) {
  mbedtls_net_free(&h->fd);
  mbedtls_x509_crt_free(&h->crt);
  mbedtls_ssl_free(&h->ssl);
  mbedtls_ssl_config_free(&h->conf);
  mbedtls_ctr_drbg_free(&h->ctr_drbg);
  mbedtls_entropy_free(&h->entropy);
  free(h);
}

int ssl_connect(https *h, const char *host, const char *port) {
  int ret;
  if ((ret = mbedtls_net_connect(&h->fd, host,
                                 port, MBEDTLS_NET_PROTO_TCP)) != 0) {
    LOGE(" failed\n  ! mbedtls_net_connect returned %d\n\n", ret);
    return ret;
  }
  return 0;

}

int ssl_handshake(https *h) {
  int ret;
  while ((ret = mbedtls_ssl_handshake(&h->ssl)) != 0) {
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
      LOGE(" failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret);
      return ret;
    }
  }
  return 0;

}

int ssl_init(https *h) {
  int ret;
  mbedtls_net_init(&h->fd);
  mbedtls_ssl_init(&h->ssl);
  mbedtls_ssl_config_init(&h->conf);
  mbedtls_x509_crt_init(&h->crt);
  mbedtls_ctr_drbg_init(&h->ctr_drbg);
  mbedtls_entropy_init(&h->entropy);
  if ((ret = mbedtls_ctr_drbg_seed(&h->ctr_drbg, mbedtls_entropy_func, &h->entropy,
                                   NULL, 0)) != 0) {
    LOGE(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
    return 1;
  }
  return 0;
}

char *ssl_read_fully(https *h) {
  char *buf = malloc(4096);
  if (buf == NULL) {
    LOGE("Failed at %s \nmalloc(4096)\n", __FUNCTION__);

    return NULL;
  }
  char *tmp = NULL;
  size_t size = 0, capacity = 4096, content_length = 0;
  ssize_t rret;

  do {
    if (size == capacity) {
      capacity *= 2;
      buf = realloc(buf, capacity);
      if (buf == NULL) {
        LOGE("Failed at %s \nrealloc(%lld)\n", __FUNCTION__, capacity);
        return NULL;
      }
    }
    //LOGE("mbedtls_ssl_read %s %d\n", __FUNCTION__, capacity);

    rret = mbedtls_ssl_read(&h->ssl, buf + size, capacity - size);

    // trying parse the body length
    if (tmp == NULL && (tmp = strstr(buf, "Content-Length: ")) != NULL) {
      tmp = tmp + strlen("Content-Length: ");

      for (int i = 0, j = strlen(tmp); i < j; ++i) {
        if (tmp[i] == '\r') {
          char buf_content[i + 1];
          tmp = memcpy(buf_content, tmp, i + 1);
          if (tmp != NULL) {
            content_length = strtol(tmp, NULL, 10);
          }
          break;
        }
      }

    }

    if (content_length != 0) {
      char *buf_body = strstr(buf, "\r\n\r\n");
      if (buf_body != NULL && strlen(buf_body) + 4 >= content_length) {
        return buf;
      }
    }
    if (rret == MBEDTLS_ERR_SSL_WANT_READ || rret == MBEDTLS_ERR_SSL_WANT_WRITE)
      continue;

    if (rret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
      break;

    if (rret < 0) {
      LOGE("failed\n  ! mbedtls_ssl_read returned %d\n\n", rret);
      break;
    }

    if (rret == 0) {
      LOGE("\n\nEOF\n\n");
      break;
    }

    size += rret;
  } while (1);
  return buf;
}

int ssl_setup(https *h, const char *host) {
  int ret;

  if ((ret = mbedtls_ssl_config_defaults(&h->conf,
                                         MBEDTLS_SSL_IS_CLIENT,
                                         MBEDTLS_SSL_TRANSPORT_STREAM,
                                         MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
    LOGE(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
    return ret;
  }

  mbedtls_ssl_conf_authmode(&h->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
  mbedtls_ssl_conf_ca_chain(&h->conf, &h->crt, NULL);
  mbedtls_ssl_conf_rng(&h->conf, mbedtls_ctr_drbg_random, &h->ctr_drbg);

  if ((ret = mbedtls_ssl_setup(&h->ssl, &h->conf)) != 0) {
    LOGE(" failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
    return ret;
  }

  if ((ret = mbedtls_ssl_set_hostname(&h->ssl, host)) != 0) {
    LOGE(" failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
    return ret;
  }

  mbedtls_ssl_set_bio(&h->ssl, &h->fd, mbedtls_net_send, mbedtls_net_recv, NULL);
  return 0;
}

int ssl_write(https *h, const unsigned char *buf, size_t buf_len) {
  int ret;
  while ((ret = mbedtls_ssl_write(&h->ssl, buf, buf_len)) <= 0) {
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
      LOGE(" failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
      return ret;
    }
  }
  return 0;
}

int ssl_write_file(https *h, const char *file_path, size_t buf_size) {

  FILE *in = fopen(file_path, "r");
  if (in == NULL) {
    return 1;
  }
  char buf[buf_size];
  size_t file_read, file_send;
  while (1) {
    file_read = read(in, buf, buf_size);
    if (file_read == 0) {
      close(in);
      return 0;
    }
    while ((file_send = mbedtls_ssl_write(&h->ssl, buf, file_read)) <= 0) {
      if (file_send != MBEDTLS_ERR_SSL_WANT_READ && file_send != MBEDTLS_ERR_SSL_WANT_WRITE) {
        {
          close(in);
          return file_send;
        }
      }
    }

  }

}

int main() {

  char *buf_header = get_upload_header();

  printf("%s\n", buf_header);
}