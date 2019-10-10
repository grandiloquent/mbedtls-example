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

int ssl_certificates(https *h);
int ssl_close(https *h);
int ssl_connect(https *h, const char *host, const char *port);
int ssl_handshake(https *h);
int ssl_init(https *h);
int ssl_setup(https *h, const char *host);
char *ssl_read_fully(https *h);

// ---------------------------------------------------------------


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
static char *header(const char *method,
                    const char *path,
                    const char *host,
                    const char *user_agent, size_t buf_length);

static char *header(const char *method,
                    const char *path,
                    const char *host,
                    const char *user_agent, size_t buf_length) {
  size_t len = buf_length;
  char *buf = malloc(len);
  if (buf == NULL)
    return NULL;
  memset(buf, 0, len);
/*
{method} {path} HTTP/1.1
Host: {host}
User-Agent: {user_agent}

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
  strcat(buf, "User-Agent: ");
  strcat(buf, user_agent);
  strcat(buf, "\r\n");
  strcat(buf, "\r\n");

// const char *method,const char *path,const char *host,const char *user_agent
// const char *method="";const char *path="";const char *host="";const char *user_agent=""
// method,path,host,user_agent
// strlen(method)+strlen(path)+strlen(host)+strlen(user_agent)


  return buf;
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

char *ssl_read_fully(https *h) {
  LOGE("%s\n", __FUNCTION__);

  char *buf = malloc(4096);
  char *tmp = NULL;
  size_t size = 0, capacity = 4096, content_length = 0;
  ssize_t rret;

  do {
    if (size == capacity) {
      capacity *= 2;
      buf = realloc(buf, capacity);
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
    //while ((rret = mbedtls_ssl_read(&h->ssl, buf + size, capacity - size)) == -1 && errno == EINTR);
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

static char *get_header(const char *host, const char *path) {
  const char *method = "GET";
  const char *user_agent = "Mozilla/5.0";
  size_t
      buf_header_length = (strlen(method) + strlen(path) + strlen(host) + strlen(user_agent));
  char *buf_header = header(method, path, host, user_agent, buf_header_length + 50);
  return buf_header;
}
int main() {
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

}