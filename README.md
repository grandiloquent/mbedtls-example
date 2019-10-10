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

- https://github.com/ARMmbed/mbedtls