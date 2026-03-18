ARG HTTPD_TAG=2.4
FROM httpd:${HTTPD_TAG}

# Install build tools for apxs
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        apache2-dev gcc libapr1-dev libaprutil1-dev make && \
    rm -rf /var/lib/apt/lists/*

# Build mod_fuzztrace
COPY mod_fuzztrace/mod_fuzztrace.c /tmp/mod_fuzztrace.c
RUN apxs -i -a -c /tmp/mod_fuzztrace.c && \
    rm -f /tmp/mod_fuzztrace.c

# Enable commonly needed modules (some configs need these)
RUN sed -i \
    -e 's/^#LoadModule rewrite_module/LoadModule rewrite_module/' \
    -e 's/^#LoadModule proxy_module/LoadModule proxy_module/' \
    -e 's/^#LoadModule proxy_http_module/LoadModule proxy_http_module/' \
    -e 's/^#LoadModule proxy_ajp_module/LoadModule proxy_ajp_module/' \
    -e 's/^#LoadModule cgi_module/LoadModule cgi_module/' \
    -e 's/^#LoadModule cgid_module/LoadModule cgid_module/' \
    -e 's/^#LoadModule negotiation_module/LoadModule negotiation_module/' \
    -e 's/^#LoadModule autoindex_module/LoadModule autoindex_module/' \
    -e 's/^#LoadModule actions_module/LoadModule actions_module/' \
    -e 's/^#LoadModule alias_module/LoadModule alias_module/' \
    -e 's/^#LoadModule include_module/LoadModule include_module/' \
    -e 's/^#LoadModule env_module/LoadModule env_module/' \
    -e 's/^#LoadModule setenvif_module/LoadModule setenvif_module/' \
    -e 's/^#LoadModule dav_module/LoadModule dav_module/' \
    -e 's/^#LoadModule dav_fs_module/LoadModule dav_fs_module/' \
    -e 's/^#LoadModule cache_module/LoadModule cache_module/' \
    -e 's/^#LoadModule cache_disk_module/LoadModule cache_disk_module/' \
    -e 's/^#LoadModule socache_shmcb_module/LoadModule socache_shmcb_module/' \
    -e 's/^#LoadModule auth_basic_module/LoadModule auth_basic_module/' \
    -e 's/^#LoadModule authn_file_module/LoadModule authn_file_module/' \
    -e 's/^#LoadModule authz_groupfile_module/LoadModule authz_groupfile_module/' \
    -e 's/^#LoadModule authz_user_module/LoadModule authz_user_module/' \
    -e 's/^#LoadModule allowmethods_module/LoadModule allowmethods_module/' \
    /usr/local/apache2/conf/httpd.conf

# Create dirs needed by mod_dav and mod_cache
RUN mkdir -p /var/lock/apache2/dav /var/cache/apache2/mod_cache_disk && \
    chown -R www-data:www-data /var/lock/apache2 /var/cache/apache2 || true

# Copy docroot with test files
COPY docroot/ /usr/local/apache2/htdocs/

# Config will be mounted or copied per-container
# Each config variant is COPYed via docker-compose build args
ARG CONFIG_FILE=configs/00_baseline.conf
COPY ${CONFIG_FILE} /usr/local/apache2/conf/extra/fuzztrace.conf

# CVE test files (persistent across container restarts)
RUN mkdir -p /var/user/orange /usr/share/test /usr/local/apache2/cgi-bin && \
    echo "SECRET PROFILE" > /var/user/orange/secret.yml && \
    echo "public profile" > /var/user/orange/profile.yml && \
    echo "USR_SHARE outside docroot" > /usr/share/test/index.html && \
    echo "ADMIN SECRET" > /usr/local/apache2/htdocs/admin.php && \
    printf '#!/bin/sh\nREDIR=$(echo "$QUERY_STRING" | sed "s/^r=//" | perl -pe "s/%%([0-9A-Fa-f]{2})/chr(hex($$1))/ge")\nprintf "Status: 200\\r\\n"\nprintf "Location: %%s\\r\\n" "$REDIR"\nprintf "Content-Type: text/html\\r\\n"\nprintf "\\r\\n"\necho "ok"\n' > /usr/local/apache2/cgi-bin/redir.cgi && \
    chmod +x /usr/local/apache2/cgi-bin/redir.cgi

# AllowEncodedSlashes for %3F and %2F testing
RUN echo 'AllowEncodedSlashes NoDecode' >> /usr/local/apache2/conf/httpd.conf

# Include our config
RUN echo 'Include conf/extra/fuzztrace.conf' >> /usr/local/apache2/conf/httpd.conf

EXPOSE 80

CMD ["httpd-foreground"]
