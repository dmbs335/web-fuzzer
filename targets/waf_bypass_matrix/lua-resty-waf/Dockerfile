FROM openresty/openresty:alpine-fat

RUN apk add --no-cache --virtual .build-deps \
        git \
        build-base \
        pcre-dev \
        python3 \
    && ln -sf /usr/bin/python3 /usr/bin/python \
    && ln -sf /usr/local/openresty/luajit/include/luajit-2.1 /usr/include/lua5.1 \
    && cd /tmp \
    && git clone https://github.com/p0pr0ck5/lua-resty-waf.git --recursive \
    && cd lua-resty-waf \
    && 2to3 -w -n libinjection/src/*.py \
    && sed -i 's/-Werror//g' src/Makefile \
    && make \
    && make install \
    && cd / && rm -rf /tmp/lua-resty-waf \
    && apk del .build-deps

RUN apk add --no-cache curl pcre

COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf

EXPOSE 8080

CMD ["openresty", "-g", "daemon off;"]
