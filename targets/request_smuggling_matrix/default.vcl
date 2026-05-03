vcl 4.1;

backend default {
    .host = "backend";
    .port = "8081";
    .connect_timeout = 1s;
    .first_byte_timeout = 30s;
    .between_bytes_timeout = 30s;
}

sub vcl_recv {
    return (hash);
}

sub vcl_backend_response {
    set beresp.ttl = 30s;
}

sub vcl_deliver {
    set resp.http.X-Varnish-Matrix = "1";
}
