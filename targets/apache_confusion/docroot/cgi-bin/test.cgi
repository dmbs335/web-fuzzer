#!/bin/sh
echo "Content-Type: text/plain"
echo ""
echo "CGI OK"
echo "PATH_INFO=$PATH_INFO"
echo "QUERY_STRING=$QUERY_STRING"
echo "REQUEST_URI=$REQUEST_URI"
