# TLS SERVER


A simple TLS Server using poll.  

## usage


Test the program using curl command:
    curl -k -v --http0.9 https://IP:PORT

## Generate Self-Signed Certificate


`openssl req -x509 -nodes -days 365 -newkey rsa:1024 -keyout [KEY_NAME].pem -out [CERT_NAME].pem`

# TLS_Server
