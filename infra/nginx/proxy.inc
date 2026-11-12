proxy_http_version 1.1;
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
# только адрес, с которого пришло соединение: присланный клиентом X-Forwarded-For отбрасывается
# (Stalwart берёт адрес клиента из этого заголовка, clientIpSource = xForwardedFor)
proxy_set_header X-Forwarded-For $remote_addr;
proxy_set_header X-Forwarded-Proto https;
proxy_set_header Forwarded "";
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection $tabora_connection;
proxy_read_timeout 300s;
proxy_buffering off;
