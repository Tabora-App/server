# Заголовки документа рамки письма (/frame/mail.html): в него приложение вкладывает очищенную вёрстку
# письма. Скриптов и сети у документа нет; встроенные стили нужны вёрстке писем.
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "no-referrer" always;
add_header Cross-Origin-Opener-Policy "same-origin" always;
add_header Cross-Origin-Resource-Policy "same-origin" always;
add_header Permissions-Policy "camera=(self), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()" always;
add_header Content-Security-Policy "default-src 'none'; style-src 'unsafe-inline'; font-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'self'; img-src data: blob:" always;
add_header X-Frame-Options "SAMEORIGIN" always;
