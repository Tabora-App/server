# То же для письма, которому человек разрешил картинки с чужих серверов (/frame/mail-remote.html).
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "no-referrer" always;
add_header Cross-Origin-Opener-Policy "same-origin" always;
add_header Cross-Origin-Resource-Policy "same-origin" always;
add_header Permissions-Policy "camera=(self), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()" always;
add_header Content-Security-Policy "default-src 'none'; style-src 'unsafe-inline'; font-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'self'; img-src data: blob: https:" always;
add_header X-Frame-Options "SAMEORIGIN" always;
