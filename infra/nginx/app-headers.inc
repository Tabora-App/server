# Заголовки страницы веб-версии (app.tabora.app). Должны совпадать с tools/web/headers.mjs:
# это сверяет tools/web/test/headers.test.mjs. Приложению разрешено только своё: скрипты, стили,
# шрифты и запросы — с того же имени; ни одного стороннего адреса и ни одного встроенного скрипта.
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "no-referrer" always;
add_header Cross-Origin-Opener-Policy "same-origin" always;
add_header Cross-Origin-Resource-Policy "same-origin" always;
add_header Permissions-Policy "camera=(self), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()" always;
add_header Content-Security-Policy "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; worker-src 'self'; frame-src 'self'; manifest-src 'self'; media-src 'self' blob:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'" always;
add_header X-Frame-Options "DENY" always;
