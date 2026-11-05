Первая публичная предварительная версия GHole.

Автор: Кислов Роман Сергеевич (@rkislov). Apache License 2.0.

DNS UDP/TCP, итеративная рекурсия, primary/forward/stub-зоны, сплит отдельных RRset по CIDR вплоть до /32 и /128, импорт/экспорт BIND9 zone files, фиды, SQLite/PostgreSQL, DoH/DoT, встроенная HTTPS-панель, Prometheus и журнал с пагинацией.

Артефакты: Linux amd64/arm64 tar.gz; RPM-профили Альт Linux и РЕД ОС; DEB-профиль Astra Linux; SHA256SUMS. Смотрите docs/linux-installation.md и актуальные результаты smoke-тестов в docs/compatibility.md.

DNSSEC-валидация ещё не реализована. Поддержка упаковки для дистрибутива не означает сертификацию или полное испытание его защитных механизмов. Проект пока предназначен для тестовых сетей и пилотных установок.
