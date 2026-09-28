# bundled/ufw-docker

Скрипт [chaifeng/ufw-docker](https://github.com/chaifeng/ufw-docker) (MIT).
Butler вызывает его при «Применить правила» (`install` + `ufw route` только для IP из whitelist).

В копии Butler есть обязательные изменения: локализованный статус UFW и
проверка правил для уже установленных входящих соединений. Fast path
ESTABLISHED разрешён только для ответов на исходящие соединения сервера;
входящие пакеты снова проходят правила сервисов. Это касается before.rules,
before6.rules и DOCKER-USER. Conntrack при Apply не удаляется: TCP loose pickup
может восстановить удалённую запись в обратном направлении.

При обновлении upstream сохраните эти изменения и запустите регрессионные
тесты, включая живые keep-alive соединения при изменении белого списка.
