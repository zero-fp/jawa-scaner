### Описание

Скрипт ищет вызовы методов в пакетах репозитория Maven, или обычных jar-файлах

### Пример использования

Поиск всех вызовов методов из классов подходящих под регэкс "org.apache.logging.log4j.*" в пакете org.mule.tools:bobberplus:3.9.0. Результат сохраняется в файл ./out/org.mule.tools:bobberplus:3.9.0.txt
```
python3 main.py scan --class-regex "org.apache.logging.log4j.*"  --method-regex ".*" --caller-method ".*" --out-filename "./out/org.mule.tools:bobberplus:3.9.0.txt" --package org.mule.tools:bobberplus:3.9.0
```

Вывод результата сканирования в удобном виде

```
python3 main.py export --scan-json "./out/org.mule.tools:bobberplus:3.9.0.txt"
```

