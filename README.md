# crypto.park-hw2

## Задание

Программа эмулирует работу автомобильного брелока, открывающего машину, с использованием ЭЦП в условиях, когда канал связи полностью доступен любому прослушивающему (в том числе и в течение большого времени и попыток), также атакующий может повторить прослушанные данные.

## Идея

Брелок посылает команду, предварительно добавив метку времени для проверки того, что команда была отправлена только что, а не была сгенерирована давно и в данный момент происходит попытка повтора сообщения злоумышленником.

Все команды отправляются в зашифрованном виде, чтобы скрыть реальные данные. Таким образом команду может прочитать только тот, кому она предназначается (автомобиль). Если данные попадут к злоумышленнику, он с ними ничего сделать не сможет.

Также, чтобы подтвердить, что команда послана от знакомого устройства, генерируется и передается подпись.

## Запуск

```go run main.go```

## Примеры
*Успешно*

![Успешно](example.png)

*Попытка повторной отправки через некоторое время*

![Попытка повторной отправки через некоторое время](hacking_example.png)
