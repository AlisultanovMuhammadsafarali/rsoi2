Третья лабораторная работа по РСОИ.

Условие: " На наработках 2ой лабораторной разделив и добавив функционал, сделать следующее:

1. Два (или более беканда) каждый отвечает за свои данные (например: бекенд работы с книгами, беканд работы с авторами)
2. Один бекенд - сессия.
3. Один фронтенд - агрегация информаций из бекенда
4. (опционально) Cлой логики, берущий на себя часть работы фронтенда (работу с сессией и запросы к более низким уровням бекендов)
Все это различные приложения. Все приложения (кроме фрнотенда) имеют REST API Желательный формат сообщений взаимодействия - JSON Можно сделать одну базу данных на все бекенды (но работать в разных таблицах)

Простенький GUI на html (не переусердствуйте) Для бекендов реализовать не только просмотр но и добавление, удаление, обновление контента. Примерная схема отображена на картинке.

Приложение должно уметь из фронтенда делать запросы на каждый из бекендов #1 по отдельности (например, просмотреть список книг, просмотреть список авторов), так и осуществлять 2 запроса и агрегировать информацию (например, просмотреть расширенный список книг с указанием в информации о книге расширенную информаци об авторах)

Часть ресурсов должна быть защищенная, часть нет (например, Вы можете просмотреть общий список книг, но так же должен функционал отобранных книг для этого пользователя)

Не забывайте про авторизацию. "
