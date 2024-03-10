DROP DATABASE IF EXISTS sftdb;
CREATE DATABASE sftdb;
USE sftdb;

CREATE TABLE users (
	user_id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(256) NOT NULL,
    password_hash VARCHAR(256) NOT NULL
) Engine=InnoDB;

insert into users (username, password_hash) values
('usman', '$2b$12$RrxpbbRqsrxM2fMl8MqX7eBcK69WpcL5MPfISW04Edsk7By6lWcMm'),
('daniel', '$2b$12$Tmy8OolB.9TMNWOvFAnOoust/8NnoNHbg35GE04.QjCmUszVtKnxS');

SET time_zone = '-05:00';

-- Create stored procedures
delimiter //

create procedure get_user (
	in username varchar(256)
)
begin
	select username, password_hash from users where users.username = username;
end //


