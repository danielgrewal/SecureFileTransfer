CREATE DATABASE IF NOT EXISTS sftdb;
USE sftdb;

CREATE TABLE IF NOT EXISTS users (
	user_id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(256) NOT NULL,
    password_hash VARCHAR(256) NOT NULL
) Engine=InnoDB;

insert into users (username, password_hash) values
('usman', '$2b$12$RrxpbbRqsrxM2fMl8MqX7eBcK69WpcL5MPfISW04Edsk7By6lWcMm'),
('daniel', '$2b$12$Tmy8OolB.9TMNWOvFAnOoust/8NnoNHbg35GE04.QjCmUszVtKnxS');

CREATE TABLE IF NOT EXISTS sessions (
	session_id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    username_initiator VARCHAR(256) NOT NULL,
    username_responder VARCHAR(256) NOT NULL,
    public_key_initiator VARCHAR(256) NOT NULL,
    public_key_responder VARCHAR(256) NULL,
    role_initiator VARCHAR(10) NOT NULL,
    address_initiator VARCHAR(12) NOT NULL,
    port_initiator SMALLINT NOT NULL,
    aes_key VARCHAR(256) NOT NULL,
    session_status VARCHAR(10) NOT NULL,
    created_on DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_on DATETIME NULL
) Engine=InnoDB;

SET time_zone = '-05:00';

-- Create stored procedures
delimiter //

create procedure get_user (
	in username varchar(256)
)
begin
	select username, password_hash from users where users.username = username;
end //

delimiter ;
