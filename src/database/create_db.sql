CREATE DATABASE IF NOT EXISTS sftdb;
USE sftdb;

CREATE TABLE IF NOT EXISTS users (
	user_id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(256) NOT NULL,
    password_hash VARCHAR(256) NOT NULL
) Engine=InnoDB;

insert into users (username, password_hash) values
('usman', '$2b$12$RrxpbbRqsrxM2fMl8MqX7eBcK69WpcL5MPfISW04Edsk7By6lWcMm'),
('daniel', '$2b$12$Tmy8OolB.9TMNWOvFAnOoust/8NnoNHbg35GE04.QjCmUszVtKnxS'),
('angad', '$2b$12$Waw6.c5tja6Dk130PCkTRudGZN1lmF9SYlJb0Kk1lc7P1k0wzsKFe'),
('kinjal', '$2b$12$ynQFjXWRNcC8WypXAbNuI.sexZh1fK59vnLehBTdq3bXjG8wRrOge');

CREATE TABLE IF NOT EXISTS sessions (
	session_id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    username_initiator VARCHAR(256) NOT NULL,
    username_responder VARCHAR(256) NULL,
    role_initiator VARCHAR(10) NOT NULL,
    address_initiator VARCHAR(12) NOT NULL,
    port_initiator SMALLINT NOT NULL,
    aes_key VARBINARY(256) NOT NULL,
    created_on DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_on DATETIME NULL
) Engine=InnoDB;

SET GLOBAL time_zone = '-04:00';

-- Create stored procedures
delimiter //

create procedure get_user (
	in username varchar(256)
)
begin
	select * from users where users.username = username;
end //

create procedure get_outstanding_requests (
	in username varchar(256)
)
begin
	select count(*) from sessions 
    where sessions.username_responder = username
    and sessions.completed_on is null;
end //

create procedure create_session (
	in username_initiator VARCHAR(256),
    in username_responder VARCHAR(256),
    in role_initiator VARCHAR(10),
    in address_initiator VARCHAR(12),
    in port_initiator SMALLINT,
    in aes_key VARBINARY(256)
)
begin
	insert into sessions(username_initiator, username_responder, role_initiator, address_initiator, port_initiator, aes_key)
    values(username_initiator, username_responder, role_initiator, address_initiator, port_initiator, aes_key);
    
    select * from sessions where session_id = LAST_INSERT_ID();
end //

create procedure get_open_invite (
	in username VARCHAR(256)
)
begin
	select * from sessions 
    where username_responder = username and completed_on is null
    order by created_on;
end //

create procedure end_session (
	in session_id INT
)
begin
	update sessions
    set completed_on = NOW()
    where sessions.session_id = session_id;
    
    IF ROW_COUNT() > 0 THEN
        SELECT 'Success' AS Status;
    ELSE
        SELECT 'Failure' AS Status;
    END IF;
    
end //

delimiter ;

