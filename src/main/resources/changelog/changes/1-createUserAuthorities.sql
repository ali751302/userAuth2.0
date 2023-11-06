-- liquibase formatted sql
-- changeset Ali:createUserAuthorities runOnChange:true

create table IF Not EXISTS users
(
    id    bigint auto_increment,
    username  varchar(255) not null,
    password  varchar(255) not null,
    email     varchar(255) not null,
    firstname varchar(255) not null,
    lastname  varchar(255) not null,
    activated bit not null,
    CONSTRAINT PK_users primary key (id)
);


create table IF Not EXISTS authorities(
                                         id bigint auto_increment not null,
                                         name varchar(50),
                                         CONSTRAINT PK_authorities primary key (id)
);

create table IF Not EXISTS user_authority
(
    user_id bigint not null,
    authority_id bigint not null
);

ALTER table user_authority add CONSTRAINT FK_user_id foreign key(user_id) references users(id);
ALTER table user_authority add CONSTRAINT FK_authority_id foreign key(authority_id) references authorities(id);

insert into users(username,password,email,firstname,lastname,activated) value('admin','$2a$10$MbHbdWgUDeJb2I5xEK0iuOqstEKNof8IkLiyGKffRW14dWS8Sp.wi','admin@admin.com','Ali','Bhai',true);

insert into authorities(name) values ('ADMIN'),('MANAGER'),('USER');

insert into user_authority value(1,1);
insert into user_authority value(1,3);

