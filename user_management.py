

create table if not exists user
(
    userid int PRIMARY KEY,
    username text NOT NULL,
    user_email text not null,
    password text not null
);

create table if not exists inventory
(
    userid,
    deviceid
)
