/*
Michael Hernandez
IS211
CERN Lookup inventory DB
*/

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

create table if not exists vendor
(
    vendor_id int PRIMARY KEY,
    vendor_name text not null
);

create table if not EXISTS device
(
    deviceid int PRIMARY KEY,
    devicename text UNIQUE not null,
    vendorid int not null,
    FOREIGN KEY (vendor_id) REFERENCES vendor(vendor_id)
)

create table if not exists ref_url
(
    ref_id int primary key,
    ref_url text,
    cve_id text not null,
    FOREIGN key cve_id references vuln (cve_id)
)

create table if not exists vulnerabilities
(
    cve_id text PRIMARY key,
    vendor_id text not null,
    device_id text not null,
    ref_id int,
    cvss numeric,
    FOREIGN key (vendor_id) REFERENCES vendor(vendor_id),
    FOREIGN key (device_id) REFERENCES device(device_id)
)