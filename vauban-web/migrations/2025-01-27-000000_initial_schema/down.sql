-- Rollback initial schema

DROP TABLE IF EXISTS proxy_sessions;
DROP TABLE IF EXISTS assets;
DROP TABLE IF EXISTS asset_groups;
DROP TABLE IF EXISTS user_groups;
DROP TABLE IF EXISTS vauban_groups;
DROP TABLE IF EXISTS users;

DROP EXTENSION IF EXISTS "pgcrypto";
DROP EXTENSION IF EXISTS "uuid-ossp";

