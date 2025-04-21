-- Table: auth
CREATE TABLE IF NOT EXISTS auth
(
    id        SERIAL PRIMARY KEY,
    session   CHAR(32)     NOT NULL,
    success   BOOLEAN      NOT NULL,
    username  VARCHAR(100) NOT NULL,
    password  VARCHAR(100) NOT NULL,
    timestamp TIMESTAMP    NOT NULL
);

-- Table: clients
CREATE TABLE IF NOT EXISTS clients
(
    id      SERIAL PRIMARY KEY,
    version VARCHAR(50) NOT NULL
);

-- Table: downloads
CREATE TABLE IF NOT EXISTS downloads
(
    id        SERIAL PRIMARY KEY,
    session   CHAR(32)  NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    url       TEXT      NOT NULL,
    outfile   TEXT,
    shasum    VARCHAR(64)
);
CREATE INDEX downloads_session_timestamp_idx ON downloads (session, timestamp);

-- Table: input
CREATE TABLE IF NOT EXISTS input
(
    id        SERIAL PRIMARY KEY,
    session   CHAR(32)  NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    realm     VARCHAR(50),
    success   BOOLEAN,
    input     TEXT      NOT NULL
);
CREATE INDEX input_session_timestamp_realm_idx ON input (session, timestamp, realm);

-- Table: keyfingerprints
CREATE TABLE IF NOT EXISTS keyfingerprints
(
    id          SERIAL PRIMARY KEY,
    session     CHAR(32)     NOT NULL,
    username    VARCHAR(100) NOT NULL,
    fingerprint VARCHAR(100) NOT NULL
);

-- Table: params
CREATE TABLE IF NOT EXISTS params
(
    id      SERIAL PRIMARY KEY,
    session CHAR(32)    NOT NULL,
    arch    VARCHAR(32) NOT NULL
);
CREATE INDEX params_arch_index ON params (arch);

-- Table: sensors
CREATE TABLE IF NOT EXISTS sensors
(
    id SERIAL PRIMARY KEY,
    ip VARCHAR(255) NOT NULL
);

-- Table: sessions
CREATE TABLE IF NOT EXISTS sessions
(
    id        CHAR(32) PRIMARY KEY,
    starttime TIMESTAMP   NOT NULL,
    endtime   TIMESTAMP,
    sensor    INTEGER     NOT NULL,
    ip        VARCHAR(61) NOT NULL DEFAULT '',
    termsize  VARCHAR(7),
    client    INTEGER
);
CREATE INDEX sessions_starttime_sensor_idx ON sessions (starttime, sensor);

-- Table: ipforwards
CREATE TABLE IF NOT EXISTS ipforwards
(
    id        SERIAL PRIMARY KEY,
    session   CHAR(32)     NOT NULL,
    timestamp TIMESTAMP    NOT NULL,
    dst_ip    VARCHAR(255) NOT NULL DEFAULT '',
    dst_port  INTEGER      NOT NULL,
    CONSTRAINT ipforwards_ibfk_1 FOREIGN KEY (session) REFERENCES sessions (id)
);
CREATE INDEX ipforwards_session_idx ON ipforwards (session);

-- Table: ipforwardsdata
CREATE TABLE IF NOT EXISTS ipforwardsdata
(
    id        SERIAL PRIMARY KEY,
    session   CHAR(32)     NOT NULL,
    timestamp TIMESTAMP    NOT NULL,
    dst_ip    VARCHAR(255) NOT NULL DEFAULT '',
    dst_port  INTEGER      NOT NULL,
    data      TEXT         NOT NULL,
    CONSTRAINT ipforwardsdata_ibfk_1 FOREIGN KEY (session) REFERENCES sessions (id)
);
CREATE INDEX ipforwardsdata_session_timestamp_idx ON ipforwardsdata (session, timestamp);

-- Table: ttylog
CREATE TABLE IF NOT EXISTS ttylog
(
    id      SERIAL PRIMARY KEY,
    session CHAR(32)     NOT NULL,
    ttylog  VARCHAR(100) NOT NULL,
    size    INTEGER      NOT NULL
);
