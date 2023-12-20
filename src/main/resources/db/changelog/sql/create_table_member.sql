CREATE TABLE member
(
    id                SERIAL       NOT NULL PRIMARY KEY,
    name              VARCHAR(255) NOT NULL,
    email             VARCHAR(255) NOT NULL,
    password          VARCHAR(255) NOT NULL,
    phone             VARCHAR(255) NOT NULL,
    card_number       VARCHAR(512),
    card_cvv          VARCHAR(512),
    card_expired_date VARCHAR(512),
    card_owner        VARCHAR(512),
    is_validate       BOOLEAN DEFAULT false
);