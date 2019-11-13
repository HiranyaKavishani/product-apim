CREATE TABLE AM_SYSTEM_APPS (
            ID INTEGER IDENTITY,
            NAME VARCHAR(50) NOT NULL,
            CONSUMER_KEY VARCHAR(512) NOT NULL,
            CONSUMER_SECRET VARCHAR(512) NOT NULL,
            CREATED_TIME DATETIME2(6) DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (ID)
);

IF NOT  EXISTS (SELECT * FROM SYS.OBJECTS WHERE OBJECT_ID = OBJECT_ID(N'[DBO].[AM_API_CLIENT_CERTIFICATE]') AND TYPE IN (N'U'))
CREATE TABLE AM_API_CLIENT_CERTIFICATE (
    TENANT_ID INTEGER NOT NULL,
    ALIAS VARCHAR(45) NOT NULL,
    API_ID INTEGER NOT NULL,
    CERTIFICATE VARBINARY(MAX) NOT NULL,
    REMOVED BIT NOT NULL DEFAULT 0,
    TIER_NAME VARCHAR(512),
    PRIMARY KEY (ALIAS, TENANT_ID, REMOVED),
    FOREIGN KEY (API_ID) REFERENCES AM_API(API_ID) ON DELETE CASCADE
);

ALTER TABLE AM_POLICY_SUBSCRIPTION ADD
 MONETIZATION_PLAN VARCHAR(25) NULL DEFAULT NULL,
 FIXED_RATE VARCHAR(15) NULL DEFAULT NULL, 
 BILLING_CYCLE VARCHAR(15) NULL DEFAULT NULL, 
 PRICE_PER_REQUEST VARCHAR(15) NULL DEFAULT NULL, 
 CURRENCY VARCHAR(15) NULL DEFAULT NULL
;

IF NOT  EXISTS (SELECT * FROM SYS.OBJECTS WHERE OBJECT_ID = OBJECT_ID(N'[DBO].[AM_MONETIZATION_USAGE_PUBLISHER]') AND TYPE IN (N'U'))

CREATE TABLE AM_MONETIZATION_USAGE_PUBLISHER (
	ID VARCHAR(100) NOT NULL,
	STATE VARCHAR(50) NOT NULL,
	STATUS VARCHAR(50) NOT NULL,
	STARTED_TIME VARCHAR(50) NOT NULL,
	PUBLISHED_TIME VARCHAR(50) NOT NULL,
	PRIMARY KEY(ID)
);

ALTER TABLE AM_API_COMMENTS
ALTER COLUMN COMMENT_ID VARCHAR(255) NOT NULL;

ALTER TABLE AM_API_RATINGS
ALTER COLUMN RATING_ID VARCHAR(255) NOT NULL;

IF NOT  EXISTS (SELECT * FROM SYS.OBJECTS WHERE OBJECT_ID = OBJECT_ID(N'[DBO].[AM_NOTIFICATION_SUBSCRIBER]') AND TYPE IN (N'U'))
CREATE TABLE AM_NOTIFICATION_SUBSCRIBER (
    UUID VARCHAR(255),
    CATEGORY VARCHAR(255),
    NOTIFICATION_METHOD VARCHAR(255),
    SUBSCRIBER_ADDRESS VARCHAR(255) NOT NULL,
    PRIMARY KEY(UUID, SUBSCRIBER_ADDRESS)
);

ALTER TABLE AM_EXTERNAL_STORES
ADD LAST_UPDATED_TIME DATETIME DEFAULT GETDATE();

ALTER TABLE AM_API
    ADD API_TYPE VARCHAR(10) NULL DEFAULT NULL;

IF NOT  EXISTS (SELECT * FROM SYS.OBJECTS WHERE OBJECT_ID = OBJECT_ID(N'[DBO].[AM_API_PRODUCT_MAPPING]') AND TYPE IN (N'U'))

CREATE TABLE AM_API_PRODUCT_MAPPING (
  API_PRODUCT_MAPPING_ID INTEGER IDENTITY(1,1),
  API_ID INTEGER,
  URL_MAPPING_ID INTEGER,
  FOREIGN KEY (API_ID) REFERENCES AM_API(API_ID) ON DELETE CASCADE,
  FOREIGN KEY (URL_MAPPING_ID) REFERENCES AM_API_URL_MAPPING(URL_MAPPING_ID) ON DELETE CASCADE,
  PRIMARY KEY(API_PRODUCT_MAPPING_ID)
);