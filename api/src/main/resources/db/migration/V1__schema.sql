-- SecureDesk schema, version 1.
--
-- Runs as the migrator account (the `migrate` service), never as the application account: the
-- API itself holds no DDL rights. Portable between MySQL 8.4 and H2 in MySQL mode, which the
-- tests use, so the same file is exercised by every `mvn test`.
--
-- Free text is VARCHAR with a hard limit rather than TEXT: the limits are the same ones the
-- request DTOs enforce, so an oversized value is refused at the API and cannot be stored.

CREATE TABLE app_user (
    id                       CHAR(36)     NOT NULL,
    username                 VARCHAR(64)  NOT NULL,
    display_name             VARCHAR(100) NOT NULL,
    email                    VARCHAR(254),
    role                     VARCHAR(16)  NOT NULL,
    enabled                  BOOLEAN      NOT NULL,
    -- AES-256-GCM sealed Argon2id record (pepper); NULL once the account is erased
    password_record          VARCHAR(512),
    password_change_required BOOLEAN      NOT NULL,
    -- for requesters only: agents and administrators always need a second factor (SR-01)
    mfa_required             BOOLEAN      NOT NULL,
    mfa_enabled              BOOLEAN      NOT NULL,
    -- AES-256-GCM sealed Base32 TOTP secret (column encryption, SR-05)
    totp_secret              VARCHAR(255),
    -- highest accepted TOTP time step: a code is accepted once
    last_accepted_step       BIGINT       NOT NULL,
    -- changes on every security-relevant change; sessions carrying an old stamp are ended
    security_stamp           CHAR(32)     NOT NULL,
    created_at               DATETIME(6)  NOT NULL,
    updated_at               DATETIME(6)  NOT NULL,
    erased_at                DATETIME(6),
    version                  BIGINT       NOT NULL,
    CONSTRAINT pk_app_user PRIMARY KEY (id),
    CONSTRAINT uq_app_user_username UNIQUE (username)
);

CREATE TABLE recovery_code (
    id          CHAR(36)     NOT NULL,
    user_id     CHAR(36)     NOT NULL,
    -- sealed Argon2id record of the code; the code itself is shown once and never stored
    code_record VARCHAR(512) NOT NULL,
    created_at  DATETIME(6)  NOT NULL,
    used_at     DATETIME(6),
    CONSTRAINT pk_recovery_code PRIMARY KEY (id),
    CONSTRAINT fk_recovery_code_user FOREIGN KEY (user_id) REFERENCES app_user (id)
);
CREATE INDEX ix_recovery_code_user ON recovery_code (user_id);

-- Failed attempts per submitted username, whether or not the account exists, so that the delay
-- and the lock behave the same for both and reveal nothing.
CREATE TABLE login_throttle (
    username_key    VARCHAR(64) NOT NULL,
    failure_count   INT         NOT NULL,
    window_start    DATETIME(6) NOT NULL,
    last_failure_at DATETIME(6) NOT NULL,
    locked_until    DATETIME(6),
    CONSTRAINT pk_login_throttle PRIMARY KEY (username_key)
);

CREATE TABLE category (
    id     BIGINT      NOT NULL AUTO_INCREMENT,
    name   VARCHAR(60) NOT NULL,
    active BOOLEAN     NOT NULL,
    CONSTRAINT pk_category PRIMARY KEY (id),
    CONSTRAINT uq_category_name UNIQUE (name)
);

INSERT INTO category (name, active) VALUES
    ('Hardware', TRUE),
    ('Software', TRUE),
    ('Access request', TRUE),
    ('Network', TRUE),
    ('Other', TRUE);

CREATE TABLE ticket (
    id           CHAR(36)       NOT NULL,
    requester_id CHAR(36)       NOT NULL,
    category_id  BIGINT         NOT NULL,
    title        VARCHAR(200)   NOT NULL,
    description  VARCHAR(10000) NOT NULL,
    status       VARCHAR(24)    NOT NULL,
    priority     VARCHAR(16)    NOT NULL,
    assignee_id  CHAR(36),
    resolution   VARCHAR(2000),
    created_at   DATETIME(6)    NOT NULL,
    updated_at   DATETIME(6)    NOT NULL,
    closed_at    DATETIME(6),
    version      BIGINT         NOT NULL,
    CONSTRAINT pk_ticket PRIMARY KEY (id),
    CONSTRAINT fk_ticket_requester FOREIGN KEY (requester_id) REFERENCES app_user (id),
    CONSTRAINT fk_ticket_assignee FOREIGN KEY (assignee_id) REFERENCES app_user (id),
    CONSTRAINT fk_ticket_category FOREIGN KEY (category_id) REFERENCES category (id)
);
CREATE INDEX ix_ticket_requester ON ticket (requester_id, updated_at);
CREATE INDEX ix_ticket_status ON ticket (status, updated_at);
CREATE INDEX ix_ticket_closed ON ticket (status, closed_at);

CREATE TABLE ticket_comment (
    id         CHAR(36)      NOT NULL,
    ticket_id  CHAR(36)      NOT NULL,
    author_id  CHAR(36)      NOT NULL,
    body       VARCHAR(5000) NOT NULL,
    -- internal notes are filtered out server-side for requesters, never in the front end
    internal   BOOLEAN       NOT NULL,
    created_at DATETIME(6)   NOT NULL,
    CONSTRAINT pk_ticket_comment PRIMARY KEY (id),
    CONSTRAINT fk_ticket_comment_ticket FOREIGN KEY (ticket_id) REFERENCES ticket (id),
    CONSTRAINT fk_ticket_comment_author FOREIGN KEY (author_id) REFERENCES app_user (id)
);
CREATE INDEX ix_ticket_comment_ticket ON ticket_comment (ticket_id, created_at);

CREATE TABLE attachment (
    id           CHAR(36)     NOT NULL,
    ticket_id    CHAR(36)     NOT NULL,
    uploader_id  CHAR(36)     NOT NULL,
    -- the uploaded name, sanitised, for display only; the content is keyed by id
    display_name VARCHAR(120) NOT NULL,
    -- the type established by content inspection, not the one the client claimed
    media_type   VARCHAR(64)  NOT NULL,
    size_bytes   BIGINT       NOT NULL,
    sha256       CHAR(64)     NOT NULL,
    created_at   DATETIME(6)  NOT NULL,
    CONSTRAINT pk_attachment PRIMARY KEY (id),
    CONSTRAINT fk_attachment_ticket FOREIGN KEY (ticket_id) REFERENCES ticket (id),
    CONSTRAINT fk_attachment_uploader FOREIGN KEY (uploader_id) REFERENCES app_user (id)
);
CREATE INDEX ix_attachment_ticket ON attachment (ticket_id);

-- The file content, in its own table so that listing attachments never loads it.
CREATE TABLE attachment_content (
    attachment_id CHAR(36) NOT NULL,
    content       LONGBLOB NOT NULL,
    CONSTRAINT pk_attachment_content PRIMARY KEY (attachment_id),
    CONSTRAINT fk_attachment_content FOREIGN KEY (attachment_id) REFERENCES attachment (id)
);

CREATE TABLE app_setting (
    setting_key   VARCHAR(64)  NOT NULL,
    setting_value VARCHAR(255) NOT NULL,
    updated_at    DATETIME(6)  NOT NULL,
    CONSTRAINT pk_app_setting PRIMARY KEY (setting_key)
);

-- The audit trail (SC-09). The application account may INSERT and SELECT here, nothing else
-- (see db/mysql/R__grants.sql). Every row carries the SHA-256 of its own canonical form chained
-- to the previous row, so a removed or altered row breaks the chain. Absent values are '-'
-- rather than NULL, which keeps the canonical form unambiguous.
CREATE TABLE audit_event (
    seq            BIGINT        NOT NULL,
    event_id       CHAR(36)      NOT NULL,
    ts             DATETIME(6)   NOT NULL,
    event_type     VARCHAR(40)   NOT NULL,
    category       VARCHAR(16)   NOT NULL,
    outcome        VARCHAR(16)   NOT NULL,
    alert          BOOLEAN       NOT NULL,
    actor_id       VARCHAR(36)   NOT NULL,
    actor          VARCHAR(64)   NOT NULL,
    actor_role     VARCHAR(16)   NOT NULL,
    src_ip         VARCHAR(45)   NOT NULL,
    session_hash   VARCHAR(16)   NOT NULL,
    target_type    VARCHAR(24)   NOT NULL,
    target_id      VARCHAR(64)   NOT NULL,
    correlation_id VARCHAR(64)   NOT NULL,
    details        VARCHAR(2000) NOT NULL,
    prev_hash      CHAR(64)      NOT NULL,
    entry_hash     CHAR(64)      NOT NULL,
    CONSTRAINT pk_audit_event PRIMARY KEY (seq),
    CONSTRAINT uq_audit_event_id UNIQUE (event_id)
);
CREATE INDEX ix_audit_event_ts ON audit_event (ts);
CREATE INDEX ix_audit_event_type ON audit_event (event_type, ts);
CREATE INDEX ix_audit_event_actor ON audit_event (actor, ts);
