package ca

import (
	"errors"

	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/certdb/dbconf"
	"github.com/ericyan/lorica/internal/certsql"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
)

// Adpated from https://github.com/cloudflare/cfssl/blob/master/certdb/sqlite/migrations/001_CreateCertificates.sql
var createSQL = `
CREATE TABLE IF NOT EXISTS certificates (
	serial_number            blob NOT NULL,
	authority_key_identifier blob NOT NULL,
	ca_label                 blob,
	status                   blob NOT NULL,
	reason                   int,
	expiry                   timestamp,
	revoked_at               timestamp,
	pem                      blob NOT NULL,
	PRIMARY KEY(serial_number, authority_key_identifier)
);

CREATE TABLE IF NOT EXISTS ocsp_responses (
	serial_number            blob NOT NULL,
	authority_key_identifier blob NOT NULL,
	body                     blob NOT NULL,
	expiry                   timestamp,
	PRIMARY KEY(serial_number, authority_key_identifier),
	FOREIGN KEY(serial_number, authority_key_identifier) REFERENCES certificates(serial_number, authority_key_identifier)
);
`

func openDB(dbCfg *dbconf.DBConfig) (certdb.Accessor, error) {
	if dbCfg == nil {
		return nil, errors.New("nil db config")
	}

	db, err := sqlx.Open(dbCfg.DriverName, dbCfg.DataSourceName)
	if err != nil {
		return nil, err
	}

	_, err = db.Exec(createSQL)
	if err != nil {
		return nil, err
	}

	return certsql.NewAccessor(db), nil
}
