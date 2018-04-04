package ca

import (
	"fmt"

	"github.com/cloudflare/cfssl/certdb"
	"github.com/ericyan/lorica/internal/certsql"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
)

var (
	// Adpated from https://github.com/cloudflare/cfssl/blob/master/certdb/sqlite/migrations/001_CreateCertificates.sql
	createSQL = `
CREATE TABLE IF NOT EXISTS metadata (
	key   blob NOT NULL,
	value blob NOT NULL,
	PRIMARY KEY(key)
);

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

	insertMetadataSQL = `INSERT INTO metadata (key, value) VALUES (?, ?);`

	selectMetadataSQL = `SELECT value FROM metadata WHERE key = ?;`
)

type database struct {
	*sqlx.DB
}

func openDB(dsn string) (*database, error) {
	db, err := sqlx.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}

	_, err = db.Exec(createSQL)
	if err != nil {
		return nil, err
	}

	return &database{db}, nil
}

func (db *database) Accessor() certdb.Accessor {
	return certsql.NewAccessor(db.DB)
}

func (db *database) GetMetadata(key []byte) ([]byte, error) {
	var values [][]byte
	err := db.DB.Select(&values, selectMetadataSQL, key)
	if err != nil {
		return nil, err
	}

	return values[0], nil
}

func (db *database) SetMetadata(key, value []byte) error {
	res, err := db.DB.Exec(insertMetadataSQL, key, value)
	if err != nil {
		return err
	}

	numRowsAffected, err := res.RowsAffected()

	if numRowsAffected == 0 {
		return fmt.Errorf("failed to insert the certificate record")
	}

	if numRowsAffected != 1 {
		return fmt.Errorf("%d rows are affected, should be 1 row", numRowsAffected)
	}

	return err
}
