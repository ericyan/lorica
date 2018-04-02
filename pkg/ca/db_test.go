package ca

import (
	"bytes"
	"testing"

	"github.com/cloudflare/cfssl/certdb/dbconf"
)

func openTestingDB() (*database, error) {
	dbCfg := &dbconf.DBConfig{
		DriverName:     "sqlite3",
		DataSourceName: ":memory:",
	}

	return openDB(dbCfg)
}

func TestMetadata(t *testing.T) {
	var (
		key   = []byte{42}
		value = []byte("hello, world")
	)

	db, err := openTestingDB()
	if err != nil {
		t.Fatal(err)
	}

	err = db.SetMetadata(key, value)
	if err != nil {
		t.Errorf("unexpected error: %s\n", err)
	}
	result, err := db.GetMetadata(key)
	if err != nil {
		t.Errorf("unexpected error: %s\n", err)
	}
	if !bytes.Equal(result, value) {
		t.Fatalf("unexpected value: got %v, want %s\n", result, value)
	}
}
