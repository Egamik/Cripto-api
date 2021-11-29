package main

import (
	dbConfig "cripto-api/postdbconfig"
	"cripto-api/utils"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/jinzhu/gorm"

	"github.com/rs/cors"

	_ "github.com/jinzhu/gorm/dialects/postgres"
)

var db *gorm.DB
var ca utils.CA

type Cert struct {
	SerialNumber int64 `gorm:"primary_key"`
	Name         string
	NotBefore    time.Time
	NotAfter     time.Time
	RawIssuer    []byte
	IsCA         bool
}

// Router Functions
func Hash(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	input := vars["word"]
	fmt.Println(input)
	hash256 := utils.HashString(input)
	json.NewEncoder(w).Encode(hash256)
}

func RsaGen(w http.ResponseWriter, r *http.Request) {
	pub, pvt := utils.GenKeyPair()
	output := [2]string{pub, pvt}
	json.NewEncoder(w).Encode(output)
}

func CertGen(w http.ResponseWriter, r *http.Request) {
	// Gets name from request
	vars := mux.Vars(r)
	input := vars["name"]

	// Creates new certificate
	cert, certPEM := ca.CreateNewCert(input)
	if cert == nil || certPEM == nil {
		http.Error(w, "Failed to generate certificate", 400)
	}

	// Database SQL query
	fmt.Printf("Accessing %s ... ", dbConfig.DbName)
	db, err := gorm.Open(dbConfig.PostgresDriver, dbConfig.DataSourceName)
	if err != nil {
		panic("Failed to connect to database")
	} else {
		fmt.Println("Connected!")
	}

	defer db.Close()

	db.AutoMigrate(&Cert{})
	toDB := Cert{
		SerialNumber: cert.SerialNumber.Int64(),
		Name:         cert.Issuer.CommonName,
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		RawIssuer:    cert.RawIssuer,
		IsCA:         false,
	}
	db.Create(&toDB)

	json.NewEncoder(w).Encode(toDB)
}

func CertGet(w http.ResponseWriter, r *http.Request) {
	// SQL query
	input := mux.Vars(r)
	var cert Cert

	fmt.Printf("Accessing %s ... ", dbConfig.DbName)
	db, err := gorm.Open(dbConfig.PostgresDriver, dbConfig.DataSourceName)
	if err != nil {
		panic("Failed to connect to database")
	} else {
		fmt.Println("Connected!")
	}

	defer db.Close()
	db.AutoMigrate(&Cert{})

	db.First(&cert, input["id"])
	json.NewEncoder(w).Encode(&cert)
}

func CertGetAll(w http.ResponseWriter, r *http.Request) {
	// SQL query
	var certs []Cert
	fmt.Printf("Accessing %s ... ", dbConfig.DbName)

	db, err := gorm.Open(dbConfig.PostgresDriver, dbConfig.DataSourceName)
	if err != nil {
		panic("Failed to connect to database")
	} else {
		fmt.Println("Connected!")
	}

	defer db.Close()
	db.AutoMigrate(&Cert{})
	db.Find(&certs)

	json.NewEncoder(w).Encode(&certs)
}

func setup() {
	fmt.Printf("Accessing %s ... ", dbConfig.DbName)

	db, err := gorm.Open(dbConfig.PostgresDriver, dbConfig.DataSourceName)
	if err != nil {
		panic("Failed to connect to database")
	} else {
		fmt.Println("Connected!")
	}

	defer db.Close()
	db.AutoMigrate(&Cert{})

	cert := ca.CaSetup()
	toDB := Cert{
		SerialNumber: cert.SerialNumber.Int64(),
		Name:         cert.Issuer.CommonName,
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		RawIssuer:    cert.RawIssuer,
		IsCA:         true,
	}
	db.Create(&toDB)
}

func main() {
	// Set up CA certificate
	setup()

	// Routers
	router := mux.NewRouter()

	router.HandleFunc("/hash/{word}", Hash).Methods("GET")
	router.HandleFunc("/rsa", RsaGen).Methods("GET")
	router.HandleFunc("/newcert/{name}", CertGen).Methods("POST")
	router.HandleFunc("/cert/{id}", CertGet).Methods("GET")
	router.HandleFunc("/cert", CertGetAll).Methods("GET")

	handler := cors.Default().Handler(router)

	// Start server
	fmt.Println("Server running on port 8080")
	log.Fatal(http.ListenAndServe(":8080", handler))
}
