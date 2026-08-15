package main

import (
	"fmt"
	"log"
	"net/http"
	"path/filepath"

	"github.com/ioflux-org/provisio/internal/config"
	"github.com/ioflux-org/provisio/internal/pki"
)

func placeholderHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "{\"message\": \"hello go!\"}")
}

const certDir = "certs"

func main() {
	cfg := config.Default()

	caCert, caKey, err := pki.EnsureCA(certDir)
	if err != nil {
		log.Fatal(err)
	}
	hosts := []string{cfg.ARMHost, cfg.LoginHost, "localhost", "127.0.0.1", "::1"}
	certFile, keyFile, err := pki.IssueLeaf(caCert, caKey, hosts, certDir)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", placeholderHandler)

	server := &http.Server{
		Addr:    cfg.ListenerAddr,
		Handler: mux,
	}

	log.Printf("Starting server on https://%s", cfg.ListenerAddr)
	log.Printf("Trust the CA: curl --cacert %s https://%s/", filepath.Join(certDir, pki.CACertFile), cfg.ListenerAddr)
	log.Fatal(server.ListenAndServeTLS(certFile, keyFile))
}
