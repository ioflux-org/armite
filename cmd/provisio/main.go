package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/ioflux-org/provisio/internal/config"
)

func placeholderHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "{\"message\": \"hello go!\"}")
}

func main() {
	cfg := config.Default()

	mux := http.NewServeMux()
	mux.HandleFunc("/", placeholderHandler)

	server := &http.Server{
		Addr:    cfg.ListenerAddr,
		Handler: mux,
	}

	log.Printf("Starting server on %s", cfg.ListenerAddr)
	log.Fatal(server.ListenAndServe())
}
