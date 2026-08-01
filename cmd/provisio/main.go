package main

import (
	"fmt"
	"log"
	"net/http"

	config "github.com/ioflux-org/provisio/internal/config"
)

func placeholderHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "{\"message\": \"hello go!\"}")
}

func main() {
	http.HandleFunc("/", placeholderHandler)

	config := config.Default()
	log.Fatal(http.ListenAndServe(config.ListenerAddr, nil))
}
