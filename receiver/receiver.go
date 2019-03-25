package main

import (
	"log"
	"net/http"
)

type response struct {
	Ready bool `json:"ready"`
}

func main() {
	http.HandleFunc("/requestComms", commsRequestHandler)
	http.HandleFunc("/message", commsRequestHandler)
	log.Fatal(http.ListenAndServe(":3000", nil))
}

func commsRequestHandler(w http.ResponseWriter, r *http.Request) {

}

func messageHandler(w http.ResponseWriter, r *http.Request) {

}
