package main

import (
	"fmt"
	"log"
	"net/http"
    "encoding/hex"

	"github.com/julienschmidt/httprouter"
)

func BasicAuth(h httprouter.Handle, requiredUser, requiredPassword string) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		// Get the Basic Authentication credentials
		user, password, hasAuth := r.BasicAuth()

		if hasAuth && user == requiredUser && password == requiredPassword {
			// Delegate request to the given handle
			h(w, r, ps)
		} else {
			// Request Basic Authentication otherwise
			w.Header().Set("WWW-Authenticate", "Basic realm=Restricted")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		}
	}
}

func Index(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	fmt.Fprint(w, "Not protected!\n")
}

func Protected(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	fmt.Fprint(w, "Protected!\n")
}

var secretKey []byte

func main() {
	user := "gordon"
	pass := "secret!"
	var err error
	secretKey, err = hex.DecodeString("13d6b4dff8f84a10851021ec8608f814570d562c92fe6b5ec4c9f595bcb3234b")
    if err != nil {
        log.Fatal(err)
    }

	router := httprouter.New()
	router.GET("/", Index)
	router.GET("/set", setCookieHandler)
	router.GET("/get", getCookieHandler)
	router.GET("/protected/", BasicAuth(Protected, user, pass))

	log.Fatal(http.ListenAndServe("localhost:4000", router))
}