package main

import (
	"fmt"
	"log"
    "errors"
	"net/http"

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


func setCookieHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
    // Initialize a new cookie containing the string "Hello world!" and some
    // non-default attributes.
    cookie := http.Cookie{
        Name:     "exampleCookie",
        Value:    "Hola!",
        Path:     "/",
        MaxAge:   3600,
        HttpOnly: true,
        Secure:   true,
        SameSite: http.SameSiteLaxMode,
    }

    // Use the http.SetCookie() function to send the cookie to the client.
    // Behind the scenes this adds a `Set-Cookie` header to the response
    // containing the necessary cookie data.
    http.SetCookie(w, &cookie)

    // Write a HTTP response as normal.
    w.Write([]byte("cookie set!"))
}

func getCookieHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
    // Retrieve the cookie from the request using its name (which in our case is
    // "exampleCookie"). If no matching cookie is found, this will return a
    // http.ErrNoCookie error. We check for this, and return a 400 Bad Request
    // response to the client.
    cookie, err := r.Cookie("exampleCookie")
    if err != nil {
        switch {
        case errors.Is(err, http.ErrNoCookie):
            http.Error(w, "cookie not found", http.StatusBadRequest)
        default:
            log.Println(err)
            http.Error(w, "server error", http.StatusInternalServerError)
        }
        return
    }

    // Echo out the cookie value in the response body.
    w.Write([]byte(cookie.Value))
}

func main() {
	user := "gordon"
	pass := "secret!"

	router := httprouter.New()
	router.GET("/", Index)
	router.GET("/set", setCookieHandler)
	router.GET("/get", getCookieHandler)
	router.GET("/protected/", BasicAuth(Protected, user, pass))

	log.Fatal(http.ListenAndServe("localhost:4000", router))
}