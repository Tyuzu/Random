package main

import (
    "io" 
	"fmt"
	"log"
    "errors"
	"net/http"
    "crypto/aes"    
    "crypto/cipher" 
    "crypto/rand"
    "encoding/base64"
    "strings" 

	"github.com/julienschmidt/httprouter"
)


var (
    ErrValueTooLong = errors.New("cookie value too long")
    ErrInvalidValue = errors.New("invalid cookie value")
)

func Write(w http.ResponseWriter, cookie http.Cookie) error {
    // Encode the cookie value using base64.
    cookie.Value = base64.URLEncoding.EncodeToString([]byte(cookie.Value))

    // Check the total length of the cookie contents. Return the ErrValueTooLong
    // error if it's more than 4096 bytes.
    if len(cookie.String()) > 4096 {
        return ErrValueTooLong
    }

    // Write the cookie as normal.
    http.SetCookie(w, &cookie)

    return nil
}

func Read(r *http.Request, name string) (string, error) {
    // Read the cookie as normal.
    cookie, err := r.Cookie(name)
    if err != nil {
        return "", err
    }

    // Decode the base64-encoded cookie value. If the cookie didn't contain a
    // valid base64-encoded value, this operation will fail and we return an
    // ErrInvalidValue error.
    value, err := base64.URLEncoding.DecodeString(cookie.Value)
    if err != nil {
        return "", ErrInvalidValue
    }

    // Return the decoded cookie value.
    return string(value), nil
}

func WriteEncrypted(w http.ResponseWriter, cookie http.Cookie, secretKey []byte) error {

    block, err := aes.NewCipher(secretKey)
    if err != nil {
        return err
    }

    aesGCM, err := cipher.NewGCM(block)
    if err != nil {
        return err
    }

    nonce := make([]byte, aesGCM.NonceSize())
    _, err = io.ReadFull(rand.Reader, nonce)
    if err != nil {
        return err
    }

    plaintext := fmt.Sprintf("%s:%s", cookie.Name, cookie.Value)
    encryptedValue := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
    cookie.Value = string(encryptedValue)
    return Write(w, cookie)
}

func ReadEncrypted(r *http.Request, name string, secretKey []byte) (string, error) {
    // Read the encrypted value from the cookie as normal.
    encryptedValue, err := Read(r, name)
    if err != nil {
        return "", err
    }

    block, err := aes.NewCipher(secretKey)
    if err != nil {
        return "", err
    }

    aesGCM, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }

    // Get the nonce size.
    nonceSize := aesGCM.NonceSize()

    // To avoid a potential 'index out of range' panic in the next step, we
    // check that the length of the encrypted value is at least the nonce
    // size.
    if len(encryptedValue) < nonceSize {
        return "", ErrInvalidValue
    }

    // Split apart the nonce from the actual encrypted data.
    nonce := encryptedValue[:nonceSize]
    ciphertext := encryptedValue[nonceSize:]

    // Use aesGCM.Open() to decrypt and authenticate the data. If this fails,
    // return a ErrInvalidValue error.
    plaintext, err := aesGCM.Open(nil, []byte(nonce), []byte(ciphertext), nil)
    if err != nil {
        return "", ErrInvalidValue
    }

    // The plaintext value is in the format "{cookie name}:{cookie value}". We
    // use strings.Cut() to split it on the first ":" character.
    expectedName, value, ok := strings.Cut(string(plaintext), ":")
    if !ok {
        return "", ErrInvalidValue
    }

    // Check that the cookie name is the expected one and hasn't been changed.
    if expectedName != name {
        return "", ErrInvalidValue
    }

    // Return the plaintext cookie value.
    return value, nil
}
func setCookieHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
    cookie := http.Cookie{
        Name:     "exampleCookie",
        Value:    "Hello Zoe!",
        Path:     "/",
        MaxAge:   3600,
        HttpOnly: true,
        Secure:   true,
        SameSite: http.SameSiteLaxMode,
    }

    err := WriteEncrypted(w, cookie, secretKey)
    if err != nil {
        log.Println(err)
        http.Error(w, "server error", http.StatusInternalServerError)
        return
    }

    w.Write([]byte("cookie set!"))
}

func getCookieHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
    value, err := ReadEncrypted(r, "exampleCookie", secretKey)
    if err != nil {
        switch {
        case errors.Is(err, http.ErrNoCookie):
            http.Error(w, "cookie not found", http.StatusBadRequest)
        case errors.Is(err, ErrInvalidValue):
            http.Error(w, "invalid cookie", http.StatusBadRequest)
        default:
            log.Println(err)
            http.Error(w, "server error", http.StatusInternalServerError)
        }
        return
    }

    w.Write([]byte(value))
}