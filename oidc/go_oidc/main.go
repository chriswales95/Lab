package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Error        string `json:"error"`
	ErrorDesc    string `json:"error_description"`
}

type JWK struct {
	KeyID  string   `json:"kid"`
	Alg    string   `json:"alg"`
	Kty    string   `json:"kty"`
	Use    string   `json:"use"`
	X5c    []string `json:"x5c"`
	X5t    string   `json:"x5t"`
	X5t256 string   `json:"x5t#S256"`
	N      string   `json:"n"`
	E      string   `json:"e"`
}

type Session struct {
	user     string
	verifier string
	state    string
}

type OIDCConfig struct {
	TokenEndpoint         string `json:"token_endpoint"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	JwksURI               string `json:"jwks_uri"`
}

//go:embed templates/*.html
var templateFS embed.FS

var funcs = template.FuncMap{
	"now": func() time.Time {
		return time.Now()
	},
	"formatDate": func(t time.Time) string {
		return t.Format("2 January 06")
	},
}

var templates = template.Must(
	template.New("").Funcs(funcs).ParseFS(templateFS, "templates/*.html"),
)

var (
	jwkCache       *JwkSet
	jwkOnce        sync.Once
	oidcConfig     *OIDCConfig
	oidcConfigOnce sync.Once
)

var sessions sync.Map

func randomString() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func deriveChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	var buf bytes.Buffer
	var data = map[string]string{}
	sessionId, err := r.Cookie("session")

	if sessionId != nil && err == nil {
		session, ok := sessions.Load(sessionId.Value)
		if ok {
			data = map[string]string{"user": session.(*Session).user}

			if err := templates.ExecuteTemplate(&buf, "layout.html", data); err != nil {
				http.Error(w, "template error", http.StatusInternalServerError)
				log.Printf("execute error: %v", err)
				return
			}

			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			buf.WriteTo(w)
			return
		}
		log.Println("Deleting invalid session: " + sessionId.Value)
		w.Header().Set("Set-Cookie", "session=; HttpOnly; SameSite=Lax; Max-Age=0")
		sessions.Delete(sessionId.Value)
	}

	data = map[string]string{"authUrl": "/login"}

	if err := templates.ExecuteTemplate(&buf, "layout.html", data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		log.Printf("execute error: %v", err)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	buf.WriteTo(w)
}

func genAuthoriseUrl(state, challenge string) (string, error) {
	params := url.Values{}
	params.Set("redirect_uri", "http://localhost:8080/callback")
	params.Set("scope", "openid")
	params.Set("state", state)
	params.Set("code_challenge", challenge)
	params.Set("code_challenge_method", "S256")
	params.Set("client_id", "go_test")
	params.Set("response_type", "code")
	config, err := getOIDCConfig()
	if err != nil {
		return "", err
	}
	return config.AuthorizationEndpoint + "?" + params.Encode(), nil
}

type JwkSet struct {
	Keys []JWK `json:"keys"`
}

type idTokenClaims struct {
	GivenName string `json:"given_name"`
	jwt.RegisteredClaims
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	verifier, err := randomString()
	if err != nil {
		http.Error(w, "failed to generate verifier", http.StatusInternalServerError)
		return
	}

	state, err := randomString() // reuse same random generator for state
	if err != nil {
		http.Error(w, "failed to generate state", http.StatusInternalServerError)
		return
	}

	sid, err := randomString() // reuse same random generator for state
	if err != nil {
		http.Error(w, "failed to generate session id", http.StatusInternalServerError)
		return
	}

	session := &Session{verifier: verifier, state: state}

	sessions.Store(sid, session)
	log.Println("New session: " + sid)
	w.Header().Set("Set-Cookie", "session="+sid+"; HttpOnly; SameSite=Lax")
	authUrl, err := genAuthoriseUrl(state, deriveChallenge(verifier))
	if err != nil {
		http.Error(w, "failed to login", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r,
		authUrl,
		http.StatusFound)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	errParam := r.URL.Query().Get("error")

	if errParam != "" {
		http.Error(w, "auth error: "+errParam+" — "+r.URL.Query().Get("error_description"), http.StatusBadRequest)
		return
	}

	sessionId, err := r.Cookie("session")
	if err != nil {
		http.Error(w, "session cookie not found", http.StatusBadRequest)
		return
	}
	log.Println("session: " + sessionId.Value)

	session, ok := sessions.Load(sessionId.Value)
	if !ok {
		http.Error(w, "invalid or expired session", http.StatusBadRequest)
		return
	}

	if session.(*Session).state != state {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}
	config, err := getOIDCConfig()
	if err != nil {
		http.Error(w, "failed to get OIDC config", http.StatusInternalServerError)
		return
	}

	verifier := session.(*Session).verifier
	secret := os.Getenv("CLIENT_SECRET")

	resp, err := http.PostForm(
		config.TokenEndpoint,
		url.Values{
			"grant_type":    {"authorization_code"},
			"client_id":     {"go_test"},
			"client_secret": {secret},
			"redirect_uri":  {"http://localhost:8080/callback"},
			"code":          {code},
			"code_verifier": {verifier},
		},
	)

	if err != nil {
		http.Error(w, "token exchange failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	var tokens tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		http.Error(w, "failed to decode token response", http.StatusInternalServerError)
		return
	}

	if tokens.Error != "" {
		http.Error(w, "token error: "+tokens.Error+" — "+tokens.ErrorDesc, http.StatusUnauthorized)
		return
	}

	log.Println("Token exchange successful")
	issuer := os.Getenv("BASE_URL")
	t, err := jwt.ParseWithClaims(tokens.IDToken, &idTokenClaims{}, fetchPublicKey,
		jwt.WithLeeway(5*time.Second),
		jwt.WithIssuer(issuer),
		jwt.WithAudience("go_test"),
	)
	if err != nil {
		http.Error(w, "failed to validate token", http.StatusInternalServerError)
		return
	}

	session = &Session{user: t.Claims.(*idTokenClaims).GivenName}
	sessions.Store(sessionId.Value, session)

	http.Redirect(w, r, "http://localhost:8080/", http.StatusFound)
}

func fetchPublicKey(token *jwt.Token) (any, error) {
	jwk, err := getJwkSet()
	if err != nil {
		return nil, err
	}

	key := jwk.byKid()[token.Header["kid"].(string)]
	return key.toPublicKey(), nil
}

func (s *JwkSet) byKid() map[string]JWK {
	m := make(map[string]JWK, len(s.Keys))
	for _, k := range s.Keys {
		m[k.KeyID] = k
	}
	return m
}

func (s *JWK) toPublicKey() *rsa.PublicKey {
	N, err := base64.RawURLEncoding.DecodeString(s.N)
	if err != nil {
		log.Fatal("failed to decode N: " + err.Error())
	}
	E, err := base64.RawURLEncoding.DecodeString(s.E)
	if err != nil {
		log.Fatal("failed to decode E: " + err.Error())
	}
	e := 0
	for _, b := range E {
		e = e<<8 | int(b)
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(N),
		E: e,
	}
}

func getJwkSet() (*JwkSet, error) {
	var fetchErr error
	config, err := getOIDCConfig()
	if err != nil {
		return nil, err
	}
	jwkOnce.Do(func() {
		resp, err := http.Get(config.JwksURI)
		if err != nil {
			fetchErr = err
			return
		}
		defer resp.Body.Close()

		var result JwkSet
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			fetchErr = err
			return
		}
		log.Println("Fetched JWKs")
		jwkCache = &result
	})
	return jwkCache, fetchErr
}

func getOIDCConfig() (*OIDCConfig, error) {
	var fetchErr error
	oidcConfigOnce.Do(func() {
		var baseUrl = os.Getenv("BASE_URL")
		resp, err := http.Get(fmt.Sprintf("%s/.well-known/openid-configuration", baseUrl))
		if err != nil {
			fetchErr = err
			return
		}
		defer resp.Body.Close()

		var result OIDCConfig
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			fetchErr = err
			return
		}
		log.Println("Fetched OIDC config")
		oidcConfig = &result
	})
	return oidcConfig, fetchErr
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/{$}", indexHandler)
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/callback", callbackHandler)

	log.Println("Listening on port 8080")
	err := http.ListenAndServe(":8080", mux)
	if err != nil {
		log.Fatalf("ListenAndServe: %s", err)
	}
}
