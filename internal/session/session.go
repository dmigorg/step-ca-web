package session

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
)

const cookieName = "step-web-session"

type SessionData struct {
	ProvisionerName string    `json:"provisioner_name"`
	ProvisionerKID  string    `json:"provisioner_kid"`
	JWKData         []byte    `json:"jwk_data"`
	RootSHA         string    `json:"root_sha"`
	AuthenticatedAt time.Time `json:"authenticated_at"`
}

type Manager struct {
	sc       *securecookie.SecureCookie
	maxAge   int
	hashKey  []byte
	blockKey []byte
}

func NewManager(secret string, maxAge int) *Manager {
	hashKey := []byte(secret)
	if len(hashKey) > 64 {
		hashKey = hashKey[:64]
	} else if len(hashKey) < 32 {
		hashKey = append(hashKey, make([]byte, 32-len(hashKey))...)
	}

	blockKey := hashKey[:32]

	sc := securecookie.New(hashKey, blockKey)
	sc.MaxAge(maxAge)
	sc.SetSerializer(securecookie.JSONEncoder{})

	return &Manager{
		sc:       sc,
		maxAge:   maxAge,
		hashKey:  hashKey,
		blockKey: blockKey,
	}
}

func (m *Manager) Create(w http.ResponseWriter, data *SessionData) error {
	data.AuthenticatedAt = time.Now()

	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	encoded, err := m.sc.Encode(cookieName, string(jsonData))
	if err != nil {
		return err
	}

	cookie := &http.Cookie{
		Name:     cookieName,
		Value:    encoded,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   m.maxAge,
	}

	http.SetCookie(w, cookie)
	return nil
}

func (m *Manager) Get(r *http.Request) (*SessionData, error) {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return nil, err
	}

	var encoded string
	if err := m.sc.Decode(cookieName, cookie.Value, &encoded); err != nil {
		return nil, err
	}

	var data SessionData
	if err := json.Unmarshal([]byte(encoded), &data); err != nil {
		return nil, err
	}

	if !m.IsValid(&data) {
		return nil, http.ErrNoCookie
	}

	return &data, nil
}

func (m *Manager) Delete(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	}
	http.SetCookie(w, cookie)
}

func (m *Manager) IsValid(data *SessionData) bool {
	if data == nil {
		return false
	}
	elapsed := time.Since(data.AuthenticatedAt)
	return elapsed.Seconds() < float64(m.maxAge)
}
