package auth

import (
	"net/http"

	"github.com/xix-support/step-ca-web/internal/session"
)

func Middleware(sessMgr *session.Manager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess, err := sessMgr.Get(r)
			if err != nil {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}

			if !sessMgr.IsValid(sess) {
				sessMgr.Delete(w)
				http.Error(w, `{"error":"session expired"}`, http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
