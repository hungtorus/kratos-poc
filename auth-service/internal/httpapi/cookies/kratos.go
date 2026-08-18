package cookies

import (
	"net/http"

	"github.com/gofiber/fiber/v2"
)

// ApplySetCookies forwards Kratos Set-Cookie headers to the browser.
// Required for OIDC link (settings) flows: Kratos stores the auth-code session
// in ory_kratos_continuity, which must survive the redirect to Google and back.
func ApplySetCookies(c *fiber.Ctx, from []*http.Cookie) {
	for _, ck := range from {
		if ck == nil || ck.Name == "" {
			continue
		}
		fc := &fiber.Cookie{
			Name:     ck.Name,
			Value:    ck.Value,
			Path:     ck.Path,
			Domain:   ck.Domain,
			MaxAge:   ck.MaxAge,
			Expires:  ck.Expires,
			Secure:   ck.Secure,
			HTTPOnly: ck.HttpOnly,
			SameSite: sameSiteString(ck.SameSite),
		}
		if fc.Path == "" {
			fc.Path = "/"
		}
		c.Cookie(fc)
	}
}

func sameSiteString(mode http.SameSite) string {
	switch mode {
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteNoneMode:
		return "None"
	default:
		return "Lax"
	}
}
