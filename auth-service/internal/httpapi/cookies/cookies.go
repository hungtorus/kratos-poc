package cookies

import (
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
)

const sessionTokenCookie = "poc_kratos_session"

func SessionTokenFromFiber(c *fiber.Ctx) string {
	return c.Cookies(sessionTokenCookie)
}

func cookieSecure(c *fiber.Ctx, publicBaseURL string) bool {
	if strings.EqualFold(c.Get("X-Forwarded-Proto"), "https") {
		return true
	}
	if c.Protocol() == "https" {
		return true
	}
	return strings.HasPrefix(publicBaseURL, "https://")
}

// SetSessionToken stores the Kratos API session token in a host-only cookie.
// Do not set Domain — explicit Domain breaks many ngrok / reverse-proxy setups.
func SetSessionToken(c *fiber.Ctx, publicBaseURL, token string) {
	c.Cookie(&fiber.Cookie{
		Name:     sessionTokenCookie,
		Value:    token,
		Path:     "/",
		HTTPOnly: true,
		SameSite: "Lax",
		Secure:   cookieSecure(c, publicBaseURL),
		MaxAge:   86400 * 7,
	})
}

func ClearSessionToken(c *fiber.Ctx, publicBaseURL string) {
	c.Cookie(&fiber.Cookie{
		Name:     sessionTokenCookie,
		Value:    "",
		Path:     "/",
		HTTPOnly: true,
		SameSite: "Lax",
		Secure:   cookieSecure(c, publicBaseURL),
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}
