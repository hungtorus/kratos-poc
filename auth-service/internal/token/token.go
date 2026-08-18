package token

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Signer struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	issuer     string
	audience   string
	ttl        time.Duration
}

type Claims struct {
	jwt.RegisteredClaims
	KratosIdentityID string   `json:"kratos_identity_id"`
	AAL              string   `json:"aal"`
	AMR              []string `json:"amr"`
	LinkedMethods    []string `json:"linked_methods"`
	Email            string   `json:"email,omitempty"`
	GoogleEmail      string   `json:"google_email,omitempty"`
	TelegramID       string   `json:"telegram_id,omitempty"`
}

func NewSigner(path, issuer, audience string, ttl time.Duration) (*Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read jwt key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("invalid pem")
	}
	var key *rsa.PrivateKey
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		key = k
	} else {
		keyAny, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("parse key: %w", err)
		}
		var ok bool
		key, ok = keyAny.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not rsa private key")
		}
	}
	return &Signer{
		privateKey: key,
		publicKey:  &key.PublicKey,
		issuer:     issuer,
		audience:   audience,
		ttl:        ttl,
	}, nil
}

func (s *Signer) Sign(userID string, c Claims) (string, string, time.Time, error) {
	now := time.Now()
	exp := now.Add(s.ttl)
	jti := uuid.NewString()
	c.RegisteredClaims = jwt.RegisteredClaims{
		Issuer:    s.issuer,
		Subject:   userID,
		Audience:  jwt.ClaimStrings{s.audience},
		ExpiresAt: jwt.NewNumericDate(exp),
		IssuedAt:  jwt.NewNumericDate(now),
		ID:        jti,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	signed, err := token.SignedString(s.privateKey)
	return signed, jti, exp, err
}

func (s *Signer) Verify(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return s.publicKey, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return claims, nil
}

func (s *Signer) JWKSJSON() ([]byte, error) {
	n := base64.RawURLEncoding.EncodeToString(s.publicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(s.publicKey.E)).Bytes())
	out := map[string]any{
		"keys": []map[string]string{{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": "poc-key-1",
			"n":   n,
			"e":   e,
		}},
	}
	return json.Marshal(out)
}
