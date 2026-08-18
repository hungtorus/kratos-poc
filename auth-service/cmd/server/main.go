package main

import (
	"context"
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"

	"github.com/hardy/kratos-poc2/auth-service/internal/config"
	"github.com/hardy/kratos-poc2/auth-service/internal/httpapi"
	"github.com/hardy/kratos-poc2/auth-service/internal/kratosx"
	"github.com/hardy/kratos-poc2/auth-service/internal/store"
	"github.com/hardy/kratos-poc2/auth-service/internal/token"
)

func main() {
	log := logrus.New()
	log.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})

	cfg, err := config.Load(".env")
	if err != nil {
		log.Fatal(err)
	}
	level, err := logrus.ParseLevel(cfg.LogLevel)
	if err == nil {
		log.SetLevel(level)
	}

	st, err := store.New(context.Background(), cfg.DynamoDBEndpoint, cfg.DynamoDBRegion, cfg.ProfileIdentifierSalt)
	if err != nil {
		log.Fatal(err)
	}
	signer, err := token.NewSigner(cfg.JWTPrivateKeyPath, cfg.JWTIssuer, cfg.JWTAudience, cfg.JWTTL)
	if err != nil {
		log.Fatal(err)
	}
	kc := kratosx.New(cfg.KratosPublicURL, cfg.KratosAdminURL)
	webDir := os.Getenv("WEB_DIR")
	if webDir == "" {
		webDir = filepath.Join(".", "web")
		if _, err := os.Stat(webDir); err != nil {
			webDir = "/app/web"
		}
	}
	srv := httpapi.New(cfg, kc, st, signer, log, webDir)
	if err := srv.Listen(); err != nil {
		log.Fatal(err)
	}
}
