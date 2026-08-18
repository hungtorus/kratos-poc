package config

import (
	"time"

	"github.com/ilyakaznacheev/cleanenv"
	"github.com/joho/godotenv"
)

type Config struct {
	PublicBaseURL string `env:"PUBLIC_BASE_URL" env-required:"true"`
	PublicHost    string `env:"PUBLIC_HOST" env-required:"true"`

	KratosPublicURL string `env:"KRATOS_PUBLIC_URL" env-default:"http://kratos:4433"`
	KratosAdminURL  string `env:"KRATOS_ADMIN_URL" env-default:"http://kratos:4434"`

	CourierWebhookSecret string `env:"COURIER_WEBHOOK_SECRET" env-default:"dev-courier-secret"`

	JWTIssuer             string        `env:"JWT_ISSUER"`
	JWTAudience           string        `env:"JWT_AUDIENCE" env-default:"kratos-poc-web"`
	JWTTL                 time.Duration `env:"JWT_TTL" env-default:"1h"`
	JWTPrivateKeyPath     string        `env:"JWT_PRIVATE_KEY_PATH" env-default:"/etc/auth/keys/jwt.pem"`
	ProfileIdentifierSalt string        `env:"PROFILE_IDENTIFIER_SALT" env-default:"dev-salt"`

	// TelegramBrokerIssuer is intentionally an internal URL: Kratos is the only
	// relying party and resolves discovery, token, and JWKS over Docker DNS.
	TelegramBrokerIssuer        string `env:"TELEGRAM_BROKER_ISSUER" env-default:"http://auth-service:8080/internal/oidc/telegram"`
	TelegramBrokerPublicBaseURL string `env:"TELEGRAM_BROKER_PUBLIC_BASE_URL"`
	TelegramBrokerClientID      string `env:"TELEGRAM_BROKER_CLIENT_ID" env-default:"kratos"`
	TelegramBrokerClientSecret  string `env:"TELEGRAM_BROKER_CLIENT_SECRET" env-required:"true"`
	TelegramBrokerRedirectURL   string `env:"TELEGRAM_BROKER_REDIRECT_URL"`
	TelegramOIDCClientID        string `env:"TELEGRAM_OIDC_CLIENT_ID" env-required:"true"`
	TelegramOIDCClientSecret    string `env:"TELEGRAM_OIDC_CLIENT_SECRET" env-required:"true"`

	DynamoDBEndpoint string `env:"DYNAMODB_ENDPOINT" env-default:"http://dynamodb-local:8000"`
	DynamoDBRegion   string `env:"DYNAMODB_REGION" env-default:"us-east-1"`

	ListenAddr string `env:"LISTEN_ADDR" env-default:":8080"`
	LogLevel   string `env:"LOG_LEVEL" env-default:"info"`
}

func Load(paths ...string) (*Config, error) {
	if len(paths) > 0 {
		_ = godotenv.Load(paths...)
	}
	var cfg Config
	if err := cleanenv.ReadEnv(&cfg); err != nil {
		return nil, err
	}
	if cfg.JWTIssuer == "" {
		cfg.JWTIssuer = cfg.PublicBaseURL
	}
	if cfg.TelegramBrokerPublicBaseURL == "" {
		cfg.TelegramBrokerPublicBaseURL = cfg.PublicBaseURL
	}
	if cfg.TelegramBrokerRedirectURL == "" {
		cfg.TelegramBrokerRedirectURL = cfg.PublicBaseURL + "/auth/kratos/self-service/methods/oidc/callback/telegram"
	}
	return &cfg, nil
}
