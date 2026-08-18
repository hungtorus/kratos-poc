.PHONY: keys up down logs build restart

keys:
	@mkdir -p keys
	@if [ ! -f keys/jwt.pem ]; then \
		openssl genrsa -out keys/jwt.pem 2048; \
		echo "Generated keys/jwt.pem"; \
	else \
		echo "keys/jwt.pem already exists"; \
	fi

build:
	docker compose build

up: keys
	docker compose up --build -d

down:
	docker compose down -v

logs:
	docker compose logs -f auth-service kratos

restart:
	docker compose restart auth-service kratos

ngrok:
	@echo "Run on host: ngrok http 8080 --domain=$$PUBLIC_HOST"
