# Makefile de jay.
#
# `make check` es lo que tiene que pasar antes de un commit. El gate de lint
# (.golangci.yml) es lo que impide que la legibilidad se vuelva a degradar:
# sin él, la deuda se acumula sin que nada avise.

.PHONY: check fmt vet lint test build conformance

check: fmt vet lint test build ## Todo lo que tiene que pasar antes de un commit
	@echo "ok: check completo"

fmt: ## gofmt sobre todo el módulo (falla si algo está sin formatear)
	@test -z "$$(gofmt -l . | grep -v vendor)" || \
		(echo "sin formatear:"; gofmt -l . | grep -v vendor; exit 1)

vet: ## go vet
	go vet ./...

lint: ## golangci-lint con la config del servicio
	golangci-lint run ./...

test: ## Tests unitarios
	go test ./...

build: ## Compila todo
	go build ./...

# Fuera de `check` a propósito: necesita aws-cli, mc y warp instalados y tarda
# alrededor de un minuto. `go test` prueba que jay coincide consigo mismo; esto
# prueba que coincide con clientes que no escribió.
conformance: ## Suite de conformidad S3 contra aws-cli, mc y warp
	./scripts/conformance.sh
