build:
	go build -o ./build/tarpan ./cmd/main.go

test:
	time go test -v

mock:
	~/.golang.d/bin/mockgen --source tarpan.go --destination mock/mock_tarpan.go
