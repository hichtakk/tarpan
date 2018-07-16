dep:
	dep ensure

build:
	go build -o ./cmd/tarpan ./cmd/tarpan.go

test:
	time go test -v

mock:
	~/.golang.d/bin/mockgen --source tarpan.go --destination mock/mock_tarpan.go
