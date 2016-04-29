build:
	go get -u github.com/codegangsta/cli
	go get -u github.com/soniah/gosnmp
	go get -u github.com/hichtakk/tarpan
	go build -o ./cmd/tarpan ./cmd/tarpan.go

test:
	time go test -v

