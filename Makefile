build:
	go get github.com/codegangsta/cli
	go get github.com/soniah/gosnmp
	go get github.com/hichtakk/tarpan
	go build -o ./cmd/tarpan ./cmd/tarpan.go

test:
	time go test -v

