build:
	go get -u gopkg.in/alecthomas/kingpin.v2
	go get -u github.com/soniah/gosnmp
	go get -u github.com/hichtakk/tarpan
	go build -o ./cmd/tarpan ./cmd/tarpan.go

test:
	time go test -v

mock:
	~/.golang.d/bin/mockgen --source tarpan.go --destination mock/mock_tarpan.go
