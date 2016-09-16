install:
	go install ...defector/cmd...

capa:
	sudo setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' $(GOPATH)/bin/tbbdnsw

doc:
	godoc -http :6060

proto:
	protoc *.proto --go_out=plugins=grpc:.
