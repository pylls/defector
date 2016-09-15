install:
	go install ...defector/cmd...

capa:
	sudo setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' $(GOPATH)/bin/tbbdnsw

proto:
	protoc *.proto --go_out=plugins=grpc:.
