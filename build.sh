CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags "-s -w" -o vvstorage-mac
zip ./vvstorage-mac.zip ./vvstorage-mac
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o vvstorage-win.exe
zip ./vvstorage-win.zip ./vvstorage-win.exe
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o vvstorage-linux
zip ./vvstorage-linux.zip ./vvstorage-linux
rm -rf vvstorage-mac
rm -rf vvstorage-win.exe
rm -rf vvstorage-linux