Required software for making a release
  * [github-release](https://github.com/aktau/github-release) for uploading packages
  * [gox](https://github.com/mitchellh/gox) for cross compiling
    * Run `gox -build-toolchain`
    * This assumes you have your own source checkout
  * pandoc for making the html and man pages

Making a release
  * go get -u -f -v ./...
  * make test
  * make tag
  * edit README.md
  * git commit fs/version.go README.md docs/content/downloads.md
  * make retag
  * # Set the GOPATH for a gox enabled compiler - . ~/bin/go-cross
  * make cross
  * make upload
  * make upload_website
  * git push --tags origin master
