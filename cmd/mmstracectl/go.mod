module github.com/otfabric/go-mms-trace/cmd/mmstracectl

go 1.26.0

require (
	github.com/otfabric/go-mms v1.7.0
	github.com/otfabric/go-mms-trace v0.0.0
	github.com/spf13/cobra v1.10.2
	github.com/spf13/pflag v1.0.9
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/otfabric/go-cotp v1.3.0 // indirect
	github.com/otfabric/go-iec61850 v1.14.0 // indirect
	github.com/otfabric/go-tpkt v1.1.0 // indirect
	golang.org/x/sys v0.44.0 // indirect
)

// Development only: replaced by a version pin of the library at release.
replace github.com/otfabric/go-mms-trace => ../..
