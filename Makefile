.POSIX:

VERSION=0.1

PREFIX?=/usr/local
_INSTDIR=$(DESTDIR)$(PREFIX)
BINDIR?=$(_INSTDIR)/bin
GO?=go
GOFLAGS?=

GOSRC!=find . -name '*.go'
GOSRC+=go.mod go.sum

goose: $(GOSRC)
	$(GO) build $(GOFLAGS) \
		-ldflags "-X main.Prefix=$(PREFIX)" \
		-o $@
	sudo setcap cap_ipc_lock+ep $@

all: goose

install: all
	install -m755 goose $(BINDIR)/goose
	sudo setcap cap_ipc_lock+ep $(BINDIR)/goose

uninstall:
	$(RM) $(BINDIR)/goose
