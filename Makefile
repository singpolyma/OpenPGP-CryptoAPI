GHCFLAGS=-Wall -XNoCPP -fno-warn-name-shadowing -XHaskell98
HLINTFLAGS=-XHaskell98 -XNoCPP -i 'Use camelCase' -i 'Use String' -i 'Use string literal' -i 'Use list comprehension' --utf8 -XMultiParamTypeClasses
VERSION=0.6.2

.PHONY: all clean doc install debian test

all: sign verify keygen test report.html doc dist/build/libHSopenpgp-crypto-api-$(VERSION).a dist/openpgp-crypto-api-$(VERSION).tar.gz

install: dist/build/libHSopenpgp-crypto-api-$(VERSION).a
	cabal install

debian: debian/control

test: tests/suite
	tests/suite

sign: examples/sign.hs Data/OpenPGP/CryptoAPI.hs
	ghc --make $(GHCFLAGS) -o $@ $^

verify: examples/verify.hs Data/OpenPGP/CryptoAPI.hs
	ghc --make $(GHCFLAGS) -o $@ $^

keygen: examples/keygen.hs Data/OpenPGP/CryptoAPI.hs
	ghc --make $(GHCFLAGS) -o $@ $^

tests/suite: tests/suite.hs Data/OpenPGP/CryptoAPI.hs
	ghc --make $(GHCFLAGS) -o $@ $^

report.html: examples/*.hs Data/OpenPGP/CryptoAPI.hs tests/suite.hs
	-hlint $(HLINTFLAGS) --report Data examples

doc: dist/doc/html/openpgp-crypto-api/index.html README

README: openpgp-crypto-api.cabal
	tail -n+$$(( `grep -n ^description: $^ | head -n1 | cut -d: -f1` + 1 )) $^ > .$@
	head -n+$$(( `grep -n ^$$ .$@ | head -n1 | cut -d: -f1` - 1 )) .$@ > $@
	-printf ',s/        //g\n,s/^.$$//g\nw\nq\n' | ed $@
	$(RM) .$@

dist/doc/html/openpgp-crypto-api/index.html: dist/setup-config Data/OpenPGP/CryptoAPI.hs
	cabal haddock --hyperlink-source

dist/setup-config: openpgp-crypto-api.cabal
	cabal configure

clean:
	find -name '*.o' -o -name '*.hi' | xargs $(RM)
	$(RM) sign verify keygen tests/suite report.html
	$(RM) -r dist dist-ghc

debian/control: openpgp-crypto-api.cabal
	cabal-debian --update-debianization

dist/build/libHSopenpgp-crypto-api-$(VERSION).a: openpgp-crypto-api.cabal dist/setup-config Data/OpenPGP/CryptoAPI.hs
	cabal build --ghc-options="$(GHCFLAGS)"

dist/openpgp-crypto-api-$(VERSION).tar.gz: openpgp-crypto-api.cabal dist/setup-config Data/OpenPGP/CryptoAPI.hs README
	cabal check
	cabal sdist
