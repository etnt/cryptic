.PHONY: all compile xref clean server client edoc lux-runpty

all: CA compile xref lux-runpty

lux-runpty: ./_build/default/lib/lux/priv/bin/runpty

./_build/default/lib/lux/priv/bin/runpty:
	(cd ./_build/default/lib/lux ; \
		autoconf ; \
		./configure ; \
		make)

compile:
	rebar3 compile

xref:
	rebar3 xref

edoc:
	rebar3 edoc

CA:
	git clone --depth 1 https://github.com/etnt/myca.git CA

clean:
	rebar3 clean

# ---------------------------------------------------------------------
# TEST STUFF
# Used by Lux test scripts
# ---------------------------------------------------------------------

.PHONY: lux-tests send_messages-lux

lux-tests: send_messages-lux console_basic_flow-lux

console_basic_flow-lux:
	./_build/default/lib/lux/bin/lux test/lux/console_basic_flow.lux

send_messages-lux:
	./_build/default/lib/lux/bin/lux ./test/send_messages.lux





