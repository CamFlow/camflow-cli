prepare:
	@echo "Nothing to do"

all:
	cd ./src && $(MAKE) all

clean:
	cd ./src && $(MAKE) clean

install:
	cd ./src && sudo $(MAKE) install
