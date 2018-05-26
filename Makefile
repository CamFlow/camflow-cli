version=0.1.8

prepare:
	@echo "Nothing to do"

all:
	cd ./src && $(MAKE) all

clean:
	cd ./src && $(MAKE) clean

install:
	cd ./src && sudo $(MAKE) install

rpm:
	mkdir -p ~/rpmbuild/{RPMS,SRPMS,BUILD,SOURCES,SPECS,tmp}
	cp -f ./camflow-cli.spec ~/rpmbuild/SPECS/camflow-cli.spec
	rpmbuild -bb camflow-cli.spec
	mkdir -p output
	cp ~/rpmbuild/RPMS/x86_64/* ./output

publish:
	cd ./output && package_cloud push camflow/provenance/fedora/27 camflow-cli-$(version)-1.x86_64.rpm
