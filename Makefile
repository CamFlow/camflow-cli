version=0.1.13

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

deb:
	sudo alien output/camflow-cli-$(version)-1.x86_64.rpm
	cp *.deb ./output

publish_rpm:
	cd ./output && package_cloud push camflow/provenance/fedora/27 camflow-cli-$(version)-1.x86_64.rpm

publish_deb:
	cd ./output && package_cloud push camflow/provenance/ubuntu/bionic camflow-cli_$(version)-2_amd64.deb

publish: publish_rpm publish_deb
