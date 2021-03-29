debsrc:
	debuild -S -sa --lintian-opts -i

deb:
	debuild -F --lintian-opts -i

