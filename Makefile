include lib/main.mk

i-d-template:
	git subtree pull --prefix=lib https://github.com/martinthomson/i-d-template master --squash
