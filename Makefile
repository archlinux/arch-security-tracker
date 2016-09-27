all: update

setup: submodule
	mkdir -p ./pacman/{cache,log}
	mkdir -p ./pacman/arch/{i686,x86_64}/db
	./db_create

submodule:
	git submodule update --recursive --init --rebase

update: setup
	./update

clean:
	rm -rf ./pacman/{cache,log}
	rm -rf ./pacman/arch/{i686,x86_64}/db

forceme:
