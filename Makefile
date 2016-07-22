all: update

setup:
	mkdir -p ./pacman/{lib,cache,log}

update: setup
	./update

clean:
	rm -rf ./pacman/{lib,cache,log}

forceme:
