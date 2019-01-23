
WARNINGS:=-O3 -g -Wall -Wextra -Wcast-align -Wno-cast-qual -Wl,-z,defs,--no-as-needed -ldl \
	      -Wformat=2 -Winit-self -Wlogical-op -Wmissing-declarations \
	      -Wmissing-include-dirs -Wnoexcept -Woverloaded-virtual \
	      -Wshadow -Wsign-promo -Wstrict-null-sentinel -Wstrict-overflow=5 \
	      -Wswitch-default -Wno-unused -foptimize-sibling-calls \
	      -D_FORTIFY_SOURCE=2 -fasynchronous-unwind-tables -fexceptions \
	      -fstack-protector-all -grecord-gcc-switches -pipe -Werror=format-security

CFLAGS=-std=c++14

