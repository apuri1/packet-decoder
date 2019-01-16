
include ../../Make.inc

INCLUDE 	= -I../ \

OBJS 	 	= json.o

$(OBJS): json.cpp
	g++ $(CC_FLAGS) $(INCLUDE) -o $@ -c $<

clean:
	rm -rf $(OBJS)

