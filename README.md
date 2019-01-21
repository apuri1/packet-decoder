# Decoder

Decode messages off the wire.

built using devtoolset-2 (CentOS 6) and devtoolset-7 (CentOS 7)

Several TODOs still outstanding:
* -use cmake to generate Makefile, as ooposed to current hand-cranked version - construct CMakeLists.txt
* -add diameter applications - currently limited to S6a diameter.
* -add HTTP decoder, possible levergaing curl for message construction.
* -keep add more protocol decoders
* -clean up boost Multiindex use
* -leverage more of boost capabilities
* -look into using templates
