# Decoder

Decode messages off the wire.

built using devtoolset-2 (CentOS 6) and devtoolset-7 (CentOS 7)

Several TODOs still outstanding:
* -use cmake to generate Makefile, as ooposed to current hand-cranked version - construct CMakeLists.txt
* -add diameter applications - currently limited to S6a diameter.
* -develop HTTP decoder, possible levergaing curl for message construction.
* -develop MQTT decoder.
* -adding more protocol decoders
* -clean up boost Multiindex use
* -Complete Client connectors
* -leverage more of boost capabilities
