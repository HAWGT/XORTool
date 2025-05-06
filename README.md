This is a tool created as a proof of concept for runtime and static obfuscation

By declaring exported functions with the prefix FunctionCode, the included XORTool will xor the functions' bytecode with a key derived from the host machine (the method needs to be changed for a real world scenario).

Said exported functions must be xor'ed before executing and should be xor'ed once again to minimize the time of which their bytecode is exposed.

Running the compiled program without utilizing the XORTool will cause it to crash, using it in another machine will also cause it to crash, this is by design and as an attempt to make static analysis more difficult.

This repository includes implementation examples (the driver one hasn't been thoroughly tested at the moment).
