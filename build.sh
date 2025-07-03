#!/bin/bash

echo "Building the program...."
cargo build --release 

sudo cp target/release/weep /usr/local/bin/
echo "Executable saved."

echo "To start the program run: weep"
