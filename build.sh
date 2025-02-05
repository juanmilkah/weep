#!/bin/bash

echo "Building the program...."
cargo build --release 

sudo cp target/release/weep /usr/local/bin/
echo "Executable saved."

WEEPRC_DIR=$HOME/.weeprc 
mkdir $WEEPRC_DIR
echo "Created weeprc directory"

touch "$WEEPRC_DIR/passwords"
touch "$WEEPRC_DIR/key"

echo "To start the program run: weep"
