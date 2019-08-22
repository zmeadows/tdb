TDB_DIR=/home/zac/tdb/

cd $TDB_DIR/build/

if [ -d "${TDB_DIR}/build" ]
then
    cd "$TDB_DIR/build/"
    cmake ..
fi

scan-build make -j 4
cppcheck --project=compile_commands.json
