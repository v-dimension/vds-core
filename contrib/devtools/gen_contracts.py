#! /usr/bin/python3

import os
import sys
import json

soldir = ''

def writecontracts(chhfile, objs):
    if not objs.get("contracts"):
        print("this file does not have any contract.")
        sys.exit(1)
        return
    for key in objs["contracts"]:
        contract = objs["contracts"][key]
        contractname = key.split(":")[1]
        if contractname in ["Ownable", "IterableMapping", "SafeMath"]:
            continue
        hexcode = contract["bin"]
        abi = contract["abi"].replace("\"", "\\\"")
        chhfile.write("const std::string s%sBin = \"%s\";\n" % (contractname, hexcode))
        chhfile.write("const std::string s%sAbi = \"%s\";\n" % (contractname, abi))

def gencontracts(header, contracts):
    chhfilename = "%s/%s.contract.hpp" % (soldir, header.lower())
    chhfile = open(chhfilename, "w")
    chhfile.write('''\
#ifndef __%s_HPP__
#define __%s_HPP__

#include <string>
''' % (header.upper(), header.upper()))
    writecontracts(chhfile, contracts)
    chhfile.write("#endif // __%s_HPP__" % header.upper())
    chhfile.close()



if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("must specify a filename")
        sys.exit(-1)
    sourcefile = sys.argv[1]
    header = os.path.basename(sourcefile).replace(".json", "")
    soldir = os.path.dirname(sourcefile)
    try:
        contracts = json.loads(open(sourcefile, "r").read())
    except(Exception):
        print("file %s load failed, incorrect file format." % sourcefile)
        sys.exit(-1)

    gencontracts(header, contracts)

