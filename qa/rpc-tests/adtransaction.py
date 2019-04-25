#!/usr/bin/env python2
# Copyright (c) 2015 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
import logging
import json

logging.basicConfig(format='%(asctime)s %(levelname)s (%(filename)s:%(lineno)s) - %(message)s', level=logging.INFO)

class AdTransactionTest(BitcoinTestFramework):
    """Tests ad via RPC command "bidad listbid listad"."""

    def setup_chain(self):
        logging.info('Initializing test directory ' + self.options.tmpdir)
        initialize_chain_clean(self.options.tmpdir, 1)

    def setup_network(self, split=False):
        self.nodes = start_nodes(1, self.options.tmpdir)
        self.is_network_split = False

    # def generate_blocks(self):
    #     node = self.nodes[0]
    #     x = 110
    #     # rpc_result = node.generate(110)
    #     # print(rpc_result)
    #
    #     blocks = []
    #     for i in range(0, x + 1):
    #         rpc_r = node.getblock(str(i), False)
    #         blocks.append(rpc_r)
    #
    #     blockstr = json.dumps(blocks)
    #     f = open('/tmp/blocks.json', 'w')
    #     f.write(blockstr)
    #     f.close()

    def read_blocks(self):
        f = open('blocks.json', 'r')
        str = f.read()
        blocks = json.loads(str)

        node = self.nodes[0]

        for s in blocks:
            node.submitblock(s)

    def prepare_coins(self):
        '''
            prepare coins to 200 addresses. For creating clue txs
        '''
        node = self.nodes[0]

        logging.info("reading 110 blocks to get 5000v")
        self.read_blocks()
        self.addresses = []

        logging.info("preparing 200 addresses to recieve 11v for creating tx")
        dest = {}
        for i in range(0, 200):
            addr = node.getnewaddress()
            dest[addr] = 11
            self.addresses.append(addr)

        logging.info("%d addresses generated" % len(self.addresses))

        logging.info("sending 11v to 200 addresses for each")
        rpc_result = node.sendmany("", dest)
        logging.info("txid=%s" % rpc_result)
        # confirm the tx
        node.generate(1)

    def createad(self):
        node = self.nodes[0]
        logging.error("TODO createad transaction tests")

    def run_test(self):
        self.prepare_coins()
        self.createad()


if __name__ == '__main__':
    AdTransactionTest().main()
