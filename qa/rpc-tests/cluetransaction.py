#!/usr/bin/env python2
# Copyright (c) 2015 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
import logging
import json
import time

logging.basicConfig(format='%(asctime)s %(levelname)s (%(filename)s:%(lineno)s) - %(message)s', level=logging.INFO)


class ClueTransactionTest(BitcoinTestFramework):
    """Tests decoding scripts via RPC command "decodescript"."""

    def setup_chain(self):
        logging.info('Initializing test directory ' + self.options.tmpdir)
        initialize_chain_clean(self.options.tmpdir, 1)

    def setup_network(self, split=False):
        self.nodes = start_nodes(1, self.options.tmpdir)
        self.is_network_split = False

    # def generate_blocks(self):
    #     node = self.nodes[0]
    #     x = 110
    #     rpc_result = node.generate(110)
    #     print(rpc_result)
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

        logging.info("preparing 200 addresses to recieve 11v for creating VID")
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

    def createcluetx(self):
        node = self.nodes[0]

        src = "vadhEJX8QP91ouB5xa8WCqaBVAuPA5zaCBc"

        r = node.getclue(src)

        assert_equal(r["address"], src)
        assert_equal(r["isRoot"], True)
        assert_equal(r["txid"], "0000000000000000000000000000000000000000000000000000000000000000")
        assert_equal(r["directParent"], "")
        assert_equal(r["indirectParent"], "")

        clueTxIdList1 = []
        for i in range(0, 12):
            r = node.createclue(self.addresses[i], src)
            clueTxIdList1.append(r["txid"])

            logging.info(self.addresses[i])
            logging.info(r)

        # tx not submited, cluechildren num should be 0
        r = node.getcluechildren(src)
        assert_equal(len(r), 0)
        r = node.getcluechildren(src, "1")
        assert_equal(len(r), 0)

        node.generate(1)

        r = node.getcluechildren(src)
        assert_equal(len(r), 12)
        directChildren = node.getcluechildren(src, "1")
        logging.info(r)
        logging.info(directChildren)

        # validate 0-12 addresses
        for i in range(0, 12):
            assert_equal(self.addresses[i] in r, True)

            rr = node.getclue(self.addresses[i])
            assert_equal(rr["address"], self.addresses[i])
            assert_equal(rr["isRoot"], False)
            assert_equal(rr["txid"] in clueTxIdList1, True)
            assert_equal(rr["directParent"], src)
            assert_equal(rr["indirectParent"], src)

            if self.addresses[i] not in directChildren:
                logging.info("%s should in directChildren,but it is not" % self.addresses[i])

        assert_equal(len(directChildren), 12)


        # make 13-24 address to be clue address
        clueTxIdList2 = []
        for i in range(12, 24):
            r = node.createclue(self.addresses[i], src)
            clueTxIdList2.append(r["txid"])

        r = node.getcluechildren(src, "0")
        assert_equal(len(r), 12)
        r = node.getcluechildren(src, "1")
        assert_equal(len(r), 12)

        node.generate(1)

        r = node.getcluechildren(src, "0")
        assert_equal(len(r), 24)

        r = node.getcluechildren(src, "1")
        assert_equal(len(r), 12)

    def run_test(self):
        # self.generate_blocks()
        self.prepare_coins()
        self.createcluetx()


if __name__ == '__main__':
    ClueTransactionTest().main()
