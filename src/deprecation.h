// Copyright (c) 2017-2019 The Vds developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef VDS_DEPRECATION_H
#define VDS_DEPRECATION_H

// Deprecation policy is 4th third-Tuesday after a release
static const int APPROX_RELEASE_HEIGHT = 120500;
static const int WEEKS_UNTIL_DEPRECATION = 18;
static const int DEPRECATION_HEIGHT = APPROX_RELEASE_HEIGHT + (WEEKS_UNTIL_DEPRECATION * 7 * 24 * 24);

// Number of blocks before deprecation to warn users
static const int DEPRECATION_WARN_LIMIT = 14 * 24 * 24; // 2 weeks

/**
 * Checks whether the node is deprecated based on the current block height, and
 * shuts down the node with an error if so (and deprecation is not disabled for
 * the current client version). Warning and error messages are sent to the debug
 * log, the metrics UI, and (if configured) -alertnofity.
 *
 * fThread means run -alertnotify in a free-running thread.
 */
void EnforceNodeDeprecation(int nHeight, bool forceLogging = false, bool fThread = true);

#endif // VDS_DEPRECATION_H
