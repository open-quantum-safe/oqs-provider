// SPDX-License-Identifier: Apache-2.0 AND MIT

/*
 * oqsprovider prereqs file.
 *
 * Handles known error conditions where headers must be included out of order.
 *
 */

/* Internal OQS functions for other submodules: not for application use */
#ifndef OQSX_PREREQS_H
#define OQSX_PREREQS_H

/* on macOS / iOS uint64_t required by openssl/e_os2.h and friends */
#include <stdint.h>

#endif
