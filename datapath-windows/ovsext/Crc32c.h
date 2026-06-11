/*
 * Copyright (c) 2025 dbosoft GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __CRC32C_H_
#define __CRC32C_H_ 1

#include "precomp.h"

/*
 * Computes the CRC32c (Castagnoli) checksum used by SCTP (RFC 4960) over
 * 'size' bytes at 'data'. The seed is all-ones and the result is negated;
 * the returned value is in network byte order, matching the on-wire SCTP
 * checksum field. Table-driven and lock/allocation-free, so it is safe to
 * call at DISPATCH_LEVEL.
 */
ovs_be32 OvsCrc32c(const UINT8 *data, SIZE_T size);

#endif /* __CRC32C_H_ */
