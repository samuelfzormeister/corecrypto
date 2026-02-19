/*
 * Copyright (C) 2026 The PureDarwin Project, All rights reserved.
 *
 * @LICENSE_HEADER_BEGIN@
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * @LICENSE_HEADER_END@
 */

#include <corecrypto/cc_config.h>

//
// Basically just the prng_seedctl of Darwin but open.
//

//
// What our task is:
// - Send the latest round of entropy (in SEEDFILE_PATH) to cckprng via /dev/random
// - Get the next round of entropy and write to SEEDFILE_PATH
//

#if CC_DARWIN

#define SEEDFILE_PATH "/var/db/EntropySeedCache"

int main(int argc, const char *argv[])
{
    
}

#endif
