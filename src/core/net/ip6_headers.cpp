/*
 *  Copyright (c) 2017, The OpenThread Authors.
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name of the copyright holder nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file
 *   This file implements IP6 header processing.
 */

#include "ip6_headers.hpp"

#include "net/ip6.hpp"

namespace ot {
namespace Ip6 {

//---------------------------------------------------------------------------------------------------------------------
// Header

Error Header::ParseFrom(const Message &aMessage)
{
    Error error = kErrorParse;

    SuccessOrExit(aMessage.Read(0, *this));
    VerifyOrExit(IsValid());
    VerifyOrExit(sizeof(Header) + GetPayloadLength() == aMessage.GetLength());

    error = kErrorNone;

exit:
    return error;
}

bool Header::IsValid(void) const
{
#if !OPENTHREAD_CONFIG_IP6_FRAGMENTATION_ENABLE
    static constexpr uint32_t kMaxLength = kMaxDatagramLength;
#else
    static constexpr uint32_t kMaxLength = kMaxAssembledDatagramLength;
#endif

    return IsVersion6() && ((sizeof(Header) + GetPayloadLength()) <= kMaxLength);
}

//---------------------------------------------------------------------------------------------------------------------
// PadNOption

void PadNOption::Init(uint8_t aPadLength)
{
    SetType(kType);
    SetLength(aPadLength - sizeof(Option));
    memset(mPad, kData, aPadLength - sizeof(Option));
}

} // namespace Ip6
} // namespace ot
