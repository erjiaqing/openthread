/*
 *  Copyright (c) 2022, The OpenThread Authors.
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
 *   This file includes definitions for IPv4 packet processing.
 */

#ifndef IP4_HEADERS_HPP_
#define IP4_HEADERS_HPP_

#include "openthread-core-config.h"

#include <stddef.h>

#include "common/clearable.hpp"
#include "common/encoding.hpp"
#include "common/message.hpp"
#include "net/ip4_address.hpp"
#include "net/ip6.hpp"
#include "net/netif.hpp"
#include "net/socket.hpp"

namespace ot {

/**
 * @namespace ot::Ip4
 *
 * @brief
 *   This namespace includes definitions for IPv4 networking.
 *
 */
namespace Ip4 {

using Encoding::BigEndian::HostSwap16;
using Encoding::BigEndian::HostSwap32;

using Ecn = Ip6::Ecn;

/**
 * @addtogroup core-ipv4
 *
 * @brief
 *   This module includes definitions for the IPv4 network layer.
 *
 */

/**
 * @addtogroup core-ip4-ip4
 *
 * @brief
 *   This module includes definitions for IPv4 networking used by NAT64.
 *
 * @{
 *
 */

/**
 * This class implements IPv4 header generation and parsing.
 *
 */
OT_TOOL_PACKED_BEGIN
class Header : public Clearable<Header>
{
public:
    static constexpr uint8_t kVersionIHLOffset         = 0;
    static constexpr uint8_t kTrafficClassOffset       = 1;
    static constexpr uint8_t kTotalLengthOffset        = 2;
    static constexpr uint8_t kIdenficationOffset       = 4;
    static constexpr uint8_t kFlagsFragmentOffset      = 6;
    static constexpr uint8_t kTTLOffset                = 8;
    static constexpr uint8_t kProtocolOffset           = 9;
    static constexpr uint8_t kHeaderChecksumOffset     = 10;
    static constexpr uint8_t kSourceAddressOffset      = 12;
    static constexpr uint8_t kDestinationAddressOffset = 16;

    /**
     * This method indicates whether or not the header appears to be well-formed.
     *
     * @retval TRUE    If the header appears to be well-formed.
     * @retval FALSE   If the header does not appear to be well-formed.
     *
     */
    bool IsValid(void) const;

    /**
     * This method initializes the Version to 6 and sets Traffic Class and Flow fields to zero.
     *
     * The other fields in the IPv4 header remain unchanged.
     *
     */
    void InitVersionIHL(void) { SetVersionIHL(kVersIHLInit); }

    /**
     * This method sets the version and IHL of the IPv4 header.
     *
     * @param[in] aVersionIHL The octet for the version and IHL field.
     */
    void SetVersionIHL(uint8_t aVersionIHL) { mVersIHL = aVersionIHL; }

    /**
     * This method indicates whether or not the IPv4 Version is set to 6.
     *
     * @retval TRUE   If the IPv4 Version is set to 4.
     * @retval FALSE  If the IPv4 Version is not set to 4.
     *
     */
    bool IsVersion4(void) const { return (mVersIHL & kVersionMask) == kVersion4; }

    /**
     * This method gets the 6-bit Differentiated Services Code Point (DSCP) from Traffic Class field.
     *
     * @returns The DSCP value.
     *
     */
    uint8_t GetDscp(void) const { return (mDSCP_ECN & kDscpMask) >> kDscpOffset; }

    /**
     * This method sets 6-bit Differentiated Services Code Point (DSCP) in IPv4 header.
     *
     * @param[in]  aDscp  The DSCP value.
     *
     */
    void SetDscp(uint8_t aDscp) { mDSCP_ECN = ((mDSCP_ECN & ~kDscpMask) | (aDscp << kDscpOffset)); }

    /**
     * This method gets the 2-bit Explicit Congestion Notification (ECN) from Traffic Class field.
     *
     * @returns The ECN value.
     *
     */
    Ecn GetEcn(void) const { return static_cast<Ecn>(mDSCP_ECN & kEcnMask); }

    /**
     * This method sets the 2-bit Explicit Congestion Notification (ECN) in IPv4 header..
     *
     * @param[in]  aEcn  The ECN value.
     *
     */
    void SetEcn(Ecn aEcn) { mDSCP_ECN = ((mDSCP_ECN & ~kEcnMask) | aEcn); }

    /**
     * This method returns the IPv4 Payload Length value.
     *
     * @returns The IPv4 Payload Length value.
     *
     */
    uint16_t GetTotalLength(void) const { return HostSwap16(mTotalLength); }

    /**
     * This method sets the IPv4 Payload Length value.
     *
     * @param[in]  aLength  The IPv4 Payload Length value.
     *
     */
    void SetTotalLength(uint16_t aLength) { mTotalLength = HostSwap16(aLength); }

    /**
     * This method returns the IPv4 payload protocol.
     *
     * @returns The IPv4 payload protocol value.
     *
     */
    uint8_t GetProtocol(void) const { return mProtocol; }

    /**
     * This method sets the IPv4 payload protocol.
     *
     * @param[in]  aNextHeader  The IPv4 payload protocol.
     *
     */
    void SetProtocol(uint8_t aProtocol) { mProtocol = aProtocol; }

    /**
     * This method sets the IPv4 header checksum, the checksum is in network endian.
     *
     * @param[in] aChecksum The checksum for the IPv4 header.
     */
    void SetChecksum(uint16_t aChecksum) { mHeaderChecksum = aChecksum; }

    /**
     * This method returns the IPv4 Identification value.
     *
     * @returns The IPv4 Identification value.
     */
    uint16_t GetIdentification() { return HostSwap16(mIdentification); }

    /**
     * This method sets the IPv4 Identification value.
     *
     * @param[in] The IPv4 Identification value.
     */
    void SetIdentification(uint16_t aIdentification) { mIdentification = HostSwap16(aIdentification); }

    /**
     * This method returns the IPv4 Time-to-Live value.
     *
     * @returns The IPv4 Time-to-Live value.
     *
     */
    uint8_t GetTTL(void) const { return mTTL; }

    /**
     * This method sets the IPv4 Time-to-Live value.
     *
     * @param[in]  aTTL  The IPv4 Time-to-Live value.
     *
     */
    void SetTTL(uint8_t aTTL) { mTTL = aTTL; }

    /**
     * This method returns the IPv4 Source address.
     *
     * @returns A reference to the IPv4 Source address.
     *
     */
    Address &GetSource(void) { return mSource; }

    /**
     * This method returns the IPv4 Source address.
     *
     * @returns A reference to the IPv4 Source address.
     *
     */
    const Address &GetSource(void) const { return mSource; }

    /**
     * This method sets the IPv4 Source address.
     *
     * @param[in]  aSource  A reference to the IPv4 Source address.
     *
     */
    void SetSource(const Address &aSource) { mSource = aSource; }

    /**
     * This method returns the IPv4 Destination address.
     *
     * @returns A reference to the IPv4 Destination address.
     *
     */
    Address &GetDestination(void) { return mDestination; }

    /**
     * This method returns the IPv4 Destination address.
     *
     * @returns A reference to the IPv4 Destination address.
     *
     */
    const Address &GetDestination(void) const { return mDestination; }

    /**
     * This method sets the IPv4 Destination address.
     *
     * @param[in]  aDestination  A reference to the IPv4 Destination address.
     *
     */
    void SetDestination(const Address &aDestination) { mDestination = aDestination; }

    /**
     * This method parses and validates the IPv4 header from a given message.
     *
     * The header is read from @p aMessage at offset zero.
     *
     * @param[in]  aMessage  The IPv4 message.
     *
     * @retval kErrorNone   Successfully parsed the IPv4 header from @p aMessage.
     * @retval kErrorParse  Malformed IPv4 header or message (e.g., message does not contained expected payload length).
     *
     */
    Error ParseFrom(const Message &aMessage);

    /**
     * This method returns the DF flag in the IPv4 header.
     *
     * @returns Whether don't fragment flag is set.
     */
    bool GetDF() const { return HostSwap16(mFlagsFargmentOffset) & kFlagsDF; }

    /**
     * This method returns the MF flag in the IPv4 header.
     *
     * @returns Whether more fragments flag is set.
     */
    bool GetMF() const { return HostSwap16(mFlagsFargmentOffset) & kFlagsMF; }

    /**
     * This method returns the fragment offset in the IPv4 header.
     *
     * @returns The fragment offset of the IPv4 packet.
     */
    uint16_t GetFragmentOffset() const { return HostSwap16(mFlagsFargmentOffset) & kFragmentOffsetMask; }

private:
    // IPv4 header
    //
    // +---------------+---------------+---------------+---------------+
    // |7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |Version|  IHL  |    DSCP   |ECN|         Total Length          |
    // |        Identification         |Flags|    Fragment Offset      |
    // |      TTL      |    Protocol   |        Header Checksum        |
    // |                       Source IP Address                       |
    // |                         Dest IP Address                       |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    static constexpr uint8_t  kVersion4           = 0x40;   // Use with `mVersIHL`
    static constexpr uint8_t  kVersionMask        = 0xf0;   // Use with `mVersIHL`
    static constexpr uint8_t  kIHLMask            = 0x0f;   // Use with `mVersIHL`
    static constexpr uint8_t  kDscpOffset         = 2;      // Use with `mDSCP_ECN`
    static constexpr uint16_t kDscpMask           = 0xfc;   // Use with `mDSCP_ECN`
    static constexpr uint8_t  kEcnOffset          = 0;      // Use with `mDSCP_ECN`
    static constexpr uint8_t  kEcnMask            = 0x03;   // Use with `mDSCP_ECN`
    static constexpr uint16_t kFlagsMask          = 0xe000; // Use with `mFlagsFragmentOffset`
    static constexpr uint16_t kFlagsDF            = 0x4000; // Use with `mFlagsFragmentOffset`
    static constexpr uint16_t kFlagsMF            = 0x2000; // Use with `mFlagsFragmentOffset`
    static constexpr uint16_t kFragmentOffsetMask = 0x1fff; // Use with `mFlagsFragmentOffset`
    static constexpr uint32_t kVersIHLInit        = 0x45;   // Version 4, Header length = 5x8 bytes.

    uint8_t  mVersIHL;
    uint8_t  mDSCP_ECN;
    uint16_t mTotalLength;
    uint16_t mIdentification;
    uint16_t mFlagsFargmentOffset;
    uint8_t  mTTL;
    uint8_t  mProtocol;
    uint16_t mHeaderChecksum;
    Address  mSource;
    Address  mDestination;
} OT_TOOL_PACKED_END;

// ICMP(in v4) messages will only be generated / handled by NAT64. So only header defination is required.
class Icmp
{
public:
    OT_TOOL_PACKED_BEGIN
    class Header : public Clearable<Header>
    {
    public:
        static constexpr uint16_t kChecksumFieldOffset = 2;
        // A few ICMP types, only the ICMP types work with NAT64 are listed here.
        enum Type : uint8_t
        {
            kTypeEchoReply              = 0,
            kTypeDestinationUnreachable = 1,
            kTypeEchoRequest            = 8,
            kTypeTimeExceeded           = 11,
        };

        enum Code : uint8_t
        {
            kCodeNone = 0,
            // Destination Unreachable codes
            kCodeNetworkUnreachable  = 0,
            kCodeHostUnreachable     = 1,
            kCodeProtocolUnreachable = 2,
            kCodePortUnreachable     = 3,
            kCodeSourceRouteFailed   = 5,
            kCodeNetworkUnknown      = 6,
            kCodeHostUnknown         = 7,
        };

        Type GetType() { return static_cast<Type>(mType); }
        Code GetCode() { return static_cast<Code>(mCode); }

        void SetType(Type aType) { mType = static_cast<uint8_t>(aType); }
        void SetCode(Code aCode) { mCode = static_cast<uint8_t>(aCode); }

        uint8_t *RestOfHeader() { return mRestOfHeader; }
        void     SetRestOfHeader(uint8_t *restOfheader) { memcpy(mRestOfHeader, restOfheader, sizeof(mRestOfHeader)); }

    private:
        uint8_t  mType;
        uint8_t  mCode;
        uint16_t mChecksum;
        uint8_t  mRestOfHeader[4];
    } OT_TOOL_PACKED_END;
};

/**
 * @}
 *
 */

} // namespace Ip4
} // namespace ot

#endif // IP4_HEADERS_HPP_
