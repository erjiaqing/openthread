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
 *   This file includes definitions for the NAT64 translator.
 *
 */

#ifndef NAT64_TRANSLATOR_HPP_
#define NAT64_TRANSLATOR_HPP_

#include "openthread-core-config.h"

#if OPENTHREAD_CONFIG_NAT64_TRANSLATOR_ENABLE

#if !OPENTHREAD_CONFIG_BORDER_ROUTING_ENABLE
#error "OPENTHREAD_CONFIG_BORDER_ROUTING_ENABLE is required for OPENTHREAD_CONFIG_NAT64_TRANSLATOR_ENABLE."
#endif

#if !OPENTHREAD_CONFIG_UPTIME_ENABLE
#error "OPENTHREAD_CONFIG_UPTIME_ENABLE is required for OPENTHREAD_CONFIG_NAT64_TRANSLATOR_ENABLE."
#endif

#include "common/linked_list.hpp"
#include "common/locator.hpp"
#include "common/pool.hpp"
#include "net/ip4_types.hpp"
#include "net/ip6.hpp"

namespace ot {
namespace BorderRouter {

class Nat64Translator : public InstanceLocator, private NonCopyable
{
public:
    static constexpr uint32_t kAddressMappingIdleTimeoutMsec =
        OPENTHREAD_CONFIG_BORDER_ROUTING_NAT64_IDLE_TIMEOUT_SECONDS * Time::kOneSecondInMsec;
    static constexpr uint32_t kAddressMappingPoolSize = OPENTHREAD_CONFIG_BORDER_ROUTING_NAT64_MAX_MAPPINGS;

    enum class Result : uint8_t
    {
        kForward   = 0,
        kDrop      = 1,
        kReplyIcmp = 2,
    };

    /**
     * This constructor initializes the nat64.
     *
     */
    explicit Nat64Translator(Instance &aInstance);

    /**
     * @brief Translates an IPv4 packet to IPv6 packet. Note the packet and packetLength might be adjusted. Note the
     * caller should reserve at least 20 bytes before the packetHead.
     * If the message is an IPv6 packet, Result::kForward will be returned and the message won't be modified.
     *
     * @param[in,out] aMessage the message to be processed.
     *
     * @returns Result::kForward the caller should contiue forwarding the packet.
     * @returns Result::kDrop the caller should drop the packet silently.
     * @returns Result::kReplyIcmp the caller should reply an ICMP packet, the buffer will be filled with the content of
     * the ICMP packet.
     *
     */
    Result HandleIncoming(Message &message);

    /**
     * @brief Translates an IPv6 packet to IPv4 packet. Note the packet and packetLength might be adjusted. Note the
     * caller should reserve at least 20 bytes before the packetHead.
     * If the message is not targeted to NAT64-mapped address, Result::kForward will be returned and the message won't
     * be modified.
     *
     * @param[in,out] aMessage the message to be processed.
     *
     * @returns Result::kForward the caller should contiue forwarding the packet.
     * @returns Result::kDrop the caller should drop the packet silently.
     * @returns Result::kReplyIcmp the caller should reply an ICMP packet, the buffer will be filled with the content of
     * the ICMP packet.
     *
     */
    Result HandleOutgoing(Message &aMessage);

    /**
     * @brief This function sets the CIDR used when setting the source address of the outgoing translated IPv4 packets.
     * A valid CIDR must have a non-zero prefix length.
     *
     * @note The actual addresses pool is limited by the size of the mapping pool and the number of addresses available
     * in the CIDR block. If the provided is a valid IPv4 CIDR for NAT64, and it is different from the one already
     * configured, the NAT64 translator will be reset and all existing sessions will be expired.
     *
     * @param[in] aCidr the CIDR for the sources of the translated packets.
     *
     * @retval  kErrorInvalidArgs    The the given CIDR a valid CIDR for NAT64.
     * @retval  kErrorNone           Successfully enabled/disabled the NAT64 translator.
     *
     */
    Error SetIp4Cidr(const Ip4::Cidr &aCidr);

    /**
     * @brief This function sets the prefix of NAT64-mapped addresses in the thread network. The address mapping table
     * will not be cleared.
     *
     * @param[in] aNat64Prefix the prefix of the NAT64-mapped addresses.
     *
     */
    void SetNat64Prefix(const Ip6::Prefix &aNat64Prefix);

private:
    class AddressMapping : public LinkedListEntry<AddressMapping>
    {
    public:
        friend class LinkedListEntry<AddressMapping>;
        friend class LinkedList<AddressMapping>;

        void Touch(uint64_t aNow) { mExpiry = aNow + kAddressMappingIdleTimeoutMsec; }

        Ip4::Address mIp4;
        Ip6::Address mIp6;

        // The timestamp when this mapping expires, in milliseconds.
        uint64_t mExpiry;

    private:
        bool Matches(const Ip4::Address &aIp4) const { return mIp4 == aIp4; }
        bool Matches(const Ip6::Address &aIp6) const { return mIp6 == aIp6; }
        bool Matches(const uint64_t aNow) const { return mExpiry < aNow; }

        AddressMapping *mNext;
    };

    Error TranslateIcmp4(AddressMapping &aMapping, Message &aMessage);

    Error TranslateIcmp6(AddressMapping &aMapping, Message &aMessage);

    void ReleaseMapping(AddressMapping &aMapping);

    AddressMapping *CreateMapping(const Ip6::Address &aAddr);

    AddressMapping *GetMapping(const Ip6::Address &aAddr, bool aTryCreate);

    AddressMapping *GetMapping(const Ip4::Address &aAddr);

    uint32_t     mAvailableAddressCount;
    Ip4::Address mIp4AddressPool[kAddressMappingPoolSize];

    Pool<AddressMapping, kAddressMappingPoolSize> mAddressMappingPool;
    LinkedList<AddressMapping>                    mActiveAddressMappings;

    Ip6::Prefix mNat64Prefix;
    Ip4::Cidr   mIp4Cidr;
};

} // namespace BorderRouter
} // namespace ot

#endif // OPENTHREAD_CONFIG_NAT64_TRANSLATOR_ENABLE

#endif // NAT64_TRANSLATOR_HPP_
