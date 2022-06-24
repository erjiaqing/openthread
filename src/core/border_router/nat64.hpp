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
 *   This file includes definitions for NAT64
 *
 */

#ifndef NAT64_HPP_
#define NAT64_HPP_

#include "openthread-core-config.h"

#if OPENTHREAD_CONFIG_BORDER_ROUTING_NAT64_MANAGER_ENABLE

#include "common/linked_list.hpp"
#include "common/locator.hpp"
#include "common/pool.hpp"
#include "common/time.hpp"
#include "net/ip4_address.hpp"
#include "net/ip4_headers.hpp"
#include "net/ip6.hpp"

#include <stdio.h>
#include <stdlib.h>

namespace ot {
namespace BorderRouter {

class Nat64 : public InstanceLocator, private NonCopyable
{
public:
    static constexpr size_t   kIPv6HeaderSize      = 40;
    static constexpr size_t   kIPv4FixedHeaderSize = 20;
    static constexpr uint32_t kAddressMappingIdleTimeoutMsec =
        OPENTHREAD_CONFIG_BORDER_ROUTING_NAT64_IDLE_TIMEOUT_SECONDS * Time::kOneSecondInMsec;
    static constexpr uint32_t kAddressMappingPoolSize = OPENTHREAD_CONFIG_BORDER_ROUTING_NAT64_MAX_MAPPINGS;

    enum class Result : uint8_t
    {
        kForward   = 0,
        kDrop      = 1,
        kReplyICMP = 2,
    };

    // The protocol numbers matches IP protocol numbers
    enum class Protocol : uint8_t
    {
        kICMP  = 0x1,
        kTCP   = 0x6,
        kUDP   = 0x11,
        kICMP6 = 0x58,
    };

    /**
     * This constructor initializes the nat64.
     *
     */
    explicit Nat64(Instance &aInstance);

    /**
     *
     * @brief Translates an IPv4 packet to IPv6 packet. Note the packet and packetLength might be adjusted. Note the
     * caller should reserve at least 20 bytes before the packetHead.
     * If the message is an IPv6 packet, Result::kForward will be returned and the message won't be modified.
     *     *
     * @param[in,out] aMessage the message to be processed.
     *
     * @returns Result::kForward the caller should contiue forwarding the packet.
     * @returns Result::kDrop the caller should drop the packet silently.
     * @returns Result::kReplyICMP the caller should reply an ICMP packet, the buffer will be filled with the content of
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
     * @returns Result::kReplyICMP the caller should reply an ICMP packet, the buffer will be filled with the content of
     * the ICMP packet.
     *
     */
    Result HandleOutgoing(Message &aMessage);

    /**
     * @brief This function sets the CIDR used when setting the source address of the outgoing translated IPv4 packets.
     * A valid CIDR must have a non-zero prefix length.
     *
     * @note The actual addresses used in the CIDR is limited by the size of mapping pool. If the provided is a valid
     * IPv4 CIDR for NAT64, and it is different with the one already configured, the NAT64 translator will be reset and
     * all existing sessions will be expired.
     *
     * @param[in] aCidr the CIDR for the sources of the translated packets.
     *
     * @retval  kErrorInvalidArgs    The the given CIDR a valid CIDR for NAT64.
     * @retval  kErrorNone           Successfully enabled/disabled the NAT64 translator.
     *
     */
    Error SetIp4Cidr(const Ip4::Cidr &aCidr);

    /**
     * @brief This function sets the prefix of NAT64-mapped addresses in the thread network.
     *
     * @param[in] aNat64Prefix the prefix of the NAT64-mapped addresses.
     *
     */
    void SetNat64Prefix(const Ip6::Prefix &aNat64Prefix);

    /**
     * This method enables/disables the NAT64 translator.
     *
     * @note  The NAT64 translator is disabled by default. If the NAT64 translator is disabled, all packets will
     * forwarded and no NAT64 related checks will be made. The NAT64 translator must be configured with a valid IPv4
     * CIDR before being enabedl.
     *
     * @param[in]  aEnabled   A boolean to enable/disable the NAT64 translator.
     *
     * @retval  kErrorInvalidState   The NAT64 translator is not configured with a valid IPv4 CIDR.
     * @retval  kErrorNone           Successfully enabled/disabled the NAT64 translator.
     *
     */
    Error SetEnabled(bool aEnabled);

private:
    class AddressMapping : public LinkedListEntry<AddressMapping>
    {
    public:
        friend class LinkedListEntry<AddressMapping>;
        friend class LinkedList<AddressMapping>;

        Ip4::Address mIp4;
        Ip6::Address mIp6;
        uint64_t     mExpiry;

        void Touch(uint64_t aNow) { mExpiry = aNow + kAddressMappingIdleTimeoutMsec; }

    private:
        bool Matches(const Ip4::Address &aIp4) const { return mIp4 == aIp4; }
        bool Matches(const Ip6::Address &aIp6) const { return mIp6 == aIp6; }
        bool Matches(const uint64_t aNow) const { return mExpiry < aNow; }

        AddressMapping *mNext;
    };

    /**
     * @brief Translates an ICMPv4 error message into a corresponding ICMPv6 error message. It will rebuild a new
     * message.
     *
     * @param[in] aMapping the address mapping for translating the IP header in the ICMP message.
     * @param[in,out] aMessage the message containing the ICMPv4 packet to be translated, and the translated ICMPv6
     * packet.
     *
     * @returns kErrorNone the packet is translated successfully.
     * @returns kErrorInvalidArgs the message is not supported. The original packet should be dropped silently.
     *
     */
    Error TranslateIcmp4(const AddressMapping &aMapping, Message &aMessage);

    /**
     * @brief Translates an ICMPv6 error message into a corresponding ICMPv4 error message. It will rebuild a new
     * message.
     *
     * @param[in] aMapping the address mapping for translating the IPv6 header in the ICMP6 message.
     * @param[in,out] aMessage the message containing the ICMPv6 packet to be translated, and the translated ICMPv4
     * packet.
     *
     * @returns kErrorNone the packet is translated successfully.
     * @returns kErrorInvalidArgs the message is not supported. The original packet should be dropped silently.
     *
     */
    Error TranslateIcmp6(const AddressMapping &aMapping, Message &aMessage);

    /**
     * @brief This function will release the given mapping including the allocated IPv4 address.
     *
     * @param[in] aMapping the mapping item.
     *
     */
    void ReleaseMapping(AddressMapping &aMapping);

    /**
     * @brief This function will create a mapping for the specified IPv6 address.
     *
     * @param[in] aAddr the unmapped IPv6 address;
     *
     * @returns A pointer to the address mapping found, or `nullptr` if no available mappings and address pool is
     * exhausted.
     *
     */
    const AddressMapping *CreateMapping(const Ip6::Address &aAddr);

    /**
     * @brief This function will look up for an address mapping, or try to create a new mapping if aTryCreate is set and
     * no existing mapping is found.
     *
     * @param[in] aAddr the source address of the IPv6 packet.
     * @param[in] aTryCreate whether try to create a new mapping if no existing mapping is found.
     *
     * @returns A pointer to the address mapping found, or `nullptr` if no such mapping is found (and failed to create a
     * new mapping is aTryCreate is set).
     *
     */
    const AddressMapping *GetMapping(const Ip6::Address &aAddr, bool aTryCreate);

    /**
     * @brief This function will look up for an existing mapping with the giving IPv4 address as the source address of
     * the outgoing packet.
     *
     * @returns A pointer to the address mapping found, or `nullptr` if no such mapping is found.
     *
     */
    const AddressMapping *GetMapping(const Ip4::Address &aAddr);

    uint32_t     mAvailableAddressCount;
    Ip4::Address mIp4AddressPool[kAddressMappingPoolSize];

    Pool<AddressMapping, kAddressMappingPoolSize> mAddressMappingPool;
    LinkedList<AddressMapping>                    mActiveAddressMappings;

    Ip6::Prefix mNat64Prefix;
    Ip4::Cidr   mIp4Cidr;
    bool        mEnabled;
};

} // namespace BorderRouter
} // namespace ot

#endif // OPENTHREAD_CONFIG_BORDER_ROUTING_NAT64_MANAGER_ENABLE

#endif // NAT64_HPP_
