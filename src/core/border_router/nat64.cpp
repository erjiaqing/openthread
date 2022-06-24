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
 *   This file includes implementation for NAT64.
 *
 */

#include "nat64.hpp"

#if OPENTHREAD_CONFIG_BORDER_ROUTING_ENABLE && OPENTHREAD_CONFIG_BORDER_ROUTING_NAT64_ENABLE

#include <openthread/border_router.h>
#include <openthread/logging.h>

#include "common/as_core_type.hpp"
#include "common/code_utils.hpp"
#include "common/locator_getters.hpp"
#include "common/timer.hpp"

#include "border_router/routing_manager.hpp"
#include "net/checksum.hpp"
#include "net/ip4_headers.hpp"
#include "net/ip4_types.hpp"
#include "net/ip6.hpp"

#include <string.h>

#include <type_traits>
#include <utility>

namespace ot {
namespace BorderRouter {

RegisterLogModule("Nat64");

Nat64::Nat64(void)
{
    mAvailableAddressCount = 0;

    mNat64Prefix.Clear();
    mIP4Cidr.Clear();
}

Nat64::Result Nat64::HandleOutgoing(Message &aMessage)
{
    Result                nat64TranslationResult = Result::kDrop;
    Ip6::Header           ip6Header;
    Ip4::Header           ip4Header;
    const AddressMapping *mapping = nullptr;

    if (aMessage.GetLength() < sizeof(Ip6::Header))
    {
        LogWarn("outgoing packet is smaller than a IPv6 header, drop");
        ExitNow(nat64TranslationResult = Result::kDrop);
    }

    ip6Header.ParseFrom(aMessage);

    if (!ip6Header.IsVersion6())
    {
        LogWarn("outgoing packet is not an IPv6 packet, drop");
        ExitNow(nat64TranslationResult = Result::kDrop);
    }

    if (!mNat64Prefix.IsValidNat64())
    {
        ExitNow(nat64TranslationResult = Result::kForward);
    }

    if (ip6Header.GetHopLimit() <= 1)
    {
        LogWarn("outgoing packet hop limit reached");
        ExitNow(nat64TranslationResult = Result::kDrop);
    }

    if (!ip6Header.GetDestination().MatchesPrefix(mNat64Prefix))
    {
        // Target is not in NAT64 network, handle it as usual.
        ExitNow(nat64TranslationResult = Result::kForward);
    }

    mapping = GetMapping(ip6Header.GetSource(), /* aTryCreate */ true);
    if (mapping == nullptr)
    {
        LogWarn("address mapping table is full");
        ExitNow(nat64TranslationResult = Result::kDrop);
    }

    aMessage.RemoveHeader(sizeof(Ip6::Header));

    ip4Header.Clear();
    ip4Header.InitVersionIhl();
    ip4Header.GetSource().SetBytes(mapping->mIP4.GetBytes());
    ip4Header.GetDestination().SynthesizeFromIp6Address(mNat64Prefix.mLength, ip6Header.GetDestination());
    ip4Header.SetIdentification(0);

    switch (ip6Header.GetNextHeader())
    {
    case Ip6::kProtoUdp:
        ip4Header.SetProtocol(Ip4::kProtoUdp);
        nat64TranslationResult = Result::kForward;
        break;
    case Ip6::kProtoTcp:
        ip4Header.SetProtocol(Ip4::kProtoTcp);
        nat64TranslationResult = Result::kForward;
        break;
    case Ip6::kProtoIcmp6:
        ip4Header.SetProtocol(Ip4::kProtoIcmp);
        nat64TranslationResult = TranslateIcmp6(mapping, aMessage);
        break;
    default:
        ExitNow(nat64TranslationResult = Result::kDrop);
    }

    switch (nat64TranslationResult)
    {
    case Result::kDrop:
        break;
    case Result::kReplyICMP:
        break;
    case Result::kForward:
        ip4Header.SetTotalLength(sizeof(Ip4::Header) + aMessage.GetLength() - aMessage.GetOffset());
        ip4Header.SetTtl(ip6Header.GetHopLimit() - 1);
        Checksum::UpdateMessageChecksum(aMessage, ip4Header.GetSource(), ip4Header.GetDestination(),
                                        ip4Header.GetProtocol());
        Checksum::UpdateIPv4HeaderChecksum(ip4Header);
        aMessage.PrependBytes(&ip4Header, sizeof(ip4Header));
        break;
    }

exit:
    return nat64TranslationResult;
}

Nat64::Result Nat64::HandleIncoming(Message &aMessage)
{
    Result                nat64TranslationResult = Result::kDrop;
    Ip6::Header           ip6Header;
    Ip4::Header           ip4Header;
    const AddressMapping *mapping = nullptr;

    if (aMessage.GetLength() >= sizeof(Ip6::Header))
    {
        ip6Header.ParseFrom(aMessage);
        if (ip6Header.IsVersion6())
        {
            ExitNow(nat64TranslationResult = Result::kForward);
        }
    }

    ip4Header.ParseFrom(aMessage);
    if (!ip4Header.IsVersion4())
    {
        LogWarn("incoming message is neither IPv4 nor an IPv6 packet, drop");
        ExitNow(nat64TranslationResult = Result::kDrop);
    }

    if (mNat64Prefix.mLength == 0)
    {
        LogWarn("incoming message is an IPv4 packet but NAT64 is not enabled, drop");
        ExitNow(nat64TranslationResult = Result::kDrop);
    }

    if (ip4Header.GetTtl() <= 1)
    {
        LogWarn("incoming packet TTL reached");
        ExitNow(nat64TranslationResult = Result::kDrop);
    }

    mapping = GetMapping(ip4Header.GetDestination());
    if (mapping == nullptr)
    {
        LogWarn("no mapping found for the IPv4 address");
        ExitNow(nat64TranslationResult = Result::kDrop);
    }

    aMessage.RemoveHeader(sizeof(Ip4::Header));

    ip6Header.Clear();
    ip6Header.InitVersionTrafficClassFlow();
    ip6Header.GetSource().SynthesizeFromIp4Address(mNat64Prefix, ip4Header.GetSource());
    ip6Header.SetDestination(mapping->mIP6);
    ip6Header.SetFlow(0);
    ip6Header.SetHopLimit(ip4Header.GetTtl() - 1);

    switch (ip4Header.GetProtocol())
    {
    case Ip4::kProtoUdp:
        ip6Header.SetNextHeader(Ip6::kProtoUdp);
        nat64TranslationResult = Result::kForward;
        break;
    case Ip4::kProtoTcp:
        ip6Header.SetNextHeader(Ip6::kProtoTcp);
        nat64TranslationResult = Result::kForward;
        break;
    case Ip4::kProtoIcmp:
        ip6Header.SetNextHeader(Ip6::kProtoIcmp6);
        nat64TranslationResult = TranslateIcmp4(mapping, aMessage);
        break;
    default:
        ExitNow(nat64TranslationResult = Result::kDrop);
    }

    switch (nat64TranslationResult)
    {
    case Result::kDrop:
        break;
    case Result::kReplyICMP:
        break;
    case Result::kForward:
        ip6Header.SetPayloadLength(aMessage.GetLength() - aMessage.GetOffset());
        Checksum::UpdateMessageChecksum(aMessage, ip6Header.GetSource(), ip6Header.GetDestination(),
                                        ip6Header.GetNextHeader());
        if (aMessage.Prepend(ip6Header) != kErrorNone)
        {
            ExitNow(nat64TranslationResult = Result::kDrop);
        }
        break;
    }

exit:
    return nat64TranslationResult;
}

void Nat64::ReleaseMapping(AddressMapping &aMapping)
{
    LogInfo("mapping removed: %s -> %s", aMapping.mIP6.ToString().AsCString(), aMapping.mIP4.ToString().AsCString());
    mIp4AddressPool[mAvailableAddressCount] = aMapping.mIP4;
    mAvailableAddressCount++;
    mAddressMappingPool.Free(aMapping);
}

const Nat64::AddressMapping *Nat64::CreateMapping(const Ip6::Address &aAddr)
{
    AddressMapping *mapping = mAddressMappingPool.Allocate();

    if (mapping == nullptr)
    {
        TimeMilli                  now = TimerMilli::GetNow();
        LinkedList<AddressMapping> idleMappings;

        mActiveAddressMappings.RemoveAllMatching(now, idleMappings);

        for (AddressMapping *idleMapping = idleMappings.Pop(); idleMapping != nullptr; idleMapping = idleMappings.Pop())
        {
            ReleaseMapping(*idleMapping);
        }

        mapping = mAddressMappingPool.Allocate();
    }

    if (mAvailableAddressCount == 0)
    {
        if (mapping != nullptr)
        {
            mAddressMappingPool.Free(*mapping);
            mapping = nullptr;
        }
        ExitNow();
    }

    VerifyOrExit(mapping != nullptr);

    mapping->mIP6 = aAddr;
    mAvailableAddressCount--;
    mapping->mIP4 = mIp4AddressPool[mAvailableAddressCount];
    mapping->Touch();
    mActiveAddressMappings.Push(*mapping);
    LogInfo("mapping created: %s -> %s", mapping->mIP6.ToString().AsCString(), mapping->mIP4.ToString().AsCString());

exit:
    return mapping;
}

const Nat64::AddressMapping *Nat64::GetMapping(const Ip6::Address &aAddr, bool aTryCreate)
{
    const AddressMapping *mapping = mActiveAddressMappings.FindMatching(aAddr);

    // Exit if we found a valid mapping.
    VerifyOrExit(mapping == nullptr);
    // If we don't have a valid mapping and we don't want to create one.
    VerifyOrExit(aTryCreate);

    mapping = CreateMapping(aAddr);
exit:
    return mapping;
}

const Nat64::AddressMapping *Nat64::GetMapping(const Ip4::Address &aAddr)
{
    AddressMapping *mapping = mActiveAddressMappings.FindMatching(aAddr);

    if (mapping != nullptr)
    {
        mapping->Touch();
    }
    return mapping;
}

Nat64::Result Nat64::TranslateIcmp4(const AddressMapping *, Message &aMessage)
{
    Result            icmpTranslationResult = Result::kDrop;
    Ip4::Icmp::Header icmp4Header;
    Ip6::Icmp::Header icmp6Header;

    aMessage.ReadBytes(0, &icmp4Header, sizeof(icmp4Header));
    switch (icmp4Header.GetType())
    {
    case Ip4::Icmp::Header::Type::kTypeEchoReply:
    {
        aMessage.ReadBytes(0, &icmp6Header, sizeof(icmp6Header));
        icmp6Header.SetType(Ip6::Icmp::Header::Type::kTypeEchoReply);
        aMessage.WriteBytes(0, &icmp6Header, sizeof(icmp6Header));
        ExitNow(icmpTranslationResult = Result::kForward);
    }
    default:
        break;
    }

exit:
    return icmpTranslationResult;
}

Nat64::Result Nat64::TranslateIcmp6(const AddressMapping *, Message &aMessage)
{
    Result            icmpTranslationResult = Result::kDrop;
    Ip4::Icmp::Header icmp4Header;
    Ip6::Icmp::Header icmp6Header;

    aMessage.ReadBytes(0, &icmp6Header, sizeof(icmp6Header));
    switch (icmp6Header.GetType())
    {
    case Ip6::Icmp::Header::Type::kTypeEchoRequest:
    {
        aMessage.ReadBytes(0, &icmp4Header, sizeof(icmp4Header));
        icmp4Header.SetType(Ip4::Icmp::Header::Type::kTypeEchoRequest);
        aMessage.WriteBytes(0, &icmp4Header, sizeof(icmp4Header));
        ExitNow(icmpTranslationResult = Result::kForward);
    }
    default:
        break;
    }

exit:
    return icmpTranslationResult;
}

void Nat64::SetIP4Cidr(const Ip4::Cidr &aCidr)
{
    uint32_t numberOfHosts = static_cast<uint32_t>(1 << ((Ip4::Address::kSize * 8) - aCidr.mLength));
    uint32_t hostIdBegin   = 1;
    uint32_t hostIdEnd     = numberOfHosts - 2;

    if (mIP4Cidr == aCidr)
    {
        ExitNow();
    }

    // Avoid using the 0s and 1s in the host id of an address, but what if the user provides us with /32 or /31
    // addresses?
    if (aCidr.mLength == 1)
    {
        hostIdBegin = hostIdEnd = 0;
        numberOfHosts           = 1;
    }
    else if (aCidr.mLength == 2)
    {
        hostIdBegin   = 0;
        hostIdEnd     = 1;
        numberOfHosts = 2;
    }
    else
    {
        numberOfHosts -= 2;
    }
    mAddressMappingPool.FreeAll();

    for (uint32_t i = hostIdBegin; i <= hostIdEnd && i < hostIdBegin + kAddressMappingPoolSize; i++)
    {
        mIp4AddressPool[i - hostIdBegin].SynthesizeFromCidrAndHost(aCidr, i);
    }

    if (numberOfHosts > kAddressMappingPoolSize)
    {
        numberOfHosts = kAddressMappingPoolSize;
    }

    LogInfo("Set IPv4 CIDR for NAT64: %s (%u available addresses)", aCidr.ToString().AsCString(), numberOfHosts);
    mAvailableAddressCount = numberOfHosts;
    mIP4Cidr               = aCidr;

exit:
    (void)0; // noting to do
}

void Nat64::SetNAT64Prefix(const Ip6::Prefix &aNat64Prefix)
{
    LogInfo("Set IPv6 Prefix for NAT64: %s", aNat64Prefix.ToString().AsCString());
    mNat64Prefix = aNat64Prefix;
}

extern "C" void otBorderRouterSetIpv4CidrForNat64(otInstance *aInstance, otIp4Cidr *aCidr)
{
    AsCoreType(aInstance).Get<Nat64>().SetIP4Cidr(static_cast<ot::Ip4::Cidr &>(*aCidr));
}

} // namespace BorderRouter
} // namespace ot

#endif // OPENTHREAD_CONFIG_BORDER_ROUTING_NAT64_ENABLE
