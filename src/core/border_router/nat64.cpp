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

#if OPENTHREAD_CONFIG_BORDER_ROUTING_NAT64_MANAGER_ENABLE

#include <openthread/border_router.h>
#include <openthread/logging.h>

#include "common/as_core_type.hpp"
#include "common/code_utils.hpp"
#include "common/locator_getters.hpp"

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

Nat64::Nat64(Instance &aInstance)
    : InstanceLocator(aInstance)
{
    mAvailableAddressCount = 0;
    mEnabled               = false;

    mNat64Prefix.Clear();
    mIp4Cidr.Clear();
}

Nat64::Result Nat64::HandleOutgoing(Message &aMessage)
{
    Result                res = Result::kDrop;
    Ip6::Header           ip6Header;
    Ip4::Header           ip4Header;
    const AddressMapping *mapping = nullptr;

    VerifyOrExit(mEnabled, res = Result::kForward);

    if (aMessage.GetLength() < sizeof(Ip6::Header))
    {
        LogWarn("outgoing packet is smaller than a IPv6 header, drop");
        ExitNow(res = Result::kDrop);
    }

    ip6Header.ParseFrom(aMessage);

    if (!ip6Header.IsVersion6())
    {
        LogWarn("outgoing packet is not an IPv6 packet, drop");
        ExitNow(res = Result::kDrop);
    }

    if (!mNat64Prefix.IsValidNat64() || !ip6Header.GetDestination().MatchesPrefix(mNat64Prefix))
    {
        ExitNow(res = Result::kForward);
    }

    if (mIp4Cidr.mLength == 0)
    {
        // The NAT64 translation is bypassed (will be handled externally)
        LogDebg("no IPv4 CIDR for nat64 is set, deliver the packet to externel NAT64 provider");
        ExitNow(res = Result::kForward);
    }

    if (ip6Header.GetHopLimit() <= 1)
    {
        LogInfo("outgoing packet hop limit reached, drop");
        ExitNow(res = Result::kDrop);
    }
    ip6Header.SetHopLimit(ip6Header.GetHopLimit() - 1);

    mapping = GetMapping(ip6Header.GetSource(), /* aTryCreate */ true);
    if (mapping == nullptr)
    {
        LogWarn("failed to get a mapping for %s (mapping pool full?)", ip6Header.GetSource().ToString().AsCString());
        ExitNow(res = Result::kDrop);
    }

    aMessage.RemoveHeader(sizeof(Ip6::Header));

    ip4Header.Clear();
    ip4Header.InitVersionIhl();
    ip4Header.GetSource().SetBytes(mapping->mIp4.GetBytes());
    ip4Header.GetDestination().ExtractFromIp6Address(mNat64Prefix.mLength, ip6Header.GetDestination());
    ip4Header.SetTtl(ip6Header.GetHopLimit());
    ip4Header.SetIdentification(0);

    switch (ip6Header.GetNextHeader())
    {
    case Ip6::kProtoUdp:
        ip4Header.SetProtocol(Ip4::kProtoUdp);
        res = Result::kForward;
        break;
    case Ip6::kProtoTcp:
        ip4Header.SetProtocol(Ip4::kProtoTcp);
        res = Result::kForward;
        break;
    case Ip6::kProtoIcmp6:
        ip4Header.SetProtocol(Ip4::kProtoIcmp);
        SuccessOrExit(TranslateIcmp6(*mapping, aMessage));
        res = Result::kForward;
        break;
    default:
        ExitNow(res = Result::kDrop);
    }

    switch (res)
    {
    case Result::kDrop:
        break;
    case Result::kReplyICMP:
        break;
    case Result::kForward:
        ip4Header.SetTotalLength(sizeof(Ip4::Header) + aMessage.GetLength() - aMessage.GetOffset());
        Checksum::UpdateMessageChecksum(aMessage, ip4Header.GetSource(), ip4Header.GetDestination(),
                                        ip4Header.GetProtocol());
        Checksum::UpdateIPv4HeaderChecksum(ip4Header);
        aMessage.PrependBytes(&ip4Header, sizeof(ip4Header));
        break;
    }

exit:
    return res;
}

Nat64::Result Nat64::HandleIncoming(Message &aMessage)
{
    Result                res = Result::kDrop;
    Ip6::Header           ip6Header;
    Ip4::Header           ip4Header;
    const AddressMapping *mapping = nullptr;

    VerifyOrExit(mEnabled, res = Result::kForward);

    if (aMessage.GetLength() >= sizeof(Ip6::Header))
    {
        ip6Header.ParseFrom(aMessage);
        if (ip6Header.IsVersion6())
        {
            ExitNow(res = Result::kForward);
        }
    }

    ip4Header.ParseFrom(aMessage);
    if (!ip4Header.IsVersion4())
    {
        LogWarn("incoming message is neither IPv4 nor an IPv6 packet, drop");
        ExitNow(res = Result::kDrop);
    }

    if (mNat64Prefix.mLength == 0)
    {
        LogWarn("incoming message is an IPv4 packet but NAT64 is not enabled, drop");
        ExitNow(res = Result::kDrop);
    }

    if (ip4Header.GetTtl() <= 1)
    {
        LogInfo("incoming packet TTL reached");
        ExitNow(res = Result::kDrop);
    }
    ip4Header.SetTtl(ip4Header.GetTtl() - 1);

    mapping = GetMapping(ip4Header.GetDestination());
    if (mapping == nullptr)
    {
        LogWarn("no mapping found for the IPv4 address");
        ExitNow(res = Result::kDrop);
    }

    aMessage.RemoveHeader(sizeof(Ip4::Header));

    ip6Header.Clear();
    ip6Header.InitVersionTrafficClassFlow();
    ip6Header.GetSource().SynthesizeFromIp4Address(mNat64Prefix, ip4Header.GetSource());
    ip6Header.SetDestination(mapping->mIp6);
    ip6Header.SetFlow(0);
    ip6Header.SetHopLimit(ip4Header.GetTtl());

    switch (ip4Header.GetProtocol())
    {
    case Ip4::kProtoUdp:
        ip6Header.SetNextHeader(Ip6::kProtoUdp);
        res = Result::kForward;
        break;
    case Ip4::kProtoTcp:
        ip6Header.SetNextHeader(Ip6::kProtoTcp);
        res = Result::kForward;
        break;
    case Ip4::kProtoIcmp:
        ip6Header.SetNextHeader(Ip6::kProtoIcmp6);
        SuccessOrExit(TranslateIcmp4(*mapping, aMessage));
        res = Result::kForward;
        break;
    default:
        ExitNow(res = Result::kDrop);
    }

    switch (res)
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
            ExitNow(res = Result::kDrop);
        }
        break;
    }

exit:
    return res;
}

void Nat64::ReleaseMapping(AddressMapping &aMapping)
{
    LogInfo("mapping removed: %s -> %s", aMapping.mIp6.ToString().AsCString(), aMapping.mIp4.ToString().AsCString());
    mIp4AddressPool[mAvailableAddressCount] = aMapping.mIp4;
    mAvailableAddressCount++;
    mAddressMappingPool.Free(aMapping);
}

const Nat64::AddressMapping *Nat64::CreateMapping(const Ip6::Address &aAddr)
{
    AddressMapping *mapping = mAddressMappingPool.Allocate();

    if (mapping == nullptr)
    {
        uint64_t                   now = Get<Uptime>().GetUptime();
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

    mapping->mIp6 = aAddr;
    mAvailableAddressCount--;
    mapping->mIp4 = mIp4AddressPool[mAvailableAddressCount];
    mapping->Touch(Get<Uptime>().GetUptime());
    mActiveAddressMappings.Push(*mapping);
    LogInfo("mapping created: %s -> %s", mapping->mIp6.ToString().AsCString(), mapping->mIp4.ToString().AsCString());

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
        mapping->Touch(Get<Uptime>().GetUptime());
    }
    return mapping;
}

Error Nat64::TranslateIcmp4(const AddressMapping &, Message &aMessage)
{
    Error             err = kErrorNone;
    Ip4::Icmp::Header icmp4Header;
    Ip6::Icmp::Header icmp6Header;

    VerifyOrExit(aMessage.ReadBytes(0, &icmp4Header, sizeof(icmp4Header)) == sizeof(icmp4Header), err = kErrorParse);
    switch (icmp4Header.GetType())
    {
    case Ip4::Icmp::Header::Type::kTypeEchoReply:
    {
        VerifyOrExit(aMessage.ReadBytes(0, &icmp6Header, sizeof(icmp6Header)) == sizeof(icmp6Header),
                     err = kErrorParse);
        icmp6Header.SetType(Ip6::Icmp::Header::Type::kTypeEchoReply);
        aMessage.WriteBytes(0, &icmp6Header, sizeof(icmp6Header));
        break;
    }
    default:
        err = kErrorInvalidArgs;
        break;
    }

exit:
    return err;
}

Error Nat64::TranslateIcmp6(const AddressMapping &, Message &aMessage)
{
    Error             err = kErrorNone;
    Ip4::Icmp::Header icmp4Header;
    Ip6::Icmp::Header icmp6Header;

    VerifyOrExit(aMessage.ReadBytes(0, &icmp6Header, sizeof(icmp6Header)) == sizeof(icmp6Header), err = kErrorParse);
    switch (icmp6Header.GetType())
    {
    case Ip6::Icmp::Header::Type::kTypeEchoRequest:
    {
        VerifyOrExit(aMessage.ReadBytes(0, &icmp4Header, sizeof(icmp4Header)) == sizeof(icmp4Header),
                     err = kErrorParse);
        icmp4Header.SetType(Ip4::Icmp::Header::Type::kTypeEchoRequest);
        aMessage.WriteBytes(0, &icmp4Header, sizeof(icmp4Header));
        break;
    }
    default:
        err = kErrorInvalidArgs;
        break;
    }

exit:
    return err;
}

Error Nat64::SetIp4Cidr(const Ip4::Cidr &aCidr)
{
    Error err = kErrorNone;

    uint32_t numberOfHosts;
    uint32_t hostIdBegin;

    VerifyOrExit(aCidr.mLength > 0 && aCidr.mLength <= 32, err = kErrorInvalidArgs);

    VerifyOrExit(mIp4Cidr != aCidr);

    // Avoid using the 0s and 1s in the host id of an address, but what if the user provides us with /32 or /31
    // addresses?
    if (aCidr.mLength == 0)
    {
        numberOfHosts = 0;
        hostIdBegin   = 0;
    }
    else if (aCidr.mLength == 32)
    {
        hostIdBegin   = 0;
        numberOfHosts = 1;
    }
    else if (aCidr.mLength == 31)
    {
        hostIdBegin   = 0;
        numberOfHosts = 2;
    }
    else
    {
        hostIdBegin   = 1;
        numberOfHosts = static_cast<uint32_t>((1 << (Ip4::Address::kSize * 8 - aCidr.mLength)) - 2);
    }
    numberOfHosts = OT_MIN(numberOfHosts, kAddressMappingPoolSize);

    mAddressMappingPool.FreeAll();

    for (uint32_t i = 0; i < numberOfHosts; i++)
    {
        mIp4AddressPool[i].SynthesizeFromCidrAndHost(aCidr, i + hostIdBegin);
    }

    LogInfo("IPv4 CIDR for NAT64: %s (actual address pool: %s - %s, %u addresses)", aCidr.ToString().AsCString(),
            mIp4AddressPool[0].ToString().AsCString(), mIp4AddressPool[numberOfHosts - 1].ToString().AsCString(),
            numberOfHosts);
    mAvailableAddressCount = numberOfHosts;
    mIp4Cidr               = aCidr;

exit:
    return err;
}

void Nat64::SetNat64Prefix(const Ip6::Prefix &aNat64Prefix)
{
    LogInfo("Set IPv6 Prefix for NAT64: %s", aNat64Prefix.ToString().AsCString());
    mNat64Prefix = aNat64Prefix;
}

Error Nat64::SetEnabled(bool aEnabled)
{
    Error err = kErrorNone;

    if (aEnabled)
    {
        VerifyOrExit(mIp4Cidr.mLength > 0 && mIp4Cidr.mLength <= 32, err = kErrorInvalidState);
    }

    mEnabled = aEnabled;

exit:
    return err;
}

} // namespace BorderRouter
} // namespace ot

#endif // OPENTHREAD_CONFIG_BORDER_ROUTING_NAT64_MANAGER_ENABLE
