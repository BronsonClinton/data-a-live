/*
 * Built-in AppleKeyStore for SWEET: a device without a passcode whose
 * system keybag is always loaded and unlocked.
 *
 * Apple's AppleKeyStore kext (closed, SEP-backed) owns the keybags behind
 * data protection. libaks (AppleKeyStore.framework, statically in keybagd)
 * opens IOServiceMatching("AppleKeyStore") with type 0, calls selector 0,
 * then one selector per aks_* function (iOS 16.7 numbering below). keybagd
 * --init asks for the system bag (14) and only loads systembag.kb when the
 * answer is kIOReturnNotFound; answering with a handle is the path a
 * userspace reboot takes, so no bag file is needed.
 *
 * Every call is logged (selector, caller, argument shapes, result) so the
 * next selectors the system needs show up on the console; unknown ones fail
 * with kIOReturnUnsupported.
 */
#include <pexpert/arm64/board_config.h>

#if defined(SWEET)
#include <IOKit/IOService.h>
#include <IOKit/IOUserClient.h>
#include <IOKit/IOKitKeys.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <libkern/c++/OSString.h>
#include <sys/proc.h>
#include <pexpert/pexpert.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <libkern/c++/OSData.h>

// SPDX-License-Identifier for the following imported helpers: BSD-2-Clause-Patent
// UniXNU/AppleKeyStoreState commit6ff4f11d8fdf853351f8d98e1bbe1373fb8da2e6.
// Software wrapping for this iOS fixture; no SEP/hardware data protection.

// New software wrapping is opt-in; original state-only behavior is unchanged.
static bool pandora_aks_enabled(void) {
    unsigned value=0;
    return PE_parse_boot_argn("pandora_aks",&value,sizeof(value)) && value==1;
}
static size_t pandora_aks_identity(uint8_t *out,size_t capacity) {
    IORegistryEntry *chosen=IORegistryEntry::fromPath("/chosen",gIODTPlane);
    OSData *id=chosen?OSDynamicCast(OSData,chosen->getProperty("unique-chip-id")):NULL;
    size_t n=0;
    if(id && id->getLength()>=8 && id->getLength()<=capacity){
        const uint8_t *p=(const uint8_t *)id->getBytesNoCopy();bool nonzero=false;
        for(unsigned i=0;i<id->getLength();++i){out[i]=p[i];nonzero|=p[i]!=0;}
        if(nonzero)n=id->getLength();
    }
    if(chosen)chosen->release();
    return n;
}

namespace pandora_aks {
constexpr uint32_t kSelLockState = 7, kSelGetSystem = 14, kSelDeviceState = 17, kSelExtendedDeviceState = 35;
constexpr uint32_t kSelWrapKey = 10, kSelUnwrapKey = 11, kSelBagUuid = 23, kSelGeneration = 40, kSelCacheFlow = 160;
constexpr size_t kTagBytes = 8, kMaxKeyBytes = 256;
constexpr uint64_t kUnlockedSinceBoot = 4;
constexpr uint32_t kStateFlags = 4;
constexpr uint64_t kSystemHandle = 0;
constexpr IOReturn kAksError = (IOReturn)0xe00002bc;   // what libaks reports itself when the connection is missing
constexpr IOReturn kAksUnsupported = (IOReturn)0xe00002c7;

// Self-contained so wrapping does not depend on when the kernel's crypto provider registers.
class Sha256 {
    uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    uint8_t buffer[64];
    uint64_t total = 0;
    size_t fill = 0;
    static uint32_t rotate(uint32_t v, unsigned n) { return (v >> n) | (v << (32 - n)); }
    void block(const uint8_t *p) {
        static const uint32_t k[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
        uint32_t w[64];
        for (unsigned i = 0; i < 16; ++i)
            w[i] = (uint32_t)p[i * 4] << 24 | (uint32_t)p[i * 4 + 1] << 16 | (uint32_t)p[i * 4 + 2] << 8 | p[i * 4 + 3];
        for (unsigned i = 16; i < 64; ++i) {
            uint32_t s0 = rotate(w[i - 15], 7) ^ rotate(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = rotate(w[i - 2], 17) ^ rotate(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t s[8];
        for (unsigned i = 0; i < 8; ++i) s[i] = h[i];
        for (unsigned i = 0; i < 64; ++i) {
            uint32_t t1 = s[7] + (rotate(s[4], 6) ^ rotate(s[4], 11) ^ rotate(s[4], 25)) +
                          ((s[4] & s[5]) ^ (~s[4] & s[6])) + k[i] + w[i];
            uint32_t t2 = (rotate(s[0], 2) ^ rotate(s[0], 13) ^ rotate(s[0], 22)) +
                          ((s[0] & s[1]) ^ (s[0] & s[2]) ^ (s[1] & s[2]));
            for (unsigned j = 7; j > 0; --j) s[j] = s[j - 1];
            s[4] += t1;
            s[0] = t1 + t2;
        }
        for (unsigned i = 0; i < 8; ++i) h[i] += s[i];
    }
public:
    void update(const void *data, size_t n) {
        const uint8_t *p = (const uint8_t *)data;
        total += n;
        while (n) {
            if (!fill && n >= sizeof buffer) { block(p); p += sizeof buffer; n -= sizeof buffer; continue; }
            size_t take = sizeof buffer - fill < n ? sizeof buffer - fill : n;
            for (size_t i = 0; i < take; ++i) buffer[fill + i] = p[i];
            fill += take; p += take; n -= take;
            if (fill == sizeof buffer) { block(buffer); fill = 0; }
        }
    }
    void final(uint8_t out[32]) {
        uint64_t bits = total * 8;
        const uint8_t one = 0x80, zero = 0;
        update(&one, 1);
        while (fill != 56) update(&zero, 1);
        uint8_t length[8];
        for (unsigned i = 0; i < 8; ++i) length[i] = (uint8_t)(bits >> (56 - 8 * i));
        update(length, 8);
        for (unsigned i = 0; i < 8; ++i)
            for (unsigned j = 0; j < 4; ++j) out[i * 4 + j] = (uint8_t)(h[i] >> (24 - 8 * j));
    }
};

// The same identity gives the same key at every boot, or existing keychain items could not be opened again.
bool deviceKey(uint8_t key[32]) {
    static uint8_t cached[32];
    static volatile bool ready;
    if (!ready) {
        uint8_t id[32];
        size_t n = pandora_aks_identity(id, sizeof id);
        if (!n) return false;
        static const char domain[] = "UniXNU AppleKeyStore v1";
        Sha256 hash;
        hash.update(domain, sizeof domain - 1);
        hash.update(id, n);
        hash.final(cached);
        ready = true;
    }
    for (unsigned i = 0; i < 32; ++i) key[i] = cached[i];
    return true;
}
void wrapTag(const uint8_t key[32], const uint8_t *plain, size_t n, uint8_t tag[kTagBytes]) {
    uint8_t digest[32];
    const uint8_t label = 'T';
    Sha256 hash;
    hash.update(key, 32); hash.update(&label, 1); hash.update(plain, n); hash.final(digest);
    for (size_t i = 0; i < kTagBytes; ++i) tag[i] = digest[i];
}
void wrapStream(const uint8_t key[32], const uint8_t tag[kTagBytes], const uint8_t *in, uint8_t *out, size_t n) {
    const uint8_t label = 'S';
    for (size_t at = 0; at < n; at += 32) {
        uint8_t counter[4] = {(uint8_t)(at >> 5), (uint8_t)(at >> 13), (uint8_t)(at >> 21), (uint8_t)(at >> 29)};
        uint8_t digest[32];
        Sha256 hash;
        hash.update(key, 32); hash.update(&label, 1); hash.update(tag, kTagBytes); hash.update(counter, 4);
        hash.final(digest);
        for (size_t i = 0; i < 32 && at + i < n; ++i) out[at + i] = in[at + i] ^ digest[i];
    }
}
IOReturn writeOutput(IOExternalMethodArguments *args, const uint8_t *data, size_t n) {
    if (args->structureOutputDescriptor) {
        if (n > args->structureOutputDescriptor->getLength()) return kIOReturnNoSpace;
        args->structureOutputDescriptor->writeBytes(0, data, n);
        args->structureOutputDescriptorSize = (uint32_t)n;
        return kIOReturnSuccess;
    }
    if (!args->structureOutput || n > args->structureOutputSize) return kIOReturnNoSpace;
    for (size_t i = 0; i < n; ++i) ((uint8_t *)args->structureOutput)[i] = data[i];
    args->structureOutputSize = (uint32_t)n;
    return kIOReturnSuccess;
}
IOReturn wrapKey(IOExternalMethodArguments *args) {
    size_t n = args->structureInputSize;
    if (args->scalarInputCount != 2 || !args->scalarOutput || args->scalarOutputCount != 1 || !args->structureInput ||
        !n || n > kMaxKeyBytes) return kIOReturnBadArgument;
    uint8_t key[32], blob[kTagBytes + kMaxKeyBytes];
    if (!deviceKey(key)) return kAksError;
    wrapTag(key, (const uint8_t *)args->structureInput, n, blob);
    wrapStream(key, blob, (const uint8_t *)args->structureInput, blob + kTagBytes, n);
    IOReturn rc = writeOutput(args, blob, kTagBytes + n);
    if (rc == kIOReturnSuccess) args->scalarOutput[0] = args->scalarInput[1];
    return rc;
}
IOReturn unwrapKey(IOExternalMethodArguments *args) {
    size_t n = args->structureInputSize;
    if (args->scalarInputCount != 2 || args->scalarOutputCount != 0 || !args->structureInput ||
        n <= kTagBytes || n > kTagBytes + kMaxKeyBytes) return kIOReturnBadArgument;
    uint8_t key[32], plain[kMaxKeyBytes], tag[kTagBytes];
    if (!deviceKey(key)) return kAksError;
    const uint8_t *blob = (const uint8_t *)args->structureInput;
    n -= kTagBytes;
    wrapStream(key, blob, blob + kTagBytes, plain, n);
    wrapTag(key, plain, n, tag);
    uint8_t difference = 0;
    for (size_t i = 0; i < kTagBytes; ++i) difference |= (uint8_t)(tag[i] ^ blob[i]);
    return difference ? kAksError : writeOutput(args, plain, n);
}
IOReturn bagUuid(IOExternalMethodArguments *args) {
    uint8_t key[32], digest[32];
    if (!deviceKey(key)) return kAksError;
    const uint8_t label = 'U';
    Sha256 hash;
    hash.update(key, 32); hash.update(&label, 1); hash.final(digest);
    args->scalarOutputCount = 0;
    return writeOutput(args, digest, 16);
}

struct DerWriter {
    uint8_t *p; size_t cap, n = 0; bool ok = true;
    void put(uint8_t b) { if (n < cap) p[n++] = b; else ok = false; }
    void len(size_t l) { if (l < 0x80) put((uint8_t)l); else { put(0x81); put((uint8_t)l); } }   // entries stay below 256 bytes
};
// Smallest two's-complement big-endian INTEGER content for a non-negative value.
size_t derIntegerContent(uint64_t v, uint8_t out[9]) {
    uint8_t raw[8];
    for (int i = 0; i < 8; ++i) raw[i] = (uint8_t)(v >> (56 - 8 * i));
    size_t start = 0;
    while (start < 7 && raw[start] == 0) ++start;
    size_t n = 0;
    if (raw[start] & 0x80) out[n++] = 0;
    while (start < 8) out[n++] = raw[start++];
    return n;
}
size_t entrySize(const char *key, uint64_t value) {
    uint8_t c[9]; size_t kl = 0; while (key[kl]) ++kl;
    size_t body = (2 + kl) + (2 + derIntegerContent(value, c));
    return 2 + body;
}
size_t encodeState(uint8_t *out, size_t capacity, uint32_t lockState) {
    struct Entry { const char *key; uint64_t value; };
    const Entry entries[] = {{"ss", kStateFlags}, {"sls", lockState}, {"sb", 0}, {"sfa", 0}, {"sgs", 0},
                             {"sas", 0}, {"sgpe", 0}, {"srcd", 0}, {"sms", 0}, {"bh", 0}};
    size_t total = 0;
    for (const Entry &e : entries) total += entrySize(e.key, e.value);
    DerWriter w{out, capacity};
    w.put(0x31); w.len(total);
    for (const Entry &e : entries) {
        uint8_t c[9]; size_t kl = 0; while (e.key[kl]) ++kl;
        size_t il = derIntegerContent(e.value, c);
        w.put(0x30); w.len((2 + kl) + (2 + il));
        w.put(0x0c); w.put((uint8_t)kl); for (size_t i = 0; i < kl; ++i) w.put((uint8_t)e.key[i]);
        w.put(0x02); w.put((uint8_t)il); for (size_t i = 0; i < il; ++i) w.put(c[i]);
    }
    return w.ok ? w.n : 0;
}

}

/* libaks selectors (AppleKeyStore.framework, iOS 16.7). */
enum {
	kAKSOpen             = 0,
	kAKSCreateBag        = 2,
	kAKSSaveBag          = 3,
	kAKSUnloadBag        = 4,
	kAKSSetSystem        = 5,
	kAKSLoadBag          = 6,
	kAKSGetLockState     = 7,
	kAKSUnlockDevice     = 9,
	kAKSWrapKey          = 10,
	kAKSUnwrapKey        = 11,
	kAKSUnlockBag        = 12,
	kAKSLockBag          = 13,
	kAKSGetSystem        = 14,
	kAKSGetDeviceState   = 17,
	kAKSGetExtDeviceState = 35,     /* aks_get_extended_device_state */
	kAKSAssertHold       = 26,
	kAKSAssertDrop       = 27,
	kAKSUnloadSessionBags = 55,
	kAKSNotifyStateSet   = 102,
	kAKSNotifyStateIsSet = 103,
	kAKSAssertConsume    = 101,     /* aks_assert_consume */
};

/* The system (device) bag handle. */
#define SWEET_AKS_SYSTEM_HANDLE 0

/*
 * aks lock state bits (aks_get_lock_state): bit 2 is "unlocked since boot"
 * (MobileKeyBag MKBDeviceUnlockedSinceBoot); clear lock bits = unlocked.
 */
#define SWEET_AKS_LOCK_STATE    0x4

class AppleKeyStore : public IOService {
	OSDeclareDefaultStructors(AppleKeyStore);

public:
	bool start(IOService *provider) APPLE_KEXT_OVERRIDE;
};

OSDefineMetaClassAndStructors(AppleKeyStore, IOService);

bool
AppleKeyStore::start(IOService *provider)
{
	if (!IOService::start(provider)) {
		return false;
	}
	setProperty(kIOUserClientClassKey, "AppleKeyStoreUserClient");
	registerService();
	IOLog("SWEET AKS: AppleKeyStore registered (no passcode, unlocked)\n");
	return true;
}

class AppleKeyStoreUserClient : public IOUserClient {
	OSDeclareDefaultStructors(AppleKeyStoreUserClient);

public:
	IOReturn clientClose(void) APPLE_KEXT_OVERRIDE;
	IOReturn externalMethod(uint32_t selector, IOExternalMethodArguments *args,
	    IOExternalMethodDispatch *dispatch, OSObject *target,
	    void *reference) APPLE_KEXT_OVERRIDE;
};

OSDefineMetaClassAndStructors(AppleKeyStoreUserClient, IOUserClient);

IOReturn
AppleKeyStoreUserClient::clientClose(void)
{
	terminate();
	return kIOReturnSuccess;
}

/* Copy len bytes to the caller's output structure (inband or descriptor). */
static IOReturn
sweet_aks_struct_out(IOExternalMethodArguments *args, const void *buf, uint32_t len)
{
	if (args->structureOutputDescriptor != NULL) {
		if (len > args->structureOutputDescriptor->getLength()) {
			return kIOReturnNoSpace;
		}
		args->structureOutputDescriptor->writeBytes(0, buf, len);
		args->structureOutputDescriptorSize = len;
		return kIOReturnSuccess;
	}
	if (args->structureOutput == NULL || len > args->structureOutputSize) {
		return kIOReturnNoSpace;
	}
	memcpy(args->structureOutput, buf, len);
	args->structureOutputSize = len;
	return kIOReturnSuccess;
}

/* Append SEQUENCE { UTF8String key, INTEGER value } (short forms only). */
static uint32_t
sweet_aks_der_pair(uint8_t *p, const char *key, uint8_t value)
{
	uint32_t klen = (uint32_t)strlen(key);
	uint32_t n = 0;
	p[n++] = 0x30;
	p[n++] = (uint8_t)(2 + klen + 3);
	p[n++] = 0x0c;
	p[n++] = (uint8_t)klen;
	memcpy(p + n, key, klen);
	n += klen;
	p[n++] = 0x02;
	p[n++] = 0x01;
	p[n++] = value;
	return n;
}

/*
 * Device state (selector 17): a DER SET of key/INTEGER pairs that libaks
 * decode_extended_state reads: ss state, sls lock state (MKBGetDeviceLockState:
 * 0 = unlocked), sb backoff, sfa failed attempts, sgs generation, sas
 * assertions, sgpe grace period, srcd recovery countdown.
 */
static IOReturn
sweet_aks_device_state(IOExternalMethodArguments *args)
{
	static const struct {
		const char *key;
		uint8_t value;
	} fields[] = {
		{ "ss", SWEET_AKS_LOCK_STATE }, { "sls", 0 }, { "sb", 0 }, { "sfa", 0 },
		{ "sgs", 0 }, { "sas", 0 }, { "sgpe", 0 }, { "srcd", 0 },
	};
	uint8_t buf[128];
	uint32_t n = 2;
	for (unsigned int i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
		n += sweet_aks_der_pair(buf + n, fields[i].key, fields[i].value);
	}
	buf[0] = 0x31;
	buf[1] = (uint8_t)(n - 2);
	return sweet_aks_struct_out(args, buf, n);
}

static uint32_t
sweet_aks_struct_out_size(IOExternalMethodArguments *args)
{
	return args->structureOutputDescriptor != NULL ?
	       (uint32_t)args->structureOutputDescriptor->getLength() : args->structureOutputSize;
}

IOReturn
AppleKeyStoreUserClient::externalMethod(uint32_t selector, IOExternalMethodArguments *args,
    __unused IOExternalMethodDispatch *dispatch, __unused OSObject *target,
    __unused void *reference)
{
	IOReturn ret = kIOReturnSuccess;
	uint32_t in_scalars = args->scalarInputCount;
	uint32_t in_struct = args->structureInputDescriptor != NULL ?
	    (uint32_t)args->structureInputDescriptor->getLength() : args->structureInputSize;
	uint32_t out_scalars = args->scalarOutputCount;
	uint32_t out_struct = sweet_aks_struct_out_size(args);
	uint64_t arg0 = in_scalars > 0 ? args->scalarInput[0] : 0;


    bool pandora_handled=false;
    if(pandora_aks_enabled()){
        pandora_handled=true;
        switch(selector){
        case 10: ret=pandora_aks::wrapKey(args);break;
        case 11: ret=pandora_aks::unwrapKey(args);break;
        case 23: ret=pandora_aks::bagUuid(args);break;
        case 40:
            if(args->scalarInputCount!=2 || !args->scalarOutput || args->scalarOutputCount!=1)
                ret=kIOReturnBadArgument;
            else{args->scalarOutput[0]=0;ret=kIOReturnSuccess;}
            break;
        case 160: args->scalarOutputCount=0;ret=kIOReturnSuccess;break;
        case 17: case 35: {
            uint8_t der[160];
            // Official no-keybag/no-passcode state; preserve normal scalar
            // unlocked-since-boot query and use sls3 only in extended state.
            size_t n=pandora_aks::encodeState(der,sizeof(der),3);
            args->scalarOutputCount=0;
            ret=n?pandora_aks::writeOutput(args,der,n):kIOReturnNoSpace;
            break;
        }
        default:pandora_handled=false;break;
        }
    }
    if(!pandora_handled)
	switch (selector) {
	case kAKSOpen:
	case kAKSUnloadBag:
	case kAKSSetSystem:
	case kAKSUnlockDevice:
	case kAKSUnlockBag:
	case kAKSLockBag:
	case kAKSAssertHold:
	case kAKSAssertDrop:
	case kAKSAssertConsume:
	case kAKSUnloadSessionBags:
	case kAKSNotifyStateSet:
		args->scalarOutputCount = 0;
		break;
	case kAKSGetSystem:
		if (out_scalars < 1) {
			ret = kIOReturnBadArgument;
			break;
		}
		args->scalarOutput[0] = SWEET_AKS_SYSTEM_HANDLE;
		args->scalarOutputCount = 1;
		break;
	case kAKSGetLockState:
		if (out_scalars < 1) {
			ret = kIOReturnBadArgument;
			break;
		}
		args->scalarOutput[0] = SWEET_AKS_LOCK_STATE;
		args->scalarOutputCount = 1;
		break;
	case kAKSNotifyStateIsSet:
		/* Nothing was ever set: answer "not set". */
		if (out_scalars < 1) {
			ret = kIOReturnBadArgument;
			break;
		}
		args->scalarOutput[0] = 0;
		args->scalarOutputCount = 1;
		break;
	case kAKSGetDeviceState:
	case kAKSGetExtDeviceState:
		args->scalarOutputCount = 0;
		ret = sweet_aks_device_state(args);
		break;
	default:
		ret = kIOReturnUnsupported;
		break;
	}

	char name[32];
	proc_selfname(name, sizeof(name));
	IOLog("SWEET AKS: %s sel %u arg0 %llu in %u/%u out %u/%u -> 0x%x\n", name, selector,
	    arg0, in_scalars, in_struct, out_scalars, out_struct, ret);
	return ret;
}
#endif /* SWEET */
