<?php
namespace SapiStudio\Domain\Dns;

class Classes
{
    /** helpers*/
    const DMARC_DNS_ADDRES  = '_dmarc.';
    /** getters*/
    const GETTER_PHP        = 'php';	
    const GETTER_DIG        = 'dig';
    /** clases*/
    const CHAOS             = 'CH';
    const HESIOD            = 'HS';
    const INTERNET          = 'IN';
    /** types*/
    const TYPE_A            = 'A';
    const TYPE_NS           = 'NS';
    const TYPE_CNAME        = 'CNAME';
    const TYPE_SOA          = 'SOA';
    const TYPE_PTR          = 'PTR';
    const TYPE_MX           = 'MX';
    const TYPE_TXT          = 'TXT';
    const TYPE_AAAA         = 'AAAA';
    const TYPE_OPT          = 'OPT';
    const TYPE_AXFR         = 'AXFR';
    const TYPE_ANY          = 'ANY';
    const TYPE_AFSDB        = 'AFSDB';
    const TYPE_APL          = 'APL';
    const TYPE_CAA          = 'CAA';
    const TYPE_CDNSKEY      = 'CDNSKEY';
    const TYPE_CDS          = 'CDS';
    const TYPE_CERT         = 'CERT';
    const TYPE_DHCID        = 'DHCID';
    const TYPE_DLV          = 'DLV';
    const TYPE_DNSKEY       = 'DNSKEY';
    const TYPE_DS           = 'DS';
    const TYPE_IPSECKEY     = 'IPSECKEY';
    const TYPE_KEY          = 'KEY';
    const TYPE_KX           = 'KX';
    const TYPE_LOC          = 'LOC';
    const TYPE_NAPTR        = 'NAPTR';
    const TYPE_NSEC         = 'NSEC';
    const TYPE_NSEC3        = 'NSEC3';
    const TYPE_NSEC3PARAM   = 'NSEC3PARAM';
    const TYPE_RRSIG        = 'RRSIG';
    const TYPE_RP           = 'RP';
    const TYPE_SIG          = 'SIG';
    const TYPE_SRV          = 'SRV';
    const TYPE_SSHFP        = 'SSHFP';
    const TYPE_TA           = 'TA';
    const TYPE_TKEY         = 'TKEY';
    const TYPE_TLSA         = 'TLSA';
    const TYPE_TSIG         = 'TSIG';
    const TYPE_URI          = 'URI';
    const TYPE_DNAME        = 'DNAME';
    
    public static $dnsTypes = [
        self::TYPE_A            => 'Maps a domain to an IPv4 address.',
        self::TYPE_NS           => 'Delegates a DNS zone to use specific authoritative name servers.',
        self::TYPE_CNAME        => 'Alias of one name to another, allowing the DNS lookup to continue with the new name.',
        self::TYPE_SOA          => 'Specifies authoritative information about a DNS zone, including the primary name server and email of the domain administrator.',
        self::TYPE_PTR          => 'Maps an IPv4 address to the canonical name for that host, typically used in reverse DNS lookups.',
        self::TYPE_MX           => 'Specifies mail servers responsible for accepting email messages on behalf of a domain.',
        self::TYPE_TXT          => 'Holds free-form text; often used for SPF records, DKIM, etc.',
        self::TYPE_AAAA         => 'Maps a domain to an IPv6 address.',
        self::TYPE_OPT          => 'Used for extending the maximum size of the DNS message and for signaling in DNSSEC.',
        self::TYPE_AXFR         => 'DNS zone transfer record, used to replicate DNS databases across a set of DNS servers.',
        self::TYPE_ANY          => 'A request to return all records of all types known for a domain.',
        self::TYPE_AFSDB        => 'AFS database record, used in AFS clients to locate AFS cells.',
        self::TYPE_APL          => 'Address Prefix List, used in DNSSEC.',
        self::TYPE_CAA          => 'Certification Authority Authorization, specifies which CAs are allowed to issue certificates for a domain.',
        self::TYPE_CDNSKEY      => 'Child DNSKEY, used in DNSSEC for a secure entry point.',
        self::TYPE_CDS          => 'Child DS, used in DNSSEC to signal changes to a DS record in the parent zone.',
        self::TYPE_CERT         => 'Stores certificates (PKIX, SPKI, PGP, and so on), used in various security and encryption contexts.',
        self::TYPE_DHCID        => 'DHCP identifier, used in conjunction with DDNS to prevent conflicts when updating DNS records.',
        self::TYPE_DLV          => 'DNSSEC Lookaside Validation, used for DNSSEC validation when a parent zone is not signed.',
        self::TYPE_DNSKEY       => 'Stores a public key for DNSSEC.',
        self::TYPE_DS           => 'Delegation Signer, used in DNSSEC to indicate a child zone is signed.',
        self::TYPE_IPSECKEY     => 'Key for IPSEC services, used to support IPSEC VPNs.',
        self::TYPE_KEY          => 'General key record, not widely used.',
        self::TYPE_KX           => 'Key Exchanger record, used for secure email exchange.',
        self::TYPE_LOC          => 'Location record, specifies geographic location of a host.',
        self::TYPE_NAPTR        => 'Naming Authority Pointer, used in Dynamic Delegation Discovery System (DDDS) for rewriting domain names.',
        self::TYPE_NSEC         => 'Next Secure record, part of DNSSEC, listing the next record name in the zone and record types that exist.',
        self::TYPE_NSEC3        => 'Next Secure record version 3, provides additional security compared to NSEC.',
        self::TYPE_NSEC3PARAM   => 'Parameter record for NSEC3, specifies parameters for NSEC3 use in the zone.',
        self::TYPE_RRSIG        => 'DNSSEC signature, contains a signature for a set of DNS records.',
        self::TYPE_RP           => 'Responsible Person, specifies the mailbox for the person responsible for the domain.',
        self::TYPE_SIG          => 'Signature record, used in older DNSSEC specifications.',
        self::TYPE_SRV          => 'Service locator, specifies the location of servers for specified services.',
        self::TYPE_SSHFP        => 'SSH Public Key Fingerprint, used to store SSH public key fingerprints.',
        self::TYPE_TA           => 'Trust Anchor, used for DNSSEC to indicate trusted keys.',
        self::TYPE_TKEY         => 'Secret key record, used for dynamic DNS and DNSSEC.',
        self::TYPE_TLSA         => 'Transport Layer Security Association, specifies a TLS certificate association.',
        self::TYPE_TSIG         => 'Transaction Signature, used for authenticated DNS updates.',
        self::TYPE_URI          => 'Uniform Resource Identifier, can be used for publishing mappings from hostnames to URIs.',
        self::TYPE_DNAME        => 'Delegation Name, provides redirection for a subtree of the domain name tree in the DNS.'
    ];

    public static $classes = [
        self::CHAOS     => 'CHAOS',
        self::HESIOD    => 'Hesiod',
        self::INTERNET  => 'Internet',
    ];

    public static function isValid($class)
    {
        return array_key_exists($class, self::$classes);
    }
    
    public static function isValidType($type)
    {
        return false !== array_search($type, self::$dnsTypes);
    }
}