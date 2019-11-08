<?php
namespace SapiStudio\Domain\Getter;
use SapiStudio\Domain\DnsQuerifier;

/** RecordPhp*/

class RecordPhp extends DnsQuerifier implements RecordInterface
{
    public static $QUERY_TYPES = [
        "A"     => DNS_A,
        "CNAME" => DNS_CNAME,
        "CAA"   => DNS_CAA,
        "MX"    => DNS_MX,
        "NS"    => DNS_NS,
        "PTR"   => DNS_PTR,
        "SOA"   => DNS_SOA,
        "TXT"   => DNS_TXT,
        "AAAA"  => DNS_AAAA,
        "ANY"   => DNS_ANY,
    ];
    CONST DEFAULT_TYPE          = DNS_ANY;
    
    /** RecordPhp::queryDns()*/
    public function queryDns($type)
    {
        return dns_get_record($this->hostname,(isset(self::$QUERY_TYPES[$type])) ? self::$QUERY_TYPES[$type] : self::DEFAULT_TYPE);
    }
}
