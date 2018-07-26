<?php
namespace SapiStudio\DnsRecords\Getter;
use SapiStudio\DnsRecords\Querifier;

/**
 * RecordPhp
 * 
 * @package 
 * @copyright 2017
 * @version $Id$
 * @access public
 */

class RecordPhp extends Querifier implements RecordInterface
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
    
    /**
     * RecordPhp::queryDns()
     * 
     * @return
     */
    public function queryDns($type)
    {
        return dns_get_record($this->hostname,(isset(self::$QUERY_TYPES[$type])) ? self::$QUERY_TYPES[$type] : self::DEFAULT_TYPE);
    }
}