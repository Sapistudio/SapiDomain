<?php
namespace SapiStudio\DnsRecords;
use Illuminate\Support\Collection;

/**
 * DnsQuerifier
 * 
 * @package 
 * @copyright 2017
 * @version $Id$
 * @access public
 */
class DnsQuerifier
{
    const  TYPE_A   = DNS_A;
    const  TYPE_TXT = DNS_TXT;
    const  TYPE_ANY = DNS_ANY;
    
    protected $hostname;
    protected $rawDnsRecords    = [];
    protected $dnsRecords       = null;
    protected $hostnameIsUp     = true;/** default , we assume that domain is up,*/
    
    /**
     * DnsQuerifier::hostLookup()
     * 
     * @param mixed $host
     * @return
     */
    public static function hostLookup($host = null)
    {
        return new static($host);
    }
    
    /**
     * DnsQuerifier::domainLookup()
     * 
     * @param mixed $domain
     * @return
     */
    public static function blacklistLookup($ip = null,$rbls = [])
    {
        if(!$ip || !$rbls)
            return false;
        $reverseIp = self::reverseIp($ip);
        $ipBlacklisted = false;
        foreach($rbls as $key=>$rblUrl){
            $blacklisted = (new static($reverseIp.'.'.$rblUrl))->testRbls();
            if($blacklisted)
                $ipBlacklisted = true;
            $results[$rblUrl] = $blacklisted;
        }
        return ['blacklisted'=>$ipBlacklisted,'results'=>$results];
    }
    
    /**
     * DnsQuerifier::reverseIp()
     * 
     * @param mixed $ip
     * @return
     */
    public static function reverseIp($ip)
    {
        list($part1, $part2, $part3, $part4) = explode('.', $ip);
        return sprintf('%s.%s.%s.%s', $part4, $part3, $part2, $part1);
    }
    
    /**
     * DnsQuerifier::__construct()
     * 
     * @param mixed $hostName
     * @return void
     */
    public function __construct($hostName)
    {
        $this->hostname = $hostName;
        $this->loadDnsRecords();
    }
    /**
     * DnsQuerifier::domain()
     * 
     * @return
     */
    public function getHost()
    {
        return $this->hostname;
    }
    /**
     * DnsQuerifier::hasDmarc()
     * 
     * @return
     */
    public function hasDmarc()
    {
        return $this->dnsRecords->has('dmarc');
    }
    /**
     * DnsQuerifier::getEntry()
     * 
     * @param mixed $entry
     * @return
     */
    public function getEntry($entry = null)
    {
        if (!$this->dnsRecords->has($entry))
            return false;
        return ($this->dnsRecords->get($entry)->count() > 1) ? $this->dnsRecords->get($entry)->all() : $this->dnsRecords->get($entry)->first();
    }
    
    /**
     * DnsQuerifier::hostnameIsUp()
     * 
     * @return
     */
    public function hostnameIsUp(){
        return $this->hostnameIsUp;
    }
    
    /**
     * DnsQuerifier::loadDnsRecords()
     * 
     * @param mixed $type
     * @return void
     *
     * For dns_get_record, type can be any one of the following:
     *      DNS_A, DNS_CNAME, DNS_HINFO, DNS_MX, DNS_NS, DNS_PTR, DNS_SOA, 
     *      DNS_TXT, DNS_AAAA, DNS_SRV, DNS_NAPTR, DNS_A6, DNS_ALL or DNS_ANY. 
     *      (DNS_ALL is better than DNS_ANY, according to php.net)
     *
     */
    protected function loadDnsRecords($type = self::TYPE_ANY)
    {
        if(!$this->hostname)
            return false;
        $nsRecords = dns_get_record($this->hostname,$type);
        if(!$nsRecords){
            $this->hostnameIsUp = false;
            $this->dnsRecords = Collection::make();
            return false;
        }
        $dmarc          = dns_get_record('_dmarc.'.$this->hostname, $type);
        $dmarcEntries   = [];
        if ($dmarc)
        {
            foreach ($dmarc as $a => $entry)
            {
                $entry['type'] = 'dmarc';
                $dmarcEntries[$a] = $entry;
            }
        }
        $this->dnsRecords = Collection::make($this->sort(array_merge($nsRecords, $dmarcEntries)));
    }
    
    /**
     * DnsQuerifier::testRbls()
     * 
     * @return
     */
    protected function testRbls()
    {
        /** check for a record,if exists,we are on the blacklist*/
        if($this->dnsRecords->has('a')){
            return $this->getEntry('txt')['entries'][0];
        }
        return false;
    }
    
    /**
     * DnsQuerifier::sort()
     * 
     * @param mixed $nsRecords
     * @return
     */
    public function sort($nsRecords = [])
    {
        if (is_array($nsRecords))
        {
            $this->rawDnsRecords = $nsRecords;
            foreach ($nsRecords as $dns_record)
            {
                $current_type = strtolower($dns_record['type']);
                if (!isset($dns_sorted[$current_type]))
                    $dns_sorted[$current_type] = [];
                $dns_sorted[$current_type][] = $dns_record;
            }
            if ($dns_sorted)
            {
                foreach ($dns_sorted as $a => $b)
                {
                    if($a=='ns'){
                        foreach($b as $dnsKey=>$dnsValue){
                            $dnsIps[]       = gethostbyname($dnsValue['target']);
                            $dnsTarget[]    = $dnsValue['target'];
                        }
                        $return['dnsIps']       = Collection::make($dnsIps);
                        $return['dnsTarget']    = Collection::make($dnsTarget);
                    }
                    $return[$a] = Collection::make($b);
                }
            }
            return $return;
        }
        return false;
    }
    
    /**
     * DnsQuerifier::getDnsRecords()
     * 
     * @return
     */
    public function getDnsRecords()
    {
        return $this->dnsRecords;
    }
    
    /**
     * DnsQuerifier::raw()
     * 
     * @return
     */
    public function raw()
    {
        return $this->rawDnsRecords;
    }
    /**
     * DnsQuerifier::nameservers()
     * 
     * @return
     */
    public function nameservers()
    {
        return $this->getEntry('dnsTarget');
    }
    
    /**
     * DnsQuerifier::nameservers()
     * 
     * @return
     */
    public function dnsIps()
    {
        return $this->getEntry('dnsIps');
    }
}
