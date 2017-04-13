<?php
namespace SapiStudio\DnsRecords;
use Illuminate\Support\Collection;

/**
 * DomainChecker
 * 
 * @package 
 * @copyright 2017
 * @version $Id$
 * @access public
 */
class DomainChecker
{
    protected $domain;
    protected $rawDns = [];
    protected $dnsRecords = null;
    /**
     * DomainChecker::make()
     * 
     * @param mixed $domain
     * @return
     */
    public static function make($domain = null)
    {
        return new static($domain);
    }
    /**
     * DomainChecker::__construct()
     * 
     * @param mixed $domain
     * @return void
     */
    public function __construct($domain)
    {
        $this->domain = $domain;
        $this->loadDns();
    }
    /**
     * DomainChecker::domain()
     * 
     * @return
     */
    public function domain()
    {
        return $this->domain;
    }
    /**
     * DomainChecker::hasDmarc()
     * 
     * @return
     */
    public function hasDmarc()
    {
        return $this->dnsRecords->has('dmarc');
    }
    /**
     * DomainChecker::getEntry()
     * 
     * @param mixed $entry
     * @return
     */
    public function getEntry($entry = null)
    {
        if (!$this->dnsRecords->has($entry))
            return false;
        return ($this->dnsRecords->get($entry)->count() > 1) ? $this->dnsRecords->get($entry)->
            all() : $this->dnsRecords->get($entry)->first();
    }
    /**
     * DomainChecker::loadDns()
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
    public function loadDns($type = DNS_ANY)
    {
        $nsRecords = dns_get_record($this->domain, $type);
        $dmarc = dns_get_record('_dmarc.' . $this->domain, $type);
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
     * DomainChecker::sort()
     * 
     * @param mixed $nsRecords
     * @return
     */
    public function sort($nsRecords = [])
    {
        if (is_array($nsRecords))
        {
            $this->rawDns = $nsRecords;
            foreach ($nsRecords as $dns_record)
            {
                $current_type = strtolower($dns_record['type']);
                if (!isset($dns_sorted[$current_type]))
                {
                    $dns_sorted[$current_type] = [];
                }
                $dns_sorted[$current_type][] = $dns_record;
            }
            if ($dns_sorted)
            {
                foreach ($dns_sorted as $a => $b)
                {
                    $return[$a] = Collection::make($b);
                }
            }
            return $return;
        }
        return false;
    }
    /**
     * DomainChecker::raw()
     * 
     * @return
     */
    public function raw()
    {
        return $this->rawDns;
    }
    /**
     * DomainChecker::nameservers()
     * 
     * @return
     */
    public function nameservers()
    {
        return $this->getEntry('ns');
    }
}
