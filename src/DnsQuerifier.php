<?php
namespace SapiStudio\Domain;

use Illuminate\Support\Collection;
use SapiStudio\Domain\Getter\RecordDig as Dig;
use SapiStudio\Domain\Getter\RecordPhp as Php;

/**
 * DnsQuerifier
 * 
 */
 
class DnsQuerifier
{
    const GETTER_PHP        = 'php';	
    const GETTER_DIG        = 'dig';
    
    protected $hostname;
    protected $rawDnsRecords= [];
    protected $dnsRecords   = null;
    protected $hostnameIsUp = true;/** default , we assume that domain is up,*/
    
    public static $A        = 'A';
    public static $CNAME    = "CNAME";
    public static $CAA      = "CAA";
    public static $MX       = "MX";
    public static $NS       = "NS";
    public static $PTR      = "PTR";
    public static $SOA      = "SOA";
    public static $TXT      = "TXT";
    public static $AAAA     = "AAAA";
    public static $ANY      = "ANY";
    
    const DMARC_DNS_ADDRES  = '_dmarc.';
    const RESULT_PASS       = 'Spf valid';
    const RESULT_FAIL       = 'Spf fail';
    const RESULT_SOFTFAIL   = 'Spf soft fail';
    const RESULT_NEUTRAL    = '?';
    const RESULT_NONE       = 'No spf';
    const SPF_PERMERROR     = 'Spf error';
    
    /**
     * DnsQuerifier::hostLookup()
     */
    public static function hostLookup($host,$getterRecord = null)
    {
        return self::make($host,$getterRecord)->loadDnsRecords();
    }
    
    /**
     * DnsQuerifier::blacklistLookup()
     */
    public static function blacklistLookup($adressToCheck = null,$rbls = [])
    {
        if(!$rbls)
            $rbls = include('config/rblConfig.php');
        $rbls           = ((bool)ip2long($adressToCheck)) ? array_keys($rbls['ipBased']) : (array_keys($rbls['domainBased']));
        $adressToCheck  = ((bool)ip2long($adressToCheck)) ? self::reverseIp($adressToCheck) : self::sanitizeDomainName($adressToCheck);
        if(!$adressToCheck || !$rbls)
            return false;
        $ipBlacklisted = false;
        foreach($rbls as $key=>$rblUrl){
            $blacklisted    = self::hostLookup($adressToCheck.'.'.$rblUrl);
            if($blacklisted->getEntries(self::$A)){
                $ipBlacklisted  = true;
                $txtEntry       = $blacklisted->getEntries(self::$TXT,true);
                $reason         =(isset($txtEntry['entries'])) ? implode("\n",$txtEntry['entries']) : 1;
            }else
                $reason         = 0;
            $results[$rblUrl]   = $reason;
        }
        return ['blacklisted' => (int)$ipBlacklisted, 'results' => $results];
    }
    
    /**
     * DnsQuerifier::make()
     */
    public static function make($host = null, $getterRecord = null)
    {
        switch(strtolower($getterRecord)){
            case 'dig':
            default:
                return new Dig($host);
                break;
            case 'php':
                return new Php($host);
                break;
        }
    }
    
    /**
     * DnsQuerifier::__construct()
     */
    public function __construct($hostName)
    {
        $this->setHost($hostName);
    }
    
    /**
     * DnsQuerifier::getSpfRecord()
     */
    public function getSpfRecord(){
        $records    = $this->getTxtRecords();
        if(!$records)
            return self::SPF_PERMERROR;
        $spfRecord  = false;
        foreach($records as $record) {
            if (preg_match("/^v=spf(.*)/i", $record['txt'])){
                if($spfRecord)
                    return self::SPF_PERMERROR;
                $spfRecord = $record['txt'];
            }
        }
        return $spfRecord;
    }
    
    /**
     * DnsQuerifier::hasDmarc()
     */
    public function hasDmarc(){
        return ($this->getDmarcRecord()) ? true : false;
    }
    
    /**
     * DnsQuerifier::getDmarcRecord()
     */
    public function getDmarcRecord()
    {
        $currentHost = $this->getHost();
        $this->setHost(SELF::DMARC_DNS_ADDRES.$currentHost);
        $dmarc = $this->loadDnsRecords(self::$TXT)->getEntries(self::$TXT,true);
        $this->setHost($currentHost);
        return ($dmarc) ? Analyzer\DmarcAnalyzer::create($dmarc['txt']) : false;
    }
    
    /**
     * DnsQuerifier::getDnsSummary()
     */
    public function getDnsSummary(){
        $summary    = [];
        $aEntries   = $this->getEntries(self::$A);
        if($aEntries){
            foreach($aEntries as $entryKey=>$entryData)
                $summary[self::$A][] = $entryData['host'].' - '.$entryData['ip'];
        }
        $aaEntries = $this->getEntries(self::$AAAA);
        if($aaEntries){
            foreach($aaEntries as $entryKey=>$entryData){
                $ip = (isset($entryData['ip6'])) ? $entryData['ip6'] : $entryData['ipv6'];
                $summary[self::$AAAA][] = $entryData['host'].' - '.$ip;
            }  
        }
        $targetEntries = $this->getEntries('dnsTarget');
        if($targetEntries){
            $summary[self::$NS] = $targetEntries;
        }
        $soaEntries = $this->getEntries(self::$SOA);
        if($soaEntries){
            foreach($soaEntries as $entryKey=>$entryData)
                $summary[self::$SOA][] = 'Ttl:'.$entryData['ttl'].' - '.$entryData['rname'];
        }
        $txtEntries = $this->getEntries(self::$TXT);
        if($txtEntries){
            foreach($txtEntries as $entryKey=>$entryData)
                $summary[self::$TXT][] = $entryData['txt'];
        }
        $mxEntries = $this->getEntries(self::$MX);
        if($mxEntries){
            foreach($mxEntries as $entryKey=>$entryData)
                $summary[self::$MX][] = $entryData['target'].' - '.$entryData['ttl'];
        }
        return $summary;
    }
    
    /**
     * DnsQuerifier::getTxtRecords()
     */
    public function getTxtRecords()
    {
        return $this->loadDnsRecords(self::$TXT)->getEntries(self::$TXT);
    }
    
    /**
     * DnsQuerifier::getARecords()
     */
    public function getARecords()
    {
        return $this->loadDnsRecords(self::$A)->getEntries(self::$A);
    }
    
    /**
     * DnsQuerifier::getMxRecords()
     */
    public function getMxRecords()
    {
        return $this->loadDnsRecords(self::$MX)->getEntries(self::$MX);
    }
    
    /**
     * DnsQuerifier::getDnsRecords()
     */
    public function getDnsRecords()
    {
        return $this->dnsRecords->toArray();
    }
    
    /**
     * DnsQuerifier::nameservers()
     */
    public function nameservers()
    {
        return array_keys($this->getEntries('dnsTarget'));
    }
    
    /**
     * DnsQuerifier::dnsIps()
     */
    public function dnsIps()
    {
        return array_values($this->getEntries('dnsTarget'));
    }
    
    /**
     * DnsQuerifier::getHost()
     */
    public function getHost()
    {
        return $this->hostname;
    }
    
    /**
     * DnsQuerifier::setHost()
     */
    public function setHost($hostName)
    {
        $this->hostname = self::sanitizeDomainName($hostName);
        return $this;
    }

    /**
     * DnsQuerifier::getEntries()
     */
    public function getEntries($entryType = null,$firstEntry = false)
    {
        if(!$this->dnsRecords)
            return false;
        $method = ($firstEntry) ? 'first' : 'toArray';
        return (!$this->dnsRecords->has($entryType)) ? false : $this->dnsRecords->get($entryType)->$method();
    }
    
    /**
     * DnsQuerifier::hostnameIsUp()
     */
    public function hostnameIsUp(){
        return $this->hostnameIsUp;
    }
    
    /**
     * DnsQuerifier::loadDnsRecords()
     */
    public function loadDnsRecords($type = null,$returnEntries = false)
    {
        if(!$this->hostname)
            throw new \InvalidArgumentException('A domain name is required');
        $this->rawDnsRecords = $this->queryDns(strtoupper($type));
        if(!$this->rawDnsRecords)
            $this->hostnameIsUp = false;
        $this->dnsRecords = Collection::make($this->sortRecords());
        return $this;
    }
  
    /**
     * DnsQuerifier::sortRecords()
     */
    protected function sortRecords()
    {
        if (is_array($this->rawDnsRecords))
        {
            foreach ($this->rawDnsRecords as $dns_record)
            {
                $dns_record['type'] = strtoupper($dns_record['type']);                
                if (!isset($dns_sorted[$dns_record['type']]))
                    $dns_sorted[$dns_record['type']] = [];
                $dns_sorted[$dns_record['type']][] = $dns_record;
            }
            if ($dns_sorted)
            {
                foreach ($dns_sorted as $dnsType => $dnsData)
                {
                    if($dnsType == self::$NS){
                        foreach($dnsData as $dnsKey=>$dnsValue)
                            $dnsTarget[$dnsValue['target']] = gethostbyname($dnsValue['target']);
                        $return['dnsTarget']    = Collection::make($dnsTarget);
                    }
                    $return[strtoupper($dnsType)] = Collection::make($dnsData);
                }
            }
            return $return;
        }
        return [];
    }
    
    /**
     * DnsQuerifier::reverseIp()
     */
    protected static function reverseIp($ipAddress,$ptr = false)
    {
        if (stripos($ipAddress, '.') !== false) {
            $reverseIp = implode('.', array_reverse(explode('.', $ipAddress)));
            return ($ptr) ? $reverseIp.'.in-addr.arpa' : $reverseIp;
        }else{
            $reverseIp = strtolower(implode('.', array_reverse(str_split(str_replace(':', '', implode(':', array_map(function ($b) {return sprintf('%04x', $b);}, unpack('n*', inet_pton($ipAddress)))))))));
            return ($ptr) ? $reverseIp.'.ip6.arpa' : $reverseIp;
        }
    }
    
    /**
     * DnsQuerifier::sanitizeDomainName()
     */
    protected static function sanitizeDomainName($domain)
    {
        return strtolower(strtok(str_replace(['http://', 'https://'], '', $domain), '/'));
    }
}