<?php
namespace SapiStudio\Domain;

use Illuminate\Support\Collection;
use SapiStudio\Domain\Getter\RecordDig as Dig;
use SapiStudio\Domain\Getter\RecordPhp as Php;

/**
 * DnsQuerifier
 */
 
class DnsQuerifier
{
    const GETTER_PHP        = 'php';	
    const GETTER_DIG        = 'dig';
    
    protected $hostname;
    protected $rawDnsRecords= [];
    protected $dnsRecords   = null;
    
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
    
    /**
     * DnsQuerifier::blacklistLookup()
     */
    public static function blacklistLookup($adressToCheck = null,$rbls = [])
    {
        if(!$rbls)
            $rbls = include('config/rblConfig.php');
        $isIp           = (bool)ip2long($adressToCheck);
        $rbls           = ($isIp) ? array_keys($rbls['ipBased']) : (array_keys($rbls['domainBased']));
        $adressToCheck  = ($isIp) ? self::reverseIp($adressToCheck) : self::sanitizeDomainName($adressToCheck);
        if(!$adressToCheck || !$rbls)
            return false;
        $ipBlacklisted = false;
        foreach($rbls as $key=>$rblUrl){
            $blacklisted    = self::dnsCheck($adressToCheck.'.'.$rblUrl);
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
     * DnsQuerifier::dnsCheck()
     */
    public static function dnsCheck($host,$getterRecord = null)
    {
        return self::make($host,$getterRecord)->loadDnsRecords();
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
     * DnsQuerifier::hasDmarc()
     */
    public function hasDmarc(){
        return ($this->getDmarcRecord()) ? true : false;
    }
    
    /**
     * DnsQuerifier::hasSpf)
     */
    public function hasSpf(){
        return ($this->getSpfRecord()) ? true : false;
    }
    
    
    /**
     * DnsQuerifier::getSpfRecord()
     */
    public function getSpfRecord(){
        return Analyzer\SpfAnalyzer::create($this->getTxtRecords())->getSpf();
    }
    
    /**
     * DnsQuerifier::getDmarcRecord()
     */
    public function getDmarcRecord()
    {
        $currentHost = $this->getHost();
        $this->setHost(SELF::DMARC_DNS_ADDRES.$currentHost);
        $dmarc = $this->loadDnsRecords(self::$TXT)->getEntries(self::$TXT,true);
        $this->setHost($currentHost)->loadDnsRecords();
        return ($dmarc) ? Analyzer\DmarcAnalyzer::create($dmarc['txt']) : false;
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
     * DnsQuerifier::getAllRecords()
     */
    public function getAllRecords()
    {
        return $this->dnsRecords->toArray();
    }
    
    /**
     * DnsQuerifier::dnsIps()
     */
    public function dnsIps()
    {
        $dnsTarget = [];
        if($this->getEntries(self::$NS)){
            foreach(array_column($this->getEntries(self::$NS),'target') as $entryKey=>$targetValue)
                $dnsTarget[$targetValue] = gethostbyname($targetValue);
        }
        return array_Values($dnsTarget);
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
     * DnsQuerifier::loadDnsRecords()
     */
    public function loadDnsRecords($type = null)
    {
        if(!$this->hostname)
            throw new \InvalidArgumentException('A domain name is required');
        $this->rawDnsRecords    = $this->queryDns(strtoupper($type));
        $this->dnsRecords       = Collection::make($this->sortRecords());
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
                    $return[strtoupper($dnsType)] = Collection::make($dnsData);
            }
            return $return;
        }
        return [];
    }
    
    /**
     * DnsQuerifier::summary()
     */
    public function summary(){
        $summary    = [];
        if($this->getEntries(self::$A))
            $summary['entries'][self::$A] = array_column($this->getEntries(self::$A),'ip');
        if($this->getEntries(self::$NS))
            $summary['entries'][self::$NS] = array_column($this->getEntries(self::$NS),'target');
        if($this->getEntries(self::$TXT))
            $summary['entries'][self::$TXT] = array_column($this->getEntries(self::$TXT),'txt');
        foreach($this->getEntries(self::$AAAA) as $entryKey=>$entryData){
            $ip = (isset($entryData['ip6'])) ? $entryData['ip6'] : $entryData['ipv6'];
            $summary['entries'][self::$AAAA][] = $entryData['host'].' - '.$ip;
        }
        foreach($this->getEntries(self::$SOA) as $entryKey=>$entryData)
            $summary['entries'][self::$SOA][] = 'Ttl:'.$entryData['ttl'].' - '.$entryData['rname'];
        foreach($this->getEntries(self::$MX) as $entryKey=>$entryData)
            $summary['entries'][self::$MX][] = $entryData['target'].' - '.$entryData['ttl'];
        $summary['hasSpf'] = $this->hasSpf();
        $summary['hasDmarc'] = $this->hasDmarc();
        $whois = Whois::load($this->hostname);
        $summary['whois'] = str_replace(["\n","\r",'"'],['<br>',"",""],$whois->getWhois());
        $summary['exists'] = $whois->isAvailable();
        return $summary;
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