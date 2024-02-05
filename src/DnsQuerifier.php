<?php
namespace SapiStudio\Domain;

use Illuminate\Support\Collection;
use SapiStudio\Domain\Getter\RecordDig as Dig;
use SapiStudio\Domain\Getter\RecordPhp as Php;

/**  DnsQuerifier */
 
class DnsQuerifier
{
    const GETTER_PHP            = 'php';	
    const GETTER_DIG            = 'dig';
    //const BLACKLIST_DNS_SERVER  = '185.228.168.9';//cleanbrowsing
    const BLACKLIST_DNS_SERVER  = '185.228.168.168';//cleanbrowsing
    protected $hostname;
    protected $rawDnsRecords    = [];
    protected $dnsRecords       = null;
    
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
    
    /** DnsQuerifier::blacklistLookup() */
    public static function blacklistLookup($adressToCheck = null,$rbls = [],$blacklist_dns_server = self::BLACKLIST_DNS_SERVER)
    {
        if(!$rbls)
            $rbls = include('config/rblConfig.php');
        $isIp           = (bool)ip2long($adressToCheck);
        $rblsData       = ($isIp) ? $rbls['ipBased'] : $rbls['domainBased'];
        $rblsUris       = array_keys($rblsData);
        $adressToCheck  = ($isIp) ? self::reverseIp($adressToCheck) : self::sanitizeDomainName($adressToCheck);
        if(!$adressToCheck || !$rbls)
            return false;
        $ipBlacklisted = false;
        foreach($rblsUris as $key => $rblUrl){
            $blacklisted    = (new Dig($adressToCheck.'.'.$rblUrl))->setQueryServer($blacklist_dns_server)->loadDnsRecords();
            if($blacklisted->getEntries(self::$A)){
                $listed         = 'listed';
                $ipBlacklisted  = true;
                $txtEntry       = $blacklisted->getEntries(self::$TXT,true);
                $reason         =(isset($txtEntry['entries'])) ? implode("\n",$txtEntry['entries']) : 1;
            }else{
                $listed         = 'not';
                $reason         = 0;
            }
            $results['rbls'][$rblsData[$rblUrl]['shortName']]   = $reason;
            $results[$listed][$rblsData[$rblUrl]['shortName']]   = $reason;
        }
        return ['blacklisted' => (int)$ipBlacklisted, 'ip_checked' => $adressToCheck,'dns_server_used' => $blacklist_dns_server,'results' => $results];
    }
    
    /** DnsQuerifier::hostLookup()  */
    public static function hostLookup($host,$getterRecord = null)
    {
        return self::dnsLoad($host,$getterRecord)->getAllRecords();
    }
    
    /** DnsQuerifier::dnsLoad()  */
    public static function dnsLoad($host,$getterRecord = null)
    {
        return self::make($host,$getterRecord)->loadDnsRecords();
    }
    
    /** DnsQuerifier::make()*/
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
    
    /** DnsQuerifier::__construct() */
    public function __construct($hostName)
    {
        $this->setHost($hostName);
    }
    
    /** DnsQuerifier::hasDmarc()  */
    public function hasDmarc(){
        return (int) $this->getDmarcAnalyzer()->dmarcIsValid();
    }
    
    /**  DnsQuerifier::hasSpf)*/
    public function hasSpf(){
        return $this->getSpfAnalyzer()->getSpfResult();
    }
    
    /** DnsQuerifier::getDmarcRecord()*/
    public function getDmarcRecord()
    {
        $currentHost = $this->getHost();
        $this->setHost(SELF::DMARC_DNS_ADDRES.$currentHost);
        $dmarc = $this->loadDnsRecords(self::$TXT)->getEntries(self::$TXT,true);
        $this->setHost($currentHost)->loadDnsRecords();
        return ($dmarc) ? $dmarc['txt'] : null;
    }
    
    /** DnsQuerifier::getDmarcAnalyzer() */
    public function getDmarcAnalyzer(){
        return Analyzer\DmarcAnalyzer::create($this->getDmarcRecord());
    }
    
    /** DnsQuerifier::getSpfAnalyzer() */
    public function getSpfAnalyzer(){
        return Analyzer\SpfAnalyzer::create($this->getTxtRecords());
    }
    
    /** DnsQuerifier::getTxtRecords() */
    public function getTxtRecords()
    {
        return $this->loadDnsRecords(self::$TXT)->getEntries(self::$TXT);
    }
    
    /** DnsQuerifier::getARecords() */
    public function getARecords()
    {
        return $this->loadDnsRecords(self::$A)->getEntries(self::$A);
    }
    
    /** DnsQuerifier::getMxRecords()*/
    public function getMxRecords()
    {
        return $this->loadDnsRecords(self::$MX)->getEntries(self::$MX);
    }
    
    /** DnsQuerifier::getAllRecords()*/
    public function getAllRecords()
    {
        return $this->dnsRecords->toArray();
    }
    
    /** DnsQuerifier::dnsIps()*/
    public function dnsIps()
    {
        $dnsTarget = [];
        if($this->getEntries(self::$NS)){
            foreach(array_column($this->getEntries(self::$NS),'target') as $entryKey=>$targetValue)
                $dnsTarget[$targetValue] = gethostbyname($targetValue);
        }
        return array_Values($dnsTarget);
    }
    
    /** DnsQuerifier::getHost() */
    public function getHost()
    {
        return $this->hostname;
    }
    
    /** DnsQuerifier::setHost()*/
    public function setHost($hostName)
    {
        $this->hostname = self::sanitizeDomainName($hostName);
        return $this;
    }

    /** DnsQuerifier::getEntries() */
    public function getEntries($entryType = null,$firstEntry = false)
    {
        if(!$this->dnsRecords)
            return false;
        $method = ($firstEntry) ? 'first' : 'toArray';
        return (!$this->dnsRecords->has($entryType)) ? false : $this->dnsRecords->get($entryType)->$method();
    }
    
    /** DnsQuerifier::loadDnsRecords() */
    public function loadDnsRecords($type = null)
    {
        if(!$this->hostname)
            throw new \InvalidArgumentException('A domain name is required');
        $this->rawDnsRecords    = $this->queryDns(strtoupper($type));
        $this->dnsRecords       = Collection::make($this->sortRecords());
        return $this;
    }
  
    /** DnsQuerifier::sortRecords() */
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
    
    /** DnsQuerifier::summary() */
    public function summary(){
        $returnData                             = [];
        if($this->getEntries(self::$A))
            $returnData['entries'][self::$A]    = array_column($this->getEntries(self::$A),'ip');
        if($this->getEntries(self::$NS))
            $returnData['entries'][self::$NS]   = array_column($this->getEntries(self::$NS),'target');
        if($this->getEntries(self::$TXT))
            $returnData['entries'][self::$TXT]  = array_column($this->getEntries(self::$TXT),'txt');
        foreach($this->getEntries(self::$AAAA) as $entryKey=>$entryData){
            $ip = (isset($entryData['ip6'])) ? $entryData['ip6'] : $entryData['ipv6'];
            $returnData['entries'][self::$AAAA][] = $entryData['host'].' - '.$ip;
        }
        foreach($this->getEntries(self::$SOA) as $entryKey=>$entryData)
            $returnData['entries'][self::$SOA][]    = 'Ttl:'.$entryData['ttl'].' - '.$entryData['rname'];
        foreach($this->getEntries(self::$MX) as $entryKey=>$entryData)
            $returnData['entries'][self::$MX][]     = $entryData['target'].' - '.$entryData['ttl'];
        $spfresults                                 = $this->hasSpf();
        $returnData['hasSpf']                       = $spfresults->isValid;
        if($spfresults->isValid)
            $returnData['spf_data']                 = $spfresults;
        $returnData['hasDmarc']                     = $this->hasDmarc();
        try {
            $whois                                  = $this->loadWhois();
            $returnData['whois']                    = str_replace(["\n","\r",'"'],['<br>',"",""],$whois->getWhois());
            $returnData['isRegistered']             = $whois->isRegistered();
            $returnData['expirationDate']           = $whois->getExpirationDate();
            $returnData['domOwner']                 = strtolower(trim($whois->getOwner()));
            $returnData['domRegistrar']             = strtolower(trim($whois->getRegistrar()));
        }catch(\Exception $e){
            throw new \Exception("Whois error : '{$e->getMessage()}'");
        }
        return $returnData;
    }
    
    /** DnsQuerifier::loadWhois() */
    public function loadWhois(){
        return Whois::load($this->hostname);
    }
    
    /** DnsQuerifier::reverseIp() */
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
    
    /** DnsQuerifier::sanitizeDomainName() */
    protected static function sanitizeDomainName($domain)
    {
        return strtolower(strtok(str_replace(['http://', 'https://'], '', $domain), '/'));
    }
}
