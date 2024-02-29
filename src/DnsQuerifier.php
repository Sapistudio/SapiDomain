<?php
namespace SapiStudio\Domain;

use Illuminate\Support\Collection;
use SapiStudio\Domain\Getter\RecordDig as Dig;
use SapiStudio\Domain\Getter\RecordPhp as Php;
use SapiStudio\Domain\Dns\Classes;
use SapiStudio\Domain\Dns\Parser;
/**  DnsQuerifier */
 
class DnsQuerifier
{
    //const BLACKLIST_DNS_SERVER  = '185.228.168.9';//cleanbrowsing
    const BLACKLIST_DNS_SERVER  = '185.228.168.168';//cleanbrowsing
    protected $hostname;
    protected $rawDnsRecords        = [];
    protected $dnsRecords           = null;
    protected $loadNsFromMainDom    = true;
    
    /** DnsQuerifier::parseDnsZone() */
    public static function parseDnsZone($zoneString){
        return new Parser($zoneString);
    }
    
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
            $blacklisted    = (new Dig($adressToCheck.'.'.$rblUrl))->setQueryServer($blacklist_dns_server)->loadDnsRecords([Classes::TYPE_TXT,Classes::TYPE_A]);
            if($blacklisted->getEntries(Classes::TYPE_A)){
                $listed         = 'listed';
                $ipBlacklisted  = true;
                $txtEntry       = $blacklisted->getEntries(Classes::TYPE_TXT,true);
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
            case Classes::GETTER_DIG:
            default:
                return new Dig($host);
                break;
            case Classes::GETTER_PHP:
                return new Php($host);
                break;
        }
    }
    
    /** DnsQuerifier::__construct() */
    public function __construct($hostName)
    {
        $this->setHost($hostName);
    }
    
    /** DnsQuerifier::loadNsFromMainDom()  */
    public function loadNsFromMainDom($boolValue = true){
        $this->loadNsFromMainDom = $boolValue;
        return $this;
    }
    
    /** DnsQuerifier::hasDmarc()  */
    public function hasDmarc(){
        return $this->getDmarcAnalyzer()->getDmarcResult();
    }
    
    /**  DnsQuerifier::hasSpf)*/
    public function hasSpf(){
        return $this->getSpfAnalyzer()->getSpfResult();
    }
    
    /** DnsQuerifier::getDmarcRecord()*/
    public function getDmarcRecord()
    {
        $currentHost = $this->getHost();
        $this->setHost(Classes::DMARC_DNS_ADDRES.$currentHost);
        $dmarc = $this->loadDnsRecords(Classes::TYPE_TXT)->getEntries(Classes::TYPE_TXT,true);
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
        return $this->loadDnsRecords(Classes::TYPE_TXT)->getEntries(Classes::TYPE_TXT);
    }
    
    /** DnsQuerifier::getARecords() */
    public function getARecords()
    {
        return $this->loadDnsRecords(Classes::TYPE_A)->getEntries(Classes::TYPE_A);
    }
    
    /** DnsQuerifier::getMxRecords()*/
    public function getMxRecords()
    {
        return $this->loadDnsRecords(Classes::TYPE_MX)->getEntries(Classes::TYPE_MX);
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
        if($this->getEntries(Classes::TYPE_NS)){
            foreach(array_column($this->getEntries(Classes::TYPE_NS),'target') as $entryKey=>$targetValue)
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
        $dnsRecordTypes         = ($type) ? (!is_array($type)) ? [$type] : $type : array_keys(Classes::$dnsTypes);
        $this->rawDnsRecords    = [];
        foreach($dnsRecordTypes as $dnstype){
            $this->rawDnsRecords    = array_merge($this->rawDnsRecords,$this->queryDns(strtoupper($dnstype)));
        }
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
        if($this->getEntries(Classes::TYPE_A))
            $returnData['entries'][Classes::TYPE_A]    = array_column($this->getEntries(Classes::TYPE_A),'ip');
        if(!$this->getEntries(Classes::TYPE_NS)){
            if(self::getMainDomain($this->hostname) != $this->hostname && $this->loadNsFromMainDom){
                $entries = self::dnsLoad(self::getMainDomain($this->hostname))->getEntries(Classes::TYPE_NS);
                if($entries)
                    $returnData['entries'][Classes::TYPE_NS]   = array_column($entries,'target');
            }
        }else
            $returnData['entries'][Classes::TYPE_NS]   = array_column($this->getEntries(Classes::TYPE_NS),'target');
        if($this->getEntries(Classes::TYPE_TXT))
            $returnData['entries'][Classes::TYPE_TXT]  = array_column($this->getEntries(Classes::TYPE_TXT),'txt');
        if($this->getEntries(Classes::TYPE_AAAA)){
            foreach($this->getEntries(Classes::TYPE_AAAA) as $entryKey=>$entryData){
                $ip = (isset($entryData['ip6'])) ? $entryData['ip6'] : $entryData['ipv6'];
                $returnData['entries'][Classes::TYPE_AAAA][] = $entryData['host'].' - '.$ip;
            }
        }
        if($this->getEntries(Classes::TYPE_SOA)){
            foreach($this->getEntries(Classes::TYPE_SOA) as $entryKey=>$entryData)
                $returnData['entries'][Classes::TYPE_SOA][]    = 'Ttl:'.$entryData['ttl'].' - '.$entryData['rname'];
        }
        if($this->getEntries(Classes::TYPE_MX)){
            foreach($this->getEntries(Classes::TYPE_MX) as $entryKey=>$entryData)
                $returnData['entries'][Classes::TYPE_MX][]     = $entryData['target'].' - '.$entryData['ttl'];
        }
        $spfresults                                 = $this->hasSpf();
        $dmarcResults                               = $this->hasDmarc();
        $returnData['hasSpf']                       = $spfresults->isValid;
        if($spfresults->isValid)
            $returnData['spf_data']                 = $spfresults;
        $returnData['hasDmarc']                     = $dmarcResults->isValid;
        $returnData['dnsIps']                       = $this->dnsIps();
        if($dmarcResults->isValid)
            $returnData['dmarc_data']               = $dmarcResults;
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
        return Whois::load(self::getMainDomain($this->hostname));
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
    
    /** DnsQuerifier::getMainDomain() */
    public static function getMainDomain($domain = '') {
        return implode('.', array_slice(explode('.', $domain), -2, 2));
    }
}
