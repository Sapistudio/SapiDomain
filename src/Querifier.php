<?php
namespace SapiStudio\DnsRecords;

use Illuminate\Support\Collection;
use SapiStudio\DnsRecords\Getter\RecordDig as Dig;
use SapiStudio\DnsRecords\Getter\RecordPhp as Php;

/**
 * Querifier
 * 
 * @package 
 * @copyright 2017
 * @version $Id$
 * @access public
 */
 
class Querifier
{
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
     * Querifier::hostLookup()
     * 
     * @param mixed $host
     * @param mixed $getterRecord
     * @return
     */
    public static function hostLookup($host,$getterRecord = null)
    {
        return self::make($host,$getterRecord)->loadDnsRecords();
    }
    
    /**
     * Querifier::blacklistLookup()
     * 
     * @param mixed $ip
     * @param mixed $rbls
     * @return
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
            echo $adressToCheck.'.'.$rblUrl."\n";
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
     * Querifier::make()
     * 
     * @param mixed $host
     * @param mixed $getterRecord
     * @return
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
     * Querifier::__construct()
     * 
     * @param mixed $hostName
     * @return void
     */
    public function __construct($hostName)
    {
        $this->setHost($hostName);
    }
    
    /**
     * Querifier::getSpfRecord()
     * 
     * @param mixed $host
     * @param mixed $getterRecord
     * @return
     */
    public function getSpfRecord($host, $getterRecord = null){
        $records    = $this->getTxtRecords();
        if(!$records)
            return self::SPF_PERMERROR;
        $spfRecord  = false;
        foreach($records as $record) {
            $txt = strtolower($record['txt']);
            if ($txt == 'v=spf1' || stripos($txt, 'v=spf1 ') === 0) {
                if($spfRecord)
                    return self::SPF_PERMERROR;
                $spfRecord = $txt;
            }
        }
        return $spfRecord;
    }
    
    /**
     * Querifier::getDmarcRecord()
     * 
     * @return
     */
    public function getDmarcRecord()
    {
        $currentHost = $this->getHost();
        $this->setHost(SELF::DMARC_DNS_ADDRES.$currentHost);
        $dmarc = $this->loadDnsRecords(self::$TXT)->getEntries(self::$TXT,true);
        $this->setHost($currentHost);
        return ($dmarc) ? $dmarc['entries'][0] : false;
    }
    
    /**
     * Querifier::getDnsSummary()
     * 
     * @return
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
     * Querifier::getTxtRecords()
     * 
     * @return
     */
    public function getTxtRecords()
    {
        return $this->loadDnsRecords(self::$TXT)->getEntries(self::$TXT);
    }
    
    /**
     * Querifier::getARecords()
     * 
     * @return
     */
    public function getARecords()
    {
        return $this->loadDnsRecords(self::$A)->getEntries(self::$A);
    }
    
    /**
     * Querifier::getMxRecords()
     * 
     * @return
     */
    public function getMxRecords()
    {
        return $this->loadDnsRecords(self::$MX)->getEntries(self::$MX);
    }
    
    /**
     * Querifier::getDnsRecords()
     * 
     * @return
     */
    public function getDnsRecords()
    {
        return $this->dnsRecords->toArray();
    }
    
    /**
     * Querifier::nameservers()
     * 
     * @return
     */
    public function nameservers()
    {
        return array_keys($this->getEntries('dnsTarget'));
    }
    
    /**
     * Querifier::dnsIps()
     * 
     * @return
     */
    public function dnsIps()
    {
        return array_values($this->getEntries('dnsTarget'));
    }
    
    /**
     * Querifier::getHost()
     * 
     * @return
     */
    public function getHost()
    {
        return $this->hostname;
    }
    
    /**
     * Querifier::setHost()
     * 
     * @param mixed $hostName
     * @return
     */
    public function setHost($hostName)
    {
        $this->hostname = self::sanitizeDomainName($hostName);
        return $this;
    }

    /**
     * Querifier::getEntries()
     * 
     * @param mixed $entryType
     * @param bool $firstEntry
     * @return
     */
    public function getEntries($entryType = null,$firstEntry = false)
    {
        if(!$this->dnsRecords)
            return false;
        $method = ($firstEntry) ? 'first' : 'all';
        return (!$this->dnsRecords->has($entryType)) ? false : $this->dnsRecords->get($entryType)->$method();
    }
    
    /**
     * Querifier::hostnameIsUp()
     * 
     * @return
     */
    public function hostnameIsUp(){
        return $this->hostnameIsUp;
    }
    
    /**
     * Querifier::loadDnsRecords()
     * 
     * @param mixed $type
     * @param bool $returnEntries
     * @return
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
     * Querifier::sortRecords()
     * 
     * @return
     */
    protected function sortRecords()
    {
        if (is_array($this->rawDnsRecords))
        {
            foreach ($this->rawDnsRecords as $dns_record)
            {
                if (!isset($dns_sorted[$dns_record['type']]))
                    $dns_sorted[$dns_record['type']] = [];
                $dns_sorted[$dns_record['type']][] = $dns_record;
            }
            if ($dns_sorted)
            {
                foreach ($dns_sorted as $dnsType => $dnsData)
                {
                    if($dnsType=='NS'){
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
     * Querifier::reverseIp()
     * 
     * @param mixed $ipAddress
     * @param bool $ptr
     * @return
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
     * Querifier::sanitizeDomainName()
     * 
     * @param mixed $domain
     * @return
     */
    protected static function sanitizeDomainName($domain)
    {
        return strtolower(strtok(str_replace(['http://', 'https://'], '', $domain), '/'));
    }
}