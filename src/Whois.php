<?php
namespace SapiStudio\Domain;
use SapiStudio\Domain\Domain as DomainHandler;
use SapiStudio\Socket\Connection;
use Iodev\Whois\Exceptions\ConnectionException;
use Iodev\Whois\Exceptions\ServerMismatchException;
use Iodev\Whois\Exceptions\WhoisException;
/** Whois  */

class Whois
{
    private $whoisQuery         = null;
    private $whoisResult        = null;
    private $domainInfo         = null;
    private $domainIsAvailable  = false;
    
    /** Whois::load()*/
    public static function load($domain){
        return (new static)->query($domain);
    }
    
    /** Whois::__construct() */
    public function __construct()
    {
        $this->whoisQuery = \Iodev\Whois\Whois::create();
    }
    
    /** Whois::getWhois() */
    public function getWhois(){
        return ($this->domainInfo) ? $this->domainInfo->getResponse()->getText() : false;
    }
    
    /** Whois::isRegistered() */
    public function isRegistered(){
        return ($this->domainIsAvailable) ? false : true;
    }
    
    /** Whois::getExpirationDate() */
    public function getExpirationDate(){
        return ($this->domainInfo) ? date("Y-m-d", $this->domainInfo->getExpirationDate()) : false;
    }
    
    /** Whois::query() */
    public function query($domain)
    {
        try {
            $this->domainIsAvailable    = $this->whoisQuery->isDomainAvailable($domain);
            $this->domainInfo           = $this->whoisQuery->loadDomainInfo($domain);
        } catch (ConnectionException $e) {
            throw new \Exception('Connection error:'.$e->getMessage());
        } catch (ServerMismatchException $e) {
            throw new \Exception("TLD server not found in current server hosts:".$domain);
        } catch (WhoisException $e) {
            throw new \Exception("Whois server responded with error '{$e->getMessage()}'");
        }
        return $this;
    }
}
