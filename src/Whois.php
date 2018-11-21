<?php
namespace SapiStudio\Domain;
use SapiStudio\Domain\Domain as DomainHandler;
use SapiStudio\Socket\Connection;

/**
 * Whois
 */

class Whois
{
    private $whoisServers;
    protected $whoisResult;
    protected $whoisServerInfo;
    
    /**
     * Whois::load()
     */
    public static function load($domain){
        return (new static)->query($domain);
    }
    
    /**
     * Whois::__construct()
     */
    public function __construct()
    {
        $this->whoisServers = json_decode(file_get_contents(__DIR__ . '/../config/servers.json'));
    }
    
    /**
     * Whois::getWhois()
     */
    public function getWhois(){
        return $this->whoisResult;
    }
    
    /**
     * Whois::isAvailable()
     */
    public function isAvailable(){
        return (strpos($this->whoisResult,$this->whoisServerInfo->not_found) !== false) ? true : false;
        
    }
    
    /**
     * Whois::query()
     */
    public function query($domain)
    {
        $domain                 = DomainHandler::create($domain);
        $this->whoisServerInfo  = $this->whoisServers->{$domain->getTld()};
        if(!$this->whoisServerInfo){
            throw new \Exception(sprintf('The TLD "%s" does not exist.', $domain->getTld()));
        }
        try {
            $connection = Connection::open($this->whoisServerInfo->server, 43);
            $this->whoisResult = $connection->sendMessage($domain->getDomainName());
            $connection->close();
        } catch (\Exception $e) {
            throw new \Exception(sprintf('Could not query WHOIS for "%s".', $domain->getDomainName()), 0, $e);
        }
        if (0 === strlen(trim($this->whoisResult))) {
            throw new \Exception(sprintf('Retrieved empty WHOIS for "%s".', $domain->getDomainName()));
        }
        return $this;
    }
}