<?php
namespace SapiStudio\Domain;

/** Domain*/
class Domain
{
    private $domainName;
    
    /** Domain::create() */
    public static function create($domainName = null)
    {
        return new self($domainName);
    }

    /** Domain::__construct()*/
    public function __construct($domainName = null)
    {
        if (null !== $domainName) {
            $this->setDomainName($domainName);
        }else
            throw new \Exception('Invalid domain');
    }

    /** Domain::setDomainName()*/
    public function setDomainName($domainName)
    {
        $this->domainName = $domainName;
        return $this;
    }

    /** Domain::getDomainName()*/
    public function getDomainName()
    {
        return $this->domainName;
    }

    /** Domain::getTld()*/
    public function getTld()
    {
        return preg_replace('/(.*)\.([a-z]+)$/', '$2', $this->domainName);
    }
}
