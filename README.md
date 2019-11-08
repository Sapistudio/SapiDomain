## Check ip or domain against blacklists
```php
use SapiStudio\Domain\DnsQuerifier;

DnsQuerifier::blacklistLookup($ipValue);
```

## Get all DNS records for a domain
```php
DnsQuerifier::hostLookup($domainName);
```
## Check DMARC record
```php
$dmarc = DnsQuerifier::make($domainName)
$dmarc->getDmarcRecord()
$dmarc->hasDmarc()
```

## Check SPF record
```php
$dmarc = DnsQuerifier::make($domainName)
$dmarc->getSpfRecord()
$dmarc->hasSpf()
```

## Initialize querifier with a custom getter(dig or php)
```php
//load all records
$querifier = DnsQuerifier::dnsLoad($domainName,Querifier::GETTER_PHP);//or Querifier::GETTER_DIG
//get txt entries
$querifier->getTxtRecords();
```
## Whois data
```php
use SapiStudio\Domain\Whois;

Whois::load('example.com')->getWhois();
