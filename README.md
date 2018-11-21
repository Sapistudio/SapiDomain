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
DnsQuerifier::make($domainName)->getDmarcRecord()
```

## Initialize querifier with a custom getter(dig or php)
```php
$querifier = DnsQuerifier::make($domainName,Querifier::GETTER_PHP);//or Querifier::GETTER_DIG
//load all records
$querifier->loadDnsRecords();
//get txt entries
$querifier->getTxtRecords();
```
## Whois data
```php
use SapiStudio\Domain\Whois;

Whois::load('example.com')->getWhois();
