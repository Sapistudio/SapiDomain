<?php
namespace SapiStudio\Domain\Analyzer;

/**
 * The SpfAnalyzer class provides functionality to analyze SPF records for a given domain.
 * It checks for SPF record presence, parses the record, and validates its syntax according to SPF standards.
 */
 
class SpfAnalyzer
{
    protected $rawRecords           = null;
    protected $spfRecordEntry       = null;
    protected $spfErrors            = [];
    private $allowedIPs             = [];
    private $checkIncludeIps        = false;
    private $parseCidrBlocks        = true;
    private $spfPolicy              = false;
    // Constants defining SPF check results and mechanisms.
    const SPF_RESULT_PASS           = 'Spf valid';
    const SPF_RESULT_FAIL           = 'Spf fail';
    const SPF_RESULT_SOFTFAIL       = 'Spf soft fail';
    const SPF_RESULT_NEUTRAL        = '?';
    const SPF_RESULT_NONE           = 'No spf';
    const SPF_RESULT_PERMERROR      = 'Spf error';
    
    const MECHANISM_ALL             = 'all';
    const MECHANISM_IP4             = 'ip4';
    const MECHANISM_IP6             = 'ip6';
    const MECHANISM_A               = 'a';
    const MECHANISM_MX              = 'mx';
    const MECHANISM_PTR             = 'ptr';
    const MECHANISM_EXISTS          = 'exists';
    const MECHANISM_INCLUDE         = 'include';
    const MODIFIER_REDIRECT         = 'redirect';
    const MODIFIER_EXP              = 'exp';
    
    /**
     * Factory method to create an instance of SpfAnalyzer with provided data.
     * 
     * @param mixed $data SPF record data or domain name.
     * @return SpfAnalyzer
     */
    public static function create($data = [])
    {
        return new static($data);
    }
    
    /**
     * Constructor for SpfAnalyzer.
     * Initializes the analyzer with DNS TXT records or directly with an SPF record.
     * 
     * @param mixed $input SPF record data or domain name.
     */
    public function __construct($input){
        // Check if the input is a valid domain format
        if (is_array($input)) {
            $this->setDnsData($input);
        } else {
            $this->setDnsData(dns_get_record($input, DNS_TXT));
        }
        $this->parseSpf();
    }
    
    
    public function setToCheckIncludeIps(){
        $this->checkIncludeIps = true;
        return $this;
    }
    /**
     * Gets the SPF analysis result.
     * 
     * @return array The analysis result including validation status, errors, allowed IPs, and the SPF record entry.
     */
    public function getSpfResult(){
        return (object)[
            'isValid'       => $this->spfIsValid(),
            'spfErrors'     => $this->spfErrors,
            'spfPolicy'     => $this->spfPolicy,
            'allowedIPs'    => ($this->parseCidrBlocks) ? $this->parseAllowedIps() : $this->allowedIPs,
            'spfRecord'     => $this->spfRecordEntry
        ];
    }
    
    /**
     * Validates if the SPF record is valid based on the parsing and analysis.
     * 
     * @return bool True if the SPF record is valid, false otherwise.
     */
    public function spfIsValid(){
        return (bool)empty($this->spfErrors);
    }
    
    /**
     * Parses SPF records from DNS TXT records and validates them.
     */
    public function parseSpf(){
        if(!$this->getDnsData()){
            $this->spfErrors[] = self::SPF_RESULT_NONE;
            return $this;
        }
        $spfRecords = [];
        foreach ($this->getDnsData() as $record) {
            if ($record['type'] == 'TXT') {
                $txt = strtolower($record['txt']);
                if (strpos($record['txt'], 'v=spf1') === 0)
                    $spfRecords[] = $txt;
            }
        }
        if (count($spfRecords) == 0) {
            $this->spfErrors[] = self::SPF_RESULT_NONE;
        }elseif (count($spfRecords) > 1) {
            $this->spfErrors[] = self::SPF_RESULT_PERMERROR;
        }else{
            $this->spfRecordEntry = $spfRecords[0];
            $this->validateSpfSyntax();
        }
        return $this;
    }
    
    /**
     * Validates the syntax of the SPF record.
     */
    private function validateSpfSyntax() {
        $parts = explode(' ', $this->spfRecordEntry);
        foreach($parts as $part) {
            $this->handlePart($part);
        }
    }
    
    /**
     * Handles individual parts of the SPF record for validation.
     * 
     * @param string $part The part of the SPF record to handle.
     */
    private function handlePart($part) {
        $part = trim(str_replace("+","",$part));
        if (strpos($part, self::MECHANISM_INCLUDE) === 0 && $this->checkIncludeIps) {
            $this->handleInclude(substr($part, 8));
        } elseif (strpos($part, self::MECHANISM_IP4) === 0 || strpos($part, self::MECHANISM_IP6) === 0) {
            $this->allowedIPs[] = substr($part, 4);
        } elseif (strpos($part, self::MECHANISM_ALL) !== false) {
            $this->handleAllMechanism($part);
        }
    }
    
    /**
     * Processes the "include" mechanism by fetching and analyzing the included domain's SPF record.
     *
     * @param string $domain The domain specified in the "include" mechanism.
     */
    private function handleInclude($domain) {
        $includedSpf = new self($domain);
        $result = $includedSpf->getSpfResult();
        if(!$result->isValid)
            $this->spfErrors = array_merge($this->spfErrors, $result->spfErrors);
        $this->allowedIPs = array_merge($this->allowedIPs, $result->allowedIPs);
    }
    
    private function handleAllMechanism($part) {
        if ($part === '-all') {
            $this->spfPolicy = 'strict'; // Hard fail policy
        } elseif ($part === '~all') {
            $this->spfPolicy = 'neutral'; // Soft fail policy
        } elseif ($part === '?all') {
            $this->spfPolicy = 'none'; // Neutral policy
        }
    }
    
    private function resolveAndCollectIPs($domain, array $types) {
        foreach ($types as $type) {
            try {
                $records = dns_get_record($domain, constant('DNS_' . $type));
                foreach ($records as $record) {
                    $ip = isset($record['ip']) ? $record['ip'] : (isset($record['ipv6']) ? $record['ipv6'] : null);
                    if ($ip) {
                        $this->allowedIPs[] = $ip;
                    }
                }
            } catch (Exception $e) {
                $this->spfErrors[] = "Error resolving $type records for $domain: " . $e->getMessage();
            }
        }
    }
    
    /**
     * Sets the raw DNS data for analysis.
     * 
     * @param array $data The DNS TXT records data.
     */
    public function getDnsData(){
        return $this->rawRecords;
    }
    
    /**
     * Gets the raw DNS data used for SPF analysis.
     * 
     * @return array|null The DNS TXT records data.
     */
    public function setDnsData($data){
        $this->rawRecords = $data;
    }
    
    
    /**
     * deprecated.
     */
    private static function isSPFValid($spfRecord)
    {
        if (preg_match('/^v=spf1( +([-+?~]?(all|include:(%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\}|%%|%_|%-|[!-$&-~])*(\.([A-Za-z]|[A-Za-z]([-0-9A-Za-z]?)*[0-9A-Za-z])|%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\})|a(:(%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\}|%%|%_|%-|[!-$&-~])*(\.([A-Za-z]|[A-Za-z]([-0-9A-Za-z]?)*[0-9A-Za-z])|%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\}))?((\/(\d|1\d|2\d|3[0-2]))?(\/\/([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8]))?)?|mx(:(%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\}|%%|%_|%-|[!-$&-~])*(\.([A-Za-z]|[A-Za-z]([-0-9A-Za-z]?)*[0-9A-Za-z])|%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\}))?((\/(\d|1\d|2\d|3[0-2]))?(\/\/([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8]))?)?|ptr(:(%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\}|%%|%_|%-|[!-$&-~])*(\.([A-Za-z]|[A-Za-z]([-0-9A-Za-z]?)*[0-9A-Za-z])|%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\}))?|ip4:([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|1[0-9]|2[0-9]|3[0-2]))?|ip6:(::|([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|([0-9A-Fa-f]{1,4}:){1,8}:|([0-9A-Fa-f]{1,4}:){7}:[0-9A-Fa-f]{1,4}|([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}){1,2}|([0-9A-Fa-f]{1,4}:){5}(:[0-9A-Fa-f]{1,4}){1,3}|([0-9A-Fa-f]{1,4}:){4}(:[0-9A-Fa-f]{1,4}){1,4}|([0-9A-Fa-f]{1,4}:){3}(:[0-9A-Fa-f]{1,4}){1,5}|([0-9A-Fa-f]{1,4}:){2}(:[0-9A-Fa-f]{1,4}){1,6}|[0-9A-Fa-f]{1,4}:(:[0-9A-Fa-f]{1,4}){1,7}|:(:[0-9A-Fa-f]{1,4}){1,8}|([0-9A-Fa-f]{1,4}:){6}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])|([0-9A-Fa-f]{1,4}:){6}:([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])|([0-9A-Fa-f]{1,4}:){5}:([0-9A-Fa-f]{1,4}:)?([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])|([0-9A-Fa-f]{1,4}:){4}:([0-9A-Fa-f]{1,4}:){0,2}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])|([0-9A-Fa-f]{1,4}:){3}:([0-9A-Fa-f]{1,4}:){0,3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])|([0-9A-Fa-f]{1,4}:){2}:([0-9A-Fa-f]{1,4}:){0,4}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])|[0-9A-Fa-f]{1,4}::([0-9A-Fa-f]{1,4}:){0,5}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])|::([0-9A-Fa-f]{1,4}:){0,6}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))(\/(\d{1,2}|10[0-9]|11[0-9]|12[0-8]))?|exists:(%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\}|%%|%_|%-|[!-$&-~])*(\.([A-Za-z]|[A-Za-z]([-0-9A-Za-z]?)*[0-9A-Za-z])|%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\}))|redirect=(%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\}|%%|%_|%-|[!-$&-~])*(\.([A-Za-z]|[A-Za-z]([-0-9A-Za-z]?)*[0-9A-Za-z])|%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\})|exp=(%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\}|%%|%_|%-|[!-$&-~])*(\.([A-Za-z]|[A-Za-z]([-0-9A-Za-z]?)*[0-9A-Za-z])|%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\})|[A-Za-z][-.0-9A-Z_a-z]*=(%\{[CDHILOPR-Tcdhilopr-t]([1-9][0-9]?|10[0-9]|11[0-9]|12[0-8])?r?[+-\/=_]*\}|%%|%_|%-|[!-$&-~])*))* *$/i',
                $spfRecord) == 1
        ) {

            $recordParts = explode(' ', $spfRecord);
            array_shift($recordParts); // Remove first part (v=spf1)

            // RFC4408 6/2: each modifier can only appear once
            $redirectCount = 0;
            $expCount      = 0;
            foreach ($recordParts as $recordPart) {
                if (false !== strpos($recordPart, '=')) {
                    list($modifier, $domain) = explode('=', $recordPart, 2);
                    $expOrRedirect = false;
                    if ($modifier == self::MODIFIER_REDIRECT || substr($modifier, 1) == self::MODIFIER_REDIRECT) {
                        $redirectCount++;
                        $expOrRedirect = true;
                    }
                    if ($modifier == self::MODIFIER_EXP || substr($modifier, 1) == self::MODIFIER_EXP) {
                        $expCount++;
                        $expOrRedirect = true;
                    }
                    if ($expOrRedirect) {
                        if (empty($domain)) {
                            return false;
                        } else {
                            if (preg_match('/^[+-?~](all|a|mx|ptr|ip4|ip6|exists):?.*$/', $domain)) {
                                return false;
                            }
                            if (!preg_match('/^(((?!-))(xn--)?[a-z0-9-_]{0,61}[a-z0-9]{1,1}\.)*(xn--)?([a-z0-9\-]{1,61}|[a-z0-9-]{1,30}\.[a-z]{2,})$/i', $domain)) {
                                return false;
                            }
                        }
                    }
                }
            }
            if ($redirectCount > 1 || $expCount > 1) {
                return false;
            }

            return true;
        }

        return false;
    }
    
    public function parseAllowedIps(){
        $return = [];
        foreach($this->allowedIPs as $ipData){
            $return = array_merge($return,$this->expandIPRange($ipData));
        }
        return $return;
    }
    
    public function expandIPRange($input) {
        // Verify if input is a valid IP address or CIDR block
        if (filter_var($input, FILTER_VALIDATE_IP)) {
            // It's a valid single IP
            return [$input];
        } elseif (strpos($input, '/') !== false) {
            list($baseIP, $cidr) = explode('/', $input);
            if (filter_var($baseIP, FILTER_VALIDATE_IP) && is_numeric($cidr) && $cidr >= 0 && $cidr <= 32) {
                // Early return for a single IP in CIDR notation
                if ($cidr == 32) {
                    return [$baseIP];
                }
                // Calculate IPs range for CIDR blocks
                $ips    = [];
                $ipLong = ip2long($baseIP);
                $mask   = ~((1 << (32 - $cidr)) - 1);
                $start  = $ipLong & $mask;
                $end    = $ipLong | ~$mask;
                for ($ip = $start; $ip <= $end; $ip++)
                    $ips[] = long2ip($ip);
                return $ips;
            } else {
                // Invalid CIDR block
                return [];
                //return array("error" => "Invalid CIDR block");
            }
        } else {
            // Invalid input
            return [];
            //return array("error" => "Invalid IP address or CIDR block");
        }
    }
}
