<?php
namespace SapiStudio\Domain\Getter;
use SapiStudio\Domain\DnsQuerifier;

/** RecordDig*/
 
class RecordDig extends DnsQuerifier implements RecordInterface
{
    // Define an array of public DNS servers
    protected $dnsServers = [
        ['name' => 'Google Public DNS', 'ips' => ['8.8.8.8', '8.8.4.4']],
        ['name' => 'Cloudflare', 'ips' => ['1.1.1.1', '1.0.0.1']],
        ['name' => 'OpenDNS', 'ips' => ['208.67.222.222', '208.67.220.220']],
        ['name' => 'Quad9', 'ips' => ['9.9.9.9', '149.112.112.112']],
        ['name' => 'CleanBrowsing', 'ips' => ['185.228.168.168', '185.228.169.168']],
        ['name' => 'DNS.WATCH', 'ips' => ['84.200.69.80', '84.200.70.40']],
        ['name' => 'Comodo Secure DNS', 'ips' => ['8.26.56.26', '8.20.247.20']],
    ];
    protected $queryServer  = '';
    CONST DEFAULT_TYPE      = "ANY";
    
    /** RecordDig::setQueryServer() */
    public function setQueryServer($nameserver = '')
    {
        $this->queryServer = $nameserver;
        return $this;
    }
    
    /** RecordDig::queryDns()*/
    public function queryDns($type)
    {
        $type       = ($type) ? $type : self::DEFAULT_TYPE;
        $command    = 'dig +nocmd'.$this->getSpecificQueryServer().' '.escapeshellarg($this->hostname)." {$type} +nomultiline +noall +answer ";
        $process    = new \Symfony\Component\Process\Process($command);
        $process->run();
        return (!$process->isSuccessful()) ? false : $this->parseDigResource($process->getOutput());
    }
    
    /** RecordDig::parseDigResource()*/
    protected function parseDigResource($digResponse = null)
    {
        $digResponse = explode("\n",$digResponse);
        if (!count($digResponse))
            return false;
        foreach($digResponse as $digLine) {
            $response[] = $this->parseDigLine($digLine);
        }
        return array_filter($response);
    }
    
    /** RecordDig::getSpecificQueryServer()*/
    protected function getSpecificQueryServer()
    {
        //return ' @'.escapeshellarg($this->getRandomDnsIp());
        return ($this->queryServer === '') ? '' : ' @'.escapeshellarg($this->queryServer);
    }
    
    // Function to get a random DNS IP address
    protected function getRandomDnsIp() {
        // Select a random DNS server from the list
        $randomServer = $this->dnsServers[array_rand($this->dnsServers)];
        // Select either the primary or secondary IP randomly
        $randomIp = $randomServer['ips'][array_rand($randomServer['ips'])];
        return $randomIp;
    }

    /** RecordDig::parseDigLine()*/
    protected function parseDigLine($digLine = null)
    {
        $digLine = trim(preg_replace('/^(;*)/', '', trim($digLine)));
        if (!$digLine)
            return false;
        list($hostname,$ttl,$class,$type,$data) = preg_split('/[\s]+/', $digLine, 5);
        $type = strtoupper($type);
        $response = [
            "host"  => $hostname,
            "class" => $class,
            "ttl"   => $ttl,
            "type"  => $type,
        ];
        $data = trim($data,'"');
        switch($type) {
                default:
                    return false;
                    break;
                case "A":
                    $response["ip"] = $data;
                    break;
                case "AAAA":
                    $response["ip6"] = $data;
                    break;
                case "MX":
                    list($priority, $target) = preg_split('/[\s]+/', $data, 2);
                    $response = array_merge($response,['pri' => $priority,'target' => $target]);
                    break;
                case "TXT":
                    $response = array_merge($response,['txt'=>$data,'entries'=>[$data]]);
                    break;
                case "PTR":
                case "NS":
                case "CNAME":
                    $response["target"] = $data;
                    break;
                case "SOA":
                    list($mname, $rname, $serial, $refresh,$retry,$expire,$minimum) = preg_split('/[\s]+/', $data, 7);
                    $response = array_merge($response,[
                        'mname' => $mname,
                        'rname' => $rname,
                        'serial' => $serial,
                        'refresh' => $refresh,
                        'retry' => $retry,
                        'expire' => $expire,
                        'minimum' => $minimum
                    ]);
                    break;
            }
        return $response;
    }
}
