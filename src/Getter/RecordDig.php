<?php
namespace SapiStudio\Domain\Getter;
use SapiStudio\Domain\DnsQuerifier;

/** RecordDig*/
 
class RecordDig extends DnsQuerifier implements RecordInterface
{
    protected $queryServer  = '';
    CONST DEFAULT_TYPE      = "ANY";
    
    /** RecordDig::setQueryServer() */
    public function setQueryServer(string $nameserver)
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
        return ($this->queryServer === '') ? '' : ' @'.escapeshellarg($this->queryServer);
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
