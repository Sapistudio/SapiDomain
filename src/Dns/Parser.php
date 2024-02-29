<?php
namespace SapiStudio\Domain\Dns;

class Parser
{
    private $lastError  = '';
    private $records    = [];
    
    public function __construct($zoneString)
    {
        try {
            $zoneString = Normaliser::normalise($zoneString);
            $lines      = explode(Tokens::LINE_FEED, $zoneString);
            foreach ($lines as $line) {
                if ($this->shouldSkipLine($line))
                    continue;
                $parts = preg_split('/\s+/', $line);
                if (!$this->isValidRecord($parts))
                    continue;
                $name               = $parts[0];
                $ttl                = $this->processTTL($parts[1]);
                $class              = $this->processClass(isset($parts[2]) ? $parts[2] : '');
                $type               = $parts[3];
                $data               = $this->processData($parts);
                $priority           = $this->processPriority($type, $parts);
                $this->records[]    = new ResourceRecord($name, $ttl, $class, $type, $data, $priority);
            }
            return $this->groupRecordsByType();
        } catch (\Exception $e) {
            $this->lastError = "Error parsing DNS zone: " . $e->getMessage();
            return [];
        }
    }
    
    public function getRecords(){
        return $this->records;    
    }
    
    private function shouldSkipLine($line)
    {
        return empty($line) || strpos($line, Tokens::SEMICOLON) === 0;
    }

    private function isValidRecord($parts)
    {
        return count($parts) >= 5;
    }

    private function processTTL($part)
    {
        return is_numeric($part) ? $part : 0;
    }

    private function processClass($part)
    {
        return Classes::isValid($part) ? $part : Classes::INTERNET;
    }

    private function processData($parts)
    {
        return implode(" ", array_slice($parts, 4));
    }

    private function processPriority($type, $parts)
    {
        return ($type === Classes::TYPE_MX || $type === Classes::TYPE_SRV) ? (int)array_shift($parts) : null;
    }

    public function getLastError()
    {
        return $this->lastError;
    }
    
    public function groupRecordsByType()
    {
        $groupedRecords = [];
        foreach ($this->records as $record) {
            if (!isset($groupedRecords[$record->type])) {
                $groupedRecords[$record->type] = [];
            }
            $groupedRecords[$record->type][] = $record;
        }
        $this->records = $groupedRecords;
        return $this;
    }
}