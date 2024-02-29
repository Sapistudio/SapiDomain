<?php
namespace SapiStudio\Domain\Dns;

class ResourceRecord
{
    public $name;
    public $ttl;
    public $class;
    public $type;
    public $data;
    public $priority;

    public function __construct($name = '', $ttl = 0, $class = Classes::INTERNET, $type = '', $data = '', $priority = null)
    {
        $this->name     = $name;
        $this->ttl      = $ttl;
        $this->class    = $class;
        $this->type     = $type;
        $this->data     = $data;
        $this->priority = $priority;
    }
    
    public function toTextEntry()
    {
        $entryParts = [$this->name, $this->ttl, $this->class, $this->type];
        // Include priority for MX or SRV records if applicable
        if (in_array($this->type, [Classes::TYPE_MX, Classes::TYPE_SRV]) && $this->priority !== null) {
            $entryParts[] = $this->priority;
        }
        $entryParts[] = $this->data;
        return implode(' ', $entryParts);
    }
}