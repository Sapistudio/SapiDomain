<?php
namespace SapiStudio\Domain\Dns;

class StringIterator extends \ArrayIterator
{
    public function __construct( $string = '')
    {
        parent::__construct(str_split($string));
    }

    public function is( $value)
    {
        return $value === $this->current();
    }

    public function isNot( $value)
    {
        return $value !== $this->current();
    }

    public function __toString()
    {
        return implode($this->getArrayCopy());
    }
}