<?php
namespace SapiStudio\Domain\Dns;

class Normaliser
{
    private $string;
    private $normalisedString = '';

    public function __construct($zone)
    {
        $zone           = str_replace([Tokens::CARRIAGE_RETURN, Tokens::TAB], ['', Tokens::SPACE], $zone);
        $this->string   = new StringIterator($zone);
    }

    public static function normalise($zone)
    {
        return (new self($zone))->process();
    }

    public function process()
    {
        while ($this->string->valid()) {
            $this->handleTxt();
            $this->handleComment();
            $this->handleMultiline();
            $this->append();
        }
        $this->removeWhitespace();
        return $this->normalisedString;
    }

    private function handleComment()
    {
        if ($this->string->isNot(Tokens::SEMICOLON)) {
            return;
        }
        while ($this->string->isNot(Tokens::LINE_FEED) && $this->string->valid()) {
            $this->string->next();
        }
    }

    private function handleTxt()
    {
        if ($this->string->isNot(Tokens::DOUBLE_QUOTES)) {
            return;
        }
        $this->append();
        while ($this->string->isNot(Tokens::DOUBLE_QUOTES)) {
            if (!$this->string->valid()) {
                throw new \Exception('Unbalanced double quotation marks. End of file reached.');
            }
            if ($this->string->is(Tokens::BACKSLASH)) {
                $this->append();
            }
            if ($this->string->is(Tokens::LINE_FEED)) {
                throw new \Exception('Line Feed found within double quotation marks context.', $this->string);
            }
            $this->append();
        }
    }

    private function handleMultiline()
    {
        if ($this->string->isNot(Tokens::OPEN_BRACKET)) {
            return;
        }
        $this->append();
        while ($this->string->valid()) {
            $this->handleTxt();
            $this->handleComment();
            if ($this->string->is(Tokens::LINE_FEED)) {
                $this->string->next();
                continue;
            }
            if ($this->string->is(Tokens::CLOSE_BRACKET)) {
                $this->append();
                return;
            }
            $this->append();
        }
        throw new \Exception('End of file reached. Unclosed bracket.');
    }

    private function removeWhitespace()
    {
        $string = preg_replace('/ {2,}/', Tokens::SPACE, $this->normalisedString);
        $lines  = [];
        foreach (explode(Tokens::LINE_FEED, $string) as $line) {
            if ('' !== $line = trim($line)) {
                $lines[] = $line;
            }
        }
        $this->normalisedString = implode(Tokens::LINE_FEED, $lines);
    }

    private function append()
    {
        $this->normalisedString .= $this->string->current();
        $this->string->next();
    }
}