<?php

declare(strict_types=1);

namespace EW\WaEncryption;

use GuzzleHttp\Psr7\StreamDecoratorTrait;
use Psr\Http\Message\StreamInterface;

abstract class WhatsAppStreamDecorator implements StreamInterface
{
    public const MEDIA_TYPE_IMAGE = 'WhatsApp Image Keys';
    public const MEDIA_TYPE_AUDIO = 'WhatsApp Audio Keys';
    public const MEDIA_TYPE_VIDEO = 'WhatsApp Video Keys';
    public const MEDIA_TYPE_DOCUMENT = 'WhatsApp Document Keys';

    use StreamDecoratorTrait;

    protected string $iv;
    protected string $cipherKey;
    protected string $macKey;

    protected string $prevBlock;
    protected string $content;
    protected $incHashContext;

    protected int $cSeek = 0;

    public function __construct(
        private readonly StreamInterface $stream,
        private readonly string $encryptionKey,
        string $mediaType
    ) {
        $mediaKeyExpanded = hash_hkdf('sha256', $this->encryptionKey, 112, $mediaType);

        if ($mediaKeyExpanded === false) {
            throw new WhatsAppDecoratorException('hash_hkdf() calculation failed.');
        }

        $this->iv = substr($mediaKeyExpanded, 0, 16);
        $this->cipherKey = substr($mediaKeyExpanded, 16, 48 - 16);
        $this->macKey = substr($mediaKeyExpanded, 48, 80 - 48);
        //$refKey = substr($mediaKeyExpanded, 80);

        $this->prevBlock = $this->iv;
        $this->incHashContext = hash_init('sha256', HASH_HMAC, $this->macKey);
        hash_update($this->incHashContext, $this->iv);
    }


    /**
     * @inheritDoc
     */
    public function __toString(): string
    {
        try {
            $this->rewind();
            return $this->getContents();
        } catch (\Throwable $e) {
            if (\PHP_VERSION_ID >= 70400) {
                throw $e;
            }
            trigger_error(sprintf('%s::__toString exception: %s', self::class, (string) $e), E_USER_ERROR);

            return '';
        }
    }

    public function tell(): int
    {
        return $this->cSeek;
    }

    /**
     * @inheritDoc
     */
    public function isSeekable(): bool
    {
        return false;
    }

    /**
     * Not implemented.
     */
    public function seek($offset, $whence = SEEK_SET): void
    {
        throw new \RuntimeException('Not implemented');
    }

    /**
     * @inheritDoc
     */
    public function isWritable(): bool
    {
        return false;
    }

    /**
     * Not implemented.
     */
    public function write($string): int
    {
        throw new \RuntimeException('Not implemented');
    }

    /**
     * Seek to the beginning of the stream.
     */
    public function rewind(): void
    {
        $this->stream->rewind();
        $this->prevBlock = $this->iv;
        $this->incHashContext = hash_init('sha256', HASH_HMAC, $this->macKey);
        hash_update($this->incHashContext, $this->iv);
        $this->cSeek = 0;
    }
}