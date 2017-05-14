<?php

namespace fpoirotte\Cryptal;

use fpoirotte\Cryptal\CryptoInterface;
use fpoirotte\Cryptal\PaddingInterface;

class Implementation implements CryptoInterface
{
    protected $cipher;
    protected $mode;
    protected $tagLength;
    protected $padding;

    protected static $supportedCiphers = null;
    protected static $supportedModes = null;

    public function __construct($cipher, $mode, PaddingInterface $padding, $tagLength = 16)
    {
        if (static::$supportedCiphers === null) {
            static::checkSupport();
        }

        if (!isset(static::$supportedCiphers[$cipher], static::$supportedModes[$mode])) {
            throw new \Exception('Unsupported cipher or mode');
        }

        $this->cipher       = static::$supportedCiphers[$cipher];
        $this->mode         = static::$supportedModes[$mode];
        $this->tagLength    = $tagLength;
        $this->padding      = $padding;
    }

    protected static function checkSupport()
    {
        // First, build the list of supported ciphers.
        $candidates = array(
            CryptoInterface::CIPHER_3DES        => 'MCRYPT_3DES',
            CryptoInterface::CIPHER_BLOWFISH    => 'MCRYPT_BLOWFISH',
            CryptoInterface::CIPHER_CAST5       => 'MCRYPT_CAST_128',
            CryptoInterface::CIPHER_DES         => 'MCRYPT_DES',
            CryptoInterface::CIPHER_TWOFISH     => 'MCRYPT_TWOFISH',

            // Special notes on mcrypt's AES implementation.
            //
            // mcrypt uses the same cipher name
            // for all variants of AES.
            // It then uses the key's length at runtime
            // to determine the actual variant in use.
            //
            // The MCRYPT_RIJNDAEL_192 & MCRYPT_RIJNDAEL_256 constants
            // DO NOT refer to the 192 & 256 bit key variants.
            // Instead, they refer to non-standard variants where
            // the blocks are 192 & 256 bit long, respectively.
            CryptoInterface::CIPHER_AES_128     => 'MCRYPT_RIJNDAEL_128',
            CryptoInterface::CIPHER_AES_192     => 'MCRYPT_RIJNDAEL_128',
            CryptoInterface::CIPHER_AES_256     => 'MCRYPT_RIJNDAEL_128',
        );

        $res = array();
        $supported = @mcrypt_list_algorithms();
        foreach ($candidates as $key => $value) {
            if (defined($value) && in_array(constant($value), $supported)) {
                $res[$key] = constant($value);
            }
        }
        static::$supportedCiphers = $res;

        // The PHP mcrypt extension does not define MCRYPT_MODE_CTR constant,
        // although the underlying library supports this mode.
        // See also https://bugs.php.net/bug.php?id=66650.
        if (!defined('MCRYPT_MODE_CTR')) {
            define('MCRYPT_MODE_CTR', 'ctr');
        }

        // Now, build the list of supported modes.
        $candidates = array(
            CryptoInterface::MODE_ECB   => 'MCRYPT_MODE_ECB',
            CryptoInterface::MODE_CBC   => 'MCRYPT_MODE_CBC',
            CryptoInterface::MODE_CFB   => 'MCRYPT_MODE_CFB',
            CryptoInterface::MODE_CTR   => 'MCRYPT_MODE_CTR',
            CryptoInterface::MODE_OFB   => 'MCRYPT_MODE_OFB',
        );

        $res = array();
        $supported = @mcrypt_list_modes();
        foreach ($candidates as $key => $value) {
            if (defined($value) && in_array(constant($value), $supported)) {
                $res[$key] = constant($value);
            }
        }
        static::$supportedModes = $res;
    }

    public function encrypt($iv, $key, $data, &$tag = null, $aad = '')
    {
        $blockSize  = $this->getBlockSize();
        $missing    = $blockSize - (strlen($data) % $blockSize);
        $data      .= $this->padding->getPaddingData($blockSize, $missing);
        $res = @mcrypt_encrypt($this->cipher, $key, $data, $this->mode, $iv);
        return $res;
    }

    public function decrypt($iv, $key, $data, $tag = null, $aad = '')
    {
        $blockSize  = $this->getBlockSize();
        $res        = @mcrypt_decrypt($this->cipher, $key, $data, $this->mode, $iv);
        $padLen     = $this->padding->getPaddingSize($res, $blockSize);
        return $padLen ? (string) substr($res, 0, -$padLen) : $res;
    }

    public function getIVSize()
    {
        $res = @mcrypt_get_iv_size($this->cipher, $this->mode);
        if (false === $res) {
           // This should never happen since we already check
            // whether the combination is valid in the constructor.
            throw new \Exception('Unsupported cipher or mode');
        }
        return $res;
    }

    public function getBlockSize()
    {
        $res = @mcrypt_get_block_size($this->cipher, $this->mode);
        if (false === $res) {
            // This should never happen since we already check
            // whether the combination is valid in the constructor.
            throw new \Exception('Unsupported cipher or mode');
        }
        return $res;
    }
}
