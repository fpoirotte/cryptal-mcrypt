<?php

namespace fpoirotte\Cryptal\Plugins;

use fpoirotte\Cryptal\Implementers\CryptoInterface;
use fpoirotte\Cryptal\Implementers\PluginInterface;
use fpoirotte\Cryptal\PaddingInterface;
use fpoirotte\Cryptal\CipherEnum;
use fpoirotte\Cryptal\ModeEnum;
use fpoirotte\Cryptal\RegistryWrapper;
use fpoirotte\Cryptal\ImplementationTypeEnum;

class Mcrypt implements CryptoInterface, PluginInterface
{
    protected $cipherConst;
    protected $modeConst;
    protected $tagLength;
    protected $padding;
    protected $cipher;
    private $key;

    protected static $supportedCiphers = null;
    protected static $supportedModes = null;

    public function __construct(
        CipherEnum          $cipher,
        ModeEnum            $mode,
        PaddingInterface    $padding,
        $key,
        $tagLength = self::DEFAULT_TAG_LENGTH
    ) {
        if (static::$supportedCiphers === null) {
            static::checkSupport();
        }

        if (!isset(static::$supportedCiphers["$cipher"], static::$supportedModes["$mode"])) {
            throw new \Exception('Unsupported cipher or mode');
        }

        $this->cipherConst  = static::$supportedCiphers["$cipher"];
        $this->modeConst    = static::$supportedModes["$mode"];
        $this->tagLength    = $tagLength;
        $this->padding      = $padding;
        $this->key          = $key;
        $this->cipher       = $cipher;
    }

    protected static function checkSupport()
    {
        // First, build the list of supported ciphers.
        $candidates = array(
            (string) CipherEnum::CIPHER_3DES()      => 'MCRYPT_3DES',
            (string) CipherEnum::CIPHER_BLOWFISH()  => 'MCRYPT_BLOWFISH',
            (string) CipherEnum::CIPHER_CAST5()     => 'MCRYPT_CAST_128',
            (string) CipherEnum::CIPHER_DES()       => 'MCRYPT_DES',
            (string) CipherEnum::CIPHER_TWOFISH()   => 'MCRYPT_TWOFISH',

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
            (string) CipherEnum::CIPHER_AES_128()   => 'MCRYPT_RIJNDAEL_128',
            (string) CipherEnum::CIPHER_AES_192()   => 'MCRYPT_RIJNDAEL_128',
            (string) CipherEnum::CIPHER_AES_256()   => 'MCRYPT_RIJNDAEL_128',
        );

        $res = array();
        $supported = @mcrypt_list_algorithms();
        foreach ($candidates as $key => $value) {
            if (defined($value) && in_array(constant($value), $supported)) {
                $res["$key"] = constant($value);
            }
        }
        static::$supportedCiphers = $res;

        // Now, build the list of supported modes.
        $candidates = array(
            (string) ModeEnum::MODE_ECB()   => 'ecb',
            (string) ModeEnum::MODE_CBC()   => 'cbc',
            (string) ModeEnum::MODE_CFB()   => 'cfb',
            (string) ModeEnum::MODE_CTR()   => 'ctr',
            (string) ModeEnum::MODE_OFB()   => 'ofb',
        );

        $res = array();
        $supported = @mcrypt_list_modes();
        foreach ($candidates as $key => $value) {
            if (in_array($value, $supported)) {
                $res[$key] = $value;
            }
        }
        static::$supportedModes = $res;
    }

    public function encrypt($iv, $data, &$tag = null, $aad = '')
    {
        $blockSize  = $this->getBlockSize();
        $missing    = $blockSize - (strlen($data) % $blockSize);
        $data      .= $this->padding->getPaddingData($blockSize, $missing);
        $res = @mcrypt_encrypt($this->cipherConst, $this->key, $data, $this->modeConst, $iv);
        return $res;
    }

    public function decrypt($iv, $data, $tag = null, $aad = '')
    {
        $blockSize  = $this->getBlockSize();
        $res        = @mcrypt_decrypt($this->cipherConst, $this->key, $data, $this->modeConst, $iv);
        $padLen     = $this->padding->getPaddingSize($res, $blockSize);
        return $padLen ? (string) substr($res, 0, -$padLen) : $res;
    }

    public function getIVSize()
    {
        $res = @mcrypt_get_iv_size($this->cipherConst, $this->modeConst);
        if (false === $res) {
           // This should never happen since we already check
            // whether the combination is valid in the constructor.
            throw new \Exception('Unsupported cipher or mode');
        }
        return $res;
    }

    public function getBlockSize()
    {
        $res = @mcrypt_get_block_size($this->cipherConst, $this->modeConst);
        if (false === $res) {
            // This should never happen since we already check
            // whether the combination is valid in the constructor.
            throw new \Exception('Unsupported cipher or mode');
        }
        return $res;
    }

    public static function registerAlgorithms(RegistryWrapper $registry)
    {
        if (static::$supportedCiphers === null) {
            static::checkSupport();
        }

        foreach (static::$supportedModes as $mode => $modeConst) {
            foreach (static::$supportedCiphers as $cipher => $cipherConst) {
                $registry->addCipher(
                    __CLASS__,
                    CipherEnum::$cipher(),
                    ModeEnum::$mode(),
                    ImplementationTypeEnum::TYPE_COMPILED()
                );
            }
        }
    }

    public function getCipher()
    {
        return $this->cipher;
    }

    public function getKey()
    {
        return $this->key;
    }
}
