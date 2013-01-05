module Data.OpenPGP.CryptoAPI.Blowfish128 (Blowfish128) where

import Crypto.Classes (BlockCipher(..))
import Crypto.Types (BitLength)
import Crypto.Cipher.Blowfish (Blowfish)
import Data.Tagged (retag, Tagged(..))
import qualified Data.Serialize as Serialize

newtype Blowfish128 = Blowfish128 Blowfish

instance Serialize.Serialize Blowfish128 where
	put (Blowfish128 b) = Serialize.put b
	get = fmap Blowfish128 Serialize.get

instance BlockCipher Blowfish128 where
	blockSize = retag (blockSize :: Tagged Blowfish BitLength)
	encryptBlock (Blowfish128 k) = encryptBlock k
	decryptBlock (Blowfish128 k) = decryptBlock k
	buildKey = fmap Blowfish128 . buildKey
	keyLength = Tagged 128
